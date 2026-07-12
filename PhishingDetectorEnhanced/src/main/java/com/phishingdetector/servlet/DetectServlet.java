package com.phishingdetector.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishingdetector.config.Config;
import com.phishingdetector.integrations.VirusTotalClient;
import com.phishingdetector.models.EmailAnalysisResult;
import com.phishingdetector.service.PhishingDetectionService;
import com.phishingdetector.utils.SecurityUtils;

@MultipartConfig(
        maxFileSize       = 50L * 1024 * 1024,
        maxRequestSize    = 100L * 1024 * 1024,
        fileSizeThreshold = 0
)
public class DetectServlet extends HttpServlet {

    private PhishingDetectionService service;
    private VirusTotalClient         vtClient;

    private volatile List<String> cachedKeywords = new ArrayList<>();
    private volatile long         lastCacheTime  = 0L;

    @Override
    public void init() throws ServletException {
        try {
            System.out.println("[SERVLET] Initialising config...");
            Config.validateConfig();

            vtClient = new VirusTotalClient();

            List<String> keywords = fetchKeywordsFromSupabase();
            // Store in cache so doPost knows they're fresh
            cachedKeywords = keywords;
            lastCacheTime  = System.currentTimeMillis();
            service        = new PhishingDetectionService(keywords, vtClient);

            System.out.println("[SERVLET] Ready with " + keywords.size() + " keywords");

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("[SERVLET] Init error: " + e.getMessage());

            List<String> fallback = Arrays.asList(
                "verify account", "confirm identity", "update payment",
                "urgent action required", "click here", "verify password",
                "bank details", "credit card", "social security",
                "suspicious activity", "locked account", "limited time"
            );
            if (vtClient == null) vtClient = new VirusTotalClient();
            // FIX: also store fallback in cachedKeywords so the empty-list check
            // in doPost does not keep retrying Supabase on every request.
            cachedKeywords = new ArrayList<>(fallback);
            lastCacheTime  = System.currentTimeMillis();
            service        = new PhishingDetectionService(fallback, vtClient);
            System.out.println("[SERVLET] Using fallback keywords");
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        req.setCharacterEncoding("UTF-8");

        // ----------------------------------------------------------------
        // FIX: refresh keyword cache correctly.
        //
        // Original bug: getCachedKeywords() assigned the new list to the
        // field and returned it, so "fresh != cachedKeywords" was ALWAYS
        // false and the service was NEVER rebuilt.
        //
        // Fixed approach: compare the timestamp directly, fetch a fresh
        // list separately, compare by size (quick heuristic), then rebuild
        // the service only when something changed.
        // ----------------------------------------------------------------
        long now = System.currentTimeMillis();
        if (now - lastCacheTime > Config.getKeywordCacheTtl()) {
            try {
                List<String> fresh = fetchKeywordsFromSupabase();
                if (fresh.size() != cachedKeywords.size()) {
                    // Keyword list changed — rebuild the service with fresh keywords
                    System.out.println("[SERVLET] Keywords refreshed: "
                            + cachedKeywords.size() + " → " + fresh.size());
                    cachedKeywords = fresh;
                    service        = new PhishingDetectionService(fresh, vtClient);
                }
                lastCacheTime = now;
            } catch (Exception e) {
                System.err.println("[SERVLET] Keyword refresh failed, using cached: " + e.getMessage());
                // lastCacheTime NOT updated so we retry on the next request
            }
        }

        String from      = req.getParameter("from");
        String subject   = req.getParameter("subject");
        String emailBody = req.getParameter("emailBody");

        try {
            Part emlPart = null;
            try { emlPart = req.getPart("emlFile"); }
            catch (IllegalStateException | ServletException ignore) { /* no file part */ }

            EmailAnalysisResult result;

            if (emlPart != null && emlPart.getSize() > 0) {
                result = analyzeEmlFile(emlPart);
                // analyzeEmlFile calls computeRisk() internally — do NOT call again.
            } else {
                if (!SecurityUtils.isValidBodyLength(emailBody, Config.MAX_EMAIL_BODY_LENGTH)) {
                    req.setAttribute("error", "Email body too large (max 1 MB)");
                    req.getRequestDispatcher("/error.jsp").forward(req, resp);
                    return;
                }
                // analyzeEmail() sets hasAttachments=false by default and calls computeRisk().
                // FIX: do NOT call computeRisk() again after this — double-calling was
                // overwriting a correct attachment score with hasAttachments=false.
                result = service.analyzeEmail(from, subject, emailBody);
            }

            req.setAttribute("result", result);
            req.getRequestDispatcher("/results.jsp").forward(req, resp);

        } catch (Exception e) {
            e.printStackTrace();
            req.setAttribute("error", "Error analysing email: " + e.getMessage());
            req.getRequestDispatcher("/error.jsp").forward(req, resp);
        }
    }

    // -------------------------------------------------------------------------
    // EML file parsing
    // -------------------------------------------------------------------------

    private EmailAnalysisResult analyzeEmlFile(Part emlPart) throws Exception {
        InputStream is  = emlPart.getInputStream();
        Session session = Session.getInstance(new Properties());
        MimeMessage msg = new MimeMessage(session, is);

        Address[] fromAddrs = msg.getFrom();
        String from    = (fromAddrs != null && fromAddrs.length > 0)
                         ? fromAddrs[0].toString() : "Unknown";
        String subject = msg.getSubject();
        String body    = extractText(msg);

        // analyzeEmail sets hasAttachments=false and calls computeRisk().
        // We re-compute below after setting attachment data.
        EmailAnalysisResult result = service.analyzeEmail(from, subject, body);

        List<String> findings = new ArrayList<>();
        analyzeJavaMailAttachments(msg, findings);

        result.hasAttachments     = !findings.isEmpty();
        result.attachmentFindings = findings;

        int attachScore = 0;
        for (String f : findings) attachScore += service.scoreAttachmentFinding(f);
        result.attachmentScore = Math.min(attachScore, 10);

        // Re-compute now that attachment data is set correctly.
        result.computeRisk();
        return result;
    }

    private String extractText(javax.mail.Part part) throws Exception {
        if (part.isMimeType("text/plain")) {
            Object c = part.getContent();
            return c != null ? c.toString() : "";
        } else if (part.isMimeType("text/html")) {
            Object c = part.getContent();
            return c != null ? SecurityUtils.stripHtmlTags(c.toString()) : "";
        } else if (part.isMimeType("multipart/*")) {
            MimeMultipart mp = (MimeMultipart) part.getContent();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mp.getCount(); i++) sb.append(extractText(mp.getBodyPart(i)));
            return sb.toString();
        }
        return "";
    }

    private void analyzeJavaMailAttachments(javax.mail.Part part, List<String> results)
            throws Exception {
        if (part.isMimeType("multipart/*")) {
            MimeMultipart mp = (MimeMultipart) part.getContent();
            for (int i = 0; i < mp.getCount(); i++)
                analyzeJavaMailAttachments(mp.getBodyPart(i), results);
        } else {
            String filename = part.getFileName();
            if (filename != null) {
                filename = filename.replaceAll("\\r?\\n", "");
                results.add(service.analyzeAttachmentName(
                        filename, part.getContentType(), part.getSize()));
            }
        }
    }

    // -------------------------------------------------------------------------
    // Supabase keyword fetch
    // -------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private List<String> fetchKeywordsFromSupabase() throws Exception {
        String url = Config.getSupabaseUrl() + "/rest/v1/"
                + Config.getSupabaseTable() + "?select=" + Config.getKeywordsColumn();

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("apikey", Config.getSupabaseApiKey())
                .header("Authorization", "Bearer " + Config.getSupabaseApiKey())
                .header("Accept", "application/json")
                .GET().build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200)
            throw new RuntimeException("Supabase returned " + response.statusCode()
                    + ": " + response.body());

        ObjectMapper mapper = new ObjectMapper();
        List<Object> rows   = mapper.readValue(response.body(), List.class);
        List<String> keywords = new ArrayList<>();

        for (Object rowObj : rows) {
            if (!(rowObj instanceof java.util.Map)) continue;
            java.util.Map<String, Object> row = (java.util.Map<String, Object>) rowObj;
            Object kw = row.get(Config.getKeywordsColumn());
            if (kw != null) {
                String s = kw.toString().trim();
                if (!s.isEmpty()) keywords.add(s);
            }
        }

        if (keywords.isEmpty()) {
            System.err.println("[SERVLET] WARNING: Supabase returned 0 keywords — "
                    + "check table '" + Config.getSupabaseTable()
                    + "' and column '" + Config.getKeywordsColumn() + "'");
        }

        return keywords;
    }
}
