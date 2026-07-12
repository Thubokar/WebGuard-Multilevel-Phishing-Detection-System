package com.phishingdetector.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishingdetector.config.Config;
import com.phishingdetector.utils.SecurityUtils;

/**
 * Layer 4 – Sender verification against Supabase "Sender" table.
 *
 * Table schema:
 *   trusted_senders  TEXT   – exact email address  e.g. "support@paypal.com"
 *   Services         TEXT   – brand name            e.g. "PayPal"
 *
 * Logic:
 *  1. If the sender email is in trusted_senders   → TRUSTED  (score −3, bonus)
 *  2. If the email body mentions a Service brand
 *     but the sender domain does NOT match the
 *     known domain of that service               → SPOOFED  (score +5)
 *  3. Otherwise                                  → UNKNOWN  (score  0)
 */
public class SenderVerificationService {

    public enum SenderStatus { TRUSTED, UNKNOWN, SPOOFED }

    public static class SenderResult {
        public SenderStatus status      = SenderStatus.UNKNOWN;
        public String       senderEmail = "";
        public String       matchedService = "";   // brand matched (if any)
        public String       reason      = "";
        public int          score       = 0;       // negative = good, positive = bad
    }

    // ---- cache ----
    private static class CachedData {
        final List<Map<String, Object>> rows;
        final long timestamp;
        CachedData(List<Map<String, Object>> rows) {
            this.rows = rows;
            this.timestamp = System.currentTimeMillis();
        }
        boolean isExpired(long ttl) {
            return System.currentTimeMillis() - timestamp > ttl;
        }
    }

    // Service-brand → canonical domain suffix mapping
    // Keep this in sync with what you store in the Services column.
    private static final Map<String, String> SERVICE_DOMAINS = new ConcurrentHashMap<>();
    static {
        SERVICE_DOMAINS.put("google",       "google.com");
        SERVICE_DOMAINS.put("microsoft",    "microsoft.com");
        SERVICE_DOMAINS.put("facebook",     "facebook.com");
        SERVICE_DOMAINS.put("meta",         "meta.com");
        SERVICE_DOMAINS.put("amazon",       "amazon.com");
        SERVICE_DOMAINS.put("apple",        "apple.com");
        SERVICE_DOMAINS.put("paypal",       "paypal.com");
        SERVICE_DOMAINS.put("twitter",      "twitter.com");
        SERVICE_DOMAINS.put("linkedin",     "linkedin.com");
        SERVICE_DOMAINS.put("netflix",      "netflix.com");
        SERVICE_DOMAINS.put("instagram",    "instagram.com");
        SERVICE_DOMAINS.put("ebay",         "ebay.com");
        SERVICE_DOMAINS.put("dropbox",      "dropbox.com");
        SERVICE_DOMAINS.put("github",       "github.com");
        SERVICE_DOMAINS.put("slack",        "slack.com");
        SERVICE_DOMAINS.put("zoom",         "zoom.us");
        SERVICE_DOMAINS.put("adobe",        "adobe.com");
        SERVICE_DOMAINS.put("spotify",      "spotify.com");
    }

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper mapper   = new ObjectMapper();

    private volatile CachedData cache = null;

    // ---- public API ----

    /**
     * @param from        Raw "From" header value (may include display name)
     * @param emailBody   Plain-text body (HTML already stripped)
     */
    public SenderResult verify(String from, String emailBody) {
        SenderResult result = new SenderResult();
        if (from == null) from = "";
        if (emailBody == null) emailBody = "";

        String email  = SecurityUtils.extractEmailAddress(from).toLowerCase().trim();
        String domain = SecurityUtils.extractDomainFromEmail(email);
        result.senderEmail = email;

        List<Map<String, Object>> rows = loadRows();

        // 1. Check if email is in trusted_senders
        for (Map<String, Object> row : rows) {
            Object ts = row.get(Config.getTrustedSendersColumn());
            if (ts == null) continue;
            String trustedEmail = ts.toString().trim().toLowerCase();
            if (trustedEmail.equals(email)) {
                result.status         = SenderStatus.TRUSTED;
                result.matchedService = safeString(row.get(Config.getServicesColumn()));
                result.reason         = "Sender is a verified trusted address"
                        + (result.matchedService.isEmpty() ? "" : " (" + result.matchedService + ")");
                result.score          = -3;   // reward; lowers total risk
                return result;
            }
        }

        // 2. Check body for brand names and verify domain matches
        String bodyLower = emailBody.toLowerCase();
        for (Map<String, Object> row : rows) {
            Object svc = row.get(Config.getServicesColumn());
            if (svc == null) continue;
            String serviceName = svc.toString().trim().toLowerCase();
            if (serviceName.isEmpty()) continue;

            if (bodyLower.contains(serviceName)) {
                // Body mentions this brand – does the sender domain match?
                String expectedDomain = SERVICE_DOMAINS.getOrDefault(serviceName,
                        serviceName.replace(" ", "") + ".com");

                if (domain.isEmpty() || !domain.endsWith(expectedDomain)) {
                    result.status         = SenderStatus.SPOOFED;
                    result.matchedService = safeString(row.get(Config.getServicesColumn()));
                    result.reason         = "Email claims to be from " + result.matchedService
                            + " but sender domain is '" + (domain.isEmpty() ? "unknown" : domain)
                            + "' (expected @" + expectedDomain + ")";
                    result.score          = 5;
                    return result;
                }
            }
        }

        // 3. Unknown sender
        result.status = SenderStatus.UNKNOWN;
        result.reason = "Sender not found in trusted list; no brand mismatch detected";
        result.score  = 0;
        return result;
    }

    // ---- Supabase fetch with caching ----

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> loadRows() {
        CachedData current = cache;
        if (current != null && !current.isExpired(Config.getSenderCacheTtl())) {
            return current.rows;
        }

        try {
            String url = Config.getSupabaseUrl() + "/rest/v1/" + Config.getSenderTable()
                    + "?select=" + Config.getTrustedSendersColumn()
                    + "," + Config.getServicesColumn();

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("apikey", Config.getSupabaseApiKey())
                    .header("Authorization", "Bearer " + Config.getSupabaseApiKey())
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() != 200) {
                System.err.println("[SENDER] Supabase error " + resp.statusCode() + ": " + resp.body());
                return current != null ? current.rows : new ArrayList<>();
            }

            List<Map<String, Object>> rows =
                    (List<Map<String, Object>>) mapper.readValue(resp.body(), List.class);
            cache = new CachedData(rows);
            System.out.println("[SENDER] Loaded " + rows.size() + " sender entries from Supabase");
            return rows;

        } catch (Exception e) {
            System.err.println("[SENDER] Failed to fetch sender table: " + e.getMessage());
            return current != null ? current.rows : new ArrayList<>();
        }
    }

    private String safeString(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}
