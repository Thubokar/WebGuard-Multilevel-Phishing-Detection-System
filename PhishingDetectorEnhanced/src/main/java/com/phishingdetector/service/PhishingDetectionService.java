package com.phishingdetector.service;

import java.util.ArrayList;
import java.util.List;

import com.phishingdetector.config.Config;
import com.phishingdetector.integrations.VirusTotalClient;
import com.phishingdetector.integrations.VirusTotalUrlReport;
import com.phishingdetector.layers.Layer1KeywordDetection;
import com.phishingdetector.layers.Layer1KeywordDetection.Layer1Result;
import com.phishingdetector.layers.Layer2PatternAnalysis;
import com.phishingdetector.layers.Layer2PatternAnalysis.PatternResult;
import com.phishingdetector.layers.Layer3UrlAnalysis;
import com.phishingdetector.layers.Layer3UrlAnalysis.UrlAnalysisResult;
import com.phishingdetector.models.EmailAnalysisResult;
import com.phishingdetector.service.SenderVerificationService;
import com.phishingdetector.service.SenderVerificationService.SenderResult;
import com.phishingdetector.service.SenderVerificationService.SenderStatus;
import com.phishingdetector.utils.SecurityUtils;
import com.phishingdetector.utils.UrlExtractor;

/**
 * Orchestrates all analysis layers.
 *
 * SENDER VERIFICATION LOGIC (corrected per user requirement):
 *
 *   Step 1 – SenderVerificationService checks the Supabase "Sender" table:
 *     • If sender email is in trusted_senders column → TRUSTED (0 pts, safe)
 *     • If body mentions a service brand but domain doesn't match → SPOOFED (+5 pts)
 *     • Otherwise → UNKNOWN (0 pts)
 *
 *   Step 2 – If Supabase check is UNKNOWN, Layer1 inline brand check runs
 *            as fallback using the hardcoded BRAND_DOMAINS map.
 *
 *   This means: a sender explicitly listed in the Supabase trusted table
 *   will NEVER contribute positive points, regardless of body content.
 *
 * Layer scores:
 *   Layer 1  - Keywords (0-10) + Sender score (0 or +5), cap 15
 *   Layer 2  - Pattern analysis (0-10)
 *   Layer 3  - URL heuristics + conditional VT (0-15)
 *   Attach   - Only counted when attachments found (0-10)
 *
 * FIX: urlIssuesMap is populated per-URL so results.jsp shows correct
 *      issues for each individual URL.
 */
public class PhishingDetectionService {

    private final Layer1KeywordDetection    layer1;
    private final Layer2PatternAnalysis     layer2;
    private final Layer3UrlAnalysis         layer3;
    private final VirusTotalClient          vtClient;
    private final SenderVerificationService senderService;

    public PhishingDetectionService(List<String> keywords, VirusTotalClient vtClient) {
        this.layer1        = new Layer1KeywordDetection(keywords);
        this.layer2        = new Layer2PatternAnalysis();
        this.layer3        = new Layer3UrlAnalysis();
        this.vtClient      = vtClient;
        this.senderService = new SenderVerificationService();
    }

    // -------------------------------------------------------------------------
    // Main entry point
    // -------------------------------------------------------------------------

    /**
     * Analyse an email through all layers and return a fully populated result.
     * computeRisk() is called internally — callers must NOT call it again
     * (unless re-computing after setting attachment data, as DetectServlet does).
     */
    public EmailAnalysisResult analyzeEmail(String from, String subject, String body) {
        EmailAnalysisResult result = new EmailAnalysisResult();
        result.from    = (from    != null ? from    : "Unknown");
        result.subject = (subject != null ? subject : "No Subject");
        result.body    = (body    != null ? body    : "");

        String textOnly       = SecurityUtils.stripHtmlTags(result.body);
        String normalizedBody = textOnly.toLowerCase();

        // ---- Layer 1: Keywords (Aho-Corasick) ----
        Layer1Result l1 = layer1.analyze(normalizedBody, result.from);
        result.suspiciousKeywords = l1.keywords;

        // ---- Sender verification (two-step) ----
        //
        // Step 1: Supabase trusted sender table (exact email match)
        //   TRUSTED  → 0 pts (safe — no risk points added)
        //   SPOOFED  → +5 pts (not safe)
        //   UNKNOWN  → fall through to Step 2
        //
        // Step 2: Layer 1 inline brand-domain check (fallback)
        //   TRUSTED  → 0 pts
        //   SPOOFED  → +5 pts
        //   UNKNOWN  → 0 pts
        int    senderScore   = 0;
        boolean senderSpoofed = false;
        boolean senderTrusted = false;
        String  senderEmail   = l1.senderEmail;
        String  senderReason  = l1.senderReason;

        try {
            SenderResult sr = senderService.verify(result.from, textOnly);
            if (sr.status == SenderStatus.TRUSTED) {
                // Exact match in Supabase trusted_senders → safe, 0 pts
                senderScore   = 0;
                senderTrusted = true;
                senderEmail   = sr.senderEmail;
                senderReason  = sr.reason;
                System.out.println("[SERVICE] Supabase trusted sender: " + senderEmail);
            } else if (sr.status == SenderStatus.SPOOFED) {
                // Supabase brand mismatch → not safe, +5 pts
                senderScore   = 5;
                senderSpoofed = true;
                senderEmail   = sr.senderEmail;
                senderReason  = sr.reason;
                System.out.println("[SERVICE] Supabase spoofed sender: " + senderEmail);
            } else {
                // UNKNOWN from Supabase → use Layer 1 inline brand check as fallback
                senderScore   = l1.senderScore;
                senderSpoofed = l1.senderSpoofed;
                senderTrusted = l1.senderTrusted;
                senderEmail   = l1.senderEmail;
                senderReason  = l1.senderReason;
            }
        } catch (Exception e) {
            // Supabase unavailable → fall back to inline brand check
            System.err.println("[SERVICE] SenderVerification failed, using inline check: " + e.getMessage());
            senderScore   = l1.senderScore;
            senderSpoofed = l1.senderSpoofed;
            senderTrusted = l1.senderTrusted;
            senderEmail   = l1.senderEmail;
            senderReason  = l1.senderReason;
        }

        // Layer 1 total = keywords + sender, capped at 15
        result.layer1Score   = Math.min(l1.keywordScore + senderScore, 15);
        result.brandMismatch = senderSpoofed;
        result.senderSpoofed = senderSpoofed;
        result.senderTrusted = senderTrusted;
        result.senderEmail   = senderEmail;
        result.senderReason  = senderReason;

        if (senderSpoofed) {
            result.flags.add("Sender spoofing detected: " + senderReason);
        } else if (senderTrusted) {
            result.flags.add("Verified trusted sender: " + senderReason);
        }

        // ---- Layer 2: Pattern analysis ----
        PatternResult pr = layer2.analyzePatterns(result.body, normalizedBody, result.from);
        result.layer2Score = Math.min(pr.score, 10);
        addPatternFlags(result, pr);

        // ---- Layer 3: URL analysis + conditional VT scanning ----
        analyzeAllUrls(result);

        result.computeRisk();
        return result;
    }

    // -------------------------------------------------------------------------
    // URL analysis + conditional VT scanning
    // -------------------------------------------------------------------------

    private void analyzeAllUrls(EmailAnalysisResult result) {
        List<String> urls = UrlExtractor.extractUrls(result.body);
        result.allUrls = urls;

        if (urls.isEmpty()) return;

        int cumulativeScore  = 0;
        int vtCallsThisEmail = 0;
        final int MAX_VT_PER_EMAIL = 3;

        for (String url : urls) {
            UrlAnalysisResult ua = layer3.analyzeUrl(url);

            if (ua.totalScore > 0) {
                result.suspiciousUrls.add(url);

                // FIX: store issues per-URL in the map, not just in the flat list
                result.urlIssuesMap.put(url, new ArrayList<>(ua.issues));
                result.urlIssues.addAll(ua.issues);   // keep flat list for compat

                cumulativeScore += ua.totalScore;
            }

            boolean meetsVtThreshold = ua.isSuspicious(Config.URL_SUSPICIOUS_SCORE_THRESHOLD);
            boolean quotaAvailable   = vtCallsThisEmail < MAX_VT_PER_EMAIL && vtClient != null;

            if (meetsVtThreshold && quotaAvailable) {
                result.vtScannedUrls.add(url);
                vtCallsThisEmail++;

                try {
                    VirusTotalUrlReport vtReport = vtClient.scanUrl(url);
                    if (vtReport != null
                            && ("SUSPICIOUS".equals(vtReport.verdict)
                                || "MALICIOUS".equals(vtReport.verdict))) {
                        result.vtReports.put(url, vtReport);
                        cumulativeScore += (vtReport.malicious * 2);
                    }
                } catch (Exception e) {
                    System.err.println("[SERVICE] VT scan failed for " + url + ": " + e.getMessage());
                }
            }
        }

        result.layer3Score = Math.min(cumulativeScore, 15);
    }

    // -------------------------------------------------------------------------
    // Attachment helpers – called by DetectServlet
    // -------------------------------------------------------------------------

    public int scoreAttachmentFinding(String finding) {
        if (finding == null) return 0;
        String f = finding.toLowerCase();
        if (f.contains("dangerous")) return 8;
        if (f.contains("suspicious")) return 4;
        return 0;
    }

    public String analyzeAttachmentName(String filename, String contentType, long sizeBytes) {
        if (filename == null) return "No attachment name";

        String safeName  = SecurityUtils.sanitizeFilename(filename);
        String nameLower = safeName.toLowerCase();
        StringBuilder finding = new StringBuilder("Attachment: ").append(safeName);

        String[] dangerous = {
            ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".jar",
            ".lnk", ".msi", ".com", ".ps1", ".wsf", ".hta", ".reg", ".chm",
            ".iso", ".img", ".dmg", ".apk"
        };
        for (String ext : dangerous) {
            if (nameLower.endsWith(ext)) {
                return finding.append(" DANGEROUS - ").append(ext).append(" executable").toString();
            }
        }

        if (nameLower.matches(".*\\.\\w+\\.\\w+$")) {
            return finding.append(" SUSPICIOUS - Double extension (hides real type)").toString();
        }

        if (nameLower.endsWith(".pdf") && contentType != null && !contentType.contains("pdf")) {
            return finding.append(" DANGEROUS - Extension/content-type mismatch").toString();
        }

        if (nameLower.endsWith(".exe") && sizeBytes > 0 && sizeBytes < 10_000) {
            return finding.append(" SUSPICIOUS - Unusually small .exe (")
                    .append(sizeBytes).append(" bytes)").toString();
        }

        if (nameLower.endsWith(".pdf") && sizeBytes > 10_000_000) {
            return finding.append(" SUSPICIOUS - Very large PDF (")
                    .append(sizeBytes).append(" bytes)").toString();
        }

        return finding.append(" - OK").toString();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void addPatternFlags(EmailAnalysisResult result, PatternResult pr) {
        if (pr.hasUrgency)                result.flags.add("Urgency / time-pressure language");
        if (pr.hasCredentialRequest)      result.flags.add("Credentials (password/PIN/OTP) requested");
        if (pr.hasAuthorityImpersonation) result.flags.add("Authority impersonation (IRS/bank/support)");
        if (pr.hasMoneyRequest)           result.flags.add("Request for money, gift cards, or crypto");
        if (pr.hasCreditCard)             result.flags.add("Credit card number detected (Luhn-valid)");
        if (pr.hasSuspiciousPhone)        result.flags.add("Phone number present (social engineering risk)");
        if (pr.hasExcessivePunctuation)   result.flags.add("Excessive punctuation (!!!, ???)");
        if (pr.hasRepetition)             result.flags.add("Repetitive 'click' or 'verify' language");
        if (pr.hasExcessiveCaps)          result.flags.add("Excessive CAPITAL LETTERS");
        if (pr.hasSenderSpoofing)         result.flags.add("Sender domain does not match claimed brand");
    }
}
