package com.phishingdetector.models;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.phishingdetector.integrations.VirusTotalUrlReport;

/**
 * DTO filled by PhishingDetectionService and read by JSPs.
 *
 * Scoring model:
 *   Layer 1  - Keywords + Sender brand check  0-15
 *   Layer 2  - Patterns                       0-10
 *   Layer 3  - URLs (cumulative)              0-15
 *   Attachment - only if present              0-10
 *
 * Thresholds (Config.java):
 *   DANGER      >= 18
 *   SUSPICIOUS  >=  8
 *   SAFE        <   8
 *
 * SENDER SCORING (per user requirement):
 *   Trusted sender (Supabase table OR domain match) → 0 pts  (safe)
 *   Spoofed sender (brand mismatch)                 → +5 pts (not safe)
 *
 * FIX: Added urlIssuesMap so results.jsp can display issues per-URL instead
 *      of incorrectly showing the global urlIssues flat list for every URL.
 */
public class EmailAnalysisResult {

    // Basic email info
    public String from;
    public String subject;
    public String body;

    // Per-layer scores
    public int layer1Score;        // keywords + sender brand check (0-15)
    public int layer2Score;        // patterns                      (0-10)
    public int layer3Score;        // URLs cumulative               (0-15)
    public int attachmentScore;    // attachments                   (0-10, only when hasAttachments=true)
    public boolean hasAttachments;

    public int totalScore;
    public String riskLevel;       // SAFE | SUSPICIOUS | DANGER

    // Layer 1 keyword details
    public Set<String>  suspiciousKeywords = new HashSet<>();
    public List<String> flags              = new ArrayList<>();

    // Sender check
    public boolean senderSpoofed = false;
    public boolean senderTrusted = false;
    public String  senderEmail   = "";
    public String  senderReason  = "";

    /** All URLs extracted from the email body. */
    public List<String> allUrls = new ArrayList<>();

    /**
     * URLs that scored > 0 in Layer 3 structural analysis.
     */
    public List<String> suspiciousUrls = new ArrayList<>();

    /**
     * URLs actually submitted to VirusTotal this request.
     * results.jsp MUST use this set to gate "Sent to VirusTotal" tags.
     */
    public Set<String> vtScannedUrls = new HashSet<>();

    /**
     * FIX: Per-URL structural issues map.
     * Key = URL string, Value = list of issue strings for that URL only.
     * results.jsp uses this instead of the flat urlIssues list.
     */
    public Map<String, List<String>> urlIssuesMap = new HashMap<>();

    /**
     * Flat list of all structural issues across all URLs (kept for backwards
     * compat with any code that reads it, but results.jsp now uses urlIssuesMap).
     */
    public List<String> urlIssues = new ArrayList<>();

    /**
     * VirusTotal reports keyed by URL.
     * Only populated when VT verdict is SUSPICIOUS or MALICIOUS.
     */
    public Map<String, VirusTotalUrlReport> vtReports = new HashMap<>();

    public List<String> attachmentFindings = new ArrayList<>();
    public boolean brandMismatch;

    // Thresholds mirrored for JSP access
    public static final int DANGER_THRESHOLD     = com.phishingdetector.config.Config.DANGER_THRESHOLD;
    public static final int SUSPICIOUS_THRESHOLD = com.phishingdetector.config.Config.SUSPICIOUS_THRESHOLD;

    /**
     * Compute totalScore and riskLevel.
     * Attachment score excluded when no attachments were found.
     */
    public void computeRisk() {
        int base = layer1Score + layer2Score + layer3Score;
        if (hasAttachments) {
            base += attachmentScore;
        }
        totalScore = base;

        boolean hasDangerousAttachment = hasAttachments && attachmentScore >= 8;

        if (hasDangerousAttachment || totalScore >= DANGER_THRESHOLD) {
            riskLevel = "DANGER";
        } else if (totalScore >= SUSPICIOUS_THRESHOLD) {
            riskLevel = "SUSPICIOUS";
        } else {
            riskLevel = "SAFE";
        }
    }
}
