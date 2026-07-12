package com.phishingdetector.integrations;

/**
 * DTO for VirusTotal scan results (URL and file scans).
 *
 * New fields / methods vs original:
 *  - verdict can now be "TIMEOUT" (analysis didn't complete in time)
 *  - getDisplaySummary() → "13/95 security vendors flagged this URL as malicious"
 *  - isThreat() threshold lowered: suspicious > 0 (was suspicious > 2)
 */
public class VirusTotalUrlReport {

    public String url;
    public int    harmless;
    public int    malicious;
    public int    suspicious;
    public int    undetected;
    public String verdict;   // CLEAN | SUSPICIOUS | MALICIOUS | TIMEOUT | UNKNOWN

    public VirusTotalUrlReport() {
        this.url        = "";
        this.harmless   = 0;
        this.malicious  = 0;
        this.suspicious = 0;
        this.undetected = 0;
        this.verdict    = "UNKNOWN";
    }

    /** Total engines that returned any result (excludes engines that errored/timed out). */
    public int getTotalEngines() {
        return harmless + malicious + suspicious + undetected;
    }

    /** Number of engines that flagged this URL (malicious + suspicious). */
    public int getFlaggedCount() {
        return malicious + suspicious;
    }

    /**
     * Human-readable summary line shown in results pages.
     *
     * Examples:
     *   "13/95 security vendors flagged this URL as malicious"
     *   "3/90 security vendors flagged this URL as suspicious"
     *   "No security vendors flagged this URL"
     *   "Analysis timed out – result unavailable"
     */
    public String getDisplaySummary() {
        if ("TIMEOUT".equals(verdict)) {
            return "Analysis timed out – result unavailable";
        }
        int total   = getTotalEngines();
        int flagged = getFlaggedCount();
        if (total == 0) {
            return "No analysis data available";
        }
        if (flagged == 0) {
            return "No security vendors flagged this URL (" + total + " checked)";
        }
        String type = malicious > 0 ? "malicious" : "suspicious";
        return flagged + "/" + total + " security vendors flagged this URL as " + type;
    }

    /** True when VT considers the URL a real threat. */
    public boolean isThreat() {
        return malicious > 0 || suspicious > 0;
    }

    public double getDetectionRate() {
        int total = getTotalEngines();
        if (total == 0) return 0.0;
        return ((double) getFlaggedCount() / total) * 100.0;
    }

    @Override
    public String toString() {
        return String.format(
            "VTReport{url='%s', verdict='%s', malicious=%d, suspicious=%d, harmless=%d, undetected=%d}",
            url, verdict, malicious, suspicious, harmless, undetected);
    }
}
