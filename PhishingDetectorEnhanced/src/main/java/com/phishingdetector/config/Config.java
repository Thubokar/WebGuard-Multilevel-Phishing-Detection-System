package com.phishingdetector.config;

public class Config {

    // ====== HARD-CODED VALUES ======

    // Supabase
    private static final String SUPABASE_URL =
        "https://cbnestwcyayergfhhrwb.supabase.co";
    private static final String SUPABASE_API_KEY =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNibmVzdHdjeWF5ZXJnZmhocndiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTc0OTk3NjksImV4cCI6MjA3MzA3NTc2OX0.ov05ULy3Dp2kA7dn3tChB6f67RRXnPrSIkL9rJxg7WE";
    private static final String SUPABASE_TABLE =
        "Keywords2";
    private static final String KEYWORDS_COLUMN =
        "Keywords";

    // Supabase - Sender verification table
    private static final String SENDER_TABLE          = "Sender";
    private static final String TRUSTED_SENDERS_COLUMN = "trusted_senders";
    private static final String SERVICES_COLUMN        = "Services";

    // VirusTotal
    private static final String VIRUSTOTAL_API_KEY =
        "9a517cb1cbdafaee5bfc6d9d176184e73b530c6e2dde1ce1a480e6c1f88ae39d";

    // Caching
    private static final long KEYWORD_CACHE_TTL_MS = 10 * 60 * 1000;   // 10 min
    private static final long VT_CACHE_TTL_MS      = 24 * 60 * 60 * 1000; // 24 h
    private static final long SENDER_CACHE_TTL_MS  = 30 * 60 * 1000;   // 30 min

    // VT rate limiting (free tier: 4 req/min, 500/day)
    private static final int  VT_REQUESTS_PER_MINUTE = 4;
    private static final long VT_RATE_LIMIT_RETRY_MS = 15_000; // 15 s

    // -------------------------------------------------------------------------
    // Scoring thresholds (UPDATED for Requirement 6)
    //
    // Old model: Layer1(0-10) + Layer2(0-10) + Layer3(0-10) + Attachment(0-10) = max 40
    //   → thresholds were DANGER=22, SUSPICIOUS=10
    //
    // New model: Layer1(0-10) + Layer2(0-10) + Layer3(dynamic, based on URLs found)
    //            + Attachment(0-10, only if attachments exist)
    //            + SenderCheck(0-5)
    //   Without attachments max base = 10+10+10+5 = 35
    //   With attachments    max base = 10+10+10+10+5 = 45
    //   We keep thresholds proportional and meaningful:
    // -------------------------------------------------------------------------
    public static final int DANGER_THRESHOLD     = 18;  // was 22
    public static final int SUSPICIOUS_THRESHOLD =  8;  // was 10

    // URL suspicion threshold: a URL scoring >= this in Layer3 is "suspicious"
    // and qualifies for VirusTotal scanning.
    //
    // WHY 4, not 3:
    //   urlResult.jsp classifies a URL as SUSPICIOUS when score >= 4.
    //   A score of 3 means "minor structural oddity" (e.g. long URL, one
    //   encoded char) — the local analysis itself does NOT flag it as
    //   suspicious, so there is no reason to spend a VT API call on it.
    //   VT is only called when the local result is already suspicious (>= 4).
    public static final int URL_SUSPICIOUS_SCORE_THRESHOLD = 4;

    // Validation limits
    public static final long MAX_EMAIL_BODY_LENGTH = 1_000_000L;        // 1 MB
    public static final long MAX_FILE_SIZE         = 50L * 1024 * 1024; // 50 MB


    // ====== GETTERS ======

    public static String getSupabaseUrl()      { return SUPABASE_URL; }

    public static String getSupabaseApiKey() {
        if (SUPABASE_API_KEY == null || SUPABASE_API_KEY.isEmpty())
            throw new IllegalStateException("SUPABASE_API_KEY not configured");
        return SUPABASE_API_KEY;
    }

    public static String getSupabaseTable()       { return SUPABASE_TABLE; }
    public static String getKeywordsColumn()      { return KEYWORDS_COLUMN; }

    public static String getSenderTable()          { return SENDER_TABLE; }
    public static String getTrustedSendersColumn() { return TRUSTED_SENDERS_COLUMN; }
    public static String getServicesColumn()       { return SERVICES_COLUMN; }

    public static String getVirusTotalApiKey() {
        if (VIRUSTOTAL_API_KEY == null || VIRUSTOTAL_API_KEY.isEmpty())
            throw new IllegalStateException("VIRUSTOTAL_API_KEY not configured");
        return VIRUSTOTAL_API_KEY;
    }

    public static long getKeywordCacheTtl()    { return KEYWORD_CACHE_TTL_MS; }
    public static long getVtCacheTtl()         { return VT_CACHE_TTL_MS; }
    public static long getSenderCacheTtl()     { return SENDER_CACHE_TTL_MS; }
    public static int  getVtRequestsPerMinute(){ return VT_REQUESTS_PER_MINUTE; }
    public static long getVtRateLimitRetryMs() { return VT_RATE_LIMIT_RETRY_MS; }

    public static void validateConfig() {
        getSupabaseApiKey();
        getVirusTotalApiKey();
        System.out.println("[CONFIG] All API keys and URLs are configured.");
    }
}
