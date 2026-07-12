package com.phishingdetector.integrations;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishingdetector.config.Config;

/**
 * VirusTotal v3 API client.
 *
 * HOW THE URL SCAN WORKS (two-step):
 *
 *   Step 1 — POST /urls
 *     Submit the URL. VT responds with an analysis ID, e.g.:
 *     { "data": { "id": "u-<hash>-<timestamp>", "type": "analysis" } }
 *     The last_analysis_stats are NOT in this response.
 *
 *   Step 2 — GET /analyses/{id}
 *     Poll the analysis until status = "completed", then read last_analysis_stats.
 *     Free tier is slow; we poll up to 6 times with 5s sleep between attempts.
 *
 *   Alternative (faster) — GET /urls/{base64-url}
 *     If VT already has a cached report for this URL we can skip Step 1 entirely.
 *     We try this first; only fall back to Submit+Poll when no cached report exists.
 */
public class VirusTotalClient {

    private static final String VT_URL_SUBMIT   = "https://www.virustotal.com/api/v3/urls";
    private static final String VT_URL_REPORT   = "https://www.virustotal.com/api/v3/urls/";
    private static final String VT_ANALYSIS     = "https://www.virustotal.com/api/v3/analyses/";
    private static final String VT_FILE_SCAN    = "https://www.virustotal.com/api/v3/files";

    private static final int  POLL_MAX_ATTEMPTS = 6;
    private static final long POLL_SLEEP_MS     = 5_000; // 5 seconds between polls

    private final HttpClient   httpClient = HttpClient.newHttpClient();
    private final ObjectMapper mapper     = new ObjectMapper();
    private final String       apiKey;

    // ---- Cache ----
    private static class CachedResult {
        final VirusTotalUrlReport report;
        final long timestamp;
        CachedResult(VirusTotalUrlReport r) { this.report = r; this.timestamp = System.currentTimeMillis(); }
        boolean isExpired(long ttl) { return System.currentTimeMillis() - timestamp > ttl; }
    }
    private final Map<String, CachedResult> cache = new ConcurrentHashMap<>();
    private final long cacheTtlMs;

    // ---- Rate limiting ----
    private final AtomicInteger requestCount  = new AtomicInteger(0);
    private final AtomicLong    lastResetTime = new AtomicLong(System.currentTimeMillis());
    private final int  maxRequestsPerMinute;
    private final long rateLimitRetryMs;

    public VirusTotalClient() {
        this.apiKey               = Config.getVirusTotalApiKey();
        this.cacheTtlMs           = Config.getVtCacheTtl();
        this.maxRequestsPerMinute = Config.getVtRequestsPerMinute();
        this.rateLimitRetryMs     = Config.getVtRateLimitRetryMs();
        System.out.println("[VT] Client ready: " + maxRequestsPerMinute
                + " req/min, cache TTL=" + (cacheTtlMs / 1000) + "s");
    }

    // =========================================================================
    // Public API
    // =========================================================================

    public VirusTotalUrlReport scanUrl(String url) throws Exception {
        // Check local cache first
        CachedResult cached = cache.get(url);
        if (cached != null && !cached.isExpired(cacheTtlMs)) {
            System.out.println("[VT] Cache hit: " + url);
            return cached.report;
        }

        System.out.println("[VT] Scanning URL: " + url);
        VirusTotalUrlReport report = doScanUrl(url);
        cache.put(url, new CachedResult(report));
        return report;
    }

    // =========================================================================
    // Two-step URL scan
    // =========================================================================

    private VirusTotalUrlReport doScanUrl(String url) throws Exception {

        // --- Fast path: try GET /urls/{id} first (uses cached VT data, no quota) ---
        try {
            VirusTotalUrlReport cached = fetchExistingReport(url);
            if (cached != null) {
                System.out.println("[VT] Got existing report for: " + url
                        + " verdict=" + cached.verdict);
                return cached;
            }
        } catch (Exception e) {
            System.out.println("[VT] No existing report, will submit: " + e.getMessage());
        }

        // --- Slow path: POST to submit, then poll the analysis ---
        checkRateLimit();

        String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8);
        HttpRequest submitReq = HttpRequest.newBuilder()
                .uri(URI.create(VT_URL_SUBMIT))
                .header("x-apikey", apiKey)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("url=" + encodedUrl))
                .build();

        HttpResponse<String> submitResp =
                httpClient.send(submitReq, HttpResponse.BodyHandlers.ofString());

        System.out.println("[VT] Submit status: " + submitResp.statusCode());

        if (submitResp.statusCode() == 429) {
            System.err.println("[VT] Rate limited on submit, waiting " + (rateLimitRetryMs / 1000) + "s");
            Thread.sleep(rateLimitRetryMs);
            return doScanUrl(url); // retry once
        }

        if (submitResp.statusCode() != 200) {
            throw new Exception("[VT] Submit failed: " + submitResp.statusCode()
                    + " " + submitResp.body());
        }

        // Extract analysis ID from submission response
        JsonNode submitJson = mapper.readTree(submitResp.body());
        String analysisId   = submitJson.path("data").path("id").asText("");

        if (analysisId.isEmpty()) {
            throw new Exception("[VT] No analysis ID in submit response: " + submitResp.body());
        }

        System.out.println("[VT] Analysis ID: " + analysisId);

        // Poll the analysis until completed
        return pollAnalysis(analysisId, url);
    }

    /**
     * Try to fetch an already-existing VT report for a URL using GET /urls/{base64id}.
     * VT identifies URLs by URL-safe base64 of the URL (no padding).
     * Returns null if VT has no data for this URL yet.
     */
    private VirusTotalUrlReport fetchExistingReport(String url) throws Exception {
        String urlId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(url.getBytes(StandardCharsets.UTF_8));

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(VT_URL_REPORT + urlId))
                .header("x-apikey", apiKey)
                .GET()
                .build();

        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() == 404) return null; // VT doesn't know this URL yet

        if (resp.statusCode() != 200) {
            throw new Exception("GET /urls/{id} returned " + resp.statusCode());
        }

        JsonNode root  = mapper.readTree(resp.body());
        JsonNode attrs = root.path("data").path("attributes");
        JsonNode stats = attrs.path("last_analysis_stats");

        // If stats are all zeros VT has seen the URL but hasn't analysed it
        int mal  = stats.path("malicious").asInt(0);
        int susp = stats.path("suspicious").asInt(0);
        int harm = stats.path("harmless").asInt(0);
        int und  = stats.path("undetected").asInt(0);
        int total = mal + susp + harm + und;

        if (total == 0) return null; // No analysis data yet

        return buildReport(url, mal, susp, harm, und);
    }

    /**
     * Poll GET /analyses/{id} until status = "completed" or max attempts reached.
     */
    private VirusTotalUrlReport pollAnalysis(String analysisId, String originalUrl)
            throws Exception {

        for (int attempt = 1; attempt <= POLL_MAX_ATTEMPTS; attempt++) {
            System.out.println("[VT] Poll attempt " + attempt + "/" + POLL_MAX_ATTEMPTS
                    + " for " + analysisId);

            Thread.sleep(POLL_SLEEP_MS);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(VT_ANALYSIS + analysisId))
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();

            HttpResponse<String> resp =
                    httpClient.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() == 429) {
                System.err.println("[VT] Rate limited during poll, waiting extra...");
                Thread.sleep(rateLimitRetryMs);
                continue;
            }

            if (resp.statusCode() != 200) {
                System.err.println("[VT] Poll returned " + resp.statusCode() + ", retrying...");
                continue;
            }

            JsonNode root   = mapper.readTree(resp.body());
            JsonNode attrs  = root.path("data").path("attributes");
            String   status = attrs.path("status").asText("queued");

            System.out.println("[VT] Analysis status: " + status);

            if ("completed".equals(status)) {
                JsonNode stats = attrs.path("stats");

                int mal  = stats.path("malicious").asInt(0);
                int susp = stats.path("suspicious").asInt(0);
                int harm = stats.path("harmless").asInt(0);
                int und  = stats.path("undetected").asInt(0);

                VirusTotalUrlReport report = buildReport(originalUrl, mal, susp, harm, und);
                System.out.println("[VT] Completed: " + report);
                return report;
            }
            // status = "queued" or "in-progress" → keep polling
        }

        // Timed out — return what we have (all zeros, verdict UNKNOWN)
        System.err.println("[VT] Analysis timed out after " + POLL_MAX_ATTEMPTS + " polls");
        VirusTotalUrlReport timeout = new VirusTotalUrlReport();
        timeout.url     = originalUrl;
        timeout.verdict = "TIMEOUT";
        return timeout;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private VirusTotalUrlReport buildReport(String url, int mal, int susp, int harm, int und) {
        VirusTotalUrlReport r = new VirusTotalUrlReport();
        r.url        = url;
        r.malicious  = mal;
        r.suspicious = susp;
        r.harmless   = harm;
        r.undetected = und;

        if (mal > 0)       r.verdict = "MALICIOUS";
        else if (susp > 0) r.verdict = "SUSPICIOUS";
        else               r.verdict = "CLEAN";

        return r;
    }

    private void checkRateLimit() throws InterruptedException {
        long now     = System.currentTimeMillis();
        long elapsed = now - lastResetTime.get();

        if (elapsed >= 60_000) {
            requestCount.set(0);
            lastResetTime.set(now);
        }

        if (requestCount.get() >= maxRequestsPerMinute) {
            long wait = 60_000 - elapsed;
            if (wait < 0) wait = 5_000;
            System.out.println("[VT] Rate limit – waiting " + (wait / 1000) + "s");
            Thread.sleep(wait);
            requestCount.set(0);
            lastResetTime.set(System.currentTimeMillis());
        }

        requestCount.incrementAndGet();
    }

    // =========================================================================
    // File scan (unchanged logic, kept for completeness)
    // =========================================================================

    public VirusTotalUrlReport scanFile(byte[] fileBytes, String fileName) throws Exception {
        String cacheKey = "file:" + fileName + ":" + fileBytes.length;
        CachedResult cached = cache.get(cacheKey);
        if (cached != null && !cached.isExpired(cacheTtlMs)) {
            System.out.println("[VT] File cache hit: " + fileName);
            return cached.report;
        }

        checkRateLimit();

        String boundary     = "----VTBOUNDARY" + System.currentTimeMillis();
        String filePartHdr  = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\n"
                + "Content-Type: application/octet-stream\r\n\r\n";
        String closing      = "\r\n--" + boundary + "--\r\n";

        byte[] hdr  = filePartHdr.getBytes(StandardCharsets.UTF_8);
        byte[] tail = closing.getBytes(StandardCharsets.UTF_8);
        byte[] body = new byte[hdr.length + fileBytes.length + tail.length];
        System.arraycopy(hdr,       0, body, 0,                           hdr.length);
        System.arraycopy(fileBytes, 0, body, hdr.length,                  fileBytes.length);
        System.arraycopy(tail,      0, body, hdr.length + fileBytes.length, tail.length);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(VT_FILE_SCAN))
                .header("x-apikey", apiKey)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200)
            throw new Exception("VT file error: " + resp.statusCode() + " " + resp.body());

        JsonNode root  = mapper.readTree(resp.body());
        JsonNode stats = root.path("data").path("attributes").path("last_analysis_stats");

        int mal  = stats.path("malicious").asInt(0);
        int susp = stats.path("suspicious").asInt(0);
        int harm = stats.path("harmless").asInt(0);
        int und  = stats.path("undetected").asInt(0);

        VirusTotalUrlReport report = buildReport(fileName, mal, susp, harm, und);
        cache.put(cacheKey, new CachedResult(report));
        return report;
    }

    public void cleanCache() {
        cache.entrySet().removeIf(e -> e.getValue().isExpired(cacheTtlMs));
        System.out.println("[VT] Cache cleaned. Size=" + cache.size());
    }
}
