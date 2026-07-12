package com.phishingdetector.layers;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.phishingdetector.utils.UrlExtractor;

/**
 * Layer 3 – Enhanced URL analysis.
 *
 * FIXES vs previous version:
 *   - Removed duplicate "steam" entry from BRAND_DOMAINS.
 */
public class Layer3UrlAnalysis {

    public static class UrlAnalysisResult {
        public int ipDetectionScore   = 0;
        public int entropyScore       = 0;
        public int structuralScore    = 0;
        public int brandMismatchScore = 0;
        public int homoglyphScore     = 0;
        public int pathScore          = 0;
        public int tldScore           = 0;
        public List<String> issues    = new ArrayList<>();
        public int totalScore         = 0;

        public void calculateTotal() {
            totalScore = ipDetectionScore + entropyScore + structuralScore
                       + brandMismatchScore + homoglyphScore + pathScore + tldScore;
        }

        public boolean isSuspicious(int threshold) {
            return totalScore >= threshold;
        }
    }

    private static final Pattern IP_PATTERN = Pattern.compile(
            "(?:https?://)?(\\d{1,3}(?:\\.\\d{1,3}){3})",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PRIVATE_IP = Pattern.compile(
            "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.).*");

    private static final Pattern SUSPICIOUS_PATH_KEYWORDS = Pattern.compile(
            "(?i)(login|signin|verify|secure|account|update|banking|webscr|"
            + "confirm|validation|credential|authenticate|passwd|password|reset)");

    private static final Set<String> RISKY_TLDS = new HashSet<>(Arrays.asList(
            "tk", "ml", "ga", "cf", "gq",
            "xyz", "top", "club", "online", "site", "click",
            "link", "work", "loan", "win", "bid", "racing",
            "download", "stream", "review", "country", "kim",
            "science", "party", "trade", "webcam", "faith"
    ));

    // FIX: removed duplicate "steam" entry that was present twice
    private static final Map<String, String> BRAND_DOMAINS = new LinkedHashMap<>();
    static {
        BRAND_DOMAINS.put("paypal",        "paypal.com");
        BRAND_DOMAINS.put("amazon",        "amazon.com");
        BRAND_DOMAINS.put("microsoft",     "microsoft.com");
        BRAND_DOMAINS.put("google",        "google.com");
        BRAND_DOMAINS.put("apple",         "apple.com");
        BRAND_DOMAINS.put("facebook",      "facebook.com");
        BRAND_DOMAINS.put("twitter",       "twitter.com");
        BRAND_DOMAINS.put("linkedin",      "linkedin.com");
        BRAND_DOMAINS.put("ebay",          "ebay.com");
        BRAND_DOMAINS.put("netflix",       "netflix.com");
        BRAND_DOMAINS.put("instagram",     "instagram.com");
        BRAND_DOMAINS.put("dropbox",       "dropbox.com");
        BRAND_DOMAINS.put("chase",         "chase.com");
        BRAND_DOMAINS.put("wellsfargo",    "wellsfargo.com");
        BRAND_DOMAINS.put("bankofamerica", "bankofamerica.com");
        BRAND_DOMAINS.put("dhl",           "dhl.com");
        BRAND_DOMAINS.put("fedex",         "fedex.com");
        BRAND_DOMAINS.put("ups",           "ups.com");
        BRAND_DOMAINS.put("usps",          "usps.com");
        BRAND_DOMAINS.put("irs",           "irs.gov");
        BRAND_DOMAINS.put("github",        "github.com");
        BRAND_DOMAINS.put("zoom",          "zoom.us");
        BRAND_DOMAINS.put("docusign",      "docusign.com");
        BRAND_DOMAINS.put("adobe",         "adobe.com");
        BRAND_DOMAINS.put("spotify",       "spotify.com");
        BRAND_DOMAINS.put("steam",         "steampowered.com");   // only once
    }

    public UrlAnalysisResult analyzeUrl(String url) {
        UrlAnalysisResult result = new UrlAnalysisResult();
        if (url == null || url.isBlank()) return result;

        analyzeIp(url, result);
        analyzeEntropy(url, result);
        analyzeStructure(url, result);
        analyzeBrand(url, result);
        analyzeHomoglyphs(url, result);
        analyzePath(url, result);
        analyzeTld(url, result);

        result.calculateTotal();
        return result;
    }

    private void analyzeIp(String url, UrlAnalysisResult r) {
        Matcher m = IP_PATTERN.matcher(url);
        if (m.find()) {
            String ip = m.group(1);
            if (ip != null) {
                if (PRIVATE_IP.matcher(ip).matches()) {
                    r.ipDetectionScore = 2;
                    r.issues.add("Private IP address in URL: " + ip);
                } else {
                    r.ipDetectionScore = 4;
                    r.issues.add("Direct public IP (legitimate services never host on raw IP): " + ip);
                }
            }
        }
    }

    private void analyzeEntropy(String url, UrlAnalysisResult r) {
        String domain = UrlExtractor.extractDomain(url).replace("www.", "");
        int lastDot = domain.lastIndexOf('.');
        String domainBody = lastDot > 0 ? domain.substring(0, lastDot) : domain;

        double entropy = calculateShannonEntropy(domainBody);
        if (entropy > 4.0) {
            r.entropyScore = 4;
            r.issues.add("Very high entropy domain (likely machine-generated): "
                    + domain + " (H=" + String.format("%.2f", entropy) + ")");
        } else if (entropy > 3.5) {
            r.entropyScore = 2;
            r.issues.add("Elevated domain entropy: "
                    + domain + " (H=" + String.format("%.2f", entropy) + ")");
        }

        // Numeric-heavy domain
        long digits = domainBody.chars().filter(Character::isDigit).count();
        if (domainBody.length() > 0 && (double) digits / domainBody.length() > 0.4) {
            r.entropyScore += 2;
            r.issues.add("Domain is heavily numeric ("
                    + digits + "/" + domainBody.length() + " chars are digits): " + domain);
        }
    }

    private void analyzeStructure(String url, UrlAnalysisResult r) {
        if (url.length() > 100) {
            r.structuralScore += 2;
            r.issues.add("Very long URL (" + url.length() + " chars)");
        } else if (url.length() > 75) {
            r.structuralScore += 1;
            r.issues.add("Long URL (" + url.length() + " chars)");
        }

        if (url.contains("@")) {
            r.structuralScore += 3;
            r.issues.add("'@' symbol in URL hides the real destination domain");
        }

        long encCount = url.chars().filter(c -> c == '%').count();
        if (encCount > 5) {
            r.structuralScore += 3;
            r.issues.add("Heavy URL encoding (" + encCount + " encoded chars) - common obfuscation");
        } else if (encCount > 2) {
            r.structuralScore += 1;
            r.issues.add("URL contains encoded characters (" + encCount + ")");
        }

        String domain = UrlExtractor.extractDomain(url);
        int parts = domain.split("\\.").length;
        if (parts > 4) {
            r.structuralScore += 3;
            r.issues.add("Deep subdomain chain (" + (parts - 1) + " levels): " + domain);
        } else if (parts > 3) {
            r.structuralScore += 2;
            r.issues.add("Multiple subdomains: " + domain);
        }

        if (url.matches(".*:\\d{4,}.*") && !url.contains(":80") && !url.contains(":443")) {
            r.structuralScore += 2;
            r.issues.add("Non-standard port in URL");
        }

        if (!UrlExtractor.isHttps(url)) {
            r.structuralScore += 1;
            r.issues.add("Unencrypted HTTP connection");
        }

        if (UrlExtractor.isUrlShortener(url)) {
            r.structuralScore += 3;
            r.issues.add("URL shortener detected (real destination is hidden)");
        }

        String path = url.replaceFirst("(?i)^https?://[^/]+", "");
        if (path.contains("//")) {
            r.structuralScore += 1;
            r.issues.add("Double slashes in URL path (possible obfuscation)");
        }
    }

    private void analyzeBrand(String url, UrlAnalysisResult r) {
        String domain = UrlExtractor.extractDomain(url).toLowerCase();
        String normalized = domain
                .replace('0', 'o').replace('1', 'l').replace('5', 's')
                .replace('8', 'b').replace('3', 'e').replace('7', 't')
                .replace('4', 'a').replace('6', 'g');

        for (Map.Entry<String, String> entry : BRAND_DOMAINS.entrySet()) {
            String brandKey      = entry.getKey();
            String legitimateDom = entry.getValue();
            if (normalized.contains(brandKey)) {
                if (!domain.equals(legitimateDom) && !domain.endsWith("." + legitimateDom)) {
                    r.brandMismatchScore = 4;
                    r.issues.add("Brand impersonation: '"
                            + domain + "' impersonates " + legitimateDom);
                }
                break;
            }
        }
    }

    private void analyzeHomoglyphs(String url, UrlAnalysisResult r) {
        String domain = UrlExtractor.extractDomain(url).toLowerCase();

        if (domain.contains("xn--")) {
            r.homoglyphScore += 4;
            r.issues.add("Punycode/IDN domain (possible homoglyph attack): " + domain);
            return;
        }

        boolean hasCyrillic = false;
        for (char c : domain.toCharArray()) {
            if (c == '\u0430' || c == '\u0435' || c == '\u043E'
                    || c == '\u0440' || c == '\u0441' || c == '\u0445') {
                hasCyrillic = true;
                break;
            }
        }
        if (hasCyrillic) {
            r.homoglyphScore += 4;
            r.issues.add("Cyrillic homoglyph characters in domain: " + domain);
        }

        if (r.homoglyphScore == 0 && r.brandMismatchScore == 0) {
            String subst = domain.replace("rn", "m").replace("vv", "w")
                    .replace("cl", "d").replace("1", "l").replace("0", "o");
            for (Map.Entry<String, String> entry : BRAND_DOMAINS.entrySet()) {
                if (subst.contains(entry.getKey())
                        && !domain.equals(entry.getValue())
                        && !domain.endsWith("." + entry.getValue())) {
                    r.homoglyphScore += 3;
                    r.issues.add("Character-substitution homoglyph attack detected: '"
                            + domain + "' may impersonate " + entry.getValue());
                    break;
                }
            }
        }
    }

    private void analyzePath(String url, UrlAnalysisResult r) {
        String afterDomain = url.replaceFirst("(?i)^https?://[^/]+", "");
        if (afterDomain.isEmpty()) return;

        Matcher m = SUSPICIOUS_PATH_KEYWORDS.matcher(afterDomain);
        Set<String> found = new HashSet<>();
        while (m.find()) found.add(m.group(1).toLowerCase());

        if (found.size() >= 3) {
            r.pathScore += 3;
            r.issues.add("Multiple phishing-related keywords in URL path: " + found);
        } else if (!found.isEmpty()) {
            r.pathScore += 1;
            r.issues.add("Suspicious keyword(s) in URL path: " + found);
        }

        if (afterDomain.matches("(?i).*[?&](url|redirect|goto|redir|return|next|dest)=.*")) {
            r.pathScore += 2;
            r.issues.add("Open redirect parameter detected in URL");
        }
    }

    private void analyzeTld(String url, UrlAnalysisResult r) {
        String domain = UrlExtractor.extractDomain(url).toLowerCase();
        int lastDot = domain.lastIndexOf('.');
        if (lastDot < 0) return;
        String tld = domain.substring(lastDot + 1);
        if (RISKY_TLDS.contains(tld)) {
            r.tldScore += 2;
            r.issues.add("High-risk TLD '." + tld + "' frequently used in phishing");
        }
    }

    private double calculateShannonEntropy(String text) {
        if (text == null || text.isEmpty()) return 0.0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : text.toCharArray())
            freq.put(c, freq.getOrDefault(c, 0) + 1);
        double entropy = 0.0;
        int len = text.length();
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy -= p * Math.log(p) / Math.log(2);
        }
        return entropy;
    }
}
