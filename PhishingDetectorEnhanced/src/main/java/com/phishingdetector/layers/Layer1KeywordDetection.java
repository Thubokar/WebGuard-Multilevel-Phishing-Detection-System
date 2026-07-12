package com.phishingdetector.layers;

import java.util.*;

import com.phishingdetector.utils.SecurityUtils;

/**
 * Layer 1 – keyword detection using Aho-Corasick, plus inline sender
 * brand-mismatch check.
 *
 * SENDER SCORING RULES (matches user requirement):
 *   • Sender email is in Supabase trusted_senders OR domain matches brand
 *     → TRUSTED  → score =  0  (safe, no points added)
 *   • Body mentions a brand but sender domain does NOT match
 *     → SPOOFED  → score = +5  (not safe, points added)
 *   • No brand mention
 *     → UNKNOWN  → score =  0
 *
 * NOTE: The -2 "bonus" that was here before has been removed.
 *       Trusted senders simply contribute 0 to the risk score.
 */
public class Layer1KeywordDetection {

    // ---- Brand → expected sender domain ----
    private static final Map<String, String> BRAND_DOMAINS = new LinkedHashMap<>();
    static {
        BRAND_DOMAINS.put("paypal",        "paypal.com");
        BRAND_DOMAINS.put("amazon",        "amazon.com");
        BRAND_DOMAINS.put("microsoft",     "microsoft.com");
        BRAND_DOMAINS.put("google",        "google.com");
        BRAND_DOMAINS.put("apple",         "apple.com");
        BRAND_DOMAINS.put("facebook",      "facebook.com");
        BRAND_DOMAINS.put("netflix",       "netflix.com");
        BRAND_DOMAINS.put("ebay",          "ebay.com");
        BRAND_DOMAINS.put("instagram",     "instagram.com");
        BRAND_DOMAINS.put("dropbox",       "dropbox.com");
        BRAND_DOMAINS.put("linkedin",      "linkedin.com");
        BRAND_DOMAINS.put("twitter",       "twitter.com");
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
        BRAND_DOMAINS.put("steam",         "steampowered.com");
    }

    // ---- Aho-Corasick state ----
    private final AhoCorasick aho;
    private final List<String> keywords;
    private final boolean debug;

    public Layer1KeywordDetection(List<String> keywordList) {
        this(keywordList, false);
    }

    public Layer1KeywordDetection(List<String> keywordList, boolean debug) {
        this.keywords = new ArrayList<>(keywordList != null ? keywordList : Collections.emptyList());
        this.aho   = new AhoCorasick();
        this.debug = debug;

        int addedCount = 0;
        for (String keyword : keywords) {
            if (keyword == null) continue;
            String normalized = keyword.trim().toLowerCase();
            if (!normalized.isEmpty()) {
                aho.addPattern(normalized);
                addedCount++;
            }
        }
        aho.build();

        if (debug) {
            System.out.println("[Layer1] Built trie with " + addedCount + " keywords");
        }
    }

    // =========================================================================
    // Combined Layer 1 entry point (keyword + sender check)
    // =========================================================================

    /**
     * Run full Layer 1 analysis: keyword detection + sender brand check.
     * @param normalizedBody  lower-cased, HTML-stripped email body
     * @param from            raw "From" header value
     */
    public Layer1Result analyze(String normalizedBody, String from) {
        Layer1Result result = new Layer1Result();
        result.keywords     = detectKeywords(normalizedBody);
        result.keywordScore = calculateScore(result.keywords);

        SenderCheckResult sc = checkSenderBrand(result.keywords, normalizedBody, from);
        result.senderScore   = sc.score;
        result.senderSpoofed = sc.spoofed;
        result.senderTrusted = sc.trusted;
        result.senderEmail   = sc.senderEmail;
        result.senderReason  = sc.reason;

        return result;
    }

    public static class Layer1Result {
        public Set<String> keywords     = new HashSet<>();
        public int keywordScore         = 0;
        public int senderScore          = 0;      // 0 (trusted/unknown) or +5 (spoofed)
        public boolean senderSpoofed    = false;
        public boolean senderTrusted    = false;
        public String  senderEmail      = "";
        public String  senderReason     = "";

        /**
         * Combined keyword + sender score, capped at 15.
         * senderScore is never negative so this will always be >= 0.
         */
        public int totalScore() {
            return Math.min(keywordScore + senderScore, 15);
        }
    }

    // =========================================================================
    // Keyword detection
    // =========================================================================

    /** Detect keywords in normalized email body using Aho-Corasick. */
    public Set<String> detectKeywords(String normalizedBody) {
        if (normalizedBody == null || normalizedBody.isEmpty()) {
            if (debug) System.out.println("[Layer1] Empty body, no keywords");
            return Collections.emptySet();
        }
        Set<String> results = new HashSet<>(aho.search(normalizedBody));
        if (debug) System.out.println("[Layer1] Keywords found: " + results.size());
        return results;
    }

    /**
     * Calculate score from detected keywords.
     * 2 pts per keyword, max 5 keywords → max 10 pts.
     */
    public int calculateScore(Set<String> detectedKeywords) {
        if (detectedKeywords == null || detectedKeywords.isEmpty()) return 0;
        int score = 0, count = 0;
        for (String ignored : detectedKeywords) {
            score += 2;
            if (++count >= 5) break;
        }
        return Math.min(score, 10);
    }

    // =========================================================================
    // Sender brand check
    // =========================================================================

    /**
     * Check whether the email claims to be from a known brand but the sender
     * domain does not match that brand's canonical domain.
     *
     * SCORING (per user requirement):
     *   TRUSTED  → score = 0  (safe; no points)
     *   SPOOFED  → score = +5 (not safe; adds to risk)
     *   UNKNOWN  → score = 0
     *
     * This method is also the fallback when no Supabase trusted-sender match
     * was found.  PhishingDetectionService calls SenderVerificationService
     * first (exact email match against Supabase), then calls this only when
     * the Supabase check returns UNKNOWN.
     *
     * @param detectedKeywords keywords found by Aho-Corasick
     * @param normalizedBody   lower-cased, HTML-stripped body
     * @param from             raw "From" header
     */
    public SenderCheckResult checkSenderBrand(Set<String> detectedKeywords,
                                              String normalizedBody,
                                              String from) {
        SenderCheckResult result = new SenderCheckResult();
        if (from == null) from = "";
        if (normalizedBody == null) normalizedBody = "";

        String email  = SecurityUtils.extractEmailAddress(from).toLowerCase().trim();
        String domain = SecurityUtils.extractDomainFromEmail(email);
        result.senderEmail = email;

        // Build a combined set: brand names from keywords + brand names from body
        Set<String> mentionedBrands = new LinkedHashSet<>();

        for (String kw : detectedKeywords) {
            String kwLower = kw.toLowerCase();
            for (String brand : BRAND_DOMAINS.keySet()) {
                if (kwLower.contains(brand)) mentionedBrands.add(brand);
            }
        }
        for (String brand : BRAND_DOMAINS.keySet()) {
            if (normalizedBody.contains(brand)) mentionedBrands.add(brand);
        }

        if (mentionedBrands.isEmpty()) {
            result.reason = "No brand mention detected in email body";
            return result;   // UNKNOWN, score = 0
        }

        for (String brand : mentionedBrands) {
            String expectedDomain = BRAND_DOMAINS.get(brand);

            boolean domainMatches = !domain.isEmpty()
                    && (domain.equals(expectedDomain) || domain.endsWith("." + expectedDomain));

            if (domainMatches) {
                // Sender domain matches a brand mentioned in the email → trusted
                // Score = 0 (trusted = safe = no risk points added)
                result.trusted = true;
                result.score   = 0;
                result.reason  = "Sender @" + domain + " legitimately matches brand '" + brand + "'";
                return result;
            }
        }

        // Body mentions at least one brand but no domain matched → spoofing
        String firstBrand = mentionedBrands.iterator().next();
        result.spoofed = true;
        result.score   = 5;
        result.reason  = "Email body mentions '" + firstBrand
                + "' but sender domain is '" + (domain.isEmpty() ? "(unknown)" : domain)
                + "' (expected @" + BRAND_DOMAINS.get(firstBrand) + ")";
        return result;
    }

    public static class SenderCheckResult {
        public boolean spoofed     = false;
        public boolean trusted     = false;
        public String  senderEmail = "";
        public String  reason      = "";
        public int     score       = 0;   // always >= 0
    }

    // =========================================================================
    // Aho-Corasick implementation
    // =========================================================================

    public static class AhoCorasick {
        private final Node root;

        public AhoCorasick() { root = new Node(); }

        public void addPattern(String pattern) {
            Node current = root;
            for (char c : pattern.toCharArray()) {
                current = current.getOrCreateChild(c);
            }
            current.isEndOfPattern = true;
            current.pattern = pattern;
        }

        public void build() {
            Queue<Node> queue = new LinkedList<>();
            root.failureLink = root;
            for (Node child : root.children.values()) {
                child.failureLink = root;
                queue.offer(child);
            }
            while (!queue.isEmpty()) {
                Node node = queue.poll();
                for (Map.Entry<Character, Node> entry : node.children.entrySet()) {
                    char c     = entry.getKey();
                    Node child = entry.getValue();
                    queue.offer(child);

                    Node fail = node.failureLink;
                    while (fail != root && !fail.children.containsKey(c)) {
                        fail = fail.failureLink;
                    }
                    Node linked = fail.children.get(c);
                    child.failureLink = (linked != null && linked != child) ? linked : root;
                }
            }
        }

        public Set<String> search(String text) {
            Set<String> matches = new HashSet<>();
            Node current = root;

            for (char c : text.toCharArray()) {
                while (current != root && !current.children.containsKey(c)) {
                    current = current.failureLink;
                }
                Node next = current.children.get(c);
                current = (next != null) ? next : root;

                Node temp = current;
                while (temp != root) {
                    if (temp.isEndOfPattern && temp.pattern != null) {
                        matches.add(temp.pattern);
                    }
                    temp = temp.failureLink;
                }
            }
            return matches;
        }

        public static class Node {
            Map<Character, Node> children = new HashMap<>();
            Node    failureLink;
            boolean isEndOfPattern = false;
            String  pattern        = null;

            Node getOrCreateChild(char c) {
                return children.computeIfAbsent(c, k -> new Node());
            }
        }
    }
}
