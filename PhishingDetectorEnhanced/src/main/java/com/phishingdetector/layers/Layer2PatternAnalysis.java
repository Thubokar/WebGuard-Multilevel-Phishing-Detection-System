package com.phishingdetector.layers;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.phishingdetector.utils.SecurityUtils;

/**
 * Layer 2 – regex / pattern analysis.
 */
public class Layer2PatternAnalysis {

    private static final Pattern URGENCY_PATTERN = Pattern.compile(
        "(?i)(urgent|immediate|emergency|last chance|warning|24 hours|48 hours|account (suspended|locked))"
    );

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        "(?i)(enter|confirm|type|provide|submit)\\s*(your)?\\s*(password|pin|otp|security code)"
    );

    private static final Pattern AUTHORITY_PATTERN = Pattern.compile(
        "(?i)(irs|fbi|cia|bank manager|support|hr department|it support|security team)"
    );

    private static final Pattern MONEY_PATTERN = Pattern.compile(
        "(?i)(wire transfer|money|gift card|bitcoin|crypto|itunes|western union|moneygram)"
    );

    private static final Pattern CREDIT_CARD_PATTERN =
        Pattern.compile("\\b(?:\\d{4}[\\s-]?){3}\\d{1,4}\\b");

    private static final Pattern PHONE_PATTERN =
        Pattern.compile("\\b\\d{10,15}\\b");

    private static final Pattern EXCESSIVE_PUNCTUATION =
        Pattern.compile("!{2,}|\\?{2,}");

    public static class PatternResult {
        public boolean hasUrgency;
        public boolean hasCredentialRequest;
        public boolean hasAuthorityImpersonation;
        public boolean hasMoneyRequest;
        public boolean hasCreditCard;
        public boolean hasExcessivePunctuation;
        public boolean hasRepetition;
        public boolean hasExcessiveCaps;
        public boolean hasSenderSpoofing;
        public boolean hasSuspiciousPhone;
        public int score = 0;
    }

    public PatternResult analyzePatterns(String emailBody, String normalizedBody, String from) {
        PatternResult result = new PatternResult();

        if (emailBody == null) emailBody = "";
        if (normalizedBody == null) normalizedBody = emailBody.toLowerCase();
        if (from == null) from = "";

        // urgency
        if (URGENCY_PATTERN.matcher(normalizedBody).find()) {
            result.hasUrgency = true;
            result.score += 3;
        }

        // credential / password
        if (PASSWORD_PATTERN.matcher(emailBody).find()) {
            result.hasCredentialRequest = true;
            result.score += 3;
        }

        // authority impersonation
        if (AUTHORITY_PATTERN.matcher(normalizedBody).find()) {
            result.hasAuthorityImpersonation = true;
            result.score += 2;
        }

        // money / payment
        if (MONEY_PATTERN.matcher(normalizedBody).find()) {
            result.hasMoneyRequest = true;
            result.score += 3;
        }

        // credit card (Luhn)
        Matcher ccMatcher = CREDIT_CARD_PATTERN.matcher(emailBody);
        while (ccMatcher.find()) {
            String cc = ccMatcher.group().replaceAll("[\\s-]", "");
            if (isValidLuhn(cc)) {
                result.hasCreditCard = true;
                result.score += 4;
                break;
            }
        }

        // phone
        if (PHONE_PATTERN.matcher(emailBody).find()) {
            result.hasSuspiciousPhone = true;
            result.score += 2;
        }

        // punctuation
        if (EXCESSIVE_PUNCTUATION.matcher(emailBody).find() ||
            countExclamations(emailBody) >= 5) {
            result.hasExcessivePunctuation = true;
            result.score += 2;
        }

        // repetition
        if (countRepeatedWords(normalizedBody, "click", 3) ||
            countRepeatedWords(normalizedBody, "verify", 3)) {
            result.hasRepetition = true;
            result.score += 2;
        }

        // CAPS
        if (getUppercaseRatio(emailBody) > 0.3) {
            result.hasExcessiveCaps = true;
            result.score += 1;
        }

        // sender spoofing (improved)
        if (isSenderSpoofed(from, normalizedBody)) {
            result.hasSenderSpoofing = true;
            result.score += 3;
        }

        return result;
    }

    private boolean isSenderSpoofed(String from, String normalizedBody) {
        String email = SecurityUtils.extractEmailAddress(from).toLowerCase();
        String domain = SecurityUtils.extractDomainFromEmail(email);

        boolean mentionsGoogle = normalizedBody.contains("google");
        boolean mentionsMicrosoft = normalizedBody.contains("microsoft");
        boolean mentionsPaypal = normalizedBody.contains("paypal");
        boolean mentionsAmazon = normalizedBody.contains("amazon");

        if (mentionsGoogle && (domain.isEmpty() || !domain.contains("google.com"))) return true;
        if (mentionsMicrosoft && (domain.isEmpty() || !domain.contains("microsoft.com"))) return true;
        if (mentionsPaypal && (domain.isEmpty() || !domain.contains("paypal.com"))) return true;
        if (mentionsAmazon && (domain.isEmpty() || !domain.contains("amazon.com"))) return true;

        return false;
    }

    private boolean isValidLuhn(String cardNumber) {
        if (cardNumber == null || cardNumber.length() < 13 || cardNumber.length() > 19) return false;
        int sum = 0;
        boolean alternate = false;
        for (int i = cardNumber.length() - 1; i >= 0; i--) {
            int n = Character.getNumericValue(cardNumber.charAt(i));
            if (n < 0 || n > 9) return false;
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    private int countExclamations(String text) {
        if (text == null || text.isEmpty()) return 0;
        return (int) text.chars().filter(ch -> ch == '!').count();
    }

    private boolean countRepeatedWords(String text, String word, int threshold) {
        if (text == null || word == null || word.isEmpty()) return false;
        long count = Arrays.stream(text.toLowerCase().split("\\s+"))
                .filter(w -> w.contains(word.toLowerCase()))
                .count();
        return count >= threshold;
    }

    private double getUppercaseRatio(String text) {
        if (text == null || text.isEmpty()) return 0.0;
        long upper = text.chars().filter(Character::isUpperCase).count();
        int total = text.length();
        return total > 0 ? (double) upper / total : 0.0;
    }
}
