package com.phishingdetector.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Security utility methods for input validation, sanitization, and XSS prevention.
 */
public class SecurityUtils {
    
    // HTML entities that need to be escaped
    private static final Pattern HTML_TAGS = Pattern.compile("<[^>]*>");
    
    /**
     * Escape HTML special characters to prevent XSS attacks.
     * Use this before displaying user input in JSP pages.
     * 
     * @param input Raw user input
     * @return HTML-safe string
     */
    public static String escapeHtml(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;")
            .replace("/", "&#x2F;");
    }
    
    /**
     * Strip HTML tags from input while preserving text content.
     * Useful for analyzing HTML email bodies.
     * 
     * @param html HTML content
     * @return Plain text without HTML tags
     */
    public static String stripHtmlTags(String html) {
        if (html == null || html.isEmpty()) {
            return html;
        }
        
        // Remove HTML tags
        String text = HTML_TAGS.matcher(html).replaceAll(" ");
        
        // Decode common HTML entities
        text = text.replace("&nbsp;", " ")
                   .replace("&amp;", "&")
                   .replace("&lt;", "<")
                   .replace("&gt;", ">")
                   .replace("&quot;", "\"")
                   .replace("&#39;", "'")
                   .replace("&#x27;", "'");
        
        // Clean up multiple spaces
        text = text.replaceAll("\\s+", " ").trim();
        
        return text;
    }
    
    /**
     * Decode URL-encoded strings safely.
     * Handles common URL encoding and obfuscation attempts.
     * 
     * @param encoded URL-encoded string
     * @return Decoded string
     */
    public static String decodeUrl(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return encoded;
        }
        
        try {
            // Decode once
            String decoded = URLDecoder.decode(encoded, "UTF-8");
            
            // Check for double encoding (phishing technique)
            if (!decoded.equals(encoded) && decoded.contains("%")) {
                // Try decoding again
                decoded = URLDecoder.decode(decoded, "UTF-8");
            }
            
            return decoded;
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            // If decoding fails, return original
            return encoded;
        }
    }
    
    /**
     * Validate email body length to prevent memory exhaustion attacks.
     * 
     * @param body Email body content
     * @param maxLength Maximum allowed length in characters
     * @return true if valid, false if too long
     */
    public static boolean isValidBodyLength(String body, long maxLength) {
        if (body == null) {
            return true;
        }
        return body.length() <= maxLength;
    }
    
    /**
     * Sanitize filename to prevent directory traversal attacks.
     * 
     * @param filename User-provided filename
     * @return Safe filename without path separators
     */
    public static String sanitizeFilename(String filename) {
        if (filename == null || filename.isEmpty()) {
            return "unknown";
        }
        
        // Remove path separators and parent directory references
        filename = filename.replaceAll("[\\\\/]", "_")
                          .replaceAll("\\.\\.", "_")
                          .replaceAll("[\\x00-\\x1F\\x7F]", "");  // Remove control chars
        
        // Limit length
        if (filename.length() > 255) {
            filename = filename.substring(0, 255);
        }
        
        return filename;
    }
    
    /**
     * Extract email address from "Display Name <email@example.com>" format.
     * 
     * @param from From header value
     * @return Email address without display name
     */
    public static String extractEmailAddress(String from) {
        if (from == null || from.isEmpty()) {
            return "";
        }
        
        // Pattern: "Display Name" <email@example.com> or Display Name <email@example.com>
        Pattern pattern = Pattern.compile("<([^>]+)>");
        Matcher matcher = pattern.matcher(from);
        
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        
        // If no angle brackets, assume it's already just an email
        return from.trim();
    }
    
    /**
     * Extract display name from "Display Name <email@example.com>" format.
     * 
     * @param from From header value
     * @return Display name (empty string if not present)
     */
    public static String extractDisplayName(String from) {
        if (from == null || from.isEmpty()) {
            return "";
        }
        
        // Pattern: "Display Name" <email@example.com>
        Pattern quotedPattern = Pattern.compile("\"([^\"]+)\"\\s*<");
        Matcher quotedMatcher = quotedPattern.matcher(from);
        
        if (quotedMatcher.find()) {
            return quotedMatcher.group(1).trim();
        }
        
        // Pattern: Display Name <email@example.com> (without quotes)
        Pattern unquotedPattern = Pattern.compile("^([^<]+)<");
        Matcher unquotedMatcher = unquotedPattern.matcher(from);
        
        if (unquotedMatcher.find()) {
            return unquotedMatcher.group(1).trim();
        }
        
        return "";
    }
    
    /**
     * Extract domain from email address.
     * 
     * @param email Email address
     * @return Domain part (e.g., "example.com")
     */
    public static String extractDomainFromEmail(String email) {
        if (email == null || email.isEmpty()) {
            return "";
        }
        
        int atIndex = email.lastIndexOf('@');
        if (atIndex > 0 && atIndex < email.length() - 1) {
            return email.substring(atIndex + 1).toLowerCase();
        }
        
        return "";
    }
    
    /**
     * Check if a string contains only printable ASCII characters.
     * Non-printable characters might indicate obfuscation attempts.
     * 
     * @param text Text to check
     * @return true if text contains only printable ASCII
     */
    public static boolean isPrintableAscii(String text) {
        if (text == null || text.isEmpty()) {
            return true;
        }
        
        for (char c : text.toCharArray()) {
            if (c < 32 || c > 126) {
                return false;
            }
        }
        
        return true;
    }
}
