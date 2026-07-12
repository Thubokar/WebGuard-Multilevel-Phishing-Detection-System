package com.phishingdetector.utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enhanced URL extraction utility that handles multiple URL formats
 * including HTML links, shortened URLs, and obfuscated URLs.
 */
public class UrlExtractor {
    
    // Multiple patterns to catch different URL formats
    private static final Pattern PLAIN_URL = Pattern.compile(
        "(https?://[^\\s<>\"'()\\[\\]{}]+)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern WWW_URL = Pattern.compile(
        "(www\\.[^\\s<>\"'()\\[\\]{}]+\\.[a-z]{2,6}[^\\s<>\"'()\\[\\]{}]*)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern HTML_HREF = Pattern.compile(
        "<a[^>]+href=[\"']([^\"']+)[\"']",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern HTML_SRC = Pattern.compile(
        "src=[\"']([^\"']+)[\"']",
        Pattern.CASE_INSENSITIVE
    );
    
    /**
     * Extract all URLs from text content (plain text or HTML).
     * Returns unique URLs found using multiple detection patterns.
     * 
     * @param content Email body or text content
     * @return List of unique URLs found
     */
    public static List<String> extractUrls(String content) {
        if (content == null || content.isEmpty()) {
            return new ArrayList<>();
        }
        
        Set<String> urls = new HashSet<>();
        
        // Extract from HTML href attributes
        urls.addAll(extractWithPattern(content, HTML_HREF, 1));
        
        // Extract from HTML src attributes (images, scripts)
        urls.addAll(extractWithPattern(content, HTML_SRC, 1));
        
        // Extract plain HTTP(S) URLs
        urls.addAll(extractWithPattern(content, PLAIN_URL, 1));
        
        // Extract www. URLs
        List<String> wwwUrls = extractWithPattern(content, WWW_URL, 1);
        for (String url : wwwUrls) {
            // Add http:// prefix to www. URLs
            urls.add("http://" + url);
        }
        
        // Clean and filter URLs
        List<String> cleanedUrls = new ArrayList<>();
        for (String url : urls) {
            String cleaned = cleanUrl(url);
            if (isValidUrl(cleaned)) {
                cleanedUrls.add(cleaned);
            }
        }
        
        return cleanedUrls;
    }
    
    /**
     * Extract URLs using a specific regex pattern.
     */
    private static List<String> extractWithPattern(String content, Pattern pattern, int group) {
        List<String> results = new ArrayList<>();
        Matcher matcher = pattern.matcher(content);
        
        while (matcher.find()) {
            String url = matcher.group(group);
            if (url != null && !url.isEmpty()) {
                results.add(url);
            }
        }
        
        return results;
    }
    
    /**
     * Clean URL by removing trailing punctuation and whitespace.
     */
    private static String cleanUrl(String url) {
        if (url == null || url.isEmpty()) {
            return url;
        }
        
        url = url.trim();
        
        // Remove trailing punctuation that's not part of URL
        while (url.length() > 0 && 
               (url.endsWith(".") || url.endsWith(",") || 
                url.endsWith(";") || url.endsWith("!") || 
                url.endsWith("?") || url.endsWith(")"))) {
            url = url.substring(0, url.length() - 1);
        }
        
        // Decode URL-encoded characters
        url = SecurityUtils.decodeUrl(url);
        
        return url;
    }
    
    /**
     * Validate if string is a proper URL.
     */
    private static boolean isValidUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        // Must start with http://, https://, or www.
        if (!url.toLowerCase().startsWith("http://") && 
            !url.toLowerCase().startsWith("https://") &&
            !url.toLowerCase().startsWith("www.")) {
            return false;
        }
        
        // Must have at least one dot (domain.tld)
        if (!url.contains(".")) {
            return false;
        }
        
        // Filter out obviously invalid URLs
        if (url.length() < 10) {  // Minimum: http://a.b
            return false;
        }
        
        // Filter out data: and javascript: URIs
        String lower = url.toLowerCase();
        if (lower.startsWith("javascript:") || lower.startsWith("data:")) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if URL uses a known URL shortener service.
     * These services hide the real destination and are commonly used in phishing.
     * 
     * @param url URL to check
     * @return true if URL is from a shortener service
     */
    public static boolean isUrlShortener(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        String domain = extractDomain(url).toLowerCase();
        
        String[] shorteners = {
            "bit.ly", "bitly.com",
            "tinyurl.com",
            "goo.gl",
            "ow.ly",
            "t.co",
            "is.gd",
            "buff.ly",
            "adf.ly",
            "bl.ink",
            "lnkd.in",
            "short.link",
            "tiny.cc",
            "rb.gy",
            "cutt.ly",
            "shorturl.at"
        };
        
        for (String shortener : shorteners) {
            if (domain.equals(shortener) || domain.endsWith("." + shortener)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Extract domain from URL.
     * 
     * @param url Full URL
     * @return Domain name (e.g., "example.com")
     */
    public static String extractDomain(String url) {
        if (url == null || url.isEmpty()) {
            return "";
        }
        
        // Remove protocol
        String temp = url.replaceFirst("(?i)^https?://", "");
        temp = temp.replaceFirst("(?i)^www\\.", "");
        
        // Remove path, query, fragment
        int slashIndex = temp.indexOf('/');
        if (slashIndex > -1) {
            temp = temp.substring(0, slashIndex);
        }
        
        int questionIndex = temp.indexOf('?');
        if (questionIndex > -1) {
            temp = temp.substring(0, questionIndex);
        }
        
        int hashIndex = temp.indexOf('#');
        if (hashIndex > -1) {
            temp = temp.substring(0, hashIndex);
        }
        
        // Remove port
        int colonIndex = temp.indexOf(':');
        if (colonIndex > -1) {
            temp = temp.substring(0, colonIndex);
        }
        
        return temp.toLowerCase();
    }
    
    /**
     * Check if URL uses HTTPS (secure connection).
     * HTTP is a security warning sign for sensitive sites.
     * 
     * @param url URL to check
     * @return true if HTTPS, false if HTTP
     */
    public static boolean isHttps(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        return url.toLowerCase().startsWith("https://");
    }
    
    /**
     * Extract all query parameters from URL as key-value pairs.
     * Useful for analyzing suspicious tracking parameters.
     * 
     * @param url URL with query string
     * @return List of "key=value" parameter strings
     */
    public static List<String> extractQueryParams(String url) {
        List<String> params = new ArrayList<>();
        
        if (url == null || url.isEmpty()) {
            return params;
        }
        
        int questionIndex = url.indexOf('?');
        if (questionIndex == -1) {
            return params;
        }
        
        String queryString = url.substring(questionIndex + 1);
        
        // Remove fragment
        int hashIndex = queryString.indexOf('#');
        if (hashIndex > -1) {
            queryString = queryString.substring(0, hashIndex);
        }
        
        // Split by & and add to list
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            if (!pair.trim().isEmpty()) {
                params.add(pair);
            }
        }
        
        return params;
    }
}
