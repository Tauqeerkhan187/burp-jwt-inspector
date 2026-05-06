package com.tk.jwtinspector.detection;

import com.nimbusds.jwt.JWTParser;

import java.text.ParseException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds JWT-shaped strings in arbitrary text (headers, bodies, params)
 * and validates them by attempting structural parse.
 *
 * A JWT is three base64url-encoded segments separated by dots:
 *  header.payload.signature
 * The signature is optional in alg:none tokens, leaving a trailing dot.
 *
 * Shape match is fast; structural validation (parse) catches false positives
 * like base64 image data or random dotted strings.
 */

public class JWTDetector {

    // 3 base64url segments. last one may be empty (alg:none tokens).
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]*"
    );

    /**
     * Extracts all JWT-shaped strings from the given text.
     * Returns only structurally valid tokens.
     */
    public java.util.List<String> findTokens(String text) {
        if (text == null || text.isEmpty()) return java.util.List.of();

        java.util.List<String> results = new java.util.ArrayList<>();
        Matcher matcher = JWT_PATTERN.matcher(text);
        while (matcher.find()) {
            String candidate = matcher.group();
            if (isStructurallyValid(candidate)) {
                results.add(candidate);
            }
        }
        return results;
    }

    /**
     * Confirms a candidate parses as a JWT. We don't verify the signature
     * (we wouldn't have the key), only that the structure is correct.
     */

    private boolean isStructurallyValid(String candidate) {
        try {
            JWTParser.parse(candidate);
            return true;
        } catch (ParseException e) {
            return false;
        }
    }

    /**
     * Checks if a string IS a JWT (vs contains one).
     * Useful when checking individual header vals.
     */
    public boolean isJWT(String value) {
        if (value == null) return false;
        // Strip "Bearer " prefix if present
        String cleaned = value.startsWith("Bearer ") ? value.substring(7) : value;
        return JWT_PATTERN.matcher(cleaned).matches() && isStructurallyValid(cleaned);
    }

    /**
     * Strips "Bearer " prefix and trims whitespace.
     */
    public static String normalize(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.startsWith("Bearer ") ? trimmed.substring(7).trim() : trimmed;
    }
}