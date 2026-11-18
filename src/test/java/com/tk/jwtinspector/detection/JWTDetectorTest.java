package com.tk.jwtinspector.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Author: TK
 * Date: 18-11-2026
 * Purpose: Tests for JWTDetector — the passive scanner that finds JWT-shaped,
 * structurally-valid tokens in arbitrary text (headers, cookies, bodies) and
 * normalizes Bearer-prefixed values.
 */
class JWTDetectorTest {

    private static final String JWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
          + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
          + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private final JWTDetector detector = new JWTDetector();

    @Test
    void isJWT_recognizesValidToken() {
        assertTrue(detector.isJWT(JWT));
    }

    @Test
    void isJWT_stripsBearerPrefix() {
        assertTrue(detector.isJWT("Bearer " + JWT));
    }

    @Test
    void isJWT_rejectsNonToken() {
        assertFalse(detector.isJWT("just.some.text"));
        assertFalse(detector.isJWT(null));
    }

    @Test
    void findTokens_extractsFromCookieHeader() {
        List<String> found = detector.findTokens("session=" + JWT + "; theme=dark");
        assertEquals(1, found.size());
        assertEquals(JWT, found.get(0));
    }

    @Test
    void findTokens_emptyWhenNonePresent() {
        assertTrue(detector.findTokens("nothing here but words").isEmpty());
    }

    @Test
    void normalize_stripsBearerAndTrims() {
        assertEquals(JWT, JWTDetector.normalize("  Bearer " + JWT + "  "));
    }
}
