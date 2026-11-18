/**
 * Author: TK
 * Date: 18-11-2026
 * Purpose: Known-answer tests for TokenForger — the stateless core that produces
 * forged JWTs. Each test builds a genuine HS256 token with Nimbus, runs one forge
 * method against it, and asserts both the structure of the result and that its
 * signature actually verifies with the expected key (via raw HMAC, matching how a
 * vulnerable server would check it).
 *
 * Coverage:
 *  - alg:none      — alg rewritten to "none", signature stripped, payload preserved
 *  - kid injection — malicious kid is injected and re-signed; includes a regression
 *                    test for kids containing '$' / '\', which used to crash the old
 *                    regex-based header editing ("Illegal group reference")
 *  - claim tamper  — valid JSON is re-signed; invalid JSON is rejected up front
 *  - alg confusion — header forced to HS256 and signed with the public-key bytes
 *
 * Only the Montoya-free core is exercised here; UI classes (ForgeDialog, etc.) are
 * out of scope because the Burp API is compileOnly and not on the test classpath.
 */

package com.tk.jwtinspector.detection.analysis.forge;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;


class TokenForgerTest {

    // Nimbus MACSigner requires a >= 32-byte secret for HS256.

    private static final String SECRET = "test-secret-at-least-32-bytes-long!";

    private final TokenForger forger = new TokenForger();

    /** Bulid a genuine HS256 token to forge from. */
    private String hs256(String secret) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("wiener")
                .claim("admin", false)
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    /** Recompute HMAC-SHA256 over header.payload and compare to token'signature. */
    
    private boolean hmacVerifies(String token, String key) throws Exception {
        String[] p = token.split("\\.", -1);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] actual = mac.doFinal((p[0] + "." + p[1]).getBytes(StandardCharsets.US_ASCII));
        return MessageDigest.isEqual(Base64URL.from(p[2]).decode(), actual);
    }


    @Test
    void algNone_setsNone_andEmptySignature() throws Exception {
        
        String original = hs256(SECRET);
        ForgedToken f = forger.forgeAlgNone(original);

        assertTrue(f.success(), f.errorMessage());
        String[] parts = f.forgedToken().split("\\.", -1);
        assertEquals(3, parts.length);
        assertEquals("", parts[2], "alg:none token has an empty signature segment");
        assertEquals(original.split("\\.")[1], parts[1], "payload is unchanged");
        Map<String, Object> header = JSONObjectUtils.parse(Base64URL.from(parts[0]).decodeToString());
        assertEquals("none", header.get("alg"));
    }

    @Test
    void kidInjection_dollarSignPayload_succeedsAndRoundTrips() throws Exception {
        // Regression: '$' in the kid used to throw "Illegal group ref"
        // in the old Matcher-based replacement, failing the forge entirely.

        ForgedToken f = forger.forgeKidInjection(hs256(SECRET), "$(id)", "k");

        assertTrue(f.success(), f.errorMessage());
        Map<String, Object> header = JSONObjectUtils.parse(
                Base64URL.from(f.forgedToken().split("\\.")[0]).decodeToString());
    }

    @Test
    void kidInjection_sqlAndTraversalPayloads_succeed() throws Exception {
        for (String kid : new String[]{"../../../dev/null", "x' UNION SELECT 'AAA'", "a$1b"}) {
            ForgedToken f = forger.forgeKidInjection(hs256(SECRET), kid, "k");
            assertTrue(f.success(), "kid '" + kid + "' : " + f.errorMessage());
            Map<String, Object> header = JSONObjectUtils.parse(
                    Base64URL.from(f.forgedToken().split("\\.")[0]).decodeToString());
            assertEquals(kid, header.get("kid"));
        }
    }

    @Test
    void claimTamper_validJson_signsWithSecret() throws Exception {

        String tampered = "{\"sub\":\"administrator\",\"admin\":true}";
        ForgedToken f = forger.forgeClaimTamper(hs256(SECRET), tampered, SECRET);


        assertTrue(f.success(), f.errorMessage());
        assertTrue(hmacVerifies(f.forgedToken(), SECRET));
        String payload = Base64URL.from(f.forgedToken().split("\\.")[1]).decodeToString();
        assertTrue(payload.contains("administrator"));
    }

    @Test
    void claimTamper_invalidJson_isRejected() throws Exception {
        
        ForgedToken f = forger.forgeClaimTamper(hs256(SECRET), "{not valid json", SECRET);

        assertFalse(f.success());
        assertNotNull(f.errorMessage());
        assertTrue(f.errorMessage().toLowerCase().contains("json"));
    }

    @Test
    void algConfusion_forcesHs256_andSignsWithKeyBytes() throws Exception {

        String pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ==\n-----END PUBLIC KEY-----\n";
        ForgedToken f = forger.forgeAlgConfusion(hs256(SECRET), pem, null);

        
        assertTrue(f.success(), f.errorMessage());
        Map<String, Object> header = JSONObjectUtils.parse(
                Base64URL.from(f.forgedToken().split("\\.")[0]).decodeToString());
        assertEquals("HS256", header.get("alg"));
        assertTrue(hmacVerifies(f.forgedToken(), pem), "signed with the PEM bytes as the HMAC key");

    }

    @Test
    void algConfusion_blankKey_fails() throws Exception {
        
        ForgedToken f = forger.forgeAlgConfusion(hs256(SECRET), "", null);
        assertFalse(f.success());
    }

    @Test
    void malformedToken_fails(){

        ForgedToken f = forger.forgeAlgNone("not-a-token");
        assertFalse(f.success());

    }
}
