package com.tk.jwtinspector.detection.analysis.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Author: TK
 * Date: 23-11-2026
 * Purpose: Tests for JwksKeys — JWKS URL construction, kid extraction, picking
 * the signing key out of a key set, and lossless JWK -> PEM conversion.
 */
class JwksKeysTest {

    private static RSAKey k1;
    private static RSAKey k2;

    @BeforeAll
    static void generateKeys() throws Exception {
        // Generated once for the class: RSA key generation is the slow part.
        k1 = new RSAKeyGenerator(2048).keyID("k1").generate();
        k2 = new RSAKeyGenerator(2048).keyID("k2").generate();
    }

    private static String jwks(RSAKey... keys) {
        List<JWK> publicKeys = java.util.Arrays.stream(keys).map(k -> (JWK) k.toPublicJWK()).toList();
        return new JWKSet(publicKeys).toString();
    }

    @Test
    void defaultUrls_omitDefaultPort() {
        assertEquals(List.of("https://lab.net/.well-known/jwks.json", "https://lab.net/jwks.json"),
                JwksKeys.defaultUrls(true, "lab.net", 443));
    }

    @Test
    void defaultUrls_keepNonDefaultPort() {
        assertEquals("http://lab.net:8080/.well-known/jwks.json",
                JwksKeys.defaultUrls(false, "lab.net", 8080).get(0));
    }

    @Test
    void kidOf_readsHeader_andToleratesGarbage() throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(),
                new JWTClaimsSet.Builder().subject("wiener").build());
        jwt.sign(new RSASSASigner(k1));

        assertEquals("k1", JwksKeys.kidOf(jwt.serialize()));
        assertNull(JwksKeys.kidOf("not-a-token"));
    }

    @Test
    void selectKey_picksKeyMatchingKid() throws Exception {
        PublicKey picked = JwksKeys.selectKey(jwks(k1, k2), "k2");
        assertArrayEquals(k2.toRSAPublicKey().getEncoded(), picked.getEncoded());
    }

    @Test
    void selectKey_singleKey_usedWhenKidDoesNotMatch() throws Exception {
        PublicKey picked = JwksKeys.selectKey(jwks(k1), "some-other-kid");
        assertArrayEquals(k1.toRSAPublicKey().getEncoded(), picked.getEncoded());
    }

    @Test
    void selectKey_severalKeys_noMatch_refusesToGuess() {
        assertThrows(ParseException.class, () -> JwksKeys.selectKey(jwks(k1, k2), "missing"));
    }

    @Test
    void toPem_hasPemFraming_andRoundTripsToSameKey() throws Exception {
        String pem = JwksKeys.toPem(k1.toRSAPublicKey());

        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----\n"));
        assertTrue(pem.endsWith("-----END PUBLIC KEY-----\n"));
        for (String line : pem.split("\n")) {
            assertTrue(line.length() <= 64, "PEM lines must be at most 64 chars");
        }

        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        PublicKey decoded = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
        assertArrayEquals(k1.toRSAPublicKey().getEncoded(), decoded.getEncoded());
    }
}
