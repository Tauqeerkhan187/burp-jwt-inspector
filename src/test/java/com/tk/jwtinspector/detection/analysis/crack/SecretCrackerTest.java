package com.tk.jwtinspector.detection.analysis.crack;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Author: TK
 * Date: 18-11-2026
 * Purpose: End-to-end tests for SecretCracker — signs a token with a known HMAC
 * secret and confirms the cracker recovers it from a wordlist, reports NOT_FOUND
 * when it is absent, and ERROR for non-HMAC tokens it cannot brute-force.
 */

class SecretCrackerTest {

    // Nimbus MACSigner requires a >= 32-byte secret for HS256.
    private static final String SECRET = "crackable-secret-32-bytes-minimum!!";
    
    private String hs256(String secret) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().subject("wiener").build());
        jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();

    }

    @Test
    void crack_findsSecretPresentInWordlist() throws Exception {
        
        CrackResult r = new SecretCracker().crack(
                hs256(SECRET), List.of("nope1", "nope2", SECRET, "nope3"), null );

        assertEquals(CrackResult.Status.FOUND, r.status());
        assertEquals(SECRET, r.secret());
        assertTrue(r.isSuccess());
        
    }

    @Test
    void crack_notFound_whenSecretAbsent() throws Exception {

        CrackResult r = new SecretCracker().crack(
                hs256(SECRET), List.of("nope1", "nope2", "nope3"), null);

        assertEquals(CrackResult.Status.NOT_FOUND, r.status());
        assertNull(r.secret());

    }

    @Test
    void crack_error_forNonHmacToken() throws Exception {
        
        RSAKey rsa = new RSAKeyGenerator(2048).generate();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),
                new JWTClaimsSet.Builder().subject("wiener").build());
        jwt.sign(new RSASSASigner(rsa));

        
        CrackResult r = new SecretCracker().crack(jwt.serialize(), List.of("whatever"), null);

        assertEquals(CrackResult.Status.ERROR, r.status());

    }
}
