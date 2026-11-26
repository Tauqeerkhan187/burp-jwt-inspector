package com.tk.jwtinspector.detection.analysis.jwks;


import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;


import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Author: TK
 * Date: 26-11-2026
 * Purpose: Tests for Sig2nSupport — finding a partner token signed by the same
 * key, and extracting only the X.509 candidate keys from sig2n-style output.
 */

class Sign2SupportTest {

    /** A token as captured in traffic; the signature isn't checked here. */
    private static String token(String alg, String kid, String sub) {
        String header = "{\"alg\":\"" + alg + "\"" + (kid != null ? ",\"kid\":\"" + kid + "\"" : "") + "}";
        return Base64URL.encode(header) + "." + Base64URL.encode("{\"sub\":\"" + sub + "\"}") + ".c2ln";

    }

    private static String b64(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));

    }

    private static String newPem() throws Exception {
        return JwksKeys.toPem(new ECKeyGenerator(Curve.P_256).generate().toECPublicKey());

    }

    @Test
    void dockerCommand_matchesPortSwiggerSolution() {
        assertEquals("docker run --rm -it portswigger/sig2n aaa bbb", Sig2nSupport.dockerCommand("aaa", "bbb"));

    }

    @Test
    void partnerFor_findsDifferentTokenWithSameAlgKid() {
        String mine = token("RS256", "k1", "wiener");
        String other = token("RS256", "k1", "wiener2");
        assertEquals(other, Sig2nSupport.partnerFor(mine, List.of(mine, other)));

    }

    @Test
    void partnerFor_ignoresDifferentKidOrAlg_andItself() {
        String mine = token("RS256", "k1", "wiener");
        assertNull(Sig2nSupport.partnerFor(mine, List.of(mine)));
        assertNull(Sig2nSupport.partnerFor(mine, List.of(token("RS256", "k2", "x"))));
        assertNull(Sig2nSupport.partnerFor(mine, List.of(token("HS256", "k1", "x"))));

    }

    @Test
    void partnerFor_hmacToken_hasNoPartner() {
        String mine = token("HS256", "k1", "wiener");
        assertNull(Sig2nSupport.partnerFor(mine, List.of(token("HS256", "k1", "other"))));

    }

    @Test
    void candidatePems_keepsOnlyX509Keys_inOrder_withoutDuplicates() throws Exception {
        String pem1 = newPem();
        String pem2 = newPem();
        String pkcs1 = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA\n-----END RSA PUBLIC KEY-----\n";
        String jwt = token("HS256", "k1", "administrator");

        String output = "Found n with multiplier 1:\n"
            + "    Base64 encoded x509 key: " + b64(pem1) + "\n"
            + "    Tampered JWT: " + jwt + "\n"
            + "    Base64 encoded pkcs1 key: " + b64(pkcs1) + "\n"
            + "Found n with multiplier 2:\n"
            + "    Base64 encoded x509 key: " + b64(pem2) + "\n"
            + "    Base64 encoded x509 key: " + b64(pem1) + "\n";   // repeated
        
        assertEquals(List.of(pem1, pem2), Sig2nSupport.candidatePems(output));

    }

    @Test
    void candidatePems_garbage_isEmpty() {
        assertTrue(Sig2nSupport.candidatePems("docker : command not found").isEmpty());

    }
}
