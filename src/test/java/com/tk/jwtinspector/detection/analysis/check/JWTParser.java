package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Author: TK
 * Date: 25-11-2026
 * Purpose: Tests for KeySourceHeaderCheck — each key-source header (jku, x5u,
 * jwk, x5c) produces one MEDIUM finding with useful evidence, and ordinary
 * headers produce none.
 */

class KeySourceHeaderCheckTest {

    private final KeySourceHeaderCheck check = new KeySourceHeaderCheck();

    /** A token as it would arrive in traffic: header JSON, payload, any signature. */
    private static JWT token(String headerJson) throws Exception {
        String header = Base64URL.encode(headerJson).toString();
        String payload = Base64URL.encode("{\"sub\":\"wiener\"}").toString();
        return JWTParser.parse(header + "." + payload + ".c2ln");
    }

    @Test
    void ordinaryHeader_noFindings() throws Exception {
        assertTrue(check.check(token("{\"alg\":\"RS256\",\"kid\":\"k1\"}")).isEmpty());
    }

    @Test
    void jku_isFlagged_withUrlAsEvidence() throws Exception {
        List<Finding> f = check.check(token(
                "{\"alg\":\"RS256\",\"jku\":\"https://attacker.example/jwks.json\"}"));
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertEquals("https://attacker.example/jwks.json", f.get(0).evidence());
    }

    @Test
    void x5u_isFlagged() throws Exception {
        List<Finding> f = check.check(token(
                "{\"alg\":\"RS256\",\"x5u\":\"https://attacker.example/cert.pem\"}"));
        assertEquals(1, f.size());
        assertTrue(f.get(0).title().contains("x5u"));
    }

    @Test
    void embeddedJwk_isFlagged_withShortEvidence() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("attacker-key").generate();
        List<Finding> f = check.check(token(
                "{\"alg\":\"ES256\",\"jwk\":" + key.toPublicJWK().toJSONString() + "}"));
        assertEquals(1, f.size());
        assertEquals("kty=EC, kid=attacker-key", f.get(0).evidence());
    }

    @Test
    void x5c_isFlagged_withCertificateCount() throws Exception {
        List<Finding> f = check.check(token("{\"alg\":\"RS256\",\"x5c\":[\"MIIBfake\"]}"));
        assertEquals(1, f.size());
        assertEquals("1 certificate(s)", f.get(0).evidence());
    }

    @Test
    void allFour_produceFourFindings() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        List<Finding> f = check.check(token("{\"alg\":\"ES256\","
                + "\"jku\":\"https://a.example/jwks.json\","
                + "\"x5u\":\"https://a.example/cert.pem\","
                + "\"jwk\":" + key.toPublicJWK().toJSONString() + ","
                + "\"x5c\":[\"MIIBfake\"]}"));
        assertEquals(4, f.size());
    }
}
