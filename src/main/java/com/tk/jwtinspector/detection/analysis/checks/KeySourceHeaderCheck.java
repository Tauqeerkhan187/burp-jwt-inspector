package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jwt.JWT;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import com.tk.jwtinspector.detection.analysis.VulnerabilityCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Author: TK
 * Date: 25-11-2026
 *
 * Flags header fields that tell the server where to get the verification key:
 * jku and x5u (URLs) and jwk and x5c (embedded key or certificate chain).
 *
 * If the server trusts these instead of keys it already holds, an attacker can
 * supply their own key and sign arbitrary tokens. Presence alone is a lead to
 * test rather than proof, since a well-built server ignores them, so each
 * finding is MEDIUM.
 */

public class KeySourceHeaderCheck implements VulnerabilityCheck {

    @Override
    public String id() {
        return "key-source-header";
    }

    @Override
    public List<Finding> check(JWT jwt) {
        try {
            Map<String, Object> header = jwt.getHeader().toJSONObject();
            List<Finding> findings = new ArrayList<>();

            Object jku = header.get("jku");
            if (jku != null) {
                findings.add(new Finding(
                        Severity.MEDIUM,
                        "Key URL in `jku` header",
                        "The token names a URL where its verification keys should be fetched. If the "
                                + "server fetches from this URL without restricting it to its own trusted "
                                + "hosts, an attacker can host their own JWK Set and sign tokens with the "
                                + "matching private key.",
                        "Ignore `jku`, or only accept exact, allow-listed URLs of the issuer's own JWKS.",
                        jku.toString()));
            }

            Object x5u = header.get("x5u");
            if (x5u != null) {
                findings.add(new Finding(
                        Severity.MEDIUM,
                        "Certificate URL in `x5u` header",
                        "The token names a URL where its signing certificate should be fetched. If the "
                                + "server fetches it from any host, an attacker can host their own "
                                + "certificate and sign tokens with its private key.",
                        "Ignore `x5u`, or only accept allow-listed URLs and validate the chain.",
                        x5u.toString()));
            }

            Object jwk = header.get("jwk");
            if (jwk != null) {
                findings.add(new Finding(
                            Severity.MEDIUM,
                            "Embedded key in 'jwk' header",
                            "The token carries its own public key. If the server verifies with this "
                                + "embedded key instead of a key it already trusts, anyone can sign tokens "
                                + "with their own key pair. Test it with the JWK injection forge tab.",
                        "Verify only with keys from the server's own key store; ignore `jwk`.",
                        describeJwk(jwk)));

            }

            Object x5c = header.get("x5c");
            if (x5c != null) {
                findings.add(new Finding(
                        Severity.MEDIUM,
                        "Embedded certificate chain in `x5c` header",
                        "The token carries its own certificate chain. If the server doesn't validate "
                                + "the chain against a trusted root, an attacker can embed a self-signed "
                                + "certificate and sign with its key.",
                        "Validate `x5c` against a pinned trusted root, or ignore it.",
                        x5c instanceof List<?> chain ? chain.size() + " certificate(s)" : x5c.toString()));

            }

            return findings;

        } 
        catch (Exception e) {
            return List.of();
        }
    }

     /** Short summary for the evidence line: key type and kid, not the whole key. */
    private static String describeJwk(Object jwk) {
        if (jwk instanceof Map<?, ?> key) {
            Object kid = key.get("kid");
            return "kty=" + key.get("kty") + (kid != null ? ", kid=" + kid : "");

        }

        return jwk.toString();

    }
}
