package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jwt.JWT;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import com.tk.jwtinspector.detection.analysis.VulnerabilityCheck;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Author: TK
 * Date: 08-05-2026
 * Flags algorithm choices that warrant attention.
 *
 * HMAC algorithms (HS256/386/512) are vulnerable to offline brute-force.
 * if the secret is weak. The algorithm itself isn't broken, but in practice
 * weak secrets are common - especially in dev/staging environments and tutorials.
 *
 * Unknown algorithms (anything outside the standard JOSE registry) are
 * suspicious - could indicate a malformed token, a custom non-standard
 * algorithm, or an attempt to confuse a permissive parser.
 */

public class WeakAlgorithmCheck implements VulnerabilityCheck{

    private static final Set<String> HMAC_ALGORITHMS = Set.of("HS256", "HS384", "HS512");

    private static final Set<String> KNOWN_ALGORITHMS = Set.of(
            "none",
            "HS256", "HS384", "HS512",
            "RS256", "RS384", "RS512",
            "ES256", "ES256K", "ES384", "ES512",
            "PS256", "PS384", "PS512",
            "EdDSA"
    );

    @Override
    public String id(){
        return "weak-algorithm";
    }

    @Override
    public List<Finding> check (JWT jwt) {
        try {
            Algorithm alg = jwt.getHeader().getAlgorithm();
            if (alg == null) return List.of();

            String name = alg.getName();

            // alg:none handled separately by algNoneCheck
            if ("none".equalsIgnoreCase(name)) return List.of();

            if (HMAC_ALGORITHMS.contains(name)) {
                return List.of(Finding.of(
                        Severity.MEDIUM,
                        "HMAC algorithm in use (" + name + ")",
                        "This token uses an HMAC signing algorithm, which relies on a shared secret."
                                          + "If the secret is weak (a dict word, a def value, or a short string),"
                                          + "an attacker who captures a single token can perform offline brute-force"
                                          + "to recover the secret and forge arbitrary tokens. Consider using an asymmetric"
                                          + "algorithm (RS256, ES256, edDSA) for tokens that traverse trust boundaries.",
                            name
                ));
            }

            if (!KNOWN_ALGORITHMS.contains(name)) {
                return List.of(Finding.of(
                        Severity.MEDIUM,
                        "Unknown algorithm: " + name,
                        "The token's `alg` header specifies an algorithm not in the standard JOSE registry. "
                                          + "This may indicate a malformed token, a custom non-standard algorithm,"
                                          + "or an attempt to exploit a permissive JWT lib"
                                          + "Verify the server validates the algorithm against an explicit allowlist.",
                        name
                ));
            }
            return List.of();
        } catch (Exception e) {
            return List.of();
        }
    }
}
