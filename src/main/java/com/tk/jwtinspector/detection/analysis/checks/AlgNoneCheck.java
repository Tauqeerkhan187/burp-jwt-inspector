package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import com.tk.jwtinspector.detection.analysis.VulnerabilityCheck;

import javax.swing.event.ListDataEvent;
import java.util.List;

/**
 * Author: TK
 * Date: 05-05-2026
 * Flags tokens using the "none" algorithm (unsigned tokens).
 *
 * This is the most severe vulnerability: any client can forge any claims
 * because there is no signature to verify. It only exists as a debugging aid
 * in the JWT spec; it should NEVER appear in production traffic.
 *
 * Detection: the 'alg' header equals "none" (case-insensitive per RFC 7518),
 * OR the signature segment is empty.
 */

public class AlgNoneCheck implements VulnerabilityCheck{

    @Override
    public String id() {
        return "alg-none";
    }

    @Override
    public List<Finding> check(JWT jwt) {
        try {
            String alg = jwt.getHeader().getAlgorithm() == null
                    ? null
                    : jwt.getHeader().getAlgorithm().getName();

            boolean algIsNone = alg != null && alg.equalsIgnoreCase("none");
            boolean isUnsignedAlgo = JWSAlgorithm.NONE.equals(jwt.getHeader().getAlgorithm());

            if (algIsNone || isUnsignedAlgo) {
                return List.of(Finding.of(
                        Severity.CRITICAL,
                        "Unsigned token (alg: none",
                        "This token uses the 'none' algorithm, meaning it has no signature. "
                                          + "Any party can forge a token with arbitrary claims and the server "
                                          + "will accept it as valid. JWT libraries that fail to reject 'none' "
                                          + "in production are a well-known authentication bypass class.",
                            alg != null ? alg : "(none)"
                ));
            }

            return List.of();
        } catch (Exception e) {
            return List.of();
        }
    }
}