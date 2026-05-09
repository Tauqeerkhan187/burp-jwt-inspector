package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import com.tk.jwtinspector.detection.analysis.VulnerabilityCheck;

import java.util.ArrayList;
import java.util.List;

/**
 * Flags tokens missing standard registered claims that improve security posture.
 *
 * - `iss` (issuer): identifies the token's source. Without it, the verifier
 *   cannot reject tokens issued by other parties.
 * - `aud` (audience): identifies who the token is intended for. Without it,
 *   a token issued for one service may be replayed against another.
 * - `sub` (subject): identifies the principal. Tokens without `sub` can't
 *   reliably be tied to a user.
 *
 * These are all "best practice" — missing any one isn't a vulnerability
 * by itself, but tokens with several missing suggest the issuer didn't
 * follow JWT hardening guidance.
 */
public class MissingClaimsCheck implements VulnerabilityCheck {

    @Override
    public String id() {
        return "missing-claims";
    }

    @Override
    public List<Finding> check(JWT jwt) {
        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims == null) return List.of();

            List<Finding> findings = new ArrayList<>();

            if (claims.getIssuer() == null || claims.getIssuer().isBlank()) {
                findings.add(Finding.of(
                        Severity.LOW,
                        "Missing `iss` (issuer) claim",
                        "The token has no `iss` claim. Without it, the verifier cannot distinguish tokens "
                                + "from this issuer versus another. Best practice is to set `iss` to the "
                                + "authorization server's URL and verify it on each request.",
                        "iss claim absent"
                ));
            }

            if (claims.getAudience() == null || claims.getAudience().isEmpty()) {
                findings.add(Finding.of(
                        Severity.LOW,
                        "Missing `aud` (audience) claim",
                        "The token has no `aud` claim. Without it, a token issued for one service can be "
                                + "replayed against another. Set `aud` to the intended recipient and verify "
                                + "it matches the receiving service.",
                        "aud claim absent"
                ));
            }

            if (claims.getSubject() == null || claims.getSubject().isBlank()) {
                findings.add(Finding.of(
                        Severity.LOW,
                        "Missing `sub` (subject) claim",
                        "The token has no `sub` claim, which conventionally identifies the principal "
                                + "(typically a user ID). Without it, the token can't be reliably attributed.",
                        "sub claim absent"
                ));
            }

            return findings;
        } catch (Exception e) {
            return List.of();
        }
    }
}
