package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import com.tk.jwtinspector.detection.analysis.VulnerabilityCheck;

import java.util.List;

/**
 * Author: TK
 * Date: 08-05-2026
 * Flags tokens with no 'exp' (expiration) claim.
 *
 * Tokens without expiration remain valid indefinitely. If such a token is
 * leaked (logs, browser history, leaked git commit, intercepted traffic),
 * an attacker has permanent valid creds with no automatic revocation.
 */

public class MissingExpirationCheck implements VulnerabilityCheck {

    @Override
    public String id() {
        return "missing-expiration";
    }

    @Override
    public List<Finding> check (JWT jwt) {
        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims == null) return List.of();

            if (claims.getExpirationTime() == null) {
                return List.of(Finding.of(
                        Severity.HIGH,
                        "Token has no expiration",
                        "This token does not include an 'exp' (expiration) claim, meaning it is valid "
                                          + "indefinitely until manually revoked. If the token is leaked, an attacker "
                                          + "retains access permanently. Production tokens should include 'exp' "
                                          + "with a short lifetime (typically 15-60 minutes for access tokens).",
                        "exp claim absent"
                ));
            }

            return List.of();
        } catch (Exception e) {
            return List.of();
        }
    }
}
