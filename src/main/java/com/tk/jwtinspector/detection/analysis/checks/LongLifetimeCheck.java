package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import com.tk.jwtinspector.detection.analysis.VulnerabilityCheck;

import java.time.Duration;
import java.util.Date;
import java.util.List;

/**
 * Author: TK
 * Date: 08-05-2026
 *
 * Flags tokens whose lifetime exceeds a threshold.
 *
 * Long-lived tokens widen the window during which a compromised token
 * remains useful to an attacker. Standard guidance is short-lived access
 * tokens (minutes) backed by longer-lived refresh tokens stored separately.
 */

public class LongLifetimeCheck implements VulnerabilityCheck{

    private static final Duration THRESHOLD = Duration.ofDays(7);

    @Override
    public String id() {
        return "long-lifetime";
    }

    @Override
    public List<Finding> check(JWT jwt) {
        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims == null) return List.of();

            Date iat = claims.getIssueTime();
            Date exp = claims.getExpirationTime();

            // Need both to compute lifetime
            if (iat == null || exp == null) return List.of();

            Duration lifetime = Duration.between(iat.toInstant(), exp.toInstant());
            if (lifetime.compareTo(THRESHOLD) > 0) {
                long days = lifetime.toDays();
                return List.of(Finding.of(
                        Severity.MEDIUM,
                        "Long token lifetime (" + days + "days)",
                        "This token has a lifetime of " + days + " days (exp - iat). Long-lived tokens"
                                          + "increase the impact of credential leaks, since a compromised token "
                                          + "remains valid for the full duration. Consider issuing short-lived"
                                          + "access tokens (minutes) with separate refresh tokens.",
                        "lifetime: " + days + " days"
                ));
            }

            return List.of();
        } catch (Exception e) {
            return List.of();
        }
    }
}
