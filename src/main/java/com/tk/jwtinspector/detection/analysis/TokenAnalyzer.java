package com.tk.jwtinspector.detection.analysis;

import burp.api.montoya.logging.Logging;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.tk.jwtinspector.detection.analysis.checks.AlgNoneCheck;
import com.tk.jwtinspector.detection.analysis.checks.KidInjectionCheck;
import com.tk.jwtinspector.detection.analysis.checks.LongLifetimeCheck;
import com.tk.jwtinspector.detection.analysis.checks.MissingClaimsCheck;
import com.tk.jwtinspector.detection.analysis.checks.MissingExpirationCheck;
import com.tk.jwtinspector.detection.analysis.checks.WeakAlgorithmCheck;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Runs all registered vulnerability checks against a token and aggregates findings.
 *
 * This is a pure function from "raw token string" to "list of findings."
 * Stateless — safe to call from any thread.
 */
public class TokenAnalyzer {

    private final List<VulnerabilityCheck> checks;
    private final Logging logging;

    public TokenAnalyzer(Logging logging) {
        this.logging = logging;
        this.checks = List.of(
                new AlgNoneCheck(),
                new WeakAlgorithmCheck(),
                new MissingExpirationCheck(),
                new LongLifetimeCheck(),
                new KidInjectionCheck(),
                new MissingClaimsCheck()
        );
    }

    /**
     * Parses the raw token and runs every check against it.
     * Returns an empty list if the token can't be parsed or no findings are produced.
     */
    public List<Finding> analyze(String rawToken) {
        JWT jwt;
        try {
            jwt = JWTParser.parse(rawToken);
        } catch (Exception e) {
            logging.logToError("TokenAnalyzer: failed to parse token: " + e.getMessage());
            return Collections.emptyList();
        }

        List<Finding> all = new ArrayList<>();
        for (VulnerabilityCheck check : checks) {
            try {
                List<Finding> result = check.check(jwt);
                if (result != null && !result.isEmpty()) {
                    all.addAll(result);
                }
            } catch (Exception e) {
                logging.logToError("Check '" + check.id() + "' threw: " + e.getMessage());
            }
        }

        all.sort((a, b) -> b.severity().compareTo(a.severity()));
        return all;
    }
}
