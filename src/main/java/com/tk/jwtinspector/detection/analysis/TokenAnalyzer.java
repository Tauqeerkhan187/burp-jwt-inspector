package com.tk.jwtinspector.detection.analysis;

import burp.api.montoya.logging.Logging;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.tk.jwtinspector.detection.analysis.checks.AlgNoneCheck;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Author: TK
 * Date: 06-05-2026
 * Runs all registered vulnerability checks against a token and aggregates findings.
 *
 * This is a pure function from "raw token string" to "List of findings."
 * Stateless (safe to call from any thread).
 */

public class TokenAnalyzer {

    private final List<VulnerabilityCheck> checks;
    private final Logging logging;

    public TokenAnalyzer(Logging logging) {
        this.logging = logging;
        this.checks = List.of(
                new AlgNoneCheck()
        );
    }

    /**
     * Parses the raw token and runs every check against it.
     * Returns empty list if the token can't be parsed or no findings are produced.
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
                // isolating failures
                logging.logToError("Check '" + check.id() + " ' threw: " + e.getMessage());
            }
        }

        // Sort findings by severity (most severe first).
        all.sort((a, b) -> b.severity().compareTo(a.severity()));
        return all;
    }
}
