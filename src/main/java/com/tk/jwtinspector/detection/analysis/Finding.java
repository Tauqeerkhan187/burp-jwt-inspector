package com.tk.jwtinspector.detection.analysis;

/**
 * A single vulnerability finding produced by a VulnerabilityCheck against a token.
 *
 * @param severity        how serious is this finding.
 * @param title           short headline
 * @param description     what's wrong and why it matters.
 * @param remediation     optional one-line hint on how to fix, maybe null
 * @param evidence        the specific value from the token that triggered the finding.
 */

public record Finding(Severity severity,
                      String title,
                      String description,
                      String remediation,
                      String evidence) {
    /// Constructor for findings without remediation/evidence.
    public static Finding of(Severity severity, String title, String description) {
        return new Finding(severity, title, description, null, null);
    }

    public static Finding of(Severity severity, String title, String description, String evidence) {
        return new Finding(severity, title, description, null, evidence);
    }
}
