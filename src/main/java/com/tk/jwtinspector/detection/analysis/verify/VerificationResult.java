package com.tk.jwtinspector.detection.analysis.verify;

/**
 * Author: TK
 * Date: 19-11-2026
 * Purpose: Outcome of replaying a forged token against the server, compared
 * against a baseline response from the original (real) token.
 */

public record VerificationResult(
        Verdict verdict,
        int baselineStatus,
        int forgedStatus,
        int baselineLength,
        int forgedLength,
        String detail
        ) {
            public enum Verdict { ACCEPTED, REJECTED, INCONCLUSIVE, ERROR }
        }
