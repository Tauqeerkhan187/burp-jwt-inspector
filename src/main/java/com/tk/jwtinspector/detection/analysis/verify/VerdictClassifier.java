package com.tk.jwtinspector.detection.analysis.verify;

import com.tk.jwtinspector.detection.analysis.verify.VerificationResult.Verdict;

/**
 * Author: TK
 * Date: 22-11-2026
 * Purpose: Pure decision logic for the verification oracle. Compares the forged
 * response against the baseline (real token) response and returns a verdict.
 * Has no Burp/Montoya dependency, so it can be unit-tested directly.
 */

final class VerdictClassifier {

    // Bodies whose sizes differ by less than this fraction count as "about the same".
    static final double LENGTH_TOLERANCE = 0.05;

    private VerdictClassifier() {  }

    static Verdict classify(int baseStatus, int forgedStatus, int baseLen, int forgedLen) {
        // Clear auth failure.
        if (forgedStatus == 401 || forgedStatus == 403) return Verdict.REJECTED;
        // Bounced to login when the real token wasn't.
        if ((forgedStatus == 301 || forgedStatus == 302) && baseStatus != forgedStatus) {

            return Verdict.REJECTED;
        }
        // The baseline must be a real page (2xx). If even the real token gets a
        // redirect or error here, this endpoint can't tell us anything.
        if (baseStatus < 200 || baseStatus >= 300) return Verdict.INCONCLUSIVE;

        // Same status as the authenticated baseline AND a similar-sized body.
        if (forgedStatus == baseStatus && similarSize(baseLen, forgedLen)) return Verdict.ACCEPTED;
        return Verdict.INCONCLUSIVE;
    }

    static boolean similarSize(int a, int b) {
        int max = Math.max(a, b);
        return max == 0 || Math.abs(a - b) <= max * LENGTH_TOLERANCE;

    }
}
