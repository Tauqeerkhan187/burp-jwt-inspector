package com.tk.jwtinspector.detection.analysis.verify;

import com.tk.jwtinspector.detection.analysis.verify.VerificationResult.Verdict;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Author: TK
 * Date: 22-11-2026
 * Purpose: Tests for the verification oracle's decision logic — that it
 * distinguishes a forged token the server accepted from one it rejected,
 * and stays honest (INCONCLUSIVE) when the evidence is ambiguous instead of
 * treating any HTTP 200 as success.
 */
class VerdictClassifierTest {

    @Test
    void identicalAuthenticatedResponse_isAccepted() {
        // The real result from the weak-signing-key lab: byte-identical 200s.
        assertEquals(Verdict.ACCEPTED, VerdictClassifier.classify(200, 200, 3439, 3439));
    }

    @Test
    void sameStatus_smallSizeDifference_isAccepted() {
        // Within 5%: e.g. a CSRF token or timestamp differs between responses.
        assertEquals(Verdict.ACCEPTED, VerdictClassifier.classify(200, 200, 3439, 3350));
    }

    @Test
    void unauthorizedOrForbidden_isRejected() {
        assertEquals(Verdict.REJECTED, VerdictClassifier.classify(200, 401, 3439, 50));
        assertEquals(Verdict.REJECTED, VerdictClassifier.classify(200, 403, 3439, 50));
    }

    @Test
    void redirectWhenBaselineWasNot_isRejected() {
        // Forged token bounced to the login page.
        assertEquals(Verdict.REJECTED, VerdictClassifier.classify(200, 302, 3439, 0));
    }

    @Test
    void same200_butVeryDifferentBody_isInconclusive() {
        // The key case: a 200 that serves the logged-out page must NOT count as accepted.
        assertEquals(Verdict.INCONCLUSIVE, VerdictClassifier.classify(200, 200, 3439, 1200));
    }

    @Test
    void unrelatedStatus_isInconclusive() {
        assertEquals(Verdict.INCONCLUSIVE, VerdictClassifier.classify(200, 500, 3439, 120));
        assertEquals(Verdict.INCONCLUSIVE, VerdictClassifier.classify(302, 400, 0, 60));
    }

    @Test
    void similarSize_handlesEmptyBodies() {
        assertTrue(VerdictClassifier.similarSize(0, 0));
        assertFalse(VerdictClassifier.similarSize(0, 100));
    }

    @Test
    void nonPageBaseline_isInconclusive_evenWhenResponsesMatch() {
    // Login endpoint: real and forged tokens both get an empty 302.
    // Matching responses here prove nothing, so this must not be ACCEPTED.
    assertEquals(Verdict.INCONCLUSIVE, VerdictClassifier.classify(302, 302, 0, 0));
}
}

