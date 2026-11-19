package com.tk.jwtinspector.detection.analysis.verify;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import static com.tk.jwtinspector.detection.analysis.verify.VerificationResult.Verdict;

/**
 * Author: TK
 * Date: 19-11-2026
 * Purpose: Differential oracle for forged tokens. Replays the baseline request
 * (original token) and the attack request (forged token) against the live server
 * and classifies whether the forged token was accepted, by comparing status codes
 * and response sizes — not by assuming HTTP 200 means success.
 *
 * Blocking network calls: callers must run verify() off the Swing EDT.
 */

public class ForgeVerifier {

    // Bodies whose sizes differ by less than this fraction count as "about the same".
    private static final double LENGTH_TOLERANCE = 0.05;

    private final MontoyaApi api;

    public ForgeVerifier(MontoyaApi api) {
        this.api = api;
    }

    public VerificationResult verify(HttpRequest baselineRequest, HttpRequest forgedRequest) {
        
        try {
            HttpResponse baseline = api.http().sendRequest(baselineRequest).response();
            HttpResponse forged = api.http().sendRequest(forgedRequest).response();

            if (baseline == null || forged == null) {
                return new VerificationResult(Verdict.ERROR, -1, -1, -1, -1,
                        "No response received for one of the requests.");
            }

            int baseStatus = baseline.statusCode();
            int forgedStatus = forged.statusCode();
            int baseLen = baseline.body().length();
            int forgedLen = forged.body().length();

            Verdict verdict = classify(baseStatus, forgedStatus, baseLen, forgedLen);
            return new VerificationResult(verdict, baseStatus, forgedStatus, baseLen, forgedLen, describe(verdict, baseStatus, forgedStatus, baseLen, forgedLen));

        }
        catch(Exception e) {
            return new VerificationResult(Verdict.ERROR, -1, -1, -1, -1, "Request failed: " + e.getMessage());

        }
    }

    private Verdict classify(int base, int forged, int baseLen, int forgedLen) {

        //Clear auth failure
        if (forged == 401 || forged == 403) return Verdict.REJECTED;
        // Bounced to login when real token wasn't
        if ((forged == 301 || forged == 302) && base != forged) return Verdict.REJECTED;
        // Same status as the authenticated baseline and a similar-sized body.
        if (forged == base && similarSize(baseLen, forgedLen)) return Verdict.ACCEPTED;
        return Verdict.INCONCLUSIVE;

    }

    private boolean similarSize(int a, int b) {

        int max = Math.max(a, b);
        return max == 0 || Math.abs(a - b) <= max * LENGTH_TOLERANCE;

    }

    private String describe(Verdict v, int base, int forged, int baseLen, int forgedLen) {

        String nums = String.format(
                "forged HTTP %d (%d bytes) vs baseline HTTP %d (%d bytes)",
                forged, forgedLen, base, baseLen);
        
        return switch (v) {

            case ACCEPTED -> "server treated the Forged token like the real one - " + nums;
            case REJECTED -> "server refused the forged token - " + nums;
            case INCONCLUSIVE -> "couldn't decide automatically, compare manually - " + nums;
            case ERROR -> nums;
        }; 
    }
}
