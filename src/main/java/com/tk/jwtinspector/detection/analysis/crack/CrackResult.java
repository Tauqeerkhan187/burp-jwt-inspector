package com.tk.jwtinspector.detection.analysis.crack;

/**
 * Outcome of a secret-cracking attempt.
 *
 * Author: TK
 * Date: 09-05-2026
 *
 * Purpose: Carries the result of a SecretCracker run back to the caller -
 * Whether a secret was found, what it was, how long it took, and how many
 * candidates were tried.
 *
 * @param status   outcome of the attempt
 * @param secret   the cracked secret if status == FOUND, otherwise null
 * @param attemptCount number of candidates tried before result.
 * @param durationMs wall-clock time spent in milliseconds
 *
 */

public record CrackResult(
        Status status,
        String secret,
        long attemptCount,
        long durationMs
) {
    public enum Status {
        /** Secret found in the wordlist. */
        FOUND,
        /** Wordlist exhausted without finding the secret. */
        NOT_FOUND,
        /** User or caller cancelled */
        CANCELLED,
        /** Crack failed for an unexpected reason (bad token, I0 error, etc.). */
        ERROR
    }

    public boolean isSuccess() {
        return status == status.FOUND;
    }

    public double attemptsPerSecond() {
        if (durationMs == 0) return 0.0;
        return attemptCount * 1000.0 / durationMs;
    }

    public static CrackResult found(String secret, long attempts, long durationMs) {
        return new CrackResult(Status.FOUND, secret, attempts, durationMs);
    }

    public static CrackResult notFound(long attempts, long durationMs) {
        return new CrackResult(Status.NOT_FOUND, null, attempts, durationMs);
    }

    public static CrackResult cancelled(long attempts, long durationMs) {
        return new CrackResult(Status.CANCELLED, null, attempts, durationMs);
    }

    public static CrackResult error(long attempts, long durationMs) {
        return new CrackResult(Status.ERROR, null, attempts, durationMs);
    }
}
