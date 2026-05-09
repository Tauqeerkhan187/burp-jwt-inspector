package com.tk.jwtinspector.detection.analysis.crack;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Brute-forces the HMAC secret of a JWT against a wordlist.
 *
 * @author TK
 * @since 2026-05-09
 *
 * Purpose: For tokens signed with HS256/HS384/HS512, attempts each candidate
 * in a wordlist as the secret. Returns the matching secret if found.
 *
 * Implementation notes:
 * - Verification uses raw javax.crypto.Mac (not Nimbus's MACVerifier) so we
 *   can test short candidate keys exactly as a vulnerable server would
 *   accept them — no zero-padding to RFC 7518 minimum sizes.
 * - Parallel execution: wordlist split across worker threads.
 * - Cooperative cancellation via shared atomic flag.
 */
public class SecretCracker {

    private static final int PROGRESS_INTERVAL = 1000;

    public interface ProgressListener {
        void onProgress(long attempts, String current);
    }

    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public void cancel() { cancelled.set(true); }
    public void reset()  { cancelled.set(false); }

    public CrackResult crack(String rawToken, List<String> wordlist, ProgressListener listener) {
        long startTime = System.currentTimeMillis();
        AtomicLong attemptCounter = new AtomicLong(0);

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(rawToken);
        } catch (ParseException e) {
            return CrackResult.error(0, System.currentTimeMillis() - startTime);
        }

        JWSAlgorithm alg = signedJWT.getHeader().getAlgorithm();
        String macAlg = macAlgorithmFor(alg);
        if (macAlg == null) {
            return CrackResult.error(0, System.currentTimeMillis() - startTime);
        }

        String[] parts = rawToken.split("\\.", -1);
        if (parts.length < 3) {
            return CrackResult.error(0, System.currentTimeMillis() - startTime);
        }
        byte[] signingInput = (parts[0] + "." + parts[1])
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] expectedSignature;
        try {
            expectedSignature = com.nimbusds.jose.util.Base64URL.from(parts[2]).decode();
        } catch (Exception e) {
            return CrackResult.error(0, System.currentTimeMillis() - startTime);
        }

        int threadCount = Math.max(2, Runtime.getRuntime().availableProcessors());
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        AtomicReference<String> foundSecret = new AtomicReference<>();

        try {
            int chunkSize = (wordlist.size() + threadCount - 1) / threadCount;
            for (int t = 0; t < threadCount; t++) {
                int start = t * chunkSize;
                int end = Math.min(start + chunkSize, wordlist.size());
                if (start >= end) break;

                List<String> chunk = wordlist.subList(start, end);
                pool.submit(() -> tryChunk(macAlg, signingInput, expectedSignature,
                        chunk, foundSecret, attemptCounter, listener));
            }

            pool.shutdown();
            boolean finished = pool.awaitTermination(1, TimeUnit.HOURS);
            if (!finished) {
                pool.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }

        long duration = System.currentTimeMillis() - startTime;
        long attempts = attemptCounter.get();

        if (cancelled.get()) {
            return CrackResult.cancelled(attempts, duration);
        }
        if (foundSecret.get() != null) {
            return CrackResult.found(foundSecret.get(), attempts, duration);
        }
        return CrackResult.notFound(attempts, duration);
    }

    private void tryChunk(String macAlg, byte[] signingInput, byte[] expectedSignature,
                          List<String> chunk, AtomicReference<String> foundSecret,
                          AtomicLong counter, ProgressListener listener) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(macAlg);
            for (String candidate : chunk) {
                if (cancelled.get() || foundSecret.get() != null) return;

                if (verify(mac, macAlg, signingInput, expectedSignature, candidate)) {
                    foundSecret.set(candidate);
                    return;
                }

                long count = counter.incrementAndGet();
                if (listener != null && count % PROGRESS_INTERVAL == 0) {
                    listener.onProgress(count, candidate);
                }
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            // unreachable: HmacSHA{256,384,512} are always available
        }
    }

    private boolean verify(javax.crypto.Mac mac, String macAlg,
                           byte[] signingInput, byte[] expectedSignature,
                           String candidate) {
        try {
            byte[] keyBytes = candidate.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            mac.init(new javax.crypto.spec.SecretKeySpec(keyBytes, macAlg));
            byte[] computed = mac.doFinal(signingInput);
            return java.security.MessageDigest.isEqual(computed, expectedSignature);
        } catch (Exception e) {
            return false;
        }
    }

    private String macAlgorithmFor(JWSAlgorithm alg) {
        if (JWSAlgorithm.HS256.equals(alg)) return "HmacSHA256";
        if (JWSAlgorithm.HS384.equals(alg)) return "HmacSHA384";
        if (JWSAlgorithm.HS512.equals(alg)) return "HmacSHA512";
        return null;
    }
}
