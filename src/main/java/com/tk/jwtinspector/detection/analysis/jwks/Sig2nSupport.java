package com.tk.jwtinspector.detection.analysis.jwks;

import com.nimbusds.jwt.JWTParser;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Author: TK
 * Date: 26-11-2026
 * Purpose: Pure helpers for recovering a server's RSA public key with
 * PortSwigger's sig2n tool when no JWKS is exposed: finding a second token
 * signed by the same key, building the docker command, and pulling the
 * candidate X.509 keys out of the tool's output.
 *
 * The heavy math (a GCD of very large numbers) runs in the external tool,
 * because Java's BigInteger is far too slow at that size.
 */
public final class Sig2nSupport {

    // Long runs of standard base64. Candidate keys are a few hundred characters.
    private static final Pattern BASE64_BLOB = Pattern.compile("[A-Za-z0-9+/]{80,}={0,2}");
    private static final String X509_HEADER = "-----BEGIN PUBLIC KEY-----";

    private Sig2nSupport() { }

    /** The command from PortSwigger's lab solution. */
    public static String dockerCommand(String token1, String token2) {
        return "docker run --rm -it portswigger/sig2n " + token1 + " " + token2;
    }

    /**
     * A different token signed with the same RSA key: same alg (RS* or PS*) and
     * same kid. Returns null if there's no such token.
     */
    public static String partnerFor(String token, List<String> candidates) {
        String alg = algOf(token);
        if (alg == null || !(alg.startsWith("RS") || alg.startsWith("PS"))) {
            return null;
        }
        String kid = JwksKeys.kidOf(token);
        for (String other : candidates) {
            if (!other.equals(token)
                    && alg.equals(algOf(other))
                    && Objects.equals(kid, JwksKeys.kidOf(other))) {
                return other;
            }
        }
        return null;
    }

    /**
     * The X.509 PEM keys in sig2n's output, in the order printed, without
     * duplicates. Finds every long base64 string and keeps those that decode to
     * an X.509 PEM, so PKCS1 keys, tampered JWTs and labels are skipped no
     * matter how the output is worded.
     */
    public static List<String> candidatePems(String output) {
        Set<String> pems = new LinkedHashSet<>();
        Matcher m = BASE64_BLOB.matcher(output);
        while (m.find()) {
            try {
                String decoded = new String(Base64.getDecoder().decode(m.group()), StandardCharsets.UTF_8);
                if (decoded.startsWith(X509_HEADER)) {
                    pems.add(decoded);
                }
            } catch (IllegalArgumentException notBase64) {
                // Part of a JWT or other text that isn't valid base64: ignore.
            }
        }
        return List.copyOf(pems);
    }

    private static String algOf(String token) {
        try {
            return JWTParser.parse(token).getHeader().getAlgorithm().getName();
        } catch (Exception e) {
            return null;
        }
    }
}
