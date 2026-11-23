package com.tk.jwtinspector.detection.analysis.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTParser;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;

/**
 * Author: TK
 * Date: 23-11-2026
 * Purpose: Pure helpers for the JWKS auto-fetch feature: where to look for a
 * server's JWKS, which key in it signed a given token, and how to turn that key
 * into the PEM text the algorithm-confusion attack signs with.
 * No Burp/Montoya dependency, so it is unit-tested directly.
 */

public final class JwksKeys {

    private JwksKeys() {  }

    // Standard JWKS locations on the token's host, most common first. 
    public static List<String> defaultUrls(boolean secure, String host, int port) {
        String scheme = secure ? "https" : "http";
        boolean defaultPort = (secure && port == 443) || (!secure && port == 80);
        String base = scheme + "://" + host + (defaultPort ? "" : ":" + port);
        return List.of(base + "/.well-known/jwks.json", base + "/jwks.json");

    }

    /** The token's 'kid' header, or null if absent or the token doesn't parse. */
    public static String kidOf(String rawToken) {
        try {
            Object kid = JWTParser.parse(rawToken).getHeader().toJSONObject().get("kid");
            return kid == null ? null : kid.toString();

        }
        catch(ParseException e) {
            return null;

        }
    }

     /**
     * Picks the public key that signed the token: the one whose kid matches, or
     * the only key if the set has exactly one. Refuses to guess between several.
     */
    public static PublicKey selectKey(String jwksJson, String kid) throws ParseException, JOSEException {
        JWKSet set = JWKSet.parse(jwksJson);

        JWK match = (kid != null) ? set.getKeyByKeyId(kid) : null;
        if (match == null) {
            List<JWK> asymmetric = set.getKeys().stream()
                .filter(k -> k instanceof AsymmetricJWK)
                .toList();
            if (asymmetric.size() != 1) {
                throw new ParseException("JWKS has " + asymmetric.size() + " public keys and none matches kid '" + kid + "'", 0);

            }
            match = asymmetric.get(0);

        }

        if (!(match instanceof AsymmetricJWK asym)) {
            throw new ParseException("Key '" + match.getKeyID() + "' is not a public key", 0);
        }
        return asym.toPublicKey();
    }

     /** X.509 SubjectPublicKeyInfo PEM, 64-char lines, trailing newline. */
    public static String toPem(PublicKey key) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(key.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";

    }

}
