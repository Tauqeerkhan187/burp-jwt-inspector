package com.tk.jwtinspector.detection.analysis.forge;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parse / edit / re-encode a JWT header segment as JSON.
 *
 * Replaces the earlier regex string-splicing (replaceAlgInHeader / setOrReplaceKid),
 * which fed attacker-controlled values into Matcher replacement strings — where '$'
 * and '\' are special and throw or corrupt the output. Going through a real JSON
 * serializer handles escaping correctly for any kid/alg value.
 */
final class JwtHeader {

    private final Map<String, Object> claims;

    private JwtHeader(Map<String, Object> claims) {
        this.claims = claims;
    }

    /** Decode a base64url header segment into an editable header. */
    static JwtHeader fromSegment(String headerB64) throws ParseException {
        String json = Base64URL.from(headerB64).decodeToString();
        return new JwtHeader(new LinkedHashMap<>(JSONObjectUtils.parse(json)));
    }

    /** The 'alg' value, or null if absent. */
    String alg() {
        Object v = claims.get("alg");
        return v == null ? null : v.toString();
    }

    /** Set or overwrite a header field; returns this for chaining. */
    JwtHeader put(String key, String value) {
        claims.put(key, value);
        return this;
    }

    /** Re-encode the (possibly modified) header as a base64url segment. */
    String toSegment() {
        String json = JSONObjectUtils.toJSONString(claims);
        return Base64URL.encode(json.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
