package com.tk.jwtinspector.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.tk.jwtinspector.detection.DetectedToken;

/**
 * Author: TK
 * Date: 26-11-2026
 * Purpose: Builds a copy of a captured request with a forged token in place of
 * the original, wherever the original token was observed. Shared by Send to
 * Repeater, Verify on server and sig2n key recovery.
 */
final class TokenSubstitution {

    private TokenSubstitution() { }

    /**
     * Returns a copy of `original` with the JWT replaced:
     *   - Authorization header carried the token: swap it
     *   - a Cookie carried it: splice it inside the cookie value
     *   - otherwise fall back to a body replace, then an Authorization header
     */
    static HttpRequest withForgedToken(DetectedToken token, HttpRequest original, String forged) {
        String originalToken = token.rawToken();

        switch (token.source()) {
            case REQUEST_HEADER -> {
                String headerName = token.sourceDetail();
                if ("Authorization".equalsIgnoreCase(headerName)) {
                    return original.withRemovedHeader("Authorization").withAddedHeader("Authorization", "Bearer " + forged);
                
                }
                if ("Cookie".equalsIgnoreCase(headerName)) {
                    String oldCookie = original.headerValue("Cookie");
                    if (oldCookie != null && oldCookie.contains(originalToken)) {
                        return original.withRemovedHeader("Cookie").withAddedHeader("Cookie", oldCookie.replace(originalToken, forged));
                    
                    }
                }
                // custom header
                String oldValue = original.headerValue(headerName);
                if (oldValue != null && oldValue.contains(originalToken)) {
                    return original.withRemovedHeader(headerName).withAddedHeader(headerName, oldValue.replace(originalToken, forged));
                
                }
            }
            case RESPONSE_HEADER, RESPONSE_BODY -> {
                // Token came from the server; servers often set it via Set-Cookie
                // and the client sends it back as a Cookie, so use the cookie jar.
                String oldCookie = original.headerValue("Cookie");
                if (oldCookie != null) {
                    String newCookie = oldCookie.contains(originalToken)
                            ? oldCookie.replace(originalToken, forged)
                            : oldCookie + "; session=" + forged;
                    return original.withRemovedHeader("Cookie").withAddedHeader("Cookie", newCookie);
                }
                return original.withAddedHeader("Cookie", "session=" + forged);
            }
            case REQUEST_BODY, REQUEST_PARAM -> {
                // Fall through to the body replace below
            }
        }

        String body = original.bodyToString();
        if (body.contains(originalToken)) {
            return original.withBody(body.replace(originalToken, forged));
        }
        return original.withAddedHeader("Authorization", "Bearer " + forged);
    }
}
