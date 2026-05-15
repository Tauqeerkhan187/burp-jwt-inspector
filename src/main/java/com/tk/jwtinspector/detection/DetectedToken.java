package com.tk.jwtinspector.detection;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.time.Instant;

/**
 * A JWT detected in HTTP traffic.
 *
 * @author TK
 * @since 2026-05-09
 *
 * @param rawToken        full encoded JWT string
 * @param source          where in the HTTP message the token was found
 * @param sourceDetail    header name, param name, or "Body"
 * @param httpMethod      HTTP method of the request that carried this token
 * @param url             request URL that carried this token
 * @param detectedAt      when this token was first observed
 * @param originalRequest the HttpRequest this token rode on (or that triggered
 *                        the response containing it). May be null.
 */
public record DetectedToken(
        String rawToken,
        TokenSource source,
        String sourceDetail,
        String httpMethod,
        String url,
        Instant detectedAt,
        HttpRequest originalRequest
) {
    public String shortToken() {
        if (rawToken.length() <= 40) return rawToken;
        return rawToken.substring(0, 20) + "..." + rawToken.substring(rawToken.length() - 10);
    }

    public enum TokenSource {
        REQUEST_HEADER,
        REQUEST_BODY,
        REQUEST_PARAM,
        RESPONSE_HEADER,
        RESPONSE_BODY
    }
}
