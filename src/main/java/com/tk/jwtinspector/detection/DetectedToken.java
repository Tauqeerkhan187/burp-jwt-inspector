package com.tk.jwtinspector.detection;

import java.time.Instant;

public record DetectedToken(
        String rawToken,
        TokenSource source,
        String sourceDetail,
        String httpMethod,
        String url,
        Instant detectedAt
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