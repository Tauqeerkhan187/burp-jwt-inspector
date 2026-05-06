package com.tk.jwtinspector.detection;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.time.Instant;
import java.util.function.Consumer;

/**
 * Hooks Burp's proxy. On every request and response, scans for JWTs
 * and pushes any found to the supplied consumer (the UI list).
 *
 * returns *Continue* actions for everything. We are read-only -
 * we do not modify, drop, or intercept. We just observer.
 */

public class ProxyHttpHandler implements ProxyRequestHandler, ProxyResponseHandler {

    private final JWTDetector detector;
    private final Consumer<DetectedToken> onTokenFound;
    private final Logging logging;

    public ProxyHttpHandler(JWTDetector detector,
                            Consumer<DetectedToken> onTokenFound,
                            Logging logging) {
        this.detector = detector;
        this.onTokenFound = onTokenFound;
        this.logging = logging;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        try {
            scanRequest(request);
        } catch (Exception e) {
            logging.logToError("Error scanning request: " + e.getMessage());
        }
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        try {
            scanResponse(response);
        } catch (Exception e) {
            logging.logToError("Error scanning response: " + e.getMessage());
        }
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    private void scanRequest(InterceptedRequest request) {
        String method = request.method();
        String url = request.url();

        // Headers (Authorization, Cookie, custom auth headers)
        for (HttpHeader header : request.headers()) {
            String name = header.name();
            String value = header.value();

            // Authorization: Bearer <jwt>
            if (name.equalsIgnoreCase("Authorization")) {
                String normalized = JWTDetector.normalize(value);
                if (detector.isJWT(normalized)) {
                    emit(normalized,
                            DetectedToken.TokenSource.REQUEST_HEADER,
                            "Authorization",
                            method, url);
                }
                continue;
            }

            // Cookie header — may contain multiple cookies, scan whole thing
            if (name.equalsIgnoreCase("Cookie")) {
                for (String token : detector.findTokens(value)) {
                    emit(token,
                            DetectedToken.TokenSource.REQUEST_HEADER,
                            "Cookie",
                            method, url);
                }
                continue;
            }

            // Other headers — scan generically (catches X-Auth-Token, etc.)
            for (String token : detector.findTokens(value)) {
                emit(token,
                        DetectedToken.TokenSource.REQUEST_HEADER,
                        name,
                        method, url);
            }
        }

        // Query string + body
        for (String token : detector.findTokens(url)) {
            emit(token, DetectedToken.TokenSource.REQUEST_PARAM, "URL", method, url);
        }

        String body = request.bodyToString();
        for (String token : detector.findTokens(body)) {
            emit(token, DetectedToken.TokenSource.REQUEST_BODY, "Body", method, url);
        }
    }

    private void scanResponse(InterceptedResponse response) {
        String method = response.initiatingRequest().method();
        String url = response.initiatingRequest().url();

        // Set-Cookie often contains JWTs in session cookies
        for (HttpHeader header : response.headers()) {
            for (String token : detector.findTokens(header.value())) {
                emit(token,
                        DetectedToken.TokenSource.RESPONSE_HEADER,
                        header.name(),
                        method, url);
            }
        }

        // Login responses often return JWTs in JSON body
        String body = response.bodyToString();
        for (String token : detector.findTokens(body)) {
            emit(token, DetectedToken.TokenSource.RESPONSE_BODY, "Body", method, url);
        }
    }

    private void emit(String token, DetectedToken.TokenSource source,
                      String detail, String method, String url) {
        DetectedToken detected = new DetectedToken(
                token, source, detail, method, url, Instant.now()
        );
        onTokenFound.accept(detected);
    }

}
