package com.tk.jwtinspector.detection;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
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
 * and pushes any found to the supplied consumer.
 *
 * Read-only — returns continueWith for everything, never modifies traffic.
 * Each detected token carries the request it rode on, so the UI's
 * "Send to Repeater" feature can replay it later.
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

        for (HttpHeader header : request.headers()) {
            String name = header.name();
            String value = header.value();

            if (name.equalsIgnoreCase("Authorization")) {
                String normalized = JWTDetector.normalize(value);
                if (detector.isJWT(normalized)) {
                    emit(normalized,
                            DetectedToken.TokenSource.REQUEST_HEADER,
                            "Authorization",
                            method, url, request);
                }
                continue;
            }

            if (name.equalsIgnoreCase("Cookie")) {
                for (String token : detector.findTokens(value)) {
                    emit(token,
                            DetectedToken.TokenSource.REQUEST_HEADER,
                            "Cookie",
                            method, url, request);
                }
                continue;
            }

            for (String token : detector.findTokens(value)) {
                emit(token,
                        DetectedToken.TokenSource.REQUEST_HEADER,
                        name,
                        method, url, request);
            }
        }

        for (String token : detector.findTokens(url)) {
            emit(token, DetectedToken.TokenSource.REQUEST_PARAM, "URL", method, url, request);
        }

        String body = request.bodyToString();
        for (String token : detector.findTokens(body)) {
            emit(token, DetectedToken.TokenSource.REQUEST_BODY, "Body", method, url, request);
        }
    }

    private void scanResponse(InterceptedResponse response) {
        HttpRequest initiatingRequest = response.initiatingRequest();
        String method = initiatingRequest.method();
        String url = initiatingRequest.url();

        for (HttpHeader header : response.headers()) {
            for (String token : detector.findTokens(header.value())) {
                emit(token,
                        DetectedToken.TokenSource.RESPONSE_HEADER,
                        header.name(),
                        method, url, initiatingRequest);
            }
        }

        String body = response.bodyToString();
        for (String token : detector.findTokens(body)) {
            emit(token, DetectedToken.TokenSource.RESPONSE_BODY, "Body", method, url, initiatingRequest);
        }
    }

    private void emit(String token, DetectedToken.TokenSource source,
                      String detail, String method, String url, HttpRequest request) {
        DetectedToken detected = new DetectedToken(
                token, source, detail, method, url, Instant.now(), request
        );
        onTokenFound.accept(detected);
    }
}
