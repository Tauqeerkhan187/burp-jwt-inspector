package com.tk.jwtinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.JWTDetector;
import com.tk.jwtinspector.detection.ProxyHttpHandler;

public class JWTInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JWT Inspector");

        Logging logging = api.logging();
        logging.logToOutput("JWT Inspector loaded successfully.");
        logging.logToOutput("Version: 0.2.0 (Phase 2 - detection");

        JWTDetector detector = new JWTDetector();

        ProxyHttpHandler handler = new ProxyHttpHandler(
                detector,
                token -> logging.logToOutput(formatDetection(token)),
                logging
        );

        api.proxy().registerRequestHandler(handler);
        api.proxy().registerResponseHandler(handler);

        logging.logToOutput("Proxy handlers registered. Detection active.");
    }

    private String formatDetection(DetectedToken token) {
        return String.format("[JWT] %s %s | %s in %s | %s",
                token.httpMethod(),
                token.url(),
                token.source(),
                token.sourceDetail(),
                token.shortToken());
    }
}