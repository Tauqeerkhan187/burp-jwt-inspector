package com.tk.jwtinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.tk.jwtinspector.detection.JWTDetector;
import com.tk.jwtinspector.detection.ProxyHttpHandler;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.TokenAnalyzer;
import com.tk.jwtinspector.ui.JWTInspectorTab;

public class JWTInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JWT Inspector");

        Logging logging = api.logging();
        logging.logToOutput("JWT Inspector loaded successfully.");
        logging.logToOutput("Version: 0.3.5 (Phase 3 - full check suite)");

        TokenStore store = new TokenStore();
        TokenAnalyzer analyzer = new TokenAnalyzer(logging);
        store.setAnalyzer(analyzer);
        JWTDetector detector = new JWTDetector();

        ProxyHttpHandler handler = new ProxyHttpHandler(detector, store::add, logging);
        api.proxy().registerRequestHandler(handler);
        api.proxy().registerResponseHandler(handler);

        // Phase 3 verification: log findings as tokens are detected
        store.addListener(token -> {
            if (token == null) return;
            var findings = store.findingsFor(token.rawToken());
            if (findings.isEmpty()) return;
            logging.logToOutput("=== Findings for token " + token.shortToken() + " ===");
            for (var finding : findings) {
                logging.logToOutput(String.format("  [%s] %s — %s",
                        finding.severity().displayName(),
                        finding.title(),
                        finding.description().substring(0, Math.min(80, finding.description().length())) + "..."));
            }
        });

        JWTInspectorTab tab = new JWTInspectorTab(store);
        api.userInterface().registerSuiteTab("JWT Inspector", tab);

        logging.logToOutput("UI tab registered. Detection active.");
    }
}