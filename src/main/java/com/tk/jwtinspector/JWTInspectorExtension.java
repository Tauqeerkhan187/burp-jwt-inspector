package com.tk.jwtinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.tk.jwtinspector.detection.JWTDetector;
import com.tk.jwtinspector.detection.ProxyHttpHandler;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.ui.JWTInspectorTab;

public class JWTInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JWT Inspector");

        Logging logging = api.logging();
        logging.logToOutput("JWT Inspector loaded successfully.");
        logging.logToOutput("Version: 0.2.5 (Phase 2 — UI)");

        TokenStore store = new TokenStore();
        JWTDetector detector = new JWTDetector();

        ProxyHttpHandler handler = new ProxyHttpHandler(detector, store::add, logging);
        api.proxy().registerRequestHandler(handler);
        api.proxy().registerResponseHandler(handler);

        JWTInspectorTab tab = new JWTInspectorTab(store);
        api.userInterface().registerSuiteTab("JWT Inspector", tab);

        logging.logToOutput("UI tab registered. Detection active.");
    }
}