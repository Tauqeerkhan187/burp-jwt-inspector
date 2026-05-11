package com.tk.jwtinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.tk.jwtinspector.detection.JWTDetector;
import com.tk.jwtinspector.detection.ProxyHttpHandler;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.TokenAnalyzer;
import com.tk.jwtinspector.detection.analysis.crack.CrackingService;
import com.tk.jwtinspector.ui.JWTInspectorTab;

/**
 * Entry point for the JWT Inspector Burp Suite extension.
 *
 * Author: TK
 * Date: 2026-05-09
 *
 * Purpose: Wires together the detection, analysis, cracking, and UI subsystems
 * when the extension is loaded by Burp. Registers the proxy hooks that observe
 * HTTP traffic and the suite tab that displays results.
 */
public class JWTInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JWT Inspector");

        Logging logging = api.logging();
        logging.logToOutput("JWT Inspector loaded successfully.");
        logging.logToOutput("Version: 0.4.2 (Phase 4.2 — crack button UI)");

        // Detection + analysis
        TokenStore store = new TokenStore();
        TokenAnalyzer analyzer = new TokenAnalyzer(logging);
        store.setAnalyzer(analyzer);
        JWTDetector detector = new JWTDetector();

        ProxyHttpHandler handler = new ProxyHttpHandler(detector, store::add, logging);
        api.proxy().registerRequestHandler(handler);
        api.proxy().registerResponseHandler(handler);

        // Cracking service: load wordlist once at startup
        CrackingService crackingService = new CrackingService(logging);
        crackingService.loadBundled();

        // UI tab
        JWTInspectorTab tab = new JWTInspectorTab(store, crackingService);
        api.userInterface().registerSuiteTab("JWT Inspector", tab);

        logging.logToOutput("UI tab registered. Detection + cracking active.");
    }
}