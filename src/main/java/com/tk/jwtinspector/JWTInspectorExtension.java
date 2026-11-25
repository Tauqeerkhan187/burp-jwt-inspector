package com.tk.jwtinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.tk.jwtinspector.detection.JWTDetector;
import com.tk.jwtinspector.detection.ProxyHttpHandler;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.TokenAnalyzer;
import com.tk.jwtinspector.detection.analysis.crack.CrackingService;
import com.tk.jwtinspector.detection.analysis.forge.ForgeAttack;
import com.tk.jwtinspector.ui.JWTInspectorTab;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;


/**
 * Entry point for the JWT Inspector Burp Suite extension.
 *
 * @author TK
 * @since 2026-05-09
 *
 * Purpose: Wires together detection, analysis, cracking, forging, and
 * Repeater-integration subsystems when Burp loads the extension.
 */
public class JWTInspectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JWT Inspector");

        Logging logging = api.logging();

        TokenStore store = new TokenStore();
        TokenAnalyzer analyzer = new TokenAnalyzer(logging);
        store.setAnalyzer(analyzer);
        JWTDetector detector = new JWTDetector();

        ProxyHttpHandler handler = new ProxyHttpHandler(detector, store::add, logging);
        api.proxy().registerRequestHandler(handler);
        api.proxy().registerResponseHandler(handler);

        CrackingService crackingService = new CrackingService(logging);
        crackingService.loadBundled();

        JWTInspectorTab tab = new JWTInspectorTab(store, crackingService, api);
        api.userInterface().registerSuiteTab("JWT Inspector", tab);

        logStartupSummary(logging, analyzer, crackingService);
    }

    /**
     * Prints what was actually loaded. Built from the live components rather than
     * typed by hand, so it stays accurate as checks and attacks are added.
     * Called last, so "loaded successfully" is only printed once everything is wired.
     */
    private void logStartupSummary(Logging logging, TokenAnalyzer analyzer, CrackingService cracking) {
        String version = JWTInspectorExtension.class.getPackage().getImplementationVersion();

        List<String> checks = analyzer.checkIds();
        List<String> attacks = Arrays.stream(ForgeAttack.values())
                .map(ForgeAttack::displayName)
                .toList();

        String wordlist = cracking.wordlistSize() > 0
                ? String.format(Locale.ROOT, "%,d-entry wordlist", cracking.wordlistSize())
                : "no wordlist loaded (use Browse in the crack dialog)";

        logging.logToOutput("JWT Inspector " + (version != null ? version : "dev") + " loaded successfully.");
        logging.logToOutput("  Checks (" + checks.size() + "):  " + String.join(", ", checks));
        logging.logToOutput("  Attacks (" + attacks.size() + "): " + String.join(", ", attacks));
        logging.logToOutput("  Cracking: HMAC secrets, " + wordlist);
        logging.logToOutput("  Also: verification oracle, JWKS auto-fetch, Send to Repeater");
        logging.logToOutput("Open the \"JWT Inspector\" tab and browse a JWT-using site through the proxy.");
    }

}
