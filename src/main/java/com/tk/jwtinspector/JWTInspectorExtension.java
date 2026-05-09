package com.tk.jwtinspector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.tk.jwtinspector.detection.JWTDetector;
import com.tk.jwtinspector.detection.ProxyHttpHandler;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.TokenAnalyzer;
import com.tk.jwtinspector.detection.analysis.crack.CrackResult;
import com.tk.jwtinspector.detection.analysis.crack.SecretCracker;
import com.tk.jwtinspector.detection.analysis.crack.WordlistLoader;
import com.tk.jwtinspector.ui.JWTInspectorTab;

import java.io.IOException;
import java.util.List;

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
        logging.logToOutput("Version: 0.4.0 (Phase 4.1 — secret cracking)");

        // Detection + analysis
        TokenStore store = new TokenStore();
        TokenAnalyzer analyzer = new TokenAnalyzer(logging);
        store.setAnalyzer(analyzer);
        JWTDetector detector = new JWTDetector();

        ProxyHttpHandler handler = new ProxyHttpHandler(detector, store::add, logging);
        api.proxy().registerRequestHandler(handler);
        api.proxy().registerResponseHandler(handler);

        // UI tab
        JWTInspectorTab tab = new JWTInspectorTab(store);
        api.userInterface().registerSuiteTab("JWT Inspector", tab);

        logging.logToOutput("UI tab registered. Detection active.");

        // -----------------------------------------------------------------
        // Phase 4.1 verification harness — TEMPORARY.
        // Auto-cracks every detected HMAC token against the bundled wordlist
        // and logs the result. Will be removed in Phase 4.2 in favor of a
        // user-initiated "Crack" button in the detail panel.
        // -----------------------------------------------------------------
        WordlistLoader loader = new WordlistLoader();
        List<String> wordlist;
        try {
            wordlist = loader.loadBundled();
            logging.logToOutput("Loaded " + wordlist.size()
                    + " candidate secrets from bundled wordlist.");
        } catch (IOException e) {
            logging.logToError("Failed to load wordlist: " + e.getMessage());
            wordlist = List.of();
        }
        final List<String> finalWordlist = wordlist;

        store.addListener(token -> {
            if (token == null || finalWordlist.isEmpty()) return;

            // Only try cracking tokens flagged as using HMAC by our analyzer
            var findings = store.findingsFor(token.rawToken());
            boolean isHmac = findings.stream()
                    .anyMatch(f -> f.title().contains("HMAC algorithm"));
            if (!isHmac) return;

            new Thread(() -> {
                SecretCracker cracker = new SecretCracker();
                CrackResult result = cracker.crack(token.rawToken(), finalWordlist, null);
                switch (result.status()) {
                    case FOUND -> logging.logToOutput(String.format(
                            "[CRACKED] %s -> secret = '%s' (%d attempts, %d ms)",
                            token.shortToken(),
                            result.secret(),
                            result.attemptCount(),
                            result.durationMs()));
                    case NOT_FOUND -> logging.logToOutput(String.format(
                            "[NOT FOUND] %s — %d attempts in %d ms",
                            token.shortToken(),
                            result.attemptCount(),
                            result.durationMs()));
                    case CANCELLED -> logging.logToOutput("[CANCELLED] " + token.shortToken());
                    case ERROR -> logging.logToOutput("[CRACK ERROR] " + token.shortToken());
                }
            }, "jwt-cracker-" + token.shortToken()).start();
        });
    }
}