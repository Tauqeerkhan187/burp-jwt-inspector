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
import com.tk.jwtinspector.detection.analysis.forge.TokenForger;
import com.tk.jwtinspector.detection.analysis.forge.ForgedToken;
import com.tk.jwtinspector.detection.analysis.forge.ForgeAttack;

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
        logging.logToOutput("Version: 0.5.1 (Phase 5.1 — forging engine)");

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

        // Phase 5.1 verification harness — TEMPORARY, removed in 5.2
        TokenForger forger = new TokenForger();
        store.addListener(token -> {
            if (token == null) return;

            // Test 1: alg:none forgery on the alg:none jwt.io sample
            if (token.rawToken().contains("eyJhbGciOiJub25lIn0")) {
                logging.logToOutput("=== Phase 5.1 forge demo for " + token.shortToken() + " ===");

                ForgedToken algNone = forger.forgeAlgNone(token.rawToken());
                if (algNone.success()) {
                    logging.logToOutput("[alg:none] " + algNone.forgedToken());
                } else {
                    logging.logToError("[alg:none] failed: " + algNone.errorMessage());
                }
            }

            // Test 2+3: kid injection and claim tamper on the HS256 jwt.io sample
            if (token.rawToken().contains("eyJhbGciOiJIUzI1NiIs") &&
                    token.rawToken().contains("SmqJp-QV30")) {

                logging.logToOutput("=== Phase 5.1 forge demo for " + token.shortToken() + " ===");

                String knownSecret = "a-string-secret-at-least-256-bits-long";

                // kid injection
                ForgedToken kid = forger.forgeKidInjection(
                        token.rawToken(),
                        "../../../dev/null",
                        knownSecret
                );
                if (kid.success()) {
                    logging.logToOutput("[kid-injection] " + kid.forgedToken());
                } else {
                    logging.logToError("[kid-injection] failed: " + kid.errorMessage());
                }

                // claim tamper
                String newPayload = "{\"sub\":\"1234567890\",\"name\":\"Attacker\",\"admin\":true,\"iat\":1516239022}";
                ForgedToken tamper = forger.forgeClaimTamper(token.rawToken(), newPayload, knownSecret);
                if (tamper.success()) {
                    logging.logToOutput("[claim-tamper] " + tamper.forgedToken());
                    logging.logToOutput("  (decoded: name=Attacker, admin=true, signed with cracked secret)");
                } else {
                    logging.logToError("[claim-tamper] failed: " + tamper.errorMessage());
                }
            }
        });
    }
}