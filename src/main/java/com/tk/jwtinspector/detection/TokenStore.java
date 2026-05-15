package com.tk.jwtinspector.detection;

import javax.swing.SwingUtilities;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Author: TK
 * Date: 07-05-2026
 * Thread-safe store of detected tokens, deduplicated by raw token string.
 * Preserves insertion order for the most recent occurrence of each token.
 *
 * Detection runs on Burp's proxy threads; listener is notified on the EDT
 * so UI code never has to think about threading.
 */

public class TokenStore {

    // LinkedHashMap preserves insertion order; we reinsert on duplicate
    // to bubble recently seen tokens to the end of the list.
    private final Map<String, DetectedToken> tokens =
            java.util.Collections.synchronizedMap(new LinkedHashMap<>());

    private final Map<String, String> crackedSecrets =
            new java.util.concurrent.ConcurrentHashMap<>();

    private final java.util.List<Consumer<DetectedToken>> listeners =
            new CopyOnWriteArrayList<>();

    private final Map<String, java.util.List<com.tk.jwtinspector.detection.analysis.Finding>> findingsByToken =
            new java.util.concurrent.ConcurrentHashMap<>();

    private com.tk.jwtinspector.detection.analysis.TokenAnalyzer analyzer;

    public void setAnalyzer(com.tk.jwtinspector.detection.analysis.TokenAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    public java.util.List<com.tk.jwtinspector.detection.analysis.Finding> findingsFor(String rawToken) {
        return findingsByToken.getOrDefault(rawToken, java.util.List.of());
    }

    /**
     * Adds or refreshes a token. If the raw token already exists,
     * replaces its entry (keeping the latest source/url info).
     * Notifies listeners on Swing EDT.
     */
    public void add(DetectedToken token) {
        boolean isNew;
        synchronized (tokens) {
            isNew = !tokens.containsKey(token.rawToken());
            tokens.remove(token.rawToken());
            tokens.put(token.rawToken(), token);
        }

        if (isNew) {
            // Analyze on detection (one-time cost per unique token)
            if (analyzer != null) {
                findingsByToken.put(
                        token.rawToken(),
                        analyzer.analyze(token.rawToken())
                );
            }

            SwingUtilities.invokeLater(() -> {
                for (Consumer<DetectedToken> listener : listeners) {
                    listener.accept(token);
                }
            });
        }
    }

    public java.util.List<DetectedToken> snapshot() {
        synchronized (tokens) {
            return new java.util.ArrayList<>(tokens.values());
        }
    }

    public void recordCrackedSecret(String rawToken, String secret) {
        crackedSecrets.put(rawToken, secret);
    }

    public String crackedSecretFor(String rawToken) {
        return crackedSecrets.get(rawToken);
    }

    public void addListener(Consumer<DetectedToken> listener) {
        listeners.add(listener);
    }

    public int size() {
        return tokens.size();
    }

    public void clear() {
        synchronized (tokens) {
            tokens.clear();
        }
        findingsByToken.clear();
        crackedSecrets.clear();
        SwingUtilities.invokeLater(() -> {
            for (Consumer<DetectedToken> listener : listeners) {
                listener.accept(null);
            }
        });
    }
}
