package com.tk.jwtinspector.detection;

import javax.swing.SwingUtilities;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
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

    private final java.util.List<Consumer<DetectedToken>> listeners =
            new CopyOnWriteArrayList<>();

    /**
     * Adds or refreshes a token. If the raw token already exists,
     * replaces its entry (keeping the latest source/url info).
     * Notifies listeners on Swing EDT.
     */
    public void add(DetectedToken token) {
        boolean isNew;
        synchronized (tokens) {
            isNew = !tokens.containsKey(token.rawToken());
            tokens.remove(token.rawToken()); // ensure re-insertion at end.
            tokens.put(token.rawToken(), token);
        }

        // Only notify on genuinely new tokens to avoid churn on every api call.
        if (isNew) {
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
        SwingUtilities.invokeLater(() -> {
            for (Consumer<DetectedToken> listener : listeners) {
                // just signal no token, listeners check size()
                listener.accept(null);
            }
        });
    }
}
