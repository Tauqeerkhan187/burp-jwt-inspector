package com.tk.jwtinspector.detection.analysis.crack;

import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Facade in front of SecretCracker that holds the loaded wordlist and
 * exposes a single high-level crack () entry point for the UI.
 *
 * Author: TK
 * Date: 10-05-2026
 * Purpose: The UI shouldn't know how wordlists are loaded or how a cracker is constructed -
 * it just wants to say "crack this token" and get progress updates. This service centralises that.
 */

public class CrackingService {

    private final Logging logging;
    private final AtomicReference<List<String>> wordlistRef = new AtomicReference<>(List.of());
    private final AtomicReference<String> wordlistSourceRef = new AtomicReference<>("(none)");

    public CrackingService(Logging logging) {
        this.logging = logging;
    }

    /**
     * Loads the bundled wordlist from JAR resources. Called once at startup.
     */
    public void loadBundled() {
        WordlistLoader loader = new WordlistLoader();
        try {
            List<String> entries = loader.loadBundled();
            wordlistRef.set(entries);
            wordlistSourceRef.set("bundled (" + entries.size() + "entries)");
            logging.logToOutput("CrackingService: loaded "
                     + entries.size() + "candidate secrets from bundled wordlist. ");
        } catch (IOException e) {
            logging.logToError("CrackingService: failed to load bundled wordlist: " + e.getMessage());
        }
    }

    /**
     * Replaces the active wordlist with one loaded from a user-supplied file.
     * Used by the "Browse...." action in the crack dialog.
     */
    public void loadFromFile(java.nio.file.Path path) throws IOException {
        WordlistLoader loader = new WordlistLoader();
        List<String> entries = loader.loadFromFile(path);
        wordlistRef.set(entries);
        wordlistSourceRef.set(path.getFileName() + "(" + entries.size() + " entries)");
        logging.logToOutput("CrackingService: loaded " +
                  entries.size() + "candidates from " + path);
    }

    public List<String> wordlist() {
        return wordlistRef.get();
    }

    public String wordlistSource() {
        return wordlistSourceRef.get();
    }

    /**
     * Returns a fresh SecretCracker.Each crack run gets its own cracker so
     * cancellation state doesn't leak between runs.
     */
    public SecretCracker newCracker() {
        return new SecretCracker();
    }
}
