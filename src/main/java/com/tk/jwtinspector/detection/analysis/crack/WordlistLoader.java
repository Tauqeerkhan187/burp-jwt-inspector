package com.tk.jwtinspector.detection.analysis.crack;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads candidate secrets from a wordlist source.
 *
 * Author: TK
 * Date: 09-05-2026
 * Purpose: Reads wordlist files into memory. Supports the bundled default
 * wordlist (shipped inside the JAR) and arbitrary user-supplied file paths.
 * Skips blank lines and comment lines (starting with #).
 */

public class WordlistLoader {

    private static final String BUNDLED_WORDLIST = "/wordlists/common-jwt-secrets.txt";

    /**
     * Loads the bundled default wordlist from the JAR resources.
     *
     * @return list of candidate secrets, never null
     * @throws IOException if the resource is missing or unreadable.
     */
    public List<String> loadBundled() throws IOException {
        try (InputStream in = WordlistLoader.class.getResourceAsStream(BUNDLED_WORDLIST)) {
            if (in == null) {
                throw new IOException("Bundled wordlist not found at " + BUNDLED_WORDLIST);
            }
            return readLines(in);
        }
    }

    /**
     * Loads a user-supplied wordlist file from disk.
     *
     * @param path filesystem path to the wordlist
     * @return list of candidate secrets, never null
     * @throws IOException if the file is missing or unreadable
     */

    public List<String> loadFromFile(Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path)) {
            return readLines(in);
        }
    }

    private List<String> readLines(InputStream in) throws IOException {
        List<String> result = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                result.add(trimmed);
            }
        }
        return result;
    }
}
