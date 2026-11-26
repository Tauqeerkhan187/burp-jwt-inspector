package com.tk.jwtinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.forge.ForgedToken;
import com.tk.jwtinspector.detection.analysis.forge.TokenForger;
import com.tk.jwtinspector.detection.analysis.jwks.Sig2nSupport;
import com.tk.jwtinspector.detection.analysis.verify.ForgeVerifier;
import com.tk.jwtinspector.detection.analysis.verify.VerificationResult.Verdict;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.function.Consumer;

/**
 * Author: TK
 * Date: 26-11-2026
 * Purpose: Recovers the server's RSA public key when no JWKS is exposed.
 * Builds the sig2n command from two captured tokens signed by the same key,
 * takes the tool's output, and uses the verification oracle to find which
 * candidate key the server actually uses.
 */

class KeyRecoveryDialog extends JDialog {

    private static final Color GREEN = new Color(0x1A, 0x86, 0x1A);
    private static final Color RED = new Color(0xC0, 0x10, 0x10);
    private static final Color BLUE = new Color(0x40, 0x60, 0x80);

    private final DetectedToken token;
    private final MontoyaApi api;
    private final Consumer<String> onKeyFound;
    private final TokenForger forger = new TokenForger();

    private final JTextArea outputArea = new JTextArea(8, 60);
    private final JButton findButton = new JButton("Find the working key");
    private final JLabel statusLabel = new JLabel(" ");

    KeyRecoveryDialog(Window parent, DetectedToken token, TokenStore store,
                      MontoyaApi api, Consumer<String> onKeyFound) {
        super(parent, "Recover public key with sig2n", ModalityType.APPLICATION_MODAL);
        this.token = token;
        this.api = api;
        this.onKeyFound = onKeyFound;
        buildUI(store);
        pack();
        setSize(Math.max(760, getWidth()), getHeight());
        setLocationRelativeTo(parent);
    }

    private void buildUI(TokenStore store) {
        List<String> captured = store.snapshot().stream().map(DetectedToken::rawToken).toList();
        String partner = Sig2nSupport.partnerFor(token.rawToken(), captured);

        // Step 1: the command
        JTextArea command = monospaceReadOnly(partner != null
                ? Sig2nSupport.dockerCommand(token.rawToken(), partner)
                : "Only one token signed by this key has been captured. Log out and log in again "
                  + "through Burp's proxy to capture a second one, then reopen this dialog.");
        JScrollPane commandScroll = new JScrollPane(command);
        commandScroll.setPreferredSize(new Dimension(700, 90));

        JButton copyButton = new JButton("Copy command");
        copyButton.setEnabled(partner != null);
        copyButton.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(command.getText()), null);
            copyButton.setText("Copied!");
            Timer t = new Timer(1500, ev -> copyButton.setText("Copy command"));
            t.setRepeats(false);
            t.start();
        });

        JPanel step1 = new JPanel(new BorderLayout(0, 6));
        step1.add(new JLabel("1. Run this in a terminal (needs Docker; add sudo in front if Docker "
                + "needs root on your machine):"), BorderLayout.NORTH);
        step1.add(commandScroll, BorderLayout.CENTER);
        JPanel copyRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        copyRow.add(copyButton);
        step1.add(copyRow, BorderLayout.SOUTH);

        // Step 2: paste the output
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setLineWrap(true);
        JPanel step2 = new JPanel(new BorderLayout(0, 6));
        step2.add(new JLabel("2. Paste the tool's complete output, then find the key the server uses:"),
                BorderLayout.NORTH);
        step2.add(new JScrollPane(outputArea), BorderLayout.CENTER);

        // Bottom: status + buttons
        findButton.setEnabled(partner != null && token.originalRequest() != null);
        findButton.addActionListener(e -> onFind());
        if (token.originalRequest() == null) {
            setStatus("No original request was captured for this token, so candidates can't be tested.", RED);
        }

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(findButton);
        buttons.add(closeButton);

        JPanel bottom = new JPanel(new BorderLayout(0, 6));
        bottom.add(statusLabel, BorderLayout.NORTH);
        bottom.add(buttons, BorderLayout.SOUTH);

        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        root.add(step1, BorderLayout.NORTH);
        root.add(step2, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);
        setContentPane(root);
    }

    /** Tries each candidate key with the oracle; the first ACCEPTED one wins. */
    private void onFind() {
        List<String> pems = Sig2nSupport.candidatePems(outputArea.getText());
        if (pems.isEmpty()) {
            setStatus("No X.509 keys found in the pasted text. Paste the tool's complete output.", RED);
            return;
        }

        HttpRequest original = token.originalRequest();
        ForgeVerifier verifier = new ForgeVerifier(api);
        findButton.setEnabled(false);

        new SwingWorker<Integer, String>() {
            @Override
            protected Integer doInBackground() {
                for (int i = 0; i < pems.size(); i++) {
                    publish("Testing candidate " + (i + 1) + " of " + pems.size() + "...");
                    ForgedToken forged = forger.forgeAlgConfusion(token.rawToken(), pems.get(i), null);
                    if (!forged.success()) {
                        continue;
                    }
                    HttpRequest attack = TokenSubstitution.withForgedToken(token, original, forged.forgedToken());
                    if (verifier.verify(original, attack).verdict() == Verdict.ACCEPTED) {
                        return i;
                    }
                }
                return -1;
            }

            @Override
            protected void process(List<String> progress) {
                setStatus(progress.get(progress.size() - 1), BLUE);
            }

            @Override
            protected void done() {
                findButton.setEnabled(true);
                try {
                    int found = get();
                    if (found >= 0) {
                        onKeyFound.accept(pems.get(found));
                        setStatus("Candidate " + (found + 1) + " of " + pems.size()
                                + " was ACCEPTED. Its key is now in the alg-confusion tab.", GREEN);
                    } else {
                        setStatus("None of the " + pems.size() + " candidates was accepted. Check that this "
                                + "token was captured in a request to a protected page.", RED);
                    }
                } catch (Exception ex) {
                    setStatus("Failed: " + ex.getMessage(), RED);
                }
            }
        }.execute();
    }

    private void setStatus(String text, Color color) {
        statusLabel.setText(text);
        statusLabel.setForeground(color);
        statusLabel.setToolTipText(text);
    }

    private static JTextArea monospaceReadOnly(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }
}
