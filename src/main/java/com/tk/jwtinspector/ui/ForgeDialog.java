package com.tk.jwtinspector.ui;

import com.nimbusds.jose.util.Base64URL;
import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.forge.ForgeAttack;
import com.tk.jwtinspector.detection.analysis.forge.ForgedToken;
import com.tk.jwtinspector.detection.analysis.forge.TokenForger;

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
 * Modal dialog that lets the user generate forged tokens for the selected token.
 *
 * @author TK
 * @since 2026-05-11
 *
 * Purpose: Hosts three tabs, one per attack type. Each tab gathers inputs,
 * invokes TokenForger, shows the forged token with a Copy button. Pre-fills
 * cracked secrets from the TokenStore when available.
 */
public class ForgeDialog extends JDialog {

    private final DetectedToken token;
    private final TokenStore store;
    private final TokenForger forger = new TokenForger();

    public ForgeDialog(Window parent, DetectedToken token, TokenStore store) {
        super(parent, "Forge attack token", ModalityType.APPLICATION_MODAL);
        this.token = token;
        this.store = store;
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
        root.add(tabs, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton close = new JButton("Close");
        close.addActionListener(e -> dispose());
        buttons.add(close);
        root.add(buttons, BorderLayout.SOUTH);

        setContentPane(root);
        pack();
        setSize(Math.max(700, getWidth()), Math.max(550, getHeight()));
    }

    // ---- Tab 1: alg:none ----
    private class AlgNoneTab extends ForgeTab {
        AlgNoneTab() {
            super(ForgeAttack.ALG_NONE);
        }

        @Override
        protected void buildInputs(JPanel inputs) {
            JLabel info = new JLabel(
                    "<html>No inputs required &mdash; strips the signature and sets alg to 'none'.</html>");
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
            // IMPORTANT: instantiate here, not as field initializers, because
            // super(...) calls buildInputs before subclass field init runs.
            kidField = new JTextField("../../../dev/null", 30);
            secretField = new JTextField();

            inputs.add(new JLabel("Malicious kid value:"), gbc(0, 0, 1));
            inputs.add(kidField, gbc(1, 0, 1));

            inputs.add(new JLabel("Signing secret:"), gbc(0, 1, 1));
            secretField.setText(crackedSecretOrEmpty());
            secretField.setToolTipText("Secret the server will derive from your malicious kid lookup. "
                    + "Often empty string for /dev/null traversal.");
            inputs.add(secretField, gbc(1, 1, 1));

            JLabel hint = new JLabel(
                    "<html><i>Common payloads: ../../../dev/null, x' UNION SELECT 'AAA, "
                            + "$(id), %00</i></html>");
            hint.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
            inputs.add(hint, gbc(0, 2, 2));
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
            // IMPORTANT: instantiate here, not as field initializers.
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

            JLabel hint = new JLabel(
                    "<html><i>Tip: classic attack is flipping admin:false &rarr; admin:true. "
                            + "Edit the JSON above, then click Generate.</i></html>");
            hint.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
            inputs.add(hint, gbc(0, 3, 2));
        }

        @Override
        protected ForgedToken doForge() {
            return forger.forgeClaimTamper(
                    token.rawToken(),
                    payloadArea.getText(),
                    secretField.getText());
        }
    }

    // ---- Shared base for the three tab panels ----
    private abstract class ForgeTab extends JPanel {
        private final ForgeAttack attack;
        private final JTextArea outputArea = new JTextArea(4, 40);
        private final JButton generateButton = new JButton("Generate forged token");
        private final JButton copyButton = new JButton("Copy");
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

            JPanel center = new JPanel(new BorderLayout(0, 8));

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

            JPanel outputRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
            copyButton.setEnabled(false);
            outputRow.add(copyButton);
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

            add(center, BorderLayout.CENTER);

            JPanel bottom = new JPanel(new BorderLayout(8, 0));
            statusLabel.setForeground(new Color(0x40, 0x60, 0x80));
            bottom.add(statusLabel, BorderLayout.WEST);
            JPanel genRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
            genRow.add(generateButton);
            bottom.add(genRow, BorderLayout.EAST);
            add(bottom, BorderLayout.SOUTH);

            generateButton.addActionListener(e -> onGenerate());
            copyButton.addActionListener(e -> onCopy());
        }

        protected abstract void buildInputs(JPanel inputs);
        protected abstract ForgedToken doForge();

        private void onGenerate() {
            ForgedToken result = doForge();
            if (result.success()) {
                outputArea.setText(result.forgedToken());
                outputArea.setCaretPosition(0);
                copyButton.setEnabled(true);
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
