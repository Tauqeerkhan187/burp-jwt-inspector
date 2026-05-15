package com.tk.jwtinspector.ui;

import com.nimbusds.jose.util.Base64URL;
import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.crack.CrackingService;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Window;
import java.util.List;

/**
 * Right-hand panel: source metadata, decoded header/payload/signature,
 * findings, and a Crack-secret action for HMAC-signed tokens.
 *
 * @author TK
 * @since 2026-05-10
 *
 * Purpose: Composes the detail view shown when a token is selected in
 * the left-hand list. Owns the Crack button which opens CrackDialog.
 */
public class TokenDetailPanel extends JPanel {

    private final JTextArea metadataArea;
    private final JTextArea headerArea;
    private final JTextArea payloadArea;
    private final JTextArea signatureArea;
    private final FindingsPanel findingsPanel;
    private final JButton crackButton;
    private final JButton forgeButton;
    private final CrackingService crackingService;
    private final TokenStore store;
    private DetectedToken currentToken;
    private final burp.api.montoya.logging.Logging logging;

    public TokenDetailPanel(CrackingService crackingService, TokenStore store, burp.api.montoya.logging.Logging logging) {
        this.crackingService = crackingService;
        this.store = store;
        this.logging = logging;
        this.crackButton = new JButton("Crack secret (HMAC tokens only)");
        this.forgeButton = new JButton("Forge attack");

        setLayout(new BorderLayout());

        JPanel inner = new JPanel();
        inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));
        inner.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        metadataArea = makeArea(3);
        metadataArea.setBackground(new Color(0x2D, 0x2D, 0x2D));
        metadataArea.setForeground(Color.LIGHT_GRAY);
        inner.add(labeled("Source", metadataArea));
        inner.add(Box.createVerticalStrut(8));

        headerArea = makeArea(6);
        headerArea.setForeground(new Color(0xFB, 0x01, 0x5B));
        inner.add(labeled("Header (decoded)", headerArea));
        inner.add(Box.createVerticalStrut(8));

        payloadArea = makeArea(8);
        payloadArea.setForeground(new Color(0xD6, 0x3A, 0xFF));
        inner.add(labeled("Payload (decoded)", payloadArea));
        inner.add(Box.createVerticalStrut(8));

        signatureArea = makeArea(3);
        signatureArea.setForeground(new Color(0x00, 0xB9, 0xF1));
        inner.add(labeled("Signature (raw)", signatureArea));
        inner.add(Box.createVerticalStrut(8));

        // Crack button row
        crackButton.setEnabled(false);
        crackButton.addActionListener(e -> openCrackDialog());

        forgeButton.setEnabled(false);
        forgeButton.addActionListener(e -> openForgeDialog());

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actionRow.setOpaque(false);
        actionRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        actionRow.setMaximumSize(new Dimension(Integer.MAX_VALUE,
                crackButton.getPreferredSize().height + 4));
        actionRow.add(crackButton);
        actionRow.add(forgeButton);
        inner.add(actionRow);
        inner.add(Box.createVerticalStrut(8));

        findingsPanel = new FindingsPanel();
        findingsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        inner.add(findingsPanel);

        JScrollPane scroll = new JScrollPane(inner);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);

        clear();
    }

    private JTextArea makeArea(int rows) {
        JTextArea area = new JTextArea(rows, 60);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    private JPanel labeled(String label, JTextArea area) {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        JLabel lbl = new JLabel(label);
        lbl.setFont(lbl.getFont().deriveFont(Font.BOLD));
        panel.add(lbl, BorderLayout.NORTH);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    public void show(DetectedToken token, List<Finding> findings) {
        if (token == null) {
            clear();
            return;
        }

        this.currentToken = token;
        crackButton.setEnabled(isHmacToken(token));
        forgeButton.setEnabled(true);

        metadataArea.setText(String.format(
                "URL: %s%nMethod: %s%nFound in: %s (%s)",
                token.url(),
                token.httpMethod(),
                token.source(),
                token.sourceDetail()
        ));

        String[] parts = token.rawToken().split("\\.", -1);
        if (parts.length < 2) {
            headerArea.setText("[malformed: fewer than 2 segments]");
            payloadArea.setText("");
            signatureArea.setText("");
        } else {
            headerArea.setText(decodeJsonSegment(parts[0]));
            payloadArea.setText(decodeJsonSegment(parts[1]));
            signatureArea.setText(parts.length >= 3 && !parts[2].isEmpty()
                    ? parts[2]
                    : "(empty — alg:none token)");
        }

        findingsPanel.show(findings);
    }

    private String decodeJsonSegment(String segment) {
        try {
            String json = Base64URL.from(segment).decodeToString();
            return prettyPrintJson(json);
        } catch (Exception e) {
            return "[decode error: " + e.getMessage() + "]";
        }
    }

    private String prettyPrintJson(String json) {
        StringBuilder out = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) inString = !inString;
            if (inString) { out.append(c); continue; }
            switch (c) {
                case '{', '[' -> {
                    out.append(c).append('\n');
                    indent++;
                    out.append("  ".repeat(indent));
                }
                case '}', ']' -> {
                    out.append('\n');
                    indent = Math.max(0, indent - 1);
                    out.append("  ".repeat(indent)).append(c);
                }
                case ',' -> out.append(c).append('\n').append("  ".repeat(indent));
                case ':' -> out.append(c).append(' ');
                default -> {
                    if (!Character.isWhitespace(c)) out.append(c);
                }
            }
        }
        return out.toString();
    }

    private boolean isHmacToken(DetectedToken token) {
        try {
            String[] parts = token.rawToken().split("\\.", -1);
            if (parts.length < 2) return false;
            String headerJson = Base64URL.from(parts[0]).decodeToString();
            return headerJson.contains("\"alg\":\"HS256\"")
                    || headerJson.contains("\"alg\":\"HS384\"")
                    || headerJson.contains("\"alg\":\"HS512\"")
                    || headerJson.contains("\"alg\": \"HS256\"")
                    || headerJson.contains("\"alg\": \"HS384\"")
                    || headerJson.contains("\"alg\": \"HS512\"");
        } catch (Exception e) {
            return false;
        }
    }

    private void openCrackDialog() {
        if (currentToken == null) return;
        Window owner = SwingUtilities.getWindowAncestor(this);
        CrackDialog dialog = new CrackDialog(owner, crackingService, store, currentToken);
        dialog.startCracking();
        dialog.setVisible(true);
    }

    private void openForgeDialog() {
        if (currentToken == null) return;
        Window owner = SwingUtilities.getWindowAncestor(this);
        ForgeDialog dialog = new ForgeDialog(owner, currentToken, store);
        dialog.setVisible(true);
    }

    public void clear() {
        metadataArea.setText("(no token selected)");
        headerArea.setText("");
        payloadArea.setText("");
        signatureArea.setText("");
        findingsPanel.clear();
        crackButton.setEnabled(false);
        forgeButton.setEnabled(false);
        this.currentToken = null;
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(550, 700);
    }
}
