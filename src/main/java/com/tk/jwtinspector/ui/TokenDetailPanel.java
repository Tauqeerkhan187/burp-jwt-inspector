package com.tk.jwtinspector.ui;

import com.nimbusds.jose.util.Base64URL;
import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.crack.CrackingService;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.List;

/**
 * Author: TK
 * Date: 05-05-2026
 * Right-hand panel: source metadata, decoded header/payload/signature,
 * and findings for the selected token.
 *
 * Whole panel is scrollable so findings (which can be many) don't squeeze
 * the JSON sections.
 */
public class TokenDetailPanel extends JPanel {

    private final JTextArea metadataArea;
    private final JTextArea headerArea;
    private final JTextArea payloadArea;
    private final JTextArea signatureArea;
    private final FindingsPanel findingsPanel;
    private final JButton crackButton;
    private final CrackingService crackingService;
    private DetectedToken currentToken;


    public TokenDetailPanel(CrackingService crackingService) {
        this.crackingService = crackingService;
        this.crackButton = new JButton("Crack secret (HMAC tokens only)");

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

        crackButton.setEnabled(false);
        crackButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        crackButton.addActionListener(e -> openCrackDialog());

        JPanel crackRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        crackRow.setOpaque(false);
        crackRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        crackRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, crackButton.getPreferredSize().height));
        crackRow.add(crackButton);
        inner.add(crackRow);
        inner.add(Box.createVerticalStrut(8));

        findingsPanel = new FindingsPanel();
        findingsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        inner.add(findingsPanel);

        // Whole detail view scrolls vertically
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

        metadataArea.setText(String.format(
                "URL: %s%nMethod: %s%nFound in: %s (%s)",
                token.url(),
                token.httpMethod(),
                token.source(),
                token.sourceDetail()
        ));

        private boolean isHmacToken(DetectedToken token) {
            try {
                String[] parts = token.rawToken().split("\\.", -1);
                if (parts.length < 2) return false;
                String headerJson = com.nimbusds.jose.util.Base64URL.from(parts[0]).decodeToString();
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
            CrackDialog dialog = new CrackDialog(owner, crackingService, currentToken);
            dialog.startCracking();
            dialog.setVisible(true);  // blocks until dialog is closed (modal)
        }

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

    public void clear() {
        metadataArea.setText("(no token selected)");
        headerArea.setText("");
        payloadArea.setText("");
        signatureArea.setText("");
        findingsPanel.clear();
        crackButton.setEnabled(false);
        this.currentToken = null;
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(550, 700);
    }
}