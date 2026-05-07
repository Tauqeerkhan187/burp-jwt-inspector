package com.tk.jwtinspector.ui;

import com.nimbusds.jose.util.Base64URL;
import com.tk.jwtinspector.detection.DetectedToken;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.Border;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;

/**
 * Displays a selected token's metadata, decoded header, Payload and signature.
 * Three monospace text areas, color-coded like jwt.io's debugger.
 */

public class TokenDetailPanel extends JPanel {

    private final JTextArea metadataArea;
    private final JTextArea headerArea;
    private final JTextArea payloadArea;
    private final JTextArea signatureArea;

    public TokenDetailPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel ();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        metadataArea = makeArea(3);
        metadataArea.setBackground(new Color(0x2D, 0x2D, 0x2D));
        metadataArea.setForeground(Color.LIGHT_GRAY);
        top.add(labeled("Source", metadataArea));

        JPanel sections = new JPanel(new GridLayout(3, 1, 0, 8));

        headerArea = makeArea(6);
        headerArea.setForeground(new Color(0xFB, 0x01, 0x5B));
        sections.add(labeled("Header (decoded)", headerArea));

        payloadArea = makeArea(10);
        payloadArea.setForeground(new Color(0xD6, 0x3A, 0xFF));
        sections.add(labeled("Payload (decoded)", payloadArea));

        signatureArea = makeArea(4);
        signatureArea.setForeground(new Color(0x00, 0xB9, 0xF1));
        sections.add(labeled("Signature (raw)", signatureArea));

        add(top, BorderLayout.NORTH);
        add(sections, BorderLayout.CENTER);

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
        return panel;
    }

    public void show(DetectedToken token) {
        if (token == null) {
            clear();
            return;
        }

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
            return;
        }

        headerArea.setText(decodeJsonSegment(parts[0]));
        payloadArea.setText(decodeJsonSegment(parts[1]));
        signatureArea.setText(parts.length >= 3 && !parts[2].isEmpty()
                ? parts[2]
                : "(empty — alg:none token)");
    }

    private String decodeJsonSegment(String segment) {
        try {
            String json = Base64URL.from(segment).decodeToString();
            return prettyPrintJson(json);
        } catch (Exception e) {
            return "[decode error: " + e.getMessage() + "]";
        }
    }

    /**
     * Minimal pretty-printer — adds line breaks after commas/braces.
     * Avoids pulling in a JSON library just for formatting.
     */
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
                case ',' -> {
                    out.append(c).append('\n').append("  ".repeat(indent));
                }
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
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(500, 600);

    }
}
