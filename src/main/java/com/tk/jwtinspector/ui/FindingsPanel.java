package com.tk.jwtinspector.ui;

import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.List;

/**
 * Author: TK
 * Date: 09-05-2026
 * Purpose: Displays a list of findings for a single token. Each finding is rendered
 * as a vertical card with a colored severity badge, title, description,
 * and optional evidence/remediation.
 *
 * Empty state ("no issues detected") is shown when no findings are present.
 */

public class FindingsPanel extends JPanel {

    private final JPanel content;
    private final JLabel headerLabel;

    public FindingsPanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(8,8,8,8));

        headerLabel = new JLabel("Findings");
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD));
        add(headerLabel, BorderLayout.NORTH);

        content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        JScrollPane scroll = new JScrollPane(content);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder(4,0,0,0));
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);

        showEmpty();

    }

    public void show(List<Finding> findings) {
        content.removeAll();

        if (findings == null || findings.isEmpty()) {
            showEmpty();
        }
        else {
            headerLabel.setText("Findings (" + findings.size() + ")");
            for (Finding f : findings) {
                content.add(buildCard(f));
                content.add(Box.createVerticalStrut(6));
            }
            content.add(Box.createVerticalGlue());
        }

        content.revalidate();
        content.repaint();
    }

    private void showEmpty() {
        headerLabel.setText("Findings");
        JLabel empty = new JLabel("No issues detected.");
        empty.setForeground(new Color(0x4C, 0x9C, 0x4C));
        empty.setBorder(BorderFactory.createEmptyBorder(8,4,8,4));
        content.add(empty);
    }

    public void clear() {
        content.removeAll();
        showEmpty();
        content.revalidate();
        content.repaint();
    }

    /**
     * Builds a single finding card. Layout:
     *
     *  [BADGE] Title (bold)
     *          Description (wrapped)
     *          Evidence: <monospace> (if present)
     *          Fix <italic remediation> (if present)
     */

    private JPanel buildCard(Finding finding) {
        JPanel card = new JPanel(new BorderLayout(8, 0));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 4, 0, 0, finding.severity().color()),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));

        // Severity Pill
        JLabel badge = new JLabel(" " + finding.severity().displayName().toUpperCase() + " ");
        badge.setOpaque(true);
        badge.setBackground(finding.severity().color());
        badge.setForeground(Color.WHITE);
        badge.setFont(badge.getFont().deriveFont(Font.BOLD, 10f));
        badge.setBorder(BorderFactory.createEmptyBorder(2,6,2,6));

        JPanel badgeWrap = new JPanel();
        badgeWrap.setLayout(new BoxLayout(badgeWrap, BoxLayout.Y_AXIS));
        badgeWrap.add(badge);
        badgeWrap.add(Box.createVerticalGlue());
        card.add(badgeWrap, BorderLayout.WEST);

        // Body: title + description + (evidence) + (remediation)
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));

        JLabel title = new JLabel(finding.title());
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        body.add(title);

        JTextArea desc = new JTextArea(finding.description());
        desc.setEditable(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setOpaque(false);
        desc.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
        desc.setAlignmentX(Component.LEFT_ALIGNMENT);
        body.add(desc);

        if (finding.evidence() != null && !finding.evidence().isBlank()) {
            JLabel evidence = new JLabel("Evidence: " + finding.evidence());
            evidence.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            evidence.setForeground(new Color(0x60, 0x60, 0x60));
            evidence.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
            evidence.setAlignmentX(Component.LEFT_ALIGNMENT);
            body.add(evidence);
        }

        if (finding.remediation() != null && !finding.remediation().isBlank()) {
            JLabel fix = new JLabel("Fix: " + finding.remediation());
            fix.setFont(fix.getFont().deriveFont(Font.ITALIC));
            fix.setForeground(new Color(0x40, 0x60, 0x80));
            fix.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
            fix.setAlignmentX(Component.LEFT_ALIGNMENT);
            body.add(fix);
        }

        card.add(body, BorderLayout.CENTER);
        return card;
    }
}