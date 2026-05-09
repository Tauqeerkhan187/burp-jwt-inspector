package com.tk.jwtinspector.ui;

import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.TokenStore;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

public class TokenListPanel extends JPanel {

    private final DefaultListModel<DetectedToken> model = new DefaultListModel<>();
    private final JList<DetectedToken> list = new JList<>(model);
    private final JLabel countLabel = new JLabel("0  tokens");
    private final TokenStore store;

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    public TokenListPanel(TokenStore store, Consumer<DetectedToken> onSelect) {
        this.store = store;

        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new TokenCellRenderer(store));
        list.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        list.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onSelect.accept(list.getSelectedValue());
            }
        });

        JPanel header = new JPanel(new BorderLayout());
        header.add(countLabel, BorderLayout.WEST);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> store.clear());
        buttons.add(clearBtn);
        header.add(buttons, BorderLayout.EAST);

        add(header, BorderLayout.NORTH);
        add(new JScrollPane(list), BorderLayout.CENTER);

        // Prime list with anything already in the store
        for (DetectedToken t : store.snapshot()) {
            model.addElement(t);
        }
        updateCount();

        // listen to new detections
        store.addListener(this::onTokenEvent);
    }

    private void onTokenEvent(DetectedToken token) {
        if (token == null) {
            // clear signal
            model.clear();
        } else {
            model.addElement(token);
        }
        updateCount();
    }

    private void updateCount() {
        countLabel.setText(model.size() + "token" + (model.size() == 1 ? "" : "s"));
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(450, 600);
    }

    /**
     * Renders each token as: [time] METHOD host - short token preview
     */
    private static class TokenCellRenderer extends JPanel
            implements javax.swing.ListCellRenderer<DetectedToken> {

        private final JLabel topLabel = new JLabel();
        private final JLabel bottomLabel = new JLabel();
        private final JLabel severityBadge = new JLabel();
        private final TokenStore store;

        TokenCellRenderer(TokenStore store) {
            this.store = store;
            setLayout(new java.awt.BorderLayout(8, 0));
            setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

            topLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
            bottomLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            bottomLabel.setForeground(java.awt.Color.GRAY);

            severityBadge.setOpaque(true);
            severityBadge.setForeground(java.awt.Color.WHITE);
            severityBadge.setFont(severityBadge.getFont().deriveFont(Font.BOLD, 9f));
            severityBadge.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
            severityBadge.setHorizontalAlignment(JLabel.CENTER);

            JPanel textColumn = new JPanel();
            textColumn.setLayout(new BoxLayout(textColumn, BoxLayout.Y_AXIS));
            textColumn.setOpaque(false);
            textColumn.add(topLabel);
            textColumn.add(bottomLabel);

            // Badge sits to the right of the text
            JPanel badgeWrap = new JPanel();
            badgeWrap.setLayout(new BoxLayout(badgeWrap, BoxLayout.Y_AXIS));
            badgeWrap.setOpaque(false);
            badgeWrap.add(severityBadge);
            badgeWrap.add(Box.createVerticalGlue());

            add(textColumn, java.awt.BorderLayout.CENTER);
            add(badgeWrap, java.awt.BorderLayout.EAST);
        }

        @Override
        public java.awt.Component getListCellRendererComponent(
                JList<? extends DetectedToken> list,
                DetectedToken token,
                int index,
                boolean isSelected,
                boolean cellHasFocus) {

            String host;
            try {
                host = new java.net.URI(token.url()).getHost();
                if (host == null) host = token.url();
            } catch (Exception e) {
                host = token.url();
            }

            topLabel.setText(String.format("[%s] %s  %s",
                    TIME_FMT.format(token.detectedAt()),
                    token.httpMethod(),
                    host));
            bottomLabel.setText(token.shortToken());

            // Look up findings, find the highest severity
            var findings = store.findingsFor(token.rawToken());
            com.tk.jwtinspector.detection.analysis.Severity highest = null;
            for (var f : findings) {
                if (highest == null || f.severity().compareTo(highest) > 0) {
                    highest = f.severity();
                }
            }

            if (highest != null) {
                severityBadge.setText(highest.displayName().toUpperCase());
                severityBadge.setBackground(highest.color());
                severityBadge.setVisible(true);
            } else {
                severityBadge.setVisible(false);
            }

            if (isSelected) {
                setBackground(list.getSelectionBackground());
                topLabel.setForeground(list.getSelectionForeground());
                bottomLabel.setForeground(list.getSelectionForeground());
            } else {
                setBackground(list.getBackground());
                topLabel.setForeground(list.getForeground());
                bottomLabel.setForeground(java.awt.Color.GRAY);
            }
            setOpaque(true);

            return this;
        }
    }
}