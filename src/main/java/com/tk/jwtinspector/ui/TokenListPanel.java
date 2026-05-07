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
    private final JLabel countLabel = new JLabel("0 tokens");
    private final TokenStore store;

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    public TokenListPanel(TokenStore store, Consumer<DetectedToken> onSelect) {
        this.store =  store;

        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(8,8,8,8));

        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new TokenCellRenderer());
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
        for (DetectedToken t: store.snapshot()) {
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

        TokenCellRenderer() {
            setLayout(new java.awt.BorderLayout());
            setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

            topLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
            bottomLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            bottomLabel.setForeground(java.awt.Color.GRAY);

            add(topLabel, java.awt.BorderLayout.NORTH);
            add(bottomLabel, java.awt.BorderLayout.SOUTH);
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
