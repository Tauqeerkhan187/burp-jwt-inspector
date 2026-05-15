package com.tk.jwtinspector.ui;

import com.tk.jwtinspector.detection.DetectedToken;
import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.crack.CrackResult;
import com.tk.jwtinspector.detection.analysis.crack.CrackingService;
import com.tk.jwtinspector.detection.analysis.crack.SecretCracker;

import javax.swing.*;
import java.nio.file.Path;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Modal dialog that runs a SecretCracker against a token and displays live
 * progress. Shows the cracked secret on success or a clear "not found"
 * message on exhaustion.
 *
 * Author: TK
 * Date: 10-05-2026
 *Purpose: The user-facing surface of the cracking feature. Owns the
 * SwingWorker lifecycle, progress callbacks, and the UI state machine
 * (RUNNING -> SUCCESS/FAILED/CANCELLED).
 */
public class CrackDialog extends JDialog {

    private final CrackingService service;
    private final DetectedToken token;
    private final TokenStore store;

    private final JLabel statusLabel = new JLabel(" ");
    private final JLabel attemptsLabel = new JLabel(" ");
    private final JLabel rateLabel = new JLabel(" ");
    private final JLabel currentLabel = new JLabel(" ");
    private final JLabel sourceLabel = new JLabel(" ");
    private final JProgressBar progressBar = new JProgressBar();
    private final JTextField secretField = new JTextField();
    private final JButton cancelButton = new JButton("Cancel");
    private final JButton closeButton = new JButton("Close");
    private final JButton copyButton = new JButton("Copy secret");
    private final JButton browseButton = new JButton("Browse....");

    private SecretCracker activeCracker;
    private SwingWorker<CrackResult, Long> worker;
    private long startTime;

    public CrackDialog(Window parent, CrackingService service, TokenStore store, DetectedToken token) {
        super(parent, "Crack JWT secret", ModalityType.APPLICATION_MODAL);
        this.service = service;
        this.store = store;
        this.token = token;

        buildUI();
        setLocationRelativeTo(parent);
    }

    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // Header: which token, how many candidates
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Cracking token: " + token.shortToken());
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(title);

        JPanel sourceRow = new JPanel(new BorderLayout(8, 0));
        sourceRow.setOpaque(false);
        sourceRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        sourceLabel.setForeground(new Color(0x60, 0x60, 0x60));
        sourceLabel.setText("Wordlist: " + service.wordlistSource());
        sourceRow.add(sourceLabel, BorderLayout.CENTER);
        sourceRow.add(browseButton, BorderLayout.EAST);
        sourceRow.setMaximumSize(new Dimension(Integer.MAX_VALUE,
                browseButton.getPreferredSize().height + 4));
        header.add(sourceRow);

        root.add(header, BorderLayout.NORTH);

        // Center: progress + live stats
        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));

        progressBar.setIndeterminate(false);
        progressBar.setMinimum(0);
        progressBar.setMaximum(Math.max(1, service.wordlistSize()));
        progressBar.setStringPainted(true);
        progressBar.setAlignmentX(Component.LEFT_ALIGNMENT);
        center.add(progressBar);
        center.add(Box.createVerticalStrut(8));

        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        center.add(statusLabel);

        attemptsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        center.add(attemptsLabel);

        rateLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        center.add(rateLabel);

        currentLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        currentLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        currentLabel.setForeground(new Color(0x80, 0x80, 0x80));
        center.add(currentLabel);

        center.add(Box.createVerticalStrut(12));

        // Result panel — secret appears here on success
        JPanel resultPanel = new JPanel(new BorderLayout(8, 0));
        resultPanel.setBorder(BorderFactory.createTitledBorder("Cracked secret"));
        secretField.setEditable(false);
        secretField.setFont(new Font(Font.MONOSPACED, Font.BOLD, 14));
        secretField.setHorizontalAlignment(JTextField.CENTER);
        resultPanel.add(secretField, BorderLayout.CENTER);
        copyButton.setEnabled(false);
        resultPanel.add(copyButton, BorderLayout.EAST);
        resultPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        center.add(resultPanel);

        root.add(center, BorderLayout.CENTER);

        // Bottom: action buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(cancelButton);
        buttons.add(closeButton);
        closeButton.setVisible(false);
        root.add(buttons, BorderLayout.SOUTH);

        // Wiring
        browseButton.addActionListener(e -> browseForWordlist());
        cancelButton.addActionListener(e -> {
            if (activeCracker != null) activeCracker.cancel();
            cancelButton.setEnabled(false);
            statusLabel.setText("Cancelling...");
        });
        closeButton.addActionListener(e -> dispose());
        copyButton.addActionListener(e -> {
            String secret = secretField.getText();
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(secret), null);
            copyButton.setText("Copied!");
            Timer t = new Timer(1500, ev -> copyButton.setText("Copy secret"));
            t.setRepeats(false);
            t.start();
        });

        setContentPane(root);
        pack();
        setSize(Math.max(520, getWidth()), getHeight());
    }

    private void browseForWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select wordlist file");
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;

        Path path = chooser.getSelectedFile().toPath();
        try {
            service.loadFromFile(path);
            sourceLabel.setText("Wordlist: " + service.wordlistSource());
            progressBar.setMaximum(Math.max(1, service.wordlistSize()));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to load wordlist: " + ex.getMessage(),
                    "Load error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Kicks off the crack. Called by the caller after constructing the dialog.
     * The dialog itself is shown with setVisible(true) — that call blocks until
     * the dialog is disposed (since it's modal).
     */
    public void startCracking() {
        browseButton.setEnabled(true);

        if (service.wordlistSize() == 0) {
            statusLabel.setText("No wordlist loaded.");
            cancelButton.setVisible(false);
            closeButton.setVisible(true);
            return;
        }

        statusLabel.setText("Cracking...");
        attemptsLabel.setText("Attempts: 0");
        rateLabel.setText("Rate: —");
        currentLabel.setText(" ");
        startTime = System.currentTimeMillis();

        activeCracker = service.newCracker();
        AtomicLong lastAttempts = new AtomicLong(0);

        worker = new SwingWorker<>() {
            @Override
            protected CrackResult doInBackground() {
                return activeCracker.crack(
                        token.rawToken(),
                        service.wordlist(),
                        (attempts, current) -> {
                            lastAttempts.set(attempts);
                            publish(attempts);
                            // Side-channel: stash the most recent candidate
                            // for the UI to display
                            currentCandidate = current;
                        }
                );
            }

            @Override
            protected void process(java.util.List<Long> chunks) {
                long latest = chunks.get(chunks.size() - 1);
                long elapsedMs = System.currentTimeMillis() - startTime;
                progressBar.setValue((int) Math.min(latest, progressBar.getMaximum()));
                attemptsLabel.setText("Attempts: " + latest + " / " + service.wordlistSize());
                if (elapsedMs > 0) {
                    long rate = latest * 1000 / elapsedMs;
                    rateLabel.setText("Rate: " + rate + " attempts/sec");
                }
                if (currentCandidate != null) {
                    currentLabel.setText("Trying: " + currentCandidate);
                }
            }

            @Override
            protected void done() {
                try {
                    CrackResult result = get();
                    onResult(result);
                } catch (Exception e) {
                    statusLabel.setText("Error: " + e.getMessage());
                    cancelButton.setVisible(false);
                    closeButton.setVisible(true);
                }
            }
        };
        worker.execute();
    }

    /** Most recent candidate the cracker reported — published to the UI. */
    private volatile String currentCandidate;

    private void onResult(CrackResult result) {
        cancelButton.setVisible(false);
        closeButton.setVisible(true);
        currentLabel.setText(" ");

        switch (result.status()) {
            case FOUND -> {
                statusLabel.setText("Secret cracked!");
                statusLabel.setForeground(new Color(0x1A, 0x86, 0x1A));
                progressBar.setValue(progressBar.getMaximum());
                secretField.setText(result.secret());
                copyButton.setEnabled(true);
                attemptsLabel.setText(String.format(
                        "Found in %d attempts (%d ms, %.0f attempts/sec)",
                        result.attemptCount(),
                        result.durationMs(),
                        result.attemptsPerSecond()));
                rateLabel.setText(" ");

                // Remember the secret so the ForgeDialog can pre-fill it
                store.recordCrackedSecret(token.rawToken(), result.secret());

            }
            case NOT_FOUND -> {
                statusLabel.setText("Secret not in wordlist.");
                statusLabel.setForeground(new Color(0xC0, 0x40, 0x10));
                attemptsLabel.setText(String.format(
                        "Tried %d candidates in %d ms (%.0f attempts/sec)",
                        result.attemptCount(),
                        result.durationMs(),
                        result.attemptsPerSecond()));
                rateLabel.setText("Try a larger wordlist for stronger secrets.");
            }
            case CANCELLED -> {
                statusLabel.setText("Cancelled.");
                attemptsLabel.setText("Stopped at "
                        + result.attemptCount() + " attempts.");
                rateLabel.setText(" ");
            }
            case ERROR -> {
                statusLabel.setText("Error: token couldn't be cracked.");
                statusLabel.setForeground(new Color(0xC0, 0x10, 0x10));
                attemptsLabel.setText("(unsupported algorithm or malformed token)");
                rateLabel.setText(" ");
            }
        }
    }
}
