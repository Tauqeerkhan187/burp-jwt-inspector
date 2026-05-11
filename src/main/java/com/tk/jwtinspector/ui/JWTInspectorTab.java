package com.tk.jwtinspector.ui;

import com.tk.jwtinspector.detection.TokenStore;
import com.tk.jwtinspector.detection.analysis.crack.CrackingService;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import java.awt.BorderLayout;

/**
 * Author: TK
 * Date: 04-05-2026
 * Purpose:
 */

public class JWTInspectorTab extends JPanel {

    public JWTInspectorTab(TokenStore store, CrackingService crackingService) {
        setLayout(new BorderLayout());

        TokenDetailPanel detailPanel = new TokenDetailPanel(crackingService);

        // When a token is selected in the list, show it AND its findings
        TokenListPanel listPanel = new TokenListPanel(store, token -> {
            if (token == null) {
                detailPanel.show(null, java.util.List.of());
            } else {
                detailPanel.show(token, store.findingsFor(token.rawToken()));
            }
        });

        JSplitPane split = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                listPanel,
                detailPanel
        );
        split.setDividerLocation(450);
        split.setResizeWeight(0.4);

        add(split, BorderLayout.CENTER);
    }
}