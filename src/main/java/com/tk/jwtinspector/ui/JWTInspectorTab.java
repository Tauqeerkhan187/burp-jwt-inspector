package com.tk.jwtinspector.ui;

import com.tk.jwtinspector.detection.TokenStore;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import java.awt.BorderLayout;

public class JWTInspectorTab extends JPanel{

    public JWTInspectorTab(TokenStore store) {
        setLayout(new BorderLayout());

        TokenDetailPanel detailPanel = new TokenDetailPanel();
        TokenListPanel listPanel = new TokenListPanel(store, detailPanel::show);

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
