package com.tk.jwtinspector.ui;

import javax.swing.JPanel;
import javax.swing.JViewport;
import javax.swing.Scrollable;
import java.awt.Dimension;
import java.awt.LayoutManager;
import java.awt.Rectangle;

/**
 * Author: TK
 * Date: 24-11-2026
 * Purpose: A panel for use inside a JScrollPane that always fills the scroll
 * pane's width (so wrapped text wraps to the visible width) but keeps its own
 * preferred height. When there isn't enough room, it scrolls instead of
 * squeezing its contents; when there's spare room, it stretches to fill it.
 */

class WidthTrackingPanel extends JPanel implements Scrollable {

    WidthTrackingPanel(LayoutManager layout) {
        super(layout);

    }

    @Override
    public Dimension getPreferredScrollableViewportSize(){
        return getPreferredSize();

    }

    @Override
    public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) {
        return 16;

    }

    @Override
    public int getScrollableBlockIncrement(Rectangle visible, int orientation,  int direction) {
        return visible.height;

    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return true;

    }

    @Override
    public boolean getScrollableTracksViewportHeight() {
    // Stretch to fill spare room; or keep natural height and scroll;
    return getParent() instanceof JViewport viewport && viewport.getHeight() > getPreferredSize().height;
    }

}
