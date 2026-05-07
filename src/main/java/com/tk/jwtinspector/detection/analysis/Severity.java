package com.tk.jwtinspector.detection.analysis;

import java.awt.Color;

/**
 * Author: TK
 * Date: 02-05-2026
 * Severity levels for vulnerability findings, ordered from least to most severe.
 * Each carries a display color used by the UI.
 *
 * Color scale: gray, blue, yellow, orange, red, matching standard.
 * Vulnerability-severity conventions (Burp itself, OWASP, CVSS visualization).
 */

public enum Severity {
    INFO("Info", new Color(0x60, 0x60, 0x60)),
    LOW("Low", new Color(0x37, 0x83, 0xC7)),
    MEDIUM("Medium", new Color(0xE0, 0xA0, 0x10)),
    HIGH("High", new Color(0xE0, 0x60, 0x10)),
    CRITICAL("Critical", new Color(0xC0, 0x10, 0x10));

    private final String displayName;
    private final Color color;

    Severity(String displayName, Color color) {
        this.displayName = displayName;
        this.color = color;
    }

    public String displayName() {
        return displayName;
    }

    public Color color() {
        return color;
    }

    /**
     * Returns true if this sev is HIGH or CRITICAL - used by the UI
     * to decide which tokens get a warning badge in the list.
     */

    public boolean isAlarming() {
        return this == HIGH || this == CRITICAL;
    }
}
