package com.tk.jwtinspector.detection.analysis.forge;

import javax.print.DocFlavor;
import java.util.List;

/**
 * Author: TK
 * Date: 13-05-2026
 * Purpose: Carries the result of a TokenForger call back to the UI.
 * Includes instructive warnings so the UI can teach the user when each attack works.
 */

public record ForgedToken(
        boolean success,
        String forgedToken,
        ForgeAttack attack,
        List<String> warnings,
        String errorMessage
) {
    public static ForgedToken success(String token, ForgeAttack attack, List<String> warnings) {
        return new ForgedToken(true, token, attack, warnings, null);

    }

    public static ForgedToken failure(ForgeAttack attack, String error) {
        return new ForgedToken(false, null, attack, List.of(), error);

    }
}
