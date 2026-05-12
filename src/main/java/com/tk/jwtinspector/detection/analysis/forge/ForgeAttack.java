package com.tk.jwtinspector.detection.analysis.forge;

/**
 * Author: TK
 * Date: 12-05-2026
 * Purpose: A type-safe identifier for which kind of forgery is being
 * requested, so the engine doesn't take a stringly-typed parameter.
 */

public enum ForgeAttack {
    /** Strip signature, set alg to "none". Tests permissive verifiers. */
    ALG_NONE("alg:none forgery",
            "Strips the token's signature and sets the algorithm to 'none'. "
                    + "Succeds against servers that fail to reject unsigned tokens "
                    + "- a classic JWT library bypass."),

    /** Inject malicious value into kid header, re-sign with chosen secret. */
    KID_INJECTION("kid injection",
            "Sets the 'kid' header to an attacker-controlled value. "
                    + "Succeeds against the servers that use kid as a filesystem path ")
                    +"(loading the key file) or database lookyp withour sanitisation."),

    /** Modify claims and re-sign with a known/cracked secret. */
    CLAIM_TAPER("Claim tampering",
                "Modigies arbitrary claims (e.g., flipping admin; false to admin: true) "
    )
}
))