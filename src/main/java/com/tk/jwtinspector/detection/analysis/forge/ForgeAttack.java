package com.tk.jwtinspector.detection.analysis.forge;

/**
 * Author: TK
 * Date: 16-11-2026
 * Purpose: A type-safe identifier for which kind of forgery is being requested,
 * so the engine doesn't take a stringly-typed parameter.
 */
public enum ForgeAttack 
{
    /** Strip signature, set alg to "none". Tests permissive verifiers. */
    ALG_NONE("alg:none forgery",
            "Strips the token's signature and sets the algorithm to 'none'. "
                    + "Succeeds against servers that fail to reject unsigned tokens "
                    + "— a classic JWT library bypass."),

    /** Inject malicious value into kid header, re-sign with chosen secret. */
    KID_INJECTION("kid injection",
            "Sets the 'kid' header to an attacker-controlled value. "
                    + "Succeeds against servers that use kid as a filesystem path "
                    + "(loading the key file) or database lookup without sanitization."),

    /** Modify claims and re-sign with a known/cracked secret. */
    CLAIM_TAMPER("Claim tampering",
            "Modifies arbitrary claims (e.g., flipping admin:false to admin:true) "
                    + "and re-signs with a known secret. Requires the secret — "
                    + "typically from cracking a weak HMAC secret first."),

    /** Sign with HS256 using the server's asymmetric PUBLIC key as the HMAC secret. */
    ALG_CONFUSION("Algorithm confusion (RS256 -> HS256)",
            "Re-signs the token with HS256 using the server's PUBLIC key as the HMAC secret. "
                    + "Succeeds when the server verifies with an algorithm-agnostic key, so a "
                    + "verifier expecting RS256 is tricked into running HMAC with the public key "
                    + "it already trusts — a full signature bypass without cracking anything.");

    private final String displayName;
    private final String description;

    ForgeAttack(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;

    }

    public String displayName() { return displayName; }
    public String description() { return description; }

}

