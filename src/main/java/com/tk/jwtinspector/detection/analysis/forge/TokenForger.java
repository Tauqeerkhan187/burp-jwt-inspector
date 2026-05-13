package com.tk.jwtinspector.detection.analysis.forge;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates forged JWT tokens for each supported attack type.
 *
 * Author: TK
 * Date: 13-05-2026
 * Purpose: Stateless utility that produces forged tokens given an original token
 * plus attack-specific parameters. Each forge method is independent;
 * Callers pick the one matching their attack.
 *
 *  Output JWT format throughout:
 *  base64url(header) "." base64url(payload) "." signature
 *  Empty signature segment for alg:none.
 */

public class TokenForger {
}
