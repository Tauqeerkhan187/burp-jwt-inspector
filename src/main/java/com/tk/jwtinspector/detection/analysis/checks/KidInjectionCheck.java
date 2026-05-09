package com.tk.jwtinspector.detection.analysis.checks;

import com.nimbusds.jwt.JWT;
import com.tk.jwtinspector.detection.analysis.Finding;
import com.tk.jwtinspector.detection.analysis.Severity;
import com.tk.jwtinspector.detection.analysis.VulnerabilityCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Author: TK
 * Date: 09-05-2026
 *
 * Flags `kid` header values containing patterns associated with common attacks.
 *
 * Some JWT verifiers use `kid` as a filesystem path (loading a key file)
 * or as a database lookup key (loading a key row). If unsanitized:
 * - Path traversal: kid="../../../dev/null" can force the verifier to use
 *   /dev/null as the "key", making the attacker's HMAC signature with empty
 *   key valid.
 * - SQL injection: kid="x' UNION SELECT 'attacker_key" can return an
 *   attacker-controlled key from the lookup.
 * - Command injection if kid is passed to a shell.
 *
 * Real-world examples include Auth0 advisories and CVEs in numerous JWT libs.
 */
public class KidInjectionCheck implements VulnerabilityCheck {

    private static final Pattern PATH_TRAVERSAL = Pattern.compile("\\.\\.[/\\\\]");
    private static final Pattern SQL_META = Pattern.compile("['\";]|--|\\bUNION\\b|\\bSELECT\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SHELL_META = Pattern.compile("[`$()|&;<>]");
    private static final Pattern NULL_BYTE = Pattern.compile("\\x00|%00");

    @Override
    public String id() {
        return "kid-injection";
    }

    @Override
    public List<Finding> check(JWT jwt) {
        try {
            Object kidObj = jwt.getHeader().toJSONObject().get("kid");
            if (kidObj == null) return List.of();
            String kid = kidObj.toString();
            if (kid.isEmpty()) return List.of();

            List<Finding> findings = new ArrayList<>();

            if (PATH_TRAVERSAL.matcher(kid).find()) {
                findings.add(Finding.of(
                        Severity.HIGH,
                        "Path traversal pattern in `kid`",
                        "The `kid` header contains `../`, suggesting an attempt to traverse the filesystem. "
                                + "If the server uses `kid` as a path to load a verification key, this could "
                                + "trick it into using a controlled or empty file as the key, enabling signature "
                                + "forgery.",
                        kid
                ));
            }

            if (SQL_META.matcher(kid).find()) {
                findings.add(Finding.of(
                        Severity.HIGH,
                        "SQL injection pattern in `kid`",
                        "The `kid` header contains SQL metacharacters or keywords. If the server uses "
                                + "`kid` as a database lookup key without parameterization, this could enable "
                                + "SQLi — potentially returning an attacker-controlled key.",
                        kid
                ));
            }

            if (SHELL_META.matcher(kid).find()) {
                findings.add(Finding.of(
                        Severity.HIGH,
                        "Shell metacharacters in `kid`",
                        "The `kid` header contains shell metacharacters. If the server passes `kid` to a "
                                + "shell command (e.g., to invoke a key-fetching script), this could enable "
                                + "command injection.",
                        kid
                ));
            }

            if (NULL_BYTE.matcher(kid).find()) {
                findings.add(Finding.of(
                        Severity.HIGH,
                        "Null byte in `kid`",
                        "The `kid` header contains a null byte. Null bytes can truncate strings in some "
                                + "language runtimes (notably C-backed code) and bypass extension or path checks.",
                        kid
                ));
            }

            return findings;
        } catch (Exception e) {
            return List.of();
        }
    }
}
