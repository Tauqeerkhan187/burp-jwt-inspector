# Changelog

## Unreleased

### New
- **Key-source header check.** Flags `jku`, `x5u`, `jwk` and `x5c` headers, which tell the server where to get its verification key, as MEDIUM findings with remediation advice.

### Quality
- 42 unit tests (up from 36).

## 1.1.0

Two new attacks against RS256 tokens, and a forge dialog that's easier to use.

### New
- **Algorithm confusion: JWKS auto-fetch.** One click downloads the server's JWKS (`/.well-known/jwks.json`, then `/jwks.json`) through Burp, picks the key matching the token's `kid`, and fills in its PEM. If several keys exist and none match, it reports that instead of guessing.
- **JWK header injection.** Signs the token with a freshly generated RSA key pair and embeds its public half in the `jwk` header.

Both were verified ACCEPTED by the built-in oracle against PortSwigger's algorithm-confusion and jwk-header-injection labs.

### Changed
- The startup output in Burp's Output tab now lists the loaded checks, attacks and wordlist size, read from the code instead of a hand-written line.

### Fixed
- The forged-token box collapsed on tabs with many inputs. Tab content now scrolls instead.
- Long status messages overlapped the Generate button. The status line now has its own row, with the full text on hover.

### Quality
- 36 unit tests (up from 25), including JWK → PEM round trips and verifying JWK-injection signatures against the embedded key.

### Install
Download `jwt-inspector-1.1.0.jar` from the release. In Burp, remove the 1.0.0 extension, then **Extensions → Installed → Add → Java** and select the JAR.

## 1.0.0

First stable release of JWT Inspector, a Burp Suite extension that automates the JWT attack chain: detect, analyse, crack, forge, verify.

### Features
- **Passive detection** of JWTs in proxied requests and responses (headers, cookies, params, bodies)
- **Six vulnerability checks** with severity-ranked findings
- **HMAC secret cracking** at ~1M attempts/sec against a bundled 103k-entry wordlist, or your own
- **Forging**: alg:none, kid injection, claim tampering, and RS256→HS256 algorithm confusion
- **Verification oracle**: replays the forged token next to the real one and reports ACCEPTED / REJECTED / INCONCLUSIVE, instead of assuming HTTP 200 means success
- **Send to Repeater** with the forged token substituted into the original request

### Quality
- 25 unit tests covering forging, cracking, detection and the oracle's decision logic
- CI builds and tests every push

### Install
1. Download `jwt-inspector-1.0.0.jar` from the release.
2. In Burp: **Extensions → Installed → Add → Java**, then select the JAR.

Requires Burp Suite 2024.x or later (Montoya API). For authorised testing only.
