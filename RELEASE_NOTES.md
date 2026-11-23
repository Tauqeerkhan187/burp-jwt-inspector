First stable release of JWT Inspector, a Burp Suite extension that automates the JWT attack chain: detect, analyse, crack, forge, verify.

## Features
- **Passive detection** of JWTs in proxied requests and responses (headers, cookies, params, bodies)
- **Six vulnerability checks** with severity-ranked findings
- **HMAC secret cracking** at ~1M attempts/sec against a bundled 103k-entry wordlist, or your own
- **Forging**: alg:none, kid injection, claim tampering, and RS256→HS256 algorithm confusion
- **Verification oracle**: replays the forged token next to the real one and reports ACCEPTED / REJECTED / INCONCLUSIVE, instead of assuming HTTP 200 means success
- **Send to Repeater** with the forged token substituted into the original request

## Quality
- 25 unit tests covering forging, cracking, detection and the oracle's decision logic
- CI builds and tests every push

## Install
1. Download `jwt-inspector-1.0.0.jar` below.
2. In Burp: **Extensions → Installed → Add → Java**, then select the JAR.

Requires Burp Suite 2024.x or later (Montoya API). For authorised testing only.
