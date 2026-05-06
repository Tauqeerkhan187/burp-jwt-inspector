# Burp JWT Inspector

A Burp Suite extension for automatic JWT detection, analysis, and exploitation.

**Status:** in development. Built as a portfolio project.

## Planned features

- Automatic JWT detection across proxy traffic (headers, cookies, bodies, params)
- Inline decoder with vulnerability flagging (`alg:none`, weak HMAC, missing claims)
- Offline secret cracking via dictionary attack
- One-click attack payload generation (alg confusion, kid injection, claim forgery)

## Build

```bash
./gradlew shadowJar
```

Output: `build/libs/burp-jwt-inspector-*.jar`

Load in Burp: *Extensions* → *Add* → select the JAR.

## License

MIT
