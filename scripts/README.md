# HTTP Security Headers Checker

A small Python script (standard library only, no installs) that checks a URL for common security response headers and flags information-disclosure headers.

## What it checks
| Header | Why it matters |
|---|---|
| Strict-Transport-Security | Forces HTTPS, blocks SSL-stripping |
| Content-Security-Policy | Limits resource sources (XSS defense) |
| X-Content-Type-Options | Stops MIME sniffing |
| X-Frame-Options | Prevents clickjacking |
| Referrer-Policy | Limits URL info leaking to other sites |
| Permissions-Policy | Restricts browser features |

It also warns on `Server`, `X-Powered-By` and `X-AspNet-Version`, which reveal technology and version details to an attacker.

## Usage
```
python security_headers_checker.py https://your-own-site.example
```

> **Only run this against sites you own or have written permission to test.**

## Sample output
Run against a local test server I set up with deliberately incomplete headers:

```

Target : http://127.0.0.1:8099
Status : 200

[SKIP]    Strict-Transport-Security: site is not served over HTTPS
[MISSING] Content-Security-Policy
          why: Limits where scripts/resources load from (XSS defense)
          fix: Content-Security-Policy: default-src 'self'
[PASS]    X-Content-Type-Options: nosniff
[PASS]    X-Frame-Options: DENY
[MISSING] Referrer-Policy
          why: Controls how much URL info leaks in Referer
          fix: Referrer-Policy: strict-origin-when-cross-origin
[MISSING] Permissions-Policy
          why: Restricts browser features (camera, mic, etc.)
          fix: Permissions-Policy: geolocation=(), camera=()

Information disclosure:
[WARN]    Server: BaseHTTP/0.6 Python/3.12.3  (consider removing or hiding the version)

Score: 2/6 security headers present

```

## What I'd improve next
- Check cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- Parse CSP and flag unsafe values like `unsafe-inline`
- Accept a list of URLs and export results to CSV
