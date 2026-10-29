#!/usr/bin/env python3
"""
HTTP Security Headers Checker
Checks a URL for common security response headers and flags information leaks.

Usage:  python security_headers_checker.py https://example.com
Only run this against sites you own or have permission to test.
"""
import sys
import urllib.request
import urllib.error

# header name -> (why it matters, recommended value)
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("Forces HTTPS, blocks SSL-stripping",
                                  "max-age=31536000; includeSubDomains"),
    "Content-Security-Policy": ("Limits where scripts/resources load from (XSS defense)",
                                "default-src 'self'"),
    "X-Content-Type-Options": ("Stops MIME-type sniffing", "nosniff"),
    "X-Frame-Options": ("Prevents clickjacking via iframes", "DENY or SAMEORIGIN"),
    "Referrer-Policy": ("Controls how much URL info leaks in Referer",
                        "strict-origin-when-cross-origin"),
    "Permissions-Policy": ("Restricts browser features (camera, mic, etc.)",
                           "geolocation=(), camera=()"),
}

# headers that reveal technology details to an attacker
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def fetch_headers(url):
    req = urllib.request.Request(url, headers={"User-Agent": "header-checker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.geturl(), resp.headers
    except urllib.error.HTTPError as e:      # 4xx/5xx still return headers
        return e.code, url, e.headers


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python security_headers_checker.py <url>")
    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        status, final_url, headers = fetch_headers(url)
    except Exception as e:
        sys.exit(f"[!] Could not connect: {e}")

    print(f"\nTarget : {final_url}\nStatus : {status}\n")
    present = 0
    for name, (why, rec) in SECURITY_HEADERS.items():
        value = headers.get(name)
        if name == "Strict-Transport-Security" and not final_url.startswith("https://"):
            print(f"[SKIP]    {name}: site is not served over HTTPS")
            continue
        if value:
            present += 1
            print(f"[PASS]    {name}: {value}")
        else:
            print(f"[MISSING] {name}\n          why: {why}\n          fix: {name}: {rec}")

    print("\nInformation disclosure:")
    leaks = [(h, headers[h]) for h in LEAKY_HEADERS if headers.get(h)]
    if leaks:
        for h, v in leaks:
            print(f"[WARN]    {h}: {v}  (consider removing or hiding the version)")
    else:
        print("[OK]      No leaky headers found")

    print(f"\nScore: {present}/{len(SECURITY_HEADERS)} security headers present\n")


if __name__ == "__main__":
    main()
