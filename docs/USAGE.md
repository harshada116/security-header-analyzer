# Usage

1. Open the app (`http://127.0.0.1:5000` locally, or your deployed URL).
2. Enter a target, e.g. `https://example.com` (or just `example.com`).
3. Click **Scan**. The tool will:
   - Fetch the URL (following redirects) with a 10-second timeout.
   - Detect whether HTTPS is actually enforced (checks the *final* URL
     after redirects, not just the one you typed).
   - Parse `Strict-Transport-Security`, `Content-Security-Policy`,
     `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
     `Permissions-Policy`, and every `Set-Cookie` header's `HttpOnly`,
     `Secure`, and `SameSite` attributes.
4. Results appear inline: severity chip counts (Critical/High/Medium/
   Low/Informational) at the top, followed by one card per finding with:
   - Description of the issue
   - Security impact
   - Recommended remediation
   - OWASP Top 10 category, CWE ID(s), and relevant standards (NIST,
     PCI-DSS, OWASP ASVS, etc.)
5. Use **Download HTML Report** / **Download PDF Report** to save a
   shareable report.

## Interpreting severities

| Severity | Meaning |
|---|---|
| Critical | Site does not enforce HTTPS at all — credentials/sessions travel in cleartext. |
| High | Missing controls that materially increase the impact of a common attack class (e.g. no CSP, no HSTS, insecure `SameSite=None` cookie). |
| Medium | Weakens a defense-in-depth control (e.g. short HSTS max-age, cookie missing HttpOnly/Secure/SameSite). |
| Low | Best-practice hardening gaps with limited standalone impact (e.g. non-standard X-Frame-Options value). |
| Informational | Optional hardening (e.g. Permissions-Policy) or a permissive-but-valid configuration worth reviewing. |

## Programmatic / scripted use

`analyzer.py` has no Flask dependency, so you can use it directly:

```python
from analyzer import scan

result = scan("https://example.com")
for f in result.findings_sorted():
    print(f.severity, f.title)

print(result.summary_counts())
```

## Legal / ethical reminder

Only run this tool against targets you own or have explicit written
authorization to test.
