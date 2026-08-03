# Architecture

## Design principles

- **Separation of concerns.** `analyzer.py` (scanning), `findings_db.py`
  (knowledge base), `report_generator.py` (rendering), and `app.py`
  (Flask UI) are independent layers. The core logic has no web-framework
  dependency, so it's unit-testable and reusable from a CLI or script.
- **Safe by default (SSRF guard).** Before contacting the target,
  `analyzer._validate_target()` resolves the hostname and rejects
  private/loopback/link-local/reserved/multicast IP ranges. This stops
  the tool from being used to probe internal infrastructure.
- **Centralized findings knowledge.** All wording — severity,
  description, impact, remediation, OWASP/CWE/standards mapping — lives
  in one dictionary (`findings_db.FINDINGS`). The analyzer only decides
  *which* finding IDs apply; it never hardcodes text. This keeps report
  content consistent and makes it trivial to update wording or
  reclassify severity in one place.
- **Optional dependency degrades gracefully.** PDF export (WeasyPrint)
  is imported lazily; if it or its system libraries aren't installed,
  the app returns a clear message instead of crashing.

## Data flow

```
Browser ─▶ Flask app.py ─▶ analyzer.scan(url)
                              │
                              ├─ requests.Session().get()  (HTTPS, then
                              │   HTTP fallback detection)
                              ├─ parse Set-Cookie headers
                              └─ run per-header analysis functions
                                 (_analyze_hsts, _analyze_csp, _analyze_xfo,
                                  _analyze_xcto, _analyze_referrer_policy,
                                  _analyze_permissions_policy,
                                  _analyze_cookies)
                                        │
                                        ▼
                              Finding.from_template(id) ──▶ findings_db.py
                                        │
                                        ▼
                              ScanResult (headers, cookies, findings[])
                                        │
                     ┌──────────────────┼───────────────────┐
                     ▼                                       ▼
             templates/index.html                  report_generator.py
             (inline results view)                 (HTML string / PDF via
                                                      WeasyPrint)
```

Each `_analyze_*` function is a pure function: it takes parsed header
data and appends `Finding` objects to a list. Adding a new check means
adding one function plus one or more entries in `findings_db.FINDINGS` —
no changes needed elsewhere.

## Severity model

| Severity | Meaning |
|---|---|
| Critical | Site does not enforce HTTPS at all. |
| High | Missing controls that materially increase the impact of a common attack class (e.g. no CSP, no HSTS). |
| Medium | Weakens a defense-in-depth control (e.g. cookie missing HttpOnly/Secure/SameSite). |
| Low | Best-practice hardening gaps with limited standalone impact. |
| Informational | Optional hardening or a permissive-but-valid configuration worth reviewing. |

## Security considerations in the code itself

- Outbound requests set a descriptive `User-Agent`.
- A network timeout (10s) is set on every external call.
- The Flask `secret_key` is read from an environment variable with a
  random fallback — set `HEADER_ANALYZER_SECRET_KEY` explicitly for any
  multi-worker or non-local deployment.
- Report HTML output is escaped via `html.escape()` everywhere
  remote/user data is interpolated, to prevent stored-XSS in the
  generated report itself.
- Scan results are cached in-memory (capped, oldest-evicted) keyed by a
  random report ID so download links work without re-scanning; this is a
  single-process store suitable for local/small-team use, not a
  replacement for a real datastore at scale.
