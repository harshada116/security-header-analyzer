# Security Header Analyzer

A web-based tool that scans a target website and analyzes its
security-related HTTP response headers and cookie attributes.

Checks performed:

- HTTP Strict Transport Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cookie security attributes: `HttpOnly`, `Secure`, `SameSite`
- **Exposed version control metadata** — publicly accessible `.git`,
  `.svn`, `.hg`, `.bzr`, or CVS directories, and a stray `.gitignore`
  file at the web root (a common misconfiguration that can leak full
  source code, commit history, and past credentials)

For each issue found, the tool reports:

- **Severity** — Critical / High / Medium / Low / Informational
- **Description** — what's missing or misconfigured
- **Security impact** — the real-world consequence
- **Remediation** — the concrete header/config change to fix it
- **Compliance mapping** — **OWASP Top 10:2025**, CWE, and relevant
  standards (NIST, PCI-DSS, OWASP ASVS)

Reports can be exported as **HTML** or **PDF**.

> ⚠️ Use only against systems you own or are explicitly authorized to test.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, enter a URL, click **Scan**.

See [`docs/SETUP.md`](docs/SETUP.md) for full install/deploy instructions,
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for design notes, and
[`docs/USAGE.md`](docs/USAGE.md) for how to use the tool and interpret
results.

## Running tests

```bash
python -m unittest test_analyzer.py -v
```

## Project layout

```
security-header-analyzer/
├── analyzer.py          core scan logic (no Flask dependency)
├── findings_db.py       severity/impact/remediation/compliance knowledge base
├── vcs_exposure.py      exposed .git/.svn/.hg/.bzr/CVS detection
├── report_generator.py  HTML + PDF report rendering
├── app.py                Flask web UI
├── templates/, static/
├── test_analyzer.py     unit tests (mocked, no network required)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── docs/
```
