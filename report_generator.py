"""
report_generator.py
--------------------
Renders a ScanResult into a standalone HTML report (self-contained, no
external assets) and, optionally, a PDF via WeasyPrint.
"""

from __future__ import annotations

import datetime
import html
import os

from analyzer import ScanResult

SEVERITY_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#b91c1c",
    "Medium": "#c2410c",
    "Low": "#a16207",
    "Informational": "#1d4ed8",
}


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


MAX_EVIDENCE_CHARS = 600


def _esc_evidence(value) -> str:
    """
    Same as _esc, but caps rendered length. This is a report-layer
    safety net independent of analyzer.py: even if some future finding
    ends up with very long evidence (e.g. a large raw header value),
    the report stays readable and doesn't balloon in size, instead of
    relying solely on callers to keep evidence short.
    """
    text = str(value) if value is not None else ""
    if len(text) > MAX_EVIDENCE_CHARS:
        omitted = len(text) - MAX_EVIDENCE_CHARS
        text = text[:MAX_EVIDENCE_CHARS] + f"... [{omitted} more characters omitted]"
    return html.escape(text)


def render_html(result: ScanResult) -> str:
    generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    counts = result.summary_counts()

    if result.error:
        body = f"<p class='error'>Scan failed: {_esc(result.error)}</p>"
        findings_html = ""
    else:
        summary_chips = "".join(
            f"<span class='chip' style='background:{SEVERITY_COLORS[sev]}'>{sev}: {counts[sev]}</span>"
            for sev in SEVERITY_COLORS
        )
        body = f"""
        <table class='meta'>
          <tr><th>Target</th><td>{_esc(result.target)}</td></tr>
          <tr><th>Final URL</th><td>{_esc(result.final_url)}</td></tr>
          <tr><th>HTTP Status</th><td>{_esc(result.status_code)}</td></tr>
          <tr><th>HTTPS Enforced</th><td>{'Yes' if result.used_https else 'No'}</td></tr>
        </table>
        <div class='summary'>{summary_chips}</div>
        """

        findings_rows = []
        for f in result.findings_sorted():
            color = SEVERITY_COLORS.get(f.severity, "#374151")
            evidence = f"<div class='evidence'><strong>Evidence:</strong> {_esc_evidence(f.evidence)}</div>" if f.evidence else ""
            findings_rows.append(f"""
            <div class="finding">
              <div class="finding-header" style="border-left-color:{color}">
                <span class="severity-badge" style="background:{color}">{_esc(f.severity)}</span>
                <span class="finding-title">{_esc(f.title)}</span>
              </div>
              <div class="finding-body">
                <p><strong>Description:</strong> {_esc(f.description)}</p>
                <p><strong>Security Impact:</strong> {_esc(f.impact)}</p>
                <p><strong>Remediation:</strong> {_esc(f.remediation)}</p>
                <p><strong>OWASP Top 10:</strong> {_esc(f.owasp)}</p>
                <p><strong>CWE:</strong> {_esc(f.cwe)}</p>
                <p><strong>Standards:</strong> {_esc(f.standards)}</p>
                {evidence}
              </div>
            </div>
            """)
        findings_html = "".join(findings_rows) if findings_rows else "<p>No issues found. All checked headers/cookies are configured securely.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Header Analysis Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background:#f3f4f6; color:#111827; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 32px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .subtitle {{ color:#6b7280; margin-bottom: 24px; font-size: 13px; }}
  table.meta {{ width:100%; border-collapse: collapse; margin-bottom: 16px; background:white; border-radius:8px; overflow:hidden; }}
  table.meta th, table.meta td {{ text-align:left; padding:8px 12px; border-bottom:1px solid #e5e7eb; font-size:14px; }}
  table.meta th {{ width: 160px; color:#374151; background:#f9fafb; }}
  .summary {{ margin-bottom: 24px; }}
  .chip {{ display:inline-block; color:white; padding:4px 10px; border-radius:12px; font-size:12px; margin-right:6px; }}
  .finding {{ background:white; border-radius:8px; margin-bottom:14px; box-shadow:0 1px 2px rgba(0,0,0,.06); overflow:hidden;}}
  .finding-header {{ display:flex; align-items:center; gap:10px; padding:12px 16px; border-left:6px solid; background:#fafafa; }}
  .severity-badge {{ color:white; font-size:11px; font-weight:600; padding:2px 8px; border-radius:10px; text-transform:uppercase; }}
  .finding-title {{ font-weight:600; font-size:15px; }}
  .finding-body {{ padding: 4px 16px 14px 16px; font-size:13.5px; line-height:1.5; }}
  .finding-body p {{ margin: 6px 0; }}
  .evidence {{ margin-top:8px; background:#f3f4f6; padding:8px 10px; border-radius:6px; font-family: monospace; font-size:12px; word-break:break-all; }}
  .error {{ color:#b91c1c; font-weight:600; }}
  footer {{ margin-top: 32px; font-size:11px; color:#9ca3af; text-align:center; }}
</style>
</head>
<body>
<div class="container">
  <h1>Security Header Analysis Report</h1>
  <div class="subtitle">Generated {generated}</div>
  {body}
  <h2 style="font-size:16px; margin-top:28px;">Findings</h2>
  {findings_html}
  <footer>Generated by Security Header Analyzer &mdash; for authorized security assessments only.</footer>
</div>
</body>
</html>"""


class PdfExportError(RuntimeError):
    """Raised when PDF export is unavailable or fails, with a message
    safe to show directly to the user."""


def render_pdf(result: ScanResult, output_path: str) -> str:
    """
    Render the report to PDF using WeasyPrint.

    Raises PdfExportError (with a user-facing message) if:
      * WeasyPrint / its system dependencies (Pango, Cairo, GDK-Pixbuf)
        are not installed, or
      * WeasyPrint is installed but rendering fails for any other reason
        (e.g. a version mismatch with one of its own dependencies such
        as pydyf -- this has happened in practice and previously caused
        an unhandled 500 error, so it is now caught explicitly).
    """
    try:
        from weasyprint import HTML  # imported lazily; optional dependency
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise PdfExportError(
            "PDF export requires WeasyPrint and its system dependencies "
            "(Pango, Cairo, GDK-Pixbuf). Install via 'pip install weasyprint' "
            "and the OS packages described in the WeasyPrint docs."
        ) from exc
    except OSError as exc:  # pragma: no cover - environment dependent
        # WeasyPrint raises OSError (not ImportError) when the *Python*
        # package is installed but the native shared libraries it links
        # against (Pango/Cairo/GDK-Pixbuf) are missing from the system.
        raise PdfExportError(
            "PDF export is installed but its system libraries "
            "(Pango, Cairo, GDK-Pixbuf) are missing or broken. "
            "See docs/SETUP.md for the required OS packages."
        ) from exc

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        HTML(string=render_html(result)).write_pdf(output_path)
    except Exception as exc:
        raise PdfExportError(
            f"PDF rendering failed ({type(exc).__name__}: {exc}). "
            "This usually means an incompatible WeasyPrint/pydyf version "
            "pair is installed -- see requirements.txt and docs/SETUP.md."
        ) from exc
    return output_path
