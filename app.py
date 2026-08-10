"""
app.py (Header Analyzer)
-------------------------
Small Flask web UI wrapping analyzer.py + report_generator.py.

Run:
    cd header_analyzer
    pip install -r ../requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import uuid

from flask import Flask, render_template, request, send_file, abort, flash, redirect, url_for

from analyzer import scan
import report_generator

app = Flask(__name__)
# SECRET_KEY only guards flash-message signing for this local tool; override
# via env var for anything beyond local/dev use.
app.secret_key = os.environ.get("HEADER_ANALYZER_SECRET_KEY", os.urandom(24))

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# In-memory store of last few scan results keyed by a random report id,
# so the "download HTML/PDF" links work without re-scanning. This is a
# single-process demo store; swap for a real datastore in production use.
_RESULT_CACHE: dict[str, "ScanResult"] = {}
_CACHE_MAX = 25


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html", result=None)

    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Please enter a target URL or hostname.")
        return redirect(url_for("index"))

    result = scan(target)

    report_id = uuid.uuid4().hex[:12]
    if len(_RESULT_CACHE) >= _CACHE_MAX:
        _RESULT_CACHE.pop(next(iter(_RESULT_CACHE)))
    _RESULT_CACHE[report_id] = result

    return render_template("index.html", result=result, report_id=report_id)


@app.route("/report/<report_id>.html")
def download_html(report_id):
    result = _RESULT_CACHE.get(report_id)
    if not result:
        abort(404)
    html_content = report_generator.render_html(result)
    path = os.path.join(REPORTS_DIR, f"{report_id}.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    return send_file(path, as_attachment=True, download_name="security-header-report.html")


@app.route("/report/<report_id>.pdf")
def download_pdf(report_id):
    result = _RESULT_CACHE.get(report_id)
    if not result:
        abort(404)
    path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")
    try:
        report_generator.render_pdf(result, path)
    except report_generator.PdfExportError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name="security-header-report.pdf")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
