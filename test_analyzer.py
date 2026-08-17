"""
test_analyzer.py
-----------------
Lightweight unit tests for analyzer.py using unittest.mock to avoid making
real network calls. Run with:

    cd header_analyzer
    python -m pytest test_analyzer.py -v
    (or: python -m unittest test_analyzer.py -v)
"""

import unittest
from unittest.mock import MagicMock, patch

import analyzer


def _mock_response(url, status=200, headers=None, set_cookie_headers=None, content=b""):
    resp = MagicMock()
    resp.url = url
    resp.status_code = status
    resp.headers = headers or {}
    resp.content = content  # real requests.Response.content is always bytes
    raw_headers = MagicMock()
    raw_headers.get_all.return_value = set_cookie_headers or []
    resp.raw.headers = raw_headers
    return resp


class TestValidateTarget(unittest.TestCase):
    def test_rejects_private_ip(self):
        with patch("analyzer.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]
            with self.assertRaises(analyzer.InvalidTargetError):
                analyzer._validate_target("http://internal.local")

    def test_accepts_public_ip(self):
        with patch("analyzer.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            url = analyzer._validate_target("example.com")
            self.assertTrue(url.startswith("https://"))


class TestScanLogic(unittest.TestCase):
    @patch("analyzer._validate_target", side_effect=lambda u: u)
    @patch("analyzer.requests.Session.get")
    def test_fully_insecure_site_raises_expected_findings(self, mock_get, _validate):
        mock_get.return_value = _mock_response(
            "http://example.com/",
            headers={},
            set_cookie_headers=["session=abc123"],
        )
        result = analyzer.scan("http://example.com")
        finding_ids = {f.id for f in result.findings}

        self.assertIn("no_https", finding_ids)
        self.assertIn("csp_missing", finding_ids)
        self.assertIn("xfo_missing", finding_ids)
        self.assertIn("xcto_missing", finding_ids)
        self.assertIn("referrer_policy_missing", finding_ids)
        self.assertIn("permissions_policy_missing", finding_ids)
        self.assertIn("cookie_missing_httponly", finding_ids)
        self.assertIn("cookie_missing_secure", finding_ids)
        self.assertIn("cookie_missing_samesite", finding_ids)
        # HSTS should not be flagged since the site never used HTTPS
        self.assertNotIn("hsts_missing", finding_ids)

    @patch("analyzer._validate_target", side_effect=lambda u: u)
    @patch("analyzer.requests.Session.get")
    def test_well_configured_site_has_no_findings(self, mock_get, _validate):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        mock_get.return_value = _mock_response(
            "https://example.com/",
            headers=headers,
            set_cookie_headers=["session=abc123; HttpOnly; Secure; SameSite=Strict"],
        )
        result = analyzer.scan("https://example.com")
        self.assertEqual(result.findings, [])

    @patch("analyzer._validate_target", side_effect=lambda u: u)
    @patch("analyzer.requests.Session.get")
    def test_samesite_none_without_secure(self, mock_get, _validate):
        mock_get.return_value = _mock_response(
            "https://example.com/",
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
            },
            set_cookie_headers=["track=xyz; HttpOnly; SameSite=None"],
        )
        result = analyzer.scan("https://example.com")
        finding_ids = {f.id for f in result.findings}
        self.assertIn("cookie_missing_secure", finding_ids)
        self.assertIn("cookie_samesite_none_insecure", finding_ids)


class TestPdfExport(unittest.TestCase):
    """
    Regression test for a real incident: weasyprint==62.3 combined with a
    too-new pydyf (>=0.11) raises AttributeError during rendering (not at
    import time), which previously was not caught and crashed the PDF
    download route with an unhandled 500. This test exercises actual PDF
    rendering (not mocked) so a bad dependency pin fails CI immediately.
    """

    def test_render_pdf_produces_a_pdf_file(self):
        try:
            import weasyprint  # noqa: F401
        except ImportError:
            self.skipTest("weasyprint not installed in this environment")

        import tempfile
        import report_generator

        result = analyzer.ScanResult(
            target="example.com",
            final_url="https://example.com",
            status_code=200,
            used_https=True,
            headers={"Server": "nginx"},
        )
        result.findings.append(analyzer.Finding.from_template("csp_missing"))

        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/report.pdf"
            try:
                out_path = report_generator.render_pdf(result, path)
            except report_generator.PdfExportError as exc:
                self.fail(
                    "render_pdf raised PdfExportError -- likely a "
                    f"weasyprint/pydyf version mismatch: {exc}"
                )
            with open(out_path, "rb") as fh:
                content = fh.read()
            self.assertTrue(content.startswith(b"%PDF"), "output is not a valid PDF")
            self.assertGreater(len(content), 500)


class TestVcsExposure(unittest.TestCase):
    def _mock_get_factory(self, hits: dict):
        """hits: {path_suffix: (status_code, content_bytes)}"""
        def _mock_get(url, timeout=None, allow_redirects=None):
            resp = MagicMock()
            resp.status_code = 404
            resp.content = b""
            for suffix, (status, content) in hits.items():
                if url.endswith(suffix):
                    resp.status_code = status
                    resp.content = content
                    break
            return resp
        return _mock_get

    @patch("analyzer.requests.Session.get")
    def test_exposed_git_directory_detected(self, mock_get):
        import vcs_exposure
        mock_get.side_effect = self._mock_get_factory({
            ".git/HEAD": (200, b"ref: refs/heads/main\n"),
        })
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        ids = {f.id for f in result.findings}
        self.assertIn("vcs_git_exposed", ids)

    @patch("analyzer.requests.Session.get")
    def test_no_false_positive_on_clean_site(self, mock_get):
        import vcs_exposure
        mock_get.side_effect = self._mock_get_factory({})  # everything 404s
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        self.assertEqual(result.findings, [])

    @patch("analyzer.requests.Session.get")
    def test_soft_404_page_not_mistaken_for_git_exposure(self, mock_get):
        """A custom error page that returns 200 with generic HTML for
        every path (a common SPA/CMS pattern) must not be misdetected as
        an exposed .git directory, since it won't contain the expected
        'ref:' / '[core]' signatures."""
        import vcs_exposure

        def _soft_404(url, timeout=None, allow_redirects=None):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"<html><body>Page not found</body></html>"
            return resp

        mock_get.side_effect = _soft_404
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        ids = {f.id for f in result.findings}
        self.assertNotIn("vcs_git_exposed", ids)
        self.assertNotIn("vcs_svn_exposed", ids)


    @patch("analyzer.requests.Session.get")
    def test_cvs_entries_weak_marker_does_not_match_ordinary_html(self, mock_get):
        """
        Regression test: an earlier version of this checker used a bare
        '/' as the CVS/Entries signature, which matched any HTML page
        containing a closing tag (e.g. '</html>'). Confirms the anchored
        regex used now does not have this false-positive.
        """
        import vcs_exposure

        def _generic_200(url, timeout=None, allow_redirects=None):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"<html><body>Page not found</body></html>"
            return resp

        mock_get.side_effect = _generic_200
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        ids = {f.id for f in result.findings}
        self.assertNotIn("vcs_cvs_exposed", ids)

    def test_end_to_end_scan_does_not_false_positive_on_soft_404_site(self):
        """
        Full scan() integration check: a site that returns HTTP 200 with
        a generic HTML body for every path (a common SPA/CMS pattern)
        must not trigger any vcs_* finding.
        """
        def mock_response(url, timeout=None, allow_redirects=None, verify=None):
            resp = MagicMock()
            resp.url = "https://example.com/"
            resp.status_code = 200
            resp.headers = {}
            resp.raw.headers.get_all.return_value = []
            resp.content = b"<html>not found</html>"
            return resp

        with patch("analyzer.requests.Session.get", side_effect=mock_response):
            result = analyzer.scan("https://example.com")
        vcs_ids = {f.id for f in result.findings if f.id.startswith("vcs_")}
        self.assertEqual(vcs_ids, set())


    @patch("analyzer.requests.Session.get")
    def test_exposed_svn_wc_db_detected(self, mock_get):
        import vcs_exposure
        mock_get.side_effect = self._mock_get_factory({
            ".svn/wc.db": (200, b"SQLite format 3\x00" + b"\x00" * 100),
        })
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        ids = {f.id for f in result.findings}
        self.assertIn("vcs_svn_exposed", ids)

    @patch("analyzer.requests.Session.get")
    def test_exposed_hg_requires_detected(self, mock_get):
        import vcs_exposure
        mock_get.side_effect = self._mock_get_factory({
            ".hg/requires": (200, b"revlogv1\nstore\nfncache\n"),
        })
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        ids = {f.id for f in result.findings}
        self.assertIn("vcs_hg_exposed", ids)

    @patch("analyzer.requests.Session.get")
    def test_exposed_bzr_readme_detected(self, mock_get):
        import vcs_exposure
        mock_get.side_effect = self._mock_get_factory({
            ".bzr/README": (200, b"This is a Bazaar control directory.\n"),
        })
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        ids = {f.id for f in result.findings}
        self.assertIn("vcs_bzr_exposed", ids)

    @patch("analyzer.requests.Session.get")
    def test_exposed_cvs_root_detected(self, mock_get):
        import vcs_exposure
        mock_get.side_effect = self._mock_get_factory({
            "CVS/Root": (200, b":pserver:anonymous@cvs.example.com:/cvsroot/project\n"),
        })
        result = vcs_exposure.check_version_control_exposure("https://example.com")
        ids = {f.id for f in result.findings}
        self.assertIn("vcs_cvs_exposed", ids)


if __name__ == "__main__":
    unittest.main()
