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


def _mock_response(url, status=200, headers=None, set_cookie_headers=None):
    resp = MagicMock()
    resp.url = url
    resp.status_code = status
    resp.headers = headers or {}
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


if __name__ == "__main__":
    unittest.main()
