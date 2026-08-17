"""
vcs_exposure.py
----------------
Checks whether a target web application publicly exposes its version
control system metadata (.git, .svn, .hg, .bzr, CVS) or a stray
.gitignore file at the web root.

This is a distinct, well-established class of security misconfiguration
(OWASP Testing Guide WSTG-CONF-04, CWE-527/538) separate from the HTTP
security-header checks in analyzer.py: an exposed .git directory allows
full source-code reconstruction (secrets, internal logic, historical
credentials) via tools like git-dumper, entirely independent of how well
the site's security headers are configured.

The checker only issues a small number of lightweight, read-only GET
requests to well-known, static paths -- it never attempts to actually
clone/dump the repository -- so it stays fast and non-intrusive even
though it confirms exposure with reasonable confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin

import requests

from findings_db import FINDINGS

USER_AGENT = "SecurityHeaderAnalyzer/1.0 (+internal security tooling)"
REQUEST_TIMEOUT = 6

# Each entry: (finding_id, path-to-check, validator).
# validator is either:
#   - a list of byte substrings, ALL of which are matched via a
#     compiled regex requiring the pattern to actually look like that
#     file format (not just "contains this common character"), or
#   - None, meaning no positive content signature exists for this path
#     (see _looks_like_real_hit for how that case is handled safely).
_CHECKS = [
    ("vcs_git_exposed", ".git/HEAD", [re.compile(rb"^ref:\s*refs/", re.MULTILINE)]),
    ("vcs_git_exposed", ".git/config", [re.compile(rb"\[core\]")]),
    ("vcs_svn_exposed", ".svn/entries", [re.compile(rb"\n\s*dir\s*\n")]),
    ("vcs_svn_exposed", ".svn/wc.db", [re.compile(rb"^SQLite format 3\x00")]),
    ("vcs_hg_exposed", ".hg/requires", [re.compile(rb"revlogv1|dotencode|store")]),
    ("vcs_hg_exposed", ".hg/store/00manifest.i", None),  # binary; presence + status is enough
    ("vcs_bzr_exposed", ".bzr/README", [re.compile(rb"This is a Bazaar")]),
    # CVS/Root: a single line in the form ":method:[user@]host:/path" or
    # a bare local path -- requiring a leading colon is far more specific
    # than "contains a colon anywhere".
    ("vcs_cvs_exposed", "CVS/Root", [re.compile(rb"^:\w+:")]),
    # CVS/Entries: lines follow "/name/revision/date/options/tag" --
    # require that shape rather than "contains a slash anywhere".
    ("vcs_cvs_exposed", "CVS/Entries", [re.compile(rb"^/[^/\r\n]+/[\d.]+/", re.MULTILINE)]),
    ("vcs_gitignore_exposed", ".gitignore", None),
]


@dataclass
class VcsCheckResult:
    findings: List["Finding"]  # noqa: F821 - Finding imported lazily to avoid a cycle
    checked_paths: List[str]
    error: Optional[str] = None


def _looks_like_real_hit(status_code: int, body: bytes, must_contain) -> bool:
    if status_code != 200 or not body:
        return False

    # Many sites return HTTP 200 with a generic HTML "not found" page for
    # *any* path (SPA catch-alls, custom CMS 404 pages). None of the VCS
    # metadata files we probe for are ever HTML documents, so rejecting
    # HTML-looking bodies up front eliminates this whole class of false
    # positive regardless of which signature check follows.
    head = body[:2000].lower()
    if b"<html" in head or b"<!doctype" in head:
        return False

    if must_contain is None:
        # No positive content signature available for this path (e.g. a
        # binary Mercurial manifest, or a plain-text .gitignore whose
        # content varies per project) -- accept based on size alone now
        # that the HTML check above has ruled out soft-404 pages.
        return 0 < len(body) < 5_000_000

    return any(pattern.search(body) for pattern in must_contain)


def check_version_control_exposure(base_url: str) -> VcsCheckResult:
    """
    Probe well-known VCS metadata paths under `base_url` and return any
    matching findings. Imports Finding lazily from analyzer.py to avoid a
    circular import (analyzer imports this module).
    """
    from analyzer import Finding  # local import: analyzer -> vcs_exposure -> analyzer would cycle otherwise

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    findings: List[Finding] = []
    seen_finding_ids = set()
    checked_paths: List[str] = []

    for finding_id, path, must_contain in _CHECKS:
        url = urljoin(base_url.rstrip("/") + "/", path)
        checked_paths.append(url)
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue  # network hiccup on one probe shouldn't abort the rest

        if _looks_like_real_hit(resp.status_code, resp.content, must_contain):
            if finding_id in seen_finding_ids:
                continue  # one finding per VCS type, even if multiple paths hit
            seen_finding_ids.add(finding_id)
            tpl = FINDINGS[finding_id]
            findings.append(
                Finding(
                    id=finding_id,
                    evidence=f"Publicly accessible: {url}",
                    **tpl,
                )
            )

    return VcsCheckResult(findings=findings, checked_paths=checked_paths)
