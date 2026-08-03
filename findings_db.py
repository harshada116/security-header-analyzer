"""
findings_db.py
--------------
Static knowledge base describing every security-header / cookie-attribute
finding the analyzer can raise. Keeping this data separate from the scan
logic (analyzer.py) makes it trivial to update severities, wording, or
compliance mappings without touching the scanning code.

Each finding template contains:
    id            -> stable machine-readable identifier
    title         -> short human readable title
    severity      -> Critical | High | Medium | Low | Informational
    description   -> what was found / what is missing
    impact        -> the security consequence if left unaddressed
    remediation   -> concrete steps to fix it
    owasp         -> related OWASP Top 10 (2021) category
    cwe           -> related CWE identifier(s)
    standards     -> other relevant standards (NIST, PCI-DSS, ASVS, etc.)
"""

FINDINGS = {
    # ---------------------------------------------------------------- HSTS
    "hsts_missing": {
        "title": "HTTP Strict Transport Security (HSTS) header is missing",
        "severity": "High",
        "description": (
            "The response does not include a Strict-Transport-Security header. "
            "Without it, browsers may allow the site to be reached over plain "
            "HTTP, or may downgrade a future connection after a certificate "
            "warning."
        ),
        "impact": (
            "Attackers on the network path (e.g. on public Wi-Fi) can perform "
            "SSL-stripping / man-in-the-middle attacks, silently downgrading "
            "the connection to HTTP and intercepting or tampering with traffic."
        ),
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; "
            "preload' to every HTTPS response and consider submitting the domain "
            "to the HSTS preload list (hstspreload.org)."
        ),
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "standards": "NIST SP 800-52, PCI-DSS 4.0 Req 4.2, OWASP ASVS 9.1",
    },
    "hsts_short_max_age": {
        "title": "HSTS max-age is too short",
        "severity": "Medium",
        "description": (
            "A Strict-Transport-Security header is present but its max-age "
            "directive is below the recommended 1 year (31536000 seconds)."
        ),
        "impact": (
            "A short max-age reduces the protection window; once it expires "
            "the browser will again accept a plain HTTP connection, re-opening "
            "the door to SSL-stripping attacks."
        ),
        "remediation": "Increase max-age to at least 31536000 (1 year), e.g. "
                        "'max-age=31536000; includeSubDomains; preload'.",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "standards": "OWASP ASVS 9.1",
    },
    "hsts_no_subdomains": {
        "title": "HSTS does not include subdomains",
        "severity": "Low",
        "description": (
            "The Strict-Transport-Security header is present but does not "
            "set the includeSubDomains directive."
        ),
        "impact": (
            "Subdomains are not covered by the HSTS policy and remain "
            "susceptible to SSL-stripping and cookie-injection attacks that "
            "can subsequently affect the parent domain."
        ),
        "remediation": "Add the 'includeSubDomains' directive once every "
                        "subdomain is confirmed to support HTTPS.",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "standards": "OWASP ASVS 9.1",
    },

    # ----------------------------------------------------------------- CSP
    "csp_missing": {
        "title": "Content-Security-Policy header is missing",
        "severity": "High",
        "description": (
            "The response does not include a Content-Security-Policy header, "
            "so the browser enforces no restriction on which scripts, styles, "
            "or other resources may execute or load on the page."
        ),
        "impact": (
            "Significantly increases the impact of any Cross-Site Scripting "
            "(XSS) vulnerability, since injected scripts run with no "
            "browser-level restriction, and enables data-exfiltration and "
            "clickjacking-style attacks via arbitrary resource loading."
        ),
        "remediation": (
            "Define a restrictive CSP, e.g. \"default-src 'self'; "
            "script-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'self'\", then iteratively tighten it using "
            "report-only mode and the CSP report-uri/report-to directive."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames "
               "/ CWE-79: Cross-Site Scripting",
        "standards": "OWASP ASVS 14.4, OWASP Secure Headers Project",
    },
    "csp_unsafe_inline": {
        "title": "CSP allows 'unsafe-inline' scripts or styles",
        "severity": "Medium",
        "description": (
            "The Content-Security-Policy includes 'unsafe-inline' in a "
            "script-src or style-src directive, permitting inline "
            "<script>/<style> execution."
        ),
        "impact": (
            "Largely neutralizes CSP's primary defense against XSS, since an "
            "injected inline script will still execute under this policy."
        ),
        "remediation": (
            "Remove 'unsafe-inline' and use nonces or hashes "
            "(script-src 'nonce-<random>') for legitimate inline scripts, or "
            "move inline code to external files."
        ),
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page "
               "Generation (XSS)",
        "standards": "OWASP ASVS 14.4.3",
    },
    "csp_unsafe_eval": {
        "title": "CSP allows 'unsafe-eval'",
        "severity": "Medium",
        "description": (
            "The Content-Security-Policy script-src directive includes "
            "'unsafe-eval', permitting eval(), Function(), and similar "
            "dynamic-code-execution APIs."
        ),
        "impact": (
            "Enables execution of attacker-supplied strings as JavaScript, "
            "weakening CSP's ability to stop DOM-based XSS."
        ),
        "remediation": "Remove 'unsafe-eval' and refactor code that relies on "
                        "eval()/new Function() to avoid dynamic code execution.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-95: Improper Neutralization of Directives in Dynamically "
               "Evaluated Code",
        "standards": "OWASP ASVS 14.4.3",
    },
    "csp_wildcard_source": {
        "title": "CSP uses an overly permissive wildcard source",
        "severity": "Medium",
        "description": (
            "One or more CSP directives allow '*' (or a very broad scheme "
            "such as https:) as a source, permitting resources from "
            "essentially any origin."
        ),
        "impact": (
            "Allows loading of scripts/styles/frames from any third-party "
            "or attacker-controlled domain, undermining the policy's "
            "intent to restrict trusted sources."
        ),
        "remediation": "Replace wildcard sources with an explicit allow-list "
                        "of the specific domains the application actually needs.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-346: Origin Validation Error",
        "standards": "OWASP ASVS 14.4",
    },
    "csp_missing_frame_ancestors": {
        "title": "CSP does not restrict frame-ancestors",
        "severity": "Low",
        "description": (
            "The Content-Security-Policy is present but does not define a "
            "frame-ancestors directive to restrict who may embed the page "
            "in an <iframe>."
        ),
        "impact": (
            "In the absence of frame-ancestors (and a matching "
            "X-Frame-Options), the page can be embedded on attacker sites, "
            "enabling clickjacking / UI-redress attacks."
        ),
        "remediation": "Add \"frame-ancestors 'self'\" (or a specific "
                        "allow-list) to the CSP.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        "standards": "OWASP ASVS 14.4.7",
    },

    # ------------------------------------------------------ X-Frame-Options
    "xfo_missing": {
        "title": "X-Frame-Options header is missing",
        "severity": "Medium",
        "description": (
            "The response does not include an X-Frame-Options header and the "
            "CSP frame-ancestors directive is also absent, so the page can "
            "be framed by any site."
        ),
        "impact": "Enables clickjacking attacks where the site is loaded in "
                   "a hidden/transparent iframe to trick users into "
                   "performing unintended actions.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' (and/or "
                        "the CSP frame-ancestors directive, which is the "
                        "modern replacement).",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        "standards": "OWASP Secure Headers Project",
    },
    "xfo_weak_value": {
        "title": "X-Frame-Options set to a non-standard or permissive value",
        "severity": "Low",
        "description": (
            "The X-Frame-Options header is present but set to a value other "
            "than DENY or SAMEORIGIN (e.g. ALLOW-FROM, which is deprecated "
            "and unsupported by modern browsers)."
        ),
        "impact": "The deprecated ALLOW-FROM directive is ignored by current "
                   "browsers, effectively leaving the page unprotected from "
                   "framing in those browsers.",
        "remediation": "Use 'DENY' or 'SAMEORIGIN', and pair it with a CSP "
                        "frame-ancestors directive for modern browser support.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        "standards": "OWASP Secure Headers Project",
    },

    # --------------------------------------------------- X-Content-Type-Options
    "xcto_missing": {
        "title": "X-Content-Type-Options header is missing",
        "severity": "Low",
        "description": (
            "The response does not include 'X-Content-Type-Options: nosniff', "
            "allowing browsers to MIME-sniff the response content type."
        ),
        "impact": (
            "MIME-sniffing can cause a browser to interpret an "
            "attacker-controlled file (e.g. an uploaded image) as HTML or "
            "JavaScript, facilitating stored XSS."
        ),
        "remediation": "Add 'X-Content-Type-Options: nosniff' to all "
                        "responses.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-116: Improper Encoding or Escaping of Output",
        "standards": "OWASP Secure Headers Project",
    },

    # ----------------------------------------------------------- Referrer-Policy
    "referrer_policy_missing": {
        "title": "Referrer-Policy header is missing",
        "severity": "Low",
        "description": (
            "No Referrer-Policy header is set, so the browser default "
            "(strict-origin-when-cross-origin in modern browsers, but "
            "historically more permissive) governs how much of the URL is "
            "leaked in the Referer header on outbound navigation."
        ),
        "impact": (
            "Sensitive information embedded in URLs (session identifiers, "
            "tokens, search terms, internal paths) may be leaked to "
            "third-party sites via the Referer header."
        ),
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' "
                        "or a stricter value such as 'no-referrer' where "
                        "appropriate.",
        "owasp": "A01:2021 - Broken Access Control / A02:2021 - Cryptographic "
                  "Failures",
        "cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized "
               "Actor",
        "standards": "OWASP Secure Headers Project",
    },
    "referrer_policy_permissive": {
        "title": "Referrer-Policy is set to a permissive value",
        "severity": "Informational",
        "description": (
            "The Referrer-Policy header is present but set to a permissive "
            "value such as 'unsafe-url' or 'no-referrer-when-downgrade', "
            "which forwards the full URL (including path and query string) "
            "on cross-origin requests."
        ),
        "impact": "Full URLs, potentially containing sensitive parameters, "
                   "may be disclosed to third-party origins.",
        "remediation": "Use 'strict-origin-when-cross-origin' or 'no-referrer' "
                        "unless the full referrer is genuinely required.",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized "
               "Actor",
        "standards": "OWASP Secure Headers Project",
    },

    # -------------------------------------------------------- Permissions-Policy
    "permissions_policy_missing": {
        "title": "Permissions-Policy header is missing",
        "severity": "Informational",
        "description": (
            "No Permissions-Policy (formerly Feature-Policy) header is "
            "present, so the page and any embedded third-party frames "
            "retain access to powerful browser features by default."
        ),
        "impact": (
            "Third-party or compromised scripts/iframes may access "
            "sensitive browser APIs such as camera, microphone, geolocation, "
            "or USB without explicit restriction."
        ),
        "remediation": (
            "Add a Permissions-Policy header that disables unneeded "
            "features, e.g. 'Permissions-Policy: camera=(), microphone=(), "
            "geolocation=(), interest-cohort=()'."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-732: Incorrect Permission Assignment for Critical Resource",
        "standards": "W3C Permissions Policy, OWASP Secure Headers Project",
    },

    # -------------------------------------------------------------------- Cookies
    "cookie_missing_httponly": {
        "title": "Cookie set without the HttpOnly attribute",
        "severity": "Medium",
        "description": (
            "A Set-Cookie header was observed without the HttpOnly "
            "attribute, allowing the cookie to be read via "
            "document.cookie in JavaScript."
        ),
        "impact": (
            "If an XSS vulnerability exists anywhere on the site, the "
            "cookie (which may contain a session identifier) can be "
            "exfiltrated by injected JavaScript, leading to session "
            "hijacking."
        ),
        "remediation": "Add the HttpOnly attribute to all cookies that do "
                        "not need to be accessed by client-side script "
                        "(most session/authentication cookies).",
        "owasp": "A05:2021 - Security Misconfiguration / A07:2021 - "
                  "Identification and Authentication Failures",
        "cwe": "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
        "standards": "OWASP ASVS 3.4.1, PCI-DSS 4.0 Req 6.2",
    },
    "cookie_missing_secure": {
        "title": "Cookie set without the Secure attribute",
        "severity": "Medium",
        "description": (
            "A Set-Cookie header was observed without the Secure attribute, "
            "so the browser may transmit the cookie over an unencrypted "
            "HTTP connection."
        ),
        "impact": (
            "An attacker performing network interception (e.g. on a "
            "shared/public network) can capture the cookie in cleartext and "
            "impersonate the user."
        ),
        "remediation": "Add the Secure attribute to all cookies on an "
                        "HTTPS-only site so they are only ever sent over "
                        "TLS-protected connections.",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' "
               "Attribute",
        "standards": "OWASP ASVS 3.4.2, PCI-DSS 4.0 Req 4.2",
    },
    "cookie_missing_samesite": {
        "title": "Cookie set without the SameSite attribute",
        "severity": "Medium",
        "description": (
            "A Set-Cookie header was observed without a SameSite attribute. "
            "Modern browsers default missing SameSite to 'Lax', which "
            "provides partial but incomplete CSRF protection."
        ),
        "impact": (
            "Increases exposure to Cross-Site Request Forgery (CSRF) "
            "attacks, since the cookie may still be sent on some "
            "cross-site top-level navigations."
        ),
        "remediation": "Explicitly set 'SameSite=Strict' or 'SameSite=Lax' "
                        "for session/authentication cookies, and 'SameSite="
                        "None; Secure' only for cookies that must be sent "
                        "cross-site.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-352: Cross-Site Request Forgery (CSRF)",
        "standards": "OWASP ASVS 3.4.3",
    },
    "cookie_samesite_none_insecure": {
        "title": "Cookie uses SameSite=None without the Secure attribute",
        "severity": "High",
        "description": (
            "A cookie declares 'SameSite=None' but does not also set "
            "'Secure'. Browsers reject this combination, but it indicates "
            "a misconfiguration."
        ),
        "impact": "The cookie may be rejected by modern browsers, breaking "
                   "functionality, or on older browsers may be sent "
                   "insecurely cross-site.",
        "remediation": "Always pair 'SameSite=None' with the 'Secure' "
                        "attribute.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' "
               "Attribute",
        "standards": "OWASP ASVS 3.4.2",
    },

    # ------------------------------------------------------------- Transport
    "no_https": {
        "title": "Site does not enforce HTTPS",
        "severity": "Critical",
        "description": (
            "The target could only be reached over plain HTTP, or the "
            "HTTPS endpoint did not respond / redirect properly."
        ),
        "impact": "All traffic, including credentials and session cookies, "
                   "is transmitted in cleartext and can be intercepted or "
                   "modified by anyone on the network path.",
        "remediation": "Obtain a TLS certificate, serve all content over "
                        "HTTPS, and redirect all HTTP requests to HTTPS with "
                        "a 301 response plus HSTS.",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "standards": "PCI-DSS 4.0 Req 4.2, NIST SP 800-52",
    },
}
