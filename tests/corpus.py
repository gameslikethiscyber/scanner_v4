"""
Golden corpus v3 — deterministic ScanResult scenarios for engine regression.

Every scenario builder returns a fresh ScanResult (call it again for a clean
copy). Findings carry scanner-side raw output exactly as the current scanners
produce it:

  - All 19 scanners are migrated and evidence-only: they collect raw evidence
    only (status stays UNKNOWN, severity stays NONE, no reason/confidence set);
    the engine pipeline derives everything. No legacy `_finding` scenarios
    remain.

Engines are then applied by the harness. Scenario coverage (Phase B0
requirement): clean, missing headers, CORS misconfig, SQL injection, XSS, TLS
variations, CMS/framework detection, plus SSTI, LFI+SSRF, Open Redirect, Host
Header, CSRF, Ports, Sensitive Files, HTTP Methods, Source Leaks, Cookies, DNS,
Security.txt, a scan-with-UNKNOWN/incomplete module, and a broad mixed corpus.
"""

from typing import Callable, Dict, List

from core.evidence import Evidence, EvidenceBuilder
from core.finding import Finding, ScanResult, Status, Severity


def _raw_finding(module: str, evidence: List, tests: int = 1,
                 occurrences: int = 1, target: str = "https://example.com") -> Finding:
    """Raw-evidence finding as a migrated scanner emits it (engines decide)."""
    f = Finding()
    f.module = module
    f.title = module
    f.status = Status.UNKNOWN
    f.severity = Severity.NONE
    f.target = target
    f.tests_performed = tests
    f.tests_run = tests
    f.occurrences = occurrences
    for ev in evidence:
        f.add_evidence(ev)
    return f


def _cv(description: str, techniques: int = 2) -> Evidence:
    """Cross-validation evidence as the SQLi/XSS scanners emit it (2+ signals)."""
    ev = eb.cross_validation(description)
    ev.verification_pass = techniques
    ev.verification_method = f"{techniques} independent signals"
    return ev


def _obs(description: str, payload: str, parameter: str,
         status_code: int = 200, body_length: int = 1000,
         method: str = "GET") -> Evidence:
    """Confirmed request/response observation as the SQLi/XSS scanners emit it
    (primary + confirm payload reproduced, so verification_pass=2)."""
    ev = eb.request_response(
        description,
        request={'method': method, 'payload': payload},
        response={'status_code': status_code, 'body_length': body_length},
        payload=payload, parameter=parameter, method=method,
    )
    ev.verification_pass = 2
    ev.verification_method = "primary + confirm payloads"
    return ev


def _scan(findings: List[Finding], total_modules: int = 0) -> ScanResult:
    sr = ScanResult()
    for f in findings:
        sr.add_finding(f)
    sr.total_modules = total_modules or len(findings)
    sr.end_time = sr.start_time
    return sr


eb = EvidenceBuilder()

_scenario_builders: Dict[str, Callable[[], ScanResult]] = {}


def _scenario(name: str, description: str, priority: int = 10):
    def decorator(fn):
        fn._description = description
        fn._priority = priority
        _scenario_builders[name] = fn
        return fn
    return decorator


@_scenario("clean_site", "Clean website: no vulnerabilities; all checks pass or informational.")
def _clean_site():
    return _scan([
        _raw_finding("Headers Security",
                     [eb.verified("All security headers properly set")], tests=12),
        _raw_finding("TLS/SSL Security",
                     [eb.verified("Valid TLS 1.3 with strong cipher suite")], tests=8),
        _raw_finding("DNS Security",
                     [eb.verified("DNSSEC and CAA records present")], tests=3),
        _raw_finding("Cookies Security",
                     [eb.verified("Session cookies Secure+HttpOnly")], tests=6),
        _raw_finding("CORS Configuration",
                     [eb.verified("CORS policy is restrictive: no tested origin is "
                                  "allowed by Access-Control-Allow-Origin")],
                     tests=5),
        _raw_finding("CSRF Protection",
                     [eb.verified("No POST forms found on the page — no "
                                  "state-changing (POST) surface to evaluate "
                                  "CSRF protection")],
                     tests=1),
        _raw_finding("Host Header Injection",
                     [eb.verified("No host header injection detected: none of the "
                                  "test hosts are reflected in the response body, "
                                  "redirects, generated URLs, or response content")],
                     tests=4),
        _raw_finding("Security.txt",
                     [eb.verified("Security.txt is accessible at "
                                  "https://example.com/.well-known/security.txt"),
                      eb.likely("Security.txt issue: missing required 'Contact' directive")],
                     tests=2),
        _raw_finding("Technology Detection",
                     [eb.verified("Technology detected: Nginx (via header Server)"),
                      eb.verified("Technology detected: React (via body fingerprint)")],
                     tests=16),
    ])


@_scenario("missing_headers", "Missing security headers; weak TLS; insecure cookies.")
def _missing_headers():
    return _scan([
        _raw_finding("Headers Security",
                     [eb.likely("X-Frame-Options is missing"),
                      eb.likely("Content-Security-Policy is missing")], tests=12),
        _raw_finding("TLS/SSL Security",
                     [eb.verified("TLS Handshake successful: TLSv1.0"),
                      eb.likely("Weak TLS version detected: TLSv1.0. Disable TLS 1.0 and 1.1.")],
                     tests=8),
        _raw_finding("Cookies Security",
                     [eb.likely("Cookie 'session' is not HTTPS-only"),
                      eb.likely("Cookie 'session' is accessible to JavaScript "
                                "(no HttpOnly flag)"),
                      eb.verified("Cookie 'session' restricts cross-site sending "
                                  "(SameSite=Lax)"),
                      eb.verified("Cookie 'session' is a session cookie "
                                  "(no Expires/Max-Age)"),
                      eb.verified("Cookie 'session' is host-only (no Domain attribute)"),
                      eb.verified("Cookie 'session' Path is /")],
                     tests=1),
    ])
@_scenario("cors_misconfig", "CORS misconfiguration allows any origin.")
def _cors_misconfig():
    return _scan([
        _raw_finding("CORS Configuration",
                     [eb.confirmed("Wildcard origin '*' is allowed in "
                                   "Access-Control-Allow-Origin")],
                     tests=5),
        _raw_finding("Headers Security",
                     [eb.verified("Security headers present")], tests=12),
    ])


@_scenario("sqli_detected", "SQL injection confirmed via multi-technique agreement (error + boolean).")
def _sqli_detected():
    return _scan([
        _raw_finding("SQL Injection",
                     [_obs("SQL error-based injection in GET parameter 'id': You have "
                           "an error in your SQL syntax near",
                           payload="'", parameter="id", status_code=500, body_length=412),
                      _obs("SQL boolean-based injection in GET parameter 'id': true/false "
                           "payloads consistently produce different responses",
                           payload="' AND '1'='1'-- -", parameter="id",
                           status_code=200, body_length=2140),
                      _cv("SQL injection confirmed by multiple independent techniques "
                          "(boolean_based, error_based)", 2)],
                     tests=16, occurrences=2, target="https://example.com/login?id="),
        _raw_finding("Technology Detection",
                     [eb.verified("Technology detected: Nginx (via header Server)"),
                      eb.verified("Technology detected: MySQL (via body fingerprint)")],
                     tests=16),
    ])


@_scenario("xss_detected", "Reflected XSS with weak CSP (correlation xss_csp_bypass).")
def _xss_detected():
    return _scan([
        _raw_finding("XSS Detection",
                     [_obs("Reflected XSS in GET parameter 'q': '<script>alert(1)</script>' "
                           "reflected into an executable HTML context",
                           payload="<script>alert(1)</script>", parameter="q",
                           status_code=200, body_length=1140),
                      _obs("Reflected XSS in GET parameter 'q': '<img src=x onerror=alert(1)>' "
                           "reflected into an executable HTML context",
                           payload="<img src=x onerror=alert(1)>", parameter="q",
                           status_code=200, body_length=1148)],
                     tests=16, occurrences=1, target="https://example.com/search?q="),
        _raw_finding("Headers Security",
                     [eb.likely("Content-Security-Policy is missing")], tests=12),
    ])


@_scenario("ssti_detected", "Server-side template injection on a form field.")
def _ssti_detected():
    return _scan([
        _raw_finding("SSTI Detection",
                     [_obs("SSTI in GET parameter 'name': jinja2 ({{ expr }}) evaluated "
                           "'{{7*7}}' -> 49 and '{{8*9}}' -> 72",
                           payload="{{7*7}}", parameter="name",
                           status_code=200, body_length=1330),
                      _cv("Server-side template injection confirmed on multiple "
                          "template engines (freemarker, jinja2)", 2)],
                     tests=14, target="https://example.com/profile?name="),
    ])


@_scenario("lfi_ssrf", "LFI + SSRF pair (correlation ssrf_lfi escalates to critical).")
def _lfi_ssrf():
    return _scan([
        _raw_finding("LFI Detection",
                     [_obs("LFI path traversal in GET parameter 'file': "
                           "../../../../etc/passwd discloses /etc/passwd ('root:x:'), "
                           "reproduced with ../../../../etc/hosts",
                           payload="../../../../etc/passwd", parameter="file",
                           status_code=200, body_length=1660)],
                     tests=10, target="https://example.com/download?file="),
        _raw_finding("SSRF Detection",
                     [_obs("SSRF to cloud metadata in GET parameter 'url': "
                           "http://169.254.169.254/latest/meta-data/ returned "
                           "metadata markers (confirmed with "
                           "http://169.254.169.254/latest/meta-data/instance-id)",
                           payload="http://169.254.169.254/latest/meta-data/",
                           parameter="url", status_code=200, body_length=2210)],
                     tests=10, target="https://example.com/fetch?url="),
    ])


@_scenario("cors_open_redirect", "CORS misconfig + open redirect pair.")
def _cors_open_redirect():
    return _scan([
        _raw_finding("CORS Configuration",
                     [eb.confirmed("Arbitrary origin 'https://evil.com' is reflected "
                                   "in Access-Control-Allow-Origin")],
                     tests=5),
        _raw_finding("Open Redirect",
                     [_obs("Open redirect (absolute) in GET parameter 'url': "
                           "//evil.com redirected to //evil.com (reproduced with "
                           "https://attacker.net)",
                           payload="//evil.com", parameter="url",
                           status_code=302, body_length=0),
                      _obs("Open redirect (encoded) in GET parameter 'url': "
                           "%2F%2Fevil.com redirected to //evil.com (reproduced "
                           "with %2F%2Fattacker.net)",
                           payload="%2F%2Fevil.com", parameter="url",
                           status_code=302, body_length=0),
                      _cv("Open redirect confirmed by multiple independent "
                          "techniques (absolute, encoded)", 2)],
                     tests=8, target="https://example.com/redirect?url="),
    ])


@_scenario("host_header_csrf", "Host header injection + missing CSRF tokens.")
def _host_header_csrf():
    return _scan([
        _raw_finding("Host Header Injection",
                     [eb.confirmed("Host header 'evil.com' is reflected in the "
                                   "response body"),
                      eb.confirmed("Host header 'evil.com' is injected into a "
                                   "generated URL")],
                     tests=4, target="https://example.com/"),
        _raw_finding("CSRF Protection",
                     [eb.confirmed("POST form to 'https://example.com/account' has "
                                   "no CSRF token field"),
                      eb.confirmed("POST form to 'https://example.com/account' "
                                   "accepts a cross-origin request with no CSRF "
                                   "token (no Origin/Referer validation)")],
                     tests=1),
    ])


@_scenario("tls_strong", "TLS variations: strong configuration, nothing to report.")
def _tls_strong():
    return _scan([
        _raw_finding("TLS/SSL Security",
                     [eb.verified("TLS 1.3 only; HSTS valid for 31536000s")], tests=8),
        _raw_finding("Headers Security",
                     [eb.verified("HSTS header present and valid")], tests=12),
        _raw_finding("Cookies Security",
                     [eb.verified("Cookie 'session' is HTTPS-only"),
                      eb.verified("Cookie 'session' blocks JavaScript access (HttpOnly)"),
                      eb.verified("Cookie 'session' restricts cross-site sending "
                                  "(SameSite=Lax)"),
                      eb.verified("Cookie 'session' is a session cookie "
                                  "(no Expires/Max-Age)"),
                      eb.verified("Cookie 'session' is host-only (no Domain attribute)"),
                      eb.verified("Cookie 'session' Path is /")],
                     tests=1),
    ])


@_scenario("tls_weak", "TLS variations: obsolete protocol and weak cipher allowed.")
def _tls_weak():
    return _scan([
        _raw_finding("TLS/SSL Security",
                     [eb.verified("TLS Handshake successful: TLSv1.0"),
                      eb.likely("Weak TLS version detected: TLSv1.0. Disable TLS 1.0 and 1.1."),
                      eb.likely("No forward secrecy (consider ECDHE/DHE ciphers)")],
                     tests=8),
    ])


@_scenario("cms_wordpress", "WordPress platform detected; security.txt and DNS informational.")
def _cms_wordpress():
    return _scan([
        _raw_finding("Technology Detection",
                     [eb.verified("Technology detected: WordPress (via body fingerprint)"),
                      eb.verified("Technology detected: PHP (via header Server)")],
                     tests=16),
        _raw_finding("Security.txt",
                     [eb.likely("Security.txt not found at /.well-known/security.txt "
                                "or /security.txt (RFC 9116 vulnerability disclosure file)")],
                     tests=2),
        _raw_finding("DNS Security",
                     [eb.verified("A and CNAME records resolve correctly")], tests=3),
    ])


@_scenario("ports_http_sensitive", "Exposed ports, dangerous HTTP methods, sensitive files, source leaks.")
def _ports_http_sensitive():
    return _scan([
        _raw_finding("Open Ports",
                     [eb.verified("Open ports: 8080(HTTP-Alt), 8443(HTTPS-Alt)"),
                      eb.likely("Sensitive ports open: 8080(HTTP-Alt), 8443(HTTPS-Alt)")],
                     tests=17),
        _raw_finding("HTTP Methods",
                     [eb.verified("Allowed methods: GET, POST, OPTIONS, TRACE"),
                      eb.confirmed("Dangerous TRACE method is allowed on the server", payload="TRACE")],
                     tests=10),
        _raw_finding("Sensitive Files",
                     [eb.confirmed("Sensitive file exposed: .env (contains: DB_)", payload="/.env"),
                      eb.verified("File robots.txt exists (no sensitive content)")],
                     tests=16),
        _raw_finding("Source Code Leaks",
                     [eb.confirmed("Source leak in category 'API Keys': matched "
                                   "\\bAPI[_-]?KEY\\s*[=:]"),
                      eb.likely("Source leak in category 'Debug Information': matched "
                                "Traceback \\(most recent call last\\)")],
                     tests=21),
    ])


@_scenario("scan_incomplete", "One module could not conclude (UNKNOWN status) — coverage quirk scenario.")
def _scan_incomplete():
    return _scan([
        _raw_finding("SQL Injection",
                     [_obs("SQL error-based injection in GET parameter 'id': You have "
                           "an error in your SQL syntax near",
                           payload="'", parameter="id", status_code=500, body_length=412)],
                     tests=8),
        _raw_finding("LFI Detection",
                     [eb.possible("File parameter could not be fully tested")],
                     tests=0),
    ])


@_scenario("scan_error", "One module produced error evidence — confidence cap and unverified classification.")
def _scan_error():
    return _scan([
        _raw_finding("XSS Detection",
                     [_obs("Reflected XSS in GET parameter 'q': '<script>alert(1)</script>' "
                           "reflected into an executable HTML context",
                           payload="<script>alert(1)</script>", parameter="q",
                           status_code=200, body_length=1140)],
                     tests=10),
        _raw_finding("SSRF Detection",
                     [eb.error("Request timed out during verification")],
                     tests=0),
    ])


@_scenario("mixed_corpus", "Broad multi-module scan exercising several correlation rules.")
def _mixed_corpus():
    return _scan([
        _raw_finding("SQL Injection",
                     [_obs("SQL error-based injection in GET parameter 'id': You have "
                           "an error in your SQL syntax near",
                           payload="'", parameter="id", status_code=500, body_length=412),
                      _obs("SQL boolean-based injection in GET parameter 'id': true/false "
                           "payloads consistently produce different responses",
                           payload="' AND '1'='1'-- -", parameter="id",
                           status_code=200, body_length=2140),
                      _cv("SQL injection confirmed by multiple independent techniques "
                          "(boolean_based, error_based)", 2)],
                     tests=16, occurrences=2),
        _raw_finding("XSS Detection",
                     [_obs("Reflected XSS in GET parameter 'q': '<script>alert(1)</script>' "
                           "reflected into an executable HTML context",
                           payload="<script>alert(1)</script>", parameter="q",
                           status_code=200, body_length=1140),
                      _obs("Reflected XSS in GET parameter 'q': '<img src=x onerror=alert(1)>' "
                           "reflected into an executable HTML context",
                           payload="<img src=x onerror=alert(1)>", parameter="q",
                           status_code=200, body_length=1148)],
                     tests=16),
        _raw_finding("Headers Security",
                     [eb.likely("Content-Security-Policy is missing")], tests=12),
        _raw_finding("Cookies Security",
                     [eb.likely("Cookie 'session' is not HTTPS-only"),
                      eb.likely("Cookie 'session' is accessible to JavaScript "
                                "(no HttpOnly flag)"),
                      eb.verified("Cookie 'session' restricts cross-site sending "
                                  "(SameSite=Lax)"),
                      eb.verified("Cookie 'session' is a session cookie "
                                  "(no Expires/Max-Age)"),
                      eb.verified("Cookie 'session' is host-only (no Domain attribute)"),
                      eb.verified("Cookie 'session' Path is /")],
                     tests=1),
        _raw_finding("TLS/SSL Security",
                     [eb.verified("TLS Handshake successful: TLSv1.0"),
                      eb.likely("Weak TLS version detected: TLSv1.0. Disable TLS 1.0 and 1.1.")],
                     tests=8),
        _raw_finding("CORS Configuration",
                     [eb.confirmed("Arbitrary origin 'https://evil.com' is reflected "
                                   "in Access-Control-Allow-Origin")],
                     tests=5),
        _raw_finding("Technology Detection",
                     [eb.verified("Technology detected: Nginx (via header Server)")],
                     tests=16),
    ])


def scenario_names() -> List[str]:
    return sorted(_scenario_builders.keys())


def scenario_description(name: str) -> str:
    return getattr(_scenario_builders.get(name), '_description', '')


def build_scenario(name: str) -> ScanResult:
    """Return a fresh ScanResult for the named scenario."""
    if name not in _scenario_builders:
        raise KeyError(f"Unknown scenario: {name}")
    return _scenario_builders[name]()
