"""
Engine unit tests — Phase A8.5 (Evidence / Confidence / Verification / Severity).

Self-contained runner (no pytest dependency). Run:

    python -m tests.engine_tests

Coverage:
  1. EvidenceEngine      — level quality base, payload/parameter/raw bonuses,
                           verification-pass bonus, error + contradiction
                           penalties, quality clamp, dict coercion.
  2. ConfidenceEngine    — base anchor, weighted-bonus math, multiple-evidence
                           bonus, verification-pass bonuses, cross-validation,
                           max-confidence cap chain, error cap, correlation and
                           cross-validated boosts, zero-evidence.
  3. Parity              — ConfidenceEngine.compute() reproduces the v2 Finding
                           auto-assessment exactly on a battery of evidence sets
                           (no duplicated, drifting calculation).
  4. VerificationEngine  — dynamic bands, hard overrides, threshold edges.
   5. SeverityEngine      — status->severity mapping (module map authoritative),
                            correlation escalation, unverified-critical downgrade,
                            impact/CVSS/exploitability/standards metadata.
  6. Pipeline integration — raw evidence-only Finding -> engine-owned outputs,
                           report-vocabulary mapping, SOP #6 reclassification.
  7. Migrated scanner contract — all 19 scanners (Headers/TLS/DNS batch 1,
     Open Ports/Sensitive Files/HTTP Methods batch 2, Technology
     Detection/Security.txt/Source Leaks/Cookies batch 3, CORS/CSRF/Host
     Header + SQL Injection/XSS Detection batch 4, LFI/SSRF/Open
     Redirect/SSTI final batch) emit evidence only; no legacy decide() path
     remains.
  8. Architecture — single source of truth, no GUI/scanner logic in core, no
                     top-level import cycles, engine/legacy table parity.
"""

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

errors = []
warnings_list = []


def check(condition, msg):
    if not condition:
        errors.append(msg)
        print(f"  FAIL: {msg}")
    else:
        print(f"  OK: {msg}")


def warn(msg):
    warnings_list.append(msg)
    print(f"  WARN: {msg}")


from core.evidence import EvidenceBuilder, EvidenceLevel
from core.finding import Finding, Status, Severity, Exploitability
from core.evidence_engine import EvidenceEngine
from core.confidence_engine import ConfidenceEngine
from core.verification_engine import VerificationEngine
from core.severity_engine import SeverityEngine
from core.coverage_engine import CoverageEngine
from core.decision_engine import DecisionEngine, RiskCalculator
from core.risk_engine import RiskEngine
from tests.v2_reference import v2_apply_evidence_assessment

eb = EvidenceBuilder()
ee = EvidenceEngine()
ce = ConfidenceEngine()
se = SeverityEngine()

# ============================================================
# 1. Evidence Engine
# ============================================================
print("\n=== 1. EvidenceEngine ===")

empty = ee.score([])
check(empty.evidence_count == 0 and empty.evidence_quality == 0,
      "Empty evidence -> count 0, quality 0")

likely1 = ee.score([eb.likely("X-Frame-Options is missing")])
check(likely1.evidence_quality == 65, f"LIKELY base quality 65 (got {likely1.evidence_quality})")
check(likely1.strongest_level == "likely", "Strongest level is 'likely'")
check(likely1.weighted_bonus == 30 and likely1.total_weight == 3,
      f"LIKELY weighted_bonus=30 total_weight=3 (got {likely1.weighted_bonus}/{likely1.total_weight})")

rich = ee.score([
    eb.possible("Reflected parameter echoed", payload="<script>alert(1)</script>",
                parameter="q", method="GET", endpoint="https://x.com/search"),
])
rich_ev = eb.possible("Reflected parameter echoed", payload="p", parameter="q")
rich_ev.raw_data = {"snippet": "<script>alert(1)</script>"}
rich2 = ee.score([rich_ev])
check(rich2.evidence_quality == 50 + 5 + 2 + 3,
      f"POSSIBLE+payload+parameter+snippet -> 60 (got {rich2.evidence_quality})")

vpass = ee.score([eb.confirmed("Dual-verified", verification_pass=2)])
check(vpass.evidence_quality == 80 + 5,
      f"CONFIRMED + 1 verification pass id -> 85 (got {vpass.evidence_quality})")

err_only = ee.score([eb.error("Connection failed")])
check(err_only.has_error and err_only.evidence_quality == 10,
      f"ERROR evidence -> quality 10 (got {err_only.evidence_quality})")

err_contra = ee.score([eb.confirmed("SQL error detected"), eb.error("timed out")])
check(err_contra.has_error and err_contra.evidence_quality == 80 - 20 - 10,
      f"CONFIRMED + ERROR -> contradiction penalty 50 (got {err_contra.evidence_quality})")

top = ee.score([eb.exploited("RCE"), eb.verified("independent"), eb.confirmed("third")])
check(top.evidence_quality == 100, f"Exploited evidence clamps quality at 100 (got {top.evidence_quality})")

dict_ev = ee.score([{"description": "x", "level": "confirmed"}])
check(dict_ev.strongest_level == "confirmed" and dict_ev.evidence_quality == 80,
      "Dict evidence coerced to Evidence, confirmed -> 80")

# ============================================================
# 2. Confidence Engine
# ============================================================
print("\n=== 2. ConfidenceEngine ===")

zero = ce.compute(ee.score([]))
check(zero.confidence == 0, "Zero evidence -> confidence 0")

one_likely = ce.compute(ee.score([eb.likely("x")]))
check(one_likely.confidence == 60, f"Single LIKELY -> 60 (got {one_likely.confidence})")

two_likely = ce.compute(ee.score([eb.likely("a"), eb.likely("b")]))
check(two_likely.confidence == 65,
      f"Two LIKELY -> 65 (+5 multiple evidence) (got {two_likely.confidence})")
check(two_likely.factors.get("Multiple Evidences") == 5, "Multiple-evidence factor recorded")

exploited = ce.compute(ee.score([eb.exploited("x")]))
check(exploited.confidence == 85, f"EXPLOITED -> 85 (got {exploited.confidence})")

verified_cap = ce.compute(ee.score([eb.verified("x")]))
check(verified_cap.confidence == min(verified_cap.confidence, 90),
      "VERIFIED evidence caps confidence at 90")

possible_cap = ce.compute(ee.score([eb.possible("x")]))
check(possible_cap.confidence <= 60, f"POSSIBLE caps at 60 (got {possible_cap.confidence})")

err_conf = ce.compute(ee.score([eb.error("fail")]))
check(err_conf.confidence == 40, f"ERROR hard-caps confidence at 40 (got {err_conf.confidence})")
check(err_conf.factors.get("Error detected") == -10, "Error penalty factor recorded")

corr = ce.compute(ee.score([eb.confirmed("x")]), correlation_boost=5)
check(corr.confidence == min(corr.confidence, 90) and corr.factors.get("Correlation boost") == 5,
      "Correlation boost applied and recorded")

xval = ce.compute(ee.score([eb.confirmed("x")]), cross_validated=True)
check(xval.factors.get("Cross-validated") == 5, "Cross-validated boost recorded")

multi_pass = ce.compute(ee.score([
    eb.confirmed("a", verification_pass=1),
    eb.confirmed("b", verification_pass=2),
]))
check(multi_pass.confidence == 85,
      f"Two confirmed + two passes -> 85 (got {multi_pass.confidence})")

# ============================================================
# 3. Confidence parity vs v2 Finding auto-assessment
# ============================================================
print("\n=== 3. ConfidenceEngine parity (no duplicated calculation) ===")

_parity_sets = [
    [eb.possible("one")],
    [eb.likely("a"), eb.likely("b")],
    [eb.verified("solo")],
    [eb.exploited("pwn")],
    [eb.confirmed("c1"), eb.confirmed("c2")],
    [eb.possible("p1"), eb.possible("p2"), eb.possible("p3")],
    [eb.likely("l"), eb.verified("v")],
    [eb.error("boom")],
    [eb.exploited("e"), eb.likely("weak")],
    [eb.confirmed("c", verification_pass=1), eb.confirmed("d", verification_pass=2),
     eb.likely("e", verification_pass=3)],
]

parity_bad = 0
for idx, evs in enumerate(_parity_sets):
    v3 = ce.compute(ee.score(list(evs))).confidence
    f = Finding()
    for ev in evs:
        f.add_evidence(ev)
    v2_apply_evidence_assessment(f)
    v2 = f.confidence
    if v3 != v2:
        parity_bad += 1
        warn(f"Parity set {idx}: v2={v2} v3={v3}")
check(parity_bad == 0, f"ConfidenceEngine matches v2 Finding on {len(_parity_sets)} evidence sets")

# ============================================================
# 4. Verification Engine (classify)
# ============================================================
print("\n=== 4. VerificationEngine.classify ===")

check(VerificationEngine.classify(90, []).status == "unverified",
      "No evidence -> unverified (hard override)")
check(VerificationEngine.classify(90, ['possible'], has_error=True).status == "unverified",
      "Error evidence -> unverified (hard override)")
check(VerificationEngine.classify(10, ['exploited']).status == "confirmed",
      "Exploited evidence -> confirmed (hard override)")
check(VerificationEngine.classify(10, ['verified']).status == "confirmed",
      "Verified evidence -> confirmed (hard override)")

check(VerificationEngine.classify(96, ['possible']).status == "confirmed", ">=95 -> confirmed")
check(VerificationEngine.classify(94, ['possible']).status == "likely", "94 -> likely")
check(VerificationEngine.classify(80, ['possible']).status == "likely", "80 -> likely (edge)")
check(VerificationEngine.classify(79, ['possible']).status == "possible", "79 -> possible")
check(VerificationEngine.classify(55, ['possible']).status == "possible", "55 -> possible (edge)")
check(VerificationEngine.classify(54, ['possible']).status == "manual_review", "54 -> manual_review")
check(VerificationEngine.classify(35, ['possible']).status == "manual_review", "35 -> manual_review (edge)")
check(VerificationEngine.classify(34, ['possible']).status == "unverified", "34 -> unverified")

# ============================================================
# 5. Severity Engine
# ============================================================
print("\n=== 5. SeverityEngine ===")


def _sev_finding(module, status, severity=Severity.NONE, confidence=80):
    f = Finding()
    f.module = module
    f.status = status
    f.severity = severity
    f.confidence = confidence
    return f


check(se.assess(_sev_finding("SQL Injection", Status.PASS)).severity == Severity.NONE.value,
      "PASS -> severity NONE")
check(se.assess(_sev_finding("SQL Injection", Status.FAIL)).severity
      == Severity.CRITICAL.value, "SQL FAIL (no preset) -> CRITICAL (module map)")
check(se.assess(_sev_finding("Headers Security", Status.WARNING)).severity
      == Severity.MEDIUM.value, "Headers WARNING -> MEDIUM (module map)")

preset = se.assess(_sev_finding("SQL Injection", Status.FAIL, severity=Severity.LOW))
check(preset.severity == Severity.CRITICAL.value,
      "Scanner-preset severity is ignored — module map is authoritative (single writer)")

info = se.assess(_sev_finding("Technology Detection", Status.INFO))
check(info.severity == Severity.INFO.value, "INFO status -> INFO severity")

escalate = se.assess(_sev_finding("HTTP Methods", Status.FAIL),
                     correlation_escalation="critical")
check(escalate.severity == Severity.CRITICAL.value, "Correlation escalation raises severity")
no_downgrade = se.assess(_sev_finding("SQL Injection", Status.FAIL, severity=Severity.CRITICAL),
                         correlation_escalation="low")
check(no_downgrade.severity == Severity.CRITICAL.value, "Escalation is upward-only")

downgrade = se.assess(_sev_finding("SQL Injection", Status.FAIL),
                      verification_status="possible")
check(downgrade.severity == Severity.HIGH.value,
      "Unverified critical -> HIGH (opt-in per-finding policy)")
keep_crit = se.assess(_sev_finding("SQL Injection", Status.FAIL),
                      verification_status="confirmed")
check(keep_crit.severity == Severity.CRITICAL.value, "Confirmed critical stays CRITICAL")

sql = se.assess(_sev_finding("SQL Injection", Status.FAIL, confidence=80))
check(sql.cvss_score == 9.4, f"SQL critical cvss 9.4 (got {sql.cvss_score})")
check(sql.cwe_id == "CWE-89" and sql.owasp_category == "A03: Injection"
      and sql.capec_id == "CAPEC-66" and sql.mitre_id == "T1190",
      "SQL Injection standards metadata applied")
check(sql.exploitability == Exploitability.EASY.value, "CRITICAL -> exploitability EASY")
check(sql.impact == {"confidentiality": 5, "integrity": 5, "availability": 3},
      "CRITICAL SQL impact profile {5,5,3}")

low = se.assess(_sev_finding("Headers Security", Status.FAIL),
                verification_status="confirmed")
check(low.impact == {"confidentiality": 1, "integrity": 1, "availability": 1},
      f"LOW-mapped impact floor {low.impact}")
check(se.assess(_sev_finding("HTTP Methods", Status.FAIL)).exploitability
      == Exploitability.HARD.value, "MEDIUM -> exploitability HARD")

# ============================================================
# 6. Pipeline integration (raw evidence-only -> engine outputs)
# ============================================================
print("\n=== 6. Pipeline integration ===")

from core.pipeline import run_engine_pipeline

raw = Finding()
raw.module = "Headers Security"
raw.target = "https://example.com"
raw.status = Status.UNKNOWN
raw.severity = Severity.NONE
raw.tests_performed = 12
raw.add_evidence(eb.likely("X-Frame-Options is missing"))
raw.add_evidence(eb.likely("Content-Security-Policy is missing"))
run_engine_pipeline(raw)

check(raw.status is Status.WARNING, f"Raw likely evidence -> WARNING (got {raw.status.value})")
check(raw.severity is Severity.MEDIUM, f"Headers WARNING -> MEDIUM (got {raw.severity.value})")
check(raw.confidence == 65, f"Two likely -> confidence 65 (got {raw.confidence})")
check(raw.verification_status == "possible", f"v3 band 'possible' (got {raw.verification_status})")
check(raw.verification_class == "possible", "verification_class holds raw v3 band")
check(bool(raw.reason) and bool(raw.recommendation), "Pipeline fills reason + recommendation")
check(raw.execution_state.value == "warning", "Execution state WARNING via Coverage Engine")

clean = Finding()
clean.module = "Headers Security"
clean.status = Status.UNKNOWN
clean.severity = Severity.NONE
clean.tests_performed = 12
clean.add_evidence(eb.verified("Strict-Transport-Security: max-age=31536000"))
run_engine_pipeline(clean)
check(clean.status is Status.PASS, f"Verified evidence -> PASS (got {clean.status.value})")
check(clean.severity is Severity.NONE, "PASS -> severity NONE")
check(clean.verification_status == "verified", "confirmed (internal) reports as 'verified'")
check(clean.verification_class == "confirmed", "verification_class keeps internal band")
check(clean.execution_state.value == "passed", "Passed execution state")

exploit = Finding()
exploit.module = "SQL Injection"
exploit.status = Status.UNKNOWN
exploit.severity = Severity.NONE
exploit.add_evidence(eb.exploited("Boolean-based blind confirmed", payload="' OR 1=1-- -"))
run_engine_pipeline(exploit)
check(exploit.status is Status.FAIL, "Exploited evidence -> FAIL")
check(exploit.severity is Severity.CRITICAL, "SQL FAIL -> CRITICAL")
check(exploit.verification_status == "verified", "Exploited -> report 'verified'")

pos = Finding()
pos.module = "TLS/SSL Security"
pos.status = Status.UNKNOWN
pos.severity = Severity.NONE
pos.tests_performed = 2
pos.add_evidence(eb.likely("TLS configuration is properly configured"))
run_engine_pipeline(pos)
check(pos.status is Status.PASS, f"SOP #6 positive observation -> PASS (got {pos.status.value})")
check(pos.severity is Severity.NONE, "SOP #6 reclassification clears severity")

unknown_incomplete = Finding()
unknown_incomplete.module = "LFI Detection"
unknown_incomplete.status = Status.UNKNOWN
unknown_incomplete.severity = Severity.NONE
unknown_incomplete.tests_performed = 0
unknown_incomplete.add_evidence(eb.possible("File parameter could not be fully tested"))
run_engine_pipeline(unknown_incomplete)
check(unknown_incomplete.execution_state.value == "not_applicable",
      "UNKNOWN/incomplete -> NOT_APPLICABLE (pipeline matches Coverage Engine)")
check(unknown_incomplete.execution_state
      == CoverageEngine.classify_execution_state(unknown_incomplete)[0],
      "finding.execution_state agrees with Coverage Engine (single owner)")

# ============================================================
# 7. Migrated scanner contract (evidence-only output)
# ============================================================
print("\n=== 7. Migrated scanner contract ===")


class _FakeResponse:
    def __init__(self, headers=None, text="<html><body>ok</body></html>"):
        self.status_code = 200
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.cookies = []
        self.elapsed = None


class _FakeSession:
    def __init__(self, response):
        self._resp = response
        self.headers = {}

    def get(self, url, **kwargs):
        return self._resp


from scanners.headers import HeadersScanner
from scanners.sensitive_files import SensitiveFilesScanner
from scanners.http_methods import HTTPMethodsScanner

hs = HeadersScanner("http://test.com", session=_FakeSession(_FakeResponse(headers={})))
raw = hs.scan()
check(raw.status is Status.UNKNOWN, f"scan() leaves status UNKNOWN (got {raw.status.value})")
check(raw.severity is Severity.NONE, f"scan() leaves severity NONE (got {raw.severity.value})")
check(raw.reason == "" and raw.recommendation == "", "scan() leaves reason/recommendation empty")
check(len(raw.evidence) > 0, "scan() still collects evidence")


class _NotFoundResponse:
    status_code = 404
    text = ""
    headers = {}
    cookies = []
    elapsed = None


class _NotFoundSession:
    headers = {}

    def get(self, url, **kwargs):
        return _NotFoundResponse()

    def request(self, method, url, **kwargs):
        return _NotFoundResponse()


sf = SensitiveFilesScanner("http://test.com", session=_NotFoundSession())
sf_raw = sf.scan()
check(sf_raw.status is Status.UNKNOWN,
      f"SensitiveFiles scan() leaves status UNKNOWN (got {sf_raw.status.value})")
check(sf_raw.severity is Severity.NONE, "SensitiveFiles scan() leaves severity NONE")
check(len(sf_raw.evidence) > 0, "SensitiveFiles scan() collects evidence")

hm = HTTPMethodsScanner("http://test.com", session=_NotFoundSession())
hm_raw = hm.scan()
check(hm_raw.status is Status.UNKNOWN,
      f"HTTPMethods scan() leaves status UNKNOWN (got {hm_raw.status.value})")
check(hm_raw.severity is Severity.NONE, "HTTPMethods scan() leaves severity NONE")
check(len(hm_raw.evidence) > 0, "HTTPMethods scan() collects evidence")

from scanners.tech_detect import TechDetectScanner
from scanners.security_txt import SecurityTxtScanner
from scanners.source_leaks import SourceLeaksScanner
from scanners.cookies import CookiesScanner

td = TechDetectScanner("http://test.com", session=_FakeSession(_FakeResponse()))
td_raw = td.scan()
check(td_raw.status is Status.UNKNOWN,
      f"TechDetect scan() leaves status UNKNOWN (got {td_raw.status.value})")
check(td_raw.severity is Severity.NONE, "TechDetect scan() leaves severity NONE")
check(len(td_raw.evidence) > 0, "TechDetect scan() collects evidence")

st = SecurityTxtScanner("http://test.com", session=_FakeSession(_FakeResponse()))
st_raw = st.scan()
check(st_raw.status is Status.UNKNOWN,
      f"SecurityTxt scan() leaves status UNKNOWN (got {st_raw.status.value})")
check(st_raw.severity is Severity.NONE, "SecurityTxt scan() leaves severity NONE")
check(len(st_raw.evidence) > 0, "SecurityTxt scan() collects evidence")

sl = SourceLeaksScanner("http://test.com", session=_FakeSession(_FakeResponse()))
sl_raw = sl.scan()
check(sl_raw.status is Status.UNKNOWN,
      f"SourceLeaks scan() leaves status UNKNOWN (got {sl_raw.status.value})")
check(sl_raw.severity is Severity.NONE, "SourceLeaks scan() leaves severity NONE")
check(len(sl_raw.evidence) > 0, "SourceLeaks scan() collects evidence")

ck = CookiesScanner("http://test.com", session=_FakeSession(_FakeResponse()))
ck_raw = ck.scan()
check(ck_raw.status is Status.UNKNOWN,
      f"Cookies scan() leaves status UNKNOWN (got {ck_raw.status.value})")
check(ck_raw.severity is Severity.NONE, "Cookies scan() leaves severity NONE")
check(len(ck_raw.evidence) > 0, "Cookies scan() collects evidence")

from scanners.cors import CORSScanner
from scanners.csrf import CSRFScanner
from scanners.host_header import HostHeaderScanner
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner


class _Batch4FormResponse(_FakeResponse):
    text = ('<html><body><form method="post" action="http://test.com/login">'
            '<input type="hidden" name="csrf_token" value="abc">'
            '<input type="text" name="q"></form></body></html>')


class _Batch4Session:
    headers = {}

    def __init__(self):
        self._form = _Batch4FormResponse()

    def get(self, url, **kwargs):
        return self._form

    def options(self, url, **kwargs):
        return _FakeResponse()

    def post(self, url, **kwargs):
        data = kwargs.get("data") or {}
        if "csrf_token" in data:
            return _FakeResponse(text="accepted")
        denied = _FakeResponse(text="forbidden")
        denied.status_code = 403
        return denied


co = CORSScanner("http://test.com", session=_Batch4Session())
co_raw = co.scan()
check(co_raw.status is Status.UNKNOWN,
      f"CORS scan() leaves status UNKNOWN (got {co_raw.status.value})")
check(co_raw.severity is Severity.NONE, "CORS scan() leaves severity NONE")
check(len(co_raw.evidence) > 0, "CORS scan() collects evidence")

ck2 = CSRFScanner("http://test.com", session=_Batch4Session())
ck2_raw = ck2.scan()
check(ck2_raw.status is Status.UNKNOWN,
      f"CSRF scan() leaves status UNKNOWN (got {ck2_raw.status.value})")
check(ck2_raw.severity is Severity.NONE, "CSRF scan() leaves severity NONE")
check(len(ck2_raw.evidence) > 0, "CSRF scan() collects evidence")
check(any(getattr(e, "level", None) is not None and e.level.name == "VERIFIED"
          for e in ck2_raw.evidence),
      "CSRF scan() emits a verified positive observation for a token-backed form")

hh = HostHeaderScanner("http://test.com", session=_Batch4Session())
hh_raw = hh.scan()
check(hh_raw.status is Status.UNKNOWN,
      f"HostHeader scan() leaves status UNKNOWN (got {hh_raw.status.value})")
check(hh_raw.severity is Severity.NONE, "HostHeader scan() leaves severity NONE")
check(len(hh_raw.evidence) > 0, "HostHeader scan() collects evidence")

# SQL Injection / XSS Detection (Batch 4 Part 2) runtime contract: scan()
# leaves UNKNOWN/NONE, collects raw evidence, emits a verified clean result on
# a clean site, and never classifies itself.
class _Batch4P2Session:
    headers = {}

    def get(self, url, **kwargs):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url).query)
        v = qs.get("id", [""])[0]
        if "'" in v:
            resp = _FakeResponse(text="<html>You have an error in your SQL syntax</html>")
            resp.status_code = 500
            return resp
        return _FakeResponse(text="<html><body>ok</body></html>")

    def post(self, url, **kwargs):
        return self.get(url, **kwargs)


sq = SQLiScanner("http://test.com/page?id=1", session=_Batch4P2Session())
sq_raw = sq.scan()
check(sq_raw.status is Status.UNKNOWN,
      f"SQLi scan() leaves status UNKNOWN (got {sq_raw.status.value})")
check(sq_raw.severity is Severity.NONE, "SQLi scan() leaves severity NONE")
check(len(sq_raw.evidence) > 0, "SQLi scan() collects evidence")
check(any(e.raw_data.get('technique') == 'error_based' for e in sq_raw.evidence),
      "SQLi scan() emits error-based observations")

xs = XSSScanner("http://test.com/search?q=clean", session=_FakeSession(_FakeResponse()))
xs_raw = xs.scan()
check(xs_raw.status is Status.UNKNOWN,
      f"XSS scan() leaves status UNKNOWN (got {xs_raw.status.value})")
check(xs_raw.severity is Severity.NONE, "XSS scan() leaves severity NONE")
check(len(xs_raw.evidence) > 0, "XSS scan() collects evidence")
check(any(e.level.value == 'verified' for e in xs_raw.evidence),
      "XSS scan() emits a verified clean observation for a clean site")

# Final Batch (LFI / SSRF / Open Redirect / SSTI) runtime contract: scan()
# leaves UNKNOWN/NONE, collects raw evidence, and never classifies itself.
from scanners.lfi import LFIScanner
from scanners.ssrf import SSRFScanner
from scanners.open_redirect import OpenRedirectScanner
from scanners.ssti import SSTIScanner


class _LfiVulnSession:
    headers = {}

    def get(self, url, **kwargs):
        from urllib.parse import parse_qs, urlparse
        v = parse_qs(urlparse(url).query).get("file", [""])[0]
        if any(f in v for f in ("passwd", "hosts", "issue", "win.ini", "environ")):
            r = _FakeResponse(text="root:x:0:0:root:/root:/bin/bash\nlocalhost\n")
            r.status_code = 200
            return r
        return _FakeResponse(text="<html><body>ok</body></html>")

    def post(self, url, **kwargs):
        return self.get(url, **kwargs)


lfi = LFIScanner("http://test.com/download?file=page", session=_LfiVulnSession())
lfi_raw = lfi.scan()
check(lfi_raw.status is Status.UNKNOWN,
      f"LFI scan() leaves status UNKNOWN (got {lfi_raw.status.value})")
check(lfi_raw.severity is Severity.NONE, "LFI scan() leaves severity NONE")
check(lfi_raw.reason == "" and lfi_raw.recommendation == "",
      "LFI scan() leaves reason/recommendation empty")
check(len(lfi_raw.evidence) > 0, "LFI scan() collects evidence")
check(any(e.raw_data.get('technique')
          in ('traversal', 'disclosure', 'encoding_bypass')
          for e in lfi_raw.evidence),
      "LFI scan() emits file-inclusion technique observations")


class _SsrfVulnSession:
    headers = {}

    def get(self, url, **kwargs):
        from urllib.parse import parse_qs, urlparse
        v = parse_qs(urlparse(url).query).get("url", [""])[0]
        if "169.254.169.254" in v or "computeMetadata" in v:
            return _FakeResponse(text="instance-id: i-123\nami-id: ami-abc\n")
        if any(h in v for h in ("127.0.0.1:1", "nonexistent.invalid")):
            return _FakeResponse(text="Connection refused")
        if any(h in v for h in ("127.0.0.", "localhost", "0.0.0.0",
                                "10.0.0.1", "192.168.1.1", "172.16.0.1", "::1")):
            r = _FakeResponse(text="<html>" + "x" * 1000 + "</html>")
            r.status_code = 200
            return r
        return _FakeResponse(text="<html><body>ok</body></html>")

    def post(self, url, **kwargs):
        return self.get(url, **kwargs)


ss = SSRFScanner("http://test.com/fetch?url=http://example.com",
                 session=_SsrfVulnSession())
ss_raw = ss.scan()
check(ss_raw.status is Status.UNKNOWN,
      f"SSRF scan() leaves status UNKNOWN (got {ss_raw.status.value})")
check(ss_raw.severity is Severity.NONE, "SSRF scan() leaves severity NONE")
check(ss_raw.reason == "" and ss_raw.recommendation == "",
      "SSRF scan() leaves reason/recommendation empty")
check(len(ss_raw.evidence) > 0, "SSRF scan() collects evidence")
check(any(e.raw_data.get('technique')
          in ('metadata', 'internal_access', 'error_signature')
          for e in ss_raw.evidence),
      "SSRF scan() emits request-forgery technique observations")


class _OpenRedirectVulnSession:
    headers = {}

    def get(self, url, **kwargs):
        from urllib.parse import parse_qs, urlparse
        v = parse_qs(urlparse(url).query).get("url", [""])[0]
        r = _FakeResponse(text="<html></html>")
        if any(h in v for h in ("evil.com", "attacker.com", "attacker.net")):
            r.status_code = 302
            r.headers = {"Location": v}
        else:
            r.status_code = 200
        return r

    def post(self, url, **kwargs):
        return self.get(url, **kwargs)


ore = OpenRedirectScanner("http://test.com/redirect?url=http://example.com",
                          session=_OpenRedirectVulnSession())
ore_raw = ore.scan()
check(ore_raw.status is Status.UNKNOWN,
      f"OpenRedirect scan() leaves status UNKNOWN (got {ore_raw.status.value})")
check(ore_raw.severity is Severity.NONE, "OpenRedirect scan() leaves severity NONE")
check(ore_raw.reason == "" and ore_raw.recommendation == "",
      "OpenRedirect scan() leaves reason/recommendation empty")
check(len(ore_raw.evidence) > 0, "OpenRedirect scan() collects evidence")
check(any(e.raw_data.get('technique')
          in ('absolute', 'relative', 'protocol_relative', 'encoded',
              'double_encoding')
          for e in ore_raw.evidence),
      "OpenRedirect scan() emits redirect technique observations")


class _SstiVulnSession:
    headers = {}

    def get(self, url, **kwargs):
        from urllib.parse import parse_qs, urlparse
        v = parse_qs(urlparse(url).query).get("name", [""])[0]
        if "7*7" in v or "7 * 7" in v:
            return _FakeResponse(text="<html>result: 49</html>")
        if "8*9" in v or "8 * 9" in v:
            return _FakeResponse(text="<html>result: 72</html>")
        return _FakeResponse(text="<html><body>ok</body></html>")

    def post(self, url, **kwargs):
        return self.get(url, **kwargs)


sti = SSTIScanner("http://test.com/profile?name=alice", session=_SstiVulnSession())
sti_raw = sti.scan()
check(sti_raw.status is Status.UNKNOWN,
      f"SSTI scan() leaves status UNKNOWN (got {sti_raw.status.value})")
check(sti_raw.severity is Severity.NONE, "SSTI scan() leaves severity NONE")
check(sti_raw.reason == "" and sti_raw.recommendation == "",
      "SSTI scan() leaves reason/recommendation empty")
check(len(sti_raw.evidence) > 0, "SSTI scan() collects evidence")
check(len(sti_raw.fingerprint.get('engines') or []) >= 2,
      f"SSTI scan() confirms multiple engines (got {sti_raw.fingerprint.get('engines')})")

from scanners.registry import ALL_SCANNERS
registered = {s("http://test.com").name for s in ALL_SCANNERS}
check(registered == {"Headers Security", "TLS/SSL Security", "DNS Security",
                     "Open Ports", "Sensitive Files", "HTTP Methods",
                     "Technology Detection", "Security.txt",
                     "Source Code Leaks", "Cookies Security",
                     "CORS Configuration", "CSRF Protection",
                     "Host Header Injection",
                     "SQL Injection", "XSS Detection",
                     "LFI Detection", "SSRF Detection",
                     "Open Redirect", "SSTI Detection"},
      f"All 19 scanners registered (got {sorted(registered)})")

# A8.9 freeze: the migration switch is gone — no scanner carries use_engine_pipeline.
check(all(not hasattr(s, "use_engine_pipeline") for s in ALL_SCANNERS),
      "No scanner carries the use_engine_pipeline migration flag")

# Evidence-only guard: every scanner SOURCE (except base.py, the shared base) must
# not assign assessment fields directly on `finding` (status/severity/confidence/
# verification/execution_state). Catches a scanner that starts writing assessment
# results again, bypassing the single engine pipeline.
_scanners_root = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanners"
)
_evidence_only_bad = []
for _fn in sorted(os.listdir(_scanners_root)):
    if not _fn.endswith(".py") or _fn in ("base.py", "__init__.py"):
        continue
    if os.path.isdir(os.path.join(_scanners_root, _fn)):
        continue
    _tree = ast.parse(open(os.path.join(_scanners_root, _fn), encoding="utf-8").read())
    for _node in ast.walk(_tree):
        if not isinstance(_node, ast.Assign):
            continue
        for _tgt in _node.targets:
            if (isinstance(_tgt, ast.Attribute)
                    and isinstance(_tgt.value, ast.Name)
                    and _tgt.value.id == "finding"
                    and _tgt.attr in ("status", "severity", "confidence",
                                      "verification_status", "verification_class",
                                      "execution_state", "confidence_factors",
                                      "cvss_score", "cwe_id")):
                _evidence_only_bad.append(f"{_fn}: finding.{_tgt.attr}")
check(not _evidence_only_bad,
      f"Scanner sources write no assessment fields (found: {_evidence_only_bad})")

# ============================================================
# 8. Architecture validation
# ============================================================
print("\n=== 8. Architecture validation ===")

# Single source of truth: severity module map derived once in DecisionEngine.
check(SeverityEngine.SEVERITY_BY_MODULE is DecisionEngine.SEVERITY_BY_MODULE,
      "SeverityEngine reuses DecisionEngine.SEVERITY_BY_MODULE (no re-derivation)")
check(SeverityEngine.SEVERITY_BY_MODULE
      == {m: d['severity'] for m, d in DecisionEngine.STANDARDS.items()},
      "Module severity map consistent with DecisionEngine.STANDARDS")

# Engine vs legacy table parity (values must not drift).
for sev in RiskEngine.SEVERITY_WEIGHTS:
    check(RiskEngine.SEVERITY_WEIGHTS[sev] == RiskCalculator.SEVERITY_WEIGHTS.get(sev),
          f"RiskEngine/ RiskCalculator severity weight parity for {sev}")
check(RiskEngine.SEVERITY_WEIGHTS == RiskCalculator.SEVERITY_WEIGHTS,
      "Risk severity weights identical")
check(RiskEngine.VERIFICATION_MULTIPLIERS['verified']
      == RiskCalculator.VERIFICATION_MULTIPLIERS['verified'], "Verification multipliers agree")
check(RiskEngine.CALCULATION_FORMULA == RiskCalculator.calculate([])["calculation_formula"],
      "Risk formula string identical")

# RiskEngine parity vs RiskCalculator on a concrete corpus.
rf1 = Finding()
rf1.module = "SQL Injection"
rf1.status = Status.FAIL
rf1.severity = Severity.CRITICAL
rf1.confidence = 90
rf1.verification_status = "verified"
rf1.occurrences = 1
rf2 = Finding()
rf2.module = "XSS Detection"
rf2.status = Status.WARNING
rf2.severity = Severity.HIGH
rf2.confidence = 70
rf2.verification_status = "possible"
rf2.occurrences = 1
v3_risk = RiskEngine().calculate([rf1, rf2])
v2_risk = RiskCalculator.calculate([rf1, rf2])
check(v3_risk.risk_score == v2_risk["risk_score"]
      and v3_risk.security_grade == v2_risk["security_grade"],
      f"RiskEngine reproduces RiskCalculator ({v3_risk.risk_score}%/{v3_risk.security_grade})")

# No GUI business logic in core or scanners (no PySide6 / gui imports).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
core_sources = []
for dirpath, _, files in os.walk(os.path.join(_ROOT, "core")):
    for fn in files:
        if fn.endswith(".py"):
            core_sources.append(os.path.join(dirpath, fn))
scanner_sources = []
for dirpath, _, files in os.walk(os.path.join(_ROOT, "scanners")):
    for fn in files:
        if fn.endswith(".py"):
            scanner_sources.append(os.path.join(dirpath, fn))


def _has_import(text, needle):
    return f"import {needle}" in text or f"from {needle}" in text or needle == "PySide6" and needle in text


core_bad = [f for f in core_sources if _has_import(open(f, encoding='utf-8').read(), "PySide6")
            or _has_import(open(f, encoding='utf-8').read(), "gui")]
check(not core_bad, f"core/ has no GUI imports (found: {core_bad})")
scanner_bad = [f for f in scanner_sources
               if _has_import(open(f, encoding='utf-8').read(), "PySide6")]
check(not scanner_bad, f"scanners/ has no GUI imports (found: {scanner_bad})")

# No scanner business logic in core (core/ never imports the scanners package).
core_scanner_imports = []
for f in core_sources:
    text = open(f, encoding='utf-8').read()
    if "from scanners" in text or "import scanners" in text:
        core_scanner_imports.append(os.path.basename(f))
check(not core_scanner_imports, f"core/ has no scanner imports (found: {core_scanner_imports})")

# No top-level import cycles among core/ + scanners/ (AST-level check).
_CYCLE_MODULES = []
for dirpath, _, files in os.walk(_ROOT):
    rel = os.path.relpath(dirpath, _ROOT)
    if rel.split(os.sep)[0] not in ("core", "scanners"):
        continue
    for fn in files:
        if fn.endswith(".py") and fn != "__init__.py":
            _CYCLE_MODULES.append(
                (os.path.join(dirpath, fn), f"{rel.replace(os.sep, '.')}.{fn[:-3]}")
            )

module_names = {path: modname for path, modname in _CYCLE_MODULES}

edges = {}
for path, modname in _CYCLE_MODULES:
    tree = ast.parse(open(path, encoding='utf-8').read())
    imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imports.append(node.module)
    deps = set()
    for imp in imports:
        if imp in module_names:
            deps.add(imp)
        elif isinstance(node, ast.ImportFrom) and node.module in ("core", "scanners"):
            for alias in node.names:
                candidate = f"{node.module}.{alias.name}"
                if candidate in module_names:
                    deps.add(candidate)
    edges[path] = deps

cycles_found = []
visited = set()
active = set()


def _visit(node, trail):
    if node in active:
        cycle_start = trail.index(node) if node in trail else 0
        cycles_found.append([module_names[p] for p in trail[cycle_start:] + [node]])
        return
    if node in visited:
        return
    active.add(node)
    for dep in edges.get(node, []):
        _visit(dep, trail + [node])
    active.discard(node)
    visited.add(node)


for start in module_names:
    _visit(start, [])
check(not cycles_found, f"No top-level import cycles (found {cycles_found[:3]})")

# All core + scanner modules import cleanly (import-time integrity). pdf_reporter
# is excluded: it is a report consumer (not part of the engine pipeline) and needs
# native WeasyPrint libs unavailable in headless test environments.
import importlib
_ENV_LIMITED_MODULES = {"core.pdf_reporter"}
import_bad = []
for _, modname in _CYCLE_MODULES:
    if modname in _ENV_LIMITED_MODULES:
        continue
    try:
        importlib.import_module(modname)
    except Exception as exc:  # noqa: BLE001
        import_bad.append(f"{modname}: {exc}")
check(not import_bad, f"Every core/scanner module imports (failures: {import_bad[:3]})")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("ENGINE UNIT TEST RESULTS")
print("=" * 60)
print(f"Errors:   {len(errors)}")
print(f"Warnings: {len(warnings_list)}")

if errors:
    print("\nFAILURES:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
print("\n[OK] All engine unit tests passed.")
sys.exit(0)
