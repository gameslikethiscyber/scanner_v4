"""
Comprehensive validation script - verifies no regressions across all phases.
Tests all components WITHOUT making live HTTP requests.
"""

import os
import sys
import json
import tempfile
import logging
from datetime import datetime
from unittest.mock import Mock, MagicMock

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

# ============================================================
# 1. Import integrity
# ============================================================
print("\n=== 1. Import Integrity ===")

try:
    from core.finding import Finding, ScanResult, Status, Severity, Exploitability, ExecutionState
    check(True, "core.finding imports OK")
except Exception as e:
    check(False, f"core.finding imports failed: {e}")

try:
    from core.evidence import Evidence, EvidenceLevel, EvidenceType, EvidenceBuilder
    check(True, "core.evidence imports OK")
except Exception as e:
    check(False, f"core.evidence imports failed: {e}")

try:
    from core.decision_engine import DecisionEngine
    check(True, "core.decision_engine imports OK")
except Exception as e:
    check(False, f"core.decision_engine imports failed: {e}")

try:
    from core.http_client import TrackedSession, ResponseCache
    check(True, "core.http_client imports OK")
except Exception as e:
    check(False, f"core.http_client imports failed: {e}")

try:
    from core.config import ScanConfig
    check(True, "core.config imports OK")
except Exception as e:
    check(False, f"core.config imports failed: {e}")

try:
    from core.crawler import Crawler
    check(True, "core.crawler imports OK")
except Exception as e:
    check(False, f"core.crawler imports failed: {e}")

try:
    from core.reporter import Reporter
    check(True, "core.reporter imports OK")
except Exception as e:
    check(False, f"core.reporter imports failed: {e}")

try:
    from scanners.base import BaseScanner, SmartPayloadSystem
    check(True, "scanners.base imports OK")
except Exception as e:
    check(False, f"scanners.base imports failed: {e}")

try:
    from scanners.registry import ALL_SCANNERS, HOST_LEVEL_SCANNERS, PAGE_LEVEL_SCANNERS
    check(True, "scanners.registry imports OK")
except Exception as e:
    check(False, f"scanners.registry imports failed: {e}")

try:
    from main import SeaScanner
    check(True, "main.SeaScanner imports OK")
except Exception as e:
    check(False, f"main.SeaScanner imports failed: {e}")

# New engine imports
try:
    from core.verification_engine import VerificationEngine, VerificationResult, VerificationPass
    check(True, "core.verification_engine imports OK")
except Exception as e:
    check(False, f"core.verification_engine imports failed: {e}")

try:
    from core.response_analyzer import ResponseAnalyzer, ResponseAnalysis, SecurityHeaderAnalysis, CookieAnalysis
    check(True, "core.response_analyzer imports OK")
except Exception as e:
    check(False, f"core.response_analyzer imports failed: {e}")

try:
    from core.correlation_engine import CorrelationEngine, CorrelationRule, CorrelationResult
    check(True, "core.correlation_engine imports OK")
except Exception as e:
    check(False, f"core.correlation_engine imports failed: {e}")

# v3 engine imports
try:
    from core.assessment import (Assessment, FindingAssessment, EvidenceScore,
                                 ConfidenceResult, VerificationClassification,
                                 SeverityResult, RiskResult, CoverageReport,
                                 ExecutiveSummary)
    check(True, "core.assessment (v3 model) imports OK")
except Exception as e:
    check(False, f"core.assessment (v3 model) imports failed: {e}")

try:
    from core.evidence_engine import EvidenceEngine
    check(True, "core.evidence_engine (v3) imports OK")
except Exception as e:
    check(False, f"core.evidence_engine (v3) imports failed: {e}")

try:
    from core.confidence_engine import ConfidenceEngine
    check(True, "core.confidence_engine (v3) imports OK")
except Exception as e:
    check(False, f"core.confidence_engine (v3) imports failed: {e}")

try:
    from core.severity_engine import SeverityEngine
    check(True, "core.severity_engine (v3) imports OK")
except Exception as e:
    check(False, f"core.severity_engine (v3) imports failed: {e}")

try:
    from core.risk_engine import RiskEngine
    check(True, "core.risk_engine (v3) imports OK")
except Exception as e:
    check(False, f"core.risk_engine (v3) imports failed: {e}")

try:
    from core.coverage_engine import CoverageEngine
    check(True, "core.coverage_engine (v3) imports OK")
except Exception as e:
    check(False, f"core.coverage_engine (v3) imports failed: {e}")

try:
    from core.executive_summary import ExecutiveSummaryGenerator
    check(True, "core.executive_summary (v3) imports OK")
except Exception as e:
    check(False, f"core.executive_summary (v3) imports failed: {e}")

try:
    from core.assessment_engine import AssessmentEngine
    check(True, "core.assessment_engine (v3) imports OK")
except Exception as e:
    check(False, f"core.assessment_engine (v3) imports failed: {e}")

try:
    from core.pipeline import run_engine_pipeline, run_assessment_pipeline
    check(True, "core.pipeline (v3) imports OK")
except Exception as e:
    check(False, f"core.pipeline (v3) imports failed: {e}")

# ============================================================
# 2. Registry completeness
# ============================================================
print("\n=== 2. Scanner Registry ===")

check(len(ALL_SCANNERS) == 19, f"ALL_SCANNERS has {len(ALL_SCANNERS)} scanners (expected 19)")
check(len(HOST_LEVEL_SCANNERS) == 7, f"HOST_LEVEL_SCANNERS has {len(HOST_LEVEL_SCANNERS)} (expected 7)")
check(len(PAGE_LEVEL_SCANNERS) == 12, f"PAGE_LEVEL_SCANNERS has {len(PAGE_LEVEL_SCANNERS)} (expected 12)")

host_names = {s.__name__ for s in HOST_LEVEL_SCANNERS}
page_names = {s.__name__ for s in PAGE_LEVEL_SCANNERS}
overlap = host_names & page_names
check(not overlap, f"No overlap between host/page scanners (overlap: {overlap})")

all_names = {s.__name__ for s in ALL_SCANNERS}
check(host_names | page_names == all_names, "All scanners belong to host or page category")

from core.decision_engine import DecisionEngine
from scanners.registry import ALL_SCANNERS
from tests.v2_reference import V2DecisionEngine, v2_apply_evidence_assessment

de = DecisionEngine()
registered_names = {s("http://test.com").name for s in ALL_SCANNERS}
engine_keys = set(de.SEVERITY_BY_MODULE.keys())
missing_in_engine = registered_names - engine_keys
extra_in_engine = engine_keys - registered_names

if missing_in_engine:
    warn(f"Scanners missing from SEVERITY_BY_MODULE: {missing_in_engine}")
if extra_in_engine:
    warn(f"Engine has entries for non-existent scanners: {extra_in_engine}")

print(f"  Registered scanner names: {sorted(registered_names)}")

# ============================================================
# 3. BaseScanner methods
# ============================================================
print("\n=== 3. BaseScanner Methods ===")

bs = BaseScanner("https://example.com/test?foo=1&bar=2")
check(bs.get_params() == ["foo", "bar"], "get_params extracts URL parameters correctly")

injected = bs.inject_payload("foo", "' OR '1'='1")
check("foo=%27+OR+%271%27%3D%271" in injected, f"inject_payload works: {injected[:60]}")

data = bs.post_data_with_payload("user", "admin")
check(data == {"user": "admin"}, "post_data_with_payload with empty post_data")

bs2 = BaseScanner("https://example.com", post_data={"user": "test", "pass": "123"})
data2 = bs2.post_data_with_payload("user", "admin")
check(data2 == {"user": "admin", "pass": "123"}, "post_data_with_payload overrides single key")

check(bs.create_finding() is not None, "create_finding returns Finding")

safe = Finding()
safe.module = "Headers Security"
safe.status = Status.PASS
safe.tests_performed = 1
run_engine_pipeline(safe)
check(safe.status == Status.PASS, "Pipeline keeps PASS status")
check(safe.severity == Severity.NONE, "Pipeline keeps NONE severity")

vuln = Finding()
vuln.module = "XSS Detection"
vuln.status = Status.FAIL
vuln.tests_performed = 1
run_engine_pipeline(vuln)
check(vuln.status == Status.FAIL, "Pipeline keeps FAIL status")
check(vuln.severity == Severity.HIGH, "Pipeline maps XSS FAIL -> HIGH (module map)")

bs3 = BaseScanner("https://example.com/")
check(bs3.get_params() == [], "get_params returns empty list when no params")

# SmartPayloadSystem
sps = SmartPayloadSystem()
payloads = sps.select_payloads(param_type="string")
check('primary' in payloads, "SmartPayloadSystem has primary payloads")
check('confirm' in payloads, "SmartPayloadSystem has confirm payloads")
check('cross' in payloads, "SmartPayloadSystem has cross payloads")

encoded = sps.encode_payload("test", encoding="url")
check(encoded == "test", "URL encoding falls through for non-special chars")

encoded_hex = sps.encode_payload("test", encoding="hex")
check(encoded_hex.startswith("0x"), "Hex encoding works")

# ============================================================
# 4. Evidence system
# ============================================================
print("\n=== 4. Evidence System ===")

from core.evidence import EvidenceBuilder

eb = EvidenceBuilder()

ev1 = eb.confirmed("SQL error detected", payload="' OR 1=1")
check(ev1.level == EvidenceLevel.CONFIRMED, "EvidenceBuilder.confirmed uses CONFIRMED level")
check(ev1.confidence_bonus == 20, "CONFIRMED evidence has confidence_bonus=20")

ev2 = eb.exploited("RCE achieved")
check(ev2.level == EvidenceLevel.EXPLOITED, "EvidenceBuilder.exploited uses EXPLOITED level")
check(ev2.confidence_bonus == 35, "EXPLOITED evidence has confidence_bonus=35")

ev3 = eb.verified("Header present")
check(ev3.level == EvidenceLevel.VERIFIED, "EvidenceBuilder.verified uses VERIFIED level")

ev4 = eb.likely("Possible issue")
check(ev4.level == EvidenceLevel.LIKELY, "EvidenceBuilder.likely uses LIKELY level")

ev5 = eb.possible("Might be a problem")
check(ev5.level == EvidenceLevel.POSSIBLE, "EvidenceBuilder.possible uses POSSIBLE level")

ev6 = eb.error("Connection failed")
check(ev6.confidence_bonus == -20, "Error evidence has negative confidence bonus")

# New evidence types
ev7 = eb.behavior_change("Server behavior changed")
check(ev7.type == EvidenceType.BEHAVIOR_CHANGE, "Behavior change evidence type")

ev8 = eb.cross_validation("Cross-validation confirmed")
check(ev8.type == EvidenceType.CROSS_VALIDATION, "Cross-validation evidence type")
check(ev8.level == EvidenceLevel.VERIFIED, "Cross-validation uses VERIFIED level")

# Test confidence calculation: the v3 engine computes confidence from evidence
finding = Finding()
finding.module = "SQL Injection"
finding.status = Status.UNKNOWN
finding.add_evidence(eb.confirmed("SQLi detected", payload="test"))
check(finding.confidence == 0, "add_evidence alone does not compute confidence (engine-owned)")
run_engine_pipeline(finding)
check(finding.confidence > 0, "Finding confidence > 0 after running the engine pipeline")

finding2 = Finding()
finding2.module = "SQL Injection"
finding2.status = Status.UNKNOWN
finding2.add_evidence(eb.exploited("RCE"))
run_engine_pipeline(finding2)
check(finding2.confidence > finding.confidence or finding2.confidence == 100,
      "EXPLOITED evidence allows higher max confidence")

ev_dict = ev1.to_dict()
check(ev_dict["level"] == "confirmed", "Evidence.to_dict has correct level string")

# Test verification_pass in evidence
ev9 = Evidence(level=EvidenceLevel.CONFIRMED, type=EvidenceType.PAYLOAD_REFLECTION,
              description="test", verification_pass=2, verification_method="2/3 passes")
check(ev9.verification_pass == 2, "Evidence stores verification_pass")
check(ev9.verification_method == "2/3 passes", "Evidence stores verification_method")

# Test to_dict includes new fields
ev9_dict = ev9.to_dict()
check("verification_pass" in ev9_dict, "to_dict includes verification_pass")
check("verification_method" in ev9_dict, "to_dict includes verification_method")

# ============================================================
# 5. Decision Engine
# ============================================================
print("\n=== 5. Decision Engine ===")

v2de = V2DecisionEngine()

finding_fail = Finding()
finding_fail.module = "SQL Injection"
finding_fail.status = Status.FAIL
finding_fail.severity = Severity.NONE
finding_fail.confidence = 85
finding_fail.add_evidence(eb.confirmed("test"))
decided = v2de.decide(finding_fail)
check(decided.severity == Severity.CRITICAL, "SQL Injection FAIL maps to CRITICAL")
check(decided.cwe_id == "CWE-89", "SQL Injection gets CWE-89")
check(decided.owasp_category == "A03: Injection", "SQL Injection gets OWASP A03")

finding_warn = Finding()
finding_warn.module = "TLS/SSL Security"
finding_warn.status = Status.WARNING
finding_warn.severity = Severity.NONE
finding_warn.add_evidence(eb.likely("test"))
decided_warn = v2de.decide(finding_warn)
check(decided_warn.severity == Severity.MEDIUM,
      f"TLS WARNING maps to MEDIUM (was {decided_warn.severity.value})")

finding_pass = Finding()
finding_pass.module = "SQL Injection"
finding_pass.status = Status.PASS
finding_pass.severity = Severity.NONE
finding_pass.add_evidence(eb.verified("No vulnerability detected"))
decided_pass = v2de.decide(finding_pass)
check(decided_pass.status == Status.PASS,
      f"Engine respects PASS status (got {decided_pass.status.value})")
check(decided_pass.severity == Severity.NONE,
      f"PASS finding keeps NONE severity (got {decided_pass.severity.value})")

finding_unknown = Finding()
finding_unknown.module = "SQL Injection"
finding_unknown.status = Status.UNKNOWN
finding_unknown.severity = Severity.NONE
finding_unknown.add_evidence(eb.confirmed("SQL error detected"))
decided_unknown = v2de.decide(finding_unknown)
check(decided_unknown.status == Status.FAIL,
      f"Engine classifies UNKNOWN+CONFIRMED as FAIL (got {decided_unknown.status.value})")
check(decided_unknown.severity == Severity.CRITICAL,
      f"Engine assigns CRITICAL for SQL Injection (got {decided_unknown.severity.value})")

check(finding_fail.cvss_score > 0, "FAIL finding has CVSS score > 0")

check("confidentiality" in decided.impact, "Finding has impact confidentiality")
check("integrity" in decided.impact, "Finding has impact integrity")
check("availability" in decided.impact, "Finding has impact availability")

finding_lfi = Finding()
finding_lfi.module = "LFI Detection"
finding_lfi.status = Status.FAIL
finding_lfi.severity = Severity.NONE
finding_lfi.add_evidence(eb.confirmed("test"))
decided_lfi = v2de.decide(finding_lfi)
check(decided_lfi.cwe_id == "CWE-98", f"LFI gets CWE-98 (got {decided_lfi.cwe_id})")

# ============================================================
# 6. Response Analyzer
# ============================================================
print("\n=== 6. Response Analyzer ===")

class MockResponse:
    def __init__(self, status_code=200, text="<html><body>OK</body></html>", headers=None, cookies=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.cookies = cookies or []
        self.elapsed = type('Elapsed', (), {'total_seconds': lambda self: 0.5})()

analysis = ResponseAnalyzer.analyze_response(MockResponse())
check(analysis.status_code == 200, "ResponseAnalysis has status_code")
check(analysis.content_type == "text/html", "ResponseAnalysis has content_type")
check(analysis.content_length > 0, "ResponseAnalysis has content_length")
check(analysis.body_hash is not None, "ResponseAnalysis has body_hash")
check(analysis.normalized_hash is not None, "ResponseAnalysis has normalized_hash")

# Security headers analysis
headers_resp = MockResponse(headers={
    "Content-Type": "text/html",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Frame-Options": "DENY",
})
analysis2 = ResponseAnalyzer.analyze_response(headers_resp)
check(len(analysis2.security_headers) > 0, "Security headers analyzed")

hsts_headers = [h for h in analysis2.security_headers if h.name == 'Strict-Transport-Security']
check(len(hsts_headers) > 0, "HSTS header detected")
if hsts_headers:
    check(hsts_headers[0].present, "HSTS present flag")
    check(hsts_headers[0].valid, "HSTS valid with max-age=31536000")

# Cookie analysis
mock_cookie = type('Cookie', (), {
    'name': 'session', 'secure': False, 'domain': 'test.com', 'path': '/',
    'expires': None, '_rest': {'httponly': None, 'samesite': 'Lax'}
})()
cookies_resp = MockResponse(cookies=[mock_cookie])
analysis3 = ResponseAnalyzer.analyze_response(cookies_resp)
check(len(analysis3.cookies) > 0, "Cookies analyzed")
if analysis3.cookies:
    ca = analysis3.cookies[0]
    check(ca.name == 'session', "Cookie name extracted")
    check(not ca.secure, "Cookie missing Secure flag detected")

# Technology detection
tech_resp = MockResponse(text="<html>wp-content</html>")
analysis4 = ResponseAnalyzer.analyze_response(tech_resp)
check('WordPress' in analysis4.technologies, "WordPress detected via wp-content")

# Body normalization
normalized = ResponseAnalyzer.normalize_body("<script>alert(1)</script>Hello")
check('alert' not in normalized, "Script tags stripped in normalization")
check('hello' in normalized, "Text preserved in normalization")

# Body similarity
similarity = ResponseAnalyzer.body_similarity("hello world test", "hello world foo")
check(similarity >= 0.5, "Body similarity >= 0.5 for similar texts")
check(similarity < 1.0, "Body similarity < 1.0 for different texts")

# Sensitive pattern extraction
sensitive = ResponseAnalyzer.extract_sensitive_patterns("password = 'supersecret123'")
check(len(sensitive) > 0, "Sensitive pattern extraction finds passwords")

# ============================================================
# 7. ScanResult
# ============================================================
print("\n=== 7. ScanResult ===")

sr = ScanResult()

f1 = Finding()
f1.module = "SQL Injection"
f1.status = Status.FAIL
f1.severity = Severity.CRITICAL
f1.confidence = 90

f2 = Finding()
f2.module = "XSS Detection"
f2.status = Status.FAIL
f2.severity = Severity.HIGH
f2.confidence = 80

f3 = Finding()
f3.module = "Headers Security"
f3.status = Status.PASS
f3.severity = Severity.NONE

f4 = Finding()
f4.module = "TLS/SSL Security"
f4.status = Status.WARNING
f4.severity = Severity.MEDIUM

f5 = Finding()
f5.module = "DNS Security"
f5.status = Status.INFO
f5.skipped = True

sr.add_finding(f1)
sr.add_finding(f2)
sr.add_finding(f3)
sr.add_finding(f4)
sr.add_finding(f5)

check(len(sr.get_vulnerabilities()) == 2, "get_vulnerabilities returns 2 findings")
check(len(sr.get_safe_findings()) == 1, "get_safe_findings returns 1 finding")
check(len(sr.get_warning_findings()) == 1, "get_warning_findings returns 1 finding")
check(len(sr.get_skipped_findings()) == 1, "get_skipped_findings returns 1 finding")
check(sr.get_highest_severity() == Severity.CRITICAL, "Highest severity is CRITICAL")

stats = sr.get_statistics()
check(stats["critical"] == 1, "Statistics counts 1 critical")
check(stats["high"] == 1, "Statistics counts 1 high")
check(stats["vulnerabilities"] == 2, "Statistics counts 2 vulnerabilities")
check(stats["risk_score"] > 0, "Risk score is calculated")

check(f1.module_name == "SQL Injection", "module_name synced from module")

# Correlation integration
corr_results = sr.run_correlation()
check(isinstance(corr_results, list), "Correlation returns list of results")
check("correlations_found" in sr.correlation_results, "Correlation results stored in ScanResult")
check("correlations_found" in stats, "Statistics includes correlations_found")

# ============================================================
# 8. ScanConfig defaults
# ============================================================
print("\n=== 8. Configuration ===")

config = ScanConfig()
check(config.max_pages == 30, "Default max_pages = 30")
check(config.max_workers == 5, "Default max_workers = 5")
check(config.request_timeout == 10, "Default request_timeout = 10")

config2 = ScanConfig(max_pages=50, max_workers=10)
check(config2.max_pages == 50, "Override max_pages = 50")
check(config2.max_workers == 10, "Override max_workers = 10")

# ============================================================
# 9. TrackedSession & ResponseCache
# ============================================================
print("\n=== 9. HTTP Client ===")

ts = TrackedSession()
check(ts.request_count == 0, "TrackedSession starts at 0 requests")
check(hasattr(ts, 'request'), "TrackedSession has request method")

rc = ResponseCache(max_size=5, ttl=60)
check(rc.get("GET", "http://test.com") is None, "Cache miss returns None")

class MockResponse:
    def __init__(self, status_code=200, text="OK", headers=None, cookies=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.cookies = cookies or []
        self.elapsed = type('Elapsed', (), {'total_seconds': lambda self: 0.5})()

rc.set("GET", "http://test.com", MockResponse())
cached = rc.get("GET", "http://test.com")
check(cached is not None, "Cache hit returns response")
check(cached.status_code == 200, "Cached response has status 200")

for i in range(10):
    rc.set("GET", f"http://test{i}.com", MockResponse())
check(rc.get("GET", "http://test.com") is None,
      "LRU eviction removes oldest entry (max_size=5)")

rc.invalidate()
check(rc.get("GET", "http://test1.com") is None, "Full invalidation clears cache")

# ============================================================
# 10. Reporter
# ============================================================
print("\n=== 10. Reporter ===")

reporter = Reporter()

sr_report = ScanResult()

f = Finding()
f.module = "Test Scanner"
f.status = Status.FAIL
f.severity = Severity.HIGH
f.confidence = 85
f.reason = "Test vulnerability found"
f.recommendation = "Fix it"
f.add_evidence(eb.confirmed("Test evidence", payload="test_payload"))
f.tests_performed = 10
f.cvss_score = 7.5
f.cwe_id = "CWE-999"
sr_report.add_finding(f)

f_safe = Finding()
f_safe.module = "Safe Scanner"
f_safe.status = Status.PASS
f_safe.severity = Severity.NONE
f_safe.confidence = 95
f_safe.reason = "All checks passed"
sr_report.add_finding(f_safe)

sr_report.end_time = datetime.now()

html_file = reporter.generate_html(sr_report, "https://test-target.com")
check(os.path.exists(html_file) if html_file else False, "HTML report file created")
if html_file:
    with open(html_file, 'r', encoding='utf-8') as fh:
        html_content = fh.read()
    check("<!DOCTYPE html>" in html_content, "HTML report has DOCTYPE")
    check("Test Scanner" in html_content, "HTML report contains module name")
    check("SEA Corporate" in html_content, "HTML report contains scanner name")
    check("&" not in html_content, "HTML report has no unescaped &")
    escaped = reporter._escape_html("AT&T says <stop> & \"quote\"")
    check("AT&amp;T" in escaped, "_escape_html escapes & to &amp;")
    check("&lt;stop&gt;" in escaped, "_escape_html escapes < > to &lt; &gt;")
    check("&quot;quote&quot;" in escaped, "_escape_html escapes \" to &quot;")

txt_file = reporter.generate_txt(sr_report, "https://test-target.com")
check(os.path.exists(txt_file) if txt_file else False, "TXT report file created")

# ============================================================
# 11. Crawler
# ============================================================
print("\n=== 11. Crawler ===")

c = Crawler()
check(hasattr(c, 'crawl'), "Crawler has crawl method")
check(hasattr(c, 'extract_post_forms'), "Crawler has extract_post_forms method")
check(len(c.SKIP_EXTENSIONS) >= 30, f"Crawler has {len(c.SKIP_EXTENSIONS)} skip extensions")
check('.png' in c.SKIP_EXTENSIONS, "SKIP_EXTENSIONS includes .png")
check(c._should_skip_by_extension("http://example.com/image.png"), "Skip .png extension")
check(not c._should_skip_by_extension("http://example.com/page.php"), "Don't skip .php")

# ============================================================
# 12. Verification Engine
# ============================================================
print("\n=== 12. Verification Engine ===")

ve = VerificationEngine()

# Test check_reflection
mock_resp = MockResponse(text="<html>payload_reflected_here</html>")
reflected, desc = ve.check_reflection(mock_resp, "payload_reflected")
check(reflected, "VerificationEngine.check_reflection finds reflected payload")
check(len(desc) > 0, "Reflection description is non-empty")

not_reflected, _ = ve.check_reflection(mock_resp, "nonexistent_payload_xyz")
check(not not_reflected, "check_reflection returns False for non-reflected payload")

# Test check_timing_delay
delayed, delay = ve.check_timing_delay(6.0, 2.0)
check(delayed, "Timing delay detected (6s vs 2s baseline)")
check(delay >= 2.0, "Delay amount calculated correctly")

no_delay, _ = ve.check_timing_delay(2.1, 2.0)
check(not no_delay, "No false timing delay for normal response")

# Test check_status_code_anomaly
mock_500 = MockResponse(status_code=500, text="Error")
anomaly, _ = ve.check_status_code_anomaly(mock_500)
check(anomaly, "Status 500 detected as anomaly")

mock_200 = MockResponse(status_code=200, text="OK")
no_anomaly, _ = ve.check_status_code_anomaly(mock_200)
check(not no_anomaly, "Status 200 not flagged as anomaly")

# Test build_evidence_from_verification
passed_results = [VerificationResult(passed=True, pass_name="p1", confidence_contribution=20),
                   VerificationResult(passed=True, pass_name="p2", confidence_contribution=25)]
ev = ve.build_evidence_from_verification(passed_results, param="id", payload="test")
check(ev is not None, "Evidence built from 2 passed verification results")
check(ev.level == EvidenceLevel.CONFIRMED, "Dual-verification yields CONFIRMED evidence")

single_result = [VerificationResult(passed=True, pass_name="p1", confidence_contribution=20)]
single_ev = ve.build_evidence_from_verification(single_result, param="id", payload="test")
check(single_ev is not None, "Evidence built from single passed result")
check(single_ev.level == EvidenceLevel.LIKELY, "Single-verification yields LIKELY evidence")

no_pass = [VerificationResult(passed=False, pass_name="p1")]
none_ev = ve.build_evidence_from_verification(no_pass, param="id", payload="test")
check(none_ev is None, "No evidence for zero passed verifications")

# ============================================================
# 13. Correlation Engine
# ============================================================
print("\n=== 13. Correlation Engine ===")

ce = CorrelationEngine()
check(len(ce.CorrelationRules) > 0, "CorrelationEngine has rules")
check(hasattr(ce, 'correlate'), "CorrelationEngine has correlate method")

# Test correlation
f_xss = Finding()
f_xss.module = "XSS Detection"
f_xss.status = Status.FAIL
f_xss.severity = Severity.HIGH
f_xss.confidence = 80

f_headers = Finding()
f_headers.module = "Headers Security"
f_headers.status = Status.WARNING
f_headers.severity = Severity.MEDIUM
f_headers.confidence = 70

corr = Finding()
corr.module = "CORS Configuration"
corr.status = Status.FAIL
corr.severity = Severity.MEDIUM
corr.confidence = 75

results = ce.correlate([f_xss, f_headers, corr])
check(len(results) >= 0, "Correlation runs without error")

# Test correlation summary
summary = ce.get_correlation_summary()
check("correlations_found" in summary, "Correlation summary has correlations_found")
check("details" in summary, "Correlation summary has details")

# ============================================================
# 14. Deleted files verification
# ============================================================
print("\n=== 14. Deleted Files Verification ===")

check(not os.path.exists("core/classifier.py"), "classifier.py is deleted")
check(not os.path.exists("core/fingerprinter.py"), "fingerprinter.py is deleted")
check(not os.path.exists("core/form_crawler.py"), "form_crawler.py is deleted")

# ============================================================
# 15. Duplicated methods verification
# ============================================================
print("\n=== 15. Duplicated Methods Verification ===")

from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.lfi import LFIScanner
from scanners.ssrf import SSRFScanner
from scanners.open_redirect import OpenRedirectScanner

for sc in [SQLiScanner, XSSScanner, LFIScanner, SSRFScanner, OpenRedirectScanner]:
    inst = sc("http://test.com?x=1")
    check(inst.get_params() == ["x"], f"{sc.__name__}.get_params inherited from BaseScanner")
    injected = inst.inject_payload("x", "test")
    check("x=test" in injected, f"{sc.__name__}.inject_payload inherited from BaseScanner")

inst_post = SQLiScanner("http://test.com", post_data={"user": "old"})
data = inst_post.post_data_with_payload("user", "new")
check(data == {"user": "new"}, "SQLiScanner post_data_with_payload works")

# ============================================================
# 15b. SSTI Scanner
# ============================================================
print("\n=== 15b. SSTI Scanner ===")

from scanners.ssti import SSTIScanner
check(True, "SSTIScanner imports correctly")

ssti_registered = any(s.__name__ == 'SSTIScanner' for s in ALL_SCANNERS)
check(ssti_registered, "SSTIScanner is present in registry.ALL_SCANNERS")

ssti_inst = SSTIScanner("http://test.com")
check(ssti_inst.name == "SSTI Detection", "SSTIScanner instantiates and sets name correctly")
check(hasattr(ssti_inst, 'ENGINE_PAYLOADS'), "SSTIScanner has ENGINE_PAYLOADS")
check({'jinja2', 'twig'} <= set(ssti_inst.ENGINE_PAYLOADS),
      "SSTIScanner covers Jinja2 and Twig payloads")
check(len(ssti_inst.ENGINE_PAYLOADS) >= 5, "SSTIScanner covers 5+ template engines")

ssti_no_params = ssti_inst.scan()
check(ssti_no_params.status == Status.UNKNOWN,
      "SSTIScanner leaves status UNKNOWN when no params (evidence-only)")
check(ssti_no_params.severity == Severity.NONE,
      "SSTIScanner leaves severity NONE when no params")
check(any('No GET parameters' in e.description for e in ssti_no_params.evidence),
      "SSTI evidence notes no params to test")

# Verify SSTI is mapped in decision engine STANDARDS
from core.decision_engine import DecisionEngine
de_ssti = DecisionEngine()
check('SSTI Detection' in de_ssti.SEVERITY_BY_MODULE, "SSTI Detection mapped in decision engine")
check(de_ssti.SEVERITY_BY_MODULE['SSTI Detection'] == Severity.CRITICAL, "SSTI severity is CRITICAL")

# ============================================================
# 16. CVSS Vector
# ============================================================
print("\n=== 16. CVSS Vector ===")
f_cvss = Finding()
f_cvss.module = "SQL Injection"
f_cvss.status = Status.FAIL
f_cvss.severity = Severity.CRITICAL
f_cvss.confidence = 95
f_cvss.impact = {'confidentiality': 5, 'integrity': 5, 'availability': 3}
f_cvss.exploitability = Exploitability.EASY
v2de._calculate_cvss(f_cvss)
check(f_cvss.cvss_score > 5, f"CVSS score computed ({f_cvss.cvss_score})")
check(f_cvss.cvss_vector.startswith("CVSS:3.1/"), f"CVSS vector is valid ({f_cvss.cvss_vector})")
check("C:H" in f_cvss.cvss_vector, "CVSS vector has high confidentiality impact")

# ============================================================
# 17. add_evidence_with_snippet
# ============================================================
print("\n=== 17. add_evidence_with_snippet ===")
bs = BaseScanner("http://test.com")
bs_finding = Finding()
bs.add_evidence_with_snippet(bs_finding, 'confirmed', "Test with snippet", response=None)
check(len(bs_finding.evidence) == 1, "add_evidence_with_snippet adds evidence")
check(bs_finding.evidence[0].level is EvidenceLevel.CONFIRMED, "Evidence level is CONFIRMED")

bs_finding2 = Finding()
class MockResp:
    text = "response body content here"
    headers = {"Content-Type": "text/html"}
    elapsed = __import__('datetime').timedelta(seconds=0.5)
bs.add_evidence_with_snippet(bs_finding2, 'likely', "Test with real response", response=MockResp())
check(len(bs_finding2.evidence) == 1, "add_evidence_with_snippet with response adds evidence")
check('snippet' in bs_finding2.evidence[0].raw_data, "Evidence raw_data has snippet")

# ============================================================
# 18. Production Quality Features
# ============================================================
print("\n=== 18. Production Quality Features ===")

eb = EvidenceBuilder()
f1 = Finding()
f1.module = "XSS Detection"
f1.status = Status.FAIL
f1.evidence.append(eb.confirmed('XSS via alert(1)'))
f1.target = "https://test.com/page1"

f2 = Finding()
f2.module = "XSS Detection"
f2.status = Status.FAIL
f2.evidence.append(eb.confirmed('XSS via alert(1)'))
f2.target = "https://test.com/page2"

sr_dedup = ScanResult()
sr_dedup.add_finding(f1)
sr_dedup.add_finding(f2)
check(len(sr_dedup.findings) == 1, "Deduplication merges same scanner+vulnerability")
check(sr_dedup.findings[0].occurrences == 2, "Occurrences count incremented after merge")

from core.decision_engine import RiskCalculator
rc_result = RiskCalculator.calculate(sr_dedup.findings)
check("risk_score" in rc_result, "RiskCalculator returns risk_score")
check("breakdown" in rc_result, "RiskCalculator returns breakdown")

f3 = Finding()
f3.module = "SQL Injection"
f3.evidence.append(eb.exploited('SQL error confirmed'))
v2_apply_evidence_assessment(f3)
check(f3.verification_status == "verified", "EXPLOITED evidence -> verified status")

f5 = Finding()
f5.module = "XSS Detection"
f5.evidence.append(eb.possible('Possible XSS reflection'))
v2_apply_evidence_assessment(f5)
check(f5.verification_status == "manual_review", "POSSIBLE evidence -> manual_review status")

check(EvidenceType.REQUEST_RESPONSE in EvidenceType, "REQUEST_RESPONSE evidence type exists")
rr_ev = EvidenceBuilder.request_response("Test evidence", request={'url': 'http://test.com'}, response={'status': 200})
check(rr_ev.level == EvidenceLevel.CONFIRMED, "request_response uses CONFIRMED level")
check('request' in rr_ev.raw_data, "request_response stores request in raw_data")
check('response' in rr_ev.raw_data, "request_response stores response in raw_data")

f6 = Finding()
f6.module = "Test"
d = f6.to_dict()
check("occurrences" in d, "to_dict includes occurrences")
check("affected_urls" in d, "to_dict includes affected_urls")
check("verification_status" in d, "to_dict includes verification_status")
check("correlation_escalated" in d, "to_dict includes correlation_escalated")
check("verification_passes" in d, "to_dict includes verification_passes")
check("payload_evidence" in d, "to_dict includes payload_evidence")
check("response_fingerprint" in d, "to_dict includes response_fingerprint")
check("technical_explanation" in d, "to_dict includes technical_explanation")
check("remediation_steps" in d, "to_dict includes remediation_steps")

# ============================================================
# 19. Final Polish Features
# ============================================================
print("\n=== 19. Final Polish Features ===")

f_pass1 = Finding()
f_pass1.module = "XSS Detection"
f_pass1.status = Status.PASS
f_pass1.target = "https://test.com/page1"
f_pass1.tests_performed = 32

f_pass2 = Finding()
f_pass2.module = "XSS Detection"
f_pass2.status = Status.PASS
f_pass2.target = "https://test.com/page2"
f_pass2.tests_performed = 32

sr_pass = ScanResult()
sr_pass.add_finding(f_pass1)
sr_pass.add_finding(f_pass2)
check(len(sr_pass.findings) == 1, "PASS findings dedup by module")
check(sr_pass.findings[0].occurrences == 2, "PASS dedup increments occurrences")

sr_as = ScanResult()
sr_as.urls_discovered = ["http://test.com/page1", "http://test.com/page2"]
sr_as.urls_crawled = 2
sr_as.forms_discovered = 3
sr_as.technologies = ["WordPress", "PHP"]
stats_as = sr_as.get_statistics()
check(stats_as.get('urls_discovered') == 2, "Attack surface urls_discovered")
check(stats_as.get('forms_discovered') == 3, "Attack surface forms_discovered")

check("executive_summary" in stats_as, "get_statistics includes executive_summary")

f_skip = Finding()
f_skip.module = "SQL Injection"
f_skip.status = Status.SKIPPED
f_skip.skip_reason = "No forms found"
sr_skip = ScanResult()
sr_skip.add_finding(f_skip)
cov = sr_skip.get_coverage()
check("skip_reasons" in cov, "Coverage includes skip_reasons")

reporter2 = Reporter()
json_file = reporter2.generate_json(sr_as, "http://test.com")
check(os.path.exists(json_file) if json_file else False, "JSON export creates file")

md_file = reporter2.generate_markdown(sr_as, "http://test.com")
check(os.path.exists(md_file) if md_file else False, "Markdown export creates file")

csv_file = reporter2.generate_csv(sr_as, "http://test.com")
check(os.path.exists(csv_file) if csv_file else False, "CSV export creates file")

sr_agg = ScanResult()
f_a1 = Finding(); f_a1.module = "XSS"; f_a1.status = Status.PASS; f_a1.target = "/p1"; f_a1.tests_performed = 10
f_a2 = Finding(); f_a2.module = "XSS"; f_a2.status = Status.PASS; f_a2.target = "/p2"; f_a2.tests_performed = 10
sr_agg.add_finding(f_a1)
sr_agg.add_finding(f_a2)
sr_agg.aggregate_safe_findings()
check(len(sr_agg.findings) == 1, "aggregate_safe_findings merges PASS")
check(sr_agg.findings[0].occurrences == 2, "aggregate_safe_findings occurrences")

sr_v = ScanResult()
stats_v = sr_v.get_statistics()
check(stats_v.get('report_version') == '3.2', "Report version updated to 3.2")
check(stats_v.get('scanner_version') == '2.0.0', "Scanner version updated to 2.0.0")

# ============================================================
# 20. Thread Safety (B9/B13 Regression)
# ============================================================
print("\n=== 20. Thread Safety (B9/B13) ===")

# B9: ScanResult.add_finding() must be thread-safe
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sr_ts = ScanResult()
lock_test_results = []

def concurrent_add(idx):
    f = Finding()
    f.module = f"TestModule{idx}"
    f.status = Status.FAIL if idx % 2 == 0 else Status.PASS
    f.severity = Severity.MEDIUM if idx % 2 == 0 else Severity.NONE
    f.target = f"http://test.com/page{idx}"
    sr_ts.add_finding(f)
    return idx

with ThreadPoolExecutor(max_workers=10) as ex:
    futures = [ex.submit(concurrent_add, i) for i in range(50)]
    for f in as_completed(futures):
        f.result()

check(len(sr_ts.findings) > 0, "B9: Concurrent add_finding does not lose findings")
total_occurrences = sum(f.occurrences for f in sr_ts.findings)
check(total_occurrences == 50, f"B9: All 50 findings accounted for (got {total_occurrences})")
check(hasattr(sr_ts, '_lock'), "B9: ScanResult has threading.Lock")

# B13: Verify scanner instances are created per-call (not shared class-level state)
from scanners.registry import PAGE_LEVEL_SCANNERS, HOST_LEVEL_SCANNERS

# Check no scanner class has mutable class-level attributes that could be shared
for sc_list in [PAGE_LEVEL_SCANNERS, HOST_LEVEL_SCANNERS]:
    for sc_cls in sc_list:
        cls_attrs = {}
        for attr_name in dir(sc_cls):
            if attr_name.startswith('_'):
                continue
            if attr_name.isupper():
                continue  # ALL_CAPS names are constants, not mutable state
            val = getattr(sc_cls, attr_name, None)
            if isinstance(val, (list, dict, set)):
                cls_attrs[attr_name] = val
        check(len(cls_attrs) == 0,
              f"B13: {sc_cls.__name__} has no mutable class-level state ({len(cls_attrs)} found)")

# Verify each scanner instantiation produces independent instances
from scanners.sqli import SQLiScanner
inst1 = SQLiScanner("http://test.com?x=1")
inst2 = SQLiScanner("http://test.com?x=2")
check(inst1 is not inst2, "B13: Each scanner call creates a fresh instance")
check(inst1.target != inst2.target, "B13: Separate instances have separate target state")

# ============================================================
# 21. SOP Report Accuracy (Reporting Logic)
# ============================================================
print("\n=== 21. SOP Report Accuracy (Reporting Logic) ===")

def sop_finding(module, status=Status.PASS, severity=Severity.NONE, tests=0,
                reason="", skip_reason="", evidence=None, skipped=False):
    f = Finding()
    f.module = module
    f.target = "https://test.com/"
    f.status = status
    f.severity = severity
    f.tests_performed = tests
    f.tests_run = tests
    f.tests_passed = tests if status == Status.PASS else 0
    f.reason = reason or ("No issues found" if status == Status.PASS else "Test completed")
    f.skipped = skipped
    f.skip_reason = skip_reason
    if evidence:
        for ev in evidence:
            f.add_evidence(ev)
    return run_engine_pipeline(f)

# SOP #4: every scanner exposes exactly one standard execution state
f_pass = sop_finding("TLS/SSL Security", Status.PASS, Severity.NONE, tests=5,
                     reason="TLS 1.3 supported")
check(f_pass.execution_state == ExecutionState.PASSED,
      f"SOP: PASS with tests -> {f_pass.execution_state.value}")
check(f_pass.execution_label == "Passed", "SOP: PASS label is Passed")

f_na = sop_finding("Cookies Security", Status.PASS, Severity.NONE, tests=0,
                   reason="No cookies found to analyze")
check(f_na.execution_state == ExecutionState.NOT_APPLICABLE,
      f"SOP: PASS with 0 tests -> {f_na.execution_state.value}")
check(f_na.state_reason and f_na.state_reason != "",
      "SOP: not_applicable carries a state_reason")

f_fail = sop_finding("SQL Injection", Status.FAIL, Severity.CRITICAL, tests=3,
                     reason="SQL injection confirmed",
                     evidence=[eb.exploited("boolean-based blind", payload="x")])
check(f_fail.execution_state == ExecutionState.FAILED,
      f"SOP: FAIL -> {f_fail.execution_state.value}")

f_skip = sop_finding("DNS Security", Status.SKIPPED, Severity.NONE, tests=0,
                     skip_reason="No NS records found", skipped=True)
check(f_skip.execution_state == ExecutionState.SKIPPED,
      f"SOP: SKIPPED -> {f_skip.execution_state.value}")

f_warn = sop_finding("Headers Security", Status.WARNING, Severity.MEDIUM, tests=1,
                     reason="CSP header missing")
check(f_warn.execution_state == ExecutionState.WARNING,
      f"SOP: WARNING -> {f_warn.execution_state.value}")

f_info = sop_finding("Technology Detection", Status.INFO, Severity.INFO, tests=1,
                     reason="Detected: React")
check(f_info.execution_state == ExecutionState.INFO,
      f"SOP: INFO -> {f_info.execution_state.value}")

# SOP #8: coverage shows executed/skipped/failed/not-applicable with a WHY
sr_sop = ScanResult()
for f in (f_pass, f_na, f_fail, f_skip, f_warn, f_info):
    sr_sop.add_finding(f)
sr_sop.total_modules = 6

states = sr_sop.get_execution_states()
check(states['passed'] == 1 and states['failed'] == 1 and states['skipped'] == 1
      and states['not_applicable'] == 1 and states['warning'] == 1 and states['info'] == 1,
      "SOP: get_execution_states counts every state")
check(states['executed'] == 4, f"SOP: executed = {states['executed']}")
check(states['explanation'] and "Coverage reduced" in states['explanation'],
      "SOP: execution states includes a WHY explanation")

coverage = sr_sop.get_coverage()
check(coverage['executed'] + coverage['skipped'] + coverage['not_applicable']
      == coverage['total'],
      "SOP: coverage counts reconcile with total")
check(coverage['coverage'] > 0 and coverage['coverage'] <= 100,
      "SOP: coverage percentage is sane")
check('explanation' in coverage and len(coverage['explanation']) > 0,
      "SOP: coverage includes explanation")

# SOP #3: never show a plain zero for Payloads Tested
sr_payload = ScanResult()
f_p1 = sop_finding("SQL Injection", Status.SKIPPED, Severity.NONE, tests=0,
                   skip_reason="No parameters found", skipped=True)
f_p2 = sop_finding("XSS Detection", Status.PASS, Severity.NONE, tests=0,
                   reason="No forms or parameters discovered")
sr_payload.add_finding(f_p1)
sr_payload.add_finding(f_p2)
payload = sr_payload.get_payload_testing_status()
check(payload['count'] == 0 and payload['status'] == 'skipped'
      and payload['display'] == 'Skipped' and payload['reason'],
      f"SOP: payloads Skipped with a reason when none executed ({payload['reason']})")

sr_payload2 = ScanResult()
f_xss = sop_finding("XSS Detection", Status.FAIL, Severity.HIGH, tests=4,
                    reason="XSS confirmed", evidence=[eb.confirmed("Reflected XSS")])
sr_payload2.add_finding(f_xss)
payload = sr_payload2.get_payload_testing_status()
check(payload['count'] == 4 and payload['status'] == 'executed'
      and payload['display'] == '4',
      f"SOP: payloads executed shows count ({payload['count']})")

# SOP #1: overall severity policy multi-factor (never risk score alone)
sr_sev = ScanResult()
f_high_unverified = Finding()
f_high_unverified.module = "XSS Detection"
f_high_unverified.target = "https://test.com/"
f_high_unverified.status = Status.FAIL
f_high_unverified.severity = Severity.HIGH
f_high_unverified.reason = "Possible reflected XSS"
f_high_unverified.recommendation = "Encode output"
f_high_unverified.tests_performed = 2
f_high_unverified.add_evidence(eb.possible("Reflected parameter echoed unencoded"))
sr_sev.add_finding(v2de.decide(f_high_unverified))
f_high_unverified.confidence = 30
sev = sr_sev.get_overall_severity()
check(sev['tier'] == 'elevated',
      f"SOP: unverified high finding -> tier {sev['tier']} (not high)")
check(len(sev['reasons']) > 0, "SOP: overall severity explains its reasons")

sr_crit = ScanResult()
f_crit = Finding()
f_crit.module = "SQL Injection"
f_crit.target = "https://test.com/"
f_crit.status = Status.FAIL
f_crit.severity = Severity.CRITICAL
f_crit.reason = "Boolean-based blind SQL injection"
f_crit.recommendation = "Use parameterized queries"
f_crit.tests_performed = 3
f_crit.add_evidence(eb.exploited("Boolean-based blind confirmed", payload="x"))
sr_crit.add_finding(v2de.decide(f_crit))
check(sr_crit.get_overall_severity()['tier'] == 'critical',
      "SOP: verified critical finding -> tier critical")
check(sr_crit.get_overall_severity()['reasons'],
      "SOP: critical tier has supporting reasons")

# SOP #6: positive observations never reported as warnings
f_pos = sop_finding("TLS/SSL Security", Status.WARNING, Severity.MEDIUM, tests=2,
                    reason="TLS 1.3 supported and HSTS enabled",
                    evidence=[eb.verified("TLS 1.3 supported")])
check(f_pos.status == Status.PASS,
      f"SOP: positive observation warning reclassified -> {f_pos.status}")
check(f_pos.severity == Severity.NONE,
      f"SOP: reclassified finding severity -> {f_pos.severity}")

# SOP #11: standardized verification labels
check(f_crit.verification_label == "Verified",
      f"SOP: verified evidence label -> {f_crit.verification_label}")
check(f_high_unverified.verification_label == "Manual Review",
      f"SOP: possible evidence label -> {f_high_unverified.verification_label}")

# SOP #12: report metadata carries engine / rules / template versions
meta_stats = sr_crit.get_statistics()
check(meta_stats['engine_version'] and meta_stats['detection_rules_version']
      and meta_stats['template_version'],
      "SOP: statistics include engine/detection-rules/template versions")
check(len(f_crit.matched_rules) > 0,
      "SOP: finding collects matched rule indicators")

# SOP #14: strict validation rejects report generation for inconsistent results
sr_invalid = ScanResult()
f_bad = Finding()
f_bad.module = "Test Module"
f_bad.target = "https://test.com/"
f_bad.status = Status.FAIL
f_bad.severity = Severity.HIGH
f_bad.tests_performed = 1
sr_invalid.add_finding(f_bad)
validate_errors = sr_invalid.validate()
check(len(validate_errors) > 0, "SOP: invalid result yields validation errors")
check(reporter.generate_html(sr_invalid, "https://test.com") == "",
      "SOP: strict reporter refuses to generate invalid report")
reporter_loose = Reporter(strict_validation=False)
loose_errors = reporter_loose.validate_results(sr_invalid)
check(len(loose_errors) == len(validate_errors),
      "SOP: loose reporter still reports the same validation errors")

# ============================================================
# 22. Authentication Awareness & Authenticated Scanning
# ============================================================
print("\n=== 22. Authentication Awareness & Authenticated Scanning ===")

try:
    from core.auth_manager import (
        AuthDetector, AuthDecisionEngine, AuthSession,
        LoginProfile, SessionImporter, classify_auth_response, is_login_path,
    )
    from core.auth_manager import AuthState
    check(True, "AUTH: core.auth_manager imports OK")
except Exception as e:
    check(False, f"AUTH: core.auth_manager imports failed: {e}")

try:
    from core.secrets_redactor import (
        REDACTED, is_secret_key, redact_dict, redact_headers, redact_text,
    )
    check(True, "AUTH: core.secrets_redactor imports OK")
except Exception as e:
    check(False, f"AUTH: core.secrets_redactor imports failed: {e}")

try:
    from core.finding import EXECUTION_STATE_LABELS, ExecutionState
    check(True, "AUTH: extended ExecutionState imports OK")
except Exception as e:
    check(False, f"AUTH: extended ExecutionState imports failed: {e}")

# Detection (Phase 1)
detector = AuthDetector()
det_res = detector.analyze(
    url="https://test.com/login",
    html='<form action="/login" method="post"><input type="text" name="user">'
         '<input type="password" name="pass"><button>Sign in</button></form>',
    headers={"WWW-Authenticate": "Basic realm=\"app\""},
    status_code=200,
    response_cookies=["PHPSESSID=abc123"],
)
check(det_res.detected, f"AUTH: login page + password detected (conf={det_res.confidence})")
check(det_res.confidence >= 50, "AUTH: detection confidence >= 50")
check(len(det_res.reasons) >= 3, "AUTH: detection reasons populated")

det_401 = detector.analyze(url="https://test.com/api/data",
                           headers={"WWW-Authenticate": "Bearer realm=\"api\""},
                           status_code=401)
check(det_401.detected and det_401.protected_status == 401, "AUTH: HTTP 401 detected")

check(is_login_path("/login") and is_login_path("https://x.com/signin"),
      "AUTH: login path recognition")
check(not is_login_path("/about"), "AUTH: non-login path ignored")

# Response classification
def fake_response(code, history_urls=(), final_url=""):
    resp = Mock()
    resp.status_code = code
    resp.url = final_url
    resp.history = []
    for h in history_urls:
        hh = Mock()
        hh.url = h
        resp.history.append(hh)
    return resp

check(classify_auth_response("u", fake_response(401))['classification'] == 'unauthorized',
      "AUTH: 401 -> unauthorized")
check(classify_auth_response("u", fake_response(403))['classification'] == 'blocked',
      "AUTH: 403 -> blocked")
check(classify_auth_response("u", fake_response(200))['classification'] == 'accessible',
      "AUTH: 200 -> accessible")
check(classify_auth_response("u", fake_response(302, ["https://x.com/login"], "https://x.com/login"))['classification'] == 'redirected',
      "AUTH: 302 to login -> redirected")
check(classify_auth_response("u", fake_response(404))['classification'] == 'unknown',
      "AUTH: 404 -> unknown")

# Decision engine (Phase 2 / 14)
dec_classifications = [
    classify_auth_response("u", fake_response(200)),
    classify_auth_response("u", fake_response(200)),
    classify_auth_response("u", fake_response(302, ["https://x.com/login"], "https://x.com/login")),
    classify_auth_response("u", fake_response(401)),
]
decision = AuthDecisionEngine().analyze(det_res, dec_classifications)
check(decision.prompt, "AUTH: prompt triggered with protected resources + improvement")
check(decision.public_coverage < decision.estimated_auth_coverage,
      f"AUTH: auth coverage improves ({decision.public_coverage}% -> {decision.estimated_auth_coverage}%)")
check(decision.coverage_message().startswith("Using authentication is estimated"),
      "AUTH: coverage message UX text")

# AuthSession cookie + bearer transport (Phases 4 / 5)
import requests as _requests
sess = _requests.Session()
cookie_auth = AuthSession(method="cookies")
cookie_auth.set_cookie("PHPSESSID", "abc123")
cookie_auth.apply_to(sess)
jar = {c.name: c.value for c in sess.cookies}
check(jar.get("PHPSESSID") == "abc123", "AUTH: empty-domain cookie attached to session")

bearer_auth = AuthSession(method="bearer")
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
bearer_auth.set_bearer_token(jwt)
bearer_auth.apply_to(sess)
check(sess.headers.get("Authorization") == f"Bearer {jwt}", "AUTH: bearer token attached")

exported = bearer_auth.to_dict(redact=True)
check("eyJhbGci" not in str(exported) and "Authorization" not in str(exported),
      "AUTH: token redacted from session export")
check(exported["has_token"] and exported["method_label"], "AUTH: session export flags token presence")

# Session refresh / expiry from Set-Cookie (Phase 8)
refresh_resp = Mock()
refresh_headers = Mock()
refresh_headers.get_list = Mock(return_value=[
    "NEWCOOKIE=xyz; Path=/",
    "OLDSESSION=; Max-Age=0; Path=/",
])
refresh_resp.headers = refresh_headers
refresh_auth = AuthSession(method="cookies")
refresh_auth.set_cookie("OLDSESSION", "keepme")
refresh_auth.update_from_response(refresh_resp)
check(refresh_auth.cookies.get("NEWCOOKIE") == "xyz", "AUTH: Set-Cookie refresh applied")
check("OLDSESSION" not in refresh_auth.cookies, "AUTH: Max-Age=0 cookie removed")

# Login profile redaction (Phase 6)
profile = LoginProfile(login_url="https://x.com/login", username="admin",
                       password="supersecret99", csrf_field="_token",
                       csrf_token="tok123456789012")
login_req = profile.build_request()
check(login_req['data'].get('password') == "supersecret99", "AUTH: login request carries credentials")
profile_export = profile.to_dict(redact=True)
check("supersecret99" not in str(profile_export) and "tok123456789012" not in str(profile_export),
      "AUTH: profile export redacts credentials")

# Redaction (Phase 13)
check("hunter2pass" not in redact_text("password=hunter2pass"), "AUTH: password pair redacted")
check(jwt not in redact_text(f"Bearer {jwt}"), "AUTH: JWT redacted")
check("abcdefghijklmnopqrstuvwxyz123456" not in redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"),
      "AUTH: Authorization header redacted")
check("abc123" not in redact_text("PHPSESSID=abc123"), "AUTH: session cookie pair redacted")
check(is_secret_key("password") and is_secret_key("API-Key") and not is_secret_key("username"),
      "AUTH: secret key name recognition")
redacted_dict = redact_dict({"password": "hunter2", "api_key": "k123456", "username": "alice"})
check(redacted_dict["password"] == REDACTED and "hunter2" not in str(redacted_dict)
      and redacted_dict["username"] == "alice",
      "AUTH: dict redaction preserves non-secrets")
redacted_headers = redact_headers({"Authorization": "Bearer abcdefghijk123456", "X-Custom": "hello"})
check("abcdefghijk123456" not in str(redacted_headers), "AUTH: header redaction")

# Coverage + session state evaluation (Phases 10 / 11)
sr_auth = ScanResult()
sr_auth.set_auth_detection(det_res)
sr_auth.auth_public_pages = 4
sr_auth.auth_authenticated_pages = 2
for i in range(2):
    sr_auth.record_auth_response(classify_auth_response("u", fake_response(200)))
sr_auth.record_auth_response(classify_auth_response("u", fake_response(302, ["https://x.com/login"], "https://x.com/login")))
sr_auth.record_auth_response(classify_auth_response("u", fake_response(401)))
session = AuthSession(method="cookies")
session.set_cookie("SID", "v1")
sr_auth.set_auth_session(session)
state = sr_auth.evaluate_auth_state()
check(state == "authenticated", f"AUTH: valid session -> {state}")
cov = sr_auth.get_auth_coverage()
check(cov['public'] == 50 and cov['authenticated'] == 75 and cov['blocked'] == 25,
      f"AUTH: coverage split public/authenticated/blocked ({cov['public']}%/{cov['authenticated']}%/{cov['blocked']}%)")
check(cov['overall'] == 75 and cov['improvement'] == 25,
      f"AUTH: overall coverage + improvement ({cov['overall']}% / +{cov['improvement']}%)")

sr_expired = ScanResult()
exp_session = AuthSession(method="cookies")
exp_session.set_cookie("SID", "v")
sr_expired.set_auth_session(exp_session)
sr_expired.record_auth_response(classify_auth_response("u", fake_response(302, ["https://x.com/login"], "https://x.com/login")))
sr_expired.record_auth_response(classify_auth_response("u", fake_response(401)))
check(sr_expired.evaluate_auth_state() == "session_expired",
      "AUTH: protected pages + no authed pages -> session expired")

sr_bad_token = ScanResult()
bad_token = AuthSession(method="bearer")
bad_token.set_bearer_token("t")
sr_bad_token.set_auth_session(bad_token)
sr_bad_token.record_auth_response(classify_auth_response("u", fake_response(401)))
check(sr_bad_token.evaluate_auth_state() == "token_invalid",
      "AUTH: unauthorized + no authed pages -> token invalid")

# New execution states (Phase 11)
check(ExecutionState.AUTH_REQUIRED.value == "auth_required"
      and ExecutionState.AUTHENTICATED.value == "authenticated"
      and ExecutionState.SESSION_EXPIRED.value == "session_expired",
      "AUTH: new execution states defined")
check(EXECUTION_STATE_LABELS[ExecutionState.AUTH_REQUIRED] == "Auth Required"
      and EXECUTION_STATE_LABELS[ExecutionState.SESSION_EXPIRED] == "Session Expired",
      "AUTH: new state labels readable")

# Browser import approval (Phase 7)
importer = SessionImporter(approval=False)
try:
    importer.import_for_domain("https://example.com", browser="chrome")
    check(False, "AUTH: import without approval should raise PermissionError")
except PermissionError:
    check(True, "AUTH: browser import denied without approval")

# Report section (Phase 9)
reporter_auth = Reporter()
auth_stats = sr_auth.get_statistics()
auth_html = reporter_auth.build_auth_section(auth_stats)
check(len(auth_html) > 0 and "v1" not in auth_html, "AUTH: report section renders without cookie values")
check("abc123" not in auth_html and "Authorization" not in auth_html, "AUTH: report section free of secrets")
check(Reporter().build_auth_section(ScanResult().get_statistics()) == "",
      "AUTH: public scan renders no auth section")

# Execution states table must tolerate auth states without KeyError
sr_auth_state = ScanResult()
f_auth_state = Finding()
f_auth_state.module = "Auth Module"
f_auth_state.target = "https://test.com/"
f_auth_state.status = Status.INFO
f_auth_state.execution_state = ExecutionState.AUTH_REQUIRED
f_auth_state.state_reason = "Authentication required"
sr_auth_state.add_finding(f_auth_state)
exec_states = sr_auth_state.get_execution_states()
check(exec_states['auth_required'] == 1 and exec_states['total'] == 1,
      "AUTH: execution-states table counts auth states")

# ============================================================
# 23. Optional Authentication Providers (SOP v4.0 Phase 1)
# ============================================================
print("\n=== 23. Optional Authentication Providers ===")

try:
    from core.auth import AuthenticationManager, AuthSpec
    from core.auth.cookie_provider import CookieProvider
    from core.auth.bearer_provider import BearerProvider
    from core.auth.jwt_provider import JwtProvider
    from core.auth.header_provider import HeaderProvider
    from core.auth.session_validator import SessionValidationResult, SessionValidator
    check(True, "AUTH: core.auth package imports OK")
except Exception as e:
    check(False, f"AUTH: core.auth package imports failed: {e}")

check(AuthSpec(type="bearer", token="t").enabled
      and not AuthSpec().enabled
      and not AuthSpec(type="bearer").enabled,
      "AUTH: AuthSpec.enabled reflects configured credentials")

with tempfile.TemporaryDirectory() as td:
    netscape = os.path.join(td, "netscape.txt")
    with open(netscape, "w", encoding="utf-8") as fh:
        fh.write("# Netscape HTTP Cookie File\n"
                 ".example.com\tTRUE\t/\tFALSE\t0\tSID\tabc123\n")
    plain = os.path.join(td, "plain.txt")
    with open(plain, "w", encoding="utf-8") as fh:
        fh.write("session=xyz123\nremember=1\n")
    token_file = os.path.join(td, "token.txt")
    with open(token_file, "w", encoding="utf-8") as fh:
        fh.write("# comment line\n  \nsecret-token-123\n")

    cookie_auth = CookieProvider().build(AuthSpec(type="cookies", cookie_file=netscape))
    check(cookie_auth is not None and cookie_auth.cookies.get("SID") == "abc123",
          "AUTH: Netscape cookie file parsed (SID)")
    cookie_auth2 = CookieProvider().build(AuthSpec(type="cookies", cookie_file=plain))
    check(cookie_auth2 is not None and cookie_auth2.cookies.get("session") == "xyz123",
          "AUTH: plain name=value cookie file parsed")
    cookie_str = CookieProvider().build(AuthSpec(type="cookies", cookie_string="a=1; b=2"))
    check(cookie_str is not None and cookie_str.cookies.get("b") == "2",
          "AUTH: cookie string parsed")

    bearer_auth = BearerProvider().build(AuthSpec(type="bearer", token_file=token_file))
    check(bearer_auth is not None and "secret-token-123" in (bearer_auth.token or ""),
          "AUTH: bearer token read from file (first non-comment line)")
    jwt_auth = JwtProvider().build(AuthSpec(type="jwt", token_file=token_file))
    check(jwt_auth is not None and jwt_auth.method == "jwt"
          and "secret-token-123" in (jwt_auth.token or ""),
          "AUTH: JWT provider builds a jwt session")
    hdr_auth = HeaderProvider().build(
        AuthSpec(type="headers", headers=["X-API-Key: k123", "X-Tenant: acme"]))
    check(hdr_auth is not None and hdr_auth.extra_headers.get("X-API-Key") == "k123",
          "AUTH: custom headers provider")

    try:
        CookieProvider().build(AuthSpec(type="cookies", cookie_file=os.path.join(td, "nope.txt")))
        check(False, "AUTH: missing cookie file should raise ValueError")
    except ValueError:
        check(True, "AUTH: missing cookie file raises ValueError")

    # AuthenticationManager facade
    manager = AuthenticationManager()
    check(manager.is_supported("bearer") and not manager.is_supported("gssapi"),
          "AUTH: manager supports cookies/bearer/jwt/headers only")
    check(manager.build(None) is None and manager.build(AuthSpec()) is None,
          "AUTH: anonymous/no-op builds return None")
    try:
        manager.build(AuthSpec(type="kerberos", token="t"))
        check(False, "AUTH: unsupported type should raise ValueError")
    except ValueError:
        check(True, "AUTH: unsupported auth type raises ValueError")
    empty_file = os.path.join(td, "empty.txt")
    with open(empty_file, "w", encoding="utf-8") as fh:
        fh.write("# only a comment\n")
    try:
        manager.build(AuthSpec(type="bearer", token_file=empty_file))
        check(False, "AUTH: empty token should raise ValueError")
    except ValueError:
        check(True, "AUTH: empty token raises ValueError")

    probe = _requests.Session()
    bauth = manager.build(AuthSpec(type="bearer", token="tok-abc"))
    manager.apply_to(bauth, probe)
    check(probe.headers.get("Authorization") == "Bearer tok-abc",
          "AUTH: manager.apply_to attaches bearer header")

    invalid_bearer = AuthSession(method="bearer")
    invalid_bearer.set_bearer_token("t")
    manager.mark_invalid(invalid_bearer)
    check(invalid_bearer.state.value == "token_invalid",
          "AUTH: mark_invalid flags token-based sessions")
    invalid_cookie = AuthSession(method="cookies")
    invalid_cookie.set_cookie("SID", "v")
    manager.mark_invalid(invalid_cookie)
    check(invalid_cookie.state.value == "session_expired",
          "AUTH: mark_invalid flags cookie sessions as expired")
    manager.mark_invalid(None)
    check(True, "AUTH: mark_invalid(None) is a no-op")

    # SessionValidator against canned responses (no network)
    from unittest.mock import patch

    def mk_response(code, text, url, history_urls=()):
        resp = Mock()
        resp.status_code = code
        resp.text = text
        resp.url = url
        resp.history = [Mock(url=h) for h in history_urls]
        return resp

    class FakeProbeSession:
        def __init__(self, responses):
            self._responses = list(responses)

        def get(self, *a, **k):
            return self._responses.pop(0)

    auth_b = AuthSession(method="bearer")
    auth_b.set_bearer_token("t")

    with patch("requests.Session",
               lambda: FakeProbeSession([mk_response(401, "", "http://x/")])):
        r401 = SessionValidator().validate(auth_b, None, "http://x/")
    check(not r401.valid and r401.classification == "unauthorized" and r401.applicable,
          "AUTH: validator rejects 401")

    with patch("requests.Session",
               lambda: FakeProbeSession(
                   [mk_response(200, "<html>sign in</html>", "http://x/login", ("http://x/",))])):
        r_redir = SessionValidator().validate(auth_b, None, "http://x/")
    check(not r_redir.valid and r_redir.redirected_to_login,
          "AUTH: validator flags redirect to login")

    with patch("requests.Session",
               lambda: FakeProbeSession(
                   [mk_response(200, '<html><form><input type="password"></form></html>', "http://x/")])):
        r_body = SessionValidator().validate(auth_b, None, "http://x/")
    check(not r_body.valid, "AUTH: validator rejects login-page body")

    with patch("requests.Session",
               lambda: FakeProbeSession(
                   [mk_response(200, "<html><body>dashboard</body></html>", "http://x/")])):
        r_ok = SessionValidator().validate(auth_b, None, "http://x/")
    check(r_ok.valid and r_ok.message == "Session validated successfully.",
          "AUTH: validator accepts valid session")

    r_anon = SessionValidator().validate(None, None, "http://x/")
    check(not r_anon.applicable and r_anon.valid,
          "AUTH: anonymous scan skips validation")

    sr = ScanResult()
    sr.set_auth_session(auth_b)
    sr.evaluate_auth_state()
    check(sr._auth_stats()["authenticated"] is True
          and sr._auth_stats()["mode"] == "Bearer Token",
          "AUTH: auth stats expose mode + authenticated")

# sea CLI (SOP v4.0 Phase 1)
import sea as sea_cli
sea_parser = sea_cli.build_parser()
anon_args = sea_parser.parse_args(["scan", "https://x.com"])
check(sea_cli.build_auth_spec(anon_args) is None,
      "AUTH: sea CLI anonymous scan -> no auth spec")
bear_args = sea_parser.parse_args(["scan", "https://x.com", "--bearer", token_file,
                                   "--jwt", token_file])
try:
    sea_cli.build_auth_spec(bear_args)
    check(False, "AUTH: sea CLI conflicting methods should exit 2")
except SystemExit as e:
    check(e.code == 2, "AUTH: sea CLI conflicting methods exit code 2")
jwt_only = sea_parser.parse_args(["scan", "https://x.com", "--jwt", token_file])
jwt_spec = sea_cli.build_auth_spec(jwt_only)
check(jwt_spec is not None and jwt_spec.type == "jwt"
      and jwt_spec.token_file == token_file and jwt_spec.validate,
      "AUTH: sea CLI --jwt builds AuthSpec")
hdr_args = sea_parser.parse_args(["scan", "https://x.com", "--header", "X-A: 1",
                                  "--header", "X-B: 2"])
hdr_spec = sea_cli.build_auth_spec(hdr_args)
check(hdr_spec is not None and len(hdr_spec.headers) == 2,
      "AUTH: sea CLI --header builds headers spec")
nov_args = sea_parser.parse_args(["scan", "https://x.com", "--bearer", token_file,
                                  "--no-validate-session"])
nov_spec = sea_cli.build_auth_spec(nov_args)
check(nov_spec is not None and nov_spec.validate is False,
      "AUTH: sea CLI --no-validate-session respected")
deep_args = sea_parser.parse_args(["scan", "https://x.com", "--mode", "deep"])
check(sea_cli.MODE_PRESETS[deep_args.mode]["max_pages"] == 60,
      "AUTH: sea CLI deep preset")

# ============================================================
# 24. Advanced Smart Crawling (SOP v4.0 Phase 2)
# ============================================================
print("\n=== 24. Advanced Smart Crawling (Phase 2) ===")

try:
    from core.crawler import (
        Crawler, CrawlQueue, ScopeManager, RobotsParser, SitemapParser,
        LinkDiscovery, URLNormalizer, PageClassifier, Deduplicator,
        CrawlStatistics,
    )
    check(True, "CRAWL: core.crawler package imports OK")
except Exception as e:
    check(False, f"CRAWL: core.crawler package imports failed: {e}")

# --- URL normalization ---
try:
    n = URLNormalizer()
    norm = n.normalize("https://Example.com:443/a//b/../c?utm_source=x&id=5#sec")
    check(norm == "https://example.com/a/c?id=5",
          f"CRAWL: normalizes host, port, slashes, fragment, tracking param ({norm!r})")
    fragments = n.normalize("https://x.com/page#frag")
    check(fragments == "https://x.com/page", "CRAWL: fragments stripped")
except Exception as e:
    check(False, f"CRAWL: URL normalization failed: {e}")

# --- Scope management ---
try:
    s = ScopeManager("https://example.com/base/")
    check(s.is_in_scope("https://www.example.com/login"), "CRAWL: subdomain in domain scope")
    check(s.is_in_scope("https://example.com/base/sub"), "CRAWL: path under base allowed")
    check(not s.is_in_scope("https://other.com/x"), "CRAWL: foreign host excluded")
    check(not s.is_in_scope("javascript:alert(1)"), "CRAWL: non-http scheme excluded")
    sp = ScopeManager("https://example.com/app/", scope="path")
    check(not sp.is_in_scope("https://example.com/elsewhere"), "CRAWL: path scope excludes outside")
    check(sp.is_in_scope("https://example.com/app/deep"), "CRAWL: path scope includes descendants")
    ex = ScopeManager("https://example.com/", exclude_patterns=["/private/"])
    check(not ex.is_in_scope("https://example.com/private/x"), "CRAWL: exclude pattern applied")
except Exception as e:
    check(False, f"CRAWL: scope management failed: {e}")

# --- robots.txt parsing ---
try:
    rp = RobotsParser()
    rob = rp.parse("User-agent: *\nDisallow: /admin\nAllow: /public\n"
                   "Sitemap: https://x.com/sitemap.xml")
    check(rob.disallow == ["/admin"], "CRAWL: robots disallow parsed")
    check(rob.sitemaps == ["https://x.com/sitemap.xml"], "CRAWL: robots sitemap parsed")
    check(rob.allow == ["/public"], "CRAWL: robots allow parsed")
except Exception as e:
    check(False, f"CRAWL: robots parsing failed: {e}")

# --- sitemap parsing ---
try:
    sp = SitemapParser()
    xml = ('<?xml version="1.0"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           '<url><loc>https://x.com/a</loc></url>'
           '<url><loc>https://x.com/b</loc></url></urlset>')
    locs = list(sp._iter_locs(xml))
    check(len(locs) == 2 and all(not i for _u, i in locs),
          "CRAWL: sitemap URLset <loc> parsed")
    idx = ('<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           '<sitemap><loc>https://x.com/nested.xml</loc></sitemap></sitemapindex>')
    idx_locs = list(sp._iter_locs(idx))
    check(len(idx_locs) == 1 and idx_locs[0][1], "CRAWL: sitemap index flagged")
    check(sp._looks_like_url("https://x.com/a"), "CRAWL: looks_like_url accepts absolute")
    check(not sp._looks_like_url("/relative"), "CRAWL: relative sitemap entry rejected")
except Exception as e:
    check(False, f"CRAWL: sitemap parsing failed: {e}")

# --- queue depth + deduplication (infinite-precrawl safety) ---
try:
    q = CrawlQueue(max_depth=2)
    added0 = q.add("https://x.com/1", 0)
    added_dup = q.add("https://x.com/1", 0)
    added_deep = q.add("https://x.com/deep", 3)
    check(added0 and not added_dup, "CRAWL: queue de-duplicates URLs")
    check(not added_deep, "CRAWL: queue enforces max depth")
    dedupe = Deduplicator(n)
    u1 = n.normalize("https://x.com/p?a=1")
    u2 = n.normalize("https://x.com/p?a=1")
    check(not dedupe.seen_url(u1), "CRAWL: dedup fresh URL")
    dedupe.add_url(u1)
    check(dedupe.seen_url(u2), "CRAWL: dedup detects normalized duplicate")
    dedupe.add_content("same body")
    check(dedupe.seen_content("same body"), "CRAWL: content-hash dedup")
except Exception as e:
    check(False, f"CRAWL: queue/dedup failed: {e}")

# --- URL de-dup in HTTP crawler (no duplicate identity) ---
try:
    cw = Crawler()
    norm1 = cw.normalizer.normalize("https://example.com/p?utm_source=x&a=1")
    norm2 = cw.normalizer.normalize("https://example.com/p?a=1")
    check(norm1 == norm2, "CRAWL: crawler maps tracking-param URLs to one identity")
except Exception as e:
    check(False, f"CRAWL: crawler dedup identity failed: {e}")

# --- page classification ---
try:
    pc = PageClassifier()
    check(pc.classify_path("/login") == "Login", "CRAWL: /login classified Login")
    check(pc.classify_path("/admin") == "Admin", "CRAWL: /admin classified Admin")
    check(pc.classify_path("/api/v1/users") == "API", "CRAWL: /api classified API")
    check(pc.classify_path("/404", 404) == "Error Page", "CRAWL: 404 classified Error")
except Exception as e:
    check(False, f"CRAWL: page classification failed: {e}")

# --- statistics diag backward compatibility ---
try:
    st = CrawlStatistics()
    st.urls_scanned = 5
    st.pages_useful = 3
    diag = st.to_diag()
    check("crawler_type" in diag and diag["urls_visited"] == 5,
          "CRAWL: stats expose legacy-compatible diag keys")
    check("sitemap_entries" in diag and "classifications" in diag,
          "CRAWL: stats expose Phase 2 keys")
except Exception as e:
    check(False, f"CRAWL: statistics diag failed: {e}")

# --- form extraction helper (backward compat) ---
try:
    from core.crawler.forms_helper import extract_post_forms
    from bs4 import BeautifulSoup
    soup = BeautifulSoup("<form method='post' action='/go'><input name='user'></form>",
                         "html.parser")
    forms = extract_post_forms(soup, "https://x.com")
    check(len(forms) == 1 and forms[0]["url"] == "https://x.com/go" and "user" in forms[0]["fields"],
          "CRAWL: form extraction preserved")
except Exception as e:
    check(False, f"CRAWL: form extraction failed: {e}")

# --- ScanConfig crawl knobs ---
try:
    cfg = ScanConfig()
    check(cfg.crawl_scope == "domain" and cfg.parse_sitemap and not cfg.respect_robots,
          "CRAWL: ScanConfig defaults (domain scope, sitemap on, robots off)")
    cfg.max_depth = 5
    check(cfg.max_depth == 5, "CRAWL: ScanConfig.max_depth settable")
except Exception as e:
    check(False, f"CRAWL: ScanConfig knobs failed: {e}")

# --- CLI advanced crawling flags ---
try:
    cli_crawl = sea_parser.parse_args(["scan", "https://x.com",
                                       "--max-pages", "99", "--max-depth", "4",
                                       "--scope", "subdomain", "--include-subdomains",
                                       "--respect-robots", "--parse-sitemap"])
    cli_cfg = ScanConfig()
    cli_cfg.max_pages = sea_cli.MODE_PRESETS[cli_crawl.mode]["max_pages"]
    cli_cfg.crawl_scope = cli_crawl.scope
    cli_cfg.include_subdomains = cli_crawl.include_subdomains
    cli_cfg.respect_robots = cli_crawl.respect_robots
    check(cli_crawl.max_pages == 99 and cli_crawl.max_depth == 4
          and cli_cfg.crawl_scope == "subdomain" and cli_cfg.include_subdomains
          and cli_cfg.respect_robots, "CRAWL: sea CLI advanced flags parsed")
except Exception as e:
    check(False, f"CRAWL: CLI advanced flags failed: {e}")

# ============================================================
# 25. SQL Injection upgrade (SOP Phase 3.1)
# ============================================================
print("\n=== 25. SQL Injection upgrade (Phase 3.1) ===")

from urllib.parse import urlparse as _up, parse_qs as _pq
from scanners.sqli import SQLiScanner
_SQLiScanner = SQLiScanner


class _SQLiElapsed:
    def total_seconds(self): return 0.02


class _SQLiResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.headers = {'Content-Type': 'text/html'}
        self.elapsed = _SQLiElapsed()


class _SQLiSess:
    """Mock session routing the first query param value into a backend."""
    def __init__(self, backend):
        self.backend = backend
        self.headers = {'User-Agent': 'test'}
    def _val(self, url, data):
        if data is not None:
            return next(iter(data.values()), "")
        return next(iter(_pq(_up(url).query).values()), [""])[0]
    def get(self, url, timeout=None):
        return self.backend.resolve(self._val(url, None), 'GET')
    def post(self, url, data=None, timeout=None):
        return self.backend.resolve(self._val(url, data), 'POST')


class _UnionBackend:
    def __init__(self, cols=4): self.cols = cols
    def resolve(self, qval, method):
        if 'ORDER BY' in qval:
            n = int(qval.split('ORDER BY')[1].split('--')[0].strip())
            return _SQLiResp("normal") if n <= self.cols else _SQLiResp("ERR", 500)
        if 'UNION SELECT' in qval:
            return _SQLiResp("Loaded " + qval + " done")
        return _SQLiResp("normal")


class _ErrorBackend:
    def resolve(self, qval, method):
        if "' OR 1=1-- -" in qval or qval in ("'", '"', "' OR '1'='1", "' AND '1'='1"):
            return _SQLiResp("You have an error in your SQL syntax at line 1", 500)
        return _SQLiResp("ok")


class _BoolBackend:
    def resolve(self, qval, method):
        if qval in ("' AND '1'='2'-- -", "' OR '1'='2'-- -",
                    "'/**/AND/**/1=2-- -"):
            return _SQLiResp("FALSE" * 20)
        return _SQLiResp("TRUE")


# 25.1 UNION-based (new technique - column oracle + marker reflection)
try:
    sc = SQLiScanner("http://x.test/query?id=1", session=_SQLiSess(_UnionBackend(cols=4)))
    obs, tested = sc._check_union_based(['id'], 'GET')
    check(len(obs) == 1 and obs[0]['technique'] ==
          'union_based' and obs[0]['comparison']['forced_columns'] == 4,
          f"SQLI-UNION: order-by oracle + 4-column UNION SELECT marker reflection "
          f"(obs={len(obs)}, tested={tested})")
except Exception as e:
    check(False, f"SQLI-UNION: union detection failed: {e}")

# 25.2 UNION non-regex corroboration: markers reflected, no regex match required
try:
    sc = SQLiScanner("http://x.test/1?id=1", _SQLiSess(_UnionBackend()))
    obs, _ = sc._check_union_based(['id'], 'GET')
    o = obs[0]
    check(o['comparison']['marker1_reflected'] and o['comparison']['marker2_reflected']
          and o['detection_method'] == 'UNION SELECT marker reflection (non-regex)',
          "SQLI-union: non-regex marker reflection evidence structured")
except Exception as e:
    check(False, f"SQLI-union: evidence struct failed: {e}")

# 25.3 error-based fingerprints MySQL and attaches detection method + reliability
try:
    sc = SQLiScanner("http://x.test/1?id=1", _SQLiSess(_ErrorBackend()))
    raw, tested = sc._check_error_based(['id'], 'GET')
    check(len(raw) == 1 and raw[0]['db'] == 'mysql' and raw[0]['reliability'] == 'high'
          and raw[0]['independence'] == 'distinct confirm payload',
          f"SQLI-error: two-distinct-payload confirm + MySQL fingerprint "
          f"(db={raw[0]['db'] if raw else None}, tested={tested})")
except Exception as e:
    check(False, f"SQLI-error: {e}")

# 25.4 boolean-based via two independent true/false pairs (no single regex)
try:
    sc = SQLiScanner("http://x.test/1?id=1", _SQLiSess(_BoolBackend()))
    obs, tested = sc._check_boolean_based(['id'], 'GET')
    check(len(obs) == 1 and obs[0]['technique'] == 'boolean_based'
          and obs[0]['payload'] == "' AND '1'='1'-- -",
          f"SQLI-boolean: true/false + comment-pair differential "
          f"(obs={len(obs)}, tested={tested})")
except Exception as e:
    check(False, f"SQLI-boolean: {e}")

# 25.5 DBMS fingerprinting is provenance-aware (never a single static signal)
try:
    sc = SQLiScanner("http://x.test/1?id=1", _SQLiSess(_ErrorBackend()))
    sc._check_error_based(['id'], 'GET')
    fp = sc._db_fingerprint()
    check(len(fp) == 1 and fp[0]['database'] == 'mysql' and fp[0]['confidence'] > 0
          and 'error_based' in fp[0]['techniques'],
          f"SQLI-fp: provenance-aware DBMS fingerprint (entry={fp})")
except Exception as e:
    check(False, f"SQLI-fp: {e}")

# 25.6 stacked queries only fire after a stacking-capable DBMS is fingerprinted
try:
    sc = _SQLiScanner("http://x.test/1?id=1", _SQLiSess(_UnionBackend()))
    sc._db_candidates = {'mssql'}
    sc._db_provenance['mssql'] = ['time_based']
    sc.get_baseline_time = lambda *a, **k: 0.1
    def _mr(param, payload, method):
        resp = sc._send(param, payload, method, timeout=10)
        return (7.5, resp) if 'WAITFOR' in payload else (0.2, resp)
    sc._time_request = _mr
    obs, tested = sc._check_stacked_queries(['id'], 'GET')
    check(len(obs) == 1 and obs[0]['technique'] == 'stacked_queries'
          and obs[0]['db'] == 'mssql',
          f"SQLI-stacked: only after MSSQL fingerprint, stacked delay confirmed "
          f"(obs={len(obs)}, tested={tested})")
except Exception as e:
    check(False, f"SQLI-stacked: {e}")

# 25.7 emitted evidence carries structured fields (detection method, reproducibility)
try:
    sc = _SQLiScanner("http://x.test/1?id=1", _SQLiSess(_ErrorBackend()))
    f = sc.scan()
    any_ev = next((ev for ev in f.evidence if ev.raw_data.get('technique')), None)
    check(any_ev is not None and any_ev.raw_data.get('reproducibility') == 2
          and any_ev.raw_data.get('detection_method')
          and any_ev.raw_data.get('request') and any_ev.raw_data.get('response'),
          "SQLI-evidence: request/response + detection method + reproducibility attached")
except Exception as e:
    check(False, f"SQLI-evidence: {e}")

# 25.8 dynamic confidence (never static) from independent cross-validation evidence
try:
    from core.pipeline import run_engine_pipeline
    sc = _SQLiScanner("http://x.test/1?id=1", _SQLiSess(_ErrorBackend()))
    f = sc.scan()
    run_engine_pipeline(f)
    check(f.confidence > 0 and f.confidence_factors,
          f"SQLI-conf: dynamic confidence {f.confidence} with factors "
          f"{list(f.confidence_factors or {})}")
except Exception as e:
    check(False, f"SQLI-conf: {e}")

# 25.8 empty-param path still reports a verified no-target observation (regression)
try:
    sc = _SQLiScanner("http://x.test/1", _SQLiSess(_UnionBackend()))
    f = sc.scan()
    check(f.tests_passed == 0 and any("No URL parameters" in ev.description for ev in f.evidence),
          "SQLI: no-parameters path preserves clean PASS/no-target evidence")
except Exception as e:
    check(False, f"SQLI: empty-path regression: {e}")

# ============================================================
# 26. XSS Detection upgrade (SOP Phase 3.2)
# ============================================================
print("\n=== 26. XSS Detection upgrade (Phase 3.2) ===")

from scanners.xss import XSSScanner


class _XElapsed:
    def total_seconds(self): return 0.02


class _XResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.headers = {'Content-Type': 'text/html'}
        self.elapsed = _XElapsed()


class _XSess:
    """Mock session routing method + payload into a backend."""
    def __init__(self, backend):
        self.backend = backend
        self.headers = {'User-Agent': 'test'}
    def get(self, url, timeout=None):
        return self.backend.get(None, 'GET')
    def post(self, url, data=None, timeout=None):
        val = next(iter((data or {}).values()), "")
        return self.backend.get(val, 'POST')


class _HTMLBackend:
    """Server whose response is injectable HTML (script tag context)."""
    def get(self, qval, method):
        return _XResp('<p>hi</p><script>alert(1)</script>') if method == 'GET' \
            else _XResp('<p>hi</p><script>alert(1)</script>')


class _AttrBackend:
    """Server reflecting into a double-quoted attribute (breakout)."""
    def get(self, qval, method):
        return _XResp('<input value=""><img src=x onerror=alert(1)> x="y">')


class _JSBackend:
    """Server: reflected value lands inside an inline <script> feeding a sink."""
    def get(self, qval, method):
        return _XResp(
            '<script>var w = document.getElementById(\'q\');'
            'w.innerHTML = alert(1);</script>'
        )


class _StoredBackend:
    """Server that persists (POST) and reflects the stored marker on read (GET)."""
    def __init__(self):
        self._stored = True
    def get(self, qval, method):
        if method == 'POST':
            self._stored = True
            return _XResp('<p>stored ok</p>')
        body = '<p>hi</p><script>alert(1)</script>' if self._stored else '<p>hi</p>'
        return _XResp(body)


# 26.1 HTML context + sink classification (script tag)
try:
    sc = XSSScanner("http://x.test/?q=1", _XSess(_HTMLBackend()))
    f = sc.scan()
    signals = f.fingerprint.get('xss_signals') or []
    check(any(s.get('context') == 'html' and s.get('sink') == 'script_tag'
              for s in signals),
          f"XSS: script_tag html context confirmed + sink classified (signals={signals})")
except Exception as e:
    check(False, f"XSS-html: {e}")

# 26.2 attribute-quote-breakout reflection (attribute family)
try:
    sc = XSSScanner("http://x.test/?q=1", _XSess(_AttrBackend()))
    f = sc.scan()
    signals = f.fingerprint.get('xss_signals') or []
    check(any(s.get('context') == 'attribute' for s in signals),
          f"XSS: attribute quote-breakout confirmed (signals={signals})")
except Exception as e:
    check(False, f"XSS-attr: {e}")

# 26.3 DOM-source indicative: reflected value feeds a sink inside <script>
try:
    sc = XSSScanner("http://x.test/?q=1", _XSess(_JSBackend()))
    f = sc.scan()
    support = f.fingerprint.get('support_signals') or []
    dom = [ev for ev in f.evidence
           if ev.raw_data.get('context') == 'dom_source']
    check('dom_source' in support,
          f"XSS: DOM-source indicative emitted (support={support})")
except Exception as e:
    check(False, f"XSS-dom: {e}")

# 26.4 stored-persistence probe fires after a confirmed reflected context
try:
    sc = XSSScanner("http://x.test/?q=1", _XSess(_StoredBackend()))
    f = sc.scan()
    stored = [ev for ev in f.evidence if ev.raw_data.get('context') == 'stored_persistence']
    check(bool(stored) and any(ev.raw_data.get('persisted') for ev in stored),
          "XSS: stored-persistence probe confirmed (POST->payload-free GET)")
except Exception as e:
    check(False, f"XSS-stored: {e}")

# 26.5 context-aware payload sets present and broadened
sc5 = XSSScanner("http://x.test/?q=1", _XSess(_HTMLBackend()))
check('javascript' in sc5.context_payloads
      and 'tpl_literal_breakout' in sc5.context_payloads['javascript']
      and any(p == '<svg onload=alert(1)>' for p in sc5.families['html']['payloads']),
      "XSS: context-aware payload sets defined (HTML/attribute/JS + SVG)")

# 26.6 multiple families on a parameter -> dynamic confidence by the engine
try:
    from core.pipeline import run_engine_pipeline
    sc = XSSScanner("http://x.test/?q=1", _XSess(_HTMLBackend()))
    f = sc.scan()
    run_engine_pipeline(f)
    check(f.confidence > 0 and f.confidence_factors,
          f"XSS: dynamic confidence {f.confidence} computed by engine")
except Exception as e:
    check(False, f"XSS-conf: {e}")

# 26.7 no-parameter path preserves a clean no-target observation (regression)
try:
    sc = XSSScanner("http://x.test/", _XSess(_HTMLBackend()))
    f = sc.scan()
    check(f.tests_passed == 0 and any("No URL parameters" in ev.description for ev in f.evidence),
          "XSS: no-parameters path preserves clean no-target evidence")
except Exception as e:
    check(False, f"XSS-empty-path: {e}")

# ============================================================
# 27. SSRF Detection Accuracy (SOP Phase 3.3)
# ============================================================
print("\n=== 27. SSRF Detection Accuracy (Phase 3.3) ===")

from scanners.ssrf import SSRFScanner


class _SSRFRes:
    def __init__(self, text, status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {'Content-Type': 'text/html'}
        self.elapsed = _XElapsed()


class _SsrfInfo:
    headers = {'User-Agent': 'test'}

    def __init__(self, mode):
        self.mode = mode

    def _v(self, url):
        from urllib.parse import urlparse, parse_qs
        return parse_qs(urlparse(url).query).get("url", [""])[0]

    def get(self, url, **kw):
        heads = kw.get("headers") or {}
        v = self._v(url)
        ok = lambda: _SSRFRes("<html><body>ok</body></html>")  # noqa: E731
        if self.mode == 'aws':
            if '169.254.169.254' in v:
                return _SSRFRes("instance-id: i-123\nami-id: ami-0abc\n"
                                "local-ipv4: 10.0.0.9\n")
            return ok()
        if self.mode == 'azure':
            if 'metadata/instance' in v:
                return _SSRFRes('{"compute":{"subscriptionId":"sub-1",'
                                '"resourceGroupId":"rg-2","vmId":"vm-3",'
                                '"azEnvironment":"AzurePublicCloud"},"service":{}}')
            return ok()
        if self.mode == 'gcp':
            if 'metadata.google.internal' in v:
                if heads.get('Metadata-Flavor') == 'Google':
                    return _SSRFRes("instanceId/\nprojectId\noslogin/\ninstance/\n")
                return _SSRFRes("", status=403)
            return ok()
        if self.mode == 'echo':
            return _SSRFRes("fetched url: " + v)
        if self.mode == 'generic':
            if v.startswith('http://127.0.0.') or v in ('http://localhost/',
                                                        'http://0.0.0.0/'):
                return _SSRFRes("<html><head><title>404</title></head>"
                                "<body><h1>404 Not Found</h1></body></html>",
                                status=404)
            return ok()
        if self.mode == 'redirect':
            if v in ('http://127.0.0.1/', 'http://[::1]/',
                     'http://169.254.169.254/latest/meta-data/'):
                r = _SSRFRes("<html></html>", status=302)
                r.headers['Location'] = ('http://[::1]/' if '[::1]' in v
                                         else 'http://10.0.0.99/')
                return r
            return ok()
        if self.mode == 'combo':
            if '169.254.169.254' in v:
                return _SSRFRes("instance-id: i-9\nami-id: ami-0x\n")
            if v in ('http://127.0.0.1:1/', 'http://169.254.169.254:65535/',
                     'http://nonexistent.invalid/'):
                return _SSRFRes("Error: Connection refused")
            if any(h in v for h in ('127.0.0.', 'localhost', '10.1.2.3',
                                    '192.168.1.1', '172.16.0.1')):
                return _SSRFRes("<html>" + "z" * 700 + "</html>")
            return ok()
        return ok()

    def post(self, url, **kw):
        return self.get(url, **kw)


def _ssrf(mode, target="http://127.0.0.1/fetch?url=probe"):
    return SSRFScanner(target, _SsrfInfo(mode))


# 27.1 AWS cloud metadata detected + provider classified
try:
    f = _ssrf('aws').scan()
    sigs = f.fingerprint.get('ssrf_signals') or []
    check(any(s.get('technique') == 'metadata' and s.get('provider') == 'aws'
              for s in sigs),
          "SSRF: AWS metadata detected + provider classified")
    check('aws' in (f.fingerprint.get('cloud_provider') or []),
          "SSRF: fingerprint aggregates cloud provider")
except Exception as e:
    check(False, f"SSRF-aws: {e}")

# 27.2 Azure IMDS metadata detected
try:
    f = _ssrf('azure').scan()
    sigs = f.fingerprint.get('ssrf_signals') or []
    check(any(s.get('technique') == 'metadata' and s.get('provider') == 'azure'
              for s in sigs),
          "SSRF: Azure IMDS metadata detected")
except Exception as e:
    check(False, f"SSRF-azure: {e}")

# 27.3 GCP metadata requires the Metadata-Flavor header (propagated)
try:
    f = _ssrf('gcp').scan()
    sigs = f.fingerprint.get('ssrf_signals') or []
    check(any(s.get('technique') == 'metadata' and s.get('provider') == 'gcp'
              for s in sigs),
          "SSRF: GCP metadata via Metadata-Flavor header")
except Exception as e:
    check(False, f"SSRF-gcp: {e}")

# 27.4 An app echoing the requested URL must NOT satisfy a metadata marker
try:
    f = _ssrf('echo').scan()
    sigs = f.fingerprint.get('ssrf_signals') or []
    check(not any(s.get('technique') == 'metadata' for s in sigs),
          "SSRF: metadata does NOT fire when the server merely echoes the URL")
except Exception as e:
    check(False, f"SSRF-echo: {e}")

# 27.5 A generic 404 error page must NOT be read as internal access
try:
    f = _ssrf('generic').scan()
    sigs = f.fingerprint.get('ssrf_signals') or []
    check(not any(s.get('technique') == 'internal_access' for s in sigs),
          "SSRF: generic 404 page not flagged as internal access")
except Exception as e:
    check(False, f"SSRF-generic: {e}")

# 27.6 Redirect-chain analysis records the internal hop
try:
    f = _ssrf('redirect').scan()
    sigs = f.fingerprint.get('ssrf_signals') or []
    check(any(s.get('technique') == 'redirect_chain' for s in sigs),
          "SSRF: server-side redirect chain to internal host detected")
    chains = [ev.raw_data.get('redirect_chain') for ev in f.evidence
              if ev.raw_data.get('technique') == 'redirect_chain']
    check(any(c for c in chains if len(c) >= 1),
          "SSRF: redirect-chain hops recorded in evidence")
except Exception as e:
    check(False, f"SSRF-redirect: {e}")

# 27.7 Multiple techniques -> cross-validation + provider aggregation
try:
    f = _ssrf('combo').scan()
    sigs = f.fingerprint.get('ssrf_signals') or []
    kinds = {s.get('technique') for s in sigs}
    check({'metadata', 'internal_access', 'error_signature'} <= kinds,
          f"SSRF: multiple confirm techniques present ({sorted(kinds)})")
    check(len(kinds) >= 2, "SSRF: >=2 techniques enable cross-validation")
except Exception as e:
    check(False, f"SSRF-combo: {e}")

# 27.8 No-parameter path preserves a clean no-target observation (regression)
try:
    f = SSRFScanner("http://127.0.0.1/fetch",
                    _SsrfInfo('aws')).scan()
    check(f.tests_passed == 0 and any("No URL parameters" in ev.description
                                      for ev in f.evidence),
          "SSRF: no-parameters path preserves clean no-target evidence")
except Exception as e:
    check(False, f"SSRF-empty-path: {e}")

# ============================================================
# 28. LFI Detection Accuracy (SOP Phase 3.4)
# ============================================================
print("\n=== 28. LFI Detection Accuracy (Phase 3.4) ===")

from scanners.lfi import LFIScanner

POSIX_LFI_BODY = ("root:x:0:0:root:/root:/bin/bash\n"
                  "daemon:x:1:1: daemon\n"
                  "localhost.localdomain\n"
                  "root:*:17885:0:99999:7:::\n"
                  "DOCUMENT_ROOT=/var/www\n")
WIN_LFI_BODY = ("[extensions]\nfor 16-bit app support\n"
                "[fonts]\n[boot loader]\n[drivers32]\n")


class _LfiRes:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.headers = {'Content-Type': 'text/plain'}
        self.elapsed = _XElapsed()


class _LfiBackend:
    """Emulates an include()/file-read endpoint for one mode."""

    def __init__(self, mode):
        self.mode = mode

    def get(self, url):
        from urllib.parse import urlparse, parse_qs
        v = parse_qs(urlparse(url).query).get("file", [""])[0]
        generic = lambda: _LfiRes("<html><body>ok</body></html>")  # noqa: E731
        if self.mode == 'baseline':
            return _LfiRes(POSIX_LFI_BODY)          # unconditional (FP control)
        if self.mode == 'clean':
            return generic()                    # no markers at all
        if v == 'probe_LFI':
            return generic()                    # benign baseline request
        if self.mode == 'win':
            return _LfiRes(WIN_LFI_BODY)
        if self.mode == 'encoded':
            # plain traversal is filtered by a WAF; only encoded variants pass
            if '%' in v or '._' in v or '_2e' in v:
                return _LfiRes(POSIX_LFI_BODY)
            return generic()
        if any(k in v for k in ('passwd', 'shadow', 'hosts', 'environ')):
            return _LfiRes(POSIX_LFI_BODY)
        return generic()

    def post(self, url, data=None):
        return self.get(url)


class _LfiSess:
    headers = {'User-Agent': 'test'}

    def __init__(self, backend):
        self.backend = backend

    def get(self, url, **kw):
        return self.backend.get(url)

    def post(self, url, data=None, **kw):
        return self.backend.post(url, data)


def _lfi(mode, target="http://lfi.test/download?file=page"):
    return LFIScanner(target, _LfiSess(_LfiBackend(mode)))


# 28.1 POSIX traversal reproduces marker across distinct files
try:
    f = _lfi('posix').scan()
    sigs = f.fingerprint.get('lfi_signals') or []
    kinds = {s['technique'] for s in sigs}
    check({'traversal', 'disclosure'} <= kinds,
          f"LFI: POSIX traversal + disclosure techniques fired ({sorted(kinds)})")
    check('/etc/passwd' in (f.fingerprint.get('files_disclosed') or []),
          "LFI: /etc/passwd listed in disclosed files")
except Exception as e:
    check(False, f"LFI-posix: {e}")

# 28.2 Windows markers (win.ini / system.ini / boot.ini) disclosed
try:
    f = _lfi('win').scan()
    files = f.fingerprint.get('files_disclosed') or []
    check(any(x in {'win.ini', 'system.ini', 'boot.ini'} for x in files),
          f"LFI: Windows config files disclosed ({files})")
except Exception as e:
    check(False, f"LFI-win: {e}")

# 28.3 Encoding-bypass detected when plain traversal is filtered
try:
    f = _lfi('encoded').scan()
    sigs = f.fingerprint.get('lfi_signals') or []
    check(any(s['technique'] == 'encoding_bypass' for s in sigs),
          "LFI: encoding bypass fires when plain traversal is filtered")
except Exception as e:
    check(False, f"LFI-encoded: {e}")

# 28.4 Baseline FP-control: unconditional marker must NOT fire (v3.4 accuracy)
try:
    f = _lfi('baseline').scan()
    sigs = f.fingerprint.get('lfi_signals') or []
    check(not sigs,
          "LFI: unconditional marker in baseline does NOT produce a finding")
except Exception as e:
    check(False, f"LFI-baseline-FP: {e}")

# 28.5 Clean page produces no signals
try:
    f = _lfi('clean').scan()
    sigs = f.fingerprint.get('lfi_signals') or []
    check(not sigs, "LFI: clean page produces no signals")
except Exception as e:
    check(False, f"LFI-clean: {e}")

# 28.6 Every emitted observation is baseline-excluded (structured accuracy guard)
try:
    f = _lfi('posix').scan()
    obs = [e for e in f.evidence if e.raw_data.get('technique')]
    check(bool(obs) and all(e.raw_data.get('baseline_excluded') for e in obs),
          "LFI: every observation carries baseline_excluded=True evidence")
except Exception as e:
    check(False, f"LFI-baseline-evidence: {e}")

# 28.7 No-parameter path preserves a clean no-target observation (regression)
try:
    f = _lfi('posix', "http://127.0.0.1/download").scan()
    check(f.tests_passed == 0 and any("No URL parameters" in ev.description
                                      for ev in f.evidence),
          "LFI: no-parameters path preserves clean no-target evidence")
except Exception as e:
    check(False, f"LFI-empty-path: {e}")

# ============================================================
# 29. SSTI Detection Accuracy (SOP Phase 3.5)
# ============================================================
print("\n=== 29. SSTI Detection Accuracy (Phase 3.5) ===")

from scanners.ssti import SSTIScanner


class _SResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.headers = {'Content-Type': 'text/html'}
        self.elapsed = _XElapsed()


class _SstBackend:
    """Emulates a template render endpoint for one mode."""

    def __init__(self, mode):
        self.mode = mode

    def get(self, url):
        from urllib.parse import urlparse, parse_qs
        v = parse_qs(urlparse(url).query).get("name", [""])[0]
        return self._respond(v)

    def post(self, url, data=None):
        v = (data or {}).get('name', '')
        return self._respond(v)

    def _respond(self, v):
        base = lambda: _SResp("<html><body>ok</body></html>")  # noqa: E731
        if self.mode == 'engine':          # generic arithmetic evaluator
            if '7*7' in v:
                return _SResp("<html>result: 49</html>")
            if '8*9' in v:
                return _SResp("<html>result: 72</html>")
            return base()
        if self.mode == 'fm':               # freemarker-only + marker fingerprint
            if v.startswith('${') and '7*7' in v:
                return _SResp("<html>result: 49 — FreeMarker template error</html>")
            if v.startswith('${') and '8*9' in v:
                return _SResp("<html>result: 72 — FreeMarker template error</html>")
            return base()
        if self.mode == 'echo':             # reflects input, never evaluates
            return _SResp(f"<html>you typed: {v}</html>")
        if self.mode == 'baseline':          # static copy prints both products
            return _SResp("<html>49 total, 72 nodes</html>")
        if self.mode == 'clean':
            return base()
        return base()


class _SstSess:
    headers = {'User-Agent': 'test'}

    def __init__(self, backend):
        self.backend = backend

    def get(self, url, **kw):
        return self.backend.get(url)

    def post(self, url, data=None, **kw):
        return self.backend.post(url, data)


def _ssti(mode, target="http://ssti.test/profile?name=x"):
    return SSTIScanner(target, _SstSess(_SstBackend(mode)))


# 29.1 Generic arithmetic evaluator confirms multiple engines
try:
    f = _ssti('engine').scan()
    engines = f.fingerprint.get('engines') or []
    check(len(engines) >= 2,
          f"SSTI: generic evaluator confirms >=2 engines ({engines})")
except Exception as e:
    check(False, f"SSTI-generic: {e}")

# 29.2 Engine fingerprint correlates with the arithmetic claim (freemarker)
try:
    f = _ssti('fm').scan()
    engines = f.fingerprint.get('engines') or []
    ev = f.fingerprint.get('engine_evidence') or []
    check(engines == ['freemarker'],
          f"SSTI: freemarker-only endpoint reports freemarker ({engines})")
    check(any(e['engine'] == 'freemarker' and e.get('fingerprint_consistent')
              for e in ev),
          "SSTI: freemarker fingerprint markers correlate with the claim")
    markers = [m for e in ev for m in (e.get('markers') or [])]
    check(any('FreeMarker template error' in m for m in markers),
          "SSTI: freemarker fingerprint markers captured in evidence")
except Exception as e:
    check(False, f"SSTI-fm: {e}")

# 29.3 Near-POST param supports POST injection
try:
    f = SSTIScanner("http://ssti.test/profile",
                    _SstSess(_SstBackend('engine')), post_data={'name': 'x'}).scan()
    engines = f.fingerprint.get('engines') or []
    check(len(engines) >= 2, "SSTI: POST field confirms engines")
except Exception as e:
    check(False, f"SSTI-post: {e}")

# 29.4 Reflection-only page must NOT evaluate (no magic numbers surfaced)
try:
    f = _ssti('echo').scan()
    engines = f.fingerprint.get('engines') or []
    check(not engines, "SSTI: reflection-only echo page yields no engines")
except Exception as e:
    check(False, f"SSTI-echo-FP: {e}")

# 29.5 Static marker (49/72 in baseline) must NOT fire (per-param baseline guard)
try:
    f = _ssti('baseline').scan()
    engines = f.fingerprint.get('engines') or []
    check(not engines,
          "SSTI: static 49/72 in baseline does not produce a finding")
except Exception as e:
    check(False, f"SSTI-baseline-FP: {e}")

# 29.6 Clean page produces no signals
try:
    f = _ssti('clean').scan()
    engines = f.fingerprint.get('engines') or []
    check(not engines, "SSTI: clean page produces no engines")
except Exception as e:
    check(False, f"SSTI-clean: {e}")

# 29.7 Engine-variant probe + markers present -> fingerprint_consistent evidence
try:
    f = _ssti('fm').scan()
    raw = [e.raw_data for e in f.evidence if e.raw_data.get('technique')
           == 'arithmetic_evaluation']
    check(bool(raw) and all(r.get('fingerprint_consistent') is not None
                            for r in raw),
          "SSTI: observations carry an explicit fingerprint_consistent flag")
except Exception as e:
    check(False, f"SSTI-evidence: {e}")

# 29.8 No-parameter path preserves a clean no-target observation (regression)
try:
    f = SSTIScanner("http://127.0.0.1/profile",
                    _SstSess(_SstBackend('clean'))).scan()
    check(f.tests_passed == 0 and any("No GET parameters" in ev.description
                                      for ev in f.evidence),
          "SSTI: no-parameters path preserves clean no-target evidence")
except Exception as e:
    check(False, f"SSTI-empty-path: {e}")

# ============================================================
# 30. OPEN REDIRECT DETECTION ACCURACY (SOP Phase 3.6)
# ============================================================
print("\n=== 30. Open Redirect Detection Accuracy (Phase 3.6) ===")

from scanners.open_redirect import OpenRedirectScanner


class _ORes:
    def __init__(self, location, status=302):
        self.status_code = status
        self.headers = {'Location': location}
        self.text = "<html></html>"
        self.elapsed = _XElapsed()


class _ORedBackend:
    """Emulates one redirecting endpoint for a mode."""

    def __init__(self, mode):
        self.mode = mode

    def get(self, url):
        from urllib.parse import urlparse, parse_qs
        v = parse_qs(urlparse(url).query).get("url", [""])[0]
        if self.mode == 'external':
            return _ORes('http://evil.com/' + v)
        if self.mode == 'coded':
            return _ORes('http:%2F%2Fevil.com/' + v)
        if self.mode == 'internal':
            return _ORes('http://127.0.0.1/next?u=' + v)
        if self.mode == 'same':
            return _ORes('/login?from=' + v)
        if self.mode == 'clean':
            return _ORes('', status=200)
        return _ORes('', status=200)

    def post(self, url, data=None):
        v = (data or {}).get('url', '')
        if self.mode == 'external':
            return _ORes('http://evil.com/' + v)
        return self.get(url)


class _ORedSess:
    headers = {'User-Agent': 'test'}

    def __init__(self, backend):
        self.backend = backend

    def get(self, url, **kw):
        return self.backend.get(url)

    def post(self, url, data=None, **kw):
        return self.backend.post(url, data)


def _ored(mode, target="http://127.0.0.1/redir?url=x"):
    return OpenRedirectScanner(target, _ORedSess(_ORedBackend(mode)))


# 30.1 External absolute redirect detected + host recorded
try:
    f = _ored('external').scan()
    sigs = f.fingerprint.get('open_redirect_signals') or []
    check(bool(sigs), "OR: external redirect detected")
    check('evil.com' in (f.fingerprint.get('redirect_targets') or []),
          "OR: off-site host evil.com recorded")
    check(len({s['technique'] for s in sigs}) >= 2,
          "OR: >=2 techniques enable cross-validation")
except Exception as e:
    check(False, f"OR-external: {e}")

# 30.2 URL-encoded redirect still detected
try:
    f = _ored('coded').scan()
    sigs = f.fingerprint.get('open_redirect_signals') or []
    check(any(s['technique'] == 'encoded' for s in sigs),
          "OR: encoded redirect detected")
except Exception as e:
    check(False, f"OR-coded: {e}")

# 30.3 Same-host redirect is not an open redirect (FP control)
try:
    f = _ored('internal').scan()
    sigs = f.fingerprint.get('open_redirect_signals') or []
    check(not sigs, "OR: same-host redirect is not an open redirect (FP control)")
except Exception as e:
    check(False, f"OR-internal-FP: {e}")

# 30.4 Same-origin relative Location NOT flagged even with an evil query
try:
    f = _ored('same').scan()
    sigs = f.fingerprint.get('open_redirect_signals') or []
    check(not sigs, "OR: same-origin relative redirect not flagged (FP control)")
except Exception as e:
    check(False, f"OR-same-FP: {e}")

# 30.5 POST field detection
try:
    sc = OpenRedirectScanner("http://127.0.0.1/redir",
                             _ORedSess(_ORedBackend('external')),
                             post_data={'url': 'z'})
    f = sc.scan()
    sigs = f.fingerprint.get('open_redirect_signals') or []
    check(bool(sigs), "OR: POST field detects external redirect")
except Exception as e:
    check(False, f"OR-post: {e}")

# 30.6 Clean (no Location) page produces no signals
try:
    f = _ored('clean').scan()
    sigs = f.fingerprint.get('open_redirect_signals') or []
    check(not sigs, "OR: clean page produces no signals")
except Exception as e:
    check(False, f"OR-clean: {e}")

# 30.7 Observations carry target_host + off_site structured metadata
try:
    f = _ored('external').scan()
    r = [e.raw_data for e in f.evidence if e.raw_data.get('technique')]
    check(bool(r) and all(x.get('target_host') == 'evil.com'
                          and x.get('off_site') is True for x in r),
          "OR: observations carry target_host/off_site metadata")
except Exception as e:
    check(False, f"OR-metadata: {e}")

# 30.8 No-parameter path preserves a clean no-target observation (regression)
try:
    f = OpenRedirectScanner("http://127.0.0.1/redir",
                            _ORedSess(_ORedBackend('clean'))).scan()
    check(f.tests_passed == 0 and any("No URL query parameters" in ev.description
                                      for ev in f.evidence),
          "OR: no-parameters path preserves clean no-target evidence")
except Exception as e:
    check(False, f"OR-empty-path: {e}")

# ============================================================
# 31. CSRF PROTECTION DETECTION ACCURACY (SOP Phase 3.7)
# ============================================================
print("\n=== 31. CSRF Protection Detection Accuracy (Phase 3.7) ===")

from scanners.csrf import CSRFScanner


class _Cookie1:
    def __init__(self, samesite):
        self._rest = {'SameSite': samesite}


class _CRes3:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {'Content-Type': 'text/html'}
        self.elapsed = _XElapsed()


def _csrf_form(field):
    if field is None:
        return ("<html><body>"
                "<form method='post' action='http://127.0.0.1/app'>"
                "<input type='text' name='q'><input type='submit'>"
                "</form></body></html>")
    return ("<html><body>"
            "<form method='post' action='http://127.0.0.1/app'>"
            "<input type='text' name='q'>"
            f"<input type='hidden' name='{field[0]}' value='{field[1]}'>"
            "<input type='submit'></form></body></html>")


class _CsrfBackend:
    """mode:
       gew  : framework token enforced + origin validated (protected)
       k      : token REQUIRED + strictly validated
       missing: accepts any request, no token anywhere
       weak : enforces token but token is short/constant
       samesite: no token, SameSite=Lax, rejects cross-origin
       clean : no form
    """
    def __init__(self, mode):
        self.mode = mode
        self.WRONG = '00000000-1847-0000-0000-wrongtoken'

    def get(self, url, **kw):
        if self.mode == 'clean':
            return _CRes3(200, "<html><body>no forms</body></html>")
        if self.mode == 'django':
            return _CRes3(200, _csrf_form(('csrfmiddlewaretoken', 'qL0x3YzZ9aB4tT8mNv2P6wR')))
        if self.mode == 'weak':
            return _CRes3(200, _csrf_form(('csrf_token', 'WEAKTOK')))
        if self.mode == 'ignored':
            return _CRes3(200, _csrf_form(('csrf_token', 'IGNORED_LONG_TOKEN_VALUE_1234570')))
        return _CRes3(200, _csrf_form(None))

    def post(self, url, data=None, headers=None, **kw):
        data = dict(data or {})
        origin = (headers or {}).get('Origin', '')
        cross = bool(origin and 'evil.com' in origin)
        has_token = '__'  # default per mode
        if self.mode == 'django':
            has_token = data.get('csrfmiddlewaretoken') not in (None, self.WRONG)
            if cross or not has_token:
                return _CRes3(403, "<h1>CSRF verification failed</h1>")
            return _CRes3(200, "ok")
        if self.mode == 'weak':
            has_token = data.get('csrf_token') == 'WEAKTOK'
            if cross or not has_token:
                return _CRes3(403, "invalid token")
            return _CRes3(200, "ok")
        if self.mode == 'ignored':
            return _CRes3(200, "ignored")
        if self.mode == 'samesite':
            if cross:
                return _CRes3(403, "bad origin")
            return _CRes3(200, "protected")
        return _CRes3(200, "accepted")


class _CsrfSess:
    headers = {'User-Agent': 'test'}

    def __init__(self, backend):
        self.backend = backend
        self.cookies = [_Cookie1('Lax')] if backend.mode == 'samesite' else []

    def get(self, url, **kw):
        return self.backend.get(url)

    def post(self, url, data=None, headers=None, **kw):
        return self.backend.post(url, data, headers)


def _csrf(mode):
    return CSRFScanner(
        "http://127.0.0.1/app",
        _CsrfSess(_CsrfBackend(mode)))


# 31.1 Framework token enforced, framework recognized, no issues
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('django'))).scan()
    prot = f.fingerprint.get('csrf_protection') or {}
    check(prot.get('framework') == 'django',
          "CSRF: Django token framework detected")
    check(len(prot.get('token_enforced', [])) >= 1,
          "CSRF: enforced token recorded as positive")
    check(not f.fingerprint.get('csrf_signals'),
          "CSRF: protected Django form yields no issues")
except Exception as e:
    check(False, f"CSRF-django: {e}")

# 31.2 No token + no SameSite -> no_token signal
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('no_token'))).scan()
    sigs = [s['technique'] for s in (f.fingerprint.get('csrf_signals') or [])]
    check('no_token' in sigs, "CSRF: missing token flagged (no SameSite)")
except Exception as e:
    check(False, f"CSRF-no_token: {e}")

# 31.3 Token present but not enforced -> token_not_enforced
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('ignored'))).scan()
    sigs = [s['technique'] for s in (f.fingerprint.get('csrf_signals') or [])]
    check('token_not_enforced' in sigs,
          "CSRF: unenforced token flagged")
except Exception as e:
    check(False, f"CSRF-ignored: {e}")

# 31.4 Enforced but weak/short token -> weak_token
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('weak'))).scan()
    sigs = [s['technique'] for s in (f.fingerprint.get('csrf_signals') or [])]
    check('weak_token' in sigs, "CSRF: short/low-entropy token flagged")
except Exception as e:
    check(False, f"CSRF-weak: {e}")

# 31.5 Cross-origin acceptance detected
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('no_token'))).scan()
    sigs = [s['technique'] for s in (f.fingerprint.get('csrf_signals') or [])]
    check('cross_origin_accepted' in sigs,
          "CSRF: cross-origin acceptance detected")
except Exception as e:
    check(False, f"CSRF-cross: {e}")

# 31.6 SameSite=Lax mitigates a missing token (FP control)
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('samesite'))).scan()
    sigs = [s['technique'] for s in (f.fingerprint.get('csrf_signals') or [])]
    check('no_token' not in sigs and not sigs,
          "CSRF: SameSite=Lax session suppresses the no-token issue (FP guard)")
    check(f.fingerprint.get('csrf_protection', {}).get('same_site', {})
          .get('lax_or_strict') is True,
          "CSRF: SameSite cookie analyzed")
except Exception as e:
    check(False, f"CSRF-samesite: {e}")

# 31.7 Clean page (no forms) -> no signals + clean evidence
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('clean'))).scan()
    check(not f.fingerprint.get('csrf_signals') and
          any("No POST forms" in ev.description for ev in f.evidence),
          "CSRF: clean page yields no signals")
except Exception as e:
    check(False, f"CSRF-clean: {e}")

# 31.8 Issue observations carry structured reproducibility metadata
try:
    f = CSRFScanner("http://127.0.0.1/app", _CsrfSess(_CsrfBackend('no_token'))).scan()
    r = [e.raw_data for e in f.evidence if e.raw_data.get('technique')]
    check(bool(r) and all(x.get('reproducible') is True
                          and x.get('reliability') == 'high'
                          and 'same_site' in x for x in r),
          "CSRF: issue observations carry structured metadata")
except Exception as e:
    check(False, f"CSRF-metadata: {e}")

# ============================================================
# 41. CORS CONFIGURATION DETECTION ACCURACY (SOP Phase 3.8)
# ============================================================
print("\n=== 41. CORS Configuration Detection Accuracy (Phase 3.8) ===")

from scanners.cors import CORSScanner

EVIL = 'https://evil.com'
ATT = 'https://attacker.com'


class _CRes4:
    def __init__(self, headers=None):
        self.status_code = 200
        self.headers = headers or {'Content-Type': 'application/json'}
        self.text = '{}'
        self.elapsed = _XElapsed()


class _CorsBackend:
    def __init__(self, mode):
        self.mode = mode

    def _acao(self, origin, method):
        m = self.mode
        if m == 'wildcard_creds':
            return '*' if origin else '*'
        if m == 'reflected':
            return origin if origin in (EVIL, ATT) else None
        if m == 'null':
            return origin if origin == 'null' else None
        if m == 'reflected_nocred':
            return origin if origin in (EVIL, ATT) else None
        if m == 'post_only':
            return origin if (method == 'POST' and origin in (EVIL, ATT)) else None
        return None

    def _headers(self, origin, method):
        acao = self._acao(origin, method)
        if acao is None:
            return None
        h = {'Access-Control-Allow-Origin': acao}
        if self.mode in ('wildcard_creds',):
            h['Access-Control-Allow-Credentials'] = 'true'
        if self.mode == 'reflected':
            h['Access-Control-Allow-Credentials'] = 'true'
        if acao != '*' and self.mode in ('reflected',):
            h['Vary'] = 'Origin'
        return h

    def get(self, url, headers=None, **kw):
        h = self._headers((headers or {}).get('Origin', ''), 'GET')
        return _CRes4(h or {}) if h else _CRes4()

    def post(self, url, headers=None, **kw):
        h = self._headers((headers or {}).get('Origin', ''), 'POST')
        return _CRes4(h or {}) if h else _CRes4()

    def options(self, url, headers=None, **kw):
        origin = (headers or {}).get('Origin', '')
        if self.mode in ('wildcard_creds', 'reflected'):
            h = {'Access-Control-Allow-Origin': origin or '*',
                 'Access-Control-Allow-Credentials': 'true',
                 'Access-Control-Allow-Methods': 'GET'}
        else:
            acao = self._acao(origin, 'GET')
            h = {'Access-Control-Allow-Origin': acao} if acao else {}
        return _CRes4(h or {})


class _CorsSess:
    headers = {'User-Agent': 'test'}
    cookies = []

    def __init__(self, backend):
        self.backend = backend

    def get(self, url, **kw):
        return self.backend.get(url, headers=kw.get('headers'))

    def post(self, url, **kw):
        return self.backend.post(url, headers=kw.get('headers'))

    def options(self, url, **kw):
        return self.backend.options(url, headers=kw.get('headers'))


def _cors(mode):
    return CORSScanner('http://127.0.0.1/app', _CorsSess(_CorsBackend(mode)))


def _sig_names(f):
    return [s['signal'] for s in (f.fingerprint.get('cors_signals') or [])]


# 41.1 wildcard + credentials is confirmed (most dangerous)
try:
    f = _cors('wildcard_creds').scan()
    check('wildcard_credentials' in _sig_names(f),
          "CORS: wildcard+credentials detected")
    check(f.fingerprint.get('cors_credentials') is True,
          "CORS: credentials flag set")
except Exception as e:
    check(False, f"CORS-wildcard: {e}")

# 41.2 arbitrary origin reflection detected
try:
    f = _cors('reflected').scan()
    check('origin_reflection' in _sig_names(f),
          "CORS: origin reflection detected")
except Exception as e:
    check(False, f"CORS-reflect: {e}")

# 41.3 null origin reflected
try:
    f = _cors('null').scan()
    check('null_origin' in _sig_names(f), "CORS: null-origin reflection detected")
except Exception as e:
    check(False, f"CORS-null: {e}")

# 41.4 credentials-less reflection downgraded to likely (FP reduction)
try:
    f = _cors('reflected_nocred').scan()
    r = next((s for s in (f.fingerprint.get('cors_signals') or [])
              if s['signal'] == 'origin_reflection'), None)
    check(r is not None and r['level'] == 'likely',
          "CORS: credential-less reflection reported as likely, not confirmed")
except Exception as e:
    check(False, f"CORS-nocred: {e}")

# 41.5 cross-method (POST-only) endpoint detected (v3 FN fixed)
try:
    f = _cors('post_only').scan()
    check('origin_reflection' in _sig_names(f) and bool(f.fingerprint.get('cors_signals')),
          "CORS: POST-only reflection detected via cross-method probe")
except Exception as e:
    check(False, f"CORS-postonly: {e}")

# 41.6 multiple-origin aggregation (both attacker origins allowed)
try:
    f = _cors('reflected').scan()
    check('multiple_origin' in _sig_names(f),
          "CORS: multiple independent origins aggregated")
except Exception as e:
    check(False, f"CORS-multi: {e}")

# 41.7 preflight (OPTIONS) confirms the misconfiguration
try:
    f = _cors('wildcard_creds').scan()
    check('preflight_confirmed' in _sig_names(f),
          "CORS: preflight (OPTIONS) analysis confirms the issue")
except Exception as e:
    check(False, f"CORS-preflight: {e}")

# 41.8 restrictive / clean policy yields no signals + positive evidence
try:
    f = _cors('no_acao').scan()
    check(not f.fingerprint.get('cors_signals') and
          f.fingerprint.get('cors_confidence') == 0 and
          any("restrictive" in ev.description for ev in f.evidence),
          "CORS: restrictive policy yields no signals (clean)")
except Exception as e:
    check(False, f"CORS-clean: {e}")

# 41.9 dynamic confidence scales with evidence & is reproducible
try:
    clean = _cors('no_acao').scan().fingerprint.get('cors_confidence', -1)
    weak = _cors('reflected_nocred').scan().fingerprint.get('cors_confidence', -1)
    strong = _cors('wildcard_creds').scan().fingerprint.get('cors_confidence', -1)
    check(clean == 0 and 0 < weak <= strong, 
          "CORS: dynamic confidence scales (0 = none, lowers no-cred <= creds)")
except Exception as e:
    check(False, f"CORS-confidence: {e}")

# 41.10 signals carry structured metadata + dynamic confidence key
try:
    f = _cors('reflected').scan()
    check(f.fingerprint.get('cors_cross_method') is not None
          and 'cors_signals' in f.fingerprint
          and all(s.get('origin') and s.get('level') in ('likely', 'confirmed')
                  for s in f.fingerprint.get('cors_signals')),
          "CORS: fingerprint carries structured per-signal metadata")
except Exception as e:
    check(False, f"CORS-metadata: {e}")

# ============================================================
# 42. COOKIES SECURITY DETECTION ACCURACY (SOP Phase 3.9)
# ============================================================
print("\n=== 42. Cookies Security Detection Accuracy (Phase 3.9) ===")

from scanners.cookies import CookiesScanner

_MISSING_SECURE = '1817231215'   # ~1 year in the future (Unix seconds)


class _Ck:
    """Minimal requests-cookie-shaped object consumed by the analyzer."""

    def __init__(self, name, secure=False, httponly=False, samesite='',
                 domain='127.0.0.1', path='/', expires=None):
        self.name = name
        self.secure = secure
        rest = {}
        if httponly:
            rest['httponly'] = ''
        if samesite:
            rest['samesite'] = samesite
        self._rest = rest
        self.domain = domain
        self.path = path
        self.expires = expires


class _RawHeaders:
    def __init__(self, set_cookies):
        self._set = set_cookies

    def getlist(self, name):
        return self._set if (name or '').lower() == 'set-cookie' else []


class _CkRes:
    """Fake response with both a normalized cookie jar and raw header text."""

    def __init__(self, cookies, set_cookies, status=200):
        self.status_code = status
        self.headers = {'Content-Type': 'text/html'}
        self.text = '<html><body>hi</body></html>'
        self.elapsed = _XElapsed()
        self.cookies = cookies
        self.raw = type('Raw', (), {'headers': _RawHeaders(set_cookies)})()


class _CkSess:
    headers = {'User-Agent': 'test'}
    cookies = []

    def __init__(self, cookies, set_cookies):
        self._c = cookies
        self._s = set_cookies

    def get(self, url, **kw):
        return _CkRes(self._c, self._s)


def _issue_types(f):
    return {i['type'] for i in (f.fingerprint.get('cookie_issues') or [])}


def _ck_scan(fixture):
    return CookiesScanner('http://127.0.0.1/app', _CkSess(*fixture))

# fixture = (jar_cookies, raw_set_cookie_strings)


# 42.1 session cookie missing Secure is detected
try:
    ck = _Ck('sid', httponly=True, samesite='Lax')
    f = _ck_scan(([ck], ['sid=1; HttpOnly; SameSite=Lax; Path=/'])).scan()
    check('missing_secure' in _issue_types(f),
          "Cookies: missing Secure flag on a session cookie detected")
except Exception as e:
    check(False, f"Cookies-secure: {e}")

# 42.2 session cookie missing HttpOnly is detected
try:
    ck = _Ck('sid', secure=True, samesite='Lax')
    f = _ck_scan(([ck], ['sid=1; Secure; SameSite=Lax; Path=/'])).scan()
    check('missing_httponly' in _issue_types(f),
          "Cookies: missing HttpOnly on a session cookie detected")
except Exception as e:
    check(False, f"Cookies-httponly: {e}")

# 42.3 __Host- prefix misuse (missing Secure) is severity-critical
try:
    ck = _Ck('__Host-sid', httponly=True)
    f = _ck_scan(([ck], ['__Host-sid=1; HttpOnly; Path=/'])).scan()
    it = _issue_types(f)
    sev = {i['type']: i['severity'] for i in (f.fingerprint.get('cookie_issues') or [])}
    check('missing_secure' in it and sev.get('missing_secure') == 'critical'
          and 'missing_samesite' in it,
          "Cookies: __Host- prefix misuse is critical + session hardening")
except Exception as e:
    check(False, f"Cookies-prefix: {e}")

# 42.4 persistent session cookie (far-future expiry) is detected
try:
    ck = _Ck('sid', secure=True, httponly=True, samesite='Lax', expires=_MISSING_SECURE)
    f = _ck_scan(([ck], ['sid=1; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000; Path=/'])).scan()
    check('persistent_session' in _issue_types(f),
          "Cookies: far-future-expiry session cookie detected")
except Exception as e:
    check(False, f"Cookies-persistent: {e}")

# 42.5 broad top-level Domain (cookie dropped by jar) recovered via raw header
try:
    f = _ck_scan(([], ['sid=1; Secure; HttpOnly; SameSite=Lax; Domain=com; Path=/'])).scan()
    check('broad_domain' in _issue_types(f),
          "Cookies: broad Domain=com detected from raw Set-Cookie (jar blind spot)")
except Exception as e:
    check(False, f"Cookies-broad: {e}")

# 42.6 __Host- + Domain is a prefix misuse (illegal combination)
try:
    f = _ck_scan(([], ['__Host-sid=1; Secure; HttpOnly; Domain=example.com; Path=/'])).scan()
    check('prefix_misuse' in _issue_types(f),
          "Cookies: __Host- prefix with a Domain attribute flagged")
except Exception as e:
    check(False, f"Cookies-prefix-domain: {e}")

# 42.7 SameSite=None on a session cookie is flagged
try:
    ck = _Ck('sid', secure=True, httponly=True, samesite='None')
    f = _ck_scan(([ck], ['sid=1; Secure; HttpOnly; SameSite=None; Path=/'])).scan()
    check('samesite_none' in _issue_types(f),
          "Cookies: SameSite=None considered an issue")
except Exception as e:
    check(False, f"Cookies-samesitenone: {e}")

# 42.8 fully hardened session cookie is clean (no FP)
try:
    ck = _Ck('sid', secure=True, httponly=True, samesite='Strict')
    f = _ck_scan(([ck], ['sid=1; Secure; HttpOnly; SameSite=Strict; Path=/'])).scan()
    check(not _issue_types(f) and f.fingerprint.get('cookie_confidence') == 0,
          "Cookies: hardened session cookie produces no issues (clean)")
except Exception as e:
    check(False, f"Cookies-clean: {e}")

# 42.9 non-session asset cookie with weak flags is NOT flagged (no FP)
try:
    ck = _Ck('visitor', path='/')
    f = _ck_scan(([ck], ['visitor=987654; Path=/'])).scan()
    check(not _issue_types(f),
          "Cookies: non-session asset cookie not falsely flagged")
except Exception as e:
    check(False, f"Cookies-asset: {e}")

# 42.10 dynamic confidence = 0 vs >0 scales with issues
try:
    clean_f = _ck_scan(([_Ck('sid', secure=True, httponly=True, samesite='Strict')],
                        ['sid=1; Secure; HttpOnly; SameSite=Strict; Path=/'])).scan()
    weak_f = _ck_scan(([_Ck('sid', httponly=True, samesite='Lax')],
                       ['sid=1; HttpOnly; SameSite=Lax; Path=/'])).scan()
    check(clean_f.fingerprint.get('cookie_confidence') == 0
          and weak_f.fingerprint.get('cookie_confidence', 0) > 0,
          "Cookies: dynamic confidence (0 clean, >0 with issues)")
except Exception as e:
    check(False, f"Cookies-confidence: {e}")

# ============================================================
# 43. SENSITIVE FILES DETECTION ACCURACY (SOP Phase 3.10)
# ============================================================
print("\n=== 43. Sensitive Files Detection Accuracy (Phase 3.10) ===")

from scanners.sensitive_files import SensitiveFilesScanner


class _SecRes:
    def __init__(self, status, text):
        self.status_code = status
        self.headers = {'Content-Type': 'text/html' if '<html' in text else 'text/plain'}
        self.text = text
        self.history = []
        self.elapsed = _XElapsed()


class _SecBackend:
    FILES = {
        '/.env': 'DB_PASSWORD=secret123\nAPP_KEY=abc\n',
        '/wp-config.php': "define('DB_PASSWORD', 'p@ss');\n",
        '/.git/config': '[remote "origin"]\n\turl = http://github.com/r\n',
        '/.htpasswd': 'user:$apr1$abcdefghijz.\n',
        '/config.php': '$db_password = "x";\n',
        '/robots.txt': 'User-agent: *\nDisallow: /admin\n',
        '/LICENSE': 'MIT License\nCopyright (c) 2023\n',
        '/package.json': '{"name":"x","version":"1.0.0","dependencies":{}}\n',
    }

    def __init__(self, extra=None, sensitive=True):
        self.extra = extra or {}
        self.sensitive = sensitive

    def get(self, url, **kw):
        from urllib.parse import urlparse as _up
        merged = dict(self.FILES) if self.sensitive else {}
        merged.update(self.extra)
        content = merged.get(_up(url).path)
        if content is None:
            return _SecRes(404, '<html>Not Found</html>')
        return _SecRes(200, content)


class _SecSess:
    headers = {'User-Agent': 'test'}
    cookies = []

    def __init__(self, backend):
        self.backend = backend

    def get(self, url, **kw):
        return self.backend.get(url, **kw)


def _sens(extra=None, sensitive=True):
    return SensitiveFilesScanner('http://127.0.0.1',
                                 _SecSess(_SecBackend(extra, sensitive)))


def _sens_exposed(f):
    return f.fingerprint.get('exposed_files') or []


# 43.1 a genuinely sensitive .env with secrets is detected
try:
    f = _sens().scan()
    check('.env' in _sens_exposed(f),
          "Sensitive files: real .env exposure detected")
except Exception as e:
    check(False, f"Sens-env: {e}")

# 43.2 wp-config.php exposed credentials detected
try:
    f = _sens().scan()
    check('wp-config.php' in _sens_exposed(f),
          "Sensitive files: exposed wp-config.php detected")
except Exception as e:
    check(False, f"Sens-wp: {e}")

# 43.3 .git/config exposed detected
try:
    f = _sens().scan()
    check('.git/config' in _sens_exposed(f),
          "Sensitive files: exposed .git/config detected")
except Exception as e:
    check(False, f"Sens-git: {e}")

# 43.4 public robots.txt is NOT reported (FP guard)
try:
    f = _sens().scan()
    check('robots.txt' not in _sens_exposed(f),
          "Sensitive files: public robots.txt not flagged")
except Exception as e:
    check(False, f"Sens-robots: {e}")

# 43.5 public LICENSE / package.json are NOT reported (no FP)
try:
    f = _sens().scan()
    check('LICENSE' not in _sens_exposed(f)
          and 'package.json' not in _sens_exposed(f),
          "Sensitive files: public LICENSE / package.json not flagged")
except Exception as e:
    check(False, f"Sens-public: {e}")

# 43.6 a 200-but-`Page not found` HTML body is NOT a real exposure (FP guard)
try:
    f = _sens(extra={'/config.json': '<html>404 Not Found</html>',
                     '/.env.local': '<html>page not found</html>'}).scan()
    check('config.json' not in _sens_exposed(f)
          and '.env.local' not in _sens_exposed(f),
          "Sensitive files: 200-with-not-found HTML page not mis-detected")
except Exception as e:
    check(False, f"Sens-notfound: {e}")

# 43.7 no-exposure site yields empty list + confidence 0
try:
    clean = _sens(extra={'/clean.txt': 'hello world\n'}, sensitive=False).scan()
    check(not _sens_exposed(clean)
          and clean.fingerprint.get('sensitive_confidence') == 0,
          "Sensitive files: clean site -> no exposures, confidence 0")
except Exception as e:
    check(False, f"Sens-clean: {e}")

# 43.8 exposures set dynamic confidence > 0
try:
    f = _sens().scan()
    check('.env' in _sens_exposed(f)
          and f.fingerprint.get('sensitive_confidence', 0) > 0,
          "Sensitive files: exposure sets dynamic confidence > 0")
except Exception as e:
    check(False, f"Sens-conf: {e}")

# ============================================================
# 44. HTTP METHODS DETECTION ACCURACY (SOP Phase 3.10)
# ============================================================
print("\n=== 44. HTTP Methods Detection Accuracy (Phase 3.10) ===")

from scanners.http_methods import HTTPMethodsScanner

_DANGEROUS = ('PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'PURGE')


class _MRes:
    def __init__(self, status):
        self.status_code = status
        self.headers = {'Content-Type': 'text/plain'}
        self.text = 'ok'
        self.cookies = []
        self.elapsed = _XElapsed()


class _MBackend:
    def __init__(self, stats):
        self.stats = stats   # method -> status

    def request(self, method, url, **kw):
        return _MRes(self.stats.get(method, 405))

    get = post = put = delete = options = trace = connect = patch = head = \
        purge = request


class _MSess:
    headers = {'User-Agent': 'test'}
    cookies = []

    def __init__(self, backend):
        self.backend = backend

    def request(self, method, url, **kw):
        return self.backend.request(method, url, **kw)


def _httpm(stats):
    return HTTPMethodsScanner('http://127.0.0.1/', _MSess(_MBackend(stats))).scan()


def _dm(f):
    return f.detection_methods or []


# all methods 405 -> no dangerous detected (clean)
try:
    f = _httpm({m: 405 for m in
                ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE',
                 'CONNECT', 'PATCH', 'HEAD', 'PURGE']})
    check(not _dm(f) and f.fingerprint.get('http_methods_confidence') == 0,
          "HTTP methods: all-disabled site yields nothing")
except Exception as e:
    check(False, f"Meth-safe: {e}")

# TRACE enabled (200) is detected
try:
    stats = {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200}
    f = _httpm(stats | {'TRACE': 200})
    check('TRACE' in _dm(f), "HTTP methods: enabled TRACE detected")
    f2 = _httpm(stats | {'TRACE': 405})
    check('TRACE' not in _dm(f2), "HTTP methods: disabled TRACE not flagged")
except Exception as e:
    check(False, f"Meth-trace: {e}")

# PUT / DELETE allowed (200) -> detected
try:
    stats = {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200}
    f = _httpm(stats | {'PUT': 200})
    check('PUT' in _dm(f), "HTTP methods: enabled PUT detected")
except Exception as e:
    check(False, f"Meth-put: {e}")

# 302 redirect on a dangerous method is NOT an allowance (FP fix)
try:
    stats = {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
             'PUT': 302, 'DELETE': 302}
    f = _httpm(stats)
    check(not _dm(f), "HTTP methods: 302 redirect is not counted as allowed (FP fix)")
except Exception as e:
    check(False, f"Meth-redirect: {e}")

# 5xx server error is not an allowance (not a confirmed method)
try:
    stats = {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
             'TRACE': 500, 'PUT': 503}
    f = _httpm(stats)
    check(not _dm(f), "HTTP methods: 5xx response not treated as allowed")
except Exception as e:
    check(False, f"Meth-5xx: {e}")

# 401 auth-gated dangerous method is recognized (likely)
try:
    stats = {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
             'DELETE': 401}
    f = _httpm(stats)
    check('DELETE' in _dm(f) and f.fingerprint.get('http_methods_confidence', 0) > 0,
          "HTTP methods: 401 auth-gated DELETE recognized")
except Exception as e:
    check(False, f"Meth-auth: {e}")

# fingerprint exposes the allowed + dangerous method lists
try:
    stats = {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200, 'PATCH': 200}
    f = _httpm(stats)
    check('PATCH' in (f.fingerprint.get('dangerous_methods') or [])
          and 'GET' in (f.fingerprint.get('allowed_methods') or []),
          "HTTP methods: fingerprint carries allowed/dangerous lists")
except Exception as e:
    check(False, f"Meth-fingerprint: {e}")

# ============================================================
# 45. HEADERS SECURITY DETECTION ACCURACY (SOP Phase 3.10)
# ============================================================
print("\n=== 45. Headers Security Detection Accuracy (Phase 3.10) ===")

from scanners.headers import HeadersScanner
from core.evidence import EvidenceLevel


class _HRes:
    def __init__(self, headers):
        self.status_code = 200
        merged = {'Content-Type': 'text/html'}
        merged.update(headers)
        self.headers = merged
        self.text = '<html><body>hi</body></html>'
        self.cookies = []
        self.elapsed = _XElapsed()


class _HSess:
    headers = {'User-Agent': 'test'}
    cookies = []

    def __init__(self, headers):
        self._h = headers

    def get(self, url, **kw):
        return _HRes(self._h)


def _hdrs(headers):
    return HeadersScanner('http://127.0.0.1/', _HSess(headers)).scan()


_GOOD_HDRS = {
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=()',
    'X-XSS-Protection': '1; mode=block',
    'Cross-Origin-Opener-Policy': 'same-origin',
}


def _neg_issues(f, needle):
    return [e for e in f.evidence
            if getattr(e, 'level', None) in (
                EvidenceLevel.LIKELY, EvidenceLevel.POSSIBLE,
                EvidenceLevel.UNKNOWN)
            and needle in (e.description or '').lower()]


# 45.1 fully-hardened headers produce no CSP/HSTS issue
try:
    f = _hdrs(_GOOD_HDRS)
    check(not _neg_issues(f, 'unsafe-inline')
          and not _neg_issues(f, 'strict-transport'),
          "Headers: hardened server has no CSP/HSTS issue")
except Exception as e:
    check(False, f"Hdr-good: {e}")

# 45.2 weak CSP (unsafe-inline, no nonce) is reported exactly ONCE (dedup)
try:
    csp = "default-src 'self' 'unsafe-inline'; script-src 'self'"
    f = _hdrs({**{k: v for k, v in _GOOD_HDRS.items()
                  if k != 'Content-Security-Policy'},
               'Content-Security-Policy': csp})
    check(len(_neg_issues(f, 'unsafe-inline')) == 1,
          "Headers: unsafe-inline CSP reported exactly once (dedup)")
except Exception as e:
    check(False, f"Hdr-csp: {e}")

# 45.3 weak HSTS (low max-age) is reported exactly ONCE (dedup)
try:
    f = _hdrs({**{k: v for k, v in _GOOD_HDRS.items()
                  if k != 'Strict-Transport-Security'},
               'Strict-Transport-Security': 'max-age=604800'})
    check(len(_neg_issues(f, 'strict-transport')) == 1,
          "Headers: low-HSTS max-age reported exactly once")
except Exception as e:
    check(False, f"Hdr-hsts: {e}")

# 45.4 high-impact missing header lands in the fingerprint
try:
    f = _hdrs({k: v for k, v in _GOOD_HDRS.items()
               if k != 'X-Frame-Options'})
    check('X-Frame-Options' in (f.fingerprint.get('header_missing') or []),
          "Headers: missing X-Frame-Options recorded")
except Exception as e:
    check(False, f"Hdr-missing: {e}")

# 45.5 fingerprint carries present + missing lists and dynamic confidence
try:
    f = _hdrs({k: v for k, v in _GOOD_HDRS.items()
               if k != 'Strict-Transport-Security'})
    check('Content-Security-Policy' in (f.fingerprint.get('header_present') or [])
          and 'Strict-Transport-Security' in (f.fingerprint.get('header_missing') or [])
          and f.fingerprint.get('header_confidence', 0) > 0,
          "Headers: fingerprint present/missing/confidence coherent")
except Exception as e:
    check(False, f"Hdr-fingerprint: {e}")

# 45.6 hardening reduces confidence toward 0 (fewer high-severity issues)
try:
    weak = _hdrs({k: v for k, v in _GOOD_HDRS.items()
                  if k not in ('X-Frame-Options', 'Strict-Transport-Security')})
    good = _hdrs(_GOOD_HDRS)
    check(weak.fingerprint.get('header_confidence', 0)
          >= good.fingerprint.get('header_confidence', 9),
          "Headers: weaker server scores confidence >= hardened server")
except Exception as e:
    check(False, f"Hdr-confidence: {e}")

# ============================================================
# 46. SOURCE CODE LEAKS DETECTION ACCURACY (SOP Phase 3.10)
# ============================================================
print("\n=== 46. Source Code Leaks Detection Accuracy (Phase 3.10) ===")

from scanners.source_leaks import SourceLeaksScanner


class _SLRes:
    def __init__(self, text):
        self.status_code = 200
        self.headers = {'Content-Type': 'text/html'}
        self.text = text
        self.cookies = []
        self.elapsed = _XElapsed()


class _SLSess:
    headers = {'User-Agent': 'test'}
    cookies = []

    def __init__(self, text):
        self._t = text

    def get(self, url, **kw):
        return _SLRes(self._t)


def _sleaks(text):
    return SourceLeaksScanner('http://127.0.0.1/',
                              _SLSess(text)).scan()


def _leak_cats(f):
    return f.fingerprint.get('leak_categories') or []


def _confirmed(f, needle):
    return any(getattr(e, 'level', None) == EvidenceLevel.CONFIRMED
               and needle in (e.description or '').lower()
               for e in f.evidence)


# 46.1 ordinary contact page (email + build comment only) is NOT a leak
try:
    f = _sleaks('Contact: <a href="mailto:info@example.com">info</a>'
                '<!-- built by dev-squad -->')
    check(_leak_cats(f) == [], "Source-leaks: email-only page is clean")
except Exception as e:
    check(False, f"SL-clean: {e}")

# 46.2 stack-trace-only page is NOT a leak
try:
    f = _sleaks('Traceback (most recent call last):\n  File "app.py", line 1')
    check(_leak_cats(f) == [], "Source-leaks: debug-info-only page is clean")
except Exception as e:
    check(False, f"SL-debug: {e}")

# 46.3 API key present -> 'API Keys' reported
try:
    f = _sleaks('const AWS_ACCESS_KEY = "AKIALJ2K3H4EXAMPLE";')
    check('API Keys' in _leak_cats(f),
          "Source-leaks: AWS access key reported")
except Exception as e:
    check(False, f"SL-api: {e}")

# 46.4 DB password present -> 'Configuration Disclosure' reported
try:
    f = _sleaks('DB_PASSWORD = "s3cr3t";')
    check('Configuration Disclosure' in _leak_cats(f),
          "Source-leaks: DB password reported")
except Exception as e:
    check(False, f"SL-db: {e}")

# 46.5 private key reported as CONFIRMED (not merely LIKELY)
try:
    f = _sleaks('-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADAN')
    check(_confirmed(f, 'private key'),
          "Source-leaks: private key is confirmed evidence")
except Exception as e:
    check(False, f"SL-pk: {e}")

# 46.6 .git exposure reported
try:
    f = _sleaks('deploy ref <a href="/.git/config">config</a>')
    check('Configuration Disclosure' in _leak_cats(f),
          "Source-leaks: .git/config exposure reported")
except Exception as e:
    check(False, f"SL-git: {e}")

# 46.7 a confirmed leak plus ambient info dedups to one category each
try:
    f = _sleaks('DB_PASSWORD = "s3cr3t"; contact <a '
                'href="mailto:info@example.com">info</a>')
    cats = _leak_cats(f)
    check(cats.count('Configuration Disclosure') == 1,
          "Source-leaks: categories reported exactly once (dedup)")
except Exception as e:
    check(False, f"SL-dedup: {e}")

# ============================================================
# SUMMARY
# ============================================================

#

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("VALIDATION RESULTS")
print("=" * 60)
print(f"Errors:   {len(errors)}")
print(f"Warnings: {len(warnings_list)}")

if errors:
    print("\nFAILURES:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("\n[OK] All checks passed - no regressions detected.")
    sys.exit(0)
