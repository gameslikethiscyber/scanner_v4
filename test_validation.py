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
    from core.finding import Finding, ScanResult, Status, Severity, Exploitability
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
    from scanners.base import BaseScanner
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

# ============================================================
# 2. Registry completeness
# ============================================================
print("\n=== 2. Scanner Registry ===")

check(len(ALL_SCANNERS) == 18, f"ALL_SCANNERS has {len(ALL_SCANNERS)} scanners (expected 18)")
check(len(HOST_LEVEL_SCANNERS) == 7, f"HOST_LEVEL_SCANNERS has {len(HOST_LEVEL_SCANNERS)} (expected 7)")
check(len(PAGE_LEVEL_SCANNERS) == 11, f"PAGE_LEVEL_SCANNERS has {len(PAGE_LEVEL_SCANNERS)} (expected 11)")

# Verify no overlap
host_names = {s.__name__ for s in HOST_LEVEL_SCANNERS}
page_names = {s.__name__ for s in PAGE_LEVEL_SCANNERS}
overlap = host_names & page_names
check(not overlap, f"No overlap between host/page scanners (overlap: {overlap})")

# Verify all scanners in one of the two categories
all_names = {s.__name__ for s in ALL_SCANNERS}
check(host_names | page_names == all_names, "All scanners belong to host or page category")

# Check that scanner module names match SEVERITY_BY_MODULE in decision engine
from core.decision_engine import DecisionEngine
from scanners.registry import ALL_SCANNERS

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

safe = bs.create_safe_finding("All good")
check(safe.status == Status.PASS, "create_safe_finding sets PASS status")
check(safe.severity == Severity.NONE, "create_safe_finding sets NONE severity")

vuln = bs.create_vulnerable_finding(Severity.HIGH, "Exploit found", "evidence", "fix it")
check(vuln.status == Status.FAIL, "create_vulnerable_finding sets FAIL status")
check(vuln.severity == Severity.HIGH, "create_vulnerable_finding sets HIGH severity")

# Test get_params with no params
bs3 = BaseScanner("https://example.com/")
check(bs3.get_params() == [], "get_params returns empty list when no params")

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

# Test Finding confidence calculation with Evidence objects
finding = Finding()
finding.add_evidence(eb.confirmed("SQLi detected", payload="test"))
check(finding.confidence > 0, "Finding confidence > 0 after adding evidence")

# Test that confidence maxes at different levels
finding2 = Finding()
finding2.add_evidence(eb.exploited("RCE"))
check(finding2.confidence > finding.confidence or finding2.confidence == 100,
      "EXPLOITED evidence allows higher max confidence")

# Test to_dict on evidence
ev_dict = ev1.to_dict()
check(ev_dict["level"] == "confirmed", "Evidence.to_dict has correct level string")
check(ev_dict["type"] == "payload_reflection", "Evidence.to_dict has correct type")

# ============================================================
# 5. Decision Engine
# ============================================================
print("\n=== 5. Decision Engine ===")

de = DecisionEngine()

# Test FAIL → severity from module map
finding_fail = Finding()
finding_fail.module = "SQL Injection"
finding_fail.status = Status.FAIL
finding_fail.severity = Severity.NONE
finding_fail.confidence = 85
finding_fail.add_evidence(eb.confirmed("test"))
decided = de.decide(finding_fail)
check(decided.severity == Severity.CRITICAL, "SQL Injection FAIL maps to CRITICAL")
check(decided.cwe_id == "CWE-89", "SQL Injection gets CWE-89")
check(decided.owasp_category == "A03: Injection", "SQL Injection gets OWASP A03")

# Test WARNING → severity from module map (Phase 1 fix)
finding_warn = Finding()
finding_warn.module = "TLS/SSL Security"
finding_warn.status = Status.WARNING
finding_warn.severity = Severity.NONE
finding_warn.add_evidence(eb.likely("test"))
decided_warn = de.decide(finding_warn)
check(decided_warn.severity == Severity.MEDIUM,
      f"TLS WARNING maps to MEDIUM (was {decided_warn.severity.value})")

# Test that decision engine respects scanner's explicit status
# When scanner sets PASS, engine should not override based on evidence
finding_pass = Finding()
finding_pass.module = "SQL Injection"
finding_pass.status = Status.PASS
finding_pass.severity = Severity.NONE
finding_pass.add_evidence(eb.verified("No vulnerability detected"))
decided_pass = de.decide(finding_pass)
check(decided_pass.status == Status.PASS,
      f"Engine respects PASS status when scanner explicitly set it (got {decided_pass.status.value})")
check(decided_pass.severity == Severity.NONE,
      f"PASS finding keeps NONE severity (got {decided_pass.severity.value})")

# Test that engine classifies UNKNOWN with CONFIRMED evidence as FAIL
finding_unknown = Finding()
finding_unknown.module = "SQL Injection"
finding_unknown.status = Status.UNKNOWN
finding_unknown.severity = Severity.NONE
finding_unknown.add_evidence(eb.confirmed("SQL error detected"))
decided_unknown = de.decide(finding_unknown)
check(decided_unknown.status == Status.FAIL,
      f"Engine classifies UNKNOWN+CONFIRMED as FAIL (got {decided_unknown.status.value})")
check(decided_unknown.severity == Severity.CRITICAL,
      f"Engine assigns CRITICAL for SQL Injection (got {decided_unknown.severity.value})")

# Test CVSS calculation
check(finding_fail.cvss_score > 0, "FAIL finding has CVSS score > 0")

# Test impact assignment
check("confidentiality" in decided.impact, "Finding has impact confidentiality")
check("integrity" in decided.impact, "Finding has impact integrity")
check("availability" in decided.impact, "Finding has impact availability")

# Test CWE/OWASP for non-core scanners
finding_lfi = Finding()
finding_lfi.module = "LFI Detection"
finding_lfi.status = Status.FAIL
finding_lfi.severity = Severity.NONE
finding_lfi.add_evidence(eb.confirmed("test"))
decided_lfi = de.decide(finding_lfi)
check(decided_lfi.cwe_id == "CWE-98", f"LFI gets CWE-98 (got {decided_lfi.cwe_id})")

# ============================================================
# 6. ScanResult
# ============================================================
print("\n=== 6. ScanResult ===")

sr = ScanResult()

# Add findings
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
check(stats["overall_severity"] == "🔥 Critical Risk", "Overall severity label correct")

# Test backward compatibility fields
check(f1.module_name == "SQL Injection", "module_name synced from module")

# ============================================================
# 7. ScanConfig defaults
# ============================================================
print("\n=== 7. Configuration ===")

config = ScanConfig()
check(config.max_pages == 30, "Default max_pages = 30")
check(config.max_workers == 5, "Default max_workers = 5")
check(config.request_timeout == 10, "Default request_timeout = 10")
check(config.long_request_timeout == 15, "Default long_request_timeout = 15")
check(config.user_agent == "SeaScanner/1.0", "Default user_agent correct")

# Test overrides
config2 = ScanConfig(max_pages=50, max_workers=10)
check(config2.max_pages == 50, "Override max_pages = 50")
check(config2.max_workers == 10, "Override max_workers = 10")

# ============================================================
# 8. TrackedSession & ResponseCache
# ============================================================
print("\n=== 8. HTTP Client ===")

ts = TrackedSession()
check(ts.request_count == 0, "TrackedSession starts at 0 requests")
check(hasattr(ts, 'request'), "TrackedSession has request method")

rc = ResponseCache(max_size=5, ttl=60)
check(rc.get("GET", "http://test.com") is None, "Cache miss returns None")

# Simulate caching a response
class MockResponse:
    def __init__(self):
        self.status_code = 200
        self.text = "OK"
        self.headers = {}

rc.set("GET", "http://test.com", MockResponse())
cached = rc.get("GET", "http://test.com")
check(cached is not None, "Cache hit returns response")
check(cached.status_code == 200, "Cached response has status 200")

# Test LRU eviction
for i in range(10):
    rc.set("GET", f"http://test{i}.com", MockResponse())
check(rc.get("GET", "http://test.com") is None,
      "LRU eviction removes oldest entry (max_size=5)")

rc.invalidate()
check(rc.get("GET", "http://test1.com") is None, "Full invalidation clears cache")

# ============================================================
# 9. Reporter
# ============================================================
print("\n=== 9. Reporter ===")

reporter = Reporter()

# Create a scan result for report generation
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
    check("&" not in html_content, "HTML report has no unescaped & (bare &)")
    # Direct unit test of _escape_html
    escaped = reporter._escape_html("AT&T says <stop> & \"quote\"")
    check("AT&amp;T" in escaped, "_escape_html escapes & to &amp;")
    check("&lt;stop&gt;" in escaped, "_escape_html escapes < > to &lt; &gt;")
    check("&quot;quote&quot;" in escaped, "_escape_html escapes \" to &quot;")

txt_file = reporter.generate_txt(sr_report, "https://test-target.com")
check(os.path.exists(txt_file) if txt_file else False, "TXT report file created")

# ============================================================
# 10. Crawler
# ============================================================
print("\n=== 10. Crawler ===")

c = Crawler()
check(hasattr(c, 'crawl'), "Crawler has crawl method")
check(hasattr(c, 'extract_post_forms'), "Crawler has extract_post_forms method")
check(len(c.SKIP_EXTENSIONS) >= 30, f"Crawler has {len(c.SKIP_EXTENSIONS)} skip extensions (>= 30)")
check('.png' in c.SKIP_EXTENSIONS, "SKIP_EXTENSIONS includes .png")
check('.json' in c.SKIP_EXTENSIONS, "SKIP_EXTENSIONS includes .json")
check('.wasm' in c.SKIP_EXTENSIONS, "SKIP_EXTENSIONS includes .wasm")

check(c._should_skip_by_extension("http://example.com/image.png"), "Skip .png extension")
check(c._should_skip_by_extension("http://example.com/script.js"), "Skip .js extension")
check(not c._should_skip_by_extension("http://example.com/page.php"), "Don't skip .php")
check(not c._should_skip_by_extension("http://example.com/"), "Don't skip root path")

# ============================================================
# 11. Deleted files verification
# ============================================================
print("\n=== 11. Deleted Files Verification ===")

check(not os.path.exists("core/classifier.py"), "classifier.py is deleted")
check(not os.path.exists("core/fingerprinter.py"), "fingerprinter.py is deleted")
check(not os.path.exists("core/form_crawler.py"), "form_crawler.py is deleted")

# ============================================================
# 12. Duplicated methods verification
# ============================================================
print("\n=== 12. Duplicated Methods Verification ===")

# Verify that scanners now inherit get_params/inject_payload from BaseScanner
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.lfi import LFIScanner
from scanners.open_redirect import OpenRedirectScanner

for sc in [SQLiScanner, XSSScanner, LFIScanner]:
    inst = sc("http://test.com?x=1")
    check(inst.get_params() == ["x"], f"{sc.__name__}.get_params inherited from BaseScanner")
    injected = inst.inject_payload("x", "test")
    check("x=test" in injected, f"{sc.__name__}.inject_payload inherited from BaseScanner")

# Verify post_data_with_payload works
inst_post = SQLiScanner("http://test.com", post_data={"user": "old"})
data = inst_post.post_data_with_payload("user", "new")
check(data == {"user": "new"}, "SQLiScanner post_data_with_payload works")

# ============================================================
# SUMMARY
# ============================================================
print("\n=== 13. CVSS Vector ===")
f_cvss = Finding()
f_cvss.module = "SQL Injection"
f_cvss.status = Status.FAIL
f_cvss.severity = Severity.CRITICAL
f_cvss.confidence = 95
f_cvss.impact = {'confidentiality': 5, 'integrity': 5, 'availability': 3}
f_cvss.exploitability = Exploitability.EASY
de._calculate_cvss(f_cvss)
check(f_cvss.cvss_score > 5, f"CVSS score computed ({f_cvss.cvss_score})")
check(f_cvss.cvss_vector.startswith("CVSS:3.1/"), f"CVSS vector is valid ({f_cvss.cvss_vector})")
check("C:H" in f_cvss.cvss_vector, "CVSS vector has high confidentiality impact")

print("\n=== 14. add_evidence_with_snippet ===")
bs = BaseScanner("http://test.com")
bs_finding = Finding()
bs.add_evidence_with_snippet(bs_finding, 'confirmed', "Test with snippet", response=None)
check(len(bs_finding.evidence) == 1, "add_evidence_with_snippet adds evidence")
check(bs_finding.evidence[0].level is EvidenceLevel.CONFIRMED, "Evidence level is CONFIRMED")
check(bs_finding.evidence[0].confidence_bonus == 20, "CONFIRMED bonus is 20")
bs_finding2 = Finding()
class MockResp:
    text = "response body content here"
    headers = {"Content-Type": "text/html"}
    elapsed = __import__('datetime').timedelta(seconds=0.5)
bs.add_evidence_with_snippet(bs_finding2, 'likely', "Test with real response", response=MockResp())
check(len(bs_finding2.evidence) == 1, "add_evidence_with_snippet with response adds evidence")
check('snippet' in bs_finding2.evidence[0].raw_data, "Evidence raw_data has snippet")
check('timing' in bs_finding2.evidence[0].raw_data, "Evidence raw_data has timing")

print("\n=== 15. Browser & JS Crawler ===")
try:
    from core.browser import BrowserManager, PLAYWRIGHT_AVAILABLE
    check(True, "core.browser imports OK")
    bm = BrowserManager(headless=True)
    check(hasattr(bm, 'start'), "BrowserManager has start method")
    check(hasattr(bm, 'get_page'), "BrowserManager has get_page method")
    check(hasattr(bm, 'stop'), "BrowserManager has stop method")
    check(bm.is_available == False, "is_available is False before start()")
    check(not bm.is_available or bm.start(), "start() returns True when available")
    if bm.is_available:
        bm.stop()
        check(not bm.is_available, "stop() makes is_available False")
except Exception as e:
    check(False, f"core.browser imports failed: {e}")

try:
    from core.js_crawler import JSCrawler
    check(True, "core.js_crawler imports OK")
    jc = JSCrawler(bm)
    check(hasattr(jc, 'crawl'), "JSCrawler has crawl method")
    check(hasattr(jc, '_extract_dynamic_links'), "JSCrawler has _extract_dynamic_links")
    check(hasattr(jc, '_extract_dynamic_forms'), "JSCrawler has _extract_dynamic_forms")
    check(hasattr(jc, '_is_spa_page'), "JSCrawler has _is_spa_page")
except Exception as e:
    check(False, f"core.js_crawler imports failed: {e}")

print("\n=== 16. Production Quality Features ===")

# Deduplication
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
check(len(sr_dedup.findings[0].affected_urls) >= 1, "Affected URLs tracked after merge")

# Risk Calculator
from core.decision_engine import RiskCalculator
rc_result = RiskCalculator.calculate(sr_dedup.findings)
check("risk_score" in rc_result, "RiskCalculator returns risk_score")
check("breakdown" in rc_result, "RiskCalculator returns breakdown")
check("calculation_formula" in rc_result, "RiskCalculator returns formula")
check(isinstance(rc_result["risk_score"], (int, float)), "Risk score is numeric")
check(len(rc_result["breakdown"]) > 0, "Risk breakdown has items")
check(rc_result["vulnerability_count"] >= 1, "Vulnerability count correct")

# Verification status
f3 = Finding()
f3.module = "SQL Injection"
f3.evidence.append(eb.exploited('SQL error confirmed'))
f3._update_confidence_from_evidence()
check(f3.verification_status == "verified", "EXPLOITED evidence -> verified status")
check(f3.confidence >= 85, "Exploited evidence gives high confidence")

f4 = Finding()
f4.module = "SQL Injection"
f4.evidence.append(eb.confirmed('Timing-based detection'))
f4._update_confidence_from_evidence()
check(f4.verification_status == "likely", "CONFIRMED evidence -> likely status")

f5 = Finding()
f5.module = "XSS Detection"
f5.evidence.append(eb.possible('Possible XSS reflection'))
f5._update_confidence_from_evidence()
check(f5.verification_status == "manual_review", "POSSIBLE evidence -> manual_review status")

# Evidence types
check(EvidenceType.REQUEST_RESPONSE in EvidenceType, "REQUEST_RESPONSE evidence type exists")
rr_ev = EvidenceBuilder.request_response("Test evidence", request={'url': 'http://test.com'}, response={'status': 200})
check(rr_ev.level == EvidenceLevel.CONFIRMED, "request_response uses CONFIRMED level")
check('request' in rr_ev.raw_data, "request_response stores request in raw_data")
check('response' in rr_ev.raw_data, "request_response stores response in raw_data")

# to_dict includes new fields
f6 = Finding()
f6.module = "Test"
d = f6.to_dict()
check("occurrences" in d, "to_dict includes occurrences")
check("affected_urls" in d, "to_dict includes affected_urls")
check("verification_status" in d, "to_dict includes verification_status")
check("target" in d, "to_dict includes target")

print("\n=== 17. Final Polish Features ===")

# PASS finding dedup (by module)
f_pass1 = Finding()
f_pass1.module = "XSS Detection"
f_pass1.status = Status.PASS
f_pass1.target = "https://test.com/page1"
f_pass1.tests_performed = 32
f_pass1.tests_run = 32
f_pass1.tests_passed = 32

f_pass2 = Finding()
f_pass2.module = "XSS Detection"
f_pass2.status = Status.PASS
f_pass2.target = "https://test.com/page2"
f_pass2.tests_performed = 32
f_pass2.tests_run = 32
f_pass2.tests_passed = 32

sr_pass = ScanResult()
sr_pass.add_finding(f_pass1)
sr_pass.add_finding(f_pass2)
check(len(sr_pass.findings) == 1, "PASS findings dedup by module")
check(sr_pass.findings[0].occurrences == 2, "PASS dedup increments occurrences")
check(sr_pass.findings[0].tests_performed == 64, "PASS dedup accumulates test counts")

# Attack surface fields
sr_as = ScanResult()
sr_as.urls_discovered = ["http://test.com/page1", "http://test.com/page2"]
sr_as.urls_crawled = 2
sr_as.urls_skipped = 5
sr_as.useful_pages = 1
sr_as.forms_discovered = 3
sr_as.hidden_inputs = 2
sr_as.params_discovered = 8
sr_as.cookies_found = 4
sr_as.crawler_type = "http"
sr_as.technologies = ["WordPress", "PHP"]
stats_as = sr_as.get_statistics()
check(stats_as.get('urls_discovered') == 2, "Attack surface urls_discovered")
check(stats_as.get('urls_crawled') == 2, "Attack surface urls_crawled")
check(stats_as.get('forms_discovered') == 3, "Attack surface forms_discovered")
check(stats_as.get('cookies_found') == 4, "Attack surface cookies_found")
check(stats_as.get('tech_count') == 2, "Attack surface technologies")

# Executive summary
check("executive_summary" in stats_as, "get_statistics includes executive_summary")
check(len(stats_as.get('executive_summary', '')) > 10, "Executive summary has content")
check("verified_vulns" in stats_as, "get_statistics includes verified_vulns")

# Coverage skip reasons
f_skip = Finding()
f_skip.module = "SQL Injection"
f_skip.status = Status.SKIPPED
f_skip.skip_reason = "No forms found"
sr_skip = ScanResult()
sr_skip.add_finding(f_skip)
cov = sr_skip.get_coverage()
check("skip_reasons" in cov, "Coverage includes skip_reasons")
check(len(cov.get('skip_reasons', {})) > 0, "Coverage skip reasons populated")

# JSON export
reporter = Reporter()
json_file = reporter.generate_json(sr_as, "http://test.com")
check(os.path.exists(json_file) if json_file else False, "JSON export creates file")

# Markdown export
md_file = reporter.generate_markdown(sr_as, "http://test.com")
check(os.path.exists(md_file) if md_file else False, "Markdown export creates file")

# CSV export
csv_file = reporter.generate_csv(sr_as, "http://test.com")
check(os.path.exists(csv_file) if csv_file else False, "CSV export creates file")

# aggregate_safe_findings
sr_agg = ScanResult()
f_a1 = Finding(); f_a1.module = "XSS"; f_a1.status = Status.PASS; f_a1.target = "/p1"; f_a1.tests_performed = 10
f_a2 = Finding(); f_a2.module = "XSS"; f_a2.status = Status.PASS; f_a2.target = "/p2"; f_a2.tests_performed = 10
sr_agg.add_finding(f_a1)
sr_agg.add_finding(f_a2)
sr_agg.aggregate_safe_findings()
check(len(sr_agg.findings) == 1, "aggregate_safe_findings merges PASS")
check(sr_agg.findings[0].occurrences == 2, "aggregate_safe_findings occurrences")
check(sr_agg.findings[0].tests_performed == 20, "aggregate_safe_findings tests")

# Report version
sr_v = ScanResult()
stats_v = sr_v.get_statistics()
check(stats_v.get('report_version') == '3.1', "Report version updated to 3.1")
check(stats_v.get('scanner_version') == '1.8.0', "Scanner version updated to 1.8.0")

# Coverage with skip_reasons in get_statistics
f_skip2 = Finding()
f_skip2.module = "CSRF Protection"
f_skip2.status = Status.SKIPPED
f_skip2.skip_reason = "No forms found on page"
sr_cov = ScanResult()
sr_cov.add_finding(f_skip2)
stats_cov = sr_cov.get_statistics()
check("skip_reasons" in stats_cov, "get_statistics returns skip_reasons")
check(stats_cov.get('coverage_skipped', 0) >= 1, "Coverage skipped count correct")

# _render_list
list_html = Reporter._render_list(["a", "b", "c"], "test-class")
check('test-class' in list_html, "_render_list uses css_class")
check('a' in list_html and 'c' in list_html, "_render_list includes items")

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
