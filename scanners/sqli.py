"""
SQL Injection Scanner - v3.3 (POST + Boolean)
"""

import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from scanners.base import BaseScanner

class SQLiScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "SQL Injection"
        if self.session is None:
            self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SeaScanner-SQLi/3.0'})
        
        self.db_signatures = {
            'mysql': [r'You have an error in your SQL syntax', r'MySQL server version', r'#\d{4}'],
            'postgresql': [r'ERROR: syntax error', r'PG::SyntaxError'],
            'mssql': [r'Unclosed quotation mark', r'Incorrect syntax near'],
            'oracle': [r'ORA-\d{5}'],
            'sqlite': [r'SQLite.Exception', r'SQL logic error']
        }
        
        self.error_payloads = ["'", '"', "' OR '1'='1", "' AND '1'='1", "' OR 1=1-- -"]
        self.time_payloads = {
            'mysql': ["' AND SLEEP(5)-- -"],
            'postgresql': ["' AND pg_sleep(5)-- -"],
            'mssql': ["' WAITFOR DELAY '00:00:05'-- -"]
        }
        self.boolean_true_payloads = ["' AND '1'='1'-- -", "' OR '1'='1'-- -"]
        self.boolean_false_payloads = ["' AND '1'='2'-- -", "' OR '1'='2'-- -"]
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            params = self.get_params()
            post_params = self.post_data
            has_params = bool(params or post_params)
            
            if not has_params:
                finding.status = Status.SKIPPED
                finding.skip_reason = "No URL parameters or POST data found to test for SQL injection"
                return finding
            
            total_payloads = 0
            confirmations = 0
            evidence_list = []
            
            if params:
                g_error = self.check_error_based(params, method='GET')
                if g_error['found']:
                    evidence_list.append(f"Error-Based (GET) in '{g_error['parameter']}'")
                    confirmations += 1
                g_time = self.check_time_based(params, method='GET')
                if g_time['found']:
                    evidence_list.append(f"Time-Based (GET) in '{g_time['parameter']}'")
                    confirmations += 1
                g_bool = self.check_boolean_based(params, method='GET')
                if g_bool['found']:
                    evidence_list.append(f"Boolean-Based (GET) in '{g_bool['parameter']}'")
                    confirmations += 1
                total_payloads += len(self.error_payloads) * len(params)
                total_payloads += len(self.time_payloads) * len(params)
                total_payloads += len(self.boolean_true_payloads) * len(params)
            
            if post_params:
                post_keys = list(post_params.keys())
                p_error = self.check_error_based(post_keys, method='POST')
                if p_error['found']:
                    evidence_list.append(f"Error-Based (POST) in '{p_error['parameter']}'")
                    confirmations += 1
                p_time = self.check_time_based(post_keys, method='POST')
                if p_time['found']:
                    evidence_list.append(f"Time-Based (POST) in '{p_time['parameter']}'")
                    confirmations += 1
                p_bool = self.check_boolean_based(post_keys, method='POST')
                if p_bool['found']:
                    evidence_list.append(f"Boolean-Based (POST) in '{p_bool['parameter']}'")
                    confirmations += 1
                total_payloads += len(self.error_payloads) * len(post_keys)
                total_payloads += len(self.time_payloads) * len(post_keys)
                total_payloads += len(self.boolean_true_payloads) * len(post_keys)
            
            finding.tests_performed = total_payloads
            finding.tests_run = total_payloads
            
            if confirmations > 0:
                for ev in evidence_list:
                    finding.add_evidence(
                        self._evidence_builder.confirmed(ev, payload=None)
                    )
                finding.confirmations = confirmations
                finding.status = Status.FAIL
                finding.tests_passed = confirmations
                finding.severity = Severity.CRITICAL if confirmations >= 2 else Severity.HIGH
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No SQL injection detected. Tested {total_payloads} payloads.",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = total_payloads
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error during SQL injection scan: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding
    
    def get_params(self) -> list:
        try:
            parsed = urlparse(self.target)
            return list(parse_qs(parsed.query).keys())
        except:
            return []
    
    def check_error_based(self, params, method='GET'):
        for param in params:
            for payload in self.error_payloads:
                try:
                    if method == 'GET':
                        test_url = self.inject_payload(param, payload)
                        resp = self.session.get(test_url, timeout=10)
                    else:
                        data = self.post_data.copy()
                        data[param] = payload
                        resp = self.session.post(self.target, data=data, timeout=10)
                    for db, patterns in self.db_signatures.items():
                        for pattern in patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                return {'found': True, 'parameter': param, 'payload': payload, 'database': db}
                except:
                    continue
        return {'found': False}
    
    def check_time_based(self, params, method='GET'):
        baseline = self.get_baseline_time(method)
        if not baseline:
            return {'found': False}
        
        for param in params:
            for db, payloads in self.time_payloads.items():
                for payload in payloads:
                    try:
                        if method == 'GET':
                            test_url = self.inject_payload(param, payload)
                            start = time.time()
                            self.session.get(test_url, timeout=15)
                        else:
                            data = self.post_data.copy()
                            data[param] = payload
                            start = time.time()
                            self.session.post(self.target, data=data, timeout=15)
                        elapsed = time.time() - start
                        if elapsed > baseline + 3:
                            return {'found': True, 'parameter': param, 'payload': payload, 'database': db, 'elapsed': elapsed}
                    except:
                        continue
        return {'found': False}
    
    def check_boolean_based(self, params, method='GET'):
        for param in params:
            try:
                if method == 'GET':
                    base_resp = self.session.get(self.target, timeout=10)
                else:
                    base_resp = self.session.post(self.target, data=self.post_data, timeout=10)
                base_len = len(base_resp.text)
                base_status = base_resp.status_code
            except:
                continue
            
            for true_payload in self.boolean_true_payloads:
                try:
                    if method == 'GET':
                        true_url = self.inject_payload(param, true_payload)
                        true_resp = self.session.get(true_url, timeout=10)
                    else:
                        true_data = self.post_data.copy()
                        true_data[param] = true_payload
                        true_resp = self.session.post(self.target, data=true_data, timeout=10)
                    true_len = len(true_resp.text)
                    true_status = true_resp.status_code
                    
                    for false_payload in self.boolean_false_payloads:
                        try:
                            if method == 'GET':
                                false_url = self.inject_payload(param, false_payload)
                                false_resp = self.session.get(false_url, timeout=10)
                            else:
                                false_data = self.post_data.copy()
                                false_data[param] = false_payload
                                false_resp = self.session.post(self.target, data=false_data, timeout=10)
                            false_len = len(false_resp.text)
                            false_status = false_resp.status_code
                            
                            diff_true = abs(true_len - base_len)
                            diff_false = abs(false_len - base_len)
                            if diff_true > 50 and diff_false > 50 and abs(diff_true - diff_false) > 30:
                                return {'found': True, 'parameter': param, 'payload': true_payload}
                            if true_status != false_status and (true_status != base_status or false_status != base_status):
                                return {'found': True, 'parameter': param, 'payload': true_payload}
                        except:
                            continue
                except:
                    continue
        return {'found': False}
    
    def inject_payload(self, param, payload):
        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        except:
            return self.target
    
    def get_baseline_time(self, method='GET'):
        times = []
        for _ in range(3):
            try:
                start = time.time()
                if method == 'GET':
                    self.session.get(self.target, timeout=10)
                else:
                    self.session.post(self.target, data=self.post_data or {}, timeout=10)
                times.append(time.time() - start)
            except:
                pass
        return sum(times) / len(times) if times else None