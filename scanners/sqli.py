import re
import time
import requests
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class SQLiScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "SQL Injection"

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
        self.confirm_time_payloads = {
            'mysql': ["' AND SLEEP(3)-- -"],
            'postgresql': ["' AND pg_sleep(3)-- -"],
            'mssql': ["' WAITFOR DELAY '00:00:03'-- -"]
        }
        self.boolean_true_payloads = [
            "' AND '1'='1'-- -",
            "' OR '1'='1'-- -",
            "'/**/OR/**/1=1-- -"
        ]
        self.boolean_false_payloads = [
            "' AND '1'='2'-- -",
            "' OR '1'='2'-- -",
            "'/**/AND/**/1=2-- -"
        ]

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
            confirmed_types = set()

            if params:
                result = self.check_error_based(params, method='GET')
                total_payloads += result['payloads_tested']
                if result['found']:
                    evidence_list.append(f"Error-Based (GET) in '{result['parameter']}'")
                    confirmations += 1
                    confirmed_types.add('error')

                result = self.check_time_based(params, method='GET')
                total_payloads += result['payloads_tested']
                if result['found']:
                    evidence_list.append(f"Time-Based (GET) in '{result['parameter']}'")
                    confirmations += 1
                    confirmed_types.add('time')

                result = self.check_boolean_based(params, method='GET')
                total_payloads += result['payloads_tested']
                if result['found']:
                    evidence_list.append(f"Boolean-Based (GET) in '{result['parameter']}'")
                    confirmations += 1
                    confirmed_types.add('boolean')

            if post_params:
                post_keys = list(post_params.keys())
                result = self.check_error_based(post_keys, method='POST')
                total_payloads += result['payloads_tested']
                if result['found']:
                    evidence_list.append(f"Error-Based (POST) in '{result['parameter']}'")
                    confirmations += 1
                    confirmed_types.add('error')

                result = self.check_time_based(post_keys, method='POST')
                total_payloads += result['payloads_tested']
                if result['found']:
                    evidence_list.append(f"Time-Based (POST) in '{result['parameter']}'")
                    confirmations += 1
                    confirmed_types.add('time')

                result = self.check_boolean_based(post_keys, method='POST')
                total_payloads += result['payloads_tested']
                if result['found']:
                    evidence_list.append(f"Boolean-Based (POST) in '{result['parameter']}'")
                    confirmations += 1
                    confirmed_types.add('boolean')

            finding.tests_performed = total_payloads
            finding.tests_run = total_payloads

            if confirmations > 0:
                for ev in evidence_list:
                    level = 'confirmed'
                    if 'boolean' in ev.lower():
                        level = 'likely'
                    self.add_evidence_with_snippet(
                        finding,
                        level,
                        ev,
                        payload=None
                    )
                finding.confirmations = confirmations
                finding.status = Status.FAIL
                finding.tests_passed = confirmations

                if 'error' in confirmed_types:
                    finding.severity = Severity.CRITICAL
                elif 'time' in confirmed_types:
                    finding.severity = Severity.HIGH
                else:
                    finding.severity = Severity.MEDIUM
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

    def check_error_based(self, params, method='GET'):
        payloads_tested = 0
        for param in params:
            for payload in self.error_payloads:
                payloads_tested += 1
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
                                confirm = self._confirm_error(param, payload, method)
                                if confirm:
                                    return {'found': True, 'parameter': param, 'payload': payload, 'database': db, 'payloads_tested': payloads_tested}
                except requests.RequestException:
                    continue
        return {'found': False, 'payloads_tested': payloads_tested}

    def _confirm_error(self, param, payload, method):
        try:
            confirm_payload = "' OR 1=1-- -" if "'" in payload else '" OR 1=1-- -'
            if method == 'GET':
                confirm_url = self.inject_payload(param, confirm_payload)
                resp = self.session.get(confirm_url, timeout=10)
            else:
                data = self.post_data.copy()
                data[param] = confirm_payload
                resp = self.session.post(self.target, data=data, timeout=10)
            for patterns in self.db_signatures.values():
                for pattern in patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return True
            return False
        except Exception:
            return False

    def check_time_based(self, params, method='GET'):
        baseline = self.get_baseline_time(method)
        if not baseline:
            return {'found': False, 'payloads_tested': 0}
        threshold = max(baseline + 4, 6)

        payloads_tested = 0
        for param in params:
            for db, payloads in self.time_payloads.items():
                for payload in payloads:
                    payloads_tested += 1
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
                        if elapsed > threshold:
                            confirm_elapsed = self._confirm_time(param, db, method)
                            if confirm_elapsed and confirm_elapsed > threshold:
                                return {'found': True, 'parameter': param, 'payload': payload, 'database': db, 'elapsed': elapsed, 'payloads_tested': payloads_tested}
                    except (requests.RequestException, OSError):
                        continue
        return {'found': False, 'payloads_tested': payloads_tested}

    def _confirm_time(self, param, db, method):
        try:
            confirm_payloads = self.confirm_time_payloads.get(db, [])
            if not confirm_payloads:
                return 0
            payload = confirm_payloads[0]
            if method == 'GET':
                test_url = self.inject_payload(param, payload)
                start = time.time()
                self.session.get(test_url, timeout=15)
            else:
                data = self.post_data.copy()
                data[param] = payload
                start = time.time()
                self.session.post(self.target, data=data, timeout=15)
            return time.time() - start
        except Exception:
            return 0

    def check_boolean_based(self, params, method='GET'):
        payloads_tested = 0
        try:
            if method == 'GET':
                base_resp = self.session.get(self.target, timeout=10)
            else:
                base_resp = self.session.post(self.target, data=self.post_data, timeout=10)
            base_len = len(base_resp.text)
            base_status = base_resp.status_code
        except requests.RequestException:
            return {'found': False, 'payloads_tested': payloads_tested}

        for param in params:
                payloads_tested += 1
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
                        payloads_tested += 1
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
                                if self._confirm_boolean(param, method):
                                    return {'found': True, 'parameter': param, 'payload': true_payload, 'payloads_tested': payloads_tested}
                            if true_status != false_status and (true_status != base_status or false_status != base_status):
                                if self._confirm_boolean(param, method):
                                    return {'found': True, 'parameter': param, 'payload': true_payload, 'payloads_tested': payloads_tested}
                        except requests.RequestException:
                            continue
                except requests.RequestException:
                    continue
        return {'found': False, 'payloads_tested': payloads_tested}

    def _confirm_boolean(self, param, method):
        try:
            comment_true = "'/**/OR/**/1=1-- -"
            comment_false = "'/**/AND/**/1=2-- -"
            if method == 'GET':
                true_url = self.inject_payload(param, comment_true)
                false_url = self.inject_payload(param, comment_false)
                true_resp = self.session.get(true_url, timeout=10)
                false_resp = self.session.get(false_url, timeout=10)
            else:
                true_data = self.post_data.copy()
                true_data[param] = comment_true
                false_data = self.post_data.copy()
                false_data[param] = comment_false
                true_resp = self.session.post(self.target, data=true_data, timeout=10)
                false_resp = self.session.post(self.target, data=false_data, timeout=10)
            diff = abs(len(true_resp.text) - len(false_resp.text))
            return diff > 30
        except Exception:
            return False

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
            except requests.RequestException:
                pass
        if not times:
            return None
        times.sort()
        return times[len(times) // 2]
