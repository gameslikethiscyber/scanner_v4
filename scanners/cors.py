import requests
import logging

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.CORS')


class CORSScanner(BaseScanner):

    PROBE_METHODS = ('GET', 'POST')
    CONCRETE_ORIGINS = ('https://evil.com', 'https://attacker.com')

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "CORS Configuration"
        self.test_origins = ['https://evil.com', 'https://attacker.com', 'null', '*']
        self.trusted_origins = []

    def set_trusted_origins(self, origins):
        self.trusted_origins = list(origins)

    def _is_trusted(self, origin):
        return any(trusted in origin for trusted in self.trusted_origins)

    # ---------------------------------------------------------------
    # Probes
    # ---------------------------------------------------------------

    def _probe(self, origin, method):
        try:
            if hasattr(self.session, 'request'):
                resp = self.session.request(method, self.target,
                                            headers={'Origin': origin}, timeout=10)
            elif method == 'POST':
                resp = self.session.post(self.target,
                                         headers={'Origin': origin}, timeout=10)
            else:
                resp = self.session.get(self.target,
                                        headers={'Origin': origin}, timeout=10)
        except requests.RequestException:
            return None
        except Exception:
            return None
        acao = resp.headers.get('Access-Control-Allow-Origin')
        if not acao or self._is_trusted(acao):
            return None
        return {
            'acao': acao,
            'acac': (resp.headers.get('Access-Control-Allow-Credentials') or '').lower(),
            'vary': resp.headers.get('Vary', ''),
            'resp': resp,
        }

    def _classify(self, origin, r):
        acao, acac = r['acao'], r['acac']
        if acao == '*':
            return ('wildcard_credentials' if acac == 'true' else 'wildcard_origin',
                    'confirmed' if acac == 'true' else 'likely')
        if origin == 'null' and acao == 'null':
            return ('null_origin', 'confirmed' if acac == 'true' else 'likely')
        if acao == origin:
            return ('origin_reflection', 'confirmed' if acac == 'true' else 'likely')
        return None

    @staticmethod
    def _level_key(level):
        return {'likely': 1, 'confirmed': 2}.get(level, 1)

    @staticmethod
    def _desc(origin, sig_name):
        if sig_name == 'wildcard_credentials':
            return ("Wildcard origin '*' is allowed together with "
                    "Access-Control-Allow-Credentials: true")
        if sig_name == 'wildcard_origin':
            return "Wildcard origin '*' is allowed in Access-Control-Allow-Origin"
        if sig_name == 'null_origin':
            return ("'null' origin is reflected in Access-Control-Allow-Origin "
                    "(sandboxed iframe or data: URL content can read responses)")
        return f"Arbitrary origin '{origin}' is reflected in Access-Control-Allow-Origin"

    def _probe_preflight(self):
        try:
            resp = self.session.options(
                self.target,
                headers={'Origin': 'https://evil.com',
                         'Access-Control-Request-Method': 'GET'},
                timeout=10,
            )
        except requests.RequestException:
            return None
        acao = resp.headers.get('Access-Control-Allow-Origin')
        if not acao or self._is_trusted(acao):
            return None
        if acao == '*' or acao == 'https://evil.com':
            am = resp.headers.get('Access-Control-Allow-Methods', '')
            return {
                'signal': 'preflight_confirmed',
                'origin': 'https://evil.com',
                'level': 'confirmed' if (
                    resp.headers.get('Access-Control-Allow-Credentials', '').lower()
                    == 'true') else 'likely',
                'acao': acao,
                'acac': resp.headers.get('Access-Control-Allow-Credentials', '').lower(),
                'vary': resp.headers.get('Vary', ''),
                'methods': ['OPTIONS'],
                'desc': ("Preflight (OPTIONS) confirms the CORS misconfiguration: "
                         f"Access-Control-Allow-Origin: {acao}"
                         + (f", Allow-Methods: {am}" if am else "")),
                'resp': resp,
            }
        return None

    @staticmethod
    def _confidence(distinct_origins, credible, multi, methods_max, vary_ok):
        if not distinct_origins:
            return 0
        score = 5
        if distinct_origins >= 1:
            score += 15
        if credible:
            score += 20
        if multi:
            score += 15
        if methods_max >= 2:
            score += 15
        score += 10 if not vary_ok else 5   # missing Vary: Origin = hygiene weakness
        return max(0, min(100, score))

    @staticmethod
    def _missing_vary(vary):
        return bool(vary and 'Origin' not in vary)

    # ---------------------------------------------------------------
    # Main scan
    # ---------------------------------------------------------------

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            observed = {}   # origin -> meta dict

            for origin in self.test_origins:
                meta = None
                for method in self.PROBE_METHODS:
                    r = self._probe(origin, method)
                    if not r:
                        continue
                    cls = self._classify(origin, r)
                    if cls is None:
                        continue
                    name, level = cls
                    if meta is None:
                        meta = {'sig': name, 'level': level, 'acao': r['acao'],
                                'acac': r['acac'], 'vary': r['vary'],
                                'methods': set(), 'resp': r['resp']}
                    elif self._level_key(level) > self._level_key(meta['level']):
                        meta['level'] = level
                    meta['methods'].add(method)
                if meta:
                    observed[origin] = meta

            credible = any(m['acac'] == 'true' for m in observed.values())
            vary_ok = any('Origin' in m['vary'] for m in observed.values())
            distinct_origins = len(observed)
            multi_origins = {o for o in observed if o in self.CONCRETE_ORIGINS}
            multi = len(multi_origins) >= 2

            signals = []
            for origin, meta in observed.items():
                mlist = sorted(meta['methods'])
                signals.append({
                    'signal': meta['sig'],
                    'origin': origin,
                    'level': meta['level'],
                    'acao': meta['acao'],
                    'acac': meta['acac'],
                    'vary': meta['vary'],
                    'methods': mlist,
                    'desc': self._desc(origin, meta['sig']),
                    'resp': meta['resp'],
                })

            if multi:
                first = sorted(multi_origins)[0]
                signals.append({
                    'signal': 'multiple_origin',
                    'origin': first,
                    'level': 'confirmed',
                    'acao': observed[first]['acao'],
                    'acac': 'true' if any(observed[o]['acac'] == 'true'
                                          for o in multi_origins) else '',
                    'vary': '',
                    'methods': ['GET', 'POST'],
                    'desc': ("Multiple independent attacker origins are allowed "
                             "by Access-Control-Allow-Origin ("
                             + ', '.join(sorted(multi_origins)) + ')'),
                    'resp': observed[first]['resp'],
                })

            preflight = self._probe_preflight()
            if preflight:
                signals.append(preflight)

            # Deduplicate by signal name, keeping the highest level.
            best = {}
            order = []
            for s in signals:
                if s['signal'] not in best:
                    best[s['signal']] = s
                    order.append(s['signal'])
                elif (self._level_key(s['level'])
                      > self._level_key(best[s['signal']]['level'])):
                    best[s['signal']] = s
            unique = [best[k] for k in order]

            methods_wide = max((len(s.get('methods') or []) for s in unique), default=0)
            conf = self._confidence(distinct_origins, credible, multi,
                                    methods_wide, vary_ok)

            finding.tests_performed = (len(self.test_origins)
                                       * len(self.PROBE_METHODS)) + 1
            finding.tests_run = finding.tests_performed

            if unique:
                for s in unique:
                    self._emit_signal(finding, s)
                finding.tests_passed = max(0, finding.tests_performed - len(unique))
                finding.fingerprint['cors_signals'] = [
                    {'signal': s['signal'], 'origin': s['origin'],
                     'level': s['level'], 'acao': s['acao'], 'acac': s['acac'],
                     'vary': s.get('vary'), 'methods': s.get('methods'),
                     'vary_missing_origin': self._missing_vary(s.get('vary'))}
                    for s in unique
                ]
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "CORS policy is restrictive: no tested origin is allowed "
                        "by Access-Control-Allow-Origin",
                        payload=None,
                    )
                )
                finding.tests_passed = finding.tests_performed
                finding.fingerprint['cors_signals'] = []

            finding.fingerprint['cors_confidence'] = conf
            finding.fingerprint['cors_cross_method'] = methods_wide
            finding.fingerprint['cors_multiple_origin'] = multi
            finding.fingerprint['cors_credentials'] = credible
            finding.fingerprint['cors_vary'] = vary_ok

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning CORS: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding

    # ---------------------------------------------------------------
    # Evidence emission
    # ---------------------------------------------------------------

    def _emit_signal(self, finding, sig):
        resp = sig['resp']
        origin = sig['origin']
        method = sig['methods'][0] if sig.get('methods') else 'GET'
        level = sig['level']

        request_info = {'method': method, 'url': self.target,
                        'headers': {'Origin': origin}, 'payload': origin}
        response_info = {
            'status_code': resp.status_code if resp else None,
            'headers': dict(resp.headers) if resp else {},
            'body_length': len(resp.text) if resp else 0,
            'body_snippet': (resp.text[:200] if resp else ''),
            'elapsed': resp.elapsed.total_seconds() if resp and resp.elapsed else None,
        }

        if level == 'confirmed':
            ev = self._evidence_builder.request_response(
                sig.get('desc', sig['signal']), request=request_info,
                response=response_info, payload=origin,
                endpoint=self.target, method=method)
        else:
            ev = getattr(self._evidence_builder, level)(
                sig.get('desc', sig['signal']), payload=origin,
                endpoint=self.target, method=method)
            ev.raw_data['request'] = request_info
            ev.raw_data['response'] = response_info

        ev.raw_data.update({
            'matched_signal': sig['signal'],
            'origin': origin,
            'acao': sig.get('acao'),
            'acac': sig.get('acac'),
            'vary': sig.get('vary'),
            'methods': sig.get('methods'),
            'vary_missing_origin': self._missing_vary(sig.get('vary')),
            'reliability': 'high',
            'reproducible': True,
        })
        finding.add_evidence(ev)