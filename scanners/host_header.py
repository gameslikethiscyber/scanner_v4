import logging

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.HostHeader')

# Multiple independent observations per test host are collected so the engine
# can weigh how many indicators agree (body reflection, redirect Location,
# generated absolute URLs, cache-poisoning indicators). The scanner never
# classifies on a single response alone.


class HostHeaderScanner(BaseScanner):

    TEST_HOSTS = ('evil.com', 'attacker.net', '127.0.0.1', 'malicious-host.com')

    # Prefixes that reveal a host injected into a generated URL.
    URL_PREFIXES = ('http://', 'https://', '//', 'src="', 'href="')

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Host Header Injection"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            # Baseline response for cache-poisoning / response-diff detection.
            try:
                baseline = self.session.get(self.target, timeout=10)
            except Exception:
                baseline = None

            observations = []
            affected_hosts = set()

            for test_host in self.TEST_HOSTS:
                try:
                    resp = self.session.get(
                        self.target, headers={'Host': test_host}, timeout=10
                    )
                except Exception:
                    continue

                body = resp.text
                location = resp.headers.get('Location', '')
                vary = resp.headers.get('Vary', '')

                # Observation 1: Host reflected in the response body.
                if test_host in body:
                    observations.append(self._observation(
                        resp, test_host, 'body_reflection', 'confirmed',
                        f"Host header '{test_host}' is reflected in the response body",
                        {'reliability': 'high'}))
                    affected_hosts.add(test_host)

                # Observation 2: Host used in a redirect Location header.
                if test_host in location:
                    observations.append(self._observation(
                        resp, test_host, 'redirect_location', 'confirmed',
                        f"Host header '{test_host}' is used in the redirect "
                        f"Location: {location}",
                        {'reliability': 'high', 'location': location}))
                    affected_hosts.add(test_host)

                # Observation 3: Host injected into a generated absolute URL.
                for prefix in self.URL_PREFIXES:
                    if f'{prefix}{test_host}' in body:
                        observations.append(self._observation(
                            resp, test_host, 'generated_url', 'confirmed',
                            f"Host header '{test_host}' is injected into a "
                            f"generated URL ({prefix}...)",
                            {'reliability': 'high', 'url_pattern': prefix}))
                        affected_hosts.add(test_host)
                        break

                # Observation 4: response differs under the injected Host while
                # Vary does not list Host/Origin â€” a cache-poisoning indicator.
                # The injected host value must actually appear in the differing
                # response: a bare content change under a foreign Host is normal
                # virtual-host routing (the server serves a different vhost page),
                # not evidence that attacker-controlled host content reaches a
                # shared cache. Only when the host value is embedded in the
                # differing response is there poisonable content to store.
                if baseline is not None and resp.text != baseline.text:
                    if 'Host' not in vary and 'Origin' not in vary:
                        if test_host in body or test_host in location:
                            observations.append(self._observation(
                                resp, test_host, 'cache_poisoning_risk', 'likely',
                                f"Host header '{test_host}' changes the response while "
                                f"Vary does not list Host/Origin â€” possible cache "
                                f"poisoning",
                                {'reliability': 'medium', 'vary': vary}))
                            affected_hosts.add(test_host)

            finding.tests_performed = len(self.TEST_HOSTS)
            finding.tests_run = len(self.TEST_HOSTS)

            if observations:
                # Confirmed reflections first so a FAIL finding's lead evidence
                # is the strongest observation.
                order = {'confirmed': 0, 'likely': 1}
                observations.sort(key=lambda o: order.get(o['level'], 2))
                for obs in observations:
                    self._emit_observation(finding, obs)

                finding.tests_passed = max(0, len(self.TEST_HOSTS) - len(affected_hosts))
                finding.fingerprint['host_header_observations'] = [
                    {'kind': o['kind'], 'host': o['host']} for o in observations
                ]
                finding.fingerprint['tested_hosts'] = list(self.TEST_HOSTS)
                finding.fingerprint['reflected_hosts'] = sorted(
                    o['host'] for o in observations
                    if o['kind'] in ('body_reflection', 'redirect_location',
                                     'generated_url')
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No host header injection detected: none of the test hosts "
                        "are reflected in the response body, redirects, generated "
                        "URLs, or response content",
                        payload=None,
                    )
                )
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning Host Header: {str(e)}", payload=None
                )
            )
            finding.scan_errors += 1

        return finding

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------

    @staticmethod
    def _observation(resp, host, kind, level, desc, extra):
        obs = {
            'resp': resp,
            'host': host,
            'kind': kind,
            'level': level,
            'desc': desc,
        }
        obs.update(extra)
        return obs

    def _emit_observation(self, finding, obs):
        resp = obs['resp']
        host = obs['host']
        request_headers = {'Host': host}

        request_info = {
            'method': 'GET',
            'url': self.target,
            'headers': request_headers,
            'payload': host,
        }
        response_info = {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body_length': len(resp.text),
            'body_snippet': resp.text[:200],
            'elapsed': resp.elapsed.total_seconds() if resp.elapsed else None,
        }

        level = obs['level']
        if level == 'confirmed':
            ev = self._evidence_builder.request_response(
                obs['desc'],
                request=request_info,
                response=response_info,
                payload=host,
                endpoint=self.target,
                method='GET',
            )
        else:
            ev = getattr(self._evidence_builder, level)(
                obs['desc'], payload=host, endpoint=self.target, method='GET'
            )
            ev.raw_data['request'] = request_info
            ev.raw_data['response'] = response_info

        ev.raw_data['matched_observation'] = obs['kind']
        ev.raw_data['tested_host'] = host
        ev.raw_data['reliability'] = obs.get('reliability', 'high')
        ev.raw_data['reproducible'] = True
        if obs.get('location'):
            ev.raw_data['location'] = obs['location']
        if obs.get('url_pattern'):
            ev.raw_data['url_pattern'] = obs['url_pattern']
        if obs.get('vary'):
            ev.raw_data['vary'] = obs['vary']
        finding.add_evidence(ev)
