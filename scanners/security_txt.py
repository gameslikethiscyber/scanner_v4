import email.utils
import logging
from datetime import datetime, timezone
from typing import List, Tuple

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.SecurityTxt')


class SecurityTxtScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Security.txt"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            base = self.target.rstrip('/')
            paths = [
                f"{base}/.well-known/security.txt",
                f"{base}/security.txt",
            ]

            found_url = None
            content = ""
            for path in paths:
                try:
                    resp = self.session.get(path, timeout=10)
                    if resp.status_code == 200:
                        found_url = path
                        content = resp.text
                        break
                except Exception:
                    continue

            finding.tests_performed = len(paths)
            finding.tests_run = finding.tests_performed

            if found_url is None:
                finding.add_evidence(
                    self._evidence_builder.likely(
                        "Security.txt not found at /.well-known/security.txt "
                        "or /security.txt (RFC 9116 vulnerability disclosure file)",
                        payload=None,
                    )
                )
                finding.fingerprint['security_txt_url'] = None
                finding.fingerprint['security_txt_state'] = 'missing'
                finding.tests_passed = 0
            else:
                state, issues = self._classify(content)
                finding.fingerprint['security_txt_url'] = found_url
                finding.fingerprint['security_txt_state'] = state
                finding.fingerprint['security_txt_directives'] = issues['directives']

                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"Security.txt is accessible at {found_url}",
                        payload=found_url,
                    )
                )
                if state == 'valid':
                    finding.add_evidence(
                        self._evidence_builder.verified(
                            "Security.txt is valid (Contact and Expires directives "
                            "present, Expires in the future)",
                            payload=None,
                        )
                    )
                else:
                    for problem in issues['problems']:
                        finding.add_evidence(
                            self._evidence_builder.likely(
                                f"Security.txt issue: {problem}",
                                payload=None,
                            )
                        )
                finding.tests_passed = 1

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning security.txt: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding

    def _classify(self, content: str) -> Tuple[str, dict]:
        """Classify a fetched security.txt into valid/accessible/invalid/malformed."""
        directives = {}
        malformed_lines = 0
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if ':' in stripped:
                key, _, value = stripped.partition(':')
                directives[key.strip().lower()] = value.strip()
            else:
                malformed_lines += 1

        if not content.strip():
            state = 'invalid'
            problems = ["file is empty (no directives)"]
        elif not directives and malformed_lines > 0:
            state = 'malformed'
            problems = ["content does not follow the 'Key: value' directive format"]
        else:
            problems = []
            if 'contact' not in directives:
                problems.append("missing required 'Contact' directive")
            if 'expires' not in directives:
                problems.append("missing required 'Expires' directive")
            elif not self._expires_valid(directives['expires']):
                problems.append("Expires directive is not a valid future date")
            if malformed_lines > 0:
                problems.append(
                    f"{malformed_lines} malformed directive line(s) "
                    "not in 'Key: value' format"
                )
            state = 'valid' if not problems else 'accessible'

        return state, {'directives': sorted(directives), 'problems': problems}

    @staticmethod
    def _expires_valid(value: str) -> bool:
        parsed = None
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            try:
                parsed = email.utils.parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed > datetime.now(timezone.utc)
