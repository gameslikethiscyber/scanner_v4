import logging
from core.finding import Finding, Status, Severity
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

            found = False
            content = ""
            for path in paths:
                try:
                    resp = self.session.get(path, timeout=10)
                    if resp.status_code == 200:
                        found = True
                        content = resp.text[:300]
                        finding.fingerprint['security_txt_url'] = path
                        break
                except Exception:
                    continue

            finding.tests_performed = len(paths)
            finding.tests_run = finding.tests_performed

            if found:
                has_contact = 'Contact:' in content
                has_expires = 'Expires:' in content
                validation_notes = []
                if has_contact:
                    validation_notes.append('has Contact')
                if has_expires:
                    validation_notes.append('has Expires')
                validation_str = f" ({', '.join(validation_notes)})" if validation_notes else " (missing required fields)"

                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"Security.txt found{validation_str}",
                        payload=None
                    )
                )
                if not has_contact or not has_expires:
                    finding.add_evidence(
                        self._evidence_builder.possible(
                            "Security.txt missing required fields (Contact, Expires)",
                            payload=None
                        )
                    )
                finding.status = Status.PASS
                finding.tests_passed = 1
            else:
                finding.add_evidence(
                    self._evidence_builder.likely("Security.txt not found", payload=None)
                )
                finding.status = Status.WARNING
                finding.tests_passed = 0
                finding.severity = Severity.LOW

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning security.txt: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
