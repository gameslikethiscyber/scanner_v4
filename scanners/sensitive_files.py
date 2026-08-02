import re
import logging
from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.SensitiveFiles')

# Only genuinely sensitive locations are reported. Public / benign files
# (robots.txt, README.md, LICENSE, package.json, sitemap.xml, Makefile) are
# deliberately excluded to avoid FALSE POSITIVES on normal deployments.
SENSITIVE_FILES = {
    '.env': [r'\bDB_[A-Z_]+\s*=', r'\bSECRET_[A-Z_]+\s*=',
             r'\bAPP_KEY\s*=', r'\bPASSWORD\s*=', r'\bAPI_[A-Z_]+\s*='],
    '.env.local': [r'\bDB_[A-Z_]+\s*=', r'\bSECRET_[A-Z_]+\s*=',
                   r'\bAPP_KEY\s*=', r'\bPASSWORD\s*='],
    'wp-config.php': [r"define\s*\(\s*['\"]DB_", r"define\s*\(\s*['\"]AUTH_KEY"],
    'config.php': [r'\$db_[a-z_]*\s*=\s*["\']', r'\$config\s*\[[^]]*\][^;]*password',
                   r"\$pass\s*=\s*['\"]"],
    'settings.py': [r'\bSECRET_KEY\s*=', r'\bDATABASES\s*=', r'\bDEBUG\s*=\s*True'],
    'config.json': [r'"password"\s*:', r'"secret"\s*:', r'"private_key"\s*:',
                    r'"api[_-]?key"\s*:'],
    '.git/config': [r'\[remote[^\]]*\]', r'\burl\s*=\s*https?://'],
    '.git/HEAD': [r'^\s*ref:\s*refs/heads/'],
    '.git/packed-refs': [r'^#{2,} refs/', r'^[0-9a-f]{40}\s+refs/'],
    '.htpasswd': [r'^\S+:\$apr1\$', r'^\S+:.[0-9a-zA-Z/.]{13}$'],
    'docker-compose.yml': [r'(MYSQL|MARIADB|POSTGRES|MONGO)_\w*_PASSWORD\s*:',
                           r'\bSECRET_KEY\s*:', r'\bDB_PASSWORD\s*:'],
    'backup.sql': [r'(?i)create\s+table', r'(?i)insert\s+into'],
    'db.sql': [r'(?i)create\s+table', r'(?i)insert\s+into'],
    'backup.zip': [r'PK\x03\x04'],
}

# Marker words common to custom "file not found" pages that many servers
# return with an HTTP 200. Content matching these is not a real exposure.
_MISSING_PAGE_MARKERS = (
    'not found', '404', 'page not found', 'no such file', 'does not exist',
    'missing file', 'cannot find',
)

_PUBLIC_FILES = (
    'robots.txt', 'README.md', 'README', 'LICENSE', 'package.json',
    'sitemap.xml', 'Makefile', '.gitignore', 'composer.json',
)


class SensitiveFilesScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Sensitive Files"
        self.files = dict(SENSITIVE_FILES)

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            exposed_files = []
            for file, patterns in self.files.items():
                try:
                    test_url = self.target.rstrip('/') + '/' + file
                    resp = self.session.get(test_url, timeout=5,
                                            allow_redirects=False)

                    # Only a direct, non-redirected 200 can be an exposure.
                    if resp.status_code != 200 or getattr(resp, 'history', None):
                        continue

                    content = resp.text or ''
                    if self._raises_wrapper_page(content):
                        continue

                    detected_patterns = []
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            detected_patterns.append(pattern)

                    if detected_patterns:
                        exposed_files.append({
                            'file': file,
                            'patterns': detected_patterns,
                            'url': test_url,
                        })
                        self.capture_http_evidence(
                            finding,
                            f"Sensitive file exposed: {file} (contains: "
                            f"{', '.join(detected_patterns[:2])})",
                            resp, payload=test_url,
                        )
                except Exception:
                    continue

            finding.tests_performed = len(self.files)
            finding.tests_run = finding.tests_performed

            if exposed_files:
                finding.tests_passed = finding.tests_performed - len(exposed_files)
                finding.fingerprint['exposed_files'] = [ef['file'] for ef in exposed_files]
                finding.fingerprint['sensitive_confidence'] = self._confidence(
                    exposed_files)
                for ef in exposed_files[:3]:
                    finding.add_recommendation(
                        1, f"Remove or restrict access to {ef['file']}",
                        f"File '{ef['file']}' exposes secrets/config that "
                        "attackers can use.",
                        f"Move {ef['file']} outside the web root.",
                        ["OWASP: Sensitive Data Exposure"]
                    )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No sensitive files exposed. Checked {finding.tests_performed} files.",
                        payload=None,
                    )
                )
                finding.tests_passed = finding.tests_performed
                finding.fingerprint['exposed_files'] = []
                finding.fingerprint['sensitive_confidence'] = 0

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning sensitive files: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding

    @staticmethod
    def _raises_wrapper_page(content: str) -> bool:
        """True if content looks like a custom HTTP-not-found HTML page that a
        server returns with status 200 rather than a real file body."""
        lowered = content.lower()
        if '<html' in lowered and any(m in lowered for m in _MISSING_PAGE_MARKERS):
            return True
        return False

    @staticmethod
    def _confidence(exposed: list) -> int:
        """Dynamic confidence from the number and sensitivity of exposures."""
        if not exposed:
            return 0
        score = 40 + min(len(exposed), 4) * 15
        return max(0, min(100, score))