import logging
import re

from core.finding import Finding
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.SourceLeaks')


class SourceLeaksScanner(BaseScanner):

    # Leak category -> evidence level + detection patterns. Confirmed-level
    # categories are hardcoded secrets / config disclosure; likely-level
    # categories are information-disclosure vectors (debug info, emails,
    # comments, source maps).
    CATEGORIES = {
        'API Keys': {
            'level': 'confirmed',
            'patterns': [
                r'\bAPI[_-]?KEY\s*[=:]',
                r'\bSECRET[_-]?KEY\s*[=:]',
                r'\baccess[_-]?key\s*[=:]',
                r'\bsecret[_-]?access[_-]?key\s*[=:]',
                r'\bPRIVATE[_-]?KEY\b',
                r'-----BEGIN.*PRIVATE KEY-----',
                r'\b(?:AWS|AZURE|GCP|AMAZON)_[A-Z0-9_]*KEY\s*[=:]',
                r'\bAKIA[0-9A-Z]{12,}\b',
            ],
        },
        'Configuration Disclosure': {
            'level': 'confirmed',
            'patterns': [
                r'\bDB[_-]?PASSWORD\s*[=:]',
                r"password\s*[=:]\s*['\"][^'\"]+['\"]",
                r'(mysql|postgres|mongodb|redis)://[^\s\'"]+',
                r'\.git/config',
                r'\.git/HEAD',
            ],
        },
        'Debug Information': {
            'level': 'likely',
            'patterns': [
                r'stack trace:',
                r'Traceback \(most recent call last\)',
                r'Warning:.*\.php.*on line',
                r'Fatal error:.*in .*\.php',
            ],
        },
        'Emails': {
            'level': 'likely',
            'patterns': [
                r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
            ],
        },
        'Comments': {
            'level': 'likely',
            'patterns': [
                r'<!--\s*(version|build|author|developer|@version)\s*[:=]',
                r'@(version|author|license)\s+[^\s*]+',
            ],
        },
        'Source Maps': {
            'level': 'likely',
            'patterns': [
                r'sourceMappingURL\s*=',
                r'sourceURL\s*=',
                r'\.map\s*["\']?\s*[,;} ]',
            ],
        },
    }

    # ResponseAnalyzer.extract_sensitive_patterns() category -> leak category.
    _SENSITIVE_TO_CATEGORY = {
        'API Key': 'API Keys',
        'AWS Key': 'API Keys',
        'Private Key': 'API Keys',
        'JWT Token': 'API Keys',
        'Secret': 'API Keys',
        'Token': 'API Keys',
        'Password': 'Configuration Disclosure',
        'Database URL': 'Configuration Disclosure',
    }

    # Ambient / informational categories only reported when a strong leak is
    # actually present, to avoid FALSE POSITIVES on ordinary public pages
    # (a contact email, a build comment, or a debug stash is not a leak).
    AMBIENT_CATEGORIES = ('Emails', 'Comments', 'Debug Information',
                          'Source Maps')

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Source Code Leaks"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10)
            content = resp.text

            strong = []
            ambient = []
            for category, spec in self.CATEGORIES.items():
                for pattern in spec['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        (ambient if self.CATEGORIES[category]['level'] == 'likely'
                         else strong).append((category, pattern))
                        break

            sensitive = ResponseAnalyzer.extract_sensitive_patterns(content)
            for name in sensitive:
                category = self._SENSITIVE_TO_CATEGORY.get(name)
                if category:
                    strong.append((category, f"[{name}]"))

            # Ambient categories fire only alongside a real confirmed leak.
            unique = []
            if strong:
                seen = set()
                for category, pattern in strong + ambient:
                    if category in seen:
                        continue
                    seen.add(category)
                    unique.append((category, pattern))

            total_patterns = sum(len(spec['patterns'])
                                 for spec in self.CATEGORIES.values())
            finding.tests_performed = total_patterns
            finding.tests_run = total_patterns

            if unique:
                for category, pattern in unique:
                    description = (f"Source leak in category '{category}': "
                                   f"matched {pattern}")
                    if self.CATEGORIES[category]['level'] == 'confirmed':
                        self.capture_http_evidence(finding, description, resp,
                                                   payload=pattern)
                    else:
                        finding.add_evidence(
                            self._evidence_builder.likely(description,
                                                          payload=pattern))
                finding.tests_passed = total_patterns - len(unique)
                finding.detection_methods = [c for c, _ in unique[:3]]
                finding.fingerprint['leak_categories'] = [c for c, _ in unique]
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No source code leak patterns detected",
                        payload=None,
                    )
                )
                finding.tests_passed = total_patterns

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning source leaks: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding
