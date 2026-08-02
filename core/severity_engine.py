"""
Severity Engine v3.0 — single owner of per-finding severity, exploitability,
impact and CVSS assignment.

Base severity comes from the standards metadata provider (DecisionEngine.STANDARDS).
The engine never reads another engine's computation; it consumes the finding plus
optional verification / correlation inputs and returns a SeverityResult.

Per-finding severity is never lowered below the module base for a FAIL finding; the
"unverified critical is reported as high" policy is applied scan-wide by the
Assessment Engine, matching v2 get_overall_severity() behaviour. This engine exposes
an opt-in ``verification_status`` downgrade for v3 consumers that want per-finding
reporting severity.

See docs/ENGINE_ARCHITECTURE_V3.md §5.4 and §6.6.
"""

import logging
from typing import Dict, Optional, Tuple

from core.finding import Finding, Severity, Status, Exploitability
from core.assessment import SeverityResult
from core.decision_engine import DecisionEngine

logger = logging.getLogger('SeaScanner.SeverityEngine')


class SeverityEngine:
    """Computes severity/exploitability/impact/CVSS for one finding."""

    # Metadata provider data (single source of truth: DecisionEngine.STANDARDS).
    SEVERITY_BY_MODULE = DecisionEngine.SEVERITY_BY_MODULE
    RECOMMENDATIONS = DecisionEngine.RECOMMENDATIONS
    CVSS_DESCRIPTIONS = DecisionEngine.CVSS_DESCRIPTIONS

    # CVSS base score per severity (v2 parity).
    SEVERITY_SCORE = {
        Severity.NONE: 0, Severity.INFO: 1.0, Severity.LOW: 3.0,
        Severity.MEDIUM: 5.0, Severity.HIGH: 7.0, Severity.CRITICAL: 9.0,
    }

    # Impact multiplier per severity (v2 parity).
    IMPACT_MULTIPLIER = {
        Severity.CRITICAL: 1.0, Severity.HIGH: 0.8, Severity.MEDIUM: 0.6,
        Severity.LOW: 0.4, Severity.INFO: 0.2, Severity.NONE: 0.2,
    }

    EXPLOITABILITY_BY_SEVERITY = {
        Severity.CRITICAL: Exploitability.EASY,
        Severity.HIGH: Exploitability.MEDIUM,
        Severity.MEDIUM: Exploitability.HARD,
        Severity.LOW: Exploitability.THEORETICAL,
    }

    _SEVERITY_ORDER = (Severity.NONE, Severity.INFO, Severity.LOW,
                       Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

    # Verification statuses considered "verified enough" to keep a critical.
    VERIFIED_STATUSES = ('confirmed', 'verified', 'likely')

    def assess(self, finding: Finding,
               verification_status: Optional[str] = None,
               correlation_escalation: Optional[str] = None) -> SeverityResult:
        """Return the SeverityResult for a finding.

        The module map (standards provider) is the single source of truth for
        severity; scanner-preset severity is never honored (A8.9 freeze).
        """
        status = finding.status

        if status in (Status.PASS, Status.SAFE):
            severity = Severity.NONE
        elif status in (Status.FAIL, Status.VULNERABLE, Status.WARNING):
            severity = self.SEVERITY_BY_MODULE.get(finding.module, Severity.MEDIUM)
        else:
            severity = Severity.INFO

        # Correlation escalation: raise severity only.
        if correlation_escalation:
            escalated = self._severity(correlation_escalation)
            if escalated in self._SEVERITY_ORDER:
                if self._SEVERITY_ORDER.index(escalated) > self._SEVERITY_ORDER.index(severity):
                    severity = escalated

        # Opt-in v3 policy: unverified critical is reported as high.
        if verification_status and severity is Severity.CRITICAL:
            if verification_status not in self.VERIFIED_STATUSES:
                severity = Severity.HIGH

        exploitability = self.EXPLOITABILITY_BY_SEVERITY.get(severity, Exploitability.UNKNOWN)
        impact = self._assign_impact(finding, severity)
        cvss_score, cvss_vector, cvss_explanation = self._calculate_cvss(finding, severity, impact)

        entry = DecisionEngine.STANDARDS.get(finding.module, {})
        return SeverityResult(
            severity=severity.value,
            exploitability=exploitability.value,
            impact=impact,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_explanation=cvss_explanation,
            cwe_id=entry.get('cwe', ''),
            owasp_category=entry.get('owasp', ''),
            capec_id=entry.get('capec', ''),
            mitre_id=entry.get('mitre', ''),
            asvs_reference=entry.get('asvs', ''),
        )

    def _assign_impact(self, finding: Finding, severity: Severity) -> Dict[str, int]:
        entry = DecisionEngine.STANDARDS.get(finding.module, {})
        impact = entry.get('impact', {'confidentiality': 1, 'integrity': 1, 'availability': 1})
        multiplier = self.IMPACT_MULTIPLIER.get(severity, 0.2)
        return {
            'confidentiality': max(1, int(impact['confidentiality'] * multiplier)),
            'integrity': max(1, int(impact['integrity'] * multiplier)),
            'availability': max(1, int(impact['availability'] * multiplier)),
        }

    def _calculate_cvss(self, finding: Finding, severity: Severity,
                        impact: Dict[str, int]) -> Tuple[float, str, str]:
        base = self.SEVERITY_SCORE.get(severity, 0)
        confidence_boost = (finding.confidence / 100.0) * 0.5
        cvss_score = round(min(10, base + confidence_boost), 1)

        av, ac, pr, ui, scope = 'N', 'L', 'N', 'N', 'U'
        c = i_val = a = 'N'
        if impact.get('confidentiality', 0) >= 4:
            c = 'H'
        elif impact.get('confidentiality', 0) >= 2:
            c = 'L'
        if impact.get('integrity', 0) >= 4:
            i_val = 'H'
        elif impact.get('integrity', 0) >= 2:
            i_val = 'L'
        if impact.get('availability', 0) >= 4:
            a = 'H'
        elif impact.get('availability', 0) >= 2:
            a = 'L'

        if severity is Severity.CRITICAL:
            av, ac, pr, ui = 'N', 'L', 'N', 'N'
        elif severity is Severity.HIGH:
            av, ac, pr, ui = 'N', 'L', 'L', 'N'
        elif severity is Severity.MEDIUM:
            av, ac, pr, ui = 'N', 'L', 'L', 'R'
        elif severity is Severity.LOW:
            av, ac, pr, ui = 'A', 'H', 'H', 'R'

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i_val}/A:{a}"

        explanations = []
        for part in vector.replace('CVSS:3.1/', '').split('/'):
            desc = self.CVSS_DESCRIPTIONS.get(part.strip())
            if desc:
                explanations.append(desc)

        total_impact = impact['confidentiality'] + impact['integrity'] + impact['availability']
        explanation = (
            f"Score {cvss_score} out of 10. "
            f"Computed from severity={severity.value} (base {base}) "
            f"adjusted by confidence {finding.confidence}% (boost +{confidence_boost:.1f}). "
            f"Impact profile: CIA={total_impact}/15. "
            + ' | '.join(explanations)
        )
        return cvss_score, vector, explanation

    @staticmethod
    def _severity(value) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return Severity(value)
        except Exception:
            return Severity.NONE
