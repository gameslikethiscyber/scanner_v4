import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from core.finding import Finding, Severity

logger = logging.getLogger('SeaScanner.Correlation')

@dataclass
class CorrelationRule:
    name: str
    description: str
    required_modules: List[str]
    required_severities: Optional[List[str]] = None
    confidence_boost: int = 15
    severity_escalation: Optional[str] = None
    risk_multiplier: float = 1.0

@dataclass
class CorrelationResult:
    rule_name: str
    description: str
    affected_findings: List[Finding]
    confidence_boost: int
    severity_escalation: Optional[str]
    risk_multiplier: float

class CorrelationEngine:
    RULES = [
        CorrelationRule(
            name="xss_csp_bypass",
            description="XSS vulnerability with weak or missing CSP increases exploitation likelihood",
            required_modules=['XSS Detection', 'Headers Security'],
            required_severities=['high', 'medium'],
            confidence_boost=20,
            severity_escalation="critical",
            risk_multiplier=1.3,
        ),
        CorrelationRule(
            name="xss_reflected_injection",
            description="Reflected input found alongside injection point increases XSS confidence",
            required_modules=['XSS Detection', 'SQL Injection'],
            confidence_boost=10,
            risk_multiplier=1.2,
        ),
        CorrelationRule(
            name="cors_xss",
            description="CORS misconfiguration combined with XSS allows cross-origin data theft",
            required_modules=['CORS Configuration', 'XSS Detection'],
            confidence_boost=15,
            severity_escalation="critical",
            risk_multiplier=1.4,
        ),
        CorrelationRule(
            name="cookie_hsts",
            description="Insecure cookies with missing HSTS increase session hijacking risk",
            required_modules=['Cookies Security', 'TLS/SSL Security'],
            confidence_boost=10,
            severity_escalation="high",
            risk_multiplier=1.2,
        ),
        CorrelationRule(
            name="info_disclosure",
            description="Multiple information disclosure vectors increase data breach risk",
            required_modules=['Sensitive Files', 'Source Code Leaks'],
            confidence_boost=10,
            severity_escalation="high",
            risk_multiplier=1.2,
        ),
        CorrelationRule(
            name="ssrf_lfi",
            description="SSRF and LFI together enable server-side file read and internal network scanning",
            required_modules=['SSRF Detection', 'LFI Detection'],
            confidence_boost=20,
            severity_escalation="critical",
            risk_multiplier=1.5,
        ),
        CorrelationRule(
            name="host_header_cache",
            description="Host header injection with cache poisoning risk increases attack surface",
            required_modules=['Host Header Injection', 'Headers Security'],
            confidence_boost=10,
            risk_multiplier=1.2,
        ),
        CorrelationRule(
            name="open_redirect_xss",
            description="Open redirect weakens XSS SOP protections for credential theft",
            required_modules=['Open Redirect', 'XSS Detection'],
            confidence_boost=10,
            severity_escalation="high",
            risk_multiplier=1.2,
        ),
        CorrelationRule(
            name="csrf_xss",
            description="CSRF vulnerable forms combined with XSS enable automated attacks",
            required_modules=['CSRF Protection', 'XSS Detection'],
            confidence_boost=15,
            risk_multiplier=1.3,
        ),
        CorrelationRule(
            name="method_sensitive",
            description="Dangerous HTTP methods exposed alongside sensitive information",
            required_modules=['HTTP Methods', 'Sensitive Files'],
            confidence_boost=5,
            risk_multiplier=1.1,
        ),
    ]

    def __init__(self):
        self._matched_rules: List[CorrelationResult] = []

    def correlate(self, findings: List[Finding]) -> List[CorrelationResult]:
        self._matched_rules = []
        vuln_findings = [f for f in findings if f.is_vulnerable()]
        warning_findings = [f for f in findings if f.status.name == "WARNING"]
        all_relevant = vuln_findings + warning_findings

        module_map: Dict[str, List[Finding]] = {}
        for f in all_relevant:
            if f.module not in module_map:
                module_map[f.module] = []
            module_map[f.module].append(f)

        for rule in self.CorrelationRules:
            matched_modules = [m for m in rule.required_modules if m in module_map]
            if len(matched_modules) == len(rule.required_modules):
                affected = []
                for mod in rule.required_modules:
                    affected.extend(module_map[mod])

                if rule.required_severities:
                    has_severity = any(
                        f.severity.value in rule.required_severities
                        for f in affected
                    )
                    if not has_severity:
                        continue

                result = CorrelationResult(
                    rule_name=rule.name,
                    description=rule.description,
                    affected_findings=affected,
                    confidence_boost=rule.confidence_boost,
                    severity_escalation=rule.severity_escalation,
                    risk_multiplier=rule.risk_multiplier,
                )
                self._matched_rules.append(result)
                self._apply_correlation(result)

        return self._matched_rules

    def correlation_payloads(self, findings: List[Finding]) -> Tuple[
            List[CorrelationResult], Dict[int, Dict[str, Any]], Dict[str, float]]:
        """Non-mutating v3 entry point: return boost payloads only.

        Returns ``(matched_rules, payloads, module_multipliers)`` where
        ``payloads`` maps ``id(finding)`` → ``{confidence_boost, severity_escalation,
        risk_multiplier}`` (aggregated across all matched rules) and
        ``module_multipliers`` maps module name → product of rule risk multipliers.
        The pipeline applies the boosts; findings are never mutated here.
        """
        self._matched_rules = []
        matched = self._match_rules(findings)
        self._matched_rules = matched

        payloads: Dict[int, Dict[str, Any]] = {}
        module_multipliers: Dict[str, float] = {}
        for result in matched:
            for finding in result.affected_findings:
                entry = payloads.setdefault(id(finding), {
                    'confidence_boost': 0,
                    'severity_escalation': None,
                    'risk_multiplier': 1.0,
                })
                entry['confidence_boost'] += result.confidence_boost
                if result.severity_escalation:
                    order = ['none', 'info', 'low', 'medium', 'high', 'critical']
                    current = entry['severity_escalation']
                    if current is None or order.index(result.severity_escalation) > order.index(current):
                        entry['severity_escalation'] = result.severity_escalation
                entry['risk_multiplier'] *= result.risk_multiplier
            for module in set(f.module for f in result.affected_findings):
                module_multipliers[module] = (
                    module_multipliers.get(module, 1.0) * result.risk_multiplier
                )

        return matched, payloads, module_multipliers

    def _match_rules(self, findings: List[Finding]) -> List[CorrelationResult]:
        vuln_findings = [f for f in findings if f.is_vulnerable()]
        warning_findings = [f for f in findings if f.status.name == "WARNING"]
        all_relevant = vuln_findings + warning_findings

        module_map: Dict[str, List[Finding]] = {}
        for f in all_relevant:
            if f.module not in module_map:
                module_map[f.module] = []
            module_map[f.module].append(f)

        matched = []
        for rule in self.CorrelationRules:
            matched_modules = [m for m in rule.required_modules if m in module_map]
            if len(matched_modules) != len(rule.required_modules):
                continue
            affected = []
            for mod in rule.required_modules:
                affected.extend(module_map[mod])
            if rule.required_severities:
                has_severity = any(
                    f.severity.value in rule.required_severities
                    for f in affected
                )
                if not has_severity:
                    continue
            matched.append(CorrelationResult(
                rule_name=rule.name,
                description=rule.description,
                affected_findings=affected,
                confidence_boost=rule.confidence_boost,
                severity_escalation=rule.severity_escalation,
                risk_multiplier=rule.risk_multiplier,
            ))
        return matched

    def _apply_correlation(self, result: CorrelationResult) -> None:
        for finding in result.affected_findings:
            finding.confidence = min(100, finding.confidence + result.confidence_boost)
            if 'correlation' not in finding.confidence_factors:
                finding.confidence_factors['correlation'] = 0
            finding.confidence_factors['correlation'] += result.confidence_boost

            if result.severity_escalation:
                try:
                    new_sev = Severity(result.severity_escalation)
                    sev_order = ['none', 'info', 'low', 'medium', 'high', 'critical']
                    if sev_order.index(new_sev.value) > sev_order.index(finding.severity.value):
                        finding.severity = new_sev
                        finding.correlation_escalated = True
                except Exception:
                    pass

    @property
    def CorrelationRules(self) -> List[CorrelationRule]:
        return list(self.RULES)

    def get_correlation_summary(self) -> Dict[str, Any]:
        if not self._matched_rules:
            return {'correlations_found': 0, 'details': []}

        return {
            'correlations_found': len(self._matched_rules),
            'details': [
                {
                    'rule': r.rule_name,
                    'description': r.description,
                    'affected': list(set(f.module for f in r.affected_findings)),
                    'confidence_boost': r.confidence_boost,
                    'severity_escalation': r.severity_escalation or 'none',
                }
                for r in self._matched_rules
            ],
        }
