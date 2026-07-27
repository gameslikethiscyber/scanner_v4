"""
Decision Engine v3.1
"""

from typing import Dict, Any, List
from core.finding import Finding, Severity, Status, Exploitability
from core.evidence import EvidenceLevel

class DecisionEngine:
    MODULE_WEIGHTS = {
        'RCE': 100,
        'SQL Injection': 95,
        'SSRF': 90,
        'Authentication': 85,
        'IDOR': 80,
        'XSS': 70,
        'CSRF': 60,
        'Headers': 25,
        'Cookies': 20,
        'Open Ports': 10,
        'Banner': 5
    }
    
    CWE_MAP = {
        'SQL Injection': 'CWE-89',
        'XSS': 'CWE-79',
        'SSRF': 'CWE-918',
        'CSRF': 'CWE-352',
        'IDOR': 'CWE-639',
        'RCE': 'CWE-94',
        'Headers': 'CWE-16',
        'TLS': 'CWE-326'
    }
    
    OWASP_MAP = {
        'SQL Injection': 'A03: Injection',
        'XSS': 'A03: Injection',
        'SSRF': 'A10: Server-Side Request Forgery',
        'CSRF': 'A04: Insecure Design',
        'IDOR': 'A01: Broken Access Control',
        'RCE': 'A03: Injection',
        'Headers': 'A05: Security Misconfiguration',
        'TLS': 'A05: Security Misconfiguration'
    }
    
    def decide(self, finding: Finding) -> Finding:
        if not finding.evidence:
            finding.status = Status.UNKNOWN
            finding.severity = Severity.NONE
            finding.confidence = 0
            return finding
        
        # Determine status
        finding = self._determine_status(finding)
        finding = self._determine_severity(finding)
        finding = self._determine_exploitability(finding)
        finding = self._assign_standards(finding)
        finding = self._assign_impact(finding)
        finding = self._calculate_cvss(finding)
        return finding
    
    def _determine_status(self, finding: Finding) -> Finding:
        if not finding.evidence:
            finding.status = Status.UNKNOWN
            return finding
        
        error_evidence = any('error' in getattr(e, 'description', '').lower() for e in finding.evidence)
        if error_evidence:
            finding.status = Status.UNKNOWN
            return finding
        
        confirmed = any(getattr(e, 'level', None) in [EvidenceLevel.VERIFIED.value, EvidenceLevel.EXPLOITED.value, EvidenceLevel.CONFIRMED.value] for e in finding.evidence)
        if confirmed:
            finding.status = Status.FAIL if len(finding.evidence) >= 2 else Status.WARNING
        elif any(getattr(e, 'level', None) == EvidenceLevel.LIKELY.value for e in finding.evidence):
            finding.status = Status.WARNING
        elif any(getattr(e, 'level', None) == EvidenceLevel.POSSIBLE.value for e in finding.evidence):
            finding.status = Status.UNKNOWN
        else:
            finding.status = Status.PASS
        return finding
    
    def _determine_severity(self, finding: Finding) -> Finding:
        if finding.status == Status.PASS:
            finding.severity = Severity.NONE
            return finding
        
        if finding.status == Status.FAIL:
            if 'SQL' in finding.module or 'RCE' in finding.module:
                finding.severity = Severity.CRITICAL
            elif 'XSS' in finding.module or 'SSRF' in finding.module:
                finding.severity = Severity.HIGH
            elif 'Headers' in finding.module or 'TLS' in finding.module:
                finding.severity = Severity.LOW
            else:
                finding.severity = Severity.MEDIUM
        elif finding.status == Status.WARNING:
            finding.severity = Severity.LOW
        else:
            finding.severity = Severity.INFO
        return finding
    
    def _determine_exploitability(self, finding: Finding) -> Finding:
        if finding.severity == Severity.CRITICAL:
            finding.exploitability = Exploitability.EASY
        elif finding.severity == Severity.HIGH:
            finding.exploitability = Exploitability.MEDIUM
        elif finding.severity == Severity.MEDIUM:
            finding.exploitability = Exploitability.HARD
        elif finding.severity == Severity.LOW:
            finding.exploitability = Exploitability.THEORETICAL
        else:
            finding.exploitability = Exploitability.UNKNOWN
        return finding
    
    def _assign_standards(self, finding: Finding) -> Finding:
        module = finding.module
        if module in self.CWE_MAP:
            finding.cwe_id = self.CWE_MAP[module]
        if module in self.OWASP_MAP:
            finding.owasp_category = self.OWASP_MAP[module]
        return finding
    
    def _assign_impact(self, finding: Finding) -> Finding:
        impact_map = {
            'SQL Injection': {'confidentiality': 5, 'integrity': 5, 'availability': 3},
            'XSS': {'confidentiality': 4, 'integrity': 3, 'availability': 1},
            'SSRF': {'confidentiality': 4, 'integrity': 3, 'availability': 2},
            'CSRF': {'confidentiality': 3, 'integrity': 4, 'availability': 2},
            'IDOR': {'confidentiality': 5, 'integrity': 4, 'availability': 1},
            'RCE': {'confidentiality': 5, 'integrity': 5, 'availability': 5},
            'Headers': {'confidentiality': 2, 'integrity': 2, 'availability': 1},
            'TLS': {'confidentiality': 3, 'integrity': 3, 'availability': 2}
        }
        if finding.module in impact_map:
            impact = impact_map[finding.module]
            multiplier = 1.0 if finding.severity == Severity.CRITICAL else 0.8 if finding.severity == Severity.HIGH else 0.6 if finding.severity == Severity.MEDIUM else 0.4 if finding.severity == Severity.LOW else 0.2
            finding.impact = {
                'confidentiality': max(1, int(impact['confidentiality'] * multiplier)),
                'integrity': max(1, int(impact['integrity'] * multiplier)),
                'availability': max(1, int(impact['availability'] * multiplier))
            }
        return finding
    
    def _calculate_cvss(self, finding: Finding) -> Finding:
        severity_score = {
            Severity.NONE: 0,
            Severity.INFO: 1.0,
            Severity.LOW: 3.0,
            Severity.MEDIUM: 5.0,
            Severity.HIGH: 7.0,
            Severity.CRITICAL: 9.0
        }
        base = severity_score.get(finding.severity, 0)
        confidence_boost = (finding.confidence / 100) * 0.5
        finding.cvss_score = round(min(10, base + confidence_boost), 1)
        return finding