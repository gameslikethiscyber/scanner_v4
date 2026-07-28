"""
Decision Engine v4.0 — Commercial Grade
"""

from typing import Dict, Any, List
from core.finding import Finding, Severity, Status, Exploitability
from core.evidence import EvidenceLevel

class DecisionEngine:
    # Complete standards mapping for all 18 scanners
    STANDARDS = {
        'SQL Injection': {
            'cwe': 'CWE-89', 'owasp': 'A03: Injection', 'capec': 'CAPEC-66',
            'mitre': 'T1190', 'asvs': 'V5.1 SQL Injection',
            'severity': Severity.CRITICAL,
            'impact': {'confidentiality': 5, 'integrity': 5, 'availability': 3},
        },
        'XSS Detection': {
            'cwe': 'CWE-79', 'owasp': 'A03: Injection', 'capec': 'CAPEC-63',
            'mitre': 'T1059.007', 'asvs': 'V5.2 Cross-Site Scripting',
            'severity': Severity.HIGH,
            'impact': {'confidentiality': 4, 'integrity': 3, 'availability': 1},
        },
        'SSRF Detection': {
            'cwe': 'CWE-918', 'owasp': 'A10: Server-Side Request Forgery', 'capec': 'CAPEC-664',
            'mitre': 'T1190', 'asvs': 'V11.1 SSRF',
            'severity': Severity.HIGH,
            'impact': {'confidentiality': 4, 'integrity': 3, 'availability': 2},
        },
        'Host Header Injection': {
            'cwe': 'CWE-644', 'owasp': 'A01: Broken Access Control', 'capec': 'CAPEC-105',
            'mitre': 'T1190', 'asvs': 'V11.2 Host Header',
            'severity': Severity.HIGH,
            'impact': {'confidentiality': 3, 'integrity': 4, 'availability': 2},
        },
        'LFI Detection': {
            'cwe': 'CWE-98', 'owasp': 'A01: Broken Access Control', 'capec': 'CAPEC-252',
            'mitre': 'T1083', 'asvs': 'V4.1 File Inclusion',
            'severity': Severity.HIGH,
            'impact': {'confidentiality': 5, 'integrity': 4, 'availability': 1},
        },
        'Open Redirect': {
            'cwe': 'CWE-601', 'owasp': 'A01: Broken Access Control', 'capec': 'CAPEC-38',
            'mitre': 'T1204.001', 'asvs': 'V11.3 Open Redirect',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 2, 'integrity': 3, 'availability': 1},
        },
        'CSRF Protection': {
            'cwe': 'CWE-352', 'owasp': 'A04: Insecure Design', 'capec': 'CAPEC-62',
            'mitre': 'T1204.002', 'asvs': 'V3.1 CSRF',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 3, 'integrity': 4, 'availability': 2},
        },
        'CORS Configuration': {
            'cwe': 'CWE-942', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-21',
            'mitre': 'T1552.001', 'asvs': 'V11.4 CORS',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 3, 'integrity': 3, 'availability': 1},
        },
        'HTTP Methods': {
            'cwe': 'CWE-749', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-272',
            'mitre': 'T1584.004', 'asvs': 'V11.5 HTTP Methods',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 2, 'integrity': 2, 'availability': 1},
        },
        'Sensitive Files': {
            'cwe': 'CWE-200', 'owasp': 'A01: Broken Access Control', 'capec': 'CAPEC-545',
            'mitre': 'T1083', 'asvs': 'V8.3 Sensitive Data',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 4, 'integrity': 2, 'availability': 1},
        },
        'Headers Security': {
            'cwe': 'CWE-693', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-272',
            'mitre': 'T1592', 'asvs': 'V14.2 HTTP Headers',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 2, 'integrity': 2, 'availability': 1},
        },
        'Cookies Security': {
            'cwe': 'CWE-614', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-199',
            'mitre': 'T1539', 'asvs': 'V3.2 Cookie Security',
            'severity': Severity.LOW,
            'impact': {'confidentiality': 2, 'integrity': 1, 'availability': 1},
        },
        'TLS/SSL Security': {
            'cwe': 'CWE-326', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-217',
            'mitre': 'T1573', 'asvs': 'V9.1 TLS',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 3, 'integrity': 3, 'availability': 2},
        },
        'DNS Security': {
            'cwe': 'CWE-350', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-537',
            'mitre': 'T1583.001', 'asvs': 'V10.1 DNS',
            'severity': Severity.LOW,
            'impact': {'confidentiality': 1, 'integrity': 1, 'availability': 1},
        },
        'Open Ports': {
            'cwe': 'CWE-200', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-300',
            'mitre': 'T1046', 'asvs': 'V10.2 Ports',
            'severity': Severity.MEDIUM,
            'impact': {'confidentiality': 2, 'integrity': 2, 'availability': 2},
        },
        'Security.txt': {
            'cwe': 'CWE-16', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-272',
            'mitre': 'T1592', 'asvs': 'V10.3 Security.txt',
            'severity': Severity.LOW,
            'impact': {'confidentiality': 1, 'integrity': 1, 'availability': 1},
        },
        'Source Code Leaks': {
            'cwe': 'CWE-540', 'owasp': 'A05: Security Misconfiguration', 'capec': 'CAPEC-118',
            'mitre': 'T1537', 'asvs': 'V8.1 Source Disclosure',
            'severity': Severity.LOW,
            'impact': {'confidentiality': 3, 'integrity': 1, 'availability': 1},
        },
        'Technology Detection': {
            'cwe': 'CWE-200', 'owasp': 'A01: Broken Access Control', 'capec': 'CAPEC-545',
            'mitre': 'T1592', 'asvs': 'V8.2 Fingerprinting',
            'severity': Severity.NONE,
            'impact': {'confidentiality': 1, 'integrity': 1, 'availability': 1},
        },
    }

    RECOMMENDATIONS = {
        'SQL Injection': (
            'Use parameterized queries (prepared statements) for all database operations. '
            'Implement input validation with whitelist approach. Apply least privilege to database accounts. '
            'Example: cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])'
        ),
        'XSS Detection': (
            'Implement Content Security Policy (CSP) header. Encode all user output based on HTML/JS/CSS context. '
            'Use framework security features (React JSX auto-escapes, Django templates). '
            'Example CSP: default-src \'self\'; script-src \'self\' \'nonce-random123\''
        ),
        'SSRF Detection': (
            'Restrict outbound traffic from application servers. Validate and sanitize all URL inputs. '
            'Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). '
            'Example: deny from 10.0.0.0/8 in Nginx or use allowlist for external URLs.'
        ),
        'Host Header Injection': (
            'Whitelist allowed Host headers in web server config. Use absolute URLs in redirects. '
            'Set Nginx: if ($host !~ ^(example.com|www.example.com)$) { return 444; }'
        ),
        'LFI Detection': (
            'Use a whitelist of allowed files. Avoid passing user input to file functions. '
            'Map requested paths to a restricted base directory. Example: basename(realpath($file))'
        ),
        'Open Redirect': (
            'Avoid using user input for redirect URLs. Use a whitelist of allowed destinations. '
            'Show intermediate warning page for external redirects. '
            'Example: return redirect(allowed_destinations[input], 302)'
        ),
        'CSRF Protection': (
            'Implement anti-CSRF tokens on all state-changing requests. Use SameSite=Strict cookies. '
            'Verify Origin/Referer headers. Example: <meta name="csrf-token" content="{{ csrf_token }}">'
        ),
        'CORS Configuration': (
            'Restrict Access-Control-Allow-Origin to specific trusted origins. '
            'Never use wildcard (*) with credentials: true. Set Vary: Origin header. '
            'Example: Access-Control-Allow-Origin: https://trusted-app.example.com'
        ),
        'HTTP Methods': (
            'Disable PUT, DELETE, TRACE, CONNECT, OPTIONS if not needed. '
            'Restrict to GET, POST, HEAD only. Example Nginx: limit_except GET POST HEAD { deny all; }'
        ),
        'Sensitive Files': (
            'Remove backup/config files from web root. Use .gitignore for deployments. '
            'Block access via web server: location ~* \.(bak|conf|sql|yml|env)$ { deny all; }'
        ),
        'Headers Security': (
            'Set security headers: X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN, '
            'Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy: geolocation=()'
        ),
        'Cookies Security': (
            'Set Secure flag on all cookies. Set HttpOnly to prevent JS access. '
            'Set SameSite=Lax or Strict. Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax'
        ),
        'TLS/SSL Security': (
            'Use TLS 1.2 or higher only. Disable weak ciphers. Ensure valid certificate. '
            'Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        ),
        'DNS Security': (
            'Enable DNSSEC. Restrict zone transfers to authorized servers. '
            'Configure SPF, DKIM, DMARC for email security.'
        ),
        'Open Ports': (
            'Close unnecessary ports with firewall rules. Implement network segmentation. '
            'Use iptables/nftables: iptables -A INPUT -p tcp --dport 3306 -j DROP'
        ),
        'Security.txt': (
            'Create security.txt at /.well-known/security.txt following RFC 9116. '
            'Include Contact, Expires, Encryption fields for vulnerability disclosure.'
        ),
        'Source Code Leaks': (
            'Disable directory listing. Block source file access (.py, .php, .asp). '
            'Use .htaccess: Options -Indexes; RewriteRule \.py$ - [F]'
        ),
        'Technology Detection': (
            'Remove version headers. Minimize exposed tech stack. '
            'Set server: server_tokens off; Remove X-Powered-By headers.'
        ),
    }

    CVSS_DESCRIPTIONS = {
        'AV:N': 'Attack Vector: Network (remotely exploitable)',
        'AV:A': 'Attack Vector: Adjacent Network',
        'AV:L': 'Attack Vector: Local (requires physical/logical access)',
        'AV:P': 'Attack Vector: Physical',
        'AC:L': 'Attack Complexity: Low (no special conditions)',
        'AC:H': 'Attack Complexity: High (requires specific conditions)',
        'PR:N': 'Privileges Required: None',
        'PR:L': 'Privileges Required: Low (basic user)',
        'PR:H': 'Privileges Required: High (admin access)',
        'UI:N': 'User Interaction: None',
        'UI:R': 'User Interaction: Required (victim must click/act)',
        'S:U': 'Scope: Unchanged',
        'S:C': 'Scope: Changed (affects components beyond vulnerability)',
        'C:H': 'Confidentiality Impact: High (full data disclosure)',
        'C:L': 'Confidentiality Impact: Low (limited disclosure)',
        'C:N': 'Confidentiality Impact: None',
        'I:H': 'Integrity Impact: High (full data corruption)',
        'I:L': 'Integrity Impact: Low (limited modification)',
        'I:N': 'Integrity Impact: None',
        'A:H': 'Availability Impact: High (full service disruption)',
        'A:L': 'Availability Impact: Low (reduced performance)',
        'A:N': 'Availability Impact: None',
    }

    PASS_RECOMMENDATION = 'Continue monitoring. No action required at this time.'
    PASS_REASON = 'No vulnerabilities detected during testing.'
    FAIL_REASON_PREFIX = 'Vulnerability confirmed via '
    WARNING_REASON_PREFIX = 'Potential issue identified: '

    def _ensure_reason_recommendation(self, finding: Finding) -> Finding:
        if finding.status == Status.PASS and not finding.reason:
            finding.reason = self.PASS_REASON
        if finding.status == Status.PASS and not finding.recommendation:
            finding.recommendation = self.PASS_RECOMMENDATION

        if not finding.reason:
            module = finding.module
            if finding.status == Status.FAIL:
                evidence_desc = ''
                if finding.evidence:
                    ev = finding.evidence[0]
                    desc = getattr(ev, 'description', '') or ''
                    if desc:
                        evidence_desc = desc.lower()
                finding.reason = f'{self.FAIL_REASON_PREFIX}{evidence_desc}' if evidence_desc else f'{module} vulnerability detected'
            elif finding.status == Status.WARNING:
                evidence_desc = ''
                if finding.evidence:
                    ev = finding.evidence[0]
                    desc = getattr(ev, 'description', '') or ''
                    if desc:
                        evidence_desc = desc.lower()
                finding.reason = f'{self.WARNING_REASON_PREFIX}{evidence_desc}' if evidence_desc else f'{module} requires review'

        if not finding.recommendation:
            module = finding.module
            if module in self.RECOMMENDATIONS:
                finding.recommendation = self.RECOMMENDATIONS[module]
            else:
                finding.recommendation = f'Review {module} configuration and apply security best practices.'
        return finding

    def decide(self, finding: Finding) -> Finding:
        if not finding.evidence and finding.status is Status.UNKNOWN:
            finding.status = Status.UNKNOWN
            finding.severity = Severity.NONE
            finding.confidence = 0
            self._ensure_reason_recommendation(finding)
            return finding

        finding = self._determine_status(finding)
        finding = self._determine_severity(finding)
        finding = self._determine_exploitability(finding)
        finding = self._assign_standards(finding)
        finding = self._assign_impact(finding)
        finding = self._calculate_cvss(finding)
        finding = self._generate_verify_commands(finding)
        finding = self._populate_replay_data(finding)
        finding = self._ensure_reason_recommendation(finding)
        return finding

    def _populate_replay_data(self, finding: Finding) -> Finding:
        for ev in finding.evidence:
            raw = getattr(ev, 'raw_data', None) or {}
            if not isinstance(raw, dict):
                continue
            req = raw.get('request', {})
            resp = raw.get('response', {})
            if req or resp:
                finding.replay_data = {'request': req, 'response': resp}
                break
        return finding

    def _determine_status(self, finding: Finding) -> Finding:
        if finding.status not in (Status.UNKNOWN,):
            return finding

        if not finding.evidence:
            finding.status = Status.UNKNOWN
            return finding

        def _level(e):
            lvl = getattr(e, 'level', None)
            if lvl is None:
                return None
            if isinstance(lvl, EvidenceLevel):
                return lvl
            try:
                return EvidenceLevel(lvl)
            except Exception:
                return None

        levels = [_level(e) for e in finding.evidence]

        has_error_evidence = any(
            lvl is not None and lvl == EvidenceLevel.UNKNOWN
            and 'error' in getattr(e, 'description', '').lower()
            for e, lvl in zip(finding.evidence, levels)
        )
        if has_error_evidence:
            finding.status = Status.UNKNOWN
            return finding

        confirmed_levels = {EvidenceLevel.EXPLOITED, EvidenceLevel.CONFIRMED}
        confirmed = any(lvl in confirmed_levels for lvl in levels)
        if confirmed:
            finding.status = Status.FAIL
        elif any(lvl == EvidenceLevel.LIKELY for lvl in levels):
            finding.status = Status.WARNING
        elif any(lvl == EvidenceLevel.POSSIBLE for lvl in levels):
            finding.status = Status.UNKNOWN
        else:
            finding.status = Status.PASS
        return finding

    SEVERITY_BY_MODULE = {mod: data['severity'] for mod, data in STANDARDS.items()}

    def _determine_severity(self, finding: Finding) -> Finding:
        if finding.status == Status.PASS:
            finding.severity = Severity.NONE
            return finding
        if finding.severity != Severity.NONE:
            return finding
        if finding.status in (Status.FAIL, Status.WARNING):
            mapped = self.SEVERITY_BY_MODULE.get(finding.module)
            if mapped is not None:
                finding.severity = mapped
            else:
                finding.severity = Severity.MEDIUM
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
        entry = self.STANDARDS.get(module)
        if entry:
            finding.cwe_id = entry['cwe']
            finding.owasp_category = entry['owasp']
            finding.capec_id = entry['capec']
            finding.mitre_id = entry['mitre']
            finding.asvs_reference = entry['asvs']
        return finding

    def _assign_impact(self, finding: Finding) -> Finding:
        module = finding.module
        entry = self.STANDARDS.get(module)
        if entry:
            impact = entry['impact']
            multiplier = (
                1.0 if finding.severity == Severity.CRITICAL else
                0.8 if finding.severity == Severity.HIGH else
                0.6 if finding.severity == Severity.MEDIUM else
                0.4 if finding.severity == Severity.LOW else 0.2
            )
            finding.impact = {
                'confidentiality': max(1, int(impact['confidentiality'] * multiplier)),
                'integrity': max(1, int(impact['integrity'] * multiplier)),
                'availability': max(1, int(impact['availability'] * multiplier)),
            }
        return finding

    def _calculate_cvss(self, finding: Finding) -> Finding:
        severity_score = {
            Severity.NONE: 0, Severity.INFO: 1.0, Severity.LOW: 3.0,
            Severity.MEDIUM: 5.0, Severity.HIGH: 7.0, Severity.CRITICAL: 9.0,
        }
        base = severity_score.get(finding.severity, 0)
        confidence_boost = (finding.confidence / 100) * 0.5
        finding.cvss_score = round(min(10, base + confidence_boost), 1)

        av, ac, pr, ui, s = 'N', 'L', 'N', 'N', 'U'
        c, i_val, a = 'N', 'N', 'N'

        imp = finding.impact
        if imp.get('confidentiality', 0) >= 4: c = 'H'
        elif imp.get('confidentiality', 0) >= 2: c = 'L'
        if imp.get('integrity', 0) >= 4: i_val = 'H'
        elif imp.get('integrity', 0) >= 2: i_val = 'L'
        if imp.get('availability', 0) >= 4: a = 'H'
        elif imp.get('availability', 0) >= 2: a = 'L'

        if finding.severity == Severity.CRITICAL:
            av, ac, pr, ui = 'N', 'L', 'N', 'N'
        elif finding.severity == Severity.HIGH:
            av, ac, pr, ui = 'N', 'L', 'L', 'N'
        elif finding.severity == Severity.MEDIUM:
            av, ac, pr, ui = 'N', 'L', 'L', 'R'
        elif finding.severity == Severity.LOW:
            av, ac, pr, ui = 'A', 'H', 'H', 'R'

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i_val}/A:{a}"
        finding.cvss_vector = vector

        parts = vector.replace('CVSS:3.1/', '').split('/')
        explanations = []
        for p in parts:
            desc = self.CVSS_DESCRIPTIONS.get(p.strip())
            if desc:
                explanations.append(desc)

        total_impact = imp.get('confidentiality', 0) + imp.get('integrity', 0) + imp.get('availability', 0)
        finding.cvss_explanation = (
            f"Score {finding.cvss_score} out of 10. "
            f"Computed from severity={finding.severity.value} (base {base}) "
            f"adjusted by confidence {finding.confidence}% (boost +{confidence_boost:.1f}). "
            f"Impact profile: CIA={total_impact}/15. "
            + ' | '.join(explanations)
        )
        return finding

    def _generate_verify_commands(self, finding: Finding) -> Finding:
        target = finding.target
        method = 'GET'
        payload = ''
        for ev in finding.evidence:
            if getattr(ev, 'payload', None):
                payload = ev.payload
            if getattr(ev, 'method', None):
                method = ev.method

        cmds = []
        if target:
            quoted_url = target.replace('"', '\\"')
            cmds.append(f'curl -X {method} -k -v "{quoted_url}"')
            if payload:
                cmds.append(f'curl -X {method} -k -v -H "Host: {payload}" "{quoted_url}"')
            cmds.append(f'# Burp Suite: Send request to Repeater, replace Host header, observe response')
            cmds.append(f'# Browser: Open DevTools (F12) > Network tab, reload page, inspect request/response')
            cmds.append(f'# OWASP ZAP: Right-click request > Open in Browser > Manual Explore')
        finding.verify_commands = cmds
        return finding


class RiskCalculator:
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 5,
        Severity.LOW: 3, Severity.INFO: 1, Severity.NONE: 0,
    }

    VERIFICATION_MULTIPLIERS = {
        "verified": 1.0, "likely": 0.85, "possible": 0.6,
        "manual_review": 0.4, "unverified": 0.3,
    }

    @staticmethod
    def calculate(findings: List[Finding]) -> Dict[str, Any]:
        vuln_findings = [f for f in findings if f.is_vulnerable()]
        warning_findings = [f for f in findings if f.status == Status.WARNING]

        total_weighted = 0.0
        max_possible = 0.0
        breakdown = []

        for f in vuln_findings:
            sev_weight = RiskCalculator.SEVERITY_WEIGHTS.get(f.severity, 1)
            confidence_factor = f.confidence / 100.0
            verification_mult = RiskCalculator.VERIFICATION_MULTIPLIERS.get(f.verification_status, 0.3)
            occurrences_factor = min(f.occurrences, 5) / 5.0

            score = sev_weight * confidence_factor * verification_mult * (0.8 + 0.2 * occurrences_factor)
            total_weighted += score
            max_possible += sev_weight

            breakdown.append({
                "module": f.module, "severity": f.severity.value,
                "confidence": f.confidence, "verification": f.verification_status,
                "occurrences": f.occurrences, "score": round(score, 2),
                "severity_weight": sev_weight, "confidence_factor": round(confidence_factor, 2),
                "verification_multiplier": verification_mult,
                "occurrences_factor": round(occurrences_factor, 2),
            })

        for f in warning_findings:
            sev_weight = RiskCalculator.SEVERITY_WEIGHTS.get(f.severity, 1) * 0.5
            confidence_factor = f.confidence / 100.0
            verification_mult = RiskCalculator.VERIFICATION_MULTIPLIERS.get(f.verification_status, 0.3)
            occurrences_factor = min(f.occurrences, 5) / 5.0

            score = sev_weight * confidence_factor * verification_mult * (0.8 + 0.2 * occurrences_factor)
            total_weighted += score
            max_possible += sev_weight * 2

            breakdown.append({
                "module": f.module, "severity": f.severity.value,
                "confidence": f.confidence, "verification": f.verification_status,
                "occurrences": f.occurrences, "score": round(score, 2),
                "severity_weight": round(sev_weight, 1),
                "confidence_factor": round(confidence_factor, 2),
                "verification_multiplier": verification_mult,
                "occurrences_factor": round(occurrences_factor, 2),
                "warning": True,
            })

        if max_possible > 0:
            risk_score = round((total_weighted / max_possible) * 100, 1)
        else:
            risk_score = 0.0

        # Security letter grade
        if risk_score <= 5:
            grade = 'A+'
        elif risk_score <= 10:
            grade = 'A'
        elif risk_score <= 20:
            grade = 'B+'
        elif risk_score <= 30:
            grade = 'B'
        elif risk_score <= 40:
            grade = 'C+'
        elif risk_score <= 50:
            grade = 'C'
        elif risk_score <= 65:
            grade = 'D+'
        elif risk_score <= 80:
            grade = 'D'
        else:
            grade = 'F'

        return {
            "risk_score": risk_score,
            "security_grade": grade,
            "total_weighted": round(total_weighted, 2),
            "max_possible": round(max_possible, 2),
            "breakdown": breakdown,
            "vulnerability_count": len(vuln_findings),
            "warning_count": len(warning_findings),
            "calculation_formula": (
                "risk_score = sum(severity_weight * confidence_factor * "
                "verification_multiplier * (0.8 + 0.2 * occurrences_factor)) / "
                "sum(severity_weight) * 100"
            ),
        }