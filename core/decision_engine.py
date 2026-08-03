"""
Standards Metadata Provider v4.0 — single source of truth for scanner standards.

After Phase A8.9 (Migration Cleanup & Architecture Freeze) this module holds ONLY
the scanner standards metadata consumed by the v3 engines, plus the v2 RiskCalculator
(live until A10, when get_statistics is superseded by AssessmentEngine._statistics).

The archived v2 decide() pipeline lives in tests/v2_reference.py (test-only).

See docs/ENGINE_ARCHITECTURE_V3.md §4.
"""

from typing import Dict, Any, List
from core.finding import Finding, Severity, Status
from core.assessment_config import RISK as RISK_CONFIG

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
        'SSTI Detection': {
            'cwe': 'CWE-1336', 'owasp': 'A03: Injection', 'capec': 'CAPEC-35',
            'mitre': 'T1190', 'asvs': 'V5.1 Template Injection',
            'severity': Severity.CRITICAL,
            'impact': {'confidentiality': 5, 'integrity': 5, 'availability': 4},
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
            'Missing Content-Security-Policy (CSP) header. '
            'Impact: Increases exposure to XSS attacks. '
            'Also ensure X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN are set.'
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
        'SSTI Detection': (
            'Never render user input through the template engine. Use sandboxed template environments '
            'if user-controlled templates are required. Treat all user input as data, not code.'
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

    SEVERITY_BY_MODULE = {mod: data['severity'] for mod, data in STANDARDS.items()}


class RiskCalculator:
    # Single-sourced from core.assessment_config (P4.2). Includes the v3
    # 'confirmed' entry; the legacy engine is only used on non-assessed
    # ScanResults whose verification_status is always report vocabulary
    # ('verified'/'likely'/...), so this is behavior-neutral.
    SEVERITY_WEIGHTS = {
        Severity(v): RISK_CONFIG["SEVERITY_WEIGHTS"][v]
        for v in RISK_CONFIG["SEVERITY_WEIGHTS"]
    }

    VERIFICATION_MULTIPLIERS = dict(RISK_CONFIG["VERIFICATION_MULTIPLIERS"])

    @staticmethod
    def calculate(findings: List[Finding]) -> Dict[str, Any]:
        vuln_findings = [f for f in findings if f.is_vulnerable()]
        warning_findings = [f for f in findings if f.status == Status.WARNING]

        total_weighted = 0.0
        max_possible = 0.0
        breakdown = []
        explanation = []

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
            explanation.append(
                f"{f.module} contributes {score:.2f}: severity weight {sev_weight} x "
                f"confidence {f.confidence}% (x{confidence_factor:.2f}) x "
                f"verification '{f.verification_status}' (x{verification_mult}) x "
                f"occurrences {f.occurrences} (x{occurrences_factor:.2f})"
            )

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
            explanation.append(
                f"{f.module} (warning) contributes {score:.2f}: half severity weight "
                f"{sev_weight:.1f} x confidence {f.confidence}% (x{confidence_factor:.2f}) x "
                f"verification '{f.verification_status}' (x{verification_mult})"
            )

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

        if explanation:
            summary = (
                f"The risk score is {risk_score}%: the weighted contribution of "
                f"{len(vuln_findings)} vulnerability finding(s) and "
                f"{len(warning_findings)} warning(s) divided by the maximum possible "
                f"severity weight. Lower confidence or unverified findings reduce the "
                f"score, so it reflects both impact and confidence."
            )
        else:
            summary = (
                f"The risk score is 0% because no vulnerabilities or warnings were "
                f"reported during the scan."
            )

        return {
            "risk_score": risk_score,
            "security_grade": grade,
            "total_weighted": round(total_weighted, 2),
            "max_possible": round(max_possible, 2),
            "breakdown": breakdown,
            "explanation": explanation,
            "summary": summary,
            "vulnerability_count": len(vuln_findings),
            "warning_count": len(warning_findings),
            "calculation_formula": (
                "risk_score = sum(severity_weight * confidence_factor * "
                "verification_multiplier * (0.8 + 0.2 * occurrences_factor)) / "
                "sum(severity_weight) * 100"
            ),
        }