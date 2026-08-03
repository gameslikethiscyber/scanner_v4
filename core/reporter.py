"""
Professional Report Generation - Complete Version
With Risk Score, Overall Severity, Coverage, Confidence Breakdown, and Detailed Findings
"""

import os
from datetime import datetime
from typing import List
from core.finding import Finding, ScanResult, Status, Severity

class Reporter:
    def __init__(self, branding: dict = None, strict_validation: bool = True):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
        self.branding = branding or {}
        self.logo_url = self.branding.get('logo_url', '')
        self.company_name = self.branding.get('company_name', 'SEA Corporate')
        self.consultant_name = self.branding.get('consultant_name', '')
        self.client_name = self.branding.get('client_name', '')
        self.report_id = self.branding.get('report_id', '')
        self.strict_validation = strict_validation
    
    def validate_results(self, scan_result: ScanResult) -> List[str]:
        """التحقق من صحة النتائج قبل إنشاء التقرير"""
        errors = scan_result.validate()
        if errors:
            print("[WARNING] Validation errors found:")
            for error in errors:
                print("  - " + error)
        return errors

    @staticmethod
    def _assessment(scan_result: ScanResult):
        """Return the immutable Assessment when present, else None.

        Phase A9: reporters are presentation-only consumers. When a scan has run
        the assessment pipeline, all report values are read from the Assessment
        object; nothing is recomputed here.
        """
        return getattr(scan_result, 'assessment', None)

    def _stats(self, scan_result: ScanResult) -> dict:
        """v2-compatible statistics for the report.

        Preferred source is the Assessment's ``statistics`` dict (the single
        assessment output). Falls back to the ScanResult legacy computation only
        for un-assessed results (tests / callers that never ran the pipeline).
        """
        assessment = self._assessment(scan_result)
        if assessment is not None:
            stats = dict(assessment.statistics or {})
        else:
            stats = scan_result.get_statistics()

        # Advanced crawl metrics (SOP v4.0 Phase 2) — kept separate so report
        # sections render clean even when an older stats dict lacks them.
        classifications = getattr(scan_result, "crawl_classifications", None) or {}
        stats["crawl"] = {
            "urls_crawled": stats.get("urls_crawled", stats.get("pages_crawled", 0)),
            "pages_crawled": stats.get("pages_crawled", 0),
            "urls_discovered": len(getattr(scan_result, "urls_discovered", None) or []),
            "duplicates": getattr(scan_result, "crawl_duplicates", 0),
            "redirects": getattr(scan_result, "crawl_redirects", 0),
            "failed": getattr(scan_result, "crawl_failed", 0),
            "forms_discovered": stats.get("forms_discovered", 0),
            "js_files": getattr(scan_result, "js_discovered_urls", 0) or 0,
            "sitemap_entries": getattr(scan_result, "crawl_sitemap_entries", 0),
            "robots_entries": getattr(scan_result, "crawl_robots_entries", 0),
            "duration_s": getattr(scan_result, "crawl_duration_s", 0.0),
            "classifications": classifications,
            "login_pages": int(classifications.get("Login", 0)),
            "admin_pages": int(classifications.get("Admin", 0)),
            "api_pages": int(classifications.get("API", 0)),
        }
        return stats
    
    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters to prevent broken layout / XSS in report."""
        if text is None:
            return ""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    def _format_evidence(self, finding: Finding) -> str:
        """
        Render a Finding's evidence list into a human-readable string.
        Handles Evidence dataclasses, dicts, and arbitrary objects gracefully.
        """
        ev_list = finding.evidence
        if not ev_list:
            # Fall back to the legacy evidence_text attribute if available.
            return finding.evidence_text or "No evidence provided"

        lines = []
        for ev in ev_list:
            # Evidence dataclass instance
            if hasattr(ev, "to_dict"):
                d = ev.to_dict()
                level = d.get("level", "?")
                desc = d.get("description", "")
                payload = d.get("payload")
                param = d.get("parameter")
                method = d.get("method", "GET")
                endpoint = d.get("endpoint")
                parts = [f"[{level}] {desc}"]
                if param or payload:
                    extra = []
                    if param:
                        extra.append(f"param={param}")
                    if payload is not None:
                        extra.append(f"payload={payload}")
                    parts.append("  " + ", ".join(extra))
                if endpoint:
                    parts.append(f"  {method} {endpoint}")
                lines.append("\n".join(parts))
            elif isinstance(ev, dict):
                level = ev.get("level") or ev.get("type") or "?"
                desc = ev.get("description") or ev.get("message") or str(ev)
                lines.append(f"[{level}] {desc}")
            else:
                lines.append(str(ev))
        return "\n---\n".join(lines)

    def _format_finding_text(self, finding: Finding, max_len: int = 0) -> str:
        """Concise text rendering used in safe/warning/info grids and PDF."""
        reason = finding.reason or ""
        if max_len and len(reason) > max_len:
            reason = reason[:max_len] + "…"
        return reason

    def build_auth_section(self, stats) -> str:
        """Phase 9: Authentication section for HTML reports (secrets redacted)."""
        auth = stats.get('auth') or {}
        if not auth:
            return ""
        state = auth.get('state', 'none')
        detected = auth.get('detected', False)
        if not detected and state in ('none', None):
            return ""
        from core.auth_manager import AUTH_STATE_BADGE
        badge_cls = AUTH_STATE_BADGE.get(state, 'info')
        state_label = auth.get('state_label', 'No Authentication')
        method_label = auth.get('method_label', 'Anonymous')
        mode = auth.get('mode') or method_label
        authenticated = auth.get('authenticated', False)
        if auth.get('session_checked'):
            session_valid = "Yes" if auth.get('session_valid') else "No"
        else:
            session_valid = "Not checked"
        coverage = auth.get('coverage', {}) or {}

        reasons_html = ""
        reasons = auth.get('reasons', [])
        if reasons:
            reasons_html = "".join(
                f'<div class="auth-reason">• {self._escape_html(r)}</div>' for r in reasons
            )

        protected_areas = coverage.get('protected_areas', [])
        areas_html = ""
        if protected_areas:
            areas_html = (
                '<span class="auth-area">Protected areas:</span> '
                + ", ".join(self._escape_html(a) for a in protected_areas[:8])
            )

        session_html = ""
        session = auth.get('session')
        if session and session.get('method') != 'public':
            names = ", ".join(self._escape_html(n) for n in session.get('cookie_names', [])[:6])
            token_note = ""
            if session.get('has_token'):
                token_note = f'<span class="auth-token-note">· {self._escape_html(session.get("token_type", "Bearer"))} token (redacted)</span>'
            session_html = (
                f'<div class="auth-session">'
                f'<strong>Session:</strong> {self._escape_html(session.get("method_label", ""))}'
                f'{(" — cookies: " + names) if names else ""} {token_note}'
                f'</div>'
            )

        return f'''
        <div class="auth-section">
            <h3>🔐 Authentication</h3>
            <div class="auth-grid">
                <div class="auth-item">
                    <span class="auth-label">Authentication Detected</span>
                    <span class="auth-value">{'Yes' if detected else 'No'}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Confidence</span>
                    <span class="auth-value">{auth.get('confidence', 0)}%</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Mode</span>
                    <span class="auth-value">{self._escape_html(mode)}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Authenticated</span>
                    <span class="auth-value">{'Yes' if authenticated else 'No'}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Session Valid</span>
                    <span class="auth-value">{session_valid}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Session State</span>
                    <span class="badge badge-{badge_cls}">{self._escape_html(state_label)}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Protected Pages Scanned</span>
                    <span class="auth-value">{coverage.get('authenticated_pages', 0)}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Public Pages</span>
                    <span class="auth-value">{coverage.get('public_pages', 0)}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Blocked / Redirected</span>
                    <span class="auth-value">{coverage.get('blocked_pages', 0) + coverage.get('redirected_pages', 0)}</span>
                </div>
                <div class="auth-item">
                    <span class="auth-label">Coverage Improved</span>
                    <span class="auth-value">+{coverage.get('improvement', 0)}%</span>
                </div>
            </div>
            <div class="auth-coverage">
                <div class="auth-coverage-row">
                    <span>Public: <strong>{coverage.get('public', 0)}%</strong></span>
                    <span>Authenticated: <strong>{coverage.get('authenticated', 0)}%</strong></span>
                    <span>Overall: <strong>{coverage.get('overall', 0)}%</strong></span>
                </div>
                <div class="auth-coverage-bar">
                    <div class="auth-coverage-fill" style="width:{coverage.get('overall', 0)}%;"></div>
                </div>
            </div>
            {session_html}
            {reasons_html}
            {areas_html}
        </div>'''


    def generate_html(self, scan_result: ScanResult, target: str) -> str:
        """إنشاء تقرير HTML احترافي"""
        try:
            errors = self.validate_results(scan_result)
            if errors and self.strict_validation:
                raise ValueError(
                    "Report generation rejected: final quality validation failed.\n  - "
                    + "\n  - ".join(errors)
                )
            stats = self._stats(scan_result)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.report_dir, f"report_{timestamp}.html")
            
            # Filter by status to prevent duplicate classification.
            # Severity sections include only FAIL/VULNERABLE findings.
            # WARNING, INFO, and PASS findings go to their own sections.
            fail_findings = [f for f in scan_result.findings if f.status in (Status.FAIL, Status.VULNERABLE)]
            critical = [f for f in fail_findings if f.severity == Severity.CRITICAL]
            high = [f for f in fail_findings if f.severity == Severity.HIGH]
            medium = [f for f in fail_findings if f.severity == Severity.MEDIUM]
            low = [f for f in fail_findings if f.severity == Severity.LOW]
            safe = scan_result.get_safe_findings()
            info = scan_result.get_info_findings()
            warnings = scan_result.get_warning_findings()
            
            html = self.build_html(target, stats, critical, high, medium, low, safe, info, warnings)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
            
            print("[OK] HTML report: " + filename)
            return filename
        except Exception as e:
            print("[ERROR] Error generating HTML: " + str(e))
            import traceback
            traceback.print_exc()
            return ""
    
    def build_html(self, target, stats, critical, high, medium, low, safe, info, warnings):
        """Build complete HTML report."""
        overall_severity = stats.get('overall_severity', 'No Risk')
        overall_color = stats.get('overall_color', '#2196F3')
        overall_description = stats.get('overall_description', '')
        risk = stats.get('risk_score', 0)
        executive = stats.get('executive_summary', overall_description)
        overall_tier = stats.get('overall_tier', 'none')

        tier_class_map = {
            'critical': 'critical', 'high': 'high', 'elevated': 'medium',
            'medium': 'medium', 'low': 'low', 'none': 'none',
        }
        tier_label_map = {
            'critical': 'Critical Risk', 'high': 'High Risk', 'elevated': 'Elevated Risk',
            'medium': 'Elevated Risk', 'low': 'Low Risk', 'none': 'No Risk',
        }
        overall_html = (
            f'<span class="sev-dot sev-{tier_class_map.get(overall_tier, "none")}"></span> '
            f'{tier_label_map.get(overall_tier, "No Risk")}'
        )

        # Risk breakdown
        risk_breakdown = ""
        if 'risk_breakdown' in stats:
            rb = stats['risk_breakdown']
            rows = ""
            for item in rb.get('breakdown', []):
                color = "#f44336" if item['severity'] == 'critical' else "#FF9800" if item['severity'] == 'high' else "#FFC107" if item['severity'] == 'medium' else "#4CAF50"
                rows += f'''
                <tr>
                    <td>{self._escape_html(item['module'])}</td>
                    <td><span class="badge badge-{item['severity']}">{item['severity'].upper()}</span></td>
                    <td>{item['confidence']}%</td>
                    <td>{self._escape_html(item['verification'])}</td>
                    <td style="color:{color};font-weight:bold;">{item['score']}</td>
                </tr>'''
            explanation = ""
            for line in rb.get('explanation', []):
                explanation += f'<li>{self._escape_html(line)}</li>'
            if explanation:
                explanation = (
                    f'<div class="risk-explanation">'
                    f'<h4>Why this score?</h4><ul>{explanation}</ul></div>'
                )
            summary_text = rb.get('summary', '')
            if rows:
                risk_breakdown = f'''
                <div class="risk-breakdown">
                    <h3>Risk Score Breakdown</h3>
                    <p class="rb-formula">Formula: {self._escape_html(rb.get('calculation_formula', ''))}</p>
                    <div class="table-wrap">
                    <table class="breakdown-table">
                        <thead><tr>
                            <th>Module</th><th>Severity</th><th>Confidence</th><th>Verification</th><th>Score</th>
                        </tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                    </div>
                    <p class="rb-total">
                        <strong>Total Weighted:</strong> {rb.get('total_weighted', 0)} / {rb.get('max_possible', 0)} = <strong class="rb-risk">{risk}%</strong>
                        <span class="msep">·</span> Vulnerabilities: {rb.get('vulnerability_count', 0)} <span class="msep">·</span> Warnings: {rb.get('warning_count', 0)}
                    </p>
                    {explanation}
                    {f'<p class="rb-summary">{self._escape_html(summary_text)}</p>' if summary_text else ''}
                </div>'''

        # Executive summary
        exec_class = "critical-summary" if critical or stats.get('critical', 0) > 0 else "medium-summary" if medium or stats.get('warning', 0) > 0 else "safe-summary"
        exec_summary = f'''
        <div class="executive-summary {exec_class}">
            <div class="es-head">
                <h3>Executive Summary</h3>
                <span class="es-badge">{self._escape_html(stats.get('overall_label', overall_severity))}</span>
            </div>
            <p class="es-body">{self._escape_html(executive)}</p>
            <div class="exec-meta">
                <div class="em-item"><span class="em-label">Risk Score</span><span class="em-value">{risk}%</span></div>
                <div class="em-item"><span class="em-label">Coverage</span><span class="em-value">{stats.get('coverage_percentage', 0)}%</span></div>
                <div class="em-item"><span class="em-label">Vulnerabilities</span><span class="em-value">{stats.get('vulnerabilities', 0)}</span></div>
                <div class="em-item"><span class="em-label">Warnings</span><span class="em-value">{stats.get('warning', 0)}</span></div>
                <div class="em-item"><span class="em-label">Passed</span><span class="em-value">{stats.get('safe', 0)}</span></div>
                <div class="em-item"><span class="em-label">Verified</span><span class="em-value">{stats.get('verified_vulns', 0)}</span></div>
                <div class="em-item"><span class="em-label">Manual Review</span><span class="em-value">{stats.get('likely_vulns', 0)}</span></div>
            </div>
        </div>'''

        # Standardized verification labels block (SOP #11)
        labels = stats.get('labels', {})
        vlabels = labels.get('verification', {})
        label_chips = "".join(
            f'<span class="label-chip">{self._escape_html(v)}</span>'
            for k, v in vlabels.items()
        )
        standardized_labels_html = f'''
        <div class="standardized-labels">
            <span class="sl-title">Standard Verification Labels:</span>
            {label_chips}
        </div>'''

        # Coverage explanation (SOP #8)
        coverage_explanation = stats.get('coverage_explanation', '')
        coverage_explanation_html = ""
        if coverage_explanation:
            coverage_explanation_html = f'''
            <div class="coverage-explain">
                <strong>Coverage note:</strong> {self._escape_html(coverage_explanation)}
            </div>'''

        # Payload testing status (SOP #3 - never show a plain zero)
        payload_testing = stats.get('payload_testing', {})
        payload_display = payload_testing.get('display', stats.get('injection_payloads', 0))
        payload_reason = payload_testing.get('reason', '')
        payload_html = ""
        if payload_testing.get('status') == 'skipped':
            payload_html = f'''
            <div class="payload-status">
                <span class="ps-badge">Skipped</span>
                <span class="ps-reason">{self._escape_html(payload_reason)}</span>
            </div>'''

        # Attack surface
        skip_reasons_html = ""
        skip_reasons = stats.get('skip_reasons', {})
        if skip_reasons:
            items = "".join(f'<div class="skip-item"><span class="skip-reason">{self._escape_html(r)}</span><span class="skip-modules">{", ".join(m for m in mods[:5])}</span></div>' for r, mods in skip_reasons.items())
            skip_reasons_html = f'''
            <div class="skip-details">
                <h4>Skipped Modules Detail</h4>
                <div class="skip-grid">{items}</div>
            </div>'''

        skip_reasons_coverage = ""
        if skip_reasons:
            items = "".join(f'<div class="cs-item">- {self._escape_html(r)}: {", ".join(m for m in mods[:4])}</div>' for r, mods in skip_reasons.items())
            skip_reasons_coverage = f'<div class="coverage-skip-note"><strong>Skipped reasons:</strong>{items}</div>'

        crawl_stats = stats.get('crawl', {}) or {}
        attack_surface = f'''
        <div class="attack-surface">
            <div class="as-grid">
                <div class="as-item">
                    <div class="as-icon">{self._icon('link')}</div>
                    <div class="as-label">URLs Crawled</div>
                    <div class="as-value">{stats.get('pages_crawled', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('scan')}</div>
                    <div class="as-label">Modules Scanned</div>
                    <div class="as-value">{stats.get('total', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('server')}</div>
                    <div class="as-label">HTTP Requests</div>
                    <div class="as-value">{stats.get('requests_sent', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('zap')}</div>
                    <div class="as-label">Payloads Tested</div>
                    <div class="as-value">{payload_display}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('list')}</div>
                    <div class="as-label">Header Tests</div>
                    <div class="as-value">{stats.get('headers_tests', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('plug')}</div>
                    <div class="as-label">Port Tests</div>
                    <div class="as-value">{stats.get('port_tests', 0)}</div>
                </div>
            </div>
            <div class="as-sub">Crawl Discovery (Phase 2)</div>
            <div class="as-grid">
                <div class="as-item">
                    <div class="as-icon">{self._icon('globe')}</div>
                    <div class="as-label">URLs Discovered</div>
                    <div class="as-value">{crawl_stats.get('urls_discovered', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('lock')}</div>
                    <div class="as-label">Login Pages</div>
                    <div class="as-value">{crawl_stats.get('login_pages', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('shield')}</div>
                    <div class="as-label">Admin Pages</div>
                    <div class="as-value">{crawl_stats.get('admin_pages', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('code')}</div>
                    <div class="as-label">API Pages</div>
                    <div class="as-value">{crawl_stats.get('api_pages', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('mail')}</div>
                    <div class="as-label">Forms Found</div>
                    <div class="as-value">{crawl_stats.get('forms_discovered', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('file')}</div>
                    <div class="as-label">JS Files</div>
                    <div class="as-value">{crawl_stats.get('js_files', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('map')}</div>
                    <div class="as-label">Sitemap Entries</div>
                    <div class="as-value">{crawl_stats.get('sitemap_entries', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('bot')}</div>
                    <div class="as-label">Robots Entries</div>
                    <div class="as-value">{crawl_stats.get('robots_entries', 0)}</div>
                </div>
                <div class="as-item">
                    <div class="as-icon">{self._icon('repeat')}</div>
                    <div class="as-label">Duplicates</div>
                    <div class="as-value">{crawl_stats.get('duplicates', 0)}</div>
                </div>
            </div>
            {payload_html}
        </div>'''

        # Execution states section (SOP #4)
        states = stats.get('execution_states', {})
        state_details = states.get('details', [])
        state_rows = ""
        state_badge_class = {
            'passed': 'badge-safe', 'failed': 'badge-critical', 'skipped': 'badge-info',
            'not_applicable': 'badge-info', 'warning': 'badge-warning', 'info': 'badge-info',
        }
        for d in state_details:
            badge = state_badge_class.get(d.get('state'), 'badge-info')
            state_rows += f'''
                <tr>
                    <td>{self._escape_html(d.get('module', ''))}</td>
                    <td><span class="badge {badge}">{self._escape_html(d.get('label', d.get('state', '')))}</span></td>
                    <td>{d.get('tests', 0)}</td>
                    <td>{d.get('duration', 0):.2f}s</td>
                    <td>{self._escape_html(d.get('reason', ''))}</td>
                </tr>'''
        if state_details:
            execution_states_html = f'''
            <div class="attack-surface">
                <h3>Module Execution States</h3>
                <div class="exec-state-summary">
                    <span><strong>Passed:</strong> {states.get('passed', 0)}</span>
                    <span><strong>Failed:</strong> {states.get('failed', 0)}</span>
                    <span><strong>Warning:</strong> {states.get('warning', 0)}</span>
                    <span><strong>Skipped:</strong> {states.get('skipped', 0)}</span>
                    <span><strong>Not Applicable:</strong> {states.get('not_applicable', 0)}</span>
                    <span><strong>Info:</strong> {states.get('info', 0)}</span>
                </div>
                <div class="table-wrap">
                <table class="breakdown-table">
                    <thead><tr>
                        <th>Module</th><th>State</th><th>Tests</th><th>Duration</th><th>Reason</th>
                    </tr></thead>
                    <tbody>{state_rows}</tbody>
                </table>
                </div>
            </div>'''
        else:
            execution_states_html = ""
        
        # Authentication section (SOP Auth Phases 9/10)
        auth_html = self.build_auth_section(stats)

        # بناء الأقسام
        critical_html = self.build_finding_section("Critical Findings", critical, "critical")
        high_html = self.build_finding_section("High Findings", high, "high")
        medium_html = self.build_finding_section("Medium Findings", medium, "medium")
        low_html = self.build_finding_section("Low Findings", low, "low")
        warnings_html = self.build_warning_section(warnings)
        info_html = self.build_info_section(info)
        safe_html = self.build_safe_section(safe)

        # Try Jinja2 template rendering (cleaner, maintainable)
        try:
            from jinja2 import Environment, FileSystemLoader
            _env = Environment(loader=FileSystemLoader('templates'), autoescape=False)
            _template = _env.get_template('report.html.j2')
            return _template.render(
                target=target,
                company_name=self._escape_html(self.company_name),
                logo_url=self._escape_html(self.logo_url),
                client_name=self._escape_html(self.client_name),
                consultant_name=self._escape_html(self.consultant_name),
                report_id=self._escape_html(self.report_id),
                stats=stats,
                overall_severity=overall_severity,
                overall_color=overall_color,
                overall_description=self._escape_html(overall_description),
                overall_html=overall_html,
                risk=risk,
                exec_summary=exec_summary,
                attack_surface=attack_surface,
                auth_html=auth_html,
                risk_breakdown=risk_breakdown,
                skip_reasons_html=skip_reasons_html,
                skip_reasons_coverage=skip_reasons_coverage,
                critical_html=critical_html,
                high_html=high_html,
                medium_html=medium_html,
                low_html=low_html,
                warnings_html=warnings_html,
                info_html=info_html,
                safe_html=safe_html,
                execution_states_html=execution_states_html,
                standardized_labels_html=standardized_labels_html,
                coverage_explanation_html=coverage_explanation_html,
                payload_html=payload_html,
                payload_display=payload_display,
                payload_reason=self._escape_html(payload_reason),
                scanner_version=stats.get('scanner_version', '1.0.0'),
                engine_version=stats.get('engine_version', stats.get('scanner_version', '1.0.0')),
                detection_rules_version=stats.get('detection_rules_version', '1.0.0'),
                template_version=stats.get('template_version', '3.2'),
                report_version=stats.get('report_version', '2.0'),
                current_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        except (ImportError, Exception):
            pass

        # Fallback to inline template (kept for backward compatibility when Jinja2 not installed)
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {target} | {self.company_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f0f2f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.15);
        }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 36px; margin-bottom: 10px; }}
        .header .subtitle {{ opacity: 0.8; font-size: 18px; }}
        .header .meta {{
            margin-top: 15px;
            opacity: 0.7;
            font-size: 14px;
        }}
        .header .meta span {{ margin: 0 15px; }}
        
        .content {{ padding: 30px; }}
        
        /* Scan Summary */
        .scan-summary {{
            background: #f8f9fa;
            padding: 20px 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid #e9ecef;
        }}
        .scan-summary h2 {{
            margin-bottom: 15px;
            color: #1a1a2e;
            font-size: 20px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }}
        .summary-item {{
            background: white;
            padding: 10px 12px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .summary-item .label {{
            display: block;
            font-size: 10px;
            color: #888;
            margin-bottom: 3px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}
        .summary-item .value {{
            display: block;
            font-size: 17px;
            font-weight: bold;
            color: #1a1a2e;
        }}
        
        /* Coverage */
        .coverage-section {{
            background: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .coverage-section .coverage-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .coverage-section .coverage-header .title {{
            font-weight: bold;
            color: #1a1a2e;
        }}
        .coverage-section .coverage-header .percentage {{
            font-weight: bold;
            color: #1a1a2e;
        }}
        .coverage-bar {{
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
        }}
        .coverage-bar .fill {{
            height: 100%;
            background: linear-gradient(90deg, #4CAF50, #2196F3);
            border-radius: 4px;
            transition: width 1s;
            width: 0%;
        }}
        .coverage-footer {{
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: #888;
            margin-top: 4px;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 10px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 12px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #4CAF50;
        }}
        .stat-card .number {{ font-size: 24px; font-weight: bold; }}
        .stat-card .label {{ color: #666; font-size: 12px; margin-top: 2px; }}
        .stat-card.critical {{ border-left-color: #f44336; }}
        .stat-card.high {{ border-left-color: #FF9800; }}
        .stat-card.medium {{ border-left-color: #FFC107; }}
        .stat-card.low {{ border-left-color: #4CAF50; }}
        .stat-card.safe {{ border-left-color: #2196F3; }}
        .stat-card.info {{ border-left-color: #9E9E9E; }}
        .stat-card.warning {{ border-left-color: #FF9800; }}
        
        /* Risk Meter */
        .risk-meter {{
            background: #f8f9fa;
            padding: 20px 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid #e9ecef;
        }}
        .risk-meter .title {{
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 5px;
            color: #1a1a2e;
        }}
        .risk-meter .score-row {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            margin: 8px 0;
        }}
        .risk-meter .score {{
            font-size: 32px;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .risk-meter .rating {{
            font-size: 20px;
            font-weight: bold;
        }}
        .risk-meter .sub-label {{
            font-size: 14px;
            color: #888;
        }}
        .meter-bar {{
            height: 28px;
            background: #e9ecef;
            border-radius: 14px;
            overflow: hidden;
            margin-top: 10px;
        }}
        .meter-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4CAF50, #FFC107, #f44336);
            transition: width 1s ease;
            border-radius: 14px;
            width: 0%;
        }}
        .meter-labels {{
            display: flex;
            justify-content: space-between;
            color: #888;
            font-size: 12px;
            margin-top: 4px;
        }}
        .risk-note {{
            margin-top: 12px;
            padding: 12px 16px;
            background: #f0f4f8;
            border-radius: 8px;
            font-size: 13px;
            color: #555;
            border-left: 4px solid #1a1a2e;
        }}
        
        /* Finding Sections */
        .finding-section {{ margin-bottom: 30px; }}
        .finding-section .section-title {{
            padding: 10px 16px;
            border-radius: 10px;
            margin-bottom: 12px;
            font-size: 17px;
            font-weight: bold;
        }}
        .finding-card {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px 18px;
            margin-bottom: 10px;
            border-left: 4px solid #666;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .finding-card .title {{
            font-size: 15px;
            font-weight: bold;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
        }}
        .finding-card .detail {{ margin: 3px 0; color: #444; font-size: 13px; }}
        .finding-card .detail strong {{ color: #1a1a2e; }}
        .finding-card .evidence {{
            background: white;
            padding: 8px 12px;
            border-radius: 6px;
            margin: 6px 0;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            border: 1px solid #e0e0e0;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 150px;
            overflow-y: auto;
        }}
        
        /* Confidence Breakdown */
        .confidence-breakdown {{
            background: #f5f7fa;
            padding: 10px 14px;
            border-radius: 6px;
            margin: 6px 0;
            font-size: 13px;
            border: 1px solid #e9ecef;
        }}
        .confidence-breakdown .factors {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin: 4px 0;
        }}
        .confidence-breakdown .factor {{
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
        }}
        .confidence-breakdown .factor.positive {{
            background: #c8e6c9;
            color: #2e7d32;
        }}
        .confidence-breakdown .factor.negative {{
            background: #ffcdd2;
            color: #c62828;
        }}
        .confidence-breakdown .final {{
            margin-top: 4px;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .confidence-breakdown .final span {{
            color: #2196F3;
        }}
        
        /* Executive Summary */
        .executive-summary {{
            padding: 20px 25px;
            border-radius: 12px;
            margin-bottom: 20px;
            border-left: 6px solid #333;
        }}
        .executive-summary h3 {{ margin-bottom: 8px; font-size: 18px; }}
        .executive-summary p {{ font-size: 14px; line-height: 1.6; }}
        .executive-summary.critical-summary {{
            background: #fef2f2;
            border-left-color: #f44336;
        }}
        .executive-summary.medium-summary {{
            background: #fffbeb;
            border-left-color: #f59e0b;
        }}
        .executive-summary.safe-summary {{
            background: #f0fdf4;
            border-left-color: #22c55e;
        }}
        
        /* Attack Surface */
        .attack-surface {{
            background: #f8f9fa;
            padding: 20px 25px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid #e9ecef;
        }}
        .attack-surface h3 {{ margin-bottom: 12px; font-size: 18px; color: #1a1a2e; }}
        .as-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 10px;
        }}
        .as-item {{
            background: white;
            padding: 12px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .as-icon {{ font-size: 24px; margin-bottom: 4px; }}
        .as-label {{ font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 0.3px; }}
        .as-value {{ font-size: 18px; font-weight: bold; color: #1a1a2e; }}

        /* Phase 2 Crawl Discovery sub-header */
        .as-sub {{ margin-top: 16px; margin-bottom: 2px; font-size: 12px; font-weight: 600;
                    color: #6a11cb; letter-spacing: 0.4px; text-transform: uppercase; }}
        
        /* Risk Breakdown Table */
        .risk-breakdown {{
            margin-top: 15px;
            padding: 12px 16px;
            background: #f5f7fa;
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }}
        .breakdown-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        .breakdown-table th {{
            background: #e9ecef;
            padding: 6px 10px;
            text-align: left;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
        }}
        .breakdown-table td {{
            padding: 5px 10px;
            border-bottom: 1px solid #e9ecef;
        }}

        /* Verification Badges */
        .vbadge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .vbadge-verified {{ background: #c8e6c9; color: #2e7d32; }}
        .vbadge-likely {{ background: #fff9c4; color: #f57f17; }}
        .vbadge-possible {{ background: #ffe0b2; color: #e65100; }}
        .vbadge-manual {{ background: #ffcdd2; color: #c62828; }}
        .vbadge-unverified {{ background: #e0e0e0; color: #616161; }}

        /* Finding Timeline */
        .timeline {{
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 2px;
            margin: 8px 0;
            padding: 6px 8px;
            background: #f5f7fa;
            border-radius: 6px;
            font-size: 9px;
        }}
        .tl-step {{
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            white-space: nowrap;
        }}
        .tl-discovery {{ background: #e3f2fd; color: #1565c0; }}
        .tl-scan {{ background: #f3e5f5; color: #7b1fa2; }}
        .tl-evidence {{ background: #e8f5e9; color: #2e7d32; }}
        .tl-decision {{ background: #fff3e0; color: #e65100; }}
        .tl-risk {{ background: #ffebee; color: #c62828; }}
        .tl-final {{ background: #1a1a2e; color: white; }}
        .tl-arrow {{
            color: #999;
            font-weight: bold;
            padding: 0 2px;
        }}
        .tl-arrow::before {{ content: ">"; }}

        /* Collapsible HTTP Evidence */
        .http-block {{
            margin: 4px 0;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            overflow: hidden;
        }}
        .http-title {{
            padding: 6px 10px;
            background: #f5f5f5;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            font-weight: bold;
            user-select: none;
        }}
        .http-title:hover {{ background: #eeeeee; }}
        .http-method {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            background: #1565c0;
            color: white;
            font-size: 10px;
        }}
        .http-status {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            background: #2e7d32;
            color: white;
            font-size: 10px;
        }}
        .http-url {{ color: #555; font-size: 11px; flex: 1; overflow: hidden; text-overflow: ellipsis; }}
        .http-len {{ color: #888; font-size: 10px; }}
        .toggle-icon {{ color: #999; font-weight: bold; margin-left: auto; }}
        .http-detail {{
            padding: 8px 10px;
            margin: 0;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 11px;
            background: #fafafa;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow: auto;
        }}
        .http-detail.collapsed {{ display: none; }}

        .evidence-block {{
            margin: 4px 0;
        }}
        .evidence-block .url-list {{
            margin: 4px 0 4px 16px;
            font-size: 12px;
        }}
        .evidence-block .url-list a {{ color: #1565c0; }}

        /* Attack Surface */
        .as-cols {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
        }}
        .as-section {{
            margin-bottom: 12px;
        }}
        .as-section h4 {{
            font-size: 13px;
            color: #1a1a2e;
            margin-bottom: 6px;
            padding-bottom: 4px;
            border-bottom: 1px solid #e9ecef;
        }}
        .as-metric {{
            display: flex;
            justify-content: space-between;
            padding: 2px 0;
            font-size: 12px;
        }}
        .as-metric .as-label {{ color: #666; }}
        .as-metric .as-value {{ font-weight: bold; color: #1a1a2e; }}
        .tech-item {{
            display: inline-block;
            padding: 2px 8px;
            margin: 2px;
            background: #e3f2fd;
            border-radius: 4px;
            font-size: 11px;
        }}

        /* Skip Details */
        .skip-details {{
            margin-top: 10px;
            padding: 10px;
            background: #fff8e1;
            border-radius: 6px;
            border: 1px solid #ffe082;
        }}
        .skip-details h4 {{ font-size: 13px; margin-bottom: 6px; color: #f57f17; }}
        .skip-grid {{
            display: grid;
            gap: 4px;
        }}
        .skip-item {{
            display: flex;
            gap: 8px;
            font-size: 12px;
            padding: 2px 4px;
        }}
        .skip-reason {{ font-weight: bold; min-width: 180px; }}
        .skip-modules {{ color: #666; }}

        /* Safe Item Enhanced */
        .safe-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 8px;
        }}
        .safe-item {{
            background: #e8f5e9;
            padding: 10px 12px;
            border-radius: 8px;
            border: 1px solid #c8e6c9;
        }}
        .safe-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }}
        .safe-name {{ font-weight: bold; font-size: 13px; }}
        .safe-badge {{
            font-size: 9px;
            padding: 1px 6px;
            border-radius: 8px;
            background: #4CAF50;
            color: white;
            text-transform: uppercase;
        }}
        .safe-meta {{
            display: flex;
            gap: 10px;
            font-size: 11px;
            color: #555;
            margin-bottom: 2px;
        }}
        .safe-note {{ font-size: 11px; color: #666; }}
        .safe-urls {{ font-size: 10px; color: #888; margin-top: 2px; }}

        /* Executive Summary Meta */
        .exec-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 8px;
            font-size: 12px;
            color: #555;
        }}
        .exec-meta span {{ background: rgba(255,255,255,0.7); padding: 2px 8px; border-radius: 4px; }}

        /* Severity Dot */
        .sev-dot {{
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 4px;
        }}
        .sev-critical {{ background: #f44336; }}
        .sev-high {{ background: #FF9800; }}
        .sev-medium {{ background: #FFC107; }}
        .sev-low {{ background: #4CAF50; }}
        .sev-none {{ background: #2196F3; }}

        /* Dark Mode */
        @media (prefers-color-scheme: dark) {{
            body {{ background: #121212; }}
            .container {{ background: #1e1e1e; }}
            .scan-summary, .risk-meter, .attack-surface {{ background: #2a2a2a; border-color: #333; }}
            .summary-item, .as-item, .stat-card {{ background: #333; }}
            .summary-item .value, .stat-card .number, .as-value, .risk-meter .score {{
                color: #e0e0e0;
            }}
            .finding-card {{ background: #2a2a2a; }}
            .finding-card .detail {{ color: #ccc; }}
            .confidence-breakdown {{ background: #333; }}
            .evidence {{ background: #1a1a1a; border-color: #444; }}
            .http-detail {{ background: #1a1a1a; color: #ccc; }}
            .http-title {{ background: #333; }}
            .http-title:hover {{ background: #3a3a3a; }}
            .risk-breakdown {{ background: #2a2a2a; }}
            .breakdown-table th {{ background: #333; }}
            .breakdown-table td {{ border-color: #444; }}
            .section-title {{ color: #1a1a2e; }}
            .safe-item {{ background: #1b3d1b; border-color: #2e7d32; }}
            .safe-name, .safe-meta {{ color: #c8e6c9; }}
            .warning-item {{ background: #3d2e1b; border-color: #e65100; }}
            .info-item {{ background: #333; }}
            .exec-meta span {{ background: rgba(0,0,0,0.3); }}
            .skip-details {{ background: #3d2e00; border-color: #f57f17; }}
            .timeline {{ background: #333; }}
            .as-metric .as-label {{ color: #aaa; }}
            .as-metric .as-value {{ color: #e0e0e0; }}
            .coverage-section {{ background: #333; }}
            .coverage-section .coverage-header .title, .coverage-section .coverage-header .percentage {{ color: #e0e0e0; }}
            .http-url {{ color: #aaa; }}
        }}

        /* Print-friendly */
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; border-radius: 0; }}
            .header {{ padding: 20px; }}
            .content {{ padding: 15px; }}
            .finding-card {{ break-inside: avoid; }}
            .http-detail {{ max-height: none; }}
            .http-detail.collapsed {{ display: block; }}
            .toggle-icon {{ display: none; }}
        }}
        
        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 10px;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #f44336; }}
        .badge-high {{ background: #FF9800; }}
        .badge-medium {{ background: #FFC107; color: #1a1a2e; }}
        .badge-low {{ background: #4CAF50; }}
        .badge-safe {{ background: #2196F3; }}
        .badge-info {{ background: #9E9E9E; }}
        .badge-warning {{ background: #FF9800; }}
        
        /* Safe Grid */
        .safe-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 8px;
        }}
        .safe-item {{
            background: #e8f5e9;
            padding: 10px 12px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #c8e6c9;
        }}
        .safe-item .name {{ font-weight: bold; font-size: 13px; }}
        .safe-item .note {{ font-size: 11px; color: #666; margin-top: 2px; }}
        
        /* Warning Grid */
        .warning-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 8px;
        }}
        .warning-item {{
            background: #fff3e0;
            padding: 10px 12px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #ffe0b2;
        }}
        .warning-item .name {{ font-weight: bold; font-size: 13px; }}
        .warning-item .note {{ font-size: 11px; color: #666; margin-top: 2px; }}
        
        /* Info Grid */
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 8px;
        }}
        .info-item {{
            background: #f5f5f5;
            padding: 10px 12px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e0e0e0;
        }}
        .info-item .name {{ font-weight: bold; font-size: 13px; }}
        .info-item .note {{ font-size: 11px; color: #666; margin-top: 2px; }}
        
        /* Branding */
        .header-branding {{
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
        }}
        .header-logo {{
            max-height: 64px;
            max-width: 240px;
            margin-bottom: 8px;
        }}

        /* Copy Button */
        .copy-btn {{
            display: inline-block;
            padding: 4px 12px;
            background: #e9ecef;
            border: 1px solid #ccc;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            font-family: inherit;
            color: #333;
            margin-left: 8px;
            transition: background 0.2s;
        }}
        .copy-btn:hover {{ background: #d0d4d8; }}
        .copy-btn:active {{ background: #b0b4b8; }}
        .copy-feedback {{
            display: inline-block;
            font-size: 10px;
            color: #4CAF50;
            margin-left: 6px;
            opacity: 0;
            transition: opacity 0.3s;
        }}
        .copy-feedback.show {{ opacity: 1; }}

        /* Replay Section */
        .replay-section {{
            margin: 8px 0;
            padding: 10px 12px;
            background: #f5f7fa;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }}
        .replay-section h4 {{
            font-size: 12px;
            color: #1a1a2e;
            margin-bottom: 6px;
        }}
        .replay-curl {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 11px;
            background: #1a1a1a;
            color: #c8e6c9;
            padding: 8px 10px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-break: break-all;
            margin: 4px 0;
        }}
        .replay-data-block {{
            margin: 4px 0;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 11px;
            background: #fafafa;
            padding: 6px 8px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 200px;
            overflow: auto;
            border: 1px solid #e0e0e0;
        }}

        @media (prefers-color-scheme: dark) {{
            .replay-section {{ background: #2a2a2a; border-color: #444; }}
            .replay-data-block {{ background: #1a1a1a; color: #ccc; }}
            .copy-btn {{ background: #444; border-color: #666; color: #ccc; }}
            .copy-btn:hover {{ background: #555; }}
        }}

        /* Footer */
        .footer {{
            background: #1a1a2e;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 13px;
            opacity: 0.8;
        }}

        /* SOP additions */
        .risk-explanation {{
            margin-top: 8px;
            padding: 8px 12px;
            background: #fafafa;
            border-radius: 6px;
            border: 1px solid #e9ecef;
        }}
        .risk-explanation h4 {{ font-size: 12px; color: #1a1a2e; margin-bottom: 4px; }}
        .risk-explanation ul {{ margin: 0 0 0 18px; font-size: 12px; color: #555; }}
        .risk-explanation li {{ margin: 2px 0; }}
        .coverage-explain {{ margin-top: 6px; padding: 6px 8px; background: #e8f5e9; border-radius: 4px; font-size: 11px; color: #444; }}
        .payload-status {{ margin-top: 8px; padding: 8px 12px; background: #fff8e1; border-radius: 6px; border: 1px solid #ffe082; font-size: 12px; display: flex; gap: 8px; align-items: center; }}
        .ps-badge {{ background: #f57f17; color: white; padding: 2px 10px; border-radius: 10px; font-size: 10px; font-weight: bold; text-transform: uppercase; }}
        .ps-reason {{ color: #555; }}
        .standardized-labels {{
            display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
            padding: 10px 14px; background: #f5f7fa; border-radius: 8px;
            border: 1px solid #e9ecef; margin-bottom: 20px; font-size: 11px;
        }}
        .sl-title {{ font-weight: bold; color: #1a1a2e; }}
        .label-chip {{ background: white; border: 1px solid #ddd; border-radius: 12px; padding: 2px 10px; color: #555; }}
        .exec-state-summary {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 10px; font-size: 12px; color: #555; }}
        .exec-state-summary span {{ background: #f0f4f8; padding: 2px 10px; border-radius: 4px; }}
        .warning-state {{ display: inline-block; margin-left: 6px; padding: 1px 8px; border-radius: 10px; background: #fff3e0; color: #e65100; font-size: 10px; font-weight: bold; }}
        .warning-verif {{ font-size: 10px; color: #888; margin-top: 2px; }}

        /* Authentication section (SOP Auth) */
        .auth-section {{
            background: #f8f9fa; padding: 18px 22px; border-radius: 12px;
            border: 1px solid #e9ecef; margin-bottom: 20px;
        }}
        .auth-section h3 {{ margin-bottom: 12px; font-size: 16px; color: #1a1a2e; }}
        .auth-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 8px; margin-bottom: 12px;
        }}
        .auth-item {{
            background: white; padding: 8px 10px; border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .auth-label {{ display: block; font-size: 10px; color: #888; text-transform: uppercase; letter-spacing: 0.3px; }}
        .auth-value {{ display: block; font-size: 15px; font-weight: bold; color: #1a1a2e; margin-top: 2px; }}
        .auth-coverage {{
            background: #f0f4f8; border-radius: 8px; padding: 10px 12px; margin: 8px 0;
        }}
        .auth-coverage-row {{ display: flex; gap: 18px; font-size: 12px; color: #444; flex-wrap: wrap; }}
        .auth-coverage-bar {{ height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; margin-top: 8px; }}
        .auth-coverage-fill {{ height: 100%; background: linear-gradient(90deg, #FF9800, #f44336); border-radius: 4px; }}
        .auth-session {{ font-size: 12px; color: #444; margin: 6px 0; }}
        .auth-token-note {{ color: #888; }}
        .auth-reason {{ font-size: 12px; color: #555; margin: 2px 0; }}
        .auth-area {{ font-size: 12px; color: #555; }}

        @media (max-width: 600px) {{
            .stats-grid {{ grid-template-columns: repeat(3, 1fr); }}
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .header h1 {{ font-size: 24px; }}
            .risk-meter .score {{ font-size: 24px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-branding">
                {f'<img src="{self._escape_html(self.logo_url)}" alt="Logo" class="header-logo">' if self.logo_url else ''}
                <h1>{self._escape_html(self.company_name)}</h1>
                <div class="subtitle">Security Assessment Report</div>
            </div>
            <div class="meta">
                <span>Target: {target}</span>
                {f'<span>Client: {self._escape_html(self.client_name)}</span>' if self.client_name else ''}
                {f'<span>Consultant: {self._escape_html(self.consultant_name)}</span>' if self.consultant_name else ''}
                {f'<span>Report ID: {self._escape_html(self.report_id)}</span>' if self.report_id else ''}
                <span>Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
                <span>Version: v{stats.get('scanner_version', '1.0.0')}</span>
                <span>Overall: {overall_html}</span>
            </div>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            {exec_summary}
            
            <!-- Attack Surface -->
            {attack_surface}

            <!-- Authentication -->
            {auth_html}
            
            <!-- Scan Summary -->
            <div class="scan-summary">
                <h2>📋 Scan Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item">
                        <span class="label">Scanner Engine</span>
                        <span class="value">v{stats.get('engine_version', stats.get('scanner_version', '1.0.0'))}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Detection Rules</span>
                        <span class="value">v{stats.get('detection_rules_version', '1.0.0')}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Report Template</span>
                        <span class="value">v{stats.get('template_version', '3.2')}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">HTTP Requests</span>
                        <span class="value">{stats.get('requests_sent', 0)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Payloads Executed</span>
                        <span class="value">{stats.get('payload_testing', {}).get('display', stats.get('injection_payloads', 0))}</span>
                    </div>
                    {f'<div style="grid-column: 1 / -1; font-size: 11px; color: #888; margin-top: -5px; padding: 0 10px;">Reason: {self._escape_html(stats.get("payload_testing", {}).get("reason", ""))}</div>' if stats.get('payload_testing', {}).get('status') == 'skipped' else ''}
                    <div class="summary-item">
                        <span class="label">Headers Tests</span>
                        <span class="value">{stats.get('headers_tests', 0)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Port Tests</span>
                        <span class="value">{stats.get('port_tests', 0)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Duration</span>
                        <span class="value">{stats.get('duration', 0):.1f}s</span>
                    </div>
                </div>
                
                <!-- Coverage -->
                <div class="coverage-section">
                    <div class="coverage-header">
                        <span class="title">Coverage</span>
                        <span class="percentage">{stats.get('coverage_percentage', 0)}%</span>
                    </div>
                    <div class="coverage-bar">
                        <div class="fill" style="width: {stats.get('coverage_percentage', 0)}%;"></div>
                    </div>
                    <div class="coverage-footer">
                        <span>{stats.get('coverage_executed', 0)} / {stats.get('coverage_total', 0)} Modules Executed</span>
                        <span>{stats.get('coverage_skipped', 0)} Skipped</span>
                        <span>{stats.get('coverage_failed', 0)} Failed</span>
                        <span>{stats.get('coverage_not_applicable', 0)} N/A</span>
                    </div>
                    {f'<div style="margin-top:6px;padding:6px 8px;background:#e8f5e9;border-radius:4px;font-size:11px;color:#444;"><strong>Coverage note:</strong> {self._escape_html(stats.get("coverage_explanation", ""))}</div>' if stats.get('coverage_explanation') else ''}
                    {skip_reasons_coverage}
                </div>
            </div>
            
            {execution_states_html}
            {standardized_labels_html}
            {payload_html}
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="number">{stats.get('critical', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{stats.get('high', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{stats.get('medium', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{stats.get('low', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card warning">
                    <div class="number">{stats.get('warning', 0)}</div>
                    <div class="label">Warnings</div>
                </div>
                <div class="stat-card info">
                    <div class="number">{stats.get('info', 0)}</div>
                    <div class="label">Info</div>
                </div>
                <div class="stat-card safe">
                    <div class="number">{stats.get('safe', 0)}</div>
                    <div class="label">Passed</div>
                </div>
            </div>
            
            <!-- Risk Meter -->
            <div class="risk-meter">
                <div class="title">Risk Assessment</div>
                <div class="score-row">
                    <div>
                        <div class="sub-label">Risk Score</div>
                        <span class="score">{risk}%</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="sub-label">Overall Severity</div>
                        <span class="rating" style="color: {overall_color};">{overall_html}</span>
                    </div>
                </div>
                <div class="meter-bar">
                    <div class="meter-fill" style="width: {risk}%;"></div>
                </div>
                <div class="meter-labels">
                    <span>Low Risk</span>
                    <span>High Risk</span>
                </div>
                <div class="risk-note">
                    {overall_description}
                </div>
                {risk_breakdown}
            </div>
            
            <!-- Findings Sections -->
            {critical_html}
            {high_html}
            {medium_html}
            {low_html}
            {warnings_html}
            {info_html}
            {safe_html}
        </div>
        
        <div class="footer">
            {self._escape_html(self.company_name)} v{stats.get('scanner_version', '1.0.0')} | Security Assessment Report | Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{f' | Report ID: {self._escape_html(self.report_id)}' if self.report_id else ''}
        </div>
    </div>
    <script>
        function copyReplay(btn) {{
            var parent = btn.parentElement.parentElement;
            var curlDiv = parent.querySelector('.replay-curl');
            if (!curlDiv) return;
            var text = curlDiv.textContent.trim();
            if (!text) return;
            if (navigator.clipboard) {{
                if (navigator.clipboard.writeText) {{
                    navigator.clipboard.writeText(text).then(function() {{
                        var fb = btn.nextElementSibling;
                        if (fb) {{ fb.classList.add('show'); setTimeout(function() {{ fb.classList.remove('show'); }}, 1500); }}
                    }}).catch(function() {{ fallbackCopy(text, btn); }});
                    return;
                }}
            }}
            fallbackCopy(text, btn);
        }}
        function fallbackCopy(text, btn) {{
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            try {{
                document.execCommand('copy');
                var fb = btn.nextElementSibling;
                if (fb) {{ fb.classList.add('show'); setTimeout(function() {{ fb.classList.remove('show'); }}, 1500); }}
            }} catch(e) {{}}
            document.body.removeChild(ta);
        }}
    </script>
</body>
</html>'''
    
    def build_finding_section(self, title, findings, severity_class):
        if not findings:
            return ""

        cards = ""
        for f in findings:
            try:
                evidence = self._escape_html(self._format_evidence(f))
                reason = self._escape_html(f.reason or "No reason provided")
                recommendation = self._escape_html(f.recommendation or "No recommendation provided")
                module = self._escape_html(f.module or "")

                # Verification badge
                vstatus = f.verification_status if hasattr(f, 'verification_status') else "unverified"
                vlabel = getattr(f, 'verification_label', vstatus)
                vbadge_map = {'verified': 'vbadge-verified', 'likely': 'vbadge-likely', 'possible': 'vbadge-possible', 'manual_review': 'vbadge-manual', 'unverified': 'vbadge-unverified'}
                vclass = vbadge_map.get(vstatus, 'vbadge-unverified')

                # Confidence breakdown
                confidence_breakdown = ""
                if hasattr(f, 'confidence_factors') and f.confidence_factors:
                    factors = []
                    for key, value in f.confidence_factors.items():
                        fclass = "positive" if value > 0 else "negative"
                        factors.append(f'<span class="factor {fclass}">{value:+d} {key}</span>')
                    if factors:
                        confidence_breakdown = f'''
                    <div class="confidence-breakdown">
                        <strong>Confidence:</strong>
                        <div class="factors">
                            {" ".join(factors)}
                        </div>
                        <div class="final">Final: <span>{f.confidence}%</span></div>
                    </div>'''

                # Confidence explanation (SOP #9 - no mystery percentages)
                confidence_explanation_html = ""
                if getattr(f, 'confidence_explanation', ''):
                    confidence_explanation_html = (
                        f'<div class="detail"><strong>Confidence explained:</strong> '
                        f'{self._escape_html(f.confidence_explanation)}</div>'
                    )

                # Matched rules / indicators (SOP #9)
                matched_rules = getattr(f, 'matched_rules', []) or []
                matched_rules_html = ""
                if matched_rules:
                    rules_items = "".join(
                        f'<li>{self._escape_html(r)}</li>' for r in matched_rules[:5]
                    )
                    matched_rules_html = f'''
                    <div class="evidence-block">
                        <strong>Matched indicators ({len(matched_rules)}):</strong>
                        <ul class="url-list">{rules_items}</ul>
                    </div>'''

                evidence_count = len(getattr(f, 'evidence', []) or [])

                # Affected URLs
                affected_urls_html = ""
                if hasattr(f, 'affected_urls') and f.affected_urls:
                    urls_html = "".join(f'<li><a href="{self._escape_html(u)}" target="_blank">{self._escape_html(u)}</a></li>' for u in f.affected_urls[:10])
                    count = len(f.affected_urls)
                    affected_urls_html = f'''
                    <div class="evidence-block">
                        <strong>Affected URLs ({count}):</strong>
                        <ul class="url-list">{urls_html}</ul>
                    </div>'''

                # Finding timeline
                timeline = f'''
                <div class="timeline">
                    <div class="tl-step tl-discovery">Discovery</div>
                    <div class="tl-arrow"></div>
                    <div class="tl-step tl-scan">Scanner</div>
                    <div class="tl-arrow"></div>
                    <div class="tl-step tl-evidence">Evidence ({vstatus})</div>
                    <div class="tl-arrow"></div>
                    <div class="tl-step tl-decision">Decision</div>
                    <div class="tl-arrow"></div>
                    <div class="tl-step tl-risk">Risk</div>
                    <div class="tl-arrow"></div>
                    <div class="tl-step tl-final">Classification</div>
                </div>'''

                # Collapsible evidence (native <details> — accessible, no JS)
                request_html = ""
                response_html = ""
                raw_data_html = ""
                for ev in f.evidence:
                    raw = getattr(ev, 'raw_data', {}) or {}
                    req = raw.get('request', {})
                    resp = raw.get('response', {})
                    if req:
                        req_headers = "\n".join(f"{k}: {v}" for k, v in req.get('headers', {}).items())
                        request_html = f'''
                        <details class="http-block">
                            <summary class="http-title">
                                <span class="http-method">{req.get('method', 'GET')}</span>
                                <span class="http-url">{self._escape_html(req.get('url', ''))}</span>
                                <span class="toggle-icon">▾</span>
                            </summary>
                            <pre class="http-detail">{self._escape_html(req_headers)}
                            {self._escape_html('Payload: ' + str(req.get('payload', ''))) if req.get('payload') else ''}</pre>
                        </details>'''
                    if resp:
                        resp_headers = "\n".join(f"{k}: {v}" for k, v in resp.get('headers', {}).items())
                        snippet = resp.get('body_snippet', '')[:300]
                        response_html = f'''
                        <details class="http-block">
                            <summary class="http-title">
                                <span class="http-status">HTTP {resp.get('status_code', '?')}</span>
                                <span class="http-len">{resp.get('body_length', 0)} bytes</span>
                                <span class="toggle-icon">▾</span>
                            </summary>
                            <pre class="http-detail">{self._escape_html(resp_headers)}
                            {self._escape_html(snippet)}</pre>
                        </details>'''

                # Matched pattern
                match_info = ""
                for ev in f.evidence:
                    desc = getattr(ev, 'description', '') or ''
                    payload = getattr(ev, 'payload', None)
                    if payload:
                        match_info = f'''
                        <div class="evidence-block">
                            <strong>Matched Pattern:</strong> <code>{self._escape_html(desc[:120])}</code>
                            <br><strong>Payload:</strong> <code>{self._escape_html(str(payload)[:120])}</code>
                        </div>'''
                        break

                # Replay section
                replay_html = ""
                if hasattr(f, 'verify_commands') and f.verify_commands:
                    commands_list = "".join(
                        f'<div class="replay-curl">{self._escape_html(cmd)}</div>'
                        for cmd in f.verify_commands[:3]
                    )
                    replay_html = f'''
                    <div class="replay-section">
                        <h4>Verification Replay <button class="copy-btn" onclick="copyReplay(this)">Copy curl</button><span class="copy-feedback">Copied!</span></h4>
                        {commands_list}
                    </div>'''

                cards += f'''
            <div class="finding-card finding-{severity_class}">
                <div class="title">
                    <span>{module}</span>
                    <span class="badge badge-{severity_class}">{f.severity.value.upper()}</span>
                    <span class="vbadge {vclass}">{self._escape_html(vlabel)}</span>
                </div>
                {timeline}
                <div class="reason-box"><strong>Summary:</strong> {reason}</div>
                <div>
                    <div class="detail"><strong>Confidence:</strong> {f.confidence}%</div>
                    <div class="detail"><strong>Evidence items:</strong> {evidence_count}</div>
                    <div class="detail"><strong>Verification:</strong> {self._escape_html(vlabel)}</div>
                    <div class="detail"><strong>Occurrences:</strong> {f.occurrences}</div>
                    <div class="detail"><strong>CVSS:</strong> {f.cvss_score} ({self._escape_html(f.cvss_vector) or 'N/A'})</div>
                    <div class="detail"><strong>Tests:</strong> {f.tests_performed}</div>
                </div>
                {confidence_explanation_html}
                {confidence_breakdown}
                {matched_rules_html}
                {affected_urls_html}
                {match_info}
                {request_html}
                {response_html}
                {replay_html}
                <details class="evidence-block">
                    <summary><strong>Evidence</strong> <span class="toggle-icon">▾</span></summary>
                    <pre class="http-detail"><strong>Evidence:</strong> {evidence}</pre>
                </details>
                <div class="recommend-box"><strong>Remediation:</strong> {recommendation}</div>
            </div>'''
            except Exception as e:
                continue

        return f'''
        <div class="finding-section">
            <div class="section-title section-{severity_class}">
                <span class="st-label">{title}</span>
                <span class="st-count">{len(findings)}</span>
            </div>
            {cards}
        </div>'''
    
    def build_warning_section(self, findings):
        if not findings:
            return ""

        items = ""
        for f in findings:
            try:
                reason = self._escape_html(f.reason or "Warning")
                confidence = f.confidence if hasattr(f, 'confidence') else 0
                decision = getattr(f, 'execution_label', 'Warning')
                verification = getattr(f, 'verification_label', f.verification_status)
                items += f'''
                <div class="warning-item">
                    <div class="warning-header">
                        <span class="warning-name">{self._escape_html(f.module)}</span>
                        <span class="warning-conf">{confidence}%</span>
                        <span class="warning-state">{self._escape_html(decision)}</span>
                    </div>
                    <div class="warning-note">{reason[:80]}</div>
                    <div class="warning-verif">Verification: {self._escape_html(verification)}</div>
                </div>'''
            except Exception:
                continue

        return f'''
        <div class="finding-section">
            <div class="section-title section-warning">
                <span class="st-label">Warnings</span>
                <span class="st-count">{len(findings)}</span>
            </div>
            <div class="warning-grid">
                {items}
            </div>
        </div>'''

    def build_safe_section(self, findings):
        """بناء قسم النتائج الآمنة (Passed Checks)"""
        if not findings:
            return ""

        items = ""
        for f in findings:
            try:
                reason = self._escape_html(f.reason or "Passed")
                pages = f.occurrences if hasattr(f, 'occurrences') and f.occurrences > 1 else 1
                tests = f.tests_performed
                decision = getattr(f, 'execution_label', 'Passed')
                duration = getattr(f, 'duration', 0) or 0
                evidence_count = len(getattr(f, 'evidence', []) or [])
                urls = ""
                if hasattr(f, 'affected_urls') and f.affected_urls:
                    url_list = "; ".join(f.affected_urls[:3])
                    if len(f.affected_urls) > 3:
                        url_list += f" (+{len(f.affected_urls)-3})"
                    urls = f'<div class="safe-urls">{self._escape_html(url_list)}</div>'
                items += f'''
                <div class="safe-item">
                    <div class="safe-header">
                        <span class="safe-name">{self._escape_html(f.module)}</span>
                        <span class="safe-badge">{self._escape_html(decision)}</span>
                    </div>
                    <div class="safe-meta">
                        <span>Tests: {tests}</span>
                        <span>Evidence: {evidence_count}</span>
                        <span>Time: {duration:.2f}s</span>
                    </div>
                    <div class="safe-note">{reason[:80]}</div>
                    {urls}
                </div>'''
            except Exception:
                continue

        return f'''
        <div class="finding-section">
            <div class="section-title section-safe">
                <span class="st-label">Passed Checks</span>
                <span class="st-count">{len(findings)}</span>
            </div>
            <div class="safe-grid">
                {items}
            </div>
        </div>'''
    
    def build_info_section(self, findings):
        if not findings:
            return ""

        items = ""
        for f in findings:
            try:
                reason = f.reason or "Information"
                items += f'''
                <div class="info-item">
                    <div class="info-header">
                        <span class="info-name">{f.module}</span>
                    </div>
                    <div class="info-note">{reason[:80]}</div>
                </div>'''
            except Exception:
                continue

        return f'''
        <div class="finding-section">
            <div class="section-title section-info">
                <span class="st-label">Information</span>
                <span class="st-count">{len(findings)}</span>
            </div>
            <div class="info-grid">
                {items}
            </div>
        </div>'''
    
    @staticmethod
    def _icon(name: str, size: int = 17) -> str:
        """Inline stroke-SVG icon (Lucide-style 24px grid) for the report UI.

        Presentation-only helper: no external assets, keeps generation fast and
        offline-safe. Icons inherit ``currentColor`` from the surrounding CSS.
        """
        icons = {
            'globe': '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/>',
            'link': '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
            'scan': '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
            'server': '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
            'zap': '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
            'list': '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
            'plug': '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-6 6 6 6 0 0 1-6-6V8z"/><path d="M12 17v5"/>',
            'lock': '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
            'shield': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
            'code': '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
            'mail': '<rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22 6 12 13 2 6"/>',
            'file': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
            'map': '<polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/>',
            'bot': '<path d="M12 8V4M8 8a4 4 0 0 1 8 0v4a4 4 0 0 1-8 0V8z"/><rect x="2" y="11" width="20" height="9" rx="2"/><line x1="6" y1="15" x2="6.01" y2="15"/><line x1="10" y1="15" x2="10.01" y2="15"/><path d="M8 20v2m8-2v2"/>',
            'repeat': '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
        }
        body = icons.get(name, icons['scan'])
        return (f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" '
                f'aria-hidden="true">{body}</svg>')

    def get_color(self, severity):
        """الحصول على لون حسب مستوى الخطورة"""
        colors = {
            'critical': '#f44336',
            'high': '#FF9800',
            'medium': '#FFC107',
            'low': '#4CAF50',
            'safe': '#2196F3',
            'info': '#9E9E9E',
            'warning': '#FF9800'
        }
        return colors.get(severity, '#666')

    @staticmethod
    def _render_list(items, css_class="list-item", max_items=20):
        if not items:
            return ""
        result = ""
        for i in items[:max_items]:
            result += f'<div class="{css_class}">{i}</div>'
        if len(items) > max_items:
            result += f'<div class="{css_class} muted">+{len(items) - max_items} more</div>'
        return result

    def generate_json(self, scan_result: ScanResult, target: str) -> str:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.report_dir, f"report_{timestamp}.json")
            stats = self._stats(scan_result)
            data = {
                "target": target,
                "generated_at": datetime.now().isoformat(),
                "scanner_version": stats.get('scanner_version', '1.0.0'),
                "report_version": stats.get('report_version', '3.0'),
                "statistics": stats,
                "findings": [f.to_dict() for f in scan_result.findings],
            }
            with open(filename, 'w', encoding='utf-8') as f:
                import json
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            print("[OK] JSON report: " + filename)
            return filename
        except Exception as e:
            print("[ERROR] Error generating JSON: " + str(e))
            return ""

    def generate_markdown(self, scan_result: ScanResult, target: str) -> str:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.report_dir, f"report_{timestamp}.md")
            stats = self._stats(scan_result)

            lines = []
            lines.append(f"# Security Assessment Report: {target}")
            lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"**Scanner:** v{stats.get('scanner_version', '1.0.0')}")
            lines.append("")
            lines.append("## Executive Summary")
            lines.append(stats.get('executive_summary', ''))
            lines.append("")
            lines.append("## Scan Statistics")
            lines.append(f"| Metric | Value |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Total Modules | {stats.get('total', 0)} |")
            lines.append(f"| Vulnerabilities | {stats.get('vulnerabilities', 0)} |")
            lines.append(f"| Critical | {stats.get('critical', 0)} |")
            lines.append(f"| High | {stats.get('high', 0)} |")
            lines.append(f"| Medium | {stats.get('medium', 0)} |")
            lines.append(f"| Low | {stats.get('low', 0)} |")
            lines.append(f"| Warnings | {stats.get('warning', 0)} |")
            lines.append(f"| Passed | {stats.get('safe', 0)} |")
            lines.append(f"| Risk Score | {stats.get('risk_score', 0)}% |")
            lines.append(f"| Coverage | {stats.get('coverage_percentage', 0)}% |")
            lines.append(f"| Duration | {stats.get('duration', 0):.1f}s |")
            lines.append(f"| HTTP Requests | {stats.get('requests_sent', 0)} |")
            lines.append("")

            vulns = [f for f in scan_result.findings if f.is_vulnerable()]
            if vulns:
                lines.append("## Vulnerabilities Found")
                lines.append("")
                for f in vulns:
                    lines.append(f"### [{f.severity.value.upper()}] {f.module}")
                    lines.append(f"- **Confidence:** {f.confidence}%")
                    lines.append(f"- **Verification:** {f.verification_status}")
                    lines.append(f"- **Occurrences:** {f.occurrences}")
                    lines.append(f"- **CVSS:** {f.cvss_score}")
                    lines.append(f"- **Reason:** {f.reason}")
                    lines.append(f"- **Recommendation:** {f.recommendation}")
                    lines.append("")

            warns = scan_result.get_warning_findings()
            if warns:
                lines.append("## Warnings")
                for w in warns:
                    lines.append(f"- {w.module}: {w.reason[:80]}")
                lines.append("")

            with open(filename, 'w', encoding='utf-8') as f:
                f.write("\n".join(lines))
            print("[OK] Markdown report: " + filename)
            return filename
        except Exception as e:
            print("[ERROR] Error generating Markdown: " + str(e))
            return ""

    def generate_csv(self, scan_result: ScanResult, target: str) -> str:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.report_dir, f"report_{timestamp}.csv")
            with open(filename, 'w', encoding='utf-8-sig', newline='') as f:
                import csv
                writer = csv.writer(f)
                writer.writerow(['Module', 'Status', 'Severity', 'Confidence', 'Verification',
                               'Occurrences', 'CVSS', 'Reason', 'Recommendation'])
                for finding in scan_result.findings:
                    writer.writerow([
                        finding.module,
                        finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
                        finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        finding.confidence,
                        finding.verification_status,
                        finding.occurrences,
                        finding.cvss_score,
                        finding.reason,
                        finding.recommendation,
                    ])
            print("[OK] CSV report: " + filename)
            return filename
        except Exception as e:
            print("[ERROR] Error generating CSV: " + str(e))
            return ""

    def generate_txt(self, scan_result: ScanResult, target: str) -> str:
        """إنشاء تقرير PDF (نصي بسيط)"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.report_dir, f"report_{timestamp}.txt")
            stats = self._stats(scan_result)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("  SEA CORPORATE Security Scanner v1.0\n")
                f.write("  Security Assessment Report\n")
                f.write("=" * 70 + "\n\n")
                
                f.write(f"Target: {target}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scanner Version: {stats.get('scanner_version', '1.0.0')}\n")
                f.write(f"Report Version: {stats.get('report_version', '2.0')}\n")
                f.write(f"Duration: {stats.get('duration', 0):.1f} seconds\n\n")
                
                f.write("=" * 70 + "\n")
                f.write("  SCAN SUMMARY\n")
                f.write("=" * 70 + "\n")
                f.write(f"Total Modules: {stats.get('total', 0)}\n")
                f.write(f"Vulnerabilities: {stats.get('vulnerabilities', 0)}\n")
                f.write(f"Passed Checks: {stats.get('safe', 0)}\n")
                f.write(f"Warnings: {stats.get('warning', 0)}\n")
                f.write(f"Information: {stats.get('info', 0)}\n")
                f.write(f"Risk Score: {stats.get('risk_score', 0)}%\n")
                f.write(f"Overall Severity: {stats.get('overall_severity', 'No Risk')}\n")
                f.write(f"HTTP Requests: {stats.get('requests_sent', 0)}\n")
                f.write(f"Injection Payloads: {stats.get('injection_payloads', 0)}\n")
                f.write(f"Headers Tests: {stats.get('headers_tests', 0)}\n")
                f.write(f"Port Tests: {stats.get('port_tests', 0)}\n")
                f.write(f"Coverage: {stats.get('coverage_percentage', 0)}% ({stats.get('coverage_executed', 0)}/{stats.get('coverage_total', 0)})\n\n")
                
                f.write("=" * 70 + "\n")
                f.write("  ASSESSMENT NOTE\n")
                f.write("=" * 70 + "\n")
                f.write(f"{stats.get('overall_description', 'No vulnerabilities detected.')}\n\n")
                
                vulnerabilities = [f for f in scan_result.findings if f.status in (Status.FAIL, Status.VULNERABLE)]
                if vulnerabilities:
                    f.write("=" * 70 + "\n")
                    f.write("  VULNERABILITIES FOUND\n")
                    f.write("=" * 70 + "\n\n")
                    for finding in vulnerabilities:
                        try:
                            f.write(f"[{finding.severity.value.upper()}] {finding.module}\n")
                            f.write(f"  Confidence: {finding.confidence}%\n")
                            
                            # عرض تفاصيل الثقة
                            if hasattr(finding, 'confidence_factors') and finding.confidence_factors:
                                f.write("  Confidence Breakdown:\n")
                                for key, value in finding.confidence_factors.items():
                                    if value > 0:
                                        f.write(f"    +{value} {key}\n")
                                    elif value < 0:
                                        f.write(f"    {value} {key}\n")
                            
                            if hasattr(finding, 'evidence_quality') and finding.evidence_quality > 0:
                                f.write(f"  Evidence Quality: {finding.evidence_quality}%\n")
                            
                            if hasattr(finding, 'detection_methods') and finding.detection_methods:
                                f.write(f"  Detection Methods: {', '.join(finding.detection_methods)}\n")
                            
                            f.write(f"  Reason: {finding.reason}\n")
                            f.write(f"  Evidence: {finding.evidence}\n")
                            f.write(f"  Recommendation: {finding.recommendation}\n")
                            f.write(f"  Tests: {finding.tests_performed}\n\n")
                        except Exception:
                            continue
                
                warnings = scan_result.get_warning_findings()
                if warnings:
                    f.write("=" * 70 + "\n")
                    f.write("  WARNINGS\n")
                    f.write("=" * 70 + "\n\n")
                    for finding in warnings:
                        try:
                            f.write(f"⚠️ {finding.module}: {finding.reason}\n")
                        except Exception:
                            continue
                    f.write("\n")
                
                info_findings = scan_result.get_info_findings()
                if info_findings:
                    f.write("=" * 70 + "\n")
                    f.write("  INFORMATION\n")
                    f.write("=" * 70 + "\n\n")
                    for finding in info_findings:
                        try:
                            f.write(f"ℹ️ {finding.module}: {finding.reason}\n")
                        except Exception:
                            continue
                    f.write("\n")
                
                safe_findings = scan_result.get_safe_findings()
                if safe_findings:
                    f.write("=" * 70 + "\n")
                    f.write("  PASSED CHECKS\n")
                    f.write("=" * 70 + "\n\n")
                    for finding in safe_findings:
                        try:
                            f.write(f"✅ {finding.module}: {finding.reason[:60]}\n")
                        except Exception:
                            continue
                    f.write("\n")
                
                f.write("=" * 70 + "\n")
                f.write("  END OF REPORT\n")
                f.write("=" * 70 + "\n")
            
            print("[OK] TXT report: " + filename)
            return filename
        except Exception as e:
            print("[ERROR] Error generating TXT report: " + str(e))
            return ""

    def generate_pdf(self, scan_result: ScanResult, target: str) -> str:
        """Alias kept for backward compatibility — delegates to generate_txt."""
        return self.generate_txt(scan_result, target)