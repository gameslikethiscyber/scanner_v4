"""
Executive Summary Generator v3.0 — narrative owner for the Assessment.

Produces the natural-language ExecutiveSummary (prose, key findings, positive
highlights, coverage statement, action priority, and the verified / likely /
requires-review buckets) from engine results. The prose mirrors the v2.x
``ScanResult.get_statistics()`` executive text exactly so report parity holds.

See docs/ENGINE_ARCHITECTURE_V3.md §5.8 and §6.6.
"""

from typing import Any, List

from core.assessment import CoverageReport, ExecutiveSummary

# Verification statuses the overall verdict treats as "good enough to act on".
VERIFIED_ENOUGH = ('confirmed', 'verified', 'likely')


class ExecutiveSummaryGenerator:
    """Builds the ExecutiveSummary consumed by the Assessment and reports."""

    ACTION_PRIORITY = {
        'critical': [
            "Immediately remediate critical vulnerabilities",
            "Prioritise high-severity findings",
            "Perform a full penetration test on affected endpoints",
        ],
        'high': [
            "Address high-severity findings as soon as possible",
            "Review findings that require manual review",
            "Schedule a remediation cycle",
        ],
        'elevated': [
            "Schedule remediation for the next maintenance cycle",
            "Review warning and informational findings",
        ],
        'low': [
            "Apply best-practice security improvements",
            "Continue periodic scanning",
        ],
        'none': [
            "Continue monitoring the target",
            "Rescan periodically to confirm a clean baseline",
        ],
    }

    def generate(
        self,
        coverage: CoverageReport,
        overall_tier: str,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        vuln_findings: List[Any] = None,
        warning_count: int = 0,
        safe_modules: List[str] = None,
    ) -> ExecutiveSummary:
        """Generate the executive summary from engine-level inputs."""
        vuln_findings = vuln_findings or []
        safe_modules = safe_modules or []

        verified_vulns = self._count(vuln_findings, 'verified')
        likely_vulns = self._count(vuln_findings, 'likely')
        requires_review = sum(
            1 for f in vuln_findings
            if getattr(f, 'verification_status', 'unverified') not in VERIFIED_ENOUGH
        )

        has_vulns = len(vuln_findings) > 0
        has_critical = critical_count > 0
        has_high = high_count > 0
        has_medium = medium_count > 0

        coverage_note = ""
        if coverage.skipped > 0 or coverage.not_applicable > 0:
            coverage_note = (
                f" Coverage was reduced because {coverage.skipped} module(s) were "
                f"skipped and {coverage.not_applicable} were not applicable to this target."
            )

        prose = self._prose(
            has_vulns=has_vulns, has_critical=has_critical, has_high=has_high,
            has_medium=has_medium, critical_count=critical_count,
            high_count=high_count, medium_count=medium_count,
            verified_vulns=verified_vulns, likely_vulns=likely_vulns,
            warning_count=warning_count, passed_states=coverage.passed,
            coverage=coverage, coverage_note=coverage_note,
        )

        key_findings = self._key_findings(
            has_vulns=has_vulns, has_critical=has_critical, has_high=has_high,
            has_medium=has_medium, critical_count=critical_count,
            high_count=high_count, medium_count=medium_count,
            verified_vulns=verified_vulns, warning_count=warning_count,
            coverage=coverage,
        )

        positive_highlights = self._positive_highlights(
            has_vulns=has_vulns, warning_count=warning_count,
            passed_states=coverage.passed, safe_modules=safe_modules,
        )

        return ExecutiveSummary(
            prose=prose,
            key_findings=key_findings,
            positive_highlights=positive_highlights,
            coverage_statement=(
                f"Coverage reached {coverage.coverage_percent}% "
                f"({coverage.executed}/{coverage.total} modules executed)."
                f"{coverage_note}"
            ),
            action_priority=list(self.ACTION_PRIORITY.get(overall_tier, [])),
            verified_count=verified_vulns,
            likely_count=likely_vulns,
            requires_review_count=requires_review,
        )

    @staticmethod
    def _count(vuln_findings: List[Any], status: str) -> int:
        return sum(1 for f in vuln_findings if getattr(f, 'verification_status', '') == status)

    @staticmethod
    def _prose(has_vulns: bool, has_critical: bool, has_high: bool, has_medium: bool,
               critical_count: int, high_count: int, medium_count: int,
               verified_vulns: int, likely_vulns: int, warning_count: int,
               passed_states: int, coverage: CoverageReport, coverage_note: str) -> str:
        if has_critical:
            return (
                f"Critical vulnerabilities were detected: {critical_count} critical and "
                f"{high_count} high-severity vulnerability finding(s). "
                f"{verified_vulns} finding(s) have verified evidence; "
                f"immediate remediation is required. "
                f"Coverage reached {coverage.coverage_percent}% "
                f"({coverage.executed}/{coverage.total} modules executed)."
            )
        if has_high:
            v_text = "verified" if verified_vulns > 0 else "reported"
            l_text = f" {likely_vulns} finding(s) require manual review." if likely_vulns > 0 else ""
            return (
                f"{high_count} high-severity {v_text} finding(s) were detected.{l_text} "
                f"Coverage reached {coverage.coverage_percent}% "
                f"({coverage.executed}/{coverage.total} modules executed), "
                f"with {warning_count} warning(s) flagged.{coverage_note}"
            )
        if has_medium:
            return (
                f"{medium_count} medium-severity issue(s) were found. "
                f"Coverage reached {coverage.coverage_percent}% "
                f"({coverage.executed}/{coverage.total} modules executed), "
                f"with {warning_count} warning(s). Remediation should be scheduled "
                f"in the next maintenance cycle.{coverage_note}"
            )
        if warning_count > 0:
            return (
                f"The scan completed with {warning_count} warning(s) flagged but "
                f"no confirmed vulnerabilities. "
                f"{passed_states} security check(s) passed. "
                f"Coverage reached {coverage.coverage_percent}% "
                f"({coverage.executed}/{coverage.total} modules executed)."
                f"{coverage_note}"
            )
        return (
            f"The scan completed successfully: {passed_states} security check(s) passed "
            f"and no vulnerabilities were detected. "
            f"Coverage reached {coverage.coverage_percent}% "
            f"({coverage.executed}/{coverage.total} modules executed)."
            f"{coverage_note}"
        )

    @staticmethod
    def _key_findings(has_vulns: bool, has_critical: bool, has_high: bool,
                      has_medium: bool, critical_count: int, high_count: int,
                      medium_count: int, verified_vulns: int, warning_count: int,
                      coverage: CoverageReport) -> List[str]:
        if has_critical:
            bullets = [
                f"{critical_count} critical finding(s) detected",
                f"{high_count} high-severity finding(s) reported",
            ]
            if verified_vulns > 0:
                bullets.append(f"{verified_vulns} finding(s) backed by verified evidence")
        elif has_high:
            bullets = [f"{high_count} high-severity finding(s) detected"]
            if verified_vulns > 0:
                bullets.append(f"{verified_vulns} finding(s) backed by verified evidence")
            if warning_count > 0:
                bullets.append(f"{warning_count} warning(s) flagged")
        elif has_medium:
            bullets = [f"{medium_count} medium-severity issue(s) found"]
            if warning_count > 0:
                bullets.append(f"{warning_count} warning(s) flagged")
        elif warning_count > 0:
            bullets = [
                f"{warning_count} warning(s) flagged",
                f"{coverage.passed} security check(s) passed",
            ]
        else:
            bullets = [
                "No vulnerabilities detected",
                f"{coverage.passed} security check(s) passed",
            ]
        return bullets

    @staticmethod
    def _positive_highlights(has_vulns: bool, warning_count: int,
                              passed_states: int, safe_modules: List[str]) -> List[str]:
        if not has_vulns and warning_count == 0:
            highlights = [f"{passed_states} security check(s) passed"]
            highlights.append("No warnings flagged")
            return highlights
        highlights = [f"{passed_states} module(s) passed security checks"]
        if warning_count == 0:
            highlights.append("No warnings flagged")
        elif not has_vulns:
            highlights.append("No confirmed vulnerabilities found")
        if safe_modules:
            highlights.append(f"{len(safe_modules)} module(s) reported no issues")
        return highlights
