import os
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger('SeaScanner.PDFReporter')

try:
    from jinja2 import Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


class PDFReporter:
    def __init__(self, branding: Optional[dict] = None, template_dir: Optional[str] = None):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
        self.branding = branding or {}

        if template_dir is None:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            template_dir = os.path.join(base, "backend", "app", "report_templates")

        self.template_dir = template_dir
        self.template_name = "report_template.html"
        self._env = None

        if JINJA2_AVAILABLE:
            self._env = Environment(loader=FileSystemLoader(self.template_dir))

    def generate_pdf(self, scan_result, target: str, output_path: Optional[str] = None) -> Optional[str]:
        if not JINJA2_AVAILABLE:
            logger.warning("jinja2 not available, PDF generation disabled")
            return None
        if not WEASYPRINT_AVAILABLE:
            logger.warning("weasyprint not available, PDF generation disabled")
            return None

        try:
            stats = scan_result.get_statistics()
            findings = []
            for f in scan_result.findings:
                if f.is_vulnerable():
                    findings.append({
                        "module": f.module,
                        "title": f.title or f.description or f.reason or f.module,
                        "description": f.description or f.reason or "",
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "confidence": f.confidence,
                        "cvss_score": f.cvss_score,
                        "cvss_vector": f.cvss_vector,
                        "cwe_id": f.cwe_id,
                        "owasp_category": f.owasp_category,
                        "affected_url": f.target or target,
                        "verification_status": f.verification_status,
                        "recommendation": f.recommendation,
                        "remediation_steps": f.remediation_steps or [],
                    })

            overall = scan_result.get_overall_severity()
            now = datetime.now()

            template = self._env.get_template(self.template_name)
            html_content = template.render(
                company_name=self.branding.get('company_name', 'SEA Corporate'),
                consultant_name=self.branding.get('consultant_name', ''),
                client_name=self.branding.get('client_name', ''),
                report_id=self.branding.get('report_id', ''),
                logo_url=self.branding.get('logo_url', ''),
                target=target,
                current_date=now.strftime("%Y-%m-%d %H:%M"),
                scanner_version=stats.get("scanner_version", "2.0.0"),
                risk=stats.get("risk_score", 0),
                overall_html=overall['label'],
                overall_description=overall['description'],
                overall_color=overall['color'],
                exec_summary=stats.get("executive_summary", ""),
                stats=stats,
                findings=findings,
                has_vulnerabilities=len(findings) > 0,
            )

            if output_path is None:
                safe_target = "".join(c if c.isalnum() or c in '-_' else '_' for c in target)
                output_path = os.path.join(self.report_dir, f"report_{safe_target}_{now.strftime('%Y%m%d_%H%M%S')}.pdf")

            HTML(string=html_content).write_pdf(output_path)
            logger.info("PDF report generated: %s", output_path)
            return output_path

        except Exception as e:
            logger.error("PDF generation failed: %s", e)
            return None
