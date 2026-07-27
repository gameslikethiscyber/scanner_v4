"""
Professional Report Generation - Complete Version
With Risk Score, Overall Severity, Coverage, Confidence Breakdown, and Detailed Findings
"""

import os
import json
from datetime import datetime
from typing import List
from core.finding import Finding, ScanResult, Status, Severity

class Reporter:
    def __init__(self):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def validate_results(self, scan_result: ScanResult) -> List[str]:
        """التحقق من صحة النتائج قبل إنشاء التقرير"""
        errors = scan_result.validate()
        if errors:
            print("⚠️ Validation errors found:")
            for error in errors:
                print(f"  - {error}")
        return errors
    
    def generate_html(self, scan_result: ScanResult, target: str) -> str:
        """إنشاء تقرير HTML احترافي"""
        try:
            errors = self.validate_results(scan_result)
            stats = scan_result.get_statistics()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.report_dir, f"report_{timestamp}.html")
            
            critical = scan_result.get_critical()
            high = scan_result.get_high()
            medium = scan_result.get_medium()
            low = scan_result.get_low()
            safe = scan_result.get_safe_findings()
            info = scan_result.get_info_findings()
            warnings = scan_result.get_warning_findings()
            
            html = self.build_html(target, stats, critical, high, medium, low, safe, info, warnings)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
            
            print(f"✅ HTML report: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Error generating HTML: {e}")
            import traceback
            traceback.print_exc()
            return ""
    
    def build_html(self, target, stats, critical, high, medium, low, safe, info, warnings):
        """بناء محتوى HTML الكامل"""
        
        # تحديد التصنيف بناءً على Overall Severity
        overall_severity = stats.get('overall_severity', '✅ No Risk')
        overall_color = stats.get('overall_color', '#2196F3')
        overall_description = stats.get('overall_description', 'No vulnerabilities detected.')
        risk = stats.get('risk_score', 0)
        
        # تحديد الأيقونة حسب التصنيف
        if 'Critical' in overall_severity:
            risk_icon = "🔥"
        elif 'High' in overall_severity:
            risk_icon = "🚨"
        elif 'Medium' in overall_severity:
            risk_icon = "⚠️"
        elif 'Low' in overall_severity:
            risk_icon = "🟡"
        else:
            risk_icon = "✅"
        
        # بناء الأقسام
        critical_html = self.build_finding_section("🔴 Critical Findings", critical, "critical")
        high_html = self.build_finding_section("🟠 High Findings", high, "high")
        medium_html = self.build_finding_section("🟡 Medium Findings", medium, "medium")
        low_html = self.build_finding_section("🟢 Low Findings", low, "low")
        warnings_html = self.build_warning_section(warnings)
        info_html = self.build_info_section(info)
        safe_html = self.build_safe_section(safe)
        
        return f'''<!DOCTYPE html>
<html lang="ar" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير الأمان - {target}</title>
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
        
        /* Footer */
        .footer {{
            background: #1a1a2e;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 13px;
            opacity: 0.8;
        }}
        
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
            <h1>🔒 SEA Corporate Security Scanner</h1>
            <div class="subtitle">تقرير فحص الأمان الشامل</div>
            <div class="meta">
                <span>🎯 {target}</span>
                <span>📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
                <span>📌 v{stats.get('scanner_version', '1.0.0')}</span>
            </div>
        </div>
        
        <div class="content">
            <!-- Scan Summary -->
            <div class="scan-summary">
                <h2>📋 Scan Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item">
                        <span class="label">Scanner Version</span>
                        <span class="value">{stats.get('scanner_version', '1.0.0')}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Report Version</span>
                        <span class="value">{stats.get('report_version', '2.0')}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">HTTP Requests</span>
                        <span class="value">{stats.get('requests_sent', 0)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Injection Payloads</span>
                        <span class="value">{stats.get('injection_payloads', 0)}</span>
                    </div>
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
                        <span class="title">📊 Coverage</span>
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
                </div>
            </div>
            
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="number">{stats.get('critical', 0)}</div>
                    <div class="label">🔴 Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{stats.get('high', 0)}</div>
                    <div class="label">🟠 High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{stats.get('medium', 0)}</div>
                    <div class="label">🟡 Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{stats.get('low', 0)}</div>
                    <div class="label">🟢 Low</div>
                </div>
                <div class="stat-card warning">
                    <div class="number">{stats.get('warning', 0)}</div>
                    <div class="label">⚠️ Warnings</div>
                </div>
                <div class="stat-card info">
                    <div class="number">{stats.get('info', 0)}</div>
                    <div class="label">ℹ️ Info</div>
                </div>
                <div class="stat-card safe">
                    <div class="number">{stats.get('safe', 0)}</div>
                    <div class="label">✅ Passed</div>
                </div>
            </div>
            
            <!-- Risk Meter -->
            <div class="risk-meter">
                <div class="title">🎯 Risk Assessment</div>
                <div class="score-row">
                    <div>
                        <div class="sub-label">Risk Score</div>
                        <span class="score">{risk}%</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="sub-label">Overall Severity</div>
                        <span class="rating" style="color: {overall_color};">{risk_icon} {overall_severity}</span>
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
                    <strong>Note:</strong> {overall_description}
                </div>
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
            SEA Corporate Security Scanner v{stats.get('scanner_version', '1.0.0')} | Generated by Automated Security Assessment Tool
        </div>
    </div>
</body>
</html>'''
    
    def build_finding_section(self, title, findings, severity_class):
        """بناء قسم النتائج (الثغرات) مع تفاصيل الثقة"""
        if not findings:
            return ""
        
        cards = ""
        for f in findings:
            try:
                evidence = f.evidence or "No evidence provided"
                reason = f.reason or "No reason provided"
                recommendation = f.recommendation or "No recommendation provided"
                
                # بناء تفاصيل الثقة (Confidence Breakdown)
                confidence_breakdown = ""
                if hasattr(f, 'confidence_factors') and f.confidence_factors:
                    factors = []
                    for key, value in f.confidence_factors.items():
                        if value > 0:
                            factors.append(f'<span class="factor positive">+{value} {key}</span>')
                        elif value < 0:
                            factors.append(f'<span class="factor negative">{value} {key}</span>')
                    if factors:
                        confidence_breakdown = f'''
                    <div class="confidence-breakdown">
                        <strong>Confidence Breakdown:</strong>
                        <div class="factors">
                            {" ".join(factors)}
                        </div>
                        <div class="final">Final Confidence: <span>{f.confidence}%</span></div>
                    </div>'''
                
                # عرض جودة الأدلة
                evidence_quality_html = ""
                if hasattr(f, 'evidence_quality') and f.evidence_quality > 0:
                    evidence_quality_html = f'<div class="detail"><strong>Evidence Quality:</strong> {f.evidence_quality}%</div>'
                
                # عرض طرق الكشف
                detection_methods_html = ""
                if hasattr(f, 'detection_methods') and f.detection_methods:
                    methods = ', '.join(f.detection_methods)
                    detection_methods_html = f'<div class="detail"><strong>Detection Methods:</strong> {methods}</div>'
                
                cards += f'''
            <div class="finding-card" style="border-left-color: {self.get_color(severity_class)};">
                <div class="title">
                    <span>{f.module}</span>
                    <span class="badge badge-{severity_class}">{f.severity.value.upper()}</span>
                </div>
                <div class="detail"><strong>Confidence:</strong> {f.confidence}%</div>
                {confidence_breakdown}
                {evidence_quality_html}
                {detection_methods_html}
                <div class="detail"><strong>Reason:</strong> {reason}</div>
                <div class="evidence"><strong>Evidence:</strong> {evidence}</div>
                <div class="detail"><strong>Recommendation:</strong> {recommendation}</div>
                <div class="detail"><strong>Tests:</strong> {f.tests_performed}</div>
            </div>'''
            except Exception as e:
                continue
        
        bg_colors = {
            'critical': '#ffcdd2',
            'high': '#ffe0b2',
            'medium': '#fff9c4',
            'low': '#c8e6c9'
        }
        bg = bg_colors.get(severity_class, '#f5f5f5')
        
        return f'''
        <div class="finding-section">
            <div class="section-title" style="background: {bg};">
                {title} ({len(findings)})
            </div>
            {cards}
        </div>'''
    
    def build_warning_section(self, findings):
        """بناء قسم التحذيرات"""
        if not findings:
            return ""
        
        items = ""
        for f in findings:
            try:
                reason = f.reason or "Warning"
                items += f'''
                <div class="warning-item">
                    <div class="name">⚠️ {f.module}</div>
                    <div class="note">{reason[:60]}</div>
                </div>'''
            except:
                continue
        
        return f'''
        <div class="finding-section">
            <div class="section-title" style="background: #fff3e0;">
                ⚠️ Warnings ({len(findings)})
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
                reason = f.reason or "Passed"
                items += f'''
                <div class="safe-item">
                    <div class="name">✅ {f.module}</div>
                    <div class="note">{reason[:50]}</div>
                </div>'''
            except:
                continue
        
        return f'''
        <div class="finding-section">
            <div class="section-title" style="background: #bbdefb;">
                ✅ Passed Checks ({len(findings)})
            </div>
            <div class="safe-grid">
                {items}
            </div>
        </div>'''
    
    def build_info_section(self, findings):
        """بناء قسم المعلومات (Not Tested, Info)"""
        if not findings:
            return ""
        
        items = ""
        for f in findings:
            try:
                reason = f.reason or "Information"
                items += f'''
                <div class="info-item">
                    <div class="name">ℹ️ {f.module}</div>
                    <div class="note">{reason[:50]}</div>
                </div>'''
            except:
                continue
        
        return f'''
        <div class="finding-section">
            <div class="section-title" style="background: #e0e0e0;">
                ℹ️ Information ({len(findings)})
            </div>
            <div class="info-grid">
                {items}
            </div>
        </div>'''
    
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
    
    def generate_pdf(self, scan_result: ScanResult, target: str) -> str:
        """إنشاء تقرير PDF (نصي بسيط)"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.report_dir, f"report_{timestamp}.txt")
            stats = scan_result.get_statistics()
            
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
                
                vulnerabilities = scan_result.get_vulnerabilities()
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
                        except:
                            continue
                
                warnings = scan_result.get_warning_findings()
                if warnings:
                    f.write("=" * 70 + "\n")
                    f.write("  WARNINGS\n")
                    f.write("=" * 70 + "\n\n")
                    for finding in warnings:
                        try:
                            f.write(f"⚠️ {finding.module}: {finding.reason}\n")
                        except:
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
                        except:
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
                        except:
                            continue
                    f.write("\n")
                
                f.write("=" * 70 + "\n")
                f.write("  END OF REPORT\n")
                f.write("=" * 70 + "\n")
            
            print(f"✅ PDF report: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            return ""