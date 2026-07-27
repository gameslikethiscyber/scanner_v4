#!/usr/bin/env python3
"""
SEA CORPORATE Security Scanner v1.0
Professional Security Scanner with Unified Results
"""

import sys
import time
import json
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# محاولة استيراد Rich للواجهة الجميلة
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️ Rich library not found. Install with: pip install rich")
    print()

from core.finding import ScanResult
from core.reporter import Reporter

# استيراد جميع الماسحات
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.headers import HeadersScanner
from scanners.tls import TLSScanner
from scanners.cookies import CookiesScanner
from scanners.sensitive_files import SensitiveFilesScanner
from scanners.cors import CORSScanner
from scanners.csrf import CSRFScanner
from scanners.lfi import LFIScanner
from scanners.ssrf import SSRFScanner
from scanners.http_methods import HTTPMethodsScanner
from scanners.open_redirect import OpenRedirectScanner
from scanners.host_header import HostHeaderScanner
from scanners.source_leaks import SourceLeaksScanner
from scanners.dns_scanner import DNSScanner
from scanners.ports import PortsScanner
from scanners.security_txt import SecurityTxtScanner
from scanners.tech_detect import TechDetectScanner

if RICH_AVAILABLE:
    console = Console()
else:
    console = None

class SeaScanner:
    def __init__(self):
        self.version = "1.0.0"
        self.target = None
        self.post_data = None
        self.scan_result = ScanResult()
        self.pages = []
        self.host_scan_done = False
        self.start_time = None
    
    def show_banner(self):
        if RICH_AVAILABLE and console:
            banner = f"""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    ███████╗███████╗ █████╗     ██████╗██████╗ ██████╗    ║
║    ██╔════╝██╔════╝██╔══██╗   ██╔════╝██╔══██╗██╔══██╗   ║
║    ███████╗█████╗  ███████║   ██║     ██████╔╝██████╔╝   ║
║    ╚════██║██╔══╝  ██╔══██║   ██║     ██╔══██╗██╔══██╗   ║
║    ███████║███████╗██║  ██║   ╚██████╗██║  ██║██║  ██║   ║
║    ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ║
║                                                           ║
║         S E A   C O R P O R A T E                        ║
║      Security Scanner v{self.version} - Enterprise        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
            """
            console.print(Panel(banner, style="bold cyan", border_style="blue"))
            console.print("[dim]Advanced Web Security Scanner - All Rights Reserved[/dim]\n")
        else:
            print("=" * 60)
            print("   SEA CORPORATE Security Scanner v1.0")
            print("=" * 60)
            print()
    
    def get_target(self):
        if RICH_AVAILABLE and console:
            target = console.input("[bold yellow]🎯 Target URL: [/bold yellow]").strip()
        else:
            target = input("🎯 Target URL: ").strip()
        
        if not target:
            if RICH_AVAILABLE and console:
                console.print("[red]❌ Target cannot be empty![/red]")
            else:
                print("❌ Target cannot be empty!")
            return self.get_target()
        
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target
    
    def get_host(self) -> str:
        parsed = urlparse(self.target)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    # ---- دوال POST data ----
    def auto_extract_post_data(self):
        try:
            from core.form_crawler import FormCrawler
            if RICH_AVAILABLE and console:
                console.print("[dim]🤖 Scanning for POST forms...[/dim]")
            crawler = FormCrawler()
            forms = crawler.get_post_data_list(self.target)
            if forms:
                if RICH_AVAILABLE and console:
                    console.print(f"[green]✅ Found {len(forms)} POST form(s) automatically![/green]")
                    for i, form in enumerate(forms):
                        console.print(f"  [dim]Form {i+1}: {', '.join(form['data'].keys())}[/dim]")
                return forms[0]['data']
            else:
                if RICH_AVAILABLE and console:
                    console.print("[yellow]⚠️ No POST forms found automatically.[/yellow]")
                return None
        except ImportError:
            if RICH_AVAILABLE and console:
                console.print("[yellow]⚠️ Form Crawler not available. Install beautifulsoup4: pip install beautifulsoup4[/yellow]")
            else:
                print("⚠️ Form Crawler not available. Install beautifulsoup4: pip install beautifulsoup4")
            return None
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"[yellow]⚠️ Auto-extraction failed: {e}[/yellow]")
            else:
                print(f"⚠️ Auto-extraction failed: {e}")
            return None
    
    def get_post_data_manual(self):
        if RICH_AVAILABLE and console:
            choice = console.input("\n[bold yellow]📤 Do you want to send POST data manually? (y/n): [/bold yellow]").strip().lower()
        else:
            choice = input("\n📤 Do you want to send POST data manually? (y/n): ").strip().lower()
        
        if choice not in ['y', 'yes']:
            return None
        
        if RICH_AVAILABLE and console:
            console.print("[dim]Enter POST data as JSON or key=value pairs[/dim]")
            post_input = console.input("[bold yellow]📝 POST data: [/bold yellow]").strip()
        else:
            post_input = input("📝 POST data: ").strip()
        
        if not post_input:
            return None
        
        try:
            return json.loads(post_input)
        except:
            pass
        
        try:
            parsed = parse_qs(post_input)
            return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        except:
            pass
        
        return {"data": post_input}
    
    def get_post_data(self):
        if RICH_AVAILABLE and console:
            console.print("\n[bold cyan]📤 POST Data Collection[/bold cyan]")
        
        post_data = self.auto_extract_post_data()
        if post_data:
            if RICH_AVAILABLE and console:
                console.print(f"[dim]Extracted data: {json.dumps(post_data, ensure_ascii=False)}[/dim]")
                choice = console.input("[bold yellow]Use this data? (y/n): [/bold yellow]").strip().lower()
            else:
                print(f"Extracted data: {json.dumps(post_data, ensure_ascii=False)}")
                choice = input("Use this data? (y/n): ").strip().lower()
            if choice in ['y', 'yes']:
                return post_data
        
        if RICH_AVAILABLE and console:
            console.print("[dim]Switching to manual entry...[/dim]")
        return self.get_post_data_manual()
    
    # ---- الزحف ----
    def crawl_target(self):
        try:
            from core.crawler import Crawler
            if RICH_AVAILABLE and console:
                console.print("[bold cyan]🕷️ Crawling target...[/bold cyan]")
            
            crawler = Crawler()
            self.pages = crawler.crawl(self.target, max_pages=30)
            
            # تصفية الصفحات غير المفيدة (التي لا تحتوي على مدخلات)
            self.pages = [p for p in self.pages if p.get('params') or p.get('forms')]
            
            if RICH_AVAILABLE and console:
                console.print(f"[green]✅ Found {len(self.pages)} useful pages[/green]")
                for i, page in enumerate(self.pages[:5]):
                    console.print(f"  [dim]{i+1}. {page['url']}[/dim]")
                if len(self.pages) > 5:
                    console.print(f"  [dim]... and {len(self.pages)-5} more[/dim]")
            else:
                print(f"✅ Found {len(self.pages)} useful pages")
            
            return True
        except ImportError:
            if RICH_AVAILABLE and console:
                console.print("[yellow]⚠️ Crawler not available. Install beautifulsoup4: pip install beautifulsoup4[/yellow]")
            else:
                print("⚠️ Crawler not available. Install beautifulsoup4: pip install beautifulsoup4")
            self.pages = [{'url': self.target, 'params': {}, 'forms': []}]
            return False
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"[red]❌ Crawling failed: {e}[/red]")
            else:
                print(f"❌ Crawling failed: {e}")
            self.pages = [{'url': self.target, 'params': {}, 'forms': []}]
            return False
    
    # ---- قوائم الماسحات ----
    def get_scanners(self):
        return [
            SQLiScanner,
            XSSScanner,
            HeadersScanner,
            TLSScanner,
            CookiesScanner,
            SensitiveFilesScanner,
            CORSScanner,
            CSRFScanner,
            LFIScanner,
            SSRFScanner,
            HTTPMethodsScanner,
            OpenRedirectScanner,
            HostHeaderScanner,
            SourceLeaksScanner,
            DNSScanner,
            PortsScanner,
            SecurityTxtScanner,
            TechDetectScanner
        ]
    
    def get_host_level_scanners(self):
        """الماسحات التي تعمل على مستوى المضيف (مرة واحدة)"""
        return [
            TLSScanner,
            DNSScanner,
            PortsScanner,
            TechDetectScanner,
            HeadersScanner,
            SecurityTxtScanner
        ]
    
    def get_page_level_scanners(self):
        """الماسحات التي تعمل على كل صفحة"""
        return [
            SQLiScanner,
            XSSScanner,
            CookiesScanner,
            SensitiveFilesScanner,
            CORSScanner,
            CSRFScanner,
            LFIScanner,
            SSRFScanner,
            HTTPMethodsScanner,
            OpenRedirectScanner,
            HostHeaderScanner,
            SourceLeaksScanner
        ]
    
    # ---- فحص المضيف (مرة واحدة) ----
    def run_host_scan(self):
        if self.host_scan_done:
            return
        
        host = self.get_host()
        if RICH_AVAILABLE and console:
            console.print(f"[bold cyan]🏠 Host Scan: {host}[/bold cyan]")
        
        scanners = self.get_host_level_scanners()
        for scanner_class in scanners:
            try:
                scanner = scanner_class(host)
                finding = scanner.run()
                self.scan_result.add_finding(finding)
                self.scan_result.requests_sent += 5
            except Exception as e:
                if RICH_AVAILABLE and console:
                    console.print(f"[red]   ❌ Error in {scanner_class.__name__}: {e}[/red]")
        
        self.host_scan_done = True
    
    # ---- فحص صفحة واحدة ----
    def run_page_scan(self, page_url, post_data=None):
        scanners = self.get_page_level_scanners()
        
        if RICH_AVAILABLE and console:
            console.print(f"[dim]🔍 Scanning: {page_url}[/dim]")
        
        for scanner_class in scanners:
            try:
                scanner = scanner_class(page_url, post_data=post_data)
                finding = scanner.run()
                self.scan_result.add_finding(finding)
                self.scan_result.requests_sent += 5
            except Exception as e:
                if RICH_AVAILABLE and console:
                    console.print(f"[red]   ❌ Error in {scanner_class.__name__}: {e}[/red]")
    
    # ---- فحص جميع الصفحات (متوازي) ----
    def run_scan_on_all_pages(self):
        if not self.pages:
            if RICH_AVAILABLE and console:
                console.print("[red]❌ No pages to scan![/red]")
            return
        
        # 1. تشغيل فحص المضيف (مرة واحدة)
        self.run_host_scan()
        
        # 2. تشغيل فحص كل صفحة (بالتوازي)
        if RICH_AVAILABLE and console:
            console.print(f"[bold cyan]📄 Scanning {len(self.pages)} pages...[/bold cyan]\n")
        
        # استخدام ThreadPoolExecutor للفحص المتوازي
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for page in self.pages:
                page_url = page['url']
                params = page.get('params', {})
                forms = page.get('forms', [])
                
                # بناء الرابط مع المعاملات
                if params:
                    from urllib.parse import urlencode
                    qs = urlencode(params)
                    page_url = page_url + ('&' if '?' in page_url else '?') + qs
                
                # استخراج POST data من أول نموذج
                post_data = None
                if forms and forms[0].get('fields'):
                    post_data = forms[0]['fields']
                
                futures.append(executor.submit(self.run_page_scan, page_url, post_data))
            
            # انتظار انتهاء جميع المهام
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if RICH_AVAILABLE and console:
                        console.print(f"[red]❌ Scan error: {e}[/red]")
        
        self.scan_result.end_time = datetime.now()
        if RICH_AVAILABLE and console:
            console.print(f"[green]✅ Scanned {len(self.pages)} pages[/green]")
    
    def show_scan_info(self):
        now = datetime.now().strftime("%H:%M:%S")
        
        if RICH_AVAILABLE and console:
            info_table = Table(box=box.ROUNDED, style="bright_blue")
            info_table.add_column("Property", style="bold cyan")
            info_table.add_column("Value", style="white")
            
            info_table.add_row("🎯 Target", self.target)
            info_table.add_row("⚙️ Engine", "SeaScan Engine v2.0")
            info_table.add_row("⏰ Started", now)
            info_table.add_row("📋 Modules", f"{len(self.get_scanners())} enabled")
            info_table.add_row("📊 Mode", "Deep Scan (Comprehensive)")
            info_table.add_row("📄 Pages Found", str(len(self.pages)))
            if self.post_data:
                info_table.add_row("📤 POST Data", f"Provided ({len(self.post_data)} fields)")
            else:
                info_table.add_row("📤 POST Data", "None")
            
            console.print(Panel(info_table, title="[bold green]⚙️ Scan Configuration[/bold green]", border_style="green"))
            console.print()
        else:
            print(f"📋 Target: {self.target}")
            print(f"⏰ Started: {now}")
            print(f"📄 Pages Found: {len(self.pages)}")
            if self.post_data:
                print(f"📤 POST Data: Provided ({len(self.post_data)} fields)")
            else:
                print("📤 POST Data: None")
            print("=" * 60)
            print()
    
    def show_summary(self):
        stats = self.scan_result.get_statistics()
        skipped_count = len(self.scan_result.get_skipped_findings())
        
        if RICH_AVAILABLE and console:
            summary_table = Table(box=box.DOUBLE_EDGE, style="bright_white")
            summary_table.add_column("📊 Metric", style="bold cyan")
            summary_table.add_column("📈 Value", style="bold yellow")
            
            summary_table.add_row("⏱️ Duration", f"{stats['duration']:.1f} seconds")
            summary_table.add_row("📋 Modules", str(stats['total']))
            summary_table.add_row("📄 Pages", str(len(self.pages)))
            summary_table.add_row("🔴 Vulnerabilities", str(stats['vulnerabilities']))
            summary_table.add_row("✅ Passed", str(stats['safe']))
            summary_table.add_row("⚠️ Warnings", str(stats['warning']))
            summary_table.add_row("ℹ️ Info", str(stats['info']))
            summary_table.add_row("⏭️ Skipped", str(skipped_count))
            summary_table.add_row("🎯 Risk Score", f"{stats['risk_score']}%")
            summary_table.add_row("📊 Overall Severity", stats['overall_severity'])
            summary_table.add_row("📊 Coverage", f"{stats['coverage_percentage']}% ({stats['coverage_executed']}/{stats['coverage_total']})")
            
            console.print(Panel(summary_table, title="[bold green]📊 Scan Summary[/bold green]", border_style="green"))
            
            findings_table = Table(box=box.ROUNDED)
            findings_table.add_column("Category", style="bold")
            findings_table.add_column("Count", justify="center")
            findings_table.add_column("Severity", justify="center")
            
            findings_table.add_row("🔴 Critical", str(stats['critical']), "[red]● CRITICAL[/red]")
            findings_table.add_row("🟠 High", str(stats['high']), "[orange]● HIGH[/orange]")
            findings_table.add_row("🟡 Medium", str(stats['medium']), "[yellow]● MEDIUM[/yellow]")
            findings_table.add_row("🟢 Low", str(stats['low']), "[green]● LOW[/green]")
            findings_table.add_row("⚠️ Warnings", str(stats['warning']), "[orange]● WARNING[/orange]")
            findings_table.add_row("ℹ️ Info", str(stats['info']), "[blue]● INFO[/blue]")
            findings_table.add_row("✅ Passed", str(stats['safe']), "[bold green]● PASSED[/bold green]")
            findings_table.add_row("⏭️ Skipped", str(skipped_count), "[orange]● SKIPPED[/orange]")
            
            console.print(Panel(findings_table, title="📋 Findings Breakdown", border_style="blue"))
            
            risk_score = stats.get('risk_score', 0)
            overall_severity = stats.get('overall_severity', '✅ No Risk')
            overall_color = stats.get('overall_color', '#2196F3')
            
            if 'Critical' in overall_severity:
                color = "red"
                icon = "🔥"
            elif 'High' in overall_severity:
                color = "orange"
                icon = "🚨"
            elif 'Medium' in overall_severity:
                color = "yellow"
                icon = "⚠️"
            elif 'Low' in overall_severity:
                color = "green"
                icon = "🟡"
            else:
                color = "green"
                icon = "✅"
            
            meter = "█" * int(risk_score / 10) + "░" * (10 - int(risk_score / 10))
            console.print(f"\n[bold]🎯 Risk Meter:[/bold] [{color}]{meter}[/{color}] {risk_score}%")
            console.print(f"[{color}]Status: {icon} {overall_severity}[/{color}]")
            
            if stats.get('overall_description'):
                console.print(f"\n[dim]💡 {stats['overall_description']}[/dim]")
            
            console.print("\n[bold cyan]💡 Recommendations:[/bold cyan]")
            if stats['critical'] > 0:
                console.print("[red]⚠ Critical vulnerabilities found! Immediate action required.[/red]")
            elif stats['high'] > 0:
                console.print("[orange]⚠ High vulnerabilities found. Address them as soon as possible.[/orange]")
            elif stats['vulnerabilities'] > 3:
                console.print("[yellow]⚠ Multiple vulnerabilities found. Review findings.[/yellow]")
            elif stats['vulnerabilities'] > 0:
                console.print("[yellow]⚠ Vulnerabilities found. Review findings.[/yellow]")
            else:
                console.print("[green]✅ System appears reasonably secure. Continue monitoring.[/green]")
        else:
            print("=" * 60)
            print("📊 SCAN SUMMARY")
            print("=" * 60)
            print(f"Duration: {stats['duration']:.1f} seconds")
            print(f"Modules: {stats['total']}")
            print(f"Pages: {len(self.pages)}")
            print(f"Vulnerabilities: {stats['vulnerabilities']}")
            print(f"Passed: {stats['safe']}")
            print(f"Warnings: {stats['warning']}")
            print(f"Info: {stats['info']}")
            print(f"Skipped: {skipped_count}")
            print(f"Risk Score: {stats['risk_score']}%")
            print(f"Overall Severity: {stats['overall_severity']}")
            print(f"Coverage: {stats['coverage_percentage']}% ({stats['coverage_executed']}/{stats['coverage_total']})")
            print("=" * 60)
            
            if stats['critical'] > 0:
                print(f"🔴 CRITICAL: {stats['critical']} vulnerabilities found!")
            elif stats['vulnerabilities'] > 0:
                print(f"🟠 Vulnerabilities found: {stats['vulnerabilities']}")
            else:
                print("✅ No vulnerabilities detected!")
            
            if stats.get('overall_description'):
                print(f"\n💡 {stats['overall_description']}")
    
    def generate_reports(self):
        if RICH_AVAILABLE and console:
            console.print("\n[bold]📄 Report Generation:[/bold]")
            choice = console.input("Generate HTML and PDF reports? (y/n): ").lower()
        else:
            print("\n📄 Generate HTML and PDF reports? (y/n): ", end="")
            choice = input().lower()
        
        if choice in ['y', 'yes']:
            reporter = Reporter()
            reporter.generate_html(self.scan_result, self.target)
            reporter.generate_pdf(self.scan_result, self.target)
            
            if RICH_AVAILABLE and console:
                console.print("[green]✅ Reports generated in 'reports/' directory![/green]")
            else:
                print("✅ Reports generated in 'reports/' directory!")
    
    def run(self):
        try:
            self.show_banner()
            self.target = self.get_target()
            self.post_data = self.get_post_data()
            self.crawl_target()
            self.scan_result.start_time = datetime.now()
            self.show_scan_info()
            self.run_scan_on_all_pages()
            self.show_summary()
            self.generate_reports()
            
            if RICH_AVAILABLE and console:
                console.print("\n[bold green]🎉 Scan completed successfully![/bold green]")
            else:
                print("\n🎉 Scan completed successfully!")
            
        except KeyboardInterrupt:
            if RICH_AVAILABLE and console:
                console.print("\n[red]⚠️ Scan interrupted by user.[/red]")
            else:
                print("\n⚠️ Scan interrupted by user.")
            sys.exit(1)
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"\n[red]❌ Error: {e}[/red]")
                import traceback
                console.print(traceback.format_exc())
            else:
                print(f"\n❌ Error: {e}")
                import traceback
                traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    scanner = SeaScanner()
    scanner.run()