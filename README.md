# SEA Corporate Security Scanner v4

Enterprise-grade modular web security assessment tool with 19 scanners, multi-pass verification, response analysis, cross-finding correlation, and professional reporting.

## Architecture

```
scanner_v4/
├── main.py                      # Entry point — SeaScanner orchestrator
├── core/                        # Shared engine modules
│   ├── finding.py               # Finding, Severity, Status, ScanResult (v3.2)
│   ├── evidence.py              # Evidence dataclass, EvidenceBuilder, 12+ builder methods
│   ├── decision_engine.py       # DecisionEngine + RiskCalculator + CWE/OWASP/CVSS mapping
│   ├── verification_engine.py   # Multi-pass verification (reflection, timing, status)
│   ├── response_analyzer.py     # Response analysis, security headers, tech detection, normalization
│   ├── correlation_engine.py    # Cross-finding correlation (10 rules, confidence boost)
│   ├── reporter.py              # HTML/TXT/JSON/MD/CSV report generation
│   ├── crawler.py               # HTTP web crawler + POST form extraction
│   ├── browser.py               # Playwright BrowserManager
│   ├── js_crawler.py            # JavaScript-aware crawling (SPA, XHR)
│   ├── http_client.py           # TrackedSession + LRU ResponseCache
│   └── config.py                # ScanConfig dataclass
├── scanners/                    # 19 security scanners
│   ├── registry.py              # Central scanner registry
│   ├── base.py                  # BaseScanner + SmartPayloadSystem
│   ├── sqli.py                  # SQL Injection (error/time/boolean, multi-pass)
│   ├── xss.py                   # XSS (3 contexts, multi-pass)
│   ├── lfi.py                   # Local File Inclusion (triple-verified)
│   ├── ssrf.py                  # SSRF (triple-verified, metadata detection)
│   ├── headers.py               # Security headers audit
│   ├── cookies.py               # Cookie security flags
│   ├── cors.py                  # CORS misconfiguration (OPTIONS preflight)
│   ├── csrf.py                  # CSRF protection (v2: form extraction + token enforcement verification)
│   ├── http_methods.py          # Dangerous HTTP methods (10 methods)
│   ├── open_redirect.py         # Open redirect (multi-payload)
│   ├── host_header.py           # Host header injection (4 test hosts)
│   ├── source_leaks.py          # Source code leakage patterns
│   ├── dns_scanner.py           # DNS record enumeration (7 record types)
│   ├── ports.py                 # Port scanning (17 ports)
│   ├── security_txt.py          # security.txt presence
│   ├── tech_detect.py           # Technology fingerprinting
│   ├── tls.py                   # TLS/SSL certificate analysis
│   ├── ssti.py                  # Server-Side Template Injection (5 engines, dual-payload verification)
│   └── sensitive_files.py       # Sensitive file discovery (16 files)
├── test_validation.py           # 200+ validation checks
├── payloads/                    # Payload data files
├── templates/                   # Report templates
└── project_docs/                # Documentation
```

## Key Features

- **18 Scanners**: SQLi, XSS, SSRF, LFI, Host Header, Open Redirect, CSRF, CORS, HTTP Methods, Headers, Cookies, TLS, DNS, Open Ports, Security.txt, Source Leaks, Tech Detection, Sensitive Files
- **Multi-Pass Verification**: Every detection goes through 3+ verification passes (initial → confirmation → cross-validation) with payload-specific checks
- **Response Analyzer**: Centralized response analysis with security header validation, cookie audit, technology detection (16+ patterns), body normalization, and sensitive data extraction
- **Correlation Engine**: 10 cross-finding correlation rules that boost confidence and escalate severity when related vulnerabilities are found together
- **Smart Payload System**: Adaptive payload selection based on detected technology and parameter type with 5 encoding modes
- **Evidence-Based Confidence**: Weighted-average confidence scoring with rewards for multi-pass verification, cross-validation, and correlation
- **CVSS 3.1 Vectors**: Per-finding CVSS vector with severity scoring
- **Standards Mapping**: CWE, OWASP Top 10, CAPEC, MITRE ATT&CK, OWASP ASVS for all scanners
- **Professional Reports**: HTML, JSON, Markdown, CSV, TXT with executive summary, attack surface, risk breakdown, verification badges, dark mode, print CSS
- **Detection Replay**: Auto-generated curl commands in every finding card

## Usage

```bash
cd scanner_v4
python main.py
```

The scanner will prompt for:
1. Target URL
2. JavaScript crawling preference (y/n)
3. POST data (manual entry)
4. Report format (HTML, HTML+JSON, or all formats)

## Requirements

```bash
pip install -r requirements.txt
```

Core dependencies: `requests`, `rich`, `dnspython`, `beautifulsoup4`, `cryptography`

Optional: `playwright` (for JavaScript-aware crawling — run `playwright install chromium`)

## Validation

```bash
python test_validation.py
```

200+ validation checks covering import integrity, scanner registry, base methods, evidence system, decision engine, response analyzer, verification engine, correlation engine, reporter, crawler, HTTP client, CVSS, and production quality features.
