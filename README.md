# Web Security Scanner v4.0 - Modular

## Structure
```
scanner_v4/
├── main.py                 # Entry point
├── core/
│   ├── scanner.py          # Core engine
│   ├── reporter.py          # Report generation
│   ├── fingerprinter.py     # Tech detection
│   └── classifier.py        # Result classification
└── scanners/
    ├── base.py             # Base scanner class
    ├── headers.py
    ├── tls.py
    ├── cookies.py
    ├── sensitive_files.py
    ├── sqli.py             # Enhanced with DB signatures + differential
    ├── xss.py              # Context-aware
    ├── cors.py
    ├── csrf.py
    ├── lfi.py
    ├── ssrf.py
    ├── http_methods.py
    ├── open_redirect.py
    ├── host_header.py
    ├── source_leaks.py
    ├── dns_scanner.py
    ├── ports.py
    ├── security_txt.py
    └── tech_detect.py
```

## Features
- **4 Categories**: Confirmed Vulns, Possible Vulns, Misconfigurations, Best Practices
- **Confidence %**: 0-100 instead of HIGH/MEDIUM/LOW
- **Evidence**: Full technical evidence for every finding
- **DB-Specific SQLi**: MySQL, PostgreSQL, SQLite, MSSQL, Oracle signatures
- **Differential Analysis**: Boolean-based detection
- **Context-Aware XSS**: body, attribute, script, tag contexts
- **Modular**: Each scanner in its own file

## Usage
```bash
cd scanner_v4
python main.py
```

## Requirements
```bash
pip install requests dnspython
```
