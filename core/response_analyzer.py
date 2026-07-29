import re
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

@dataclass
class SecurityHeaderAnalysis:
    name: str
    present: bool
    value: str = ""
    valid: bool = False
    recommendation: str = ""
    severity: str = ""

@dataclass
class CookieAnalysis:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    domain: str = ""
    path: str = ""
    expires: Optional[str] = None
    issues: List[str] = field(default_factory=list)

@dataclass
class ResponseAnalysis:
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    body_hash: str = ""
    normalized_hash: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    security_headers: List[SecurityHeaderAnalysis] = field(default_factory=list)
    cookies: List[CookieAnalysis] = field(default_factory=list)
    redirect_url: str = ""
    timing: float = 0.0
    has_forms: bool = False
    has_scripts: bool = False
    has_errors: bool = False
    error_messages: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)

class ResponseAnalyzer:
    SECURITY_HEADERS = {
        'Content-Security-Policy': 'CSP prevents XSS and data injection',
        'X-Frame-Options': 'Prevents clickjacking',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'Strict-Transport-Security': 'Enforces HTTPS',
        'Referrer-Policy': 'Controls referrer information',
        'Permissions-Policy': 'Controls browser features',
        'X-XSS-Protection': 'Legacy XSS filter',
        'Access-Control-Allow-Origin': 'CORS policy',
        'Cross-Origin-Embedder-Policy': 'COEP policy',
        'Cross-Origin-Opener-Policy': 'COOP policy',
        'Cross-Origin-Resource-Policy': 'CORP policy',
    }

    ERROR_PATTERNS = [
        r'error', r'exception', r'warning', r'fatal',
        r'stack trace', r'on line \d+', r'invalid query',
        r'syntax error', r'unexpected token', r'not found',
        r'failed to', r'could not', r'unable to',
        r'Fatal error', r'Parse error', r'Notice:',
        r'Warning:', r'Deprecated:', r'Strict Standards:',
    ]

    TECH_PATTERNS = {
        'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
        'Drupal': [r'drupal.js', r'Drupal.settings', r'Drupal.ajax'],
        'Joomla': [r'joomla', r'com_content', r'Joomla!'],
        'Laravel': [r'laravel', r'X-Powered-By.*Laravel', r'__cre'],
        'React': [r'react', r'reactjs', r'react\.js', r'__REACT'],
        'Angular': [r'angular', r'ng-', r'ng_app', r'__angular'],
        'Vue.js': [r'vue', r'vuejs', r'vue\.js', r'__VUE'],
        'Next.js': [r'__NEXT_DATA__', r'next\.js', r'_next/static'],
        'Nuxt.js': [r'__NUXT__', r'_nuxt/'],
        'Express': [r'express', r'X-Powered-By.*Express'],
        'Django': [r'csrfmiddlewaretoken', r'django', r'__admin'],
        'Flask': [r'flask', r'__FLASK'],
        'ASP.NET': [r'__VIEWSTATE', r'__EVENTVALIDATION', r'X-AspNet'],
        'jQuery': [r'jquery', r'jQuery', r'\$\.'],
        'Bootstrap': [r'bootstrap', r'Bootstrap'],
        'Tailwind': [r'tailwind', r'Tailwind'],
    }

    @staticmethod
    def analyze_response(response) -> ResponseAnalysis:
        if response is None:
            return ResponseAnalysis()

        analysis = ResponseAnalysis(
            status_code=response.status_code,
            content_type=response.headers.get('Content-Type', ''),
            content_length=len(response.text),
            body_hash=hashlib.md5(response.text.encode('utf-8', errors='replace'), usedforsecurity=False).hexdigest(),
            headers=dict(response.headers),
            timing=getattr(response, 'elapsed', None).total_seconds() if getattr(response, 'elapsed', None) else 0.0,
            redirect_url=response.headers.get('Location', ''),
        )

        analysis.normalized_hash = hashlib.md5(
            ResponseAnalyzer.normalize_body(response.text).encode('utf-8', errors='replace'),
            usedforsecurity=False
        ).hexdigest()

        analysis.security_headers = ResponseAnalyzer._analyze_headers(response.headers)
        analysis.cookies = ResponseAnalyzer._analyze_cookies(response)
        analysis.has_forms = bool(re.search(r'<form[^>]*>', response.text, re.IGNORECASE))
        analysis.has_scripts = bool(re.search(r'<script[^>]*>', response.text, re.IGNORECASE))
        analysis.technologies = ResponseAnalyzer._detect_technologies(response.text, response.headers)

        error_messages = []
        for pattern in ResponseAnalyzer.ERROR_PATTERNS:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                error_messages.extend(matches[:3])
                analysis.has_errors = True
        analysis.error_messages = list(set(error_messages))[:5]

        meta_pattern = re.compile(r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
        analysis.meta_tags = dict(meta_pattern.findall(response.text))

        return analysis

    @staticmethod
    def _analyze_headers(headers: Dict[str, str]) -> List[SecurityHeaderAnalysis]:
        results = []
        std_headers = {k.lower(): v for k, v in headers.items()}
        for hdr, purpose in ResponseAnalyzer.SECURITY_HEADERS.items():
            existing = std_headers.get(hdr.lower())
            if existing:
                analysis = SecurityHeaderAnalysis(
                    name=hdr, present=True, value=existing[:100], valid=True,
                    recommendation=f"Verify {hdr} configuration",
                )
                if hdr == 'Content-Security-Policy':
                    if 'unsafe-inline' in existing and 'nonce' not in existing:
                        analysis.valid = False
                        analysis.severity = 'medium'
                        analysis.recommendation = 'Avoid unsafe-inline without nonce in CSP'
                elif hdr == 'Strict-Transport-Security':
                    match = re.search(r'max-age=(\d+)', existing)
                    if match and int(match.group(1)) < 31536000:
                        analysis.valid = False
                        analysis.severity = 'low'
                        analysis.recommendation = 'Increase HSTS max-age to at least 31536000'
                results.append(analysis)
            else:
                results.append(SecurityHeaderAnalysis(
                    name=hdr, present=False,
                    recommendation=f'Add {hdr} header: {purpose}',
                    severity='low',
                ))
        return results

    @staticmethod
    def _analyze_cookies(response) -> List[CookieAnalysis]:
        results = []
        for cookie in response.cookies:
            ca = CookieAnalysis(name=cookie.name, secure=cookie.secure)
            cookie_rest = {k.lower(): v for k, v in (getattr(cookie, '_rest', {}) or {}).items()}
            ca.httponly = 'httponly' in cookie_rest
            ca.samesite = cookie_rest.get('samesite', '')
            ca.domain = cookie.domain or ''
            ca.path = cookie.path or ''
            ca.expires = str(cookie.expires) if hasattr(cookie, 'expires') and cookie.expires else None
            if not ca.secure:
                ca.issues.append('Missing Secure flag')
            if not ca.httponly:
                ca.issues.append('Missing HttpOnly flag')
            if not ca.samesite:
                ca.issues.append('Missing SameSite flag')
            results.append(ca)
        return results

    @staticmethod
    def _detect_technologies(text: str, headers: Dict[str, str]) -> List[str]:
        detected = []
        text_lower = text.lower()
        for tech, patterns in ResponseAnalyzer.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected.append(tech)
                    break
        for hdr, val in headers.items():
            val_lower = val.lower()
            if 'php' in val_lower:
                detected.append('PHP')
            if 'nginx' in val_lower:
                detected.append('Nginx')
            if 'apache' in val_lower:
                detected.append('Apache')
            if 'cloudflare' in val_lower:
                detected.append('Cloudflare')
            if 'iis' in val_lower:
                detected.append('IIS')
            if val_lower.startswith('python'):
                detected.append('Python')
            if 'java' in val_lower or 'tomcat' in val_lower or 'spring' in val_lower:
                detected.append('Java')
            if 'ruby' in val_lower or 'rails' in val_lower:
                detected.append('Ruby')
            if 'node' in val_lower or 'express' in val_lower:
                detected.append('Node.js')
            if 'go' in val_lower or 'golang' in val_lower:
                detected.append('Go')
        return list(set(detected))

    @staticmethod
    def normalize_body(text: str) -> str:
        if not text:
            return ""
        normalized = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        normalized = re.sub(r'<style[^>]*>.*?</style>', '', normalized, flags=re.DOTALL | re.IGNORECASE)
        normalized = re.sub(r'<[^>]+>', ' ', normalized)
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = re.sub(r'\d+', '0', normalized)
        normalized = re.sub(r'[^\w\s]', '', normalized)
        return normalized.strip().lower()

    @staticmethod
    def check_response_consistency(resp1, resp2) -> bool:
        if resp1 is None or resp2 is None:
            return False
        h1 = ResponseAnalyzer._body_fingerprint(resp1.text)
        h2 = ResponseAnalyzer._body_fingerprint(resp2.text)
        return h1 == h2

    @staticmethod
    def _body_fingerprint(text: str) -> str:
        normalized = ResponseAnalyzer.normalize_body(text)
        return hashlib.md5(normalized.encode('utf-8', errors='replace'), usedforsecurity=False).hexdigest()

    @staticmethod
    def body_similarity(text1: str, text2: str) -> float:
        if not text1 or not text2:
            return 0.0
        n1 = set(ResponseAnalyzer.normalize_body(text1).split())
        n2 = set(ResponseAnalyzer.normalize_body(text2).split())
        if not n1 or not n2:
            return 0.0
        intersection = n1 & n2
        union = n1 | n2
        return len(intersection) / len(union) if union else 0.0

    @staticmethod
    def extract_sensitive_patterns(text: str) -> List[str]:
        patterns = {
            'API Key': r'api[_-]?key[_-]?[\s=:]+["\']?([A-Za-z0-9_\-]{16,})',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Private Key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'JWT Token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'Password': r'password\s*[=:]\s*["\']?([^"\'&\s]{4,})',
            'Secret': r'secret\s*[=:]\s*["\']?([^"\'&\s]{8,})',
            'Token': r'token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',
            'Database URL': r'(mysql|postgres|mongodb)://[^\s\'"]+',
        }
        found = []
        for name, pattern in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                found.append(name)
        return found
