"""
Crawler - محسن مع فلترة المحتوى المكرر وتجاهل الصفحات غير المفيدة
"""

import requests
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

class Crawler:
    # الامتدادات التي يجب تخطيها (لا نزحفها ولا نفحصها)
    SKIP_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.flac',
        '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
    }

    # أنواع المحتوى التي يجب تخطيها
    SKIP_CONTENT_TYPES = {
        'image/', 'video/', 'audio/', 'font/', 'application/octet-stream'
    }

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'SeaScanner-Crawler/1.0'
        })
        self.visited = set()           # العناوين التي تم زيارتها
        self.content_hashes = set()    # بصمات المحتوى (لتجنب التكرار)
        self.pages = []                # الصفحات المقبولة للفحص

    def crawl(self, start_url: str, max_pages: int = 30):
        """بدء الزحف من رابط معين"""
        self.visited = set()
        self.content_hashes = set()
        self.pages = []
        self._crawl_recursive(start_url, max_pages)
        return self.pages

    def _should_skip_by_extension(self, url: str) -> bool:
        """تحديد ما إذا كان يجب تخطي الرابط بناءً على الامتداد"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in self.SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False

    def _should_skip_by_content_type(self, response) -> bool:
        """تحديد التخطي بناءً على Content-Type"""
        content_type = response.headers.get('Content-Type', '').lower()
        for skip_type in self.SKIP_CONTENT_TYPES:
            if content_type.startswith(skip_type):
                return True
        return False

    def _is_useful_page(self, soup, url: str) -> bool:
        """
        تحديد ما إذا كانت الصفحة تستحق الفحص:
        - تحتوي على نموذج (<form>)
        - أو تحتوي على معاملات في الرابط (?)
        - أو تحتوي على مدخلات (<input>, <textarea>, <select>)
        """
        # إذا كان هناك معاملات في الرابط
        if '?' in url and parse_qs(urlparse(url).query):
            return True

        # إذا كان هناك نموذج POST
        if soup.find('form', method=lambda m: m and m.lower() == 'post'):
            return True

        # إذا كان هناك أي عنصر إدخال (حتى لو لم يكن داخل form)
        if soup.find_all(['input', 'textarea', 'select']):
            return True

        return False

    def _crawl_recursive(self, url: str, max_pages: int):
        if len(self.visited) >= max_pages:
            return

        if url in self.visited:
            return

        if self._should_skip_by_extension(url):
            return

        self.visited.add(url)

        try:
            response = self.session.get(url, timeout=5, stream=True)

            if self._should_skip_by_content_type(response):
                return

            if response.status_code != 200:
                return

            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # التحقق من تكرار المحتوى (صفحات مكررة)
            content_hash = hashlib.md5(response.text.encode()).hexdigest()
            if content_hash in self.content_hashes:
                return  # صفحة مكررة، نتجاهلها
            self.content_hashes.add(content_hash)

            # التحقق من فائدة الصفحة (هل تحتوي على مدخلات؟)
            if not self._is_useful_page(soup, url):
                # لا نضيفها للفحص، لكن نستمر في الزحف للروابط الداخلية
                pass
            else:
                # صفحة مفيدة، نضيفها للفحص
                params = self._extract_params(url)
                forms = self._extract_forms(soup, url)

                self.pages.append({
                    'url': url,
                    'params': params,
                    'forms': forms,
                    'status': response.status_code,
                    'title': soup.title.string if soup.title else ''
                })

            # استخراج الروابط الداخلية (حتى لو كانت الصفحة غير مفيدة)
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                full_url = urljoin(url, href)

                if not self._is_internal(full_url, url):
                    continue

                if '#' in full_url:
                    continue

                if self._should_skip_by_extension(full_url):
                    continue

                self._crawl_recursive(full_url, max_pages)

        except requests.exceptions.Timeout:
            print(f"⏱️ Timeout crawling {url}, skipping...")
        except Exception as e:
            print(f"⚠️ Error crawling {url}: {e}")

    def _extract_params(self, url: str) -> dict:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    def _extract_forms(self, soup, base_url: str) -> list:
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            if method != 'post':
                continue

            full_url = urljoin(base_url, action)

            fields = {}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if not name:
                    continue
                fields[name] = self._generate_value(input_tag)

            # تجاهل النماذج الفارغة
            if fields:
                forms.append({
                    'url': full_url,
                    'fields': fields
                })

        return forms

    def _generate_value(self, tag) -> str:
        input_type = tag.get('type', 'text').lower()
        name = tag.get('name', '').lower()

        if tag.get('value'):
            return tag.get('value')

        if input_type == 'email' or 'email' in name:
            return 'test@example.com'
        elif input_type == 'password' or 'password' in name or 'pass' in name:
            return 'Password123!'
        elif 'phone' in name or 'tel' in name:
            return '01000000000'
        elif 'date' in name:
            return '2024-01-01'
        elif 'number' in name or 'age' in name:
            return '25'
        elif input_type == 'checkbox':
            return 'on'
        elif input_type == 'radio':
            return tag.get('value', 'on')
        elif tag.name == 'select':
            options = tag.find_all('option')
            if options:
                return options[0].get('value', '')
            return '1'
        elif 'search' in name or name == 'q':
            return 'test'
        elif 'comment' in name or 'message' in name or 'content' in name:
            return 'This is a test message.'
        else:
            return 'test'

    def _is_internal(self, url: str, base_url: str) -> bool:
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        if not parsed_url.netloc:
            return True
        return parsed_url.netloc == parsed_base.netloc