"""
Form Crawler - لاستخراج نماذج POST تلقائياً
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

class FormCrawler:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'SeaScanner-Crawler/1.0'
        })
    
    def extract_forms(self, url: str) -> list:
        """استخراج جميع النماذج من الصفحة"""
        forms = []
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return forms
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = self._parse_form(form, url)
                if form_data:
                    forms.append(form_data)
                    
        except Exception as e:
            print(f"⚠️ Error crawling forms: {e}")
        
        return forms
    
    def _parse_form(self, form, base_url: str) -> dict:
        """تحليل نموذج HTML إلى بيانات POST"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        if method != 'post':
            return None
        
        if action:
            full_url = urljoin(base_url, action)
        else:
            full_url = base_url
        
        fields = {}
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name')
            if not name:
                continue
            
            input_type = input_tag.get('type', 'text').lower()
            value = self._generate_value(input_type, name, input_tag)
            
            if value is not None:
                fields[name] = value
        
        if not fields:
            return None
        
        return {
            'url': full_url,
            'method': method,
            'fields': fields
        }
    
    def _generate_value(self, input_type: str, name: str, tag) -> str:
        """توليد قيمة افتراضية ذكية حسب نوع الحقل"""
        name_lower = name.lower()
        
        if tag.get('value'):
            return tag.get('value')
        
        if input_type == 'email' or 'email' in name_lower:
            return 'test@example.com'
        elif input_type == 'password' or 'password' in name_lower or 'pass' in name_lower:
            return 'Password123!'
        elif 'phone' in name_lower or 'tel' in name_lower:
            return '01000000000'
        elif 'date' in name_lower:
            return '2024-01-01'
        elif 'number' in name_lower or 'age' in name_lower:
            return '25'
        elif 'checkbox' in input_type:
            return 'on'
        elif 'radio' in input_type:
            return tag.get('value', 'on')
        elif 'select' in tag.name:
            options = tag.find_all('option')
            if options:
                return options[0].get('value', '')
            return '1'
        elif 'search' in name_lower or 'q' == name_lower:
            return 'test'
        elif 'comment' in name_lower or 'message' in name_lower or 'content' in name_lower:
            return 'This is a test message.'
        else:
            return 'test'
    
    def get_post_data_list(self, url: str) -> list:
        """الواجهة الرئيسية: إرجاع قائمة بجميع طلبات POST المستخرجة"""
        forms = self.extract_forms(url)
        post_data_list = []
        
        for form in forms:
            post_data_list.append({
                'url': form['url'],
                'data': form['fields']
            })
        
        return post_data_list