"""
Technology Fingerprinting Module
Detects: Frameworks, Servers, CDN, WAF, CMS
"""

import re
import requests

class Fingerprinter:
    def __init__(self, target, session=None):
        self.target = target
        self.session = session or requests.Session()
        self.technologies = {
            'frameworks': {
                'django': [r'django', r'csrftoken', r'__admin_'],
                'laravel': [r'laravel', r'X-Powered-By: Laravel'],
                'rails': [r'rails', r'ruby on rails', r'_csrf_token'],
                'spring': [r'spring', r'X-Application-Context'],
                'react': [r'react', r'reactjs', r'__react'],
                'vue': [r'vue', r'vuejs', r'data-v-'],
                'angular': [r'angular', r'ng-', r'_ng']
            },
            'servers': {
                'nginx': [r'nginx', r'Server: nginx'],
                'apache': [r'apache', r'Server: Apache'],
                'iis': [r'iis', r'Server: Microsoft-IIS'],
                'tomcat': [r'tomcat', r'Apache-Coyote']
            },
            'cdn': {
                'cloudflare': [r'cloudflare', r'cf-ray', r'__cfduid'],
                'akamai': [r'akamai', r'x-akamai-'],
                'cloudfront': [r'cloudfront', r'x-amz-cf-']
            },
            'waf': {
                'modsecurity': [r'modsecurity', r'ModSecurity'],
                'cloudfront': [r'x-amz-cf-', r'aws'],
                'sucuri': [r'sucuri', r'x-sucuri-']
            },
            'cms': {
                'wordpress': [r'wordpress', r'wp-', r'wp-content'],
                'drupal': [r'drupal', r'drupal.org'],
                'joomla': [r'joomla', r'joomla!'],
                'magento': [r'magento', r'x-magento-']
            }
        }
    
    def fingerprint(self):
        """Main fingerprinting method"""
        results = {}
        
        try:
            response = self.session.get(self.target, timeout=10, allow_redirects=True)
            headers = response.headers
            content = response.text
            
            # Check each technology category
            for category, techs in self.technologies.items():
                results[category] = []
                for tech, patterns in techs.items():
                    if self.detect_technology(patterns, headers, content):
                        results[category].append(tech)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def detect_technology(self, patterns, headers, content):
        """Detect if a technology is present"""
        # Check headers
        for pattern in patterns:
            for key, value in headers.items():
                if re.search(pattern, key, re.IGNORECASE) or re.search(pattern, value, re.IGNORECASE):
                    return True
        
        # Check content
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def get_summary(self):
        """Get human-readable fingerprint summary"""
        results = self.fingerprint()
        
        if 'error' in results:
            return f"❌ Error: {results['error']}"
        
        summary = []
        for category, techs in results.items():
            if techs:
                summary.append(f"• {category.title()}: {', '.join(techs)}")
        
        if not summary:
            return "⚠️ No technologies detected"
        
        return "\n".join(summary)