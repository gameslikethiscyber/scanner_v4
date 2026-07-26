class Fingerprinter:
    def __init__(self, core):
        self.core = core

    def detect(self):
        tech = []
        try:
            r = self.core.get(self.core.target_url)
            text = r.text.lower()
            headers = {k.lower(): v for k, v in r.headers.items()}

            checks = [
                ('WordPress', ['wp-content', 'wp-includes']),
                ('Drupal', ['drupal', 'sites/default']),
                ('Joomla', ['joomla']),
                ('Laravel', ['laravel']),
                ('Django', ['django', 'csrfmiddlewaretoken']),
                ('React', ['react', 'reactroot']),
                ('Next.js', ['next.js', '_next']),
                ('Angular', ['angular', 'ng-app']),
                ('Vue.js', ['vue.js', '__vuedevtools']),
                ('ASP.NET', ['asp.net', '__viewstate']),
                ('Ruby on Rails', ['rails', 'csrf-param']),
            ]

            for name, indicators in checks:
                if any(ind in text for ind in indicators):
                    tech.append(name)

            if 'x-powered-by' in headers:
                tech.append(headers['x-powered-by'].split('/')[0])
            if 'server' in headers:
                tech.append(headers['server'].split('/')[0])

        except:
            pass

        self.core.tech_stack = list(set(tech))
        return self.core.tech_stack
