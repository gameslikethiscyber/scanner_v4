from scanners.base import BaseScanner
from urllib.parse import quote
import time

class SQLiScanner(BaseScanner):
    DB_SIGNATURES = {
        'MySQL': ['you have an error in your sql syntax', 'mysql_fetch', 'mysqli_', 'mysql_num_rows', 'unknown column'],
        'PostgreSQL': ['pg::syntaxerror', 'postgresql error', 'psquery', 'pg_query'],
        'SQLite': ['sqlite error', 'near', 'unrecognized token', 'syntax error', 'sqlite3::'],
        'MSSQL': ['unclosed quotation mark', 'microsoft ole db', 'sql server', 'mssql_error'],
        'Oracle': ['ora-', 'oracle error', 'pl/sql', 'ora_'],
        'Generic': ['sql syntax', 'sql error', 'odbc_exec', 'pdoexception', 'sqlstate', 'unexpected token']
    }

    def scan(self):
        print("   [+] SQL Injection (Enhanced)")
        params = ['id', 'page', 'cat', 'user', 'item', 'product', 'news']
        found = False

        for p in params:
            if found: break

            # Phase 1: Error-based with DB-specific signatures
            payloads = ["'", "''", "' OR '1'='1", "' UNION SELECT NULL--", "1' AND 1=1--"]
            for payload in payloads:
                try:
                    url = f"{self.core.target_url}/?{p}={quote(payload)}"
                    r = self.get(url)
                    text_lower = r.text.lower()

                    for db, sigs in self.DB_SIGNATURES.items():
                        for sig in sigs:
                            if sig in text_lower:
                                idx = text_lower.find(sig)
                                snippet = r.text[max(0, idx-50):idx+len(sig)+50]
                                ev = f"Parameter: {p}\nPayload: {payload}\nDB Type: {db}\nSignature: '{sig}'\n\nSnippet:\n{snippet}\n\nFull URL: {url}"
                                self.add(f'Confirmed SQL Injection ({db}): {p}', 'CRITICAL', 
                                    f"{db} error triggered. Signature: '{sig}'", 'Use prepared statements', ev, 95, 'A03:2021', 'CWE-89', 'SQL Injection', 'confirmed')
                                found = True
                                break
                        if found: break
                    if found: break
                except:
                    pass

            if found: break

            # Phase 2: Differential Analysis (Boolean-based)
            try:
                base_url = f"{self.core.target_url}/?{p}="

                # Send multiple payloads and compare
                tests = [
                    ('1', 'baseline'),
                    ("1'", 'single_quote'),
                    ("1''", 'double_quote'),
                    ("1 AND 1=1", 'true_condition'),
                    ("1 AND 1=2", 'false_condition'),
                ]

                responses = {}
                for payload, label in tests:
                    try:
                        r = self.get(base_url + quote(payload))
                        responses[label] = {
                            'status': r.status_code,
                            'length': len(r.content),
                            'text': r.text[:500]
                        }
                    except:
                        responses[label] = None

                # Analyze differences
                baseline = responses.get('baseline')
                true_cond = responses.get('true_condition')
                false_cond = responses.get('false_condition')

                if baseline and true_cond and false_cond:
                    # Check if true/false produce different results from baseline
                    true_diff = abs(true_cond['length'] - baseline['length'])
                    false_diff = abs(false_cond['length'] - baseline['length'])

                    # If true_condition matches baseline but false_condition differs significantly
                    if true_diff < 50 and false_diff > 200:
                        ev = f"Parameter: {p}\n\nDifferential Analysis:\n"
                        ev += f"  Baseline (1):        Status={baseline['status']}, Length={baseline['length']}\n"
                        ev += f"  True (AND 1=1):      Status={true_cond['status']}, Length={true_cond['length']}\n"
                        ev += f"  False (AND 1=2):     Status={false_cond['status']}, Length={false_cond['length']}\n"
                        ev += f"\nDifference: {false_diff} bytes ({false_diff/baseline['length']*100:.1f}%)"

                        conf = min(85, 50 + false_diff/10)
                        self.add(f'Possible Boolean-Based SQL Injection: {p}', 'HIGH',
                            f"Differential response detected. False condition differs by {false_diff} bytes.",
                            'Use prepared statements', ev, int(conf), 'A03:2021', 'CWE-89', 'SQL Injection', 'possible')
                        found = True
                        break

                    # Check status code differences
                    if baseline['status'] == 200 and false_cond['status'] >= 500:
                        ev = f"Parameter: {p}\n\nStatus Code Analysis:\n"
                        ev += f"  Baseline: {baseline['status']}\n  True: {true_cond['status']}\n  False: {false_cond['status']}"
                        self.add(f'Possible SQL Injection (Status Diff): {p}', 'HIGH',
                            f"HTTP {false_cond['status']} on false condition", 'Use prepared statements', ev, 75, 'A03:2021', 'CWE-89', 'SQL Injection', 'possible')
                        found = True
                        break
            except:
                pass

            if found: break

            # Phase 3: Time-based
            try:
                start = time.time()
                self.get(f"{self.core.target_url}/?{p}={quote('1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)')}", timeout=self.core.timeout + 5)
                elapsed = time.time() - start

                start2 = time.time()
                self.get(f"{self.core.target_url}/?{p}=1")
                normal = time.time() - start2

                if elapsed - normal > 4:
                    ev = f"Parameter: {p}\nPayload: SLEEP(5)\nBaseline: {normal:.2f}s\nPayload: {elapsed:.2f}s\nDiff: +{elapsed-normal:.2f}s"
                    conf = min(90, 60 + (elapsed-normal) * 5)
                    self.add(f'Possible Time-Based SQL Injection: {p}', 'CRITICAL',
                        f"Time delay of {elapsed:.1f}s detected", 'Use prepared statements', ev, int(conf), 'A03:2021', 'CWE-89', 'SQL Injection', 'possible')
                    found = True
                    break
            except:
                pass

        if not found:
            print("      OK No SQLi detected")
