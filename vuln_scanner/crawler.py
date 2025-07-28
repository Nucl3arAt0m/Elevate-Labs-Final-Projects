import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

def crawl(url, max_depth=2):
    visited = set()
    forms = []
    urls = set([url])

    def extract_forms(page_url, depth=0):
        if depth > max_depth or page_url in visited:
            return
        visited.add(page_url)
        try:
            response = requests.get(page_url, timeout=5)
            if response.status_code != 200:
                return
            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                action = form.get('action', '')
                action_url = urljoin(page_url, action)
                inputs = [
                    {'name': inp.get('name', ''), 'type': inp.get('type', 'text')}
                    for inp in form.find_all('input')
                ]
                forms.append({'url': action_url, 'method': form.get('method', 'get').lower(), 'inputs': inputs})

            for link in soup.find_all('a', href=True):
                href = urljoin(page_url, link['href'])
                if urlparse(href).netloc == urlparse(url).netloc:
                    urls.add(href)
        except Exception as e:
            print(f"Crawler: Error at {page_url}: {e}")

    for link in list(urls):
        extract_forms(link)
    return forms, urls

if __name__ == "__main__":
    target = "http://testphp.vulnweb.com"
    forms, urls = crawl(target)
    print("Forms:", forms)
    print("URLs:", urls)
