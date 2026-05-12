import requests
import re

session = requests.Session()
session.proxies = {'http': 'socks5h://tor:9050', 'https': 'socks5h://tor:9050'}
session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'

resp = session.post('https://html.duckduckgo.com/html/', data={'q': 'site:example.com'})
print("Status:", resp.status_code)

html = resp.text

links = re.findall(r'<a[^>]+class="result__url"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL)
snippets = re.findall(r'<a[^>]+class="result__snippet[^>]*>(.*?)</a>', html, re.DOTALL)
titles = re.findall(r'<h2[^>]+class="result__title"[^>]*><a[^>]+href="([^"]+)"[^>]*>(.*?)</a></h2>', html, re.DOTALL)

print('Len links:', len(links))
print('Len titles:', len(titles))
print('Len snippets:', len(snippets))

if titles:
    print("First title:", titles[0][1].strip())
if snippets:
    print("First snippet:", snippets[0].strip())
