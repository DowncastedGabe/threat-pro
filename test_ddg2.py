import requests

session = requests.Session()
session.proxies = {'http': 'socks5h://tor:9050', 'https': 'socks5h://tor:9050'}
session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'

print("Test 1: Only q")
resp1 = session.post('https://html.duckduckgo.com/html/', data={'q': 'site:example.com'})
print("Status 1:", resp1.status_code)

print("Test 2: q and kl")
resp2 = session.post('https://html.duckduckgo.com/html/', data={'q': 'site:example.com', 'kl': 'br-pt'})
print("Status 2:", resp2.status_code)

print("Test 3: q and kl with explicit headers")
resp3 = session.post('https://html.duckduckgo.com/html/', data={'q': 'site:example.com', 'kl': 'br-pt'}, headers={'Content-Type': 'application/x-www-form-urlencoded'})
print("Status 3:", resp3.status_code)
