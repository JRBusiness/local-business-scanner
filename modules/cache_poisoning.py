import requests

def check(url):
    findings = []
    try:
        headers = {
            "X-Forwarded-Host": "evil.com",
            "X-Original-URL": "/",
            "X-Rewrite-URL": "/"
        }
        r = requests.get(url, headers=headers, timeout=5)
        if "evil.com" in r.text:
            findings.append("Cache poisoning vector detected via header reflection")
    except Exception:
        findings.append("Cache poisoning test failed")
    return findings

# === Cache Poisoning Payloads ===
#    "X-Forwarded-Host: victim.com",
#    "%0d%0aX-Injected: 1%0d%0aContent-Type: text/html%0d%0a%0d%0a<h1>Hacked</h1>",
