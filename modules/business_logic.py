
import requests

# Simulate price manipulation and parameter tampering
TEST_CASES = [
    {"product_id": "1", "price": "1"},
    {"product_id": "1", "price": "-1"},
    {"user_id": "1", "role": "admin"},
    {"amount": "999999"},
    {"quantity": "-5"}
]

def check(url):
    findings = []
    for test in TEST_CASES:
        try:
            r = requests.get(url, params=test, timeout=5)
            if r.status_code == 200 and any(term in r.text.lower() for term in ["admin", "order confirmed", "balance", "price", "$0"]):
                findings.append(f"Potential Business Logic Flaw with params: {test}")
        except Exception:
            continue
    return findings
