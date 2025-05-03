# Api Shadow Routing.Py Module
from . import get_session
session = get_session()
payloads = ["/debug", "/internal", "/.env", "/.git", "/api/v2/private"]

def check(target_url):
    results = []
    for payload in payloads:
        try:
            if isinstance(payload, str):
                url = target_url.rstrip("/") + payload if payload.startswith("/") else payload
                r = session.get(url, timeout=5)
                results.append({"url": url, "status_code": r.status_code, "length": len(r.text)})
            elif isinstance(payload, dict) and "header" in payload and "value" in payload:
                r = session.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
                results.append({"url": target_url, "status_code": r.status_code, "headers": dict(r.headers)})
            elif isinstance(payload, dict) and "alg" in payload:
                results.append({"jwt_test_payload": payload})
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    return results
