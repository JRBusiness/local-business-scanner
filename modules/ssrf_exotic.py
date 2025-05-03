# Ssrf Exotic.Py Module

import requests
from . import get_session

PAYLOADS = [
    {"header": "X-Forwarded-For", "value": "localhost"},
    {"header": "X-Forwarded-Host", "value": "127.0.0.1"},
    {"header": "Referer", "value": "http://localhost/admin"},
    {"header": "Client-IP", "value": "127.0.0.1"},
    {"header": "X-Original-URL", "value": "/internal-api"}
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Check base URL for existing vulnerabilities
    try:
        r = req_session.get(target_url, timeout=5)
        # Do some base analysis if needed
    except Exception:
        pass
        
    # Test each payload
    for payload in PAYLOADS:
        try:
            r = req_session.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
            # Simple detection criteria (look for changes when adding the headers)
            if len(r.text) > 0 and (
                "internal" in r.text.lower() or 
                "localhost" in r.text.lower() or
                "127.0.0.1" in r.text.lower()
            ):
                findings.append(f"Possible SSRF via header manipulation: {payload['header']}:{payload['value']}")
        except Exception:
            continue
            
    return findings
