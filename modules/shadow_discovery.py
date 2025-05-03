# Shadow Discovery.Py Module

import requests
from . import get_session

PAYLOADS = [
    {"header": "X-Original-URL", "value": "/admin"},
    {"header": "X-Rewrite-URL", "value": "/config.php"},
    {"header": "X-Override-URL", "value": "/secret"},
    {"header": "X-Custom-URL-Path", "value": "/.git/config"},
    {"header": "X-Forwarded-Path", "value": "/internal"}
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Check base URL for existing vulnerabilities
    try:
        r = req_session.get(target_url, timeout=5)
        base_content_length = len(r.text)
        base_status = r.status_code
    except Exception:
        return findings
        
    # Test each payload
    for payload in PAYLOADS:
        try:
            r = req_session.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
            # Look for changes in response indicating successful URL rewriting
            if r.status_code != base_status or abs(len(r.text) - base_content_length) > 50:
                findings.append(f"Possible shadow path via header: {payload['header']}:{payload['value']}")
        except Exception:
            continue
            
    return findings
