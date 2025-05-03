# Token Confusion.Py Module

import requests
from . import get_session

PAYLOADS = [
    {"header": "Authorization", "value": "Bearer abc123"},
    {"header": "X-API-Token", "value": "token123"},
    {"header": "Cookie", "value": "auth=xyz; session=abc;"},
    {"header": "Authorization", "value": "Basic YWRtaW46YWRtaW4="},
    {"header": "X-CSRF-Token", "value": "invalid-token"}
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Check base URL for existing vulnerabilities
    try:
        r = req_session.get(target_url, timeout=5)
        # Look for authentication headers in response
        auth_headers = ['www-authenticate', 'authorization', 'x-api-key', 'x-csrf-token']
        for header in auth_headers:
            if header in r.headers:
                findings.append(f"Authentication header found: {header}={r.headers[header]}")
    except Exception:
        pass
        
    # Test each payload
    for payload in PAYLOADS:
        try:
            r = req_session.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
            # Check for authentication-related errors or success
            if "invalid token" in r.text.lower() or "invalid auth" in r.text.lower():
                findings.append(f"Token confusion potential: {payload['header']}:{payload['value']}")
        except Exception:
            continue
            
    return findings
