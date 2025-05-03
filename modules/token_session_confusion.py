# Token Session Confusion.Py Module

import requests
from . import get_session

PAYLOADS = [
    {"header": "Cookie", "value": "session=xyz123; sessionId=otherVal"},
    {"header": "Authorization", "value": "Bearer session=invalidValue"}
]

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Initial request without any manipulation
    try:
        r = req_session.get(url, timeout=5)
        # Check for session identifier in response
        if "sessionid" in r.headers.get('Set-Cookie', '').lower() or "csrf" in r.headers.get('Set-Cookie', '').lower():
            # Try manipulation
            for payload in PAYLOADS:
                try:
                    r = req_session.get(url, headers={payload["header"]: payload["value"]}, timeout=5)
                    # Check for application errors
                    if "error" in r.text.lower() or "exception" in r.text.lower() or "invalid token" in r.text.lower():
                        findings.append(f"Possible token/session confusion: {payload['header']}:{payload['value']}")
                except Exception:
                    continue
    except Exception:
        pass
    
    return findings
