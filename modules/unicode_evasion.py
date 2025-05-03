# Unicode Evasion.Py Module

import requests
from . import get_session

PAYLOADS = [
    {"header": "X-Forwarded-For", "value": "%C0%AF127.0.0.1"},
    {"header": "User-Agent", "value": "Mozilla/5.0\u0000PentestTool"},
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
            # Simple detection criteria
            if "malformed" in r.text.lower() or "invalid" in r.text.lower():
                findings.append(f"Possible unicode evasion: {payload['header']}:{payload['value']}")
        except Exception:
            continue
            
    return findings
