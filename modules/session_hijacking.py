import requests
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    try:
        r = req_session.get(url, timeout=5)
        
        # Check cookies for missing security attributes
        if 'set-cookie' in r.headers:
            cookies = r.headers['set-cookie'].split(',')
            for cookie in cookies:
                if cookie and 'session' in cookie.lower():
                    if 'httponly' not in cookie.lower():
                        findings.append("Session cookie missing HttpOnly flag - vulnerable to XSS cookie theft")
                    if 'secure' not in cookie.lower():
                        findings.append("Session cookie missing Secure flag - vulnerable to MITM attacks")
                    if 'samesite' not in cookie.lower():
                        findings.append("Session cookie missing SameSite attribute - vulnerable to CSRF attacks")
    except Exception:
        pass
        
    return findings
