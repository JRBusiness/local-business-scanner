import requests
import re
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    try:
        r = req_session.get(url, timeout=5)
        
        # Look for common token/API key patterns in the HTML
        patterns = [
            r'api[-_]key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,64})["\']',
            r'auth[-_]token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,64})["\']',
            r'access[-_]token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,64})["\']',
            r'secret[-_]key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,64})["\']',
            r'JWT["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,512})["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            for match in matches:
                findings.append(f"Possible token leakage: {pattern} - {match[:10]}...")
    except Exception:
        pass
        
    return findings
