import requests
import re
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    try:
        # Request the page
        r = req_session.get(url, timeout=5)
        
        # Look for localStorage or sessionStorage access in JavaScript
        storage_patterns = [
            r'localStorage\.setItem\s*\(\s*[\'"](\w+)[\'"]',
            r'localStorage\[[\'"](\w+)[\'"]\]',
            r'sessionStorage\.setItem\s*\(\s*[\'"](\w+)[\'"]',
            r'sessionStorage\[[\'"](\w+)[\'"]\]'
        ]
        
        # Sensitive key patterns
        sensitive_keys = ['token', 'auth', 'key', 'secret', 'credential', 'password', 'apikey']
        
        for pattern in storage_patterns:
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            for key in matches:
                # Check if the key name suggests sensitive data
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    findings.append(f"Potential sensitive data in client-side storage: {key}")
                    
        # Also check for indexed DB with sensitive info
        if 'indexedDB.open' in r.text and any(sensitive in r.text.lower() for sensitive in sensitive_keys):
            findings.append("Potential sensitive data in IndexedDB")
            
    except Exception:
        pass
        
    return findings
