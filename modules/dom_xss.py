import requests
import re
from . import get_session

PAYLOAD = "<img src=x onerror=console.log('DOM-XSS-TEST')>"

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    try:
        # Test with a benign payload
        r = req_session.get(url, params={"x": PAYLOAD}, timeout=5)
        
        # Look for unencoded reflection of the payload in HTML or JavaScript
        if PAYLOAD in r.text:
            # Check if payload is inside script tags
            script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL)
            scripts = script_pattern.findall(r.text)
            
            for script in scripts:
                if PAYLOAD in script:
                    findings.append("Potential DOM XSS: payload reflected inside script tags")
                    
            # Check if payload is passed to dangerous JavaScript functions
            dangerous_patterns = [
                r'document\.write\s*\([^)]*' + re.escape(PAYLOAD),
                r'innerHTML\s*=\s*[\'"][^\'"]*' + re.escape(PAYLOAD),
                r'eval\s*\([^)]*' + re.escape(PAYLOAD)
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, r.text, re.IGNORECASE):
                    findings.append(f"Potential DOM XSS: payload reflected in dangerous JavaScript context: {pattern}")
                    
    except Exception:
        pass
        
    return findings
