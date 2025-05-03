import requests
import re
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    try:
        # Initial request to find forms and CSRF tokens
        r = req_session.get(url, timeout=5)
        
        # Look for CSRF tokens in HTML
        csrf_patterns = [
            r'name=["\']csrf[_-]token["\'].*?value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'].*?value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\'].*?value=["\']([^"\']+)["\']'
        ]
        
        tokens_found = []
        for pattern in csrf_patterns:
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            tokens_found.extend(matches)
            
        if tokens_found:
            # Found tokens, now let's check if they're leaked
            for token in tokens_found:
                # Check if token is exposed in JavaScript
                if f"var csrfToken = '{token}'" in r.text or f'var csrfToken = "{token}"' in r.text:
                    findings.append(f"CSRF token exposed in JavaScript: {token[:10]}...")
                    
                # Check if token is exposed in URL
                if token in r.url:
                    findings.append(f"CSRF token exposed in URL: {token[:10]}...")
                    
                # Check if token is predictable (e.g., all digits or simple patterns)
                if token.isdigit() or (len(token) < 10 and not any(c.isdigit() for c in token)):
                    findings.append(f"Potentially weak CSRF token: {token}")
                    
        else:
            # Check for forms without CSRF protection
            form_count = r.text.count('<form')
            if form_count > 0 and not any(pattern in r.text.lower() for pattern in ['csrf', '_token', 'authenticity_token']):
                findings.append(f"Form(s) without CSRF protection detected: {form_count} form(s)")
    
    except Exception:
        pass
        
    return findings
