import requests
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    try:
        r = req_session.get(url, timeout=5)
        
        # Check if CSP header exists
        csp_header = r.headers.get('Content-Security-Policy', '')
        
        if csp_header:
            # Check for common CSP bypasses
            if "unsafe-inline" in csp_header:
                findings.append("CSP bypass potential: 'unsafe-inline' directive allows inline script execution")
                
            if "unsafe-eval" in csp_header:
                findings.append("CSP bypass potential: 'unsafe-eval' directive allows eval() and similar functions")
                
            if "*" in csp_header:
                findings.append("CSP bypass potential: Wildcard (*) source allows loading from any domain")
                
            # Check for missing protections
            if "script-src" not in csp_header and "default-src" not in csp_header:
                findings.append("CSP bypass potential: Missing script-src or default-src directive")
        else:
            findings.append("No Content-Security-Policy header found")
    
    except Exception:
        pass
        
    return findings
