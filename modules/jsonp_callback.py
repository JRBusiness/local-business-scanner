import requests
import re
from . import get_session

# Common callback parameters
PARAMS = ["callback", "jsonp", "cb", "_cb", "_"]

JSONP_PARAMS = ["callback", "jsonp", "cb", "jsonpcallback", "callbackfn", "function"]

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Check if URL appears to be an API endpoint
    if '/api/' in url or '/json' in url or '/data' in url:
        for param in JSONP_PARAMS:
            test_url = f"{url}?{param}=testCallback"
            try:
                r = req_session.get(test_url, timeout=5)
                content_type = r.headers.get('Content-Type', '')
                
                # Look for evidence of JSONP support
                if ('application/json' in content_type or 'javascript' in content_type) and 'testCallback(' in r.text:
                    # Try with potentially dangerous callback name
                    xss_test_url = f"{url}?{param}=<script>alert(1)</script>"
                    r_xss = req_session.get(xss_test_url, timeout=5)
                    
                    if '<script>alert(1)</script>(' in r_xss.text:
                        findings.append(f"Insecure JSONP callback parameter: {param} - XSS possible")
                    else:
                        findings.append(f"JSONP callback parameter found: {param}")
            except Exception:
                continue
    
    return findings
