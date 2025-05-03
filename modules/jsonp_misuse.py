import requests
import re
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Common JSONP callback parameter names
    callback_params = ["callback", "jsonp", "cb", "call", "jsonCallback"]
    
    for cb in callback_params:
        try:
            r = req_session.get(f"{url}?{cb}=alert", timeout=5)
            
            # Look for signs of JSONP support
            if "alert(" in r.text and (r.headers.get('content-type', '').startswith('application/json') or 
                                      r.headers.get('content-type', '').startswith('text/javascript')):
                findings.append(f"JSONP endpoint found: parameter={cb}")
                
                # Check if the callback value is properly sanitized
                r_xss = req_session.get(f"{url}?{cb}=alert(document.cookie)//", timeout=5)
                if "alert(document.cookie)//" in r_xss.text:
                    findings.append(f"JSONP callback parameter not sanitized: {cb} - XSS possible")
                break
        except Exception:
            continue
            
    return findings
