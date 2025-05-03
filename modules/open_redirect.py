import re
import urllib.parse
from . import get_session

# Categorized open redirect payloads
REDIRECT_PAYLOADS = {
    "basic": [
        "https://evil.com",
        "//evil.com",
        "https:evil.com",
        "https:/evil.com",
        "https://evil.com@example.com",
        "evil.com/"
    ],
    "encoding_bypass": [
        "https%3A%2F%2Fevil.com",
        "https://%65%76%69%6c.com",
        "%68%74%74%70%73%3a%2f%2fevil.com",
        "https://evil%252ecom",
        "https://evil.com%23.example.com"
    ],
    "protocol_relative": [
        "\\\\evil.com",
        "\\\\/\\\\/evil.com",
        "//evil.com/",
        "///evil.com/",
        "////evil.com/"
    ],
    "javascript_scheme": [
        "javascript:alert(document.domain)",
        "javascript://alert(document.domain)",
        "javascript://%0Aalert(document.domain)",
        "javascript://example.com/%0Aalert(document.domain)"
    ],
    "data_scheme": [
        "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
        "data:application/x-www-form-urlencoded;charset=utf-8;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="
    ],
    "domain_confusion": [
        "https://evil.com?next=https://example.com",
        "https://evil.com#https://example.com",
        "https://example.com.evil.com",
        "https://example.com@evil.com",
        "https://evil.com/example.com"
    ],
    "path_manipulation": [
        "https://example.com./evil.com",
        "https://example.com/evil.com",
        "https://example.com\\@evil.com",
        "/\\/evil.com",
        "/evil.com/"
    ],
    "filter_bypass": [
        "https://evil.com\\.example.com",
        "https://evil.com&.example.com",
        "https://example.com.evil.com",
        "https://evil.com/\\_@example.com",
        "https:evil.com"
    ]
}

# Common parameter names that might be vulnerable to open redirect
REDIRECT_PARAMETERS = [
    "next", "url", "redirect", "redirect_to", "redirecturi", "redirect_uri", 
    "return", "return_to", "returnurl", "return_url", "callback", "goto", 
    "continue", "destination", "redir", "forward", "forward_url", "link", 
    "location", "target", "to", "path", "back", "back_to", "from_uri", 
    "go", "ref", "referer", "referrer", "view", "action", "url_next", 
    "fromurl", "tourl", "redirecturi", "resource"
]

# List of HTTP status codes that indicate a redirection
REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308]

def check(session, url, soup, response, config):
    """
    Enhanced open redirect vulnerability detection with comprehensive payload testing
    and improved detection techniques.
    
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
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Generate domain for testing
    test_domain = "evil-domain-test-123.com"
    
    # Track which parameters we already tested to avoid duplicates
    tested_params = set()
    
    # Helper function to check if a location header points to our test domain
    def is_redirect_to_test_domain(location_header):
        if not location_header:
            return False
            
        location_lower = location_header.lower()
        
        # Basic check if our test domain is in the redirect URL
        if test_domain in location_lower:
            return True
            
        # Check for encoded versions of our test domain
        encoded_domain = urllib.parse.quote(test_domain)
        if encoded_domain in location_lower:
            return True
            
        # Check for double-encoded versions
        double_encoded = urllib.parse.quote(encoded_domain)
        if double_encoded in location_lower:
            return True
            
        return False
            
    # Helper function to detect DOM-based open redirects in JavaScript
    def check_dom_based_redirects(html_content):
        potential_vulnerabilities = []
        
        # Patterns that might indicate DOM-based open redirects
        patterns = [
            r"location\.href\s*=\s*(.+?)[;)]",
            r"location\.replace\s*\(\s*(.+?)\s*\)",
            r"location\.assign\s*\(\s*(.+?)\s*\)",
            r"window\.location\s*=\s*(.+?)[;)]",
            r"window\.open\s*\(\s*(.+?)[,)]",
            r"self\.location\s*=\s*(.+?)[;)]",
            r"top\.location\s*=\s*(.+?)[;)]",
            r"parent\.location\s*=\s*(.+?)[;)]",
            r"document\.location\s*=\s*(.+?)[;)]",
            r"document\.location\.href\s*=\s*(.+?)[;)]"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content)
            for match in matches:
                # Look for URL parameters being used in redirects
                param_patterns = [
                    r"urlParams\.get\(['\"]([^'\"]+)['\"]\)",
                    r"params\.get\(['\"]([^'\"]+)['\"]\)",
                    r"getParam\(['\"]([^'\"]+)['\"]\)",
                    r"getParameter\(['\"]([^'\"]+)['\"]\)",
                    r"searchParams\.get\(['\"]([^'\"]+)['\"]\)",
                    r"URLSearchParams.*\.get\(['\"]([^'\"]+)['\"]\)"
                ]
                
                for param_pattern in param_patterns:
                    param_matches = re.findall(param_pattern, match)
                    for param_match in param_matches:
                        if param_match.lower() in [p.lower() for p in REDIRECT_PARAMETERS]:
                            potential_vulnerabilities.append(param_match)
                            
                # Look for URL fragments being used in redirects
                if "location.hash" in match or "window.location.hash" in match:
                    potential_vulnerabilities.append("URL fragment (#)")
                
        return potential_vulnerabilities
    
    # Test 1: Check for DOM-based redirects in JavaScript
    if response.text:
        dom_vulnerabilities = check_dom_based_redirects(response.text)
        if dom_vulnerabilities:
            findings.append("Potential DOM-based open redirect detected")
            findings.append("Found potential vulnerable redirect parameters in JavaScript:")
            for param in set(dom_vulnerabilities):
                findings.append(f"- {param}")
    
    # Test 2: Check for open redirects in URL parameters
    query_params = urllib.parse.parse_qs(parsed_url.query)
    for param_name, param_values in query_params.items():
        # Skip if we've already tested this parameter
        if param_name in tested_params:
            continue
            
        tested_params.add(param_name)
        
        # Check if parameter name might be related to redirects
        is_likely_redirect_param = any(redirect_param.lower() in param_name.lower() 
                                   for redirect_param in REDIRECT_PARAMETERS)
                                   
        # Prioritize testing parameters that are likely to be redirect parameters
        if is_likely_redirect_param:
            # Test with a few sample payloads
            payload_categories_to_test = ["basic", "protocol_relative", "domain_confusion"]
            
            for category in payload_categories_to_test:
                for payload in REDIRECT_PAYLOADS[category][:2]:  # Test first 2 payloads from each category
                    # Replace the parameter value with our payload
                    new_query_params = query_params.copy()
                    new_query_params[param_name] = [payload.replace("evil.com", test_domain)]
                    
                    # Build new query string and URL
                    new_query_string = urllib.parse.urlencode(new_query_params, doseq=True)
                    new_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query_string,
                        parsed_url.fragment
                    ))
                    
                    # Send the request
                    try:
                        r = req_session.get(new_url, allow_redirects=False, timeout=5)
                        
                        # Check for redirect status codes
                        if r.status_code in REDIRECT_STATUS_CODES:
                            # Check if the Location header points to our test domain
                            if is_redirect_to_test_domain(r.headers.get('Location', '')):
                                findings.append(f"Open redirect vulnerability detected in parameter: {param_name}")
                                findings.append(f"- URL: {new_url}")
                                findings.append(f"- Redirects to: {r.headers.get('Location', '')}")
                                # Once found, no need to test other payloads for this parameter
                                break
                    except Exception as e:
                        continue
                        
                # If we found a vulnerability, break out of the category loop
                if any(f"Open redirect vulnerability detected in parameter: {param_name}" in finding for finding in findings):
                    break
    
    # Test 3: If no findings yet, try other payload categories
    if not findings and query_params:
        additional_categories = ["encoding_bypass", "filter_bypass"]
        
        for param_name in tested_params:
            is_likely_redirect_param = any(redirect_param.lower() in param_name.lower() 
                                       for redirect_param in REDIRECT_PARAMETERS)
                                       
            if is_likely_redirect_param:
                for category in additional_categories:
                    for payload in REDIRECT_PAYLOADS[category][:1]:  # Test only first payload from each category
                        # Replace the parameter value with our payload
                        new_query_params = query_params.copy()
                        new_query_params[param_name] = [payload.replace("evil.com", test_domain)]
                        
                        # Build new query string and URL
                        new_query_string = urllib.parse.urlencode(new_query_params, doseq=True)
                        new_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query_string,
                            parsed_url.fragment
                        ))
                        
                        # Send the request
                        try:
                            r = req_session.get(new_url, allow_redirects=False, timeout=5)
                            
                            # Check for redirect status codes
                            if r.status_code in REDIRECT_STATUS_CODES:
                                # Check if the Location header points to our test domain
                                if is_redirect_to_test_domain(r.headers.get('Location', '')):
                                    findings.append(f"Open redirect vulnerability detected in parameter: {param_name}")
                                    findings.append(f"- URL: {new_url}")
                                    findings.append(f"- Redirects to: {r.headers.get('Location', '')}")
                                    # Once found, no need to test other payloads for this parameter
                                    break
                        except Exception as e:
                            continue
                            
                    # If we found a vulnerability, break out of the category loop
                    if any(f"Open redirect vulnerability detected in parameter: {param_name}" in finding for finding in findings):
                        break
    
    # Test 4: Check for redirection in forms (especially login forms)
    if soup:
        forms = soup.find_all('form')
        for form in forms:
            # Check all input fields in the form
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name', '')
                
                # If input name is related to redirection and has a value
                if input_name and input_tag.get('value') and any(redirect_param.lower() in input_name.lower() 
                                                            for redirect_param in REDIRECT_PARAMETERS):
                    # This might be used for redirection after form submission
                    findings.append(f"Potential open redirect in form input: {input_name}")
                    findings.append(f"- Form action: {form.get('action', 'No action specified')}")
                    findings.append(f"- Input value: {input_tag.get('value', '')}")
                    findings.append("- Consider testing for open redirect after form submission")
    
    # Test 5: Look for referer-based open redirects
    # This involves checking if the site uses the Referer header for redirects
    try:
        headers = {
            'Referer': f'https://{test_domain}/'
        }
        r = req_session.get(url, headers=headers, allow_redirects=False, timeout=5)
        
        # Check for redirect status codes
        if r.status_code in REDIRECT_STATUS_CODES:
            # Check if the Location header points to our test domain
            if is_redirect_to_test_domain(r.headers.get('Location', '')):
                findings.append("Referer-based open redirect vulnerability detected")
                findings.append(f"- Redirects to: {r.headers.get('Location', '')}")
    except Exception as e:
        pass
    
    # If no findings, check for common redirect endpoints
    if not findings:
        common_redirect_paths = [
            '/redirect', '/login', '/logout', '/signin', '/signout', 
            '/auth/redirect', '/auth/login', '/auth/logout',
            '/account/redirect', '/account/login', '/account/logout'
        ]
        
        for path in common_redirect_paths[:3]:  # Test first 3 paths to avoid too many requests
            # Construct the URL
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                path,
                '',
                f'url=https://{test_domain}/',
                ''
            ))
            
            try:
                r = req_session.get(test_url, allow_redirects=False, timeout=5)
                
                # Check for redirect status codes
                if r.status_code in REDIRECT_STATUS_CODES:
                    # Check if the Location header points to our test domain
                    if is_redirect_to_test_domain(r.headers.get('Location', '')):
                        findings.append(f"Open redirect vulnerability detected at path: {path}")
                        findings.append(f"- URL: {test_url}")
                        findings.append(f"- Redirects to: {r.headers.get('Location', '')}")
            except Exception as e:
                continue
    
    return findings

# === Exotic Payloads Enhancement ===

# Exotic redirect payloads
#    "http://example.com%00@evil.com",
#    "//evil.com",
#    "javascript:alert(1)",
#    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

# === Advanced Open Redirect Payloads ===
#    "https://www.trustedsite.com.evil.org/login",
#    "java%0D%0Ascript%0D%0A:alert(1)",
#    "https://trusted.com%00.evil.com/",
