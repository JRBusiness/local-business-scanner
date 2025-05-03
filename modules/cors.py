import re
import json
import urllib.parse
from . import get_session

# Origin domains for testing CORS misconfigurations
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "https://malicious.org",
    "null",  # Special case for null origin
    "https://subdomain.{target_domain}",  # Will be formatted with target domain
    "https://{target_domain}.evil.com",   # Will be formatted with target domain
    "https://{target_domain}.attacker.com",
    "https://{target_domain}",            # Same as target but with https
    "http://{target_domain}",             # Same as target but with http
]

# Headers to check in CORS responses
CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Timing-Allow-Origin"
]

# Common HTTP methods for testing
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"]

# Headers that might be allowed in CORS and could be used maliciously
SENSITIVE_HEADERS = [
    "Authorization",
    "Cookie",
    "X-API-Key",
    "X-CSRF-Token",
    "X-Auth-Token",
    "X-Session-ID",
    "X-Custom-Auth",
    "Bearer"
]

def check(session, url, soup, response, config):
    """
    Enhanced CORS misconfiguration detection with comprehensive testing.
    
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
    
    # Parse the target URL to get the domain
    parsed_url = urllib.parse.urlparse(url)
    target_domain = parsed_url.netloc

    
    # Set up the test origins with target domain
    test_origins = []
    for origin in CORS_TEST_ORIGINS:
        if "{target_domain}" in origin:
            test_origins.append(origin.format(target_domain=target_domain))
        else:
            test_origins.append(origin)
    
    # Extract domain without port if present
    domain_parts = target_domain.split(':')
    bare_domain = domain_parts[0]
    
    # Track the CORS policy information
    cors_policy_info = {}
    
    # Baseline - request without Origin header
    baseline_headers = {}
    for header in CORS_HEADERS:
        if header in response.headers:
            baseline_headers[header] = response.headers[header]
    
    # Test 1: Basic CORS test with various origins
    for test_origin in test_origins:
        headers = {
            'Origin': test_origin
        }
        
        try:
            r = req_session.get(url, headers=headers, timeout=5)
            
            # Check if CORS headers are in response
            cors_headers_in_response = {}
            for header in CORS_HEADERS:
                if header in r.headers:
                    cors_headers_in_response[header] = r.headers[header]
            
            # Skip if no CORS headers found in response
            if not cors_headers_in_response:
                continue
            
            # Check if Access-Control-Allow-Origin header is present and reflective
            if 'Access-Control-Allow-Origin' in r.headers:
                allow_origin = r.headers['Access-Control-Allow-Origin']
                cors_policy_info[test_origin] = allow_origin
                
                # Check for specific CORS issues
                
                # Issue 1: Origin reflection (echoing back the origin header directly)
                if allow_origin == test_origin and test_origin not in ["null", f"https://{target_domain}", f"http://{target_domain}"]:
                    findings.append(f"CORS misconfiguration: Origin reflection detected with {test_origin}")
                    findings.append(f"- Server reflects arbitrary Origin: {allow_origin}")
                    
                    # Check if credentials are allowed with this reflection
                    if 'Access-Control-Allow-Credentials' in r.headers and r.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                        findings.append(f"CRITICAL: CORS allows credentials with arbitrary origin {test_origin}")
                        findings.append(f"- This can lead to cross-domain data theft if user is authenticated")
                
                # Issue 2: Wildcard origin with credentials (not allowed by browsers but still report)
                if allow_origin == '*' and 'Access-Control-Allow-Credentials' in r.headers and r.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                    findings.append("CORS warning: Wildcard origin (*) with credentials true")
                    findings.append("- Browsers will refuse this combination, but it suggests a misconfiguration")
                
                # Issue 3: Overly permissive subdomain matching
                if test_origin.endswith(bare_domain) and allow_origin == test_origin:
                    findings.append(f"CORS misconfiguration: Permissive subdomain matching for {test_origin}")
                    findings.append(f"- Subdomains of the main domain are trusted: {allow_origin}")
                    
                    # Check credentials for subdomain issue
                    if 'Access-Control-Allow-Credentials' in r.headers and r.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                        findings.append(f"CRITICAL: CORS allows credentials with arbitrary subdomain origin")
                
                # Issue 4: Null origin allowed
                if test_origin == 'null' and allow_origin == 'null':
                    findings.append("CORS misconfiguration: 'null' origin allowed")
                    findings.append("- This can be exploited via sandbox iframes, data URLs, or local HTML files")
                    
                    # Check credentials with null origin
                    if 'Access-Control-Allow-Credentials' in r.headers and r.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                        findings.append("CRITICAL: CORS allows credentials with 'null' origin")
                        findings.append("- This can lead to data theft through attacker-controlled frames")
                
                # Issue 5: Very permissive allowed methods
                if 'Access-Control-Allow-Methods' in r.headers:
                    allowed_methods = [m.strip() for m in r.headers['Access-Control-Allow-Methods'].split(',')]
                    if len(allowed_methods) > 5 or '*' in allowed_methods:
                        findings.append("CORS warning: Very permissive Access-Control-Allow-Methods")
                        findings.append(f"- Allows methods: {r.headers['Access-Control-Allow-Methods']}")
                
                # Issue 6: Very permissive allowed headers
                if 'Access-Control-Allow-Headers' in r.headers:
                    allowed_headers = [h.strip().lower() for h in r.headers['Access-Control-Allow-Headers'].split(',')]
                    if '*' in allowed_headers:
                        findings.append("CORS warning: Wildcard (*) in Access-Control-Allow-Headers")
                        findings.append("- Any header can be included in cross-origin requests")
                    else:
                        sensitive_headers_allowed = [h for h in SENSITIVE_HEADERS if h.lower() in allowed_headers]
                        if sensitive_headers_allowed and 'Access-Control-Allow-Credentials' in r.headers and r.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                            findings.append("CORS warning: Sensitive headers allowed in cross-origin requests with credentials")
                            findings.append(f"- Sensitive headers: {', '.join(sensitive_headers_allowed)}")
        
        except Exception as e:
            continue
    
    # Test 2: Pre-flight OPTIONS request tests
    for test_origin in test_origins[:3]:  # Use first few origins to avoid too many requests
        headers = {
            'Origin': test_origin,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type, Authorization'
        }
        
        try:
            r = req_session.options(url, headers=headers, timeout=5)
            
            # Check if CORS pre-flight headers are in response
            if 'Access-Control-Allow-Origin' in r.headers:
                allow_origin = r.headers['Access-Control-Allow-Origin']
                
                # Check for pre-flight CORS issues
                
                # Issue 7: Pre-flight reflection of arbitrary origin
                if allow_origin == test_origin and test_origin not in ["null", f"https://{target_domain}", f"http://{target_domain}"]:
                    findings.append(f"CORS pre-flight misconfiguration: Origin reflection in OPTIONS request with {test_origin}")
                    
                    # Check what methods are allowed after pre-flight
                    if 'Access-Control-Allow-Methods' in r.headers:
                        findings.append(f"- Allows methods after pre-flight: {r.headers['Access-Control-Allow-Methods']}")
                    
                    # Check what headers are allowed after pre-flight
                    if 'Access-Control-Allow-Headers' in r.headers:
                        findings.append(f"- Allows headers after pre-flight: {r.headers['Access-Control-Allow-Headers']}")
                    
                    # Check if credentials are allowed for pre-flight
                    if 'Access-Control-Allow-Credentials' in r.headers and r.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                        findings.append(f"CRITICAL: Pre-flight allows credentials with arbitrary origin {test_origin}")
        
        except Exception as e:
            continue
    
    # Test 3: Check for exploitable JSON endpoints that might be vulnerable to CORS misconfigurations
    # This focuses on endpoints that might return sensitive data
    if not findings:
        # Try to find JSON endpoints by modifying the URL path
        path_parts = parsed_url.path.split('/')
        test_paths = []
        
        # Add common JSON API paths
        api_paths = [
            '/api/user', '/api/profile', '/api/account',
            '/api/users', '/api/data', '/api/config',
            '/user', '/profile', '/account', '/settings',
            '/api/v1/user', '/api/v1/profile', '/api/v1/account'
        ]
        
        # Construct test paths based on the current URL path and common API paths
        for api_path in api_paths:
            test_url = urllib.parse.urlunparse((
                parsed_url.netloc,
                api_path,
                parsed_url.params,
                parsed_url.query,
                parsed_url.fragment
            ))
            test_paths.append(test_url)
        
        # If we're already at an API path, use that
        if '/api/' in parsed_url.path:
            test_paths.insert(0, url)
        
        # Test JSON endpoints for CORS issues
        for test_url in test_paths[:3]:  # Limit to first 3 to avoid too many requests
            for test_origin in test_origins[:2]:  # Limit origins as well
                headers = {
                    'Origin': test_origin,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'X-Requested-With': 'XMLHttpRequest'
                }
                
                try:
                    r = req_session.get(test_url, headers=headers, timeout=5)
                    
                    # Check if response is JSON
                    is_json = False
                    try:
                        if r.headers.get('Content-Type', '').startswith('application/json'):
                            json_data = r.json()
                            is_json = True
                    except:
                        pass
                    
                    # If it's a JSON response, check for CORS headers
                    if is_json and 'Access-Control-Allow-Origin' in r.headers:
                        allow_origin = r.headers['Access-Control-Allow-Origin']
                        
                        # Check for CORS issues with JSON API endpoints
                        if allow_origin == test_origin and test_origin not in ["null", f"https://{target_domain}", f"http://{target_domain}"]:
                            findings.append(f"CORS misconfiguration in JSON API: {test_url}")
                            findings.append(f"- Origin {test_origin} is allowed to access potentially sensitive data")
                            
                            # Check for credentials with JSON endpoint
                            if 'Access-Control-Allow-Credentials' in r.headers and r.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                                findings.append(f"CRITICAL: JSON API allows credentials with arbitrary origin")
                                findings.append(f"- This can lead to exposure of sensitive user data from {test_url}")
                
                except Exception as e:
                    continue
    
    # Test 4: Try to determine if the site has CORS protection via framework headers
    # Parse the response for evidence of security headers that might indicate a framework
    security_headers = [
        'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
        'Content-Security-Policy', 'Referrer-Policy', 'Feature-Policy',
        'Strict-Transport-Security'
    ]
    
    security_headers_present = {}
    for header in security_headers:
        if header in response.headers:
            security_headers_present[header] = response.headers[header]
    
    # Check for framework-specific headers
    framework_headers = {
        'X-Powered-By': None,
        'Server': None,
        'X-AspNet-Version': None,
        'X-AspNetMvc-Version': None,
        'X-Generator': None
    }
    
    framework_info = {}
    for header in framework_headers:
        if header in response.headers:
            framework_info[header] = response.headers[header]
    
    # If we have some CORS findings and we know the framework, add a note
    if findings and framework_info:
        findings.append("Framework information that may be relevant to CORS configuration:")
        for header, value in framework_info.items():
            findings.append(f"- {header}: {value}")
    
    # If no findings, but we detected CORS headers, add informational note
    if not findings and cors_policy_info:
        findings.append("CORS is implemented but no obvious misconfigurations were found")
        findings.append("- The server has the following CORS policy:")
        for origin, allow_origin in cors_policy_info.items():
            findings.append(f"  Origin: {origin} → Allow-Origin: {allow_origin}")
    
    return findings 