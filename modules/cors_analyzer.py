import json
import re
import urllib.parse
from urllib.parse import urlparse
import ipaddress
import requests

# CORS related headers
CORS_HEADERS = {
    'Access-Control-Allow-Origin': 'Specifies which origins can access the resource',
    'Access-Control-Allow-Credentials': 'Indicates whether the response can be shared when credentials flag is true',
    'Access-Control-Allow-Methods': 'Specifies the methods allowed when accessing the resource',
    'Access-Control-Allow-Headers': 'Indicates which headers can be used during the actual request',
    'Access-Control-Expose-Headers': 'Indicates which headers can be exposed as part of the response',
    'Access-Control-Max-Age': 'Indicates how long the results of a preflight request can be cached',
    'Timing-Allow-Origin': 'Specifies origins that are allowed to see values of attributes retrieved via timing API',
}

# Risky wildcards in origins that may indicate vulnerable configurations
RISKY_WILDCARDS = [
    '*',
    '*.example.com',
    'https://*',
    'https://*.com',
    'null',
    'file://',
    'data:',
]

# Potentially dangerous wildcards and configurations
DANGEROUS_ORIGINS = [
    '*',                         # Allows any origin
    'null',                      # Allows requests from data: or file: URLs
    'file://',                   # Allows file protocol (dangerous)
    'data:',                     # Allows data URLs (dangerous)
]

# Commonly vulnerable endpoints
SENSITIVE_ENDPOINTS = [
    '/api/',
    '/user/',
    '/account/',
    '/admin/',
    '/auth/',
    '/oauth/',
    '/token/',
    '/login',
    '/register',
    '/profile',
    '/settings',
    '/password',
    '/reset',
    '/payment',
    '/billing',
    '/checkout'
]

# Dictionary of common CORS misconfigurations with descriptions and severity
CORS_MISCONFIGURATIONS = {
    'wildcard_origin': {
        'description': 'CORS allows requests from any origin using wildcard (*)',
        'severity': 'HIGH',
        'recommendation': 'Restrict CORS to specific trusted origins instead of using wildcards',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSAllowOriginWithWildcard'
    },
    'reflect_origin': {
        'description': 'CORS reflects the Origin header without validation',
        'severity': 'HIGH',
        'recommendation': 'Validate Origin headers against a whitelist of trusted domains',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'
    },
    'null_origin': {
        'description': 'CORS allows the null origin, which can be exploited',
        'severity': 'MEDIUM',
        'recommendation': 'Remove "null" from allowed origins list',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin'
    },
    'insecure_origin': {
        'description': 'CORS allows insecure origins (HTTP instead of HTTPS)',
        'severity': 'MEDIUM',
        'recommendation': 'Only allow secure origins using HTTPS protocol',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'
    },
    'credentials_with_wildcard': {
        'description': 'CORS allows credentials with wildcard origin',
        'severity': 'HIGH',
        'recommendation': 'Never use wildcard with credentials; specify exact origins',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials'
    },
    'weak_regex_protection': {
        'description': 'CORS uses weak regex pattern for allowed origins',
        'severity': 'MEDIUM',
        'recommendation': 'Use strict domain matching without easily bypassed patterns',
        'info_link': 'https://www.zaproxy.org/docs/alerts/40039/'
    },
    'excessive_allowed_methods': {
        'description': 'CORS allows sensitive HTTP methods unnecessarily',
        'severity': 'MEDIUM',
        'recommendation': 'Only allow methods that are required for the application to function',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods'
    },
    'excessive_allowed_headers': {
        'description': 'CORS allows sensitive headers unnecessarily',
        'severity': 'LOW',
        'recommendation': 'Only allow headers that are required for the application to function',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers'
    },
    'excessive_exposed_headers': {
        'description': 'CORS exposes sensitive headers unnecessarily',
        'severity': 'LOW',
        'recommendation': 'Only expose headers that are required for the application to function',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers'
    },
    'missing_cors_headers': {
        'description': 'API endpoint is missing CORS headers for cross-origin functionality',
        'severity': 'INFO',
        'recommendation': 'If cross-origin access is intended, properly configure CORS headers',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'
    }
}

# Dangerous HTTP methods for CORS
SENSITIVE_METHODS = ['DELETE', 'PUT', 'PATCH']

# Headers that shouldn't typically be exposed
SENSITIVE_HEADERS = ['Authorization', 'Cookie', 'Set-Cookie', 'WWW-Authenticate', 'Proxy-Authenticate']

# Headers that shouldn't typically be allowed
SENSITIVE_ALLOWED_HEADERS = ['Cookie', 'Origin', 'Referer', 'User-Agent', 'Host']

# Patterns that might indicate weak regex-based origin validation
WEAK_REGEX_PATTERNS = [
    r'.*\.example\.com$',  # Doesn't account for subdomains like evil-example.com
    r'https?://.*\.example\.com$',  # Matches http://subdomain.example.com.evil.com
    r'^https://example\.',  # Doesn't check the end of the string
    r'example\.com',  # No protocol or boundary checks
]

# CORS misconfiguration risk levels
CORS_RISKS = {
    'wildcard_allow_origin_with_credentials': {
        'description': 'Access-Control-Allow-Origin set to * with Allow-Credentials: true',
        'severity': 'CRITICAL',
        'recommendation': 'Never use wildcard with credentials, specify exact trusted origins instead',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials'
    },
    'wildcard_allow_origin': {
        'description': 'Access-Control-Allow-Origin set to * (wildcard)',
        'severity': 'HIGH',
        'recommendation': 'Specify exact trusted origins instead of using wildcard',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin'
    },
    'null_allow_origin': {
        'description': 'Access-Control-Allow-Origin set to "null"',
        'severity': 'HIGH',
        'recommendation': 'Avoid using "null" as it can be spoofed. Specify exact trusted origins.',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin'
    },
    'wildcard_allow_methods': {
        'description': 'Access-Control-Allow-Methods includes all methods or sensitive methods',
        'severity': 'MEDIUM',
        'recommendation': 'Only allow necessary HTTP methods',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods'
    },
    'sensitive_origin': {
        'description': 'Access-Control-Allow-Origin includes sensitive/suspicious domains',
        'severity': 'HIGH',
        'recommendation': 'Review and remove untrusted domains',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'
    },
    'reflected_origin': {
        'description': 'Access-Control-Allow-Origin appears to reflect Origin header',
        'severity': 'HIGH',
        'recommendation': 'Validate origins against a whitelist instead of reflecting them',
        'info_link': 'https://portswigger.net/web-security/cors/access-control-allow-origin'
    },
    'regex_or_prefix_in_origin': {
        'description': 'Access-Control-Allow-Origin contains regex or prefix patterns',
        'severity': 'HIGH',
        'recommendation': 'Use exact origin matching instead of patterns or prefixes',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'
    },
    'overly_permissive_allow_headers': {
        'description': 'Access-Control-Allow-Headers set to * (wildcard)',
        'severity': 'MEDIUM',
        'recommendation': 'Explicitly list necessary headers instead of using wildcard',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers'
    },
    'missing_allow_methods': {
        'description': 'Access-Control-Allow-Methods is missing',
        'severity': 'LOW',
        'recommendation': 'Specify allowed methods explicitly',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods'
    },
    'missing_allow_headers': {
        'description': 'Access-Control-Allow-Headers is missing',
        'severity': 'LOW',
        'recommendation': 'Specify allowed headers explicitly',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers'
    },
    'missing_max_age': {
        'description': 'Access-Control-Max-Age is missing',
        'severity': 'LOW',
        'recommendation': 'Set an appropriate max age to optimize preflight requests',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age'
    }
}

# Suspicious domains that might indicate misconfiguration if allowed
SUSPICIOUS_DOMAINS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'evil.com',
    'attacker.com',
    'example.com',
    'test.com',
    'null.com'
]

# Helper function to extract domain from URL
def extract_domain(url):
    """Extract the domain from a URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        return domain
    except:
        return None

# Helper function to check if domain is IP
def is_ip_address(domain):
    """Check if a domain is an IP address."""
    try:
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def check_wildcard_in_origin(origin_value):
    """Check if origin contains wildcards or dangerous values."""
    issues = []
    
    if origin_value == '*':
        issues.append("Access-Control-Allow-Origin set to wildcard '*' - any domain can access this resource")
    
    if 'null' in origin_value.lower():
        issues.append("Access-Control-Allow-Origin accepts 'null' origin, which can be spoofed by attackers")

    # Check for subdomain wildcards
    if origin_value.startswith('*.'):
        domain = origin_value[2:]
        issues.append(f"Access-Control-Allow-Origin uses subdomain wildcard (*.{domain}) which may be overly permissive")
    
    return issues

def check_dynamic_cors(request_origin, response_origin):
    """Check if CORS headers are dynamically reflected from request."""
    if request_origin and response_origin and request_origin == response_origin:
        return ["CORS origin appears to be dynamically reflected from request, which may allow attackers to bypass restrictions"]
    return []

def check_credentials_with_wildcard(allow_origin, allow_credentials):
    """Check for wildcard origin with credentials allowed."""
    if allow_origin == '*' and allow_credentials.lower() == 'true':
        return ["Access-Control-Allow-Origin set to wildcard '*' with Access-Control-Allow-Credentials set to 'true' (browsers will block this)"]
    return []

def check_unnecessary_cors(request_origin, response_origin, request_url):
    """Check if CORS headers are being set for same-origin requests."""
    if not request_origin or not response_origin or not request_url:
        return []
    
    request_domain = extract_domain(request_url)
    origin_domain = extract_domain(request_origin)
    
    if request_domain and origin_domain and request_domain == origin_domain:
        return ["CORS headers are being set for same-origin requests, which is unnecessary"]
    
    return []

def analyze_methods(methods_value):
    """Analyze the allowed methods for security concerns."""
    issues = []
    
    if not methods_value:
        return issues
    
    methods = [m.strip().upper() for m in methods_value.split(',')]
    
    # Check for dangerous methods
    dangerous_methods = ['PUT', 'DELETE', 'PATCH']
    found_dangerous = [m for m in methods if m in dangerous_methods]
    
    if found_dangerous:
        issues.append(f"Access-Control-Allow-Methods includes potentially dangerous methods: {', '.join(found_dangerous)}")
    
    # Check for non-standard methods
    standard_methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH']
    nonstandard = [m for m in methods if m not in standard_methods]
    
    if nonstandard:
        issues.append(f"Access-Control-Allow-Methods includes non-standard methods: {', '.join(nonstandard)}")
    
    return issues

def parse_cors_headers(headers):
    """
    Parse CORS headers from response headers.
    
    Args:
        headers: HTTP response headers
        
    Returns:
        Dictionary of CORS headers
    """
    cors_headers = {}
    
    # Extract all CORS-related headers
    for key, value in headers.items():
        if key.lower().startswith('access-control-'):
            cors_headers[key.lower()] = value
    
    return cors_headers

def is_origin_wildcard(origin):
    """
    Check if an origin contains wildcards that can be exploited.
    
    Args:
        origin: The origin value to check
        
    Returns:
        Boolean indicating if it's a risky origin
    """
    if any(wildcard in origin for wildcard in DANGEROUS_ORIGINS):
        return True
        
    # Check for domain wildcards that are too broad
    if origin.startswith('*.') and origin.count('.') <= 2:  # e.g. *.example.com
        return True
        
    # Check for subdomain wildcards
    wildcard_subdomain = re.search(r'https?://[^.]+\.\*\.', origin)
    if wildcard_subdomain:
        return True
        
    return False

def test_preflight_request(session, url, methods=None):
    """
    Test CORS preflight response for the given URL.
    
    Args:
        session: Requests session
        url: URL to test
        methods: HTTP methods to test
        
    Returns:
        Dictionary with preflight results
    """
    if methods is None:
        methods = ['PUT', 'DELETE', 'PATCH']
    
    results = {}
    
    try:
        parsed_url = urllib.parse.urlparse(url)
        origin = f"{parsed_url.scheme}://evil-attacker.com"
        
        for method in methods:
            headers = {
                'Origin': origin,
                'Access-Control-Request-Method': method,
                'Access-Control-Request-Headers': 'Content-Type, Authorization'
            }
            
            response = session.options(url, headers=headers, timeout=10)
            cors_headers = parse_cors_headers(response.headers)
            
            results[method] = {
                'status_code': response.status_code,
                'allowed': 'access-control-allow-methods' in cors_headers and 
                           method in cors_headers.get('access-control-allow-methods', ''),
                'allow_origin': cors_headers.get('access-control-allow-origin', ''),
                'allow_credentials': cors_headers.get('access-control-allow-credentials', ''),
                'allow_headers': cors_headers.get('access-control-allow-headers', ''),
                'expose_headers': cors_headers.get('access-control-expose-headers', '')
            }
    except Exception as e:
        results['error'] = str(e)
    
    return results

def check_sensitive_endpoints(session, url, cors_issues):
    """
    Check CORS configuration on potentially sensitive endpoints.
    
    Args:
        session: Requests session
        url: Base URL
        cors_issues: List to append findings to
        
    Returns:
        Updated cors_issues list
    """
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for endpoint in SENSITIVE_ENDPOINTS:
        endpoint_url = urllib.parse.urljoin(base_url, endpoint)
        
        try:
            headers = {'Origin': 'https://evil-attacker.com'}
            response = session.get(endpoint_url, headers=headers, timeout=5)
            
            cors_headers = parse_cors_headers(response.headers)
            
            # Check if endpoint exists (200, 204, 401, 403 suggest it exists)
            if response.status_code in (200, 204, 401, 403):
                allow_origin = cors_headers.get('access-control-allow-origin', '')
                allow_credentials = cors_headers.get('access-control-allow-credentials', '')
                
                # Check for dangerous configurations
                if allow_origin and (is_origin_wildcard(allow_origin) or 'evil-attacker.com' in allow_origin):
                    issue = f"Sensitive endpoint {endpoint} allows requests from arbitrary origins"
                    if allow_credentials == 'true':
                        issue += " with credentials"
                    cors_issues.append(issue)
        except:
            # Skip any errors for endpoints that don't exist
            pass
    
    return cors_issues

def analyze_cors_policy(cors_headers, url):
    """
    Analyze CORS policy for security issues.
    
    Args:
        cors_headers: Dictionary of CORS headers
        url: URL being tested
        
    Returns:
        List of issues found
    """
    issues = []
    
    allow_origin = cors_headers.get('access-control-allow-origin', '')
    allow_credentials = cors_headers.get('access-control-allow-credentials', '')
    allow_methods = cors_headers.get('access-control-allow-methods', '')
    allow_headers = cors_headers.get('access-control-allow-headers', '')
    
    # Check for overly permissive allow-origin
    if allow_origin == '*':
        issues.append("CORS allows requests from any origin (access-control-allow-origin: *)")
    
    # Check for dangerous Allow-Origin and Allow-Credentials combination
    if allow_origin and allow_credentials == 'true':
        if allow_origin == '*':
            issues.append("Misconfiguration: access-control-allow-origin: * with access-control-allow-credentials: true (browsers will block this)")
        elif is_origin_wildcard(allow_origin):
            issues.append(f"Dangerous configuration: allows wildcard origin {allow_origin} with credentials")
    
    # Check for dangerous wildcards in origin
    if allow_origin and is_origin_wildcard(allow_origin) and allow_origin != '*':
        issues.append(f"Uses potentially exploitable wildcard in Access-Control-Allow-Origin: {allow_origin}")
    
    # Check for reflection of Origin header (possible CORS misconfiguration)
    parsed_url = urllib.parse.urlparse(url)
    origin_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    if allow_origin and allow_origin != '*' and allow_origin != origin_domain:
        issues.append(f"CORS policy allows non-standard origin: {allow_origin}")
    
    # Check for overly permissive allowed methods
    if 'DELETE' in allow_methods or 'PUT' in allow_methods or 'PATCH' in allow_methods:
        issues.append(f"Allows potentially dangerous HTTP methods: {allow_methods}")
    
    return issues

def analyze_cors_headers(response_headers, request_headers, findings):
    """
    Analyzes CORS headers for security issues.
    
    Args:
        response_headers: HTTP response headers
        request_headers: HTTP request headers
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    origin_header = None
    if 'Origin' in request_headers:
        origin_header = request_headers['Origin']
    
    # Extract CORS-related headers
    allow_origin = response_headers.get('Access-Control-Allow-Origin', '')
    allow_credentials = response_headers.get('Access-Control-Allow-Credentials', '')
    allow_methods = response_headers.get('Access-Control-Allow-Methods', '')
    allow_headers = response_headers.get('Access-Control-Allow-Headers', '')
    expose_headers = response_headers.get('Access-Control-Expose-Headers', '')
    max_age = response_headers.get('Access-Control-Max-Age', '')
    
    # Check if CORS is implemented
    if not any([allow_origin, allow_credentials, allow_methods, allow_headers, expose_headers, max_age]):
        findings.append({
            'type': 'missing_cors_headers',
            'message': CORS_MISCONFIGURATIONS['missing_cors_headers']['description'],
            'severity': CORS_MISCONFIGURATIONS['missing_cors_headers']['severity'],
            'recommendation': CORS_MISCONFIGURATIONS['missing_cors_headers']['recommendation']
        })
        return findings
    
    # Check for wildcard origin
    if allow_origin == '*':
        findings.append({
            'type': 'wildcard_origin',
            'message': CORS_MISCONFIGURATIONS['wildcard_origin']['description'],
            'severity': CORS_MISCONFIGURATIONS['wildcard_origin']['severity'],
            'recommendation': CORS_MISCONFIGURATIONS['wildcard_origin']['recommendation']
        })
    
    # Check for reflected origin
    if origin_header and allow_origin == origin_header:
        findings.append({
            'type': 'reflect_origin',
            'message': CORS_MISCONFIGURATIONS['reflect_origin']['description'],
            'severity': CORS_MISCONFIGURATIONS['reflect_origin']['severity'],
            'recommendation': CORS_MISCONFIGURATIONS['reflect_origin']['recommendation']
        })
    
    # Check for null origin
    if 'null' in allow_origin:
        findings.append({
            'type': 'null_origin',
            'message': CORS_MISCONFIGURATIONS['null_origin']['description'],
            'severity': CORS_MISCONFIGURATIONS['null_origin']['severity'],
            'recommendation': CORS_MISCONFIGURATIONS['null_origin']['recommendation']
        })
    
    # Check for insecure origin (HTTP)
    if allow_origin and 'http:' in allow_origin and not 'https:' in allow_origin:
        findings.append({
            'type': 'insecure_origin',
            'message': CORS_MISCONFIGURATIONS['insecure_origin']['description'],
            'severity': CORS_MISCONFIGURATIONS['insecure_origin']['severity'],
            'recommendation': CORS_MISCONFIGURATIONS['insecure_origin']['recommendation']
        })
    
    # Check for credentials with wildcard
    if allow_credentials.lower() == 'true' and allow_origin == '*':
        findings.append({
            'type': 'credentials_with_wildcard',
            'message': CORS_MISCONFIGURATIONS['credentials_with_wildcard']['description'],
            'severity': CORS_MISCONFIGURATIONS['credentials_with_wildcard']['severity'],
            'recommendation': CORS_MISCONFIGURATIONS['credentials_with_wildcard']['recommendation']
        })
    
    # Check for sensitive methods
    if allow_methods:
        methods = [m.strip().upper() for m in allow_methods.split(',')]
        found_sensitive_methods = [m for m in methods if m in SENSITIVE_METHODS]
        if found_sensitive_methods:
            findings.append({
                'type': 'excessive_allowed_methods',
                'message': f"{CORS_MISCONFIGURATIONS['excessive_allowed_methods']['description']}: {', '.join(found_sensitive_methods)}",
                'severity': CORS_MISCONFIGURATIONS['excessive_allowed_methods']['severity'],
                'recommendation': CORS_MISCONFIGURATIONS['excessive_allowed_methods']['recommendation']
            })
    
    # Check for sensitive allowed headers
    if allow_headers:
        headers = [h.strip().lower() for h in allow_headers.split(',')]
        found_sensitive_headers = [h for h in headers if h.lower() in [sh.lower() for sh in SENSITIVE_ALLOWED_HEADERS]]
        if found_sensitive_headers:
            findings.append({
                'type': 'excessive_allowed_headers',
                'message': f"{CORS_MISCONFIGURATIONS['excessive_allowed_headers']['description']}: {', '.join(found_sensitive_headers)}",
                'severity': CORS_MISCONFIGURATIONS['excessive_allowed_headers']['severity'],
                'recommendation': CORS_MISCONFIGURATIONS['excessive_allowed_headers']['recommendation']
            })
    
    # Check for sensitive exposed headers
    if expose_headers:
        headers = [h.strip().lower() for h in expose_headers.split(',')]
        found_sensitive_headers = [h for h in headers if h.lower() in [sh.lower() for sh in SENSITIVE_HEADERS]]
        if found_sensitive_headers:
            findings.append({
                'type': 'excessive_exposed_headers',
                'message': f"{CORS_MISCONFIGURATIONS['excessive_exposed_headers']['description']}: {', '.join(found_sensitive_headers)}",
                'severity': CORS_MISCONFIGURATIONS['excessive_exposed_headers']['severity'],
                'recommendation': CORS_MISCONFIGURATIONS['excessive_exposed_headers']['recommendation']
            })
    
    return findings

def check_for_weak_regex_validation(allow_origin, findings):
    """
    Check if the Allow-Origin header might be using weak regex validation.
    This is a heuristic check based on common patterns.
    
    Args:
        allow_origin: The Access-Control-Allow-Origin header value
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Skip if it's a simple wildcard or a single domain
    if allow_origin == '*' or ',' not in allow_origin:
        return findings
    
    # Check for signs of regex patterns (multiple domains with similar patterns)
    origins = [o.strip() for o in allow_origin.split(',')]
    
    # Extract domains from origins
    domains = []
    for origin in origins:
        try:
            parsed = urlparse(origin)
            if parsed.netloc:
                domains.append(parsed.netloc)
        except:
            continue
    
    # Look for patterns that might suggest regex validation
    domain_prefixes = {}
    domain_suffixes = {}
    
    for domain in domains:
        parts = domain.split('.')
        if len(parts) > 2:
            prefix = parts[0]
            suffix = '.'.join(parts[1:])
            
            if suffix in domain_suffixes:
                domain_suffixes[suffix] += 1
            else:
                domain_suffixes[suffix] = 1
                
            if prefix in domain_prefixes:
                domain_prefixes[prefix] += 1
            else:
                domain_prefixes[prefix] = 1
    
    # If multiple subdomains of the same domain are allowed, it might be using regex
    high_count_suffixes = [suffix for suffix, count in domain_suffixes.items() if count > 3]
    if high_count_suffixes:
        findings.append({
            'type': 'weak_regex_protection',
            'message': f"{CORS_MISCONFIGURATIONS['weak_regex_protection']['description']} (multiple subdomains of {', '.join(high_count_suffixes)})",
            'severity': CORS_MISCONFIGURATIONS['weak_regex_protection']['severity'],
            'recommendation': CORS_MISCONFIGURATIONS['weak_regex_protection']['recommendation']
        })
    
    return findings

def test_cors_preflight_request(session, url, findings):
    """
    Test CORS preflight requests to check for proper CORS implementation.
    
    Args:
        session: Request session to use
        url: URL to test
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Set up the OPTIONS request with CORS preflight headers
    headers = {
        'Origin': 'https://scanner-testing-domain.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type'
    }
    
    try:
        # Send OPTIONS request
        response = session.options(url, headers=headers, timeout=10)
        
        # Check if the preflight request was properly handled
        if response.status_code < 200 or response.status_code >= 300:
            findings.append({
                'type': 'preflight_error',
                'message': f"CORS preflight request failed with status code {response.status_code}",
                'severity': 'MEDIUM',
                'recommendation': "Properly handle OPTIONS requests for CORS preflight"
            })
            return findings
        
        # Analyze the preflight response headers
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check for required preflight response headers
        required_headers = [
            'access-control-allow-origin',
            'access-control-allow-methods',
            'access-control-allow-headers'
        ]
        
        missing_headers = [h for h in required_headers if h not in response_headers]
        if missing_headers:
            findings.append({
                'type': 'missing_preflight_headers',
                'message': f"Missing required CORS preflight response headers: {', '.join(missing_headers)}",
                'severity': 'MEDIUM',
                'recommendation': "Include all required CORS headers in preflight responses"
            })
        
    except Exception as e:
        findings.append({
            'type': 'preflight_error',
            'message': f"Error testing CORS preflight: {str(e)}",
            'severity': 'INFO',
            'recommendation': "Ensure the server properly handles OPTIONS requests"
        })
    
    return findings

def format_findings(findings):
    """
    Format the findings list for better readability.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        List of formatted finding strings
    """
    formatted_findings = []
    
    for finding in findings:
        severity = finding['severity']
        message = finding['message']
        recommendation = finding.get('recommendation', '')
        
        formatted_finding = f"{severity} RISK: {message}"
        if recommendation:
            formatted_finding += f"\nRECOMMENDATION: {recommendation}"
        
        formatted_findings.append(formatted_finding)
    
    return formatted_findings

def check(session, url, soup, response, config):
    """
    Check for CORS security issues.
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
    
    Returns:
        List of formatted findings
    """
    findings = []
    
    # Extract request and response headers
    response_headers = {k: v for k, v in response.headers.items()}
    request_headers = {'Origin': 'https://scanner-testing-domain.com'}
    
    # Analyze CORS headers in the response
    findings = analyze_cors_headers(response_headers, request_headers, findings)
    
    # Check for weak regex validation if Allow-Origin header is present
    if 'Access-Control-Allow-Origin' in response_headers:
        findings = check_for_weak_regex_validation(response_headers['Access-Control-Allow-Origin'], findings)
    
    # Test CORS preflight requests
    findings = test_cors_preflight_request(session, url, findings)
    
    # If no CORS issues were found but CORS headers are present, add a note
    if not findings and any(h.startswith('Access-Control-') for h in response_headers):
        findings.append({
            'type': 'info',
            'message': "CORS headers are properly configured",
            'severity': 'INFO',
            'recommendation': ""
        })
    
    # Format the findings for better readability
    formatted_findings = format_findings(findings)
    
    return formatted_findings 