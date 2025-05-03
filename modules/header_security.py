import json
from . import get_session

# Headers that should be set for security
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS',
        'recommended': 'max-age=31536000; includeSubDomains; preload',
        'regex': r'max-age=(\d+)',
        'min_value': 15768000  # 6 months in seconds
    },
    'Content-Security-Policy': {
        'description': 'Content Security Policy (CSP) helps prevent XSS attacks',
        'recommended': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';",
        'weak_patterns': ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]
    },
    'X-Content-Type-Options': {
        'description': 'Prevents browser from MIME-sniffing a response away from the declared content-type',
        'recommended': 'nosniff'
    },
    'X-Frame-Options': {
        'description': 'Protects against clickjacking attacks',
        'recommended': ['DENY', 'SAMEORIGIN']
    },
    'X-XSS-Protection': {
        'description': 'Enables XSS filtering in some browsers',
        'recommended': '1; mode=block'
    },
    'Referrer-Policy': {
        'description': 'Controls how much referrer information is included with requests',
        'recommended': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']
    },
    'Permissions-Policy': {
        'description': 'Controls which browser features can be used (replaces Feature-Policy)',
        'recommended': "camera=(), microphone=(), geolocation=(), payment=()"
    },
    'Cache-Control': {
        'description': 'Directives for caching mechanisms',
        'recommended_sensitive': 'no-store, no-cache, must-revalidate, max-age=0'
    }
}

# Cookie security attributes
COOKIE_SECURITY = {
    'Secure': {
        'description': 'Cookie is only sent over HTTPS',
        'required': True
    },
    'HttpOnly': {
        'description': 'Helps mitigate XSS attacks by preventing JavaScript access to cookies',
        'required': True
    },
    'SameSite': {
        'description': 'Controls whether cookies are sent with cross-site requests',
        'recommended': ['Strict', 'Lax'],
        'weak': ['None']
    },
    'Expires/Max-Age': {
        'description': 'Sets expiration time for cookies',
        'check': True
    },
    '__Host-': {
        'description': 'Cookie prefix that requires Secure, no Domain, and Path=/',
        'recommended': True
    }
}

# Headers that may leak sensitive information
INFORMATION_LEAKAGE_HEADERS = [
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-Generator',
    'X-Drupal-Cache',
    'X-Drupal-Dynamic-Cache',
    'X-Varnish',
    'Via',
    'X-Backend-Server',
    'X-Runtime',
    'X-Version'
]

def check(session, url, soup, response, config):
    """
    Check for security issues in HTTP response headers
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
    
    Returns:
        List of findings
    """
    findings = []
    
    # Check for each security header
    missing_headers = []
    weak_headers = []
    
    for header, details in SECURITY_HEADERS.items():
        if header not in response.headers:
            missing_headers.append(f"{header} ({details['description']})")
        else:
            # Check if header value is weak
            header_value = response.headers[header]
            
            if header == 'Strict-Transport-Security':
                if 'max-age=' in header_value:
                    import re
                    max_age_match = re.search(details['regex'], header_value)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < details['min_value']:
                            weak_headers.append(f"{header} has a weak max-age ({max_age} seconds, recommended minimum is {details['min_value']})")
                    
                    if 'includeSubDomains' not in header_value:
                        weak_headers.append(f"{header} does not include 'includeSubDomains' directive")
            
            elif header == 'Content-Security-Policy':
                for weak_pattern in details['weak_patterns']:
                    if weak_pattern in header_value:
                        weak_headers.append(f"{header} contains potentially unsafe directive: {weak_pattern}")
            
            elif header == 'X-Frame-Options':
                if header_value.upper() not in details['recommended']:
                    weak_headers.append(f"{header} has value '{header_value}', recommended: {' or '.join(details['recommended'])}")
            
            elif header == 'Referrer-Policy':
                if header_value not in details['recommended']:
                    weak_headers.append(f"{header} has value '{header_value}', recommended: {', '.join(details['recommended'])}")
            
            elif header == 'X-Content-Type-Options' and header_value != 'nosniff':
                weak_headers.append(f"{header} has value '{header_value}', recommended: nosniff")
            
            elif header == 'X-XSS-Protection' and header_value != '1; mode=block':
                weak_headers.append(f"{header} has value '{header_value}', recommended: 1; mode=block")
    
    # Check for information leakage headers
    leaked_info = []
    for header in INFORMATION_LEAKAGE_HEADERS:
        if header in response.headers:
            leaked_info.append(f"{header}: {response.headers[header]}")
    
    # Check cookies for security issues
    insecure_cookies = []
    for cookie in response.cookies:
        cookie_issues = []
        
        # Check if the cookie is missing security attributes
        if not cookie.secure:
            cookie_issues.append("Missing 'Secure' attribute")
        
        if not cookie.has_nonstandard_attr('HttpOnly'):
            cookie_issues.append("Missing 'HttpOnly' attribute")
        
        # Check SameSite attribute
        samesite = None
        for attr in cookie._rest.keys():
            if attr.lower() == 'samesite':
                samesite = cookie._rest[attr]
        
        if not samesite:
            cookie_issues.append("Missing 'SameSite' attribute")
        elif samesite == 'None' and not cookie.secure:
            cookie_issues.append("'SameSite=None' requires 'Secure' attribute")
        
        # Check for session cookies without expiry
        if cookie.name.lower().find('sess') >= 0 and not cookie.expires:
            cookie_issues.append("Session cookie without expiration")
        
        # Check for __Host- prefix compliance
        if cookie.name.startswith('__Host-'):
            if not cookie.secure or cookie.domain or cookie.path != '/':
                cookie_issues.append("__Host- prefix cookie doesn't meet requirements (requires Secure, no Domain, Path=/)")
        
        # Check for __Secure- prefix compliance
        if cookie.name.startswith('__Secure-') and not cookie.secure:
            cookie_issues.append("__Secure- prefix cookie missing Secure attribute")
        
        if cookie_issues:
            insecure_cookies.append(f"Cookie '{cookie.name}': {', '.join(cookie_issues)}")
    
    # Generate findings
    if missing_headers:
        findings.append("Missing security headers:")
        for header in missing_headers:
            findings.append(f"- {header}")
    
    if weak_headers:
        findings.append("Weak security header configurations:")
        for header in weak_headers:
            findings.append(f"- {header}")
    
    if leaked_info:
        findings.append("Information leakage in headers:")
        for info in leaked_info:
            findings.append(f"- {info}")
    
    if insecure_cookies:
        findings.append("Insecure cookie configurations:")
        for cookie in insecure_cookies:
            findings.append(f"- {cookie}")
    
    # Additional security checks
    
    # Check for HTTPS
    if url.startswith('http:'):
        findings.append("- Site is not using HTTPS, which exposes all traffic to interception")
    
    # Check for Mixed Content
    if url.startswith('https:') and 'Content-Security-Policy' not in response.headers:
        findings.append("- Site using HTTPS but doesn't define Content-Security-Policy to prevent mixed content")
    
    # Check if Cookies are sent over HTTP
    has_sensitive_cookies = False
    for cookie in response.cookies:
        if any(sensitive_name in cookie.name.lower() for sensitive_name in ['session', 'auth', 'token', 'jwt', 'admin', 'login', 'user']):
            has_sensitive_cookies = True
            break
    
    if has_sensitive_cookies and url.startswith('http:'):
        findings.append("- Sensitive cookies are being transmitted over insecure HTTP")
    
    if not findings:
        findings.append("No header security issues found")
    
    return findings 