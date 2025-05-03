import re
import json
from urllib.parse import urlparse

# Dictionary of security headers with explanations and best practices
SECURITY_HEADERS = {
    # Essential Security Headers
    'Content-Security-Policy': {
        'importance': 'HIGH',
        'description': 'Controls resources the browser is allowed to load',
        'best_practice': 'Set strict rules allowing only necessary resources',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
    },
    'Strict-Transport-Security': {
        'importance': 'HIGH',
        'description': 'Enforces HTTPS connections',
        'best_practice': 'max-age=31536000; includeSubDomains; preload',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
    },
    'X-Content-Type-Options': {
        'importance': 'HIGH',
        'description': 'Prevents MIME-sniffing',
        'best_practice': 'nosniff',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
    },
    'X-Frame-Options': {
        'importance': 'HIGH',
        'description': 'Prevents clickjacking',
        'best_practice': 'DENY or SAMEORIGIN',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
    },
    
    # Additional Important Headers
    'Permissions-Policy': {
        'importance': 'MEDIUM',
        'description': 'Controls browser features and APIs',
        'best_practice': 'Restrict to necessary features only',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
    },
    'Referrer-Policy': {
        'importance': 'MEDIUM',
        'description': 'Controls referrer information',
        'best_practice': 'strict-origin-when-cross-origin or no-referrer',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
    },
    'Cache-Control': {
        'importance': 'MEDIUM',
        'description': 'Controls browser caching',
        'best_practice': 'no-store, max-age=0 (for sensitive data)',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control'
    },
    'Clear-Site-Data': {
        'importance': 'LOW',
        'description': 'Clears browsing data',
        'best_practice': '"cache", "cookies", "storage" (for logout pages)',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data'
    },
    
    # Deprecated but still checked headers
    'X-XSS-Protection': {
        'importance': 'LOW',
        'description': 'Controls browser XSS protections (deprecated, use CSP instead)',
        'best_practice': '1; mode=block',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
    },
    'Public-Key-Pins': {
        'importance': 'DEPRECATED',
        'description': 'Certificate pinning (deprecated and dangerous)',
        'best_practice': 'Do not use, deprecated by browsers',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins'
    },
    
    # Headers for cookies
    'Set-Cookie': {
        'importance': 'HIGH',
        'description': 'Sets cookies for the client',
        'best_practice': 'Use Secure; HttpOnly; SameSite=Strict attributes',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie'
    }
}

# Headers that should not be present for security
INSECURE_HEADERS = {
    'Server': {
        'importance': 'MEDIUM',
        'description': 'Reveals server information',
        'recommendation': 'Remove or provide minimal information'
    },
    'X-Powered-By': {
        'importance': 'MEDIUM',
        'description': 'Reveals technology stack',
        'recommendation': 'Remove completely'
    },
    'X-AspNet-Version': {
        'importance': 'MEDIUM',
        'description': 'Reveals ASP.NET version',
        'recommendation': 'Remove completely'
    },
    'X-AspNetMvc-Version': {
        'importance': 'MEDIUM',
        'description': 'Reveals ASP.NET MVC version',
        'recommendation': 'Remove completely'
    }
}

def analyze_hsts_header(value, findings):
    """
    Analyze the HSTS header for best practices.
    
    Args:
        value: HSTS header value
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    try:
        # Extract max-age value
        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            
            if max_age < 31536000:  # Less than 1 year
                findings.append(f"MEDIUM RISK: HSTS max-age is {max_age} seconds, which is less than the recommended 1 year (31536000 seconds)")
            else:
                findings.append(f"GOOD: HSTS max-age is set to {max_age} seconds (≥ 1 year)")
        else:
            findings.append("HIGH RISK: HSTS header is missing max-age directive")
        
        # Check for includeSubDomains
        if 'includeSubDomains' not in value:
            findings.append("LOW RISK: HSTS header is missing includeSubDomains directive, which is recommended for full protection")
        else:
            findings.append("GOOD: HSTS includes the includeSubDomains directive")
        
        # Check for preload
        if 'preload' not in value:
            findings.append("INFO: HSTS header does not include the preload directive. Consider adding it for maximum protection")
        else:
            findings.append("GOOD: HSTS includes the preload directive")
            
            # If preload is present, check if the domain is actually in the preload list
            findings.append("NOTE: To ensure your domain is in the HSTS preload list, submit it at https://hstspreload.org")
    
    except Exception as e:
        findings.append(f"ERROR analyzing HSTS header: {str(e)}")
    
    return findings

def analyze_csp_header_basic(value, findings):
    """
    Perform a basic analysis of CSP header to identify major issues.
    
    Args:
        value: CSP header value
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # We'll only do a basic check here as the full CSP analysis is in csp_analyzer.py
    
    # Check for 'unsafe-inline' in script-src
    if "'unsafe-inline'" in value and "script-src" in value:
        findings.append("HIGH RISK: CSP contains 'unsafe-inline' in script-src, which weakens XSS protections")
    
    # Check for 'unsafe-eval'
    if "'unsafe-eval'" in value and "script-src" in value:
        findings.append("MEDIUM RISK: CSP contains 'unsafe-eval' in script-src, which allows potentially dangerous code evaluation")
    
    # Check for wildcards
    if " * " in value or ";*" in value or "* " in value:
        findings.append("HIGH RISK: CSP contains wildcards, which significantly reduces its effectiveness")
    
    # Check if report-uri is present
    if "report-uri" not in value and "report-to" not in value:
        findings.append("IMPROVEMENT: CSP does not include reporting directives (report-uri or report-to)")
    
    # Note about more detailed analysis
    findings.append("NOTE: For a detailed CSP analysis, check the full CSP analyzer results")
    
    return findings

def analyze_xfo_header(value, findings):
    """
    Analyze the X-Frame-Options header for best practices.
    
    Args:
        value: X-Frame-Options header value
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    value = value.upper()
    
    if value == "DENY":
        findings.append("GOOD: X-Frame-Options is set to DENY, providing the strongest protection against clickjacking")
    elif value == "SAMEORIGIN":
        findings.append("GOOD: X-Frame-Options is set to SAMEORIGIN, allowing framing by the same origin only")
    elif value.startswith("ALLOW-FROM"):
        findings.append("CAUTION: X-Frame-Options uses ALLOW-FROM which is not supported by all browsers. Consider using CSP's frame-ancestors instead")
    else:
        findings.append(f"WARNING: X-Frame-Options has an invalid value: {value}")
    
    return findings

def analyze_xxp_header(value, findings):
    """
    Analyze the X-XSS-Protection header for best practices.
    
    Args:
        value: X-XSS-Protection header value
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    if value == "0":
        findings.append("CAUTION: X-XSS-Protection is disabled (0). This may be intentional if using a strong CSP")
    elif value == "1; mode=block":
        findings.append("GOOD: X-XSS-Protection is set to block mode, though modern browsers rely more on CSP")
    elif value == "1":
        findings.append("IMPROVEMENT: X-XSS-Protection is enabled but without block mode. Consider using '1; mode=block'")
    else:
        findings.append(f"NOTE: X-XSS-Protection has an uncommon value: {value}")
    
    findings.append("NOTE: X-XSS-Protection is deprecated in favor of CSP. It's only effective in older browsers")
    
    return findings

def analyze_referrer_policy(value, findings):
    """
    Analyze the Referrer-Policy header for privacy best practices.
    
    Args:
        value: Referrer-Policy header value
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    value = value.lower()
    
    if value in ["no-referrer", "no-referrer-when-downgrade", "strict-origin", "strict-origin-when-cross-origin"]:
        findings.append(f"GOOD: Referrer-Policy is set to '{value}', which provides good privacy protection")
    elif value == "same-origin":
        findings.append("GOOD: Referrer-Policy is set to 'same-origin', which provides decent privacy protection")
    elif value == "origin":
        findings.append("CAUTION: Referrer-Policy 'origin' sends the origin even to cross-origin destinations")
    elif value == "origin-when-cross-origin":
        findings.append("CAUTION: Referrer-Policy 'origin-when-cross-origin' still sends some information to other origins")
    elif value == "unsafe-url":
        findings.append("HIGH RISK: Referrer-Policy 'unsafe-url' sends the full URL in all cases, which may leak sensitive data")
    elif value == "":
        findings.append("MEDIUM RISK: Referrer-Policy is empty, defaulting to browser behavior")
    else:
        findings.append(f"NOTE: Referrer-Policy has an uncommon value: {value}")
    
    return findings

def analyze_permissions_policy(value, findings):
    """
    Analyze the Permissions-Policy header for security best practices.
    
    Args:
        value: Permissions-Policy header value
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Check if any permissions are overly permissive
    if re.search(r'\*\)', value):
        findings.append("CAUTION: Permissions-Policy grants some features to all origins (*), which may be too permissive")
    
    # Check for critical permissions that should be restricted
    critical_features = [
        "camera", "microphone", "geolocation", "payment", "usb", "interest-cohort", 
        "browsing-topics", "publickey-credentials-get"
    ]
    
    for feature in critical_features:
        # Check if the feature is explicitly mentioned
        if feature in value:
            if re.search(rf"{feature}=\(\)", value):
                findings.append(f"GOOD: '{feature}' is blocked completely in Permissions-Policy")
            elif re.search(rf"{feature}=\(\s*self\s*\)", value):
                findings.append(f"GOOD: '{feature}' is restricted to same origin in Permissions-Policy")
        else:
            findings.append(f"NOTE: '{feature}' is not explicitly restricted in Permissions-Policy")
    
    return findings

def analyze_cache_control(value, findings, url_path):
    """
    Analyze the Cache-Control header for security best practices.
    
    Args:
        value: Cache-Control header value
        findings: List to append findings to
        url_path: The path of the URL being analyzed
        
    Returns:
        Updated findings list
    """
    value = value.lower()
    
    # Check for sensitive paths that should have strict caching
    sensitive_path_patterns = [
        r'/login', r'/admin', r'/account', r'/profile', r'/user', r'/settings', 
        r'/dashboard', r'/private', r'/secure', r'/auth', r'/payment', r'/billing'
    ]
    
    is_sensitive_path = any(re.search(pattern, url_path) for pattern in sensitive_path_patterns)
    
    if is_sensitive_path:
        if 'no-store' in value:
            findings.append("GOOD: Cache-Control includes 'no-store' for sensitive content")
        else:
            findings.append("HIGH RISK: Sensitive page should use Cache-Control: no-store to prevent caching")
        
        if 'private' in value:
            findings.append("GOOD: Cache-Control includes 'private' for sensitive content")
        elif 'public' in value:
            findings.append("HIGH RISK: Sensitive page uses Cache-Control: public, which allows shared caches to store the response")
    else:
        # For non-sensitive content, different recommendations apply
        if 'max-age=' in value:
            # Extract max-age value
            max_age_match = re.search(r'max-age=(\d+)', value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age > 31536000:  # More than 1 year
                    findings.append(f"CAUTION: Cache-Control max-age is very long ({max_age} seconds)")
        else:
            findings.append("INFO: No explicit max-age in Cache-Control header")
    
    # Check for stale-while-revalidate which can improve performance
    if 'stale-while-revalidate' not in value and not is_sensitive_path:
        findings.append("IMPROVEMENT: Consider adding 'stale-while-revalidate' directive for better performance")
    
    return findings

def analyze_cookie_security(cookies, findings, is_secure_connection):
    """
    Analyze cookies for security best practices.
    
    Args:
        cookies: List of cookies from the response
        findings: List to append findings to
        is_secure_connection: Boolean indicating if the connection is HTTPS
        
    Returns:
        Updated findings list
    """
    if not cookies:
        findings.append("No cookies found in the response")
        return findings
    
    for cookie in cookies:
        cookie_name = cookie.name if hasattr(cookie, 'name') else "Unknown"
        
        # Check for Secure flag
        if not cookie.secure:
            if is_secure_connection:
                findings.append(f"HIGH RISK: Cookie '{cookie_name}' missing Secure flag, allowing transmission over HTTP")
            else:
                findings.append(f"NOTE: Cookie '{cookie_name}' missing Secure flag, but site is using HTTP")
        
        # Check for HttpOnly flag
        if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, 'httponly', False):
            findings.append(f"MEDIUM RISK: Cookie '{cookie_name}' missing HttpOnly flag, allowing JavaScript access")
        
        # Check for SameSite attribute
        same_site = None
        if hasattr(cookie, 'same_site'):
            same_site = cookie.same_site
        elif cookie.has_nonstandard_attr('SameSite'):
            for attr in cookie._rest.items():
                if attr[0].lower() == 'samesite':
                    same_site = attr[1]
        
        if not same_site:
            findings.append(f"MEDIUM RISK: Cookie '{cookie_name}' missing SameSite attribute, vulnerable to CSRF")
        elif same_site.lower() == 'none':
            if cookie.secure:
                findings.append(f"CAUTION: Cookie '{cookie_name}' uses SameSite=None with Secure flag")
            else:
                findings.append(f"HIGH RISK: Cookie '{cookie_name}' uses SameSite=None without Secure flag, which is invalid")
        elif same_site.lower() == 'lax':
            findings.append(f"CAUTION: Cookie '{cookie_name}' uses SameSite=Lax, which provides moderate CSRF protection")
        elif same_site.lower() == 'strict':
            findings.append(f"GOOD: Cookie '{cookie_name}' uses SameSite=Strict, providing strong CSRF protection")
        
        # Check for sensitive cookie names
        sensitive_names = ['session', 'auth', 'token', 'jwt', 'access', 'admin', 'key', 'secret']
        if any(sensitive in cookie_name.lower() for sensitive in sensitive_names):
            if not cookie.secure or not (cookie.has_nonstandard_attr('HttpOnly') or getattr(cookie, 'httponly', False)):
                findings.append(f"HIGH RISK: Potentially sensitive cookie '{cookie_name}' missing security attributes")
    
    return findings

def analyze_information_disclosure(headers, findings):
    """
    Analyze headers for information disclosure issues.
    
    Args:
        headers: Response headers dictionary
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    for header_name, info in INSECURE_HEADERS.items():
        if header_name in headers:
            header_value = headers[header_name]
            findings.append(f"{info['importance']} RISK: {header_name} header reveals information: '{header_value}'")
            findings.append(f"RECOMMENDATION: {info['recommendation']}")
    
    # Check for other common information disclosure headers
    custom_server_headers = [h for h in headers if h.lower().startswith('x-') and 'version' in h.lower()]
    for header in custom_server_headers:
        if header not in INSECURE_HEADERS:
            findings.append(f"CAUTION: Custom header '{header}' may reveal version information: '{headers[header]}'")
    
    return findings

def check_missing_security_headers(headers, findings):
    """
    Identify important security headers that are missing.
    
    Args:
        headers: Response headers dictionary
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    for header_name, info in SECURITY_HEADERS.items():
        # Skip checking Set-Cookie here as it's handled separately
        if header_name == 'Set-Cookie':
            continue
            
        # Skip deprecated headers
        if info['importance'] == 'DEPRECATED':
            continue
            
        if header_name not in headers:
            if info['importance'] == 'HIGH':
                findings.append(f"HIGH RISK: Missing {header_name} header")
                findings.append(f"RECOMMENDATION: Add the header with value: {info['best_practice']}")
            elif info['importance'] == 'MEDIUM':
                findings.append(f"MEDIUM RISK: Missing {header_name} header")
                findings.append(f"RECOMMENDATION: Consider adding with value: {info['best_practice']}")
            elif info['importance'] == 'LOW':
                findings.append(f"LOW RISK: Missing {header_name} header")
                findings.append(f"RECOMMENDATION: Optionally add with value: {info['best_practice']}")
    
    return findings

def generate_security_score(findings):
    """
    Generate a security score based on findings.
    
    Args:
        findings: List of findings
        
    Returns:
        Score from 0-100 and summary
    """
    base_score = 100
    critical_issues = 0
    high_issues = 0
    medium_issues = 0
    low_issues = 0
    
    for finding in findings:
        if "CRITICAL" in finding:
            base_score -= 15
            critical_issues += 1
        elif "HIGH RISK" in finding:
            base_score -= 10
            high_issues += 1
        elif "MEDIUM RISK" in finding:
            base_score -= 5
            medium_issues += 1
        elif "LOW RISK" in finding:
            base_score -= 1
            low_issues += 1
    
    # Ensure score stays within bounds
    score = max(0, min(base_score, 100))
    
    # Generate summary
    if score >= 90:
        rating = "Excellent"
    elif score >= 80:
        rating = "Good"
    elif score >= 70:
        rating = "Fair"
    elif score >= 60:
        rating = "Poor"
    else:
        rating = "Very Poor"
    
    summary = f"Security Headers Score: {score}/100 ({rating})"
    summary += f"\nIssues: {critical_issues} critical, {high_issues} high, {medium_issues} medium, {low_issues} low"
    
    return score, summary

def check(session, url, soup, response, config):
    """
    Analyze HTTP response headers for security best practices.
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
    
    Returns:
        List of findings related to security headers
    """
    findings = []
    
    # Extract URL components
    parsed_url = urlparse(url)
    is_secure_connection = parsed_url.scheme == 'https'
    path = parsed_url.path or '/'
    
    # Get all headers (convert to dictionary with lowercase keys for case-insensitive matching)
    headers = {k: v for k, v in response.headers.items()}
    
    # First check if we're using HTTPS
    if not is_secure_connection:
        findings.append("CRITICAL: Site is not using HTTPS, which is essential for security")
    
    # Check for missing important security headers
    findings = check_missing_security_headers(headers, findings)
    
    # If HSTS header is present, analyze it
    if 'Strict-Transport-Security' in headers:
        findings = analyze_hsts_header(headers['Strict-Transport-Security'], findings)
    
    # If CSP header is present, do a basic analysis (detailed analysis is in csp_analyzer.py)
    if 'Content-Security-Policy' in headers:
        findings = analyze_csp_header_basic(headers['Content-Security-Policy'], findings)
    
    # If X-Frame-Options is present, analyze it
    if 'X-Frame-Options' in headers:
        findings = analyze_xfo_header(headers['X-Frame-Options'], findings)
    
    # If X-XSS-Protection is present, analyze it
    if 'X-XSS-Protection' in headers:
        findings = analyze_xxp_header(headers['X-XSS-Protection'], findings)
    
    # If Referrer-Policy is present, analyze it
    if 'Referrer-Policy' in headers:
        findings = analyze_referrer_policy(headers['Referrer-Policy'], findings)
    
    # If Permissions-Policy is present, analyze it
    if 'Permissions-Policy' in headers:
        findings = analyze_permissions_policy(headers['Permissions-Policy'], findings)
    elif 'Feature-Policy' in headers:  # Check legacy header name
        findings.append("NOTE: Site uses the deprecated 'Feature-Policy' header instead of 'Permissions-Policy'")
        findings = analyze_permissions_policy(headers['Feature-Policy'], findings)
    
    # If Cache-Control is present, analyze it
    if 'Cache-Control' in headers:
        findings = analyze_cache_control(headers['Cache-Control'], findings, path)
    
    # Check for cookies and analyze their security
    if response.cookies:
        findings = analyze_cookie_security(response.cookies, findings, is_secure_connection)
    
    # Check for information disclosure in headers
    findings = analyze_information_disclosure(headers, findings)
    
    # Generate overall security score
    score, summary = generate_security_score(findings)
    findings.append("\n" + summary)
    
    # Add general recommendations
    if score < 80:
        findings.append("\nKey recommendations to improve security headers:")
        if 'Content-Security-Policy' not in headers:
            findings.append("1. Implement a Content Security Policy header")
        if 'Strict-Transport-Security' not in headers and is_secure_connection:
            findings.append("2. Add Strict-Transport-Security header with appropriate max-age")
        if 'X-Content-Type-Options' not in headers:
            findings.append("3. Add X-Content-Type-Options: nosniff header")
        if 'X-Frame-Options' not in headers:
            findings.append("4. Add X-Frame-Options header to prevent clickjacking")
        if score < 50:
            findings.append("5. Review and secure all cookies with appropriate flags")
    
    return findings 