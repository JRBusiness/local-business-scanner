import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

# CSRF protection methods
CSRF_PROTECTION_METHODS = {
    'token': {
        'description': 'CSRF token validation',
        'patterns': [
            r'csrf[_-]token',
            r'_token',
            r'authenticity_token',
            r'xsrf[_-]token',
            r'__RequestVerificationToken'
        ]
    },
    'samesite': {
        'description': 'SameSite cookie attribute',
        'patterns': [
            r'samesite=strict',
            r'samesite=lax',
            r'samesite=none'
        ]
    },
    'double_submit_cookie': {
        'description': 'Double submit cookie pattern',
        'patterns': [
            r'X-CSRF-TOKEN',
            r'X-XSRF-TOKEN'
        ]
    },
    'custom_header': {
        'description': 'Custom request header validation',
        'patterns': [
            r'X-Requested-With',
            r'X-CSRF-Protection'
        ]
    },
    'referer_check': {
        'description': 'Referer header validation',
        'patterns': [
            r'referer',
            r'origin'
        ]
    }
}

# Forms that typically perform state-changing operations
SENSITIVE_FORM_ACTIONS = [
    'login',
    'register',
    'signup',
    'password',
    'reset',
    'profile',
    'account',
    'update',
    'delete',
    'create',
    'edit',
    'post',
    'upload',
    'checkout',
    'payment',
    'transfer',
    'admin'
]

def extract_forms(soup):
    """
    Extract forms from the HTML content.
    
    Args:
        soup: BeautifulSoup object of the response
        
    Returns:
        List of tuples (form, is_sensitive)
    """
    forms = soup.find_all('form')
    result = []
    
    for form in forms:
        # Determine if form is sensitive based on action, id, class or name
        is_sensitive = False
        action = form.get('action', '').lower()
        form_id = form.get('id', '').lower()
        form_class = form.get('class', [])
        if isinstance(form_class, list):
            form_class = ' '.join(form_class).lower()
        form_name = form.get('name', '').lower()
        
        # Check form attributes against sensitive patterns
        for pattern in SENSITIVE_FORM_ACTIONS:
            if (pattern in action or pattern in form_id or 
                pattern in form_class or pattern in form_name):
                is_sensitive = True
                break
        
        # Forms with password fields are considered sensitive
        if form.find('input', {'type': 'password'}):
            is_sensitive = True
        
        # Forms with method="post" are considered sensitive
        if form.get('method', '').lower() == 'post':
            is_sensitive = True
            
        result.append((form, is_sensitive))
    
    return result

def check_csrf_token_in_form(form):
    """
    Check if the form has a CSRF token.
    
    Args:
        form: BeautifulSoup form element
        
    Returns:
        Tuple (has_token, token_field_name)
    """
    # Look for hidden inputs that might be CSRF tokens
    for method in CSRF_PROTECTION_METHODS['token']['patterns']:
        pattern = re.compile(method, re.IGNORECASE)
        
        # Check for hidden input fields
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        for input_field in hidden_inputs:
            name = input_field.get('name', '')
            if pattern.search(name):
                return True, name
    
    # Check for meta tags that might indicate CSRF protection
    meta_tags = form.find_all('meta')
    for meta in meta_tags:
        name = meta.get('name', '')
        if any(re.compile(pattern, re.IGNORECASE).search(name) for pattern in CSRF_PROTECTION_METHODS['token']['patterns']):
            return True, name
            
    return False, None

def check_all_csrf_tokens(soup):
    """
    Check for CSRF tokens in the document that might be added via JavaScript.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        bool: Whether CSRF tokens were found in the document
    """
    # Check meta tags
    meta_csrf = soup.find('meta', attrs={'name': lambda x: x and any(
        re.compile(pattern, re.IGNORECASE).search(x) 
        for pattern in CSRF_PROTECTION_METHODS['token']['patterns']
    )})
    
    if meta_csrf:
        return True
    
    # Check for scripts that might be setting CSRF tokens
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string and any(re.compile(pattern, re.IGNORECASE).search(script.string) 
                               for pattern in CSRF_PROTECTION_METHODS['token']['patterns']):
            return True
    
    return False

def check_cookie_attributes(response):
    """
    Check cookies for SameSite and other security attributes.
    
    Args:
        response: HTTP response object
        
    Returns:
        dict: Results of cookie analysis
    """
    results = {
        'has_samesite': False,
        'samesite_strict_count': 0,
        'samesite_lax_count': 0,
        'samesite_none_count': 0,
        'missing_samesite_count': 0,
        'session_cookies': []
    }
    
    # Extract cookies from response
    cookies = response.cookies
    
    for cookie in cookies:
        cookie_name = cookie.name
        same_site = cookie.get_nonstandard_attr('SameSite', None)
        secure = cookie.secure
        
        # Track SameSite attribute usage
        if same_site:
            results['has_samesite'] = True
            same_site = same_site.lower()
            
            if same_site == 'strict':
                results['samesite_strict_count'] += 1
            elif same_site == 'lax':
                results['samesite_lax_count'] += 1
            elif same_site == 'none':
                results['samesite_none_count'] += 1
        else:
            results['missing_samesite_count'] += 1
        
        # Track session cookies for additional analysis
        if cookie_name.lower() in ['sessionid', 'session', 'jsessionid', 'phpsessid', 
                                 'aspsessionid', 'asp.net_sessionid']:
            results['session_cookies'].append({
                'name': cookie_name,
                'samesite': same_site,
                'secure': secure,
            })
    
    return results

def test_post_request_with_no_csrf(session, url, findings):
    """
    Test if a simple POST request without CSRF token is accepted.
    
    Args:
        session: Request session
        url: URL to test
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    try:
        # Create a minimal POST request
        data = {'test_field': 'test_value'}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://different-origin.com/'
        }
        
        # Send POST request
        response = session.post(url, data=data, headers=headers, timeout=10, allow_redirects=False)
        
        # Check if the request was accepted (200 OK or 302 Found)
        if response.status_code in [200, 302]:
            findings.append({
                'type': 'accepted_post_without_csrf',
                'message': f"POST request without CSRF token was accepted (status code {response.status_code})",
                'severity': 'HIGH',
                'recommendation': "Implement CSRF protection for all state-changing operations"
            })
        
    except Exception as e:
        findings.append({
            'type': 'test_error',
            'message': f"Error testing POST request: {str(e)}",
            'severity': 'INFO',
            'recommendation': "Manually verify CSRF protection for POST requests"
        })
    
    return findings

def test_csrf_token_replay(session, url, forms, findings):
    """
    Test if CSRF tokens can be replayed.
    
    Args:
        session: Request session
        url: URL to test
        forms: List of forms from the page
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Look for forms with CSRF tokens
    for form, is_sensitive in forms:
        has_token, token_name = check_csrf_token_in_form(form)
        
        if has_token and is_sensitive:
            try:
                # Extract form data
                form_data = {}
                for input_field in form.find_all('input'):
                    name = input_field.get('name')
                    value = input_field.get('value', '')
                    if name:
                        form_data[name] = value
                
                # Get form action
                action = form.get('action')
                if not action:
                    action = url
                elif not action.startswith('http'):
                    # Handle relative URLs
                    base_url = urlparse(url)
                    if action.startswith('/'):
                        action = f"{base_url.scheme}://{base_url.netloc}{action}"
                    else:
                        action = f"{url.rstrip('/')}/{action.lstrip('/')}"
                
                # Get form method
                method = form.get('method', 'get').lower()
                
                # Keep the original token value
                if token_name in form_data:
                    token_value = form_data[token_name]
                    
                    # Try to send the form twice with the same token
                    if method == 'post':
                        # First request
                        first_response = session.post(action, data=form_data, timeout=10, allow_redirects=False)
                        
                        # Second request with same token
                        second_response = session.post(action, data=form_data, timeout=10, allow_redirects=False)
                        
                        # If both requests succeed, token might be reusable
                        if first_response.status_code in [200, 302] and second_response.status_code in [200, 302]:
                            findings.append({
                                'type': 'potential_token_reuse',
                                'message': f"CSRF token in form '{form.get('id', 'unnamed')}' might be reusable",
                                'severity': 'MEDIUM',
                                'recommendation': "Ensure CSRF tokens are single-use and tied to the user's session"
                            })
            
            except Exception as e:
                findings.append({
                    'type': 'test_error',
                    'message': f"Error testing CSRF token replay: {str(e)}",
                    'severity': 'INFO',
                    'recommendation': "Manually verify CSRF token implementation"
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
    Check for CSRF vulnerabilities.
    
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
    
    # Extract forms from the page
    forms = extract_forms(soup)
    
    # Analyze cookie security attributes
    cookie_results = check_cookie_attributes(response)
    
    # Check for SameSite cookie attribute
    if not cookie_results['has_samesite'] and cookie_results['session_cookies']:
        findings.append({
            'type': 'missing_samesite',
            'message': "Session cookies missing SameSite attribute, which helps prevent CSRF attacks",
            'severity': 'MEDIUM',
            'recommendation': "Set SameSite=Lax or SameSite=Strict for all cookies, especially session cookies"
        })
    
    # Check for global CSRF protection mechanisms
    has_global_protection = check_all_csrf_tokens(soup)
    
    # Check each form for CSRF tokens
    sensitive_forms_without_csrf = 0
    total_sensitive_forms = 0
    
    for form, is_sensitive in forms:
        if is_sensitive:
            total_sensitive_forms += 1
            has_token, _ = check_csrf_token_in_form(form)
            
            if not has_token and not has_global_protection:
                sensitive_forms_without_csrf += 1
                form_info = f"Form with action='{form.get('action', 'n/a')}'"
                if form.get('id'):
                    form_info += f" id='{form.get('id')}'"
                
                findings.append({
                    'type': 'form_without_csrf',
                    'message': f"{form_info} lacks CSRF protection",
                    'severity': 'HIGH',
                    'recommendation': "Add CSRF tokens to all state-changing forms"
                })
    
    # Summary of form analysis
    if total_sensitive_forms > 0:
        if sensitive_forms_without_csrf == 0 and has_global_protection:
            findings.append({
                'type': 'good_csrf_protection',
                'message': f"All {total_sensitive_forms} sensitive forms have CSRF protection",
                'severity': 'INFO',
                'recommendation': ""
            })
        elif sensitive_forms_without_csrf == 0:
            findings.append({
                'type': 'good_csrf_protection',
                'message': f"All {total_sensitive_forms} sensitive forms appear to have CSRF protection",
                'severity': 'INFO',
                'recommendation': ""
            })
        else:
            findings.append({
                'type': 'missing_csrf_summary',
                'message': f"{sensitive_forms_without_csrf} out of {total_sensitive_forms} sensitive forms lack CSRF protection",
                'severity': 'HIGH',
                'recommendation': "Add CSRF protection to all forms that perform state-changing operations"
            })
    
    # Test if POST requests without CSRF tokens are accepted
    if total_sensitive_forms > 0 and not has_global_protection:
        findings = test_post_request_with_no_csrf(session, url, findings)
    
    # Test CSRF token replay if there are forms with tokens
    findings = test_csrf_token_replay(session, url, forms, findings)
    
    # Check for other CSRF mitigation headers
    if 'X-Frame-Options' not in response.headers:
        findings.append({
            'type': 'missing_xfo',
            'message': "Missing X-Frame-Options header increases clickjacking risk, which can lead to CSRF attacks",
            'severity': 'MEDIUM',
            'recommendation': "Add X-Frame-Options header with DENY or SAMEORIGIN value"
        })
    
    # If no findings were reported but no forms were found, add an info message
    if not findings and total_sensitive_forms == 0:
        findings.append({
            'type': 'info',
            'message': "No sensitive forms detected to test for CSRF vulnerabilities",
            'severity': 'INFO',
            'recommendation': "Manually verify CSRF protection for any state-changing operations"
        })
    
    # Format the findings for better readability
    formatted_findings = format_findings(findings)
    
    return formatted_findings 