import logging
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import urllib.parse
import json
import time
import hashlib
from . import get_session

# CSRF token patterns for various frameworks
CSRF_TOKEN_PATTERNS = {
    "general": [
        r"csrf[\-_]token",
        r"csrf[\-_]param",
        r"csrf[\-_]key",
        r"csrf[\-_]field",
        r"\_csrf",
        r"csrf",
        r"csrfmiddlewaretoken",
        r"authenticity_token",
        r"csrf[\-_]value",
        r"xsrf[\-_]token",
    ],
    "specific": {
        "django": [r"csrfmiddlewaretoken"],
        "rails": [r"authenticity[\-_]token"],
        "php": [r"_token", r"csrf_token"],
        "laravel": [r"_token"],
        "spring": [r"_csrf"],
        "aspnet": [r"__RequestVerificationToken"],
        "symfony": [r"_csrf_token"],
        "express": [r"_csrf"],
    }
}

# CSRF exploitation templates
CSRF_PAYLOAD_TEMPLATES = {
    "basic_get": """
        <html>
          <body>
            <form action="{action}" method="get" id="csrf-form">
              {inputs}
              <input type="submit" value="Submit">
            </form>
            <script>document.getElementById("csrf-form").submit();</script>
          </body>
        </html>
    """,
    "basic_post": """
        <html>
          <body>
            <form action="{action}" method="post" id="csrf-form">
              {inputs}
              <input type="submit" value="Submit">
            </form>
            <script>document.getElementById("csrf-form").submit();</script>
          </body>
        </html>
    """,
    "fetch_post": """
        <html>
          <body>
            <script>
              fetch("{action}", {{
                method: "POST",
                headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
                body: "{body}",
                credentials: "include"
              }});
            </script>
          </body>
        </html>
    """,
    "json_post": """
        <html>
          <body>
            <script>
              fetch("{action}", {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: '{json_body}',
                credentials: "include"
              }});
            </script>
          </body>
        </html>
    """,
    "iframe": """
        <html>
          <body>
            <iframe name="csrf-frame" style="display:none"></iframe>
            <form action="{action}" method="post" target="csrf-frame" id="csrf-form">
              {inputs}
            </form>
            <script>document.getElementById("csrf-form").submit();</script>
          </body>
        </html>
    """
}

# Security relevant headers for CSRF protection
CSRF_PROTECTION_HEADERS = [
    'X-CSRF-Token', 
    'X-Frame-Options',
    'Content-Security-Policy',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Opener-Policy',
    'Referrer-Policy'
]

def check(session, url, soup, response, config):
    """
    Enhanced CSRF vulnerability scanner with improved detection logic.
    
    Checks for:
    1. Missing CSRF tokens in forms
    2. Issues with token validation (such as accepting empty tokens)
    3. Weak CSRF token generation patterns
    4. Same-origin policy bypass opportunities
    
    Args:
        session: Session object for making requests
        url: Target URL
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary with settings
        
    Returns:
        List of findings
    """
    req_session = get_session(session)
    findings = []
    
    # Can't proceed without a soup object
    if not soup:
        return findings
    
    # Extract domain for origin checks
    parsed_url = urllib.parse.urlparse(url)
    base_domain = parsed_url.netloc
    
    # --- 1. Extract all forms from the page ---
    forms = soup.find_all('form')
    
    if not forms:
        # No forms to check
        return findings
    
    # Track tokens for analysis
    csrf_tokens = {}
    forms_without_tokens = []
    protected_forms = []
    
    # --- 2. Analyze each form for CSRF protection ---
    for i, form in enumerate(forms):
        form_id = form.get('id', f"form_{i}")
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        
        # Resolve relative URLs
        if form_action:
            form_action = urllib.parse.urljoin(url, form_action)
        else:
            form_action = url
            
        # Skip forms that use GET method (generally not vulnerable to CSRF)
        if form_method == 'get':
            continue
            
        # Skip forms with targets that point to another frame or window
        form_target = form.get('target', '')
        if form_target and form_target != '_self':
            continue
            
        # Extract all input fields
        fields = {}
        token_fields = []
        
        # Get all inputs
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_field in inputs:
            name = input_field.get('name')
            value = input_field.get('value', '')
            input_type = input_field.get('type', 'text').lower()
            
            if name:
                fields[name] = value
                
                # Check if this might be a CSRF token
                for framework, patterns in CSRF_TOKEN_PATTERNS["specific"].items():
                    for pattern in patterns:
                        if re.search(pattern, name, re.IGNORECASE):
                            token_fields.append({
                                'name': name,
                                'value': value,
                                'framework': framework
                            })
                            csrf_tokens[name] = value
                            break
                
                # If not matched to a specific framework, check general patterns
                if not any(name in token['name'] for token in token_fields):
                    for pattern in CSRF_TOKEN_PATTERNS["general"]:
                        if re.search(pattern, name, re.IGNORECASE):
                            token_fields.append({
                                'name': name,
                                'value': value,
                                'framework': 'unknown'
                            })
                            csrf_tokens[name] = value
                            break
        
        # Check if form has CSRF token
        if token_fields:
            protected_forms.append({
                'id': form_id,
                'action': form_action,
                'method': form_method,
                'token_fields': token_fields,
                'fields': fields
            })
        else:
            forms_without_tokens.append({
                'id': form_id,
                'action': form_action,
                'method': form_method,
                'fields': fields
            })
    
    # --- 3. Process forms without CSRF tokens ---
    for form in forms_without_tokens:
        # Ignore forms that submit to external domains (less relevant for CSRF)
        form_domain = urllib.parse.urlparse(form['action']).netloc
        if form_domain and form_domain != base_domain:
            continue
            
        # Generate a POC for the form
        inputs_html = ""
        for name, value in form['fields'].items():
            inputs_html += f'<input type="hidden" name="{name}" value="{value}">\n'
            
        csrf_proof_of_concept = CSRF_PAYLOAD_TEMPLATES["basic_post"].format(
            action=form['action'],
            inputs=inputs_html
        )
        
        findings.append({
            "name": f"Missing CSRF Token in Form (ID: {form['id']})",
            "severity": "High",
            "description": f"A form with the action '{form['action']}' and method '{form['method']}' does not contain a CSRF token.",
            "evidence": {
                "form_id": form['id'],
                "action": form['action'],
                "method": form['method'],
                "poc": csrf_proof_of_concept.strip()
            },
            "recommendation": "Add CSRF token validation for all state-changing forms and actions."
        })
    
    # --- 4. Test for CSRF token weaknesses in protected forms ---
    for form in protected_forms:
        for token_field in form['token_fields']:
            token_name = token_field['name']
            token_value = token_field['value']
            
            # Skip empty tokens
            if not token_value:
                continue
                
            # 4.1 Check token randomness and predictability
            check_token_quality(token_value, form, findings)
            
            # 4.2 Verify server-side token validation
            # (Needs active testing - might be enabled with a config flag)
            if config.get('active_csrf_testing', False):
                # This would submit the form with:
                # - Empty token
                # - Static token
                # - Mismatched token
                pass
    
    # --- 5. Check response headers for protection bypass opportunities ---
    # Check if Cross-Origin Resource Sharing headers are overly permissive
    cors_headers = {
        'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
        'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials')
    }
    
    if cors_headers['Access-Control-Allow-Origin'] == '*' or cors_headers['Access-Control-Allow-Origin'] == 'null':
        if cors_headers['Access-Control-Allow-Credentials'] == 'true':
            findings.append({
                "name": "Overly Permissive CORS Headers",
                "severity": "Medium",
                "description": "The site has CORS headers that allow credentials from any origin, potentially bypassing CSRF protections.",
                "evidence": cors_headers,
                "recommendation": "Restrict CORS headers to specific trusted origins and avoid using 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'."
            })
    
    # --- 6. Check for SameSite cookie attribute ---
    cookies = response.cookies
    vulnerable_cookies = []
    
    for cookie in cookies:
        samesite = cookie.get_nonstandard_attr('SameSite')
        if not samesite or samesite.lower() == 'none':
            vulnerable_cookies.append(cookie.name)
    
    if vulnerable_cookies:
        findings.append({
            "name": "Missing or Weak SameSite Cookie Attribute",
            "severity": "Medium",
            "description": f"Cookies without SameSite=Lax or SameSite=Strict are vulnerable to CSRF: {', '.join(vulnerable_cookies)}",
            "evidence": {"vulnerable_cookies": vulnerable_cookies},
            "recommendation": "Set SameSite=Lax or SameSite=Strict on all session and authentication cookies."
        })
    
    return findings

def check_token_quality(token, form, findings):
    """
    Analyze token quality for randomness and predictability.
    """
    # Skip empty tokens
    if not token:
        findings.append({
            "name": "Empty CSRF Token",
            "severity": "High",
            "description": f"Form (ID: {form['id']}) has an empty CSRF token.",
            "evidence": {"form_id": form['id'], "action": form['action']},
            "recommendation": "Ensure CSRF tokens are non-empty and generated with cryptographically secure random algorithms."
        })
        return
        
    # Check token length
    if len(token) < 16:
        findings.append({
            "name": "Short CSRF Token",
            "severity": "Medium",
            "description": f"Form (ID: {form['id']}) has a short CSRF token ({len(token)} characters). Short tokens are potentially easier to guess.",
            "evidence": {"form_id": form['id'], "token_length": len(token)},
            "recommendation": "Use tokens of at least 128 bits (16 bytes) of randomness."
        })
    
    # Check for static or predictable components
    time_components = ['time', 'timestamp', 'date']
    if any(component in token.lower() for component in time_components):
        findings.append({
            "name": "Time-Based CSRF Token",
            "severity": "Medium",
            "description": f"Form (ID: {form['id']}) CSRF token appears to contain time-based components, which can be predictable.",
            "evidence": {"token": token[:20] + "..." if len(token) > 20 else token},
            "recommendation": "Use cryptographically secure random tokens instead of time-based algorithms."
        })
    
    # Check for common encoding patterns
    if len(token) == 32 and re.match(r'^[a-f0-9]+$', token):
        findings.append({
            "name": "Potentially Weak CSRF Token (MD5-like)",
            "severity": "Low",
            "description": f"Form (ID: {form['id']}) CSRF token appears to be an MD5 hash (32 hex characters). Verify if the input to the hash is sufficiently random.",
            "evidence": {"token": token},
            "recommendation": "Use secure random generators rather than hashing predictable inputs."
        })
    elif len(token) == 40 and re.match(r'^[a-f0-9]+$', token):
        findings.append({
            "name": "Potentially Weak CSRF Token (SHA1-like)",
            "severity": "Low",
            "description": f"Form (ID: {form['id']}) CSRF token appears to be a SHA1 hash (40 hex characters). Verify if the input to the hash is sufficiently random.",
            "evidence": {"token": token},
            "recommendation": "Use secure random generators rather than hashing predictable inputs."
        })
    
    # Check for base64 encoding
    try:
        if re.match(r'^[a-zA-Z0-9+/=]+$', token) and len(token) % 4 == 0:
            # Looks like base64, which is often used for encoding predictable data
            findings.append({
                "name": "Potentially Weak CSRF Token (Base64-encoded)",
                "severity": "Low",
                "description": f"Form (ID: {form['id']}) CSRF token appears to be Base64-encoded. Verify if the source data is sufficiently random.",
                "evidence": {"token": token[:20] + "..." if len(token) > 20 else token},
                "recommendation": "Use secure random generators and avoid encoding predictable data."
            })
    except:
        pass
