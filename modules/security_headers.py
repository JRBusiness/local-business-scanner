import logging

# Define recommended security headers and their typical importance
# Severities: Critical, High, Medium, Low, Info
RECOMMENDED_HEADERS = {
    # Foundational Security
    'Strict-Transport-Security': {'severity': 'High', 'description': 'Ensures browsers only connect via HTTPS.'},
    'Content-Security-Policy': {'severity': 'High', 'description': 'Mitigates XSS and data injection attacks.'},
    'X-Frame-Options': {'severity': 'Medium', 'description': 'Protects against clickjacking attacks.'},
    'X-Content-Type-Options': {'severity': 'Medium', 'description': 'Prevents MIME-sniffing attacks.'},
    # Enhancements & Best Practices
    'Referrer-Policy': {'severity': 'Medium', 'description': 'Controls how much referrer information is sent.'},
    'Permissions-Policy': {'severity': 'Low', 'description': 'Controls browser features available to the page.'},
    # Optional / Context-dependent
    # 'X-Permitted-Cross-Domain-Policies': {'severity': 'Low', 'description': 'Controls cross-domain data loading policies (Flash/Acrobat).'}, # Often less relevant now
    # 'Expect-CT': {'severity': 'Low', 'description': 'Enforces Certificate Transparency checks.'}, # Importance varies
    # Deprecated/Less Effective
    # 'X-XSS-Protection': {'severity': 'Info', 'description': 'Legacy XSS filter (often disabled by modern browsers).'}, # CSP is preferred
    # Cache Control - important but complex to generalize severity without context
    'Cache-Control': {'severity': 'Info', 'description': 'General caching directive presence.'},
    'Pragma': {'severity': 'Info', 'description': 'HTTP/1.0 cache control (often overridden by Cache-Control).'},
    'Clear-Site-Data': {'severity': 'Low', 'description': 'Allows clearing browsing data for the origin.'}
}

# Note: The 'headers' object passed in is expected to be a case-insensitive dictionary-like object
# (like the one from the requests library)

def check(response, headers):
    """
    Checks for the presence and basic configuration of important security headers.

    Args:
        response (requests.Response): The response object from the initial request.
        headers (dict): A case-insensitive dictionary of response headers.
        **kwargs: Catches unused context arguments.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    if not headers:
        logging.warning("SecurityHeaders: No headers provided for analysis.")
        # Optionally return an informational finding if appropriate
        # findings.append({'name': 'Header Scan Error', 'severity': 'Info', 'description': 'Could not retrieve headers for analysis.'})
        return findings # Cannot proceed without headers

    # Check for missing recommended headers (case-insensitive check)
    header_keys_lower = {k.lower() for k in headers.keys()}
    for header_name, details in RECOMMENDED_HEADERS.items():
        if header_name.lower() not in header_keys_lower:
            findings.append({
                'name': 'Missing Security Header',
                'severity': details['severity'],
                'description': f"The '{header_name}' header is missing. ({details['description']})"
            })

    # Basic check for weak CSP configurations (if header exists)
    csp_header = headers.get('Content-Security-Policy') # Case-insensitive get
    if csp_header:
        # Simple checks for common weaknesses - more advanced parsing could be added
        weaknesses = []
        if "'unsafe-inline'" in csp_header:
            weaknesses.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp_header:
            weaknesses.append("'unsafe-eval'")
        # Check for overly broad wildcards (example: default-src *)
        if "default-src *" in csp_header.replace(";", "") or "script-src *" in csp_header.replace(";", ""):
             # Be careful, this is a very basic check and might have false positives
             # A proper parser would be better. Check if it's the *only* source or combined with others.
             if "default-src *;" in csp_header or csp_header.strip() == "default-src *":
                 weaknesses.append("broad wildcard ('*') in default-src")
             if "script-src *;" in csp_header or csp_header.strip() == "script-src *":
                 weaknesses.append("broad wildcard ('*') in script-src")

        if weaknesses:
            findings.append({
                'name': 'Weak CSP Configuration',
                'severity': 'Medium', # Could be High depending on context
                'description': f"Potential CSP weaknesses detected: {', '.join(weaknesses)}. Policy: \"{csp_header[:100]}...\"" # Truncate long policies
            })

    # Check for HSTS header details (if present)
    hsts_header = headers.get('Strict-Transport-Security')
    if hsts_header:
        if 'max-age' not in hsts_header or int(re.search(r'max-age=(\d+)', hsts_header, re.IGNORECASE).group(1) if re.search(r'max-age=(\d+)', hsts_header, re.IGNORECASE) else 0) < 31536000: # Less than 1 year
             findings.append({
                'name': 'Weak HSTS Policy',
                'severity': 'Medium',
                'description': f"HSTS 'max-age' is missing or less than one year. Value: \"{hsts_header}\""
             })
        # You could also check for 'includeSubDomains' and 'preload' directives

    return findings

# Example of how the main scanner would call this (conceptual):
# if 'headers' in context and context['headers'] is not None:
#     header_findings = check(response=context.get('response'), headers=context.get('headers'))
#     if header_findings:
#         all_findings['security_headers'] = header_findings
# else:
#     skipped_modules.append("security_headers (Missing headers context)")

# Removed the old code that made its own request
# import requests # No longer needed here
#
# REQUIRED_HEADERS = [ # Old list
#     'Content-Security-Policy',
#     'Strict-Transport-Security',
#     'X-Frame-Options',
#     'X-Content-Type-Options',
#     'Referrer-Policy',
#     'Permissions-Policy',
#     'X-Permitted-Cross-Domain-Policies',
#     'Expect-CT',
#     'Cache-Control',
#     'Pragma'
# ]
#
# def check(url): # Old signature
#     findings = []
#     try:
#         r = requests.get(url, timeout=5)
#         for header in REQUIRED_HEADERS:
#             if header not in r.headers:
#                 findings.append(f"Missing Header: {header}")
#         # Bonus check for misconfigured CSP
#         if 'Content-Security-Policy' in r.headers:
#             csp = r.headers['Content-Security-Policy']
#             if "*" in csp or "unsafe-inline" in csp:
#                 findings.append(f"Weak CSP Policy: {csp}")
#     except Exception:
#         findings.append("Header scan failed")
#     return findings
