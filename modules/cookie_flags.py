import logging
# Use the standard library http.cookies for parsing
from http.cookies import SimpleCookie

def check(response, headers):
    """
    Checks Set-Cookie headers for missing Secure and HttpOnly flags.

    Args:
        response (requests.Response): The response object (unused here).
        headers (dict): A case-insensitive dictionary of response headers.
        **kwargs: Catches unused context arguments.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    if not headers:
        logging.warning("CookieFlags: No headers provided.")
        return findings

    # Get Set-Cookie headers (requests headers are case-insensitive)
    set_cookie_headers = headers.get('Set-Cookie', None)

    # Ensure it's a list, even if None or single string
    if isinstance(set_cookie_headers, str):
        set_cookie_headers = [set_cookie_headers]
    elif set_cookie_headers is None:
        set_cookie_headers = []

    # Parse all cookies using SimpleCookie
    raw_cookies = SimpleCookie()
    if set_cookie_headers:
        for header_val in set_cookie_headers:
            try:
                raw_cookies.load(header_val)
            except Exception as e:
                # Use a simpler log message format
                log_msg = "CookieFlags: Failed to parse Set-Cookie header value starting with '{}': {}".format(header_val[:50], e)
                logging.warning(log_msg)

    # If no cookies were successfully parsed, exit
    if not raw_cookies:
        return findings

    # Check flags for each cookie
    for name, morsel in raw_cookies.items():
        is_secure = morsel.get('secure', False)
        is_httponly = morsel.get('httponly', False)
        missing_flags = []

        if not is_secure:
            missing_flags.append('Secure')
        if not is_httponly:
            missing_flags.append('HttpOnly')

        if missing_flags:
            # Determine severity
            severity = 'Low' # Default
            if 'Secure' in missing_flags:
                severity = 'Medium'

            # Raise severity for sensitive-looking cookie names
            sensitive_names = ['session', 'auth', 'token', 'user', 'id', 'cred']
            is_sensitive = any(sn in name.lower() for sn in sensitive_names)

            # If sensitive and *any* flag is missing, it's high risk
            if is_sensitive:
                 severity = 'High'
            # If not sensitive, but both flags missing, could argue Medium? Let's keep Medium if Secure is missing.

            # Format description string separately for clarity
            value_snippet = morsel.value[:30] # Get first 30 chars of value
            missing_flags_str = ', '.join(missing_flags)
            desc = f"Cookie '{name}' is missing flag(s): {missing_flags_str}. Value starts with: '{value_snippet}'"

            findings.append({
                'name': 'Missing Cookie Flags',
                'severity': severity,
                'description': desc
            })

    return findings

# Removed old code
# import requests
#
# def check(url):
#     findings = []
#     try:
#         r = requests.get(url, timeout=5)
#         cookies = r.cookies
#         for cookie in cookies:
#             if not cookie.secure or \"httponly\" not in str(cookie._rest).lower():
#                 findings.append(f\"Insecure cookie: {cookie.name} - Secure={cookie.secure}, HttpOnly={'httponly' in str(cookie._rest).lower()}\")
#     except Exception:
#         findings.append(\"Failed to analyze cookies\")
#     return findings
