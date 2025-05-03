import logging

# Define Referrer Policies and their potential risk level
# See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
POLICY_RISKS = {
    # Policies considered potentially unsafe (can leak sensitive info)
    'unsafe-url': {'severity': 'Medium', 'description': 'Full URL sent on all requests (cross-origin included). Highest risk.'},
    'no-referrer-when-downgrade': {'severity': 'Low', 'description': 'Full URL sent on same-origin and HTTPS->HTTPS, no referrer on HTTP downgrade. (Default behavior in many browsers if no policy set).'},
    'origin-when-cross-origin': {'severity': 'Low', 'description': 'Sends origin on cross-origin, full URL on same-origin.'},
    # Policies generally considered safer
    'strict-origin-when-cross-origin': {'severity': 'Info', 'description': 'Sends origin on cross-origin (HTTPS->HTTPS only), full URL on same-origin. Good balance.'},
    'origin': {'severity': 'Info', 'description': 'Only sends the origin, regardless of destination.'},
    'same-origin': {'severity': 'Info', 'description': 'Sends full URL on same-origin only.'},
    'strict-origin': {'severity': 'Info', 'description': 'Sends origin on same-origin and HTTPS->HTTPS cross-origin (if same protocol level or higher).'},
    'no-referrer': {'severity': 'Info', 'description': 'No referrer information sent.'}
}

def check(response, headers):
    """
    Analyzes the Referrer-Policy header for potentially weak configurations.
    Complements the basic presence check in security_headers.py.

    Args:
        response (requests.Response): The response object (unused).
        headers (dict): A case-insensitive dictionary of response headers.
        **kwargs: Catches unused context arguments.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    if not headers:
        logging.warning("RefererLeakage: No headers provided.")
        return findings

    # Use case-insensitive get for the header
    policy_header = headers.get('Referrer-Policy')

    if not policy_header:
        # The main security_headers module should flag the missing header.
        # We might add an Info finding here indicating default browser behavior applies.
        findings.append({
            'name': 'Referrer Policy Not Explicitly Set',
            'severity': 'Info', # Or potentially Low depending on philosophy
            'description': "No Referrer-Policy header found. Browsers will use their default (often 'strict-origin-when-cross-origin' or 'no-referrer-when-downgrade'), which might not be the desired behavior."
        })
        return findings

    # Policies can have multiple comma-separated values, browser picks the first recognized one.
    # We check the first policy declared as it's the most likely effective one.
    # A more robust check might parse all and check if *any* are weak.
    first_policy = policy_header.split(',')[0].strip().lower()

    if first_policy in POLICY_RISKS:
        risk_info = POLICY_RISKS[first_policy]
        # Only report if the severity is Low or Medium (i.e., considered potentially weak)
        if risk_info['severity'] in ['Low', 'Medium']:
            findings.append({
                'name': 'Potentially Weak Referrer Policy',
                'severity': risk_info['severity'],
                'description': f"The Referrer-Policy is set to '{first_policy}'. {risk_info['description']}"
            })
        else:
            # Policy is considered safe, maybe log as debug
            logging.debug(f"RefererLeakage: Policy '{first_policy}' found, considered safe.")
    else:
        # Found a policy value we don't recognize
        findings.append({
            'name': 'Unrecognized Referrer Policy',
            'severity': 'Info',
            'description': f"The Referrer-Policy header contains an unrecognized value: '{first_policy}'. Policy: '{policy_header}'"
        })

    return findings
