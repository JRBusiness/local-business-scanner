import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Keywords often found in admin login pages/panels
ADMIN_KEYWORDS = [
    'admin login', 'administrator login', 'control panel', 'cpanel login',
    'dashboard login', 'management console', 'staff login', 'backend access',
    'system administration', 'webadmin', 'phpmyadmin',
    # Be careful with generic terms like 'login' or 'password' without context
]

# Common path segments that might indicate an admin area
ADMIN_PATH_SEGMENTS = [
    '/admin', '/administrator', '/controlpanel', '/cpanel', '/dashboard',
    '/manage', '/superuser', '/login', '/backend', '/system',
    '/webadmin', '/phpmyadmin'
]

def check(response, soup, url):
    """
    Checks if the *currently scanned* page appears to be an exposed admin interface
    based on URL path, title, and content keywords.

    Args:
        response (requests.Response): The response object from the initial request.
        soup (BeautifulSoup): Parsed HTML object (if available).
        url (str): The specific URL that was scanned.
        **kwargs: Catches unused context arguments.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    if not response:
        logging.warning("AdminExposure: No response object provided.")
        return findings

    try:
        parsed_url = urlparse(url)
        path_lower = parsed_url.path.lower()
        text_content_lower = response.text.lower()
        title_text_lower = ''
        if soup and soup.title and soup.title.string:
            title_text_lower = soup.title.string.lower()

        path_match = False
        title_match = False
        body_match = False

        # Check 1: Does the URL path itself suggest an admin area?
        # Check if the path *ends* with a common admin segment or exactly matches one
        for segment in ADMIN_PATH_SEGMENTS:
            if path_lower == segment or path_lower.endswith(segment + '/') or path_lower.endswith(segment + '.php') or path_lower.endswith(segment + '.aspx'): # Added extensions
                 path_match = True
                 logging.debug(f"AdminExposure: Path match found: {segment} in {path_lower}")
                 break

        # Check 2: Does the page title suggest an admin area?
        if title_text_lower:
            for keyword in ADMIN_KEYWORDS:
                # Avoid simple 'login' match unless combined with other admin terms
                if keyword == 'login' and ('admin' in title_text_lower or 'control' in title_text_lower or 'manage' in title_text_lower):
                     title_match = True
                     logging.debug(f"AdminExposure: Title match found: {keyword} in {title_text_lower}")
                     break
                elif keyword != 'login' and keyword in title_text_lower:
                    title_match = True
                    logging.debug(f"AdminExposure: Title match found: {keyword} in {title_text_lower}")
                    break

        # Check 3: Does the body content suggest an admin area?
        # Look for keywords AND presence of password fields for higher confidence
        has_password_field = '<input type=["\']password["\']' in text_content_lower
        keyword_in_body = False
        for keyword in ADMIN_KEYWORDS:
             # Avoid simple 'login' match unless combined with other admin terms or password field
             if keyword == 'login' and (has_password_field or 'admin' in text_content_lower or 'control' in text_content_lower):
                 keyword_in_body = True
                 logging.debug(f"AdminExposure: Body keyword match found: {keyword}")
                 break
             elif keyword != 'login' and keyword in text_content_lower:
                 keyword_in_body = True
                 logging.debug(f"AdminExposure: Body keyword match found: {keyword}")
                 break
        
        if keyword_in_body and has_password_field:
            body_match = True # Strong indicator
        elif keyword_in_body: # Weaker indicator
            body_match = True 

        # Determine finding based on evidence
        # Strong evidence: Path match AND (Title match OR Body match)
        # Medium evidence: Title match AND Body match (even if no path match)
        # Medium evidence: Path match
        # Low evidence: Title match OR Body match alone
        if path_match and (title_match or body_match):
            severity = 'High'
            reason = "URL path, title/body content suggest admin interface."
        elif title_match and body_match:
             severity = 'Medium'
             reason = "Page title and body content suggest admin interface."
        elif path_match:
            severity = 'Medium' # Path alone is concerning
            reason = "URL path suggests an admin interface."
        elif title_match or body_match:
             severity = 'Low' # Weaker signal
             reason = "Page title or body content contain keywords related to admin interfaces."
        else:
            # No significant evidence found
            return findings

        # Create the finding
        findings.append({
            'name': 'Potential Admin Interface Exposure',
            'severity': severity,
            'description': f"The page at {url} might be an exposed administration interface. {reason}"
        })

    except Exception as e:
        logging.error(f"AdminExposure: Error analyzing URL {url}: {e}", exc_info=True)
        # Optionally add an info finding about the error
        # findings.append({'name': 'Admin Scan Error', 'severity': 'Info', 'description': f'Error during analysis: {e}'})

    return findings

# --- Removed old code ---
