import logging
from bs4 import BeautifulSoup # Use BeautifulSoup for title check

def check(response, soup):
    """
    Checks the HTML content for signs of directory listing enabled on the server.

    Args:
        response (requests.Response): The response object from the initial request.
        soup (BeautifulSoup): Parsed HTML object (if available).
        **kwargs: Catches unused context arguments.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []

    if not response:
        logging.warning("DirListing: No response object provided.")
        return findings

    # Check content type - only proceed if likely HTML or text
    content_type = response.headers.get('Content-Type', '').lower()
    if not ('html' in content_type or 'text' in content_type):
        logging.debug("DirListing: Skipping check, content type is not HTML/Text.")
        return findings

    # Get text content and title (if available)
    text_content_lower = response.text.lower()
    title_text_lower = ''
    if soup and soup.title and soup.title.string:
        title_text_lower = soup.title.string.lower()

    # Patterns to look for
    title_patterns = [
        'index of /',
        'directory listing for'
    ]
    body_patterns = [
        'parent directory',
        '<pre>name</a>',        # Common in Apache listings
        'to parent directory</>' # Common in Nginx/IIS
    ]

    found_title = False
    found_body = False
    matched_body_pattern = '' # Store which pattern matched for reporting

    # Check title
    if title_text_lower:
        for pattern in title_patterns:
            if pattern in title_text_lower:
                found_title = True
                break

    # Check body
    for pattern in body_patterns:
        if pattern in text_content_lower:
            found_body = True
            matched_body_pattern = pattern # Remember the specific pattern
            break

    # Report finding based on evidence
    # Title match OR (Body match AND 'index of' text) = Medium severity
    if found_title or (found_body and 'index of' in text_content_lower):
        # Use simpler string formatting
        desc = "The web server appears to have directory listing enabled for the requested path '{}'. This could expose unintended files or directory structures.".format(response.url)
        findings.append({
            'name': 'Directory Listing Enabled',
            'severity': 'Medium',
            'description': desc
        })
    # Just a Body match without 'index of' = Low severity / Potential
    elif found_body:
         # Use simpler string formatting
         desc = "The response content for '{}' contains patterns ('{}') often associated with directory listings, although confirmation is weak. Manual review recommended.".format(response.url, matched_body_pattern)
         findings.append({
            'name': 'Potential Directory Listing',
            'severity': 'Low',
            'description': desc
         })

    return findings

# --- Removed old code ---
# import requests
#
# def check(url):
#     findings = []
#     try:
#         r = requests.get(url, timeout=5)
#         # Simple check, prone to false positives/negatives
#         if all(word in r.text.lower() for word in ["index of", "<title>", "parent directory"]):
#             findings.append("Directory listing enabled")
#     except Exception:
#         findings.append("Directory listing test failed")
#     return findings
