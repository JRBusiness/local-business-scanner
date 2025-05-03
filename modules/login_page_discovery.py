import logging
import requests
from urllib.parse import urljoin, urlparse

# Common paths often associated with login pages
COMMON_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/account/login",
    "/portal",
    "/admin/login",
    "/login.php",
    "/login.aspx",
    "/wp-login.php",
    "/user/login",
    "/auth",
    "/account",
]

# Keywords often found in login links or titles
LOGIN_KEYWORDS = [
    "login",
    "log in",
    "sign in",
    "signin",
    "account",
    "portal",
    "customer login",
    "client login",
    "member area",
    "authenticate",
]

def check(session, url, soup, response, config):
    """
    Checks for potential login pages using heuristics:
    - Checks common URL paths.
    - Looks for keywords in link text and titles.
    - Looks for password fields in forms.
    """
    findings = []
    verbose = config.get('verbose', False)
    timeout = config.get('timeout', 5)
    base_url = f"{response.url.split('/')[0]}//{response.url.split('/')[2]}" # Get scheme://domain
    checked_urls = set() # Avoid checking the same URL multiple times

    # --- 1. Check Common Paths --- 
    if verbose: logging.debug("Checking common login paths...")
    for path in COMMON_LOGIN_PATHS:
        test_url = urljoin(base_url, path)
        if test_url in checked_urls:
            continue
        checked_urls.add(test_url)
        
        try:
            # HEAD request is faster just to check existence
            head_resp = session.head(test_url, timeout=timeout, allow_redirects=False) # Don't follow redirects for HEAD
            # Check for 2xx status codes primarily
            if 200 <= head_resp.status_code < 300:
                logging.info(f"Potential login path found: {test_url} (Status: {head_resp.status_code})")
                findings.append({
                    "name": "Potential Login Page Found (Common Path)",
                    "severity": "Info",
                    "description": f"A common login path '{path}' responded successfully ({head_resp.status_code}).",
                    "evidence": {"url": test_url, "path": path, "status_code": head_resp.status_code},
                    "recommendation": "Manually verify if this is an accessible user login page."
                })
            # Optionally check for redirects if needed, but be cautious
            # elif 300 <= head_resp.status_code < 400:
            #     location = head_resp.headers.get('Location')
            #     logging.info(f"Potential login path found (Redirect): {test_url} -> {location}")
            #     # Add finding for redirect?

        except requests.exceptions.Timeout:
            if verbose: logging.debug(f"Timeout checking path: {test_url}")
        except requests.exceptions.RequestException as e:
            # Ignore connection errors, 404s etc. unless verbose
            if verbose: logging.debug(f"Error checking path {test_url}: {e}")
        except Exception as e:
             logging.warning(f"Unexpected error checking path {test_url}: {e}")

    # --- 2. Check Keywords in Links --- 
    if soup:
        if verbose: logging.debug("Checking for login keywords in links...")
        links = soup.find_all('a', href=True)
        for link in links:
            link_text = link.text.strip().lower()
            link_href = link['href'].lower()
            found_keyword = None

            for keyword in LOGIN_KEYWORDS:
                if keyword in link_text:
                    found_keyword = keyword
                    break
                # Check href as well, but be less certain (e.g., /assets/login.css)
                # if keyword in link_href:
                #    found_keyword = keyword
                #    break 
            
            if found_keyword:
                absolute_url = urljoin(base_url, link['href']) # Resolve relative URLs
                if absolute_url not in checked_urls:
                     logging.info(f"Potential login link found: Text='{link.text.strip()}', Href='{link['href']}', Keyword='{found_keyword}'")
                     findings.append({
                        "name": "Potential Login Page Found (Link Keyword)",
                        "severity": "Info",
                        "description": f"Link text containing keyword '{found_keyword}' found.",
                        "evidence": {"link_text": link.text.strip(), "link_href": link['href'], "resolved_url": absolute_url, "keyword": found_keyword},
                        "recommendation": "Manually verify if this link leads to an accessible user login page."
                    })
                     checked_urls.add(absolute_url)

    # --- 3. Check Keywords in Title --- 
    if soup and soup.title and soup.title.string:
        title_text = soup.title.string.strip().lower()
        if verbose: logging.debug(f"Checking page title: '{title_text[:50]}...'")
        for keyword in LOGIN_KEYWORDS:
            if keyword in title_text:
                logging.info(f"Potential login keyword '{keyword}' found in page title.")
                findings.append({
                    "name": "Potential Login Page Found (Title Keyword)",
                    "severity": "Info",
                    "description": f"Page title contains keyword '{keyword}'.",
                    "evidence": {"title": soup.title.string.strip(), "keyword": keyword},
                    "recommendation": "Manually verify if this page is an accessible user login page."
                })
                break # Found one keyword in title, no need to check others for this page

    # --- 4. Check for Password Fields in Forms --- 
    if soup:
        if verbose: logging.debug("Checking for password fields in forms...")
        forms = soup.find_all('form')
        for form in forms:
            password_input = form.find('input', attrs={ 'type': 'password', 'name': True }) # Look for named password inputs
            if password_input:
                form_action = form.get('action', '')
                action_url = urljoin(base_url, form_action) if form_action else url # Default to current page if no action
                logging.info(f"Password field found in form (Action: '{form_action}', Resolved: '{action_url}')")
                findings.append({
                    "name": "Potential Login Form Found (Password Field)",
                    "severity": "Info",
                    "description": f"A form containing a password input field was found.",
                    "evidence": {"form_action": form_action, "resolved_action_url": action_url, "password_field_name": password_input.get('name')},
                    "recommendation": "Manually verify if this form corresponds to an accessible user login mechanism."
                })
                # Note: Could add checks for username fields, CSRF tokens etc. for higher confidence

    return findings 