import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import builtwith
import os
import logging

# Add import for the socks module
try:
    import socks
    import socket
    SOCKS_SUPPORT = True
except ImportError:
    SOCKS_SUPPORT = False
    print("WARNING: PySocks library not found. SOCKS proxy support will be unavailable.")
    print("Install using: pip install PySocks")

from config import load_config # pip install python-builtwith
from technology_detector import detect_technology_inhouse
from pagespeed_analyzer import analyze_pagespeed_inhouse
from security_scanner import scan_website_security

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    # from selenium.webdriver.firefox.options import Options as FirefoxOptions # Uncomment if using Firefox
    from selenium.webdriver.common.by import By # Not strictly used here, but often useful
    from selenium.webdriver.support.ui import WebDriverWait # Potentially useful for more complex waits
    from selenium.webdriver.support import expected_conditions as EC # Potentially useful
    from selenium.common.exceptions import WebDriverException, TimeoutException
    SELENIUM_IMPORTED = True
except ImportError:
    SELENIUM_IMPORTED = False
    print("WARNING: Selenium library not found. JS error checking will be skipped.")
    print("Install using: pip install selenium")

config = load_config()

# Get retry configuration from config or use defaults
RETRY_CONFIG = config.get('retry_settings', {})
MAX_RETRIES = RETRY_CONFIG.get('max_retries', 15)
BACKOFF_FACTOR = RETRY_CONFIG.get('backoff_factor', 0.5)
RETRY_STATUS_CODES = RETRY_CONFIG.get('retry_status_codes', [429, 500, 502, 503, 504])
RETRY_METHODS = ["GET", "POST", "HEAD", "OPTIONS"]

# Add function to configure proxy settings
def configure_proxy():
    """Configure proxy settings based on config.json"""
    proxy_config = config.get('proxy', {})
    
    if not proxy_config.get('enabled', False):
        print("Proxy is disabled in config, using direct connection")
        return None
        
    proxy_type = proxy_config.get('type', '').lower()
    
    if proxy_type == 'socks5':
        if not SOCKS_SUPPORT:
            print("WARNING: SOCKS5 proxy specified but PySocks not installed.")
            return None
            
        proxy_host = proxy_config.get('host')
        proxy_port = proxy_config.get('port')
        proxy_username = proxy_config.get('username')
        proxy_password = proxy_config.get('password')
        
        if not (proxy_host and proxy_port):
            print("WARNING: Incomplete SOCKS5 proxy configuration (missing host or port)")
            return None
            
        # Format for requests library
        proxy_url = proxy_config.get('url')
        if not proxy_url:
            if proxy_username and proxy_password:
                proxy_url = f"socks5://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"
            else:
                proxy_url = f"socks5://{proxy_host}:{proxy_port}"
                
        print(f"Configuring SOCKS5 proxy: {proxy_host}:{proxy_port}")
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    elif proxy_type == 'http' or proxy_type == 'https':
        proxy_url = proxy_config.get('url')
        if not proxy_url:
            proxy_host = proxy_config.get('host')
            proxy_port = proxy_config.get('port')
            proxy_username = proxy_config.get('username')
            proxy_password = proxy_config.get('password')
            
            if not (proxy_host and proxy_port):
                print("WARNING: Incomplete HTTP proxy configuration (missing host or port)")
                return None
                
            if proxy_username and proxy_password:
                proxy_url = f"{proxy_type}://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"
            else:
                proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"
        
        print(f"Configuring {proxy_type.upper()} proxy: {proxy_url.split('@')[-1]}")
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    else:
        print(f"WARNING: Unsupported proxy type '{proxy_type}'. Supported types: socks5, http, https")
        return None

# Configure proxy for the entire application
proxy_settings = configure_proxy()

# Create a function to configure retry logic for sessions
def configure_session_retries(session, max_retries=MAX_RETRIES, backoff_factor=BACKOFF_FACTOR):
    """
    Configure a requests.Session with retry logic.
    
    Args:
        session (requests.Session): The session to configure
        max_retries (int): Maximum number of retries
        backoff_factor (float): Backoff factor for exponential delay between retries
        
    Returns:
        requests.Session: The configured session
    """
    # Define retry strategy
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=RETRY_STATUS_CODES,
        allowed_methods=RETRY_METHODS,
        respect_retry_after_header=True,
        # Additional options from config
        raise_on_redirect=False,
        raise_on_status=True,
        connect=RETRY_CONFIG.get('retry_on_connection_error', True),
        read=RETRY_CONFIG.get('retry_on_timeout', True)
    )
    
    # Mount the retry adapter to both HTTP and HTTPS
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    print(f"Configured retry strategy: max_retries={max_retries}, backoff_factor={backoff_factor}")
    return session

def check_pagespeed(url, api_key):
    """Uses Google PageSpeed Insights API."""
    print("    - Checking PageSpeed Insights using Google API...")
    # Documentation: https://developers.google.com/speed/docs/insights/v5/reference/pagespeedapi/runpagespeed
    api_endpoint = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}&key={api_key}&strategy=DESKTOP" # &strategy=MOBILE for mobile
    try:
        # Create a session with retry logic
        session = configure_session_retries(requests.Session())
        response = session.get(api_endpoint, timeout=30) # API call can be slow
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        # Extract key metrics
        score = data.get('lighthouseResult', {}).get('categories', {}).get('performance', {}).get('score')
        lcp = data.get('lighthouseResult', {}).get('audits', {}).get('largest-contentful-paint', {}).get('displayValue')
        cls = data.get('lighthouseResult', {}).get('audits', {}).get('cumulative-layout-shift', {}).get('displayValue')
        # Convert score to percentage
        performance_score = int(score * 100) if score is not None else None
        print(f"      * Score: {performance_score}, LCP: {lcp}, CLS: {cls}")
        return {"performance_score": performance_score, "lcp": lcp, "cls": cls}
    except requests.exceptions.RetryError as e:
        print(f"      * PageSpeed API Error: Maximum retries exceeded: {e}")
        return {"error": f"Maximum retries exceeded: {str(e)}"}
    except requests.exceptions.Timeout as e:
        print(f"      * PageSpeed API Error: Request timed out: {e}")
        return {"error": f"Request timed out: {str(e)}"}
    except requests.exceptions.RequestException as e:
        print(f"      * PageSpeed API Error: {e}")
        return {"error": str(e)}
    except Exception as e:
         print(f"      * Error processing PageSpeed results: {e}")
         return {"error": str(e)}

def check_links(base_url, soup, config):
    """Checks internal (and optionally external) links on the page."""
    print(f"    - Checking links (max: {config.get('max_links_to_check_per_page')}, external: {config.get('check_external_links')})...")
    broken_internal = []
    broken_external = []
    checked_count = 0
    base_domain = urlparse(base_url).netloc
    headers = {'User-Agent': config.get('user_agent')}
    
    # Create a session with retry logic for link checking
    link_session = requests.Session()
    link_session.headers.update(headers)
    link_session = configure_session_retries(
        link_session, 
        max_retries=config.get('max_retries', MAX_RETRIES),
        backoff_factor=config.get('backoff_factor', BACKOFF_FACTOR)
    )

    # Apply proxy settings if configured
    if proxy_settings:
        link_session.proxies.update(proxy_settings)

    for link in soup.find_all('a', href=True):
        if checked_count >= config.get('max_links_to_check_per_page'):
            break

        href = link['href']
        try:
            # Construct absolute URL
            absolute_url = urljoin(base_url, href)
            parsed_link = urlparse(absolute_url)

            # Skip non-http(s) links
            if parsed_link.scheme not in ('http', 'https'):
                continue

            is_internal = parsed_link.netloc == base_domain

            if is_internal or config.get('check_external_links'):
                checked_count += 1
                print(f"      * Checking {'Internal' if is_internal else 'External'} link: {absolute_url[:80]}...", end="")
                status = None
                error_msg = None
                retry_info = None
                
                try:
                    # HEAD request is faster, with retry logic
                    link_response = link_session.head(
                        absolute_url, 
                        timeout=config.get('scan_timeout', 15) / 2, 
                        allow_redirects=True
                    )
                    status = link_response.status_code
                    
                    # Check for retry information from adapter history
                    retry_history = getattr(link_response, 'history', [])
                    retry_count = len(retry_history)
                    
                    if retry_count > 0:
                        retry_info = {"attempts": retry_count, "success": True}
                        print(f" OK ({status}, after {retry_count} retries)")
                    elif status >= 400:
                        error_msg = f"HTTP {status}"
                        print(f" BROKEN ({status})")
                    else:
                        print(f" OK ({status})")
                        
                except requests.exceptions.RetryError as e:
                    error_msg = f"Max retries exceeded: {str(e)}"
                    retry_info = {"attempts": MAX_RETRIES, "success": False, "error": str(e)}
                    print(f" ERROR (Max retries exceeded)")
                except requests.exceptions.Timeout:
                    error_msg = "Timeout"
                    print(" TIMEOUT")
                except requests.exceptions.ConnectionError as e:
                    error_msg = f"Connection Error: {str(e)}"
                    print(f" ERROR (Connection Error)")
                except requests.exceptions.RequestException as req_err:
                    error_msg = f"Request Error: {type(req_err).__name__}"
                    print(f" ERROR ({type(req_err).__name__})")

                if error_msg:
                    link_data = {
                        "url": absolute_url, 
                        "status": status or error_msg
                    }
                    if retry_info:
                        link_data["retry_info"] = retry_info
                        
                    if is_internal:
                        broken_internal.append(link_data)
                    else:
                        broken_external.append(link_data)

                time.sleep(config.get('scanner_delay_seconds', 0.5) / 4) # Small delay between link checks

        except Exception as parse_err:
            print(f"      * Error parsing link '{href}': {parse_err}")

    print(f"    - Link check finished. Broken Internal: {len(broken_internal)}, Broken External: {len(broken_external)}")
    return {"broken_internal": broken_internal, "broken_external": broken_external}

def check_security_headers(headers):
    """Checks for basic security headers."""
    print("    - Checking security headers...")
    results = {
        "content_security_policy": headers.get('Content-Security-Policy', 'Missing'),
        "strict_transport_security": headers.get('Strict-Transport-Security', 'Missing'),
        "x_frame_options": headers.get('X-Frame-Options', 'Missing'),
        "x_content_type_options": headers.get('X-Content-Type-Options', 'Missing'),
    }
    print(f"      * CSP: {'Present' if results['content_security_policy'] != 'Missing' else 'Missing'}, HSTS: {'Present' if results['strict_transport_security'] != 'Missing' else 'Missing'}, XFO: {'Present' if results['x_frame_options'] != 'Missing' else 'Missing'}")
    return results

def check_seo_basics(soup):
    """Checks for title, meta description, H1, image alt tags."""
    print("    - Checking basic SEO elements...")
    results = {
        "title": None,
        "meta_description": None,
        "h1_count": 0,
        "images_missing_alt": 0,
        "total_images": 0,
    }
    title_tag = soup.find('title')
    results["title"] = title_tag.string.strip() if title_tag else "Missing"

    meta_desc = soup.find('meta', attrs={'name': 'description'})
    results["meta_description"] = meta_desc['content'].strip() if meta_desc and 'content' in meta_desc.attrs else "Missing"

    results["h1_count"] = len(soup.find_all('h1'))

    images = soup.find_all('img')
    results["total_images"] = len(images)
    for img in images:
        if not img.get('alt', '').strip():
            results["images_missing_alt"] += 1

    print(f"      * Title: {'Present' if results['title'] != 'Missing' else 'Missing'}, Meta Desc: {'Present' if results['meta_description'] != 'Missing' else 'Missing'}, H1s: {results['h1_count']}, Imgs w/o Alt: {results['images_missing_alt']}/{results['total_images']}")
    return results

def check_mixed_content(url, soup):
    """Checks for http:// resources on an https:// page."""
    print("    - Checking for mixed content...")
    mixed_content_found = []
    if url.startswith("https://"):
        for tag in soup.find_all(['script', 'link', 'img'], src=True):
            src = tag.get('src', '')
            if src.startswith('http://'):
                 mixed_content_found.append({'tag': tag.name, 'src': src})
        for tag in soup.find_all(['link'], href=True): # Check CSS links too
            href = tag.get('href', '')
            if href.startswith('http://') and tag.get('rel') == ['stylesheet']:
                 mixed_content_found.append({'tag': 'link[stylesheet]', 'href': href})
    status = f"Found {len(mixed_content_found)} items" if mixed_content_found else "None Found"
    print(f"      * Status: {status}")
    return {"mixed_content_items": mixed_content_found, "status": status}

def check_js_errors_selenium(url, config):
    """
    Uses Selenium to load a page and capture severe JavaScript console errors.

    Args:
        url (str): The URL to check.
        config (dict): The configuration dictionary. Must contain 'user_agent'.
                       Optionally can contain 'webdriver_path' if not in system PATH.
                       Also uses 'scan_timeout' for page load wait.

    Returns:
        dict: {
            "status": "Checked | Skipped | Error",
            "error_message": str or None,
            "js_errors": list[dict] containing {'level', 'message', 'timestamp'}
        }
    """
    print("    - Checking for JavaScript errors (using Selenium)...")
    if not SELENIUM_IMPORTED:
        return {"status": "Skipped", "error_message": "Selenium library not installed.", "js_errors": []}

    results = {
        "status": "Error", # Default to error
        "error_message": None,
        "js_errors": []
    }
    driver = None # Initialize driver to None for finally block

    try:
        # --- Configure Chrome Options ---
        # TODO: Add Firefox options if needed with an if/else based on config
        options = ChromeOptions()
        options.add_argument("--headless") # Run without opening a browser window
        options.add_argument("--disable-gpu") # Often necessary for headless
        options.add_argument("--no-sandbox") # Often necessary in CI/server environments
        options.add_argument("--window-size=1280,800") # Set a reasonable window size
        options.add_argument(f"user-agent={config.get('user_agent', 'Selenium Bot')}")
        options.add_argument("--log-level=3") # Suppress excessive Selenium logging in console

        # Enable browser logging to capture console errors
        # Note: 'goog:loggingPrefs' is for Chrome >= 75
        options.set_capability('goog:loggingPrefs', {'browser': 'SEVERE'}) # Capture only SEVERE level logs

        # --- Instantiate WebDriver ---
        webdriver_path = config.get('webdriver_path') # Check config for specific path
        if webdriver_path:
             # Use Service object for modern Selenium versions (4.x+)
             from selenium.webdriver.chrome.service import Service as ChromeService
             service = ChromeService(executable_path=webdriver_path)
             driver = webdriver.Chrome(service=service, options=options)
             print(f"      * Using WebDriver from: {webdriver_path}")
        else:
             # Assume chromedriver is in PATH
             driver = webdriver.Chrome(options=options)
             print("      * Using WebDriver from system PATH")


        # Set a page load timeout (adjust as needed)
        page_load_timeout = config.get('scan_timeout', 15) # Use scan_timeout from config or default
        driver.set_page_load_timeout(page_load_timeout)

        # --- Navigate and Wait ---
        print(f"      * Navigating to {url}...")
        try:
            driver.get(url)
            # Wait a fixed amount of time after page load for JS to potentially execute/fail
            # More robust waits (e.g., WebDriverWait) are better but harder for generic JS errors.
            time.sleep(config.get('selenium_js_wait_seconds', 5)) # Add this wait time to config if desired
            print("      * Page loaded, retrieving logs...")
        except TimeoutException:
            results["error_message"] = f"Page load timed out after {page_load_timeout} seconds."
            print(f"      * Error: {results['error_message']}")
            # Don't return yet, try to get logs anyway if possible, then quit in finally
        except WebDriverException as nav_err:
            # Handle navigation errors (e.g., invalid URL, DNS error caught by driver)
            results["error_message"] = f"Navigation error: {nav_err}"
            print(f"      * Error: {results['error_message']}")
            # Don't return yet, ensure cleanup in finally

        # --- Retrieve and Process Logs (if driver started) ---
        if driver: # Check if driver initialization was successful
            try:
                log_entries = driver.get_log('browser')
                severe_errors = [
                    entry for entry in log_entries
                    if entry.get('level') == 'SEVERE'
                ]
                # Format errors for reporting
                results["js_errors"] = [
                    {
                        "level": entry.get('level'),
                        "message": entry.get('message', '').strip(),
                        "timestamp": entry.get('timestamp')
                    }
                    for entry in severe_errors
                ]
                results["status"] = "Checked" # Mark as checked if logs were retrieved
                print(f"      * Found {len(results['js_errors'])} severe JavaScript errors.")
                # Clear error message if logs were retrieved successfully, even if page timed out before
                if results["error_message"] and "timed out" in results["error_message"]:
                    # Keep timeout message if errors were found, otherwise clear it
                     if not results["js_errors"]:
                        results["error_message"] = None # No severe errors found despite timeout, likely OK
                elif results["error_message"] is None: # No prior errors
                     pass # Status is Checked, no error message needed

            except WebDriverException as log_err:
                # Error retrieving logs
                results["error_message"] = f"Could not retrieve browser logs: {log_err}"
                print(f"      * Error: {results['error_message']}")
                results["status"] = "Error" # Set status back to Error


    except WebDriverException as e:
        # Errors during WebDriver setup (e.g., driver not found, browser crash on start)
        results["error_message"] = f"Selenium WebDriver setup failed: {e}"
        print(f"      * Error: {results['error_message']}")
        results["status"] = "Error"
    except Exception as e:
        # Catch-all for other unexpected errors
        results["error_message"] = f"Unexpected Selenium error: {e}"
        print(f"      * Error: {results['error_message']}")
        results["status"] = "Error"

    finally:
        # --- Cleanup ---
        if driver:
            try:
                driver.quit()
                print("      * WebDriver closed.")
            except Exception as e:
                print(f"      * Warning: Error closing WebDriver: {e}")

    return results
    

def scan_website_advanced(url, config):
    """Perform a comprehensive scan on a website."""
    # Normalize URL
    if not url.startswith('http'):
        url = 'http://' + url
    
    # Prepare the request session with retry logic and timeout
    session = configure_session_retries(requests.Session())
    session.headers.update({'User-Agent': config.get('user_agent')})
    
    # Apply proxy settings if configured
    if proxy_settings:
        session.proxies.update(proxy_settings)
        print(f"Using proxy for scan: {proxy_settings}")
        logging.info(f"Proxy configured for scan: {str(proxy_settings)}")
    
    # Start the scan
    start_time = time.time()
    print(f"Starting scan on {url}")
    
    scan_results = {
        "url": url,
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "scan_success": False,
        "error": None,
        "status_code": None,
        "content_type": None,
        "technologies": {},
        "security": {},
        "pagespeed": {},
        "seo": {},
        "links": {},
        "js_errors": {},
        "mixed_content": {},
        "headers": {},
        "retry_info": None  # Will store retry information
    }
    
    try:
        # Initial request with retry logic
        print(f"1. Making initial request to {url} (with auto-retry)...")
        retry_count = 0
        retry_succeeded = False
        
        try:
            response = session.get(url, timeout=config.get('scan_timeout', 15), allow_redirects=True)
            response.raise_for_status()
            retry_succeeded = True
            scan_results["status_code"] = response.status_code
            scan_results["content_type"] = response.headers.get('Content-Type', 'Unknown')
            scan_results["headers"] = dict(response.headers)
            
            # Check if we had to retry
            adapter = session.adapters["https://"] if url.startswith("https") else session.adapters["http://"]
            retry_history = getattr(response, 'history', [])
            retry_count = len(retry_history)
            
            if retry_count > 0:
                scan_results["retry_info"] = {
                    "attempts": retry_count,
                    "success": True,
                    "status_codes": [r.status_code for r in retry_history]
                }
                print(f"   - Request succeeded after {retry_count} retries")
            else:
                print(f"   - Request successful on first attempt (Status: {response.status_code})")
            
        except (requests.exceptions.RequestException, IOError) as e:
            # Check retry history if available
            error_type = type(e).__name__
            error_msg = str(e)
            
            if isinstance(e, requests.exceptions.RetryError):
                retry_count = config.get('max_retries', MAX_RETRIES)  # Reached max retries
            
            scan_results["retry_info"] = {
                "attempts": retry_count,
                "success": False,
                "error": error_msg,
                "error_type": error_type
            }
            print(f"   - ERROR: {error_type} - {error_msg} (after {retry_count} retries)")
            raise  # Re-raise for outer exception handler
        
        # Handle redirects
        if response.history:
            original_url = url
            final_url = response.url
            print(f"   - Redirected: {original_url} -> {final_url}")
            scan_results["redirects"] = [{"status_code": r.status_code, "url": r.url} for r in response.history]
            scan_results["final_url"] = final_url
            url = final_url  # Update URL for subsequent checks
        
        # Check content type
        if 'text/html' not in scan_results["content_type"].lower():
            print(f"   - Warning: Not an HTML page (Content-Type: {scan_results['content_type']})")
            scan_results["warning"] = f"Not an HTML page (Content-Type: {scan_results['content_type']})"
        
        # Parse HTML
        print("2. Parsing HTML content")
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            page_title = soup.title.string.strip() if soup.title else "No title found"
            print(f"   - Title: {page_title}")
            scan_results["title"] = page_title
        except Exception as parse_err:
            print(f"   - Error parsing HTML: {parse_err}")
            scan_results["error"] = f"HTML parsing error: {str(parse_err)}"
            soup = BeautifulSoup("<html></html>", 'html.parser')  # Empty soup
        
        # Security headers check (basic)
        scan_results["headers_check"] = check_security_headers(response.headers)
        
        # SEO basics check
        scan_results["seo"] = check_seo_basics(soup)
        
        # Check for mixed content
        scan_results["mixed_content"] = check_mixed_content(url, soup)
        
        # Link checking
        scan_results["links"] = check_links(url, soup, config)
        
        # Technology detection
        if config.get('enable_tech_detection', True):
            print("3. Detecting website technologies...")
            inhouse_detected = False
            if config.get('use_inhouse_tech_detection', True):
                try:
                    tech_results = detect_technology_inhouse(response.text, response.headers, url)
                    print(f"   - In-house detection found {len(tech_results.get('technologies', []))} technologies")
                    scan_results["technologies"] = tech_results
                    inhouse_detected = True
                except Exception as tech_err:
                    print(f"   - Error in in-house tech detection: {tech_err}")
                    inhouse_detected = False
            
            if not inhouse_detected and config.get('use_builtwith_fallback', True):
                print("   - Falling back to BuiltWith API...")
                try:
                    # Create a session with retry for BuiltWith API
                    bw_session = configure_session_retries(requests.Session())
                    bw_session.headers.update({'User-Agent': config.get('user_agent')})
                    
                    # Use the session in builtwith.py (if possible) or just call builtwith
                    builtwith_results = builtwith.builtwith(url, ua=config.get('user_agent'))
                    tech_results = {"source": "builtwith", "technologies": []}
                    for category, techs in builtwith_results.items():
                        for tech_name in techs:
                            tech_results["technologies"].append({
                                "name": tech_name,
                                "category": category,
                                "confidence": "high"  # BuiltWith doesn't provide confidence levels
                            })
                    print(f"   - BuiltWith found {len(tech_results['technologies'])} technologies")
                    scan_results["technologies"] = tech_results
                except Exception as builtwith_err:
                    print(f"   - Error in BuiltWith detection: {builtwith_err}")
        else:
            print("   - Technology detection disabled in config")
        
        # PageSpeed analysis
        if config.get('enable_pagespeed_scan', True):
            print("4. Analyzing page speed...")
            if config.get('use_inhouse_pagespeed', True):
                try:
                    speed_results = analyze_pagespeed_inhouse(response, url)
                    scan_results["pagespeed"] = speed_results
                    print(f"   - In-house PageSpeed Score: {speed_results.get('score', 'N/A')}/100")
                except Exception as speed_err:
                    print(f"   - Error in in-house PageSpeed: {speed_err}")
                    if config.get('use_google_pagespeed_fallback', True):
                        print("   - Falling back to Google PageSpeed API...")
                        api_key = config.get('google_api_key')
                        if api_key:
                            speed_results = check_pagespeed(url, api_key)
                            scan_results["pagespeed"] = speed_results
                        else:
                            print("   - No Google API key found in config")
            elif config.get('use_google_pagespeed_fallback', True):
                print("   - Using Google PageSpeed API directly...")
                api_key = config.get('google_api_key')
                if api_key:
                    speed_results = check_pagespeed(url, api_key)
                    scan_results["pagespeed"] = speed_results
                else:
                    print("   - No Google API key found in config")
        else:
            print("   - PageSpeed analysis disabled in config")
        
        # JavaScript error detection (requires Selenium)
        if config.get('enable_js_error_check', True) and SELENIUM_IMPORTED:
            print("5. Checking for JavaScript errors...")
            try:
                js_results = check_js_errors_selenium(url, config)
                scan_results["js_errors"] = js_results
                if js_results.get("status") == "Checked":
                    errors_count = len(js_results.get("js_errors", []))
                    print(f"   - Found {errors_count} serious JavaScript errors")
                else:
                    print(f"   - JS error check {js_results.get('status', 'Failed')}: {js_results.get('error_message', 'Unknown error')}")
            except Exception as js_err:
                print(f"   - Failed to check JS errors: {js_err}")
                scan_results["js_errors"] = {"status": "Error", "error_message": str(js_err)}
        else:
            print("   - JavaScript error checking disabled or not available")
        
        # Security scan (most thorough, using modular scanner)
        if config.get('enable_security_scan', True):
            print("6. Performing comprehensive security scan...")
            security_config = {
                'user_agent': config.get('user_agent'),
                'proxy': proxy_settings,  # Pass proxy settings to security scanner
                'scan_timeout': config.get('scan_timeout', 15),
                'verbose_security_scan': config.get('verbose_security_scan', False),
                'max_retries': config.get('max_retries', MAX_RETRIES),
                'backoff_factor': config.get('backoff_factor', BACKOFF_FACTOR)
            }
            try:
                security_results = scan_website_security(url, security_config)
                scan_results["security"] = security_results
                # Get summary counts
                if isinstance(security_results, dict) and 'summary' in security_results:
                    summary = security_results.get('summary', {})
                    print(f"   - Security findings: Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)}, Info: {summary.get('info', 0)}")
                else:
                    print("   - Security scan completed but returned unexpected format")
            except Exception as sec_err:
                print(f"   - Error during security scan: {sec_err}")
                scan_results["security"] = {"error": str(sec_err)}
        else:
            print("   - Security scan disabled in config")
        
        # Mark scan as successful
        scan_results["scan_success"] = True
        
    except requests.exceptions.RetryError as e:
        # The request exceeded the configured maximum number of retries
        error_type = type(e).__name__
        error_msg = str(e)
        print(f"ERROR: Maximum retries exceeded - {error_msg}")
        scan_results["error"] = f"Maximum retries exceeded: {error_msg}"
    except requests.exceptions.Timeout as e:
        # The request timed out
        error_type = type(e).__name__
        error_msg = str(e)
        print(f"ERROR: Request timed out - {error_msg}")
        scan_results["error"] = f"Request timed out: {error_msg}"
    except requests.exceptions.ConnectionError as e:
        # A network connection error occurred
        error_type = type(e).__name__
        error_msg = str(e)
        print(f"ERROR: Connection error - {error_msg}")
        scan_results["error"] = f"Connection error: {error_msg}"
    except requests.exceptions.RequestException as req_err:
        # Handle any other request exceptions
        error_type = type(req_err).__name__
        error_msg = str(req_err)
        print(f"ERROR: {error_type} - {error_msg}")
        scan_results["error"] = f"{error_type}: {error_msg}"
    except Exception as e:
        # Catch-all for other errors
        error_type = type(e).__name__
        error_msg = str(e)
        print(f"UNEXPECTED ERROR: {error_type} - {error_msg}")
        scan_results["error"] = f"{error_type}: {error_msg}"
    finally:
        # Calculate scan duration
        scan_duration = time.time() - start_time
        scan_results["scan_duration_seconds"] = round(scan_duration, 2)
        print(f"Scan completed in {scan_results['scan_duration_seconds']} seconds")
        
    return scan_results
