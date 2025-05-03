import os
import importlib
import inspect
import sys
import requests
from urllib.parse import urlparse
import time
# Try to import optional dependencies, warn if missing
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None # Flag that it's not available
try:
    import websocket
except ImportError:
    websocket = None # Flag that it's not available

# Define the path to the modules directory relative to this script
MODULES_DIR = 'modules'
# Define the preferred order of function names to look for
SCAN_FUNCTION_NAMES = ['scan', 'run_scan', 'check'] # Prioritize 'scan'/'run_scan' over generic 'check'

def run_tests(target_url):
    """
    Discovers and runs tests from modules in the MODULES_DIR.
    """
    print(f"--- Running tests against: {target_url} ---")
    start_time = time.time()

    # Basic URL parsing
    try:
        parsed_target = urlparse(target_url)
        domain = parsed_target.netloc
        base_url = f"{parsed_target.scheme}://{domain}" # Scheme + domain
        if not domain:
             print(f"Error: Could not parse domain from target URL: {target_url}")
             return
    except ValueError as e:
        print(f"Error: Invalid target URL provided: {target_url} ({e})")
        return

    # Determine potential WebSocket URL
    ws_url = None
    if parsed_target.scheme in ['http', 'https']:
        ws_scheme = 'ws' if parsed_target.scheme == 'http' else 'wss'
        # Simple guess: ws(s)://domain/path - might need adjustment
        ws_url = f"{ws_scheme}://{domain}{parsed_target.path or '/'}"

    # Prepare session and initial request data for modules that might need it (like xss)
    session = requests.Session()
    # Add a common user-agent
    session.headers.update({'User-Agent': 'SecurityScannerTestRunner/1.0'})
    initial_response = None
    soup = None

    try:
        print(f"Performing initial request to {target_url}...")
        initial_response = session.get(target_url, timeout=10, allow_redirects=True)
        initial_response.raise_for_status() # Raise error for bad status codes (4xx or 5xx)
        print(f"Initial request successful (Status: {initial_response.status_code})")
        if BeautifulSoup:
            soup = BeautifulSoup(initial_response.text, 'html.parser')
        else:
            print("Warning: BeautifulSoup4 not installed. DOM-based checks (like in xss module) cannot be performed.")
    except requests.exceptions.RequestException as e:
        print(f"Warning: Error fetching initial target URL {target_url}: {e}")
        print("    Modules requiring an initial successful connection might fail or be skipped.")
    except Exception as e:
        print(f"Warning: Unexpected error during initial request setup: {e}")


    all_findings = {}
    skipped_modules = []
    modules_with_errors = {}

    # Ensure the modules directory is in the Python path
    sys.path.insert(0, os.path.abspath('.'))

    if not os.path.isdir(MODULES_DIR):
        print(f"Error: Modules directory '{MODULES_DIR}' not found in the current directory.")
        return

    for filename in sorted(os.listdir(MODULES_DIR)): # Sort for consistent order
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            module_full_path = f"{MODULES_DIR}.{module_name}"
            print(f"[+] Testing Module: {module_name}")

            module = None
            target_func = None
            func_name_found = None

            try:
                # Dynamically import the module
                module = importlib.import_module(module_full_path)

                # Find the appropriate scan function
                for func_name in SCAN_FUNCTION_NAMES:
                    if hasattr(module, func_name):
                        target_func = getattr(module, func_name)
                        func_name_found = func_name
                        break # Found a suitable function

                if target_func:
                    sig = inspect.signature(target_func)
                    params = sig.parameters
                    num_params = len(params)
                    param_names = list(params.keys())

                    findings = None
                    # --- Attempt to call based on known signatures ---
                    try:
                        if func_name_found in ['check'] and num_params == 1:
                            # Handles most modules expecting a single URL/Target
                            param_name = param_names[0]
                            # Special cases needing domain or ws_url
                            if module_name in ['open_port', 'subdomain_takeover']:
                                print(f"    Calling {func_name_found}({param_name}='{domain}')...")
                                findings = target_func(domain)
                            elif module_name == 'websocket_injection':
                                if not websocket:
                                     print("    Skipping: websocket-client library not installed.")
                                     skipped_modules.append(f"{module_name} (websocket-client missing)")
                                elif ws_url:
                                    print(f"    Calling {func_name_found}({param_name}='{ws_url}')...")
                                    findings = target_func(ws_url)
                                else:
                                    print(f"    Skipping: Could not determine WebSocket URL from {target_url}")
                                    skipped_modules.append(f"{module_name} (WebSocket URL needed)")
                            else:
                                # Default: pass the full target_url
                                print(f"    Calling {func_name_found}({param_name}='{target_url}')...")
                                findings = target_func(target_url)

                        elif func_name_found == 'check' and num_params == 1 and module_name == 'unicode_filter_bypass':
                             # Specific case for unicode_filter_bypass which uses check(target_url)
                             param_name = param_names[0]
                             print(f"    Calling {func_name_found}({param_name}='{target_url}')...")
                             findings = target_func(target_url)

                        # Handle check(...) signature for xss
                        elif func_name_found == 'check' and module_name == 'xss':
                            if not BeautifulSoup:
                                print("    Skipping: BeautifulSoup4 library not installed.")
                                skipped_modules.append(f"{module_name} (BeautifulSoup4 missing)")
                            elif initial_response and soup:
                                print(f"    Calling {func_name_found}(session, url, soup, response, headers, payloads, config)...")
                                # Basic config, adjust as needed
                                config = {'verbose': False, 'timeout': 5}
                                # Use the module's own PAYLOADS if available, else provide empty
                                module_payloads = getattr(module, 'PAYLOADS', [])
                                # Note: This call assumes the signature matches exactly.
                                findings = target_func(session, target_url, soup, initial_response, initial_response.headers, module_payloads, config)
                            else:
                                print(f"    Skipping: Requires successful initial fetch and BeautifulSoup.")
                                skipped_modules.append(f"{module_name} (Initial fetch/BS4 failed)")

                        else:
                            print(f"    Skipping: Unrecognized function signature for '{func_name_found}' ({num_params} params: {param_names}).")
                            skipped_modules.append(f"{module_name} (Unrecognized signature: {func_name_found}{sig})")

                    # Catch errors during the execution of the scan function
                    except Exception as e:
                        print(f"    ERROR running {module_name}.{func_name_found}: {type(e).__name__}: {e}")
                        # Optionally include traceback here for more detail
                        modules_with_errors[module_name] = str(e)
                        findings = None # Ensure findings aren't processed if scan errored

                    # Process results if the scan didn't error out
                    if findings is not None:
                         if findings:
                             print(f"    Findings: {findings}")
                             all_findings[module_name] = findings
                         else: # Explicitly check for empty list (no findings)
                             print("    Findings: None")
                             all_findings[module_name] = [] # Record that it ran with no findings

                else:
                    print(f"    Skipping: No suitable scan function ({', '.join(SCAN_FUNCTION_NAMES)}) found.")
                    skipped_modules.append(f"{module_name} (No scan function)")

            # Catch errors during import or module processing
            except ImportError as e:
                print(f"    ERROR importing {module_name}: {e}")
                skipped_modules.append(f"{module_name} (Import Error: {e})")
            except Exception as e:
                print(f"    UNEXPECTED ERROR processing module {module_name}: {type(e).__name__}: {e}")
                skipped_modules.append(f"{module_name} (Unexpected Error: {e})")


    print("--- Test Run Summary ---")
    print(f"Target: {target_url}")
    elapsed_time = time.time() - start_time
    print(f"Time Elapsed: {elapsed_time:.2f} seconds")

    print("[+] Modules with Findings:")
    found_any = False
    for module, findings in all_findings.items():
        if findings:
            print(f"  - {module}: {len(findings)} finding(s)")
            # Optionally print the findings themselves here
            # for finding in findings:
            #     print(f"      - {finding}")
            found_any = True
    if not found_any:
        print("    (None)")


    print("[+] Modules with No Findings:")
    found_none = False
    for module, findings in all_findings.items():
        if not findings: # Empty list means ran with no findings
             print(f"  - {module}")
             found_none = True
    if not found_none:
        print("    (None)")


    if modules_with_errors:
        print("[!] Modules with Errors during Scan:")
        for module, error_msg in modules_with_errors.items():
             print(f"  - {module}: {error_msg}")

    if skipped_modules:
        print("[*] Skipped Modules:")
        # Use set for unique reasons
        for reason in sorted(list(set(skipped_modules))):
            print(f"  - {reason}")

    print("--- Test Run Complete ---")
    # Return combined results if needed, e.g., for CI/CD
    # return {"findings": all_findings, "errors": modules_with_errors, "skipped": skipped_modules}


if __name__ == "__main__":
    # if len(sys.argv) != 2:
        # print(f"Usage: python {os.path.basename(__file__)} <target_url>")
        # print("Example: python test_all_modules.py https://example.com")
        # sys.exit(1)

    # target = sys.argv[1]
    target = "https://hangryjoes.com/"
    # Basic validation
    if not target.startswith('http://') and not target.startswith('https://'):
         print("Error: Target URL must start with http:// or https://")
         sys.exit(1)

    run_tests(target) 