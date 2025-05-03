# Http Smuggling.Py Module

import requests
from . import get_session

# Advanced HTTP smuggling payloads for detecting various types of vulnerabilities
HTTP_SMUGGLING_PAYLOADS = [
    # CL.TE (Content-Length and Transfer-Encoding conflict)
    {"header": "Content-Length", "value": "6"},
    {"header": "Transfer-Encoding", "value": "chunked"},
    
    # TE.CL (Transfer-Encoding and Content-Length conflict)
    {"header": "Transfer-Encoding", "value": "chunked"},
    {"header": "Content-Length", "value": "4"},
    
    # TE.TE (Multiple Transfer-Encoding headers)
    {"header": "Transfer-Encoding", "value": "identity, chunked"},
    {"header": "Transfer-Encoding", "value": "identity"},
    
    # Obfuscated headers to bypass security checks
    {"header": "Transfer-Encoding", "value": "chunked\r\n\r\n0\r\n\r\n"},
    {"header": "Transfer-Encoding", "value": "xchunked"},
    {"header": "Transfer-Encoding", "value": "chunked\r\nX-Ignore: X"},
    {"header": "Transfer-Encoding", "value": " chunked"},
    {"header": "Transfer-Encoding", "value": "CHUNKED"},
    {"header": "Transfer-Encoding", "value": "chunk\ned"},
    {"header": "Transfer-Encoding", "value": "chun\r\nked"},
    
    # Abnormal Content-Length values
    {"header": "Content-Length", "value": "0"},
    {"header": "Content-Length", "value": "-1"},
    {"header": "Content-Length", "value": "99999999"},
    
    # Headers specific to front-end servers
    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"header": "Forwarded", "value": "for=127.0.0.1;by=127.0.0.1;host=example.com"},
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Get baseline response
    try:
        r = req_session.get(target_url, timeout=5)
        baseline_status = r.status_code
        baseline_length = len(r.text)
    except Exception:
        return findings
        
    # Test each payload - focus on detecting anomalies
    for payload in HTTP_SMUGGLING_PAYLOADS:
        try:
            # Use a specially crafted POST request for testing HTTP smuggling
            if payload["header"] in ["Content-Length", "Transfer-Encoding"]:
                # For CL.TE and TE.CL payloads, we need to send a specific body
                if payload["header"] == "Content-Length" and payload["value"] in ["6", "4"]:
                    body = "0\r\n\r\n"  # Request smuggling body for CL.TE attacks
                    headers = {payload["header"]: payload["value"]}
                    r = req_session.post(target_url, headers=headers, data=body, timeout=5, allow_redirects=False)
                else:
                    headers = {payload["header"]: payload["value"]}
                    r = req_session.get(target_url, headers=headers, timeout=5, allow_redirects=False)
                    
                # Look for anomalies
                status_changed = r.status_code != baseline_status
                timing_anomaly = hasattr(r, 'elapsed') and r.elapsed.total_seconds() > 3  # Unusually long response
                
                if status_changed or timing_anomaly:
                    findings.append(f"Potential HTTP Smuggling vulnerability: {payload['header']}:{payload['value']} - Response anomaly detected")
            else:
                # For other headers, just see if they cause unusual behavior
                r = req_session.get(target_url, headers={payload["header"]: payload["value"]}, timeout=5)
                if r.status_code != baseline_status or abs(len(r.text) - baseline_length) > 100:
                    findings.append(f"Unusual response with {payload['header']}:{payload['value']} - Potential HTTP Smuggling")
                    
        except Exception as e:
            # Timeout or connection error can indicate a successful HTTP smuggling attempt
            findings.append(f"Connection error with {payload['header']}:{payload['value']} - Potential HTTP Smuggling: {str(e)}")
            continue
            
    # Test for H2.CL desync (HTTP/2 specific)
    try:
        headers = {
            "Content-Length": "0",
            "Host": "example.com",
            "Upgrade": "h2c"  # Try to upgrade to HTTP/2 cleartext
        }
        r = req_session.post(target_url, headers=headers, timeout=5)
        
        if "Upgrade" in r.headers.get("Connection", "") or r.status_code == 101:
            findings.append("Potential HTTP/2 desync vulnerability - server attempted HTTP/2 upgrade")
    except Exception:
        pass
        
    return findings
