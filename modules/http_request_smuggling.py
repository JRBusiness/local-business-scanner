# Http Request Smuggling.Py Module

import requests
import time
from . import get_session

# Advanced HTTP Request Smuggling detection payloads
HRS_PAYLOADS = [
    # CL.TE: Content-Length header understood by front-end, Transfer-Encoding by back-end
    {
        "name": "CL.TE basic",
        "headers": {
            "Content-Length": "4",
            "Transfer-Encoding": "chunked"
        },
        "body": "1\r\nZ\r\nQ",  # Valid chunked encoding that will be processed differently
        "method": "POST"
    },
    
    # TE.CL: Transfer-Encoding header understood by front-end, Content-Length by back-end
    {
        "name": "TE.CL basic",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked"
        },
        "body": "0\r\n\r\nX",  # Chunked message ends before the X, but will be included with CL
        "method": "POST"
    },
    
    # TE.TE: Different servers interpret Transfer-Encoding differently
    {
        "name": "TE.TE obfuscation 1",
        "headers": {
            "Transfer-Encoding": "xchunked"  # Some servers ignore invalid TE values
        },
        "body": "0\r\n\r\n",
        "method": "POST"
    },
    {
        "name": "TE.TE obfuscation 2",
        "headers": {
            "Transfer-Encoding": "chunked",
            "X-Transfer-Encoding": "chunked"  # Duplicate with a different name
        },
        "body": "0\r\n\r\n",
        "method": "POST"
    },
    {
        "name": "TE.TE obfuscation 3",
        "headers": {
            "Transfer-Encoding": " chunked"  # Space before value
        },
        "body": "0\r\n\r\n",
        "method": "POST"
    },
    {
        "name": "TE.TE obfuscation 4",
        "headers": {
            "Transfer-Encoding": "chunked\r\nContent-Length: 5"  # Header value injection
        },
        "body": "0\r\n\r\n",
        "method": "POST"
    },
    
    # Request timeout differentiation test
    {
        "name": "Timeout differentiation",
        "headers": {
            "Content-Length": "500"  # We'll only send a small body, should hang waiting for more
        },
        "body": "X",
        "method": "POST"
    }
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Get baseline response for comparison
    try:
        baseline_start = time.time()
        r_baseline = req_session.get(target_url, timeout=5)
        baseline_duration = time.time() - baseline_start
        baseline_status = r_baseline.status_code
        baseline_length = len(r_baseline.text)
    except Exception:
        return findings
        
    # Test each smuggling payload
    for payload in HRS_PAYLOADS:
        try:
            start_time = time.time()
            
            # Send the request based on the payload method
            if payload["method"] == "POST":
                r = req_session.post(
                    target_url, 
                    headers=payload["headers"], 
                    data=payload.get("body", ""), 
                    timeout=3,  # Shorter timeout to detect hanging connections
                    allow_redirects=False
                )
            else:
                r = req_session.get(
                    target_url, 
                    headers=payload["headers"], 
                    timeout=3,
                    allow_redirects=False
                )
                
            duration = time.time() - start_time
            
            # Check for anomalies that might indicate request smuggling
            # 1. Status code changes
            if r.status_code != baseline_status:
                findings.append(f"Potential HTTP Request Smuggling ({payload['name']}): Status code changed from {baseline_status} to {r.status_code}")
                
            # 2. Significant response size changes
            if r.text and abs(len(r.text) - baseline_length) > baseline_length * 0.5:
                findings.append(f"Potential HTTP Request Smuggling ({payload['name']}): Response size changed significantly")
                
            # 3. Timing anomalies (taking much longer or shorter than baseline)
            if duration > baseline_duration * 3 or duration < baseline_duration * 0.2:
                findings.append(f"Potential HTTP Request Smuggling ({payload['name']}): Response time anomaly ({duration:.2f}s vs {baseline_duration:.2f}s baseline)")
                
        except requests.exceptions.Timeout:
            # Timeout can indicate a successful attack for certain payloads
            if payload["name"] == "Timeout differentiation":
                findings.append(f"Potential HTTP Request Smuggling ({payload['name']}): Request timed out as expected")
        except Exception as e:
            # Unusual errors might indicate successful smuggling
            if "Unexpected EOF" in str(e) or "connection" in str(e).lower():
                findings.append(f"Potential HTTP Request Smuggling ({payload['name']}): Connection error occurred - {str(e)}")
            continue
            
    return findings
