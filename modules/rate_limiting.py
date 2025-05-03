import requests
import time
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Try sending 10 rapid requests
    try:
        response_times = []
        for i in range(10):
            start_time = time.time()
            r = req_session.get(url, timeout=3)
            end_time = time.time()
            response_times.append(end_time - start_time)
            
            # If we get rate limited, we'll record it and stop
            if r.status_code == 429:
                findings.append(f"Rate limiting detected after {i+1} requests")
                break
                
        # No rate limiting detected after 10 requests
        if len(findings) == 0:
            # Look for dramatic slowdown which might indicate throttling
            if max(response_times) > 3 * min(response_times):
                findings.append("Possible request throttling detected (response time increased significantly)")
            else:
                findings.append("No rate limiting detected after 10 rapid requests")
    except Exception:
        pass
        
    return findings
