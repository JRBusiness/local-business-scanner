import requests
from . import get_session

# Common sensitive paths to try traversal for
SENSITIVE_PATHS = [
    "/etc/passwd",
    "/proc/self/environ",
    "C:/Windows/win.ini",
    "/var/log/apache2/access.log",
    "../../../.env",
    "../../.git/config"
]

def check(base_url, session=None):
    req_session = get_session(session)
    findings = []
    
    for path in SENSITIVE_PATHS:
        try:
            r = req_session.get(base_url.rstrip("/") + path, timeout=5)
            
            # Look for specific patterns that would indicate successful traversal
            if (path == "/etc/passwd" and "root:x:" in r.text) or \
               (path == "C:/Windows/win.ini" and ("fonts" in r.text.lower() or "extension" in r.text.lower())) or \
               (path == "../../.git/config" and "[core]" in r.text) or \
               (path == "../../../.env" and ("APP_" in r.text or "DB_" in r.text)):
                findings.append(f"Directory traversal found: {path}")
        except Exception:
            continue
    
    return findings
