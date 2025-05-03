import requests
from . import get_session

# Common misconfigurations to check for
MISCONFIG_PATHS = [
    "/.git/config",
    "/.svn/entries",
    "/.env",
    "/wp-config.php.bak",
    "/config.php.old",
    "/phpinfo.php",
    "/server-status",
    "/server-info"
]

def check(base_url, session=None):
    req_session = get_session(session)
    findings = []
    
    for path in MISCONFIG_PATHS:
        try:
            r = req_session.get(base_url.rstrip("/") + path, timeout=5)
            
            # Check for successful access
            if r.status_code == 200:
                # Look for specific patterns that would indicate successful access
                if (path == "/.git/config" and "[core]" in r.text) or \
                   (path == "/.env" and ("APP_" in r.text or "DB_" in r.text)) or \
                   (path == "/phpinfo.php" and "PHP Version" in r.text) or \
                   (path.endswith(".bak") or path.endswith(".old")):
                    findings.append(f"Misconfiguration found: {path}")
        except Exception:
            continue
    
    return findings
