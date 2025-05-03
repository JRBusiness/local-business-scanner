import requests
from . import get_session

PROTECTED_PATHS = [
    "/admin", "/dashboard", "/settings", "/user/edit", "/account", "/config", "/api/users", "/control",
    "/private", "/root", "/internal", "/manage"
]

METHODS = ['GET', 'POST', 'PUT', 'DELETE']

def check(base_url, session=None):
    findings = []
    # Use the session helper
    req_session = get_session(session)
    
    for path in PROTECTED_PATHS:
        for method in METHODS:
            url = base_url.rstrip("/") + path
            try:
                response = req_session.request(method, url, timeout=5)
                if response.status_code == 200 and not any(x in response.text.lower() for x in ["login", "unauthorized", "forbidden", "error"]):
                    findings.append(f"Possible Auth Bypass: {method} {url}")
            except Exception:
                continue
    return findings
