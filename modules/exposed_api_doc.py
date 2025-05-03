
import requests

DOC_PATHS = [
    "/swagger", "/swagger.json", "/api-docs", "/v3/api-docs", "/docs", "/openapi.json"
]

def check(base_url):
    findings = []
    for path in DOC_PATHS:
        try:
            r = requests.get(base_url.rstrip("/") + path, timeout=5)
            if r.status_code == 200 and any(x in r.text.lower() for x in ["openapi", "swagger", "info", "paths"]):
                findings.append(f"Exposed API Documentation: {base_url.rstrip('/') + path}")
        except Exception:
            continue
    return findings
