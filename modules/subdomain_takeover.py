import requests
import re
from . import get_session

# Common takeover indicators
TAKEOVER_PATTERNS = [
    "NoSuchBucket", "There isn't a GitHub Pages site", "Heroku | No such app", "Do you want to register",
    "unclaimed", "NoSuchDomain", "This domain is available", "project not found", "Repository not found"
]

COMMON_SUBDOMAINS = [
    "blog", "dev", "staging", "test", "admin", "dashboard", "files", "cdn", "static", "old"
]

VULNERABLE_SIGNATURES = [
    {"service": "GitHub Pages", "signature": "There isn't a GitHub Pages site here"},
    {"service": "Heroku", "signature": "No such app"},
    {"service": "AWS S3", "signature": "NoSuchBucket"},
    {"service": "Shopify", "signature": "Sorry, this shop is currently unavailable"},
    {"service": "Wordpress", "signature": "Domain mapping upgrade for this domain not found"},
    {"service": "Azure", "signature": "This web app is stopped"},
]

def check(domain, session=None):
    req_session = get_session(session)
    findings = []
    subdomains = [
        f"www.{domain}", f"api.{domain}", f"blog.{domain}", 
        f"dev.{domain}", f"mail.{domain}", f"admin.{domain}"
    ]
    
    for subdomain in subdomains:
        try:
            r = req_session.get(f"https://{subdomain}", timeout=5)
            content = r.text.lower()
            
            for vuln in VULNERABLE_SIGNATURES:
                if vuln["signature"].lower() in content:
                    findings.append(f"Potential subdomain takeover: {subdomain} ({vuln['service']})")
                    break
        except Exception:
            # Connection errors might also indicate potential takeover opportunities
            pass
            
    return findings
