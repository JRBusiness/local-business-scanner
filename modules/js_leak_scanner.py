import requests
import re
from . import get_session

SENSITIVE_PATTERNS = [
    r'api[-_]key\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]',
    r'secret\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]',
    r'password\s*[=:]\s*[\'"`]([^\'"`]{6,})[\'"`]',
    r'username\s*[=:]\s*[\'"`]([^\'"`]{4,})[\'"`]',
    r'aws[-_]access[-_]key[=:]\s*[\'"`]([^\'"`]{16,})[\'"`]'
]

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    try:
        r = req_session.get(url, timeout=5)
        
        # Look for JavaScript files
        js_files = set()
        
        # Extract from script tags with src
        script_pattern = re.compile(r'<script[^>]+src=["\'](.*?)["\']', re.IGNORECASE)
        for src in script_pattern.findall(r.text):
            if src.endswith('.js'):
                js_files.add(src)
                
        # Check for sensitive information in the main page
        for pattern in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            for match in matches:
                findings.append(f"Sensitive information found in main page: {pattern} - {match[:10]}...")
                
        # Check each JavaScript file
        for js_file in js_files:
            # Handle relative paths
            if js_file.startswith('/'):
                js_url = url.split('://', 1)[0] + '://' + url.split('://', 1)[1].split('/', 1)[0] + js_file
            elif not js_file.startswith(('http://', 'https://')):
                js_url = url.rstrip('/') + '/' + js_file
            else:
                js_url = js_file
                
            try:
                js_response = req_session.get(js_url, timeout=5)
                for pattern in SENSITIVE_PATTERNS:
                    matches = re.findall(pattern, js_response.text, re.IGNORECASE)
                    for match in matches:
                        findings.append(f"Sensitive information found in {js_url}: {pattern} - {match[:10]}...")
            except Exception:
                continue
    except Exception:
        pass
        
    return findings
