import hashlib
import base64
import re
import requests
from bs4 import BeautifulSoup

def calculate_hash(content, algorithm='sha384'):
    """
    Calculate a hash for the given content using the specified algorithm.
    
    Args:
        content: The content to hash
        algorithm: The hash algorithm to use (sha256, sha384, sha512)
        
    Returns:
        The base64-encoded hash with algorithm prefix
    """
    if algorithm not in ['sha256', 'sha384', 'sha512']:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    if algorithm == 'sha256':
        hash_obj = hashlib.sha256()
    elif algorithm == 'sha384':
        hash_obj = hashlib.sha384()
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512()
    
    hash_obj.update(content.encode('utf-8') if isinstance(content, str) else content)
    hash_digest = hash_obj.digest()
    base64_digest = base64.b64encode(hash_digest).decode('ascii')
    
    return f"{algorithm}-{base64_digest}"

def verify_integrity(resource_url, integrity_value, session=None):
    """
    Verify if the integrity value matches the resource content.
    
    Args:
        resource_url: URL of the resource to verify
        integrity_value: The integrity value to check against
        session: Optional requests session to use
        
    Returns:
        (bool, str): Tuple of (is_valid, error_message)
    """
    if not session:
        session = requests

    try:
        response = session.get(resource_url, timeout=10)
        if response.status_code != 200:
            return False, f"Failed to fetch resource: HTTP {response.status_code}"
        
        content = response.text
        
        # Split the integrity value to get algorithm and hash
        parts = integrity_value.split('-', 1)
        if len(parts) != 2:
            return False, f"Invalid integrity format: {integrity_value}"
        
        algorithm, expected_hash = parts
        
        # Calculate hash for the fetched content
        calculated_integrity = calculate_hash(content, algorithm)
        
        return calculated_integrity == integrity_value, "Hash mismatch" if calculated_integrity != integrity_value else ""
    
    except Exception as e:
        return False, f"Error verifying integrity: {str(e)}"

def check_resource_origins(soup, domain):
    """
    Check if external scripts and styles have SRI attributes.
    
    Args:
        soup: BeautifulSoup object of the page
        domain: The domain of the current page
        
    Returns:
        List of (element, issue) tuples
    """
    issues = []
    
    # Check script tags
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = script.get('src', '')
        if src and not src.startswith(('data:', 'blob:', 'javascript:')):
            # Check if it's an external resource
            if not src.startswith(('//', 'http://', 'https://')):
                # It's a relative URL, likely from same origin
                continue
                
            src_domain = src.split('//', 1)[1].split('/', 1)[0] if '//' in src else src
            
            # If it's from a different domain, it should have integrity
            if domain not in src_domain and src_domain not in domain:
                integrity = script.get('integrity')
                if not integrity:
                    issues.append((script, f"External script from {src_domain} lacks SRI attributes"))
                elif not integrity.startswith(('sha256-', 'sha384-', 'sha512-')):
                    issues.append((script, f"Invalid integrity format for script from {src_domain}: {integrity}"))
    
    # Check link tags (for stylesheets)
    links = soup.find_all('link', rel='stylesheet')
    for link in links:
        href = link.get('href', '')
        if href and not href.startswith(('data:', 'blob:')):
            # Check if it's an external resource
            if not href.startswith(('//', 'http://', 'https://')):
                # It's a relative URL, likely from same origin
                continue
                
            href_domain = href.split('//', 1)[1].split('/', 1)[0] if '//' in href else href
            
            # If it's from a different domain, it should have integrity
            if domain not in href_domain and href_domain not in domain:
                integrity = link.get('integrity')
                if not integrity:
                    issues.append((link, f"External stylesheet from {href_domain} lacks SRI attributes"))
                elif not integrity.startswith(('sha256-', 'sha384-', 'sha512-')):
                    issues.append((link, f"Invalid integrity format for stylesheet from {href_domain}: {integrity}"))
    
    return issues

def check_resource_integrity(soup, session):
    """
    Check if resources with integrity attributes have matching content.
    
    Args:
        soup: BeautifulSoup object of the page
        session: Session object for making requests
        
    Returns:
        List of (element, issue) tuples
    """
    issues = []
    
    # Check script tags with integrity
    scripts = soup.find_all('script', src=True, integrity=True)
    for script in scripts:
        src = script.get('src', '')
        integrity = script.get('integrity', '')
        
        # Make sure the src is an absolute URL
        if src.startswith('//'):
            src = 'https:' + src
        elif not src.startswith(('http://', 'https://')):
            # Skip relative URLs for now
            continue
            
        # Verify the integrity
        is_valid, error = verify_integrity(src, integrity, session)
        if not is_valid:
            issues.append((script, f"Integrity verification failed for {src}: {error}"))
    
    # Check link tags with integrity
    links = soup.find_all('link', rel='stylesheet', integrity=True)
    for link in links:
        href = link.get('href', '')
        integrity = link.get('integrity', '')
        
        # Make sure the href is an absolute URL
        if href.startswith('//'):
            href = 'https:' + href
        elif not href.startswith(('http://', 'https://')):
            # Skip relative URLs for now
            continue
            
        # Verify the integrity
        is_valid, error = verify_integrity(href, integrity, session)
        if not is_valid:
            issues.append((link, f"Integrity verification failed for {href}: {error}"))
    
    return issues

def check_cdn_usage(soup):
    """
    Check if common CDNs are used and if SRI is implemented.
    
    Args:
        soup: BeautifulSoup object of the page
        
    Returns:
        List of findings
    """
    findings = []
    
    # Common CDNs that support SRI
    common_cdns = [
        'cdn.jsdelivr.net',
        'unpkg.com',
        'cdnjs.cloudflare.com',
        'ajax.googleapis.com',
        'code.jquery.com',
        'stackpath.bootstrapcdn.com',
        'maxcdn.bootstrapcdn.com'
    ]
    
    # Check script tags
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = script.get('src', '')
        
        for cdn in common_cdns:
            if cdn in src:
                integrity = script.get('integrity')
                if not integrity:
                    findings.append(f"Script from CDN {cdn} lacks SRI: {src}")
                break
    
    # Check link tags
    links = soup.find_all('link', rel='stylesheet')
    for link in links:
        href = link.get('href', '')
        
        for cdn in common_cdns:
            if cdn in href:
                integrity = link.get('integrity')
                if not integrity:
                    findings.append(f"Stylesheet from CDN {cdn} lacks SRI: {href}")
                break
    
    return findings

def check_sri_policy(response):
    """
    Check if the page has a Require-SRI-For header.
    
    Args:
        response: HTTP response object
        
    Returns:
        List of findings
    """
    findings = []
    
    # Check for Require-SRI-For header (part of CSP)
    csp_header = None
    if 'Content-Security-Policy' in response.headers:
        csp_header = response.headers['Content-Security-Policy']
    elif 'Content-Security-Policy-Report-Only' in response.headers:
        csp_header = response.headers['Content-Security-Policy-Report-Only']
    
    if csp_header:
        # Check for require-sri-for directive
        require_sri_match = re.search(r'require-sri-for\s+([^;]+)', csp_header)
        if require_sri_match:
            sri_policy = require_sri_match.group(1).strip()
            findings.append(f"SRI policy found: require-sri-for {sri_policy}")
        else:
            findings.append("No SRI policy (require-sri-for) found in Content-Security-Policy")
    else:
        findings.append("No Content-Security-Policy header found with SRI requirements")
    
    return findings

def check(session, url, soup, response, config):
    """
    Check for Subresource Integrity (SRI) implementation and issues.
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
    
    Returns:
        List of findings
    """
    findings = []
    
    # Extract domain from URL
    parsed_url = url.split('//', 1)[1].split('/', 1)[0] if '//' in url else url.split('/', 1)[0]
    domain = parsed_url
    
    # Check for resources without SRI
    resource_issues = check_resource_origins(soup, domain)
    if resource_issues:
        findings.append(f"Found {len(resource_issues)} resources lacking SRI attributes:")
        for _, issue in resource_issues:
            findings.append(f"- {issue}")
    else:
        findings.append("All external resources have SRI attributes applied")
    
    # Check for resources with incorrect SRI values
    integrity_issues = check_resource_integrity(soup, session)
    if integrity_issues:
        findings.append(f"Found {len(integrity_issues)} resources with SRI integrity issues:")
        for _, issue in integrity_issues:
            findings.append(f"- {issue}")
    
    # Check CDN usage
    cdn_findings = check_cdn_usage(soup)
    if cdn_findings:
        findings.append(f"Found {len(cdn_findings)} CDN resources without SRI:")
        for finding in cdn_findings:
            findings.append(f"- {finding}")
    
    # Check SRI policy
    policy_findings = check_sri_policy(response)
    findings.extend(policy_findings)
    
    # If no findings, add a general note
    if len(findings) == 1 and "All external resources have SRI attributes applied" in findings[0]:
        findings.append("Subresource Integrity is properly implemented")
    
    return findings 