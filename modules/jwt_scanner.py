import json
import base64
import re
from datetime import datetime
import time
import urllib.parse
import hashlib
import hmac

# JWT constants and common secrets
COMMON_JWT_SECRETS = [
    "secret", "password", "jwt_secret", "jwt-secret", "jwtSecret", 
    "key", "private_key", "api_key", "apiKey", "app_secret", 
    "appSecret", "client_secret", "clientSecret", "secret_key", "secretKey",
    "SECRET_KEY", "JWT_SECRET", "API_KEY", "APP_SECRET", "PRIVATE_KEY"
]

JWT_ALG_NONE_PAYLOADS = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",              # {"alg":"none","typ":"JWT"}
    "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0",              # {"alg":"None","typ":"JWT"}
    "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0",              # {"alg":"nOnE","typ":"JWT"}
    "eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0",              # {"alg":"none","typ":"JWS"}
]

JWT_HEADER_PATTERNS = {
    "kid_sql_injection": r'"kid"\s*:\s*"[^"]*\s*(and|or|union|select|from|where|group|order|having|limit)\s+',
    "jku_url_injection": r'"jku"\s*:\s*"(https?:\/\/|file:\/\/|\/\/)[^"]*"',
    "x5u_url_injection": r'"x5u"\s*:\s*"(https?:\/\/|file:\/\/|\/\/)[^"]*"',
}

def parse_jwt(token):
    """Parse and decode JWT token parts without verification"""
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None

    try:
        # Fix padding for base64url decoding
        def fix_padding(encoded):
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            return encoded

        # Decode header and payload
        header_json = base64.urlsafe_b64decode(fix_padding(parts[0])).decode('utf-8')
        payload_json = base64.urlsafe_b64decode(fix_padding(parts[1])).decode('utf-8')

        header = json.loads(header_json)
        payload = json.loads(payload_json)
        signature = parts[2]

        return header, payload, signature
    except Exception as e:
        print(f"Error parsing JWT: {str(e)}")
        return None, None, None

def check_jwt_expiration(payload):
    """Check if JWT is expired or has suspicious validity period"""
    issues = []
    current_time = int(time.time())
    
    if 'exp' not in payload:
        issues.append("JWT missing expiration claim (exp)")
    else:
        exp_time = payload['exp']
        if isinstance(exp_time, int):
            if exp_time < current_time:
                issues.append("JWT is expired")
            elif exp_time > current_time + 31536000:  # 1 year
                issues.append(f"JWT has unusually long expiration time (expires in {(exp_time - current_time) // 86400} days)")
    
    if 'iat' in payload and 'exp' in payload:
        if isinstance(payload['iat'], int) and isinstance(payload['exp'], int):
            lifetime = payload['exp'] - payload['iat']
            if lifetime > 604800:  # 7 days
                issues.append(f"JWT has long lifetime: {lifetime // 3600} hours")
    
    if 'nbf' not in payload:
        issues.append("JWT missing not-before claim (nbf)")
    
    return issues

def check_weak_algorithm(header):
    """Check for weak or vulnerable signature algorithms"""
    issues = []
    algorithm = header.get('alg', '').lower()
    
    if algorithm == 'none':
        issues.append("JWT uses 'none' algorithm (authentication bypass)")
    elif algorithm in ['hs256', 'hs384', 'hs512']:
        issues.append(f"JWT uses {algorithm.upper()} algorithm (potentially vulnerable to key confusion if public key also accepted)")
    elif algorithm == 'rs256':
        # RS256 is generally good, but worth noting for key confusion testing
        pass
    elif algorithm in ['es256', 'es384', 'es512']:
        # ECDSA algorithms are generally secure
        pass
    elif algorithm.startswith('ps'):
        # PSS algorithms are generally secure
        pass
    else:
        issues.append(f"JWT uses uncommon or unsupported algorithm: {algorithm}")
    
    return issues

def check_sensitive_data(payload):
    """Check if JWT payload contains sensitive information"""
    issues = []
    sensitive_fields = [
        'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'token', 
        'ssn', 'social_security', 'credit_card', 'creditcard', 'cc', 'secret_question',
        'private', 'access_key', 'auth', 'credentials'
    ]
    
    for key in payload.keys():
        for field in sensitive_fields:
            if field in key.lower():
                issues.append(f"JWT contains potentially sensitive data in claim: {key}")
                break
    
    # Check for email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    for key, value in payload.items():
        if isinstance(value, str) and re.search(email_pattern, value):
            issues.append(f"JWT contains email address in claim: {key}")
    
    return issues

def check_header_vulnerabilities(header):
    """Check JWT header for potential vulnerabilities"""
    issues = []
    
    # Check for kid parameter that might be used for injection
    if 'kid' in header:
        kid_value = header['kid']
        
        if '../' in kid_value or './' in kid_value:
            issues.append(f"JWT contains potential directory traversal in kid parameter: {kid_value}")
        
        if re.search(r'[\'";]', kid_value):
            issues.append(f"JWT contains suspicious characters in kid parameter that might enable SQL injection: {kid_value}")
    
    # Check for jku or x5u which might enable URL-based attacks
    for url_param in ['jku', 'x5u']:
        if url_param in header:
            issues.append(f"JWT uses {url_param} header which may enable URL-based attacks: {header[url_param]}")
    
    return issues

def test_jwt_none_algorithm(token, session, url):
    """Test if the server accepts 'none' algorithm"""
    original_header, payload, _ = parse_jwt(token)
    if not original_header or not payload:
        return []
    
    issues = []
    
    # Create tokens with 'none' algorithm in different case variations
    test_results = []
    for header_base64 in JWT_ALG_NONE_PAYLOADS:
        # Get original payload part
        parts = token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            
            # Create 'none' algorithm token variations
            none_token_empty = f"{header_base64}.{payload_part}."
            none_token_original = f"{header_base64}.{payload_part}.{parts[2]}"
            
            # Test both variations
            for test_token in [none_token_empty, none_token_original]:
                # Here we would make a request with the token and check if accepted
                # This is a placeholder as actual implementation depends on where the token is used
                # (header, cookie, request parameter)
                pass
    
    return issues

def test_algorithm_confusion(token, session, url):
    """Test for algorithm confusion vulnerabilities (e.g., RS256 to HS256)"""
    header, payload, signature = parse_jwt(token)
    if not header or not payload:
        return []
    
    issues = []
    
    # Only test if using asymmetric algorithm
    if header.get('alg', '').upper() in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']:
        # Create a token with symmetric algorithm instead
        symmetric_alg = 'HS256'
        
        # Here we would modify the token and test if the server accepts it
        # In practice, we would need to sign with various keys, including the public key
        # This is a placeholder as actual implementation requires key material
        
        # placeholder for full implementation
        pass
    
    return issues

def check(session, url, soup, response, config):
    """
    Check for JWT tokens in cookies, headers, and HTML
    
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
    jwt_tokens = []
    
    # Look for JWT in cookies
    for cookie in response.cookies:
        if check_if_jwt(cookie.value):
            jwt_tokens.append({
                'token': cookie.value,
                'location': f"Cookie: {cookie.name}",
                'source': 'response_cookie'
            })
    
    # Look for JWT in authorization header
    auth_header = response.request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        if check_if_jwt(token):
            jwt_tokens.append({
                'token': token,
                'location': 'Authorization: Bearer',
                'source': 'request_header'
            })
    
    # Look for JWT patterns in HTML
    html_content = response.text
    possible_jwt_pattern = r'ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    for match in re.finditer(possible_jwt_pattern, html_content):
        potential_jwt = match.group(0)
        if check_if_jwt(potential_jwt):
            # Find surrounding context to determine location
            start = max(0, match.start() - 50)
            end = min(len(html_content), match.end() + 50)
            context = html_content[start:end]
            
            # Try to determine where the token appears
            location = "HTML body"
            if 'localStorage.setItem' in context or 'sessionStorage.setItem' in context:
                location = "Browser storage (localStorage/sessionStorage)"
            elif '<input' in context:
                location = "HTML input field"
            elif 'var' in context or 'const' in context or 'let' in context:
                location = "JavaScript variable"
            
            jwt_tokens.append({
                'token': potential_jwt,
                'location': location,
                'source': 'html_content'
            })
    
    # Analyze found tokens
    for jwt_info in jwt_tokens:
        token = jwt_info['token']
        header, payload, signature = parse_jwt(token)
        
        if not header or not payload:
            findings.append(f"Found potential JWT token in {jwt_info['location']} but couldn't parse it")
            continue
        
        token_issues = []
        
        # Check header
        token_issues.extend(check_weak_algorithm(header))
        token_issues.extend(check_header_vulnerabilities(header))
        
        # Check payload
        token_issues.extend(check_jwt_expiration(payload))
        token_issues.extend(check_sensitive_data(payload))
        
        # Additional tests
        # Note: These are theoretical and would require actual testing with modified tokens
        if header.get('alg', '').lower() == 'none' or 'none' in token_issues:
            token_issues.append("Recommendation: Test for 'none' algorithm vulnerability (auth bypass)")
        
        if header.get('alg', '').upper().startswith('RS'):
            token_issues.append("Recommendation: Test for algorithm confusion vulnerability (RS256 to HS256)")
        
        if token_issues:
            findings.append(f"JWT token issues in {jwt_info['location']}:")
            for issue in token_issues:
                findings.append(f"- {issue}")
            
            # Show simplified token information
            findings.append(f"- Token algorithm: {header.get('alg', 'unknown')}")
            findings.append(f"- Token type: {header.get('typ', 'unknown')}")
            
            # Show selected payload fields
            safe_fields = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']
            payload_info = []
            for field in safe_fields:
                if field in payload:
                    # Format timestamps as dates
                    if field in ['exp', 'nbf', 'iat'] and isinstance(payload[field], int):
                        try:
                            dt = datetime.fromtimestamp(payload[field])
                            payload_info.append(f"{field}: {payload[field]} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
                        except:
                            payload_info.append(f"{field}: {payload[field]}")
                    else:
                        payload_info.append(f"{field}: {payload[field]}")
            
            if payload_info:
                findings.append("- Payload information:")
                for info in payload_info:
                    findings.append(f"  * {info}")
    
    if not findings:
        findings.append("No JWT tokens found or no security issues detected in JWT tokens")
    
    return findings

def check_if_jwt(token_str):
    """Check if a string appears to be a JWT token"""
    if not isinstance(token_str, str):
        return False
    
    # Check basic JWT structure: 3 parts separated by dots
    parts = token_str.split('.')
    if len(parts) != 3:
        return False
    
    # Check that first two parts are valid base64url
    try:
        for i in range(2):
            # Add padding if needed
            padded = parts[i] + '=' * (4 - len(parts[i]) % 4) if len(parts[i]) % 4 else parts[i]
            base64.urlsafe_b64decode(padded)
        return True
    except:
        return False 