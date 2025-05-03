
import socket

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443]

def check(domain):
    findings = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((domain, port))
            if result == 0:
                findings.append(f"Open Port Detected: {port}")
        except:
            continue
        finally:
            sock.close()
    return findings
