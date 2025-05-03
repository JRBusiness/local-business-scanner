import json
import re
import urllib.parse
from urllib.parse import urlparse
from collections import defaultdict

# CSP directives and their descriptions
CSP_DIRECTIVES = {
    'default-src': 'Default policy for loading content such as JavaScript, Images, CSS, Fonts, etc',
    'script-src': 'Defines valid sources of JavaScript',
    'style-src': 'Defines valid sources of stylesheets or CSS',
    'img-src': 'Defines valid sources of images',
    'connect-src': 'Defines valid sources for fetch, WebSocket, and EventSource',
    'font-src': 'Defines valid sources of fonts',
    'object-src': 'Defines valid sources of plugins, e.g. <object>, <embed> or <applet>',
    'media-src': 'Defines valid sources of audio and video, e.g. <audio> and <video>',
    'frame-src': 'Defines valid sources for loading frames',
    'frame-ancestors': 'Defines valid sources for embedding the resource using frames',
    'worker-src': 'Defines valid sources for Worker, SharedWorker, or ServiceWorker scripts',
    'child-src': 'Defines valid sources for web workers and nested browsing contexts like frames',
    'form-action': 'Defines valid sources that can be used as a HTML form action',
    'base-uri': 'Defines allowed URLs which can be used in a document\'s <base> element',
    'manifest-src': 'Defines valid sources of application manifest files',
    'report-uri': 'Instructs the browser to POST reports of policy failures to this URI (deprecated)',
    'report-to': 'Instructs the browser to POST reports of policy failures to this URI (replacement for report-uri)',
    'upgrade-insecure-requests': 'Instructs browsers to treat all insecure URLs as though they have been replaced with secure URLs',
    'block-all-mixed-content': 'Prevents loading any assets using HTTP when the page is loaded using HTTPS',
    'require-sri-for': 'Requires the use of SRI for scripts or styles on the page',
    'trusted-types': 'Defines valid sources for trusted types',
    'sandbox': 'Defines valid sources for sandboxed iframes'
}

# Risky CSP values
RISKY_CSP_VALUES = {
    'unsafe-inline': 'Allows inline JavaScript or CSS (risky)',
    'unsafe-eval': 'Allows the use of eval() and similar methods (risky)',
    'data:': 'Allows loading resources from data: URIs (potentially risky)',
    'blob:': 'Allows loading resources from blob: URIs',
    'filesystem:': 'Allows loading resources from the filesystem: scheme',
    'http:': 'Allows loading resources over http (non-secure)',
    '*': 'Wildcard, allows anything (very permissive)'
}

# List of common CSP bypasses
CSP_BYPASSES = {
    'script-src': [
        'unsafe-inline',
        'unsafe-eval',
        'data:',
        'blob:',
        'filesystem:',
        '*',
        'https:',
        'http:',
        'https://*',
        'http://*',
        'self'  # Only a bypass in certain cases
    ],
    'default-src': [
        'unsafe-inline',
        'unsafe-eval',
        'data:',
        'blob:',
        '*',
        'https:',
        'http:',
        'https://*',
        'http://*'
    ],
    'object-src': [
        '*',
        'https:',
        'http:',
        'data:'
    ],
    'base-uri': [
        '*',
        'https:',
        'http:'
    ],
    'frame-ancestors': [
        '*',
        'https:',
        'http:'
    ],
    'connect-src': [
        '*',
        'https:',
        'http:',
        'ws:',
        'wss:'
    ]
}

# Dangerous keywords that might indicate unsafe domains in CSP
DANGEROUS_DOMAINS = [
    'jsdelivr.net',
    'unpkg.com',
    'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com',
    'code.jquery.com',
    'ajax.googleapis.com',
    'cdn.rawgit.com',
    'rawgit.com',
    'raw.githubusercontent.com',
    'pastebin.com',
    'jsfiddle.net',
    'github.io',
    'codepen.io',
    's3.amazonaws.com',
    'storage.googleapis.com',
    'jsbin.com',
    'bootstrapcdn.com',
    'fontawesome.com',
    'cloudfront.net'
]

# CSP directive types
CSP_DIRECTIVES_TYPES = [
    'default-src',
    'script-src',
    'style-src',
    'img-src',
    'connect-src',
    'font-src',
    'object-src',
    'media-src',
    'frame-src',
    'frame-ancestors',
    'worker-src',
    'manifest-src',
    'form-action',
    'base-uri',
    'upgrade-insecure-requests',
    'block-all-mixed-content',
    'require-sri-for',
    'trusted-types',
    'sandbox'
]

# Unsafe CSP values
UNSAFE_VALUES = {
    'unsafe-inline': "Allows execution of inline scripts/styles, negating XSS protections",
    'unsafe-eval': "Allows use of eval() and similar functions, increasing XSS risk",
    'unsafe-hashes': "Less secure than nonces or hashes, can weaken XSS protection",
    'http:': "Allows loading resources over insecure HTTP connections",
    'data:': "Allows potentially dangerous data: URIs which can contain executable code",
    'blob:': "Allows blob: URIs which can contain executable code",
    'wasm-unsafe-eval': "Allows compilation of WebAssembly modules, which can be security risk"
}

# Wildcard sources
WILDCARD_SOURCES = [
    '*',
    'https:',
    'http:'
]

# CSP issues and their descriptions
CSP_ISSUES = {
    'missing': {
        'description': 'Content-Security-Policy header is missing',
        'severity': 'HIGH',
        'recommendation': 'Implement a Content Security Policy to protect against XSS attacks',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
    },
    'report_only': {
        'description': 'Using Content-Security-Policy-Report-Only',
        'severity': 'MEDIUM',
        'recommendation': 'While reporting is good, it does not actually block violations',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only'
    },
    'wildcard_default_src': {
        'description': 'default-src uses a wildcard',
        'severity': 'HIGH',
        'recommendation': 'Avoid wildcards in default-src; explicitly define trusted sources',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src'
    },
    'unsafe_inline': {
        'description': 'unsafe-inline directive found',
        'severity': 'HIGH',
        'recommendation': 'Replace unsafe-inline with nonces or hashes for scripts and styles',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'
    },
    'unsafe_eval': {
        'description': 'unsafe-eval directive found',
        'severity': 'HIGH',
        'recommendation': 'Avoid using eval() or unsafe-eval in your CSP',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'
    },
    'wildcard_script_src': {
        'description': 'script-src uses a wildcard',
        'severity': 'HIGH',
        'recommendation': 'Explicitly define trusted script sources instead of using wildcards',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'
    },
    'missing_script_src': {
        'description': 'script-src directive is missing',
        'severity': 'MEDIUM',
        'recommendation': 'Define script-src to control JavaScript execution sources',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'
    },
    'missing_object_src': {
        'description': 'object-src directive is missing',
        'severity': 'MEDIUM',
        'recommendation': "Define object-src to prevent embedding of potentially harmful plugins",
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src'
    },
    'missing_base_uri': {
        'description': 'base-uri directive is missing',
        'severity': 'MEDIUM',
        'recommendation': "Define base-uri to prevent changing the document's base URL",
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri'
    },
    'missing_frame_ancestors': {
        'description': 'frame-ancestors directive is missing',
        'severity': 'MEDIUM',
        'recommendation': 'Define frame-ancestors to protect against clickjacking attacks',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'
    },
    'weak_frame_src': {
        'description': 'frame-src uses a wildcard or is missing',
        'severity': 'MEDIUM',
        'recommendation': 'Define frame-src to control which URLs can be loaded in frames',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src'
    },
    'data_img_src': {
        'description': 'img-src allows data: URLs',
        'severity': 'LOW',
        'recommendation': 'Consider restricting data: URLs in img-src if possible',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/img-src'
    },
    'missing_upgrade_insecure': {
        'description': 'upgrade-insecure-requests directive is missing',
        'severity': 'LOW',
        'recommendation': 'Add upgrade-insecure-requests to automatically upgrade HTTP requests to HTTPS',
        'info_link': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests'
    }
}

# Parse CSP header
def parse_csp(csp_string):
    """Parse a CSP header string into a dictionary of directives and their values."""
    if not csp_string:
        return {}
    
    csp_dict = defaultdict(list)
    
    # Split the CSP string into directive blocks
    for directive_block in csp_string.split(';'):
        if not directive_block.strip():
            continue
            
        parts = directive_block.strip().split()
        if not parts:
            continue
            
        # The first part is the directive name
        directive_name = parts[0].lower()
        
        # The rest are the values
        values = parts[1:]
        csp_dict[directive_name].extend(values)
    
    return csp_dict

def check_missing_directives(csp_dict):
    """Check for missing critical directives in CSP."""
    issues = []
    
    # Critical directives that should generally be present
    critical_directives = [
        'default-src',
        'script-src',
        'object-src',
        'base-uri',
        'frame-ancestors'
    ]
    
    # Check if 'default-src' is specified, if not, check if the other critical 
    # fetch directives are specified instead
    if 'default-src' not in csp_dict:
        fetch_directives = [
            'script-src', 'style-src', 'img-src', 'connect-src', 
            'font-src', 'object-src', 'media-src', 'frame-src'
        ]
        missing_fetch = [d for d in fetch_directives if d not in csp_dict]
        if missing_fetch:
            issues.append(f"Missing 'default-src' and the following fetch directives: {', '.join(missing_fetch)}")
    
    # Check for other critical directives
    for directive in critical_directives:
        if directive != 'default-src' and directive not in csp_dict:
            issues.append(f"Missing critical directive: '{directive}'")
    
    return issues

def check_risky_values(csp_dict):
    """Check for risky values in CSP directives."""
    issues = []
    
    for directive, values in csp_dict.items():
        for value in values:
            for risky_value, description in RISKY_CSP_VALUES.items():
                if value == risky_value:
                    issues.append(f"Risky value '{value}' in {directive}: {description}")
                elif risky_value == '*' and value.endswith('*'):
                    # Check for wildcard subdomains
                    if value != '*' and '*.' in value:
                        issues.append(f"Wildcard subdomain in {directive}: '{value}' may be overly permissive")
    
    return issues

def check_deprecated_directives(csp_dict):
    """Check for deprecated directives in CSP."""
    issues = []
    
    deprecated_directives = {
        'report-uri': 'Use report-to instead',
        'child-src': 'Use frame-src and worker-src instead'
    }
    
    for directive in csp_dict:
        if directive in deprecated_directives:
            issues.append(f"Deprecated directive: '{directive}'. {deprecated_directives[directive]}")
    
    return issues

def check_weak_configuration(csp_dict):
    """Check for weak CSP configurations."""
    issues = []
    
    # Check if object-src is not restricted
    if 'object-src' in csp_dict:
        values = csp_dict['object-src']
        if not values or '*' in values or "'" in ''.join(values):
            issues.append("object-src directive is not properly restricted")
    
    # Check if default-src is too permissive
    if 'default-src' in csp_dict:
        default_values = csp_dict['default-src']
        if '*' in default_values:
            issues.append("default-src is set to wildcard '*' which is too permissive")
    
    # Check if script-src allows unsafe practices
    if 'script-src' in csp_dict:
        script_values = csp_dict['script-src']
        if "'unsafe-inline'" in script_values or "'unsafe-eval'" in script_values:
            issues.append("script-src allows unsafe JavaScript execution methods")
    
    # Check if style-src allows unsafe practices
    if 'style-src' in csp_dict:
        style_values = csp_dict['style-src']
        if "'unsafe-inline'" in style_values:
            issues.append("style-src allows unsafe inline CSS")
    
    return issues

def check_reporting_configuration(csp_dict):
    """Check for issues with the reporting configuration."""
    issues = []
    
    # Check if both report-uri and report-to are specified
    if 'report-uri' in csp_dict and 'report-to' in csp_dict:
        issues.append("Both report-uri and report-to are specified. Some browsers will ignore report-uri.")
    
    # Check if report-uri contains a valid URL
    if 'report-uri' in csp_dict and csp_dict['report-uri']:
        uri = csp_dict['report-uri'][0]
        if not uri.startswith(('http://', 'https://')):
            issues.append(f"report-uri may contain an invalid URL: {uri}")
    
    # Check if report-to contains a valid endpoint name
    if 'report-to' in csp_dict and not csp_dict['report-to']:
        issues.append("report-to directive is empty")
    
    return issues

def check_implementation_errors(csp_string):
    """Check for common implementation errors in CSP header."""
    issues = []
    
    # Check for duplicate directives
    seen_directives = set()
    for directive_block in csp_string.split(';'):
        if not directive_block.strip():
            continue
            
        parts = directive_block.strip().split()
        if not parts:
            continue
            
        directive_name = parts[0].lower()
        if directive_name in seen_directives:
            issues.append(f"Duplicate directive: '{directive_name}'. Only the first instance will be used.")
        seen_directives.add(directive_name)
    
    # Check for syntax errors
    if csp_string.count("'") % 2 != 0:
        issues.append("Possible syntax error: unmatched single quote in CSP")
    
    # Check for malformed directives
    for part in csp_string.split(';'):
        part = part.strip()
        if part and len(part.split()) < 2 and part not in ['block-all-mixed-content', 'upgrade-insecure-requests']:
            issues.append(f"Malformed directive or missing values: '{part}'")
    
    return issues

def extract_csp_headers(response):
    """
    Extract CSP headers from HTTP response.
    
    Args:
        response: HTTP response object
        
    Returns:
        Dictionary of CSP headers and their values
    """
    headers = {}
    
    # Check primary CSP header
    if 'Content-Security-Policy' in response.headers:
        headers['Content-Security-Policy'] = response.headers['Content-Security-Policy']
    
    # Check report-only header
    if 'Content-Security-Policy-Report-Only' in response.headers:
        headers['Content-Security-Policy-Report-Only'] = response.headers['Content-Security-Policy-Report-Only']
    
    # Check legacy headers (though these are deprecated)
    if 'X-Content-Security-Policy' in response.headers:
        headers['X-Content-Security-Policy'] = response.headers['X-Content-Security-Policy']
    
    if 'X-WebKit-CSP' in response.headers:
        headers['X-WebKit-CSP'] = response.headers['X-WebKit-CSP']
    
    return headers

def parse_csp_policy(csp_string):
    """
    Parse CSP policy string into a structured format.
    
    Args:
        csp_string: CSP policy string
        
    Returns:
        Dictionary with directives as keys and values as lists
    """
    policy = defaultdict(list)
    
    # Remove newlines and extra whitespace
    csp_string = re.sub(r'\s+', ' ', csp_string)
    
    # Split by semicolons to get directives
    directives = csp_string.split(';')
    
    for directive in directives:
        directive = directive.strip()
        if not directive:
            continue
            
        # Split by spaces to separate directive name from values
        parts = directive.split()
        
        if not parts:
            continue
            
        directive_name = parts[0].lower()
        
        # Add all values to the directive
        values = parts[1:] if len(parts) > 1 else []
        policy[directive_name] = values
    
    return policy

def analyze_script_src(values, findings):
    """
    Analyze script-src directive values for security issues.
    
    Args:
        values: List of script-src values
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    if not values:
        findings.append("script-src directive is missing, falling back to default-src")
        return findings
    
    for value in values:
        value = value.strip("'").lower()
        
        if value == "'unsafe-inline'":
            findings.append("HIGH RISK: script-src allows 'unsafe-inline' which permits inline scripts and event handlers")
        
        elif value == "'unsafe-eval'":
            findings.append("HIGH RISK: script-src allows 'unsafe-eval' which permits the use of eval() and similar functions")
        
        elif value == "*":
            findings.append("HIGH RISK: script-src allows wildcard (*) which permits scripts from any source")
        
        elif value in ("data:", "blob:", "filesystem:"):
            findings.append(f"HIGH RISK: script-src allows {value} URI which can be used to bypass CSP")
        
        elif value in ("https:", "http:"):
            findings.append(f"HIGH RISK: script-src allows any {value} domain which significantly weakens CSP protection")
        
        # Check for potentially risky domains
        for domain in DANGEROUS_DOMAINS:
            if domain in value:
                findings.append(f"MEDIUM RISK: script-src includes potentially risky domain {value} which may be vulnerable to script injection")
    
    # Check for missing nonce or strict-dynamic
    has_nonce = any("'nonce-" in val for val in values)
    has_strict_dynamic = any("'strict-dynamic'" in val for val in values)
    
    if not has_nonce and not has_strict_dynamic and "'unsafe-inline'" in str(values):
        findings.append("IMPROVEMENT: Consider using nonces or hashes with 'strict-dynamic' instead of 'unsafe-inline'")
    
    return findings

def analyze_default_src(values, findings):
    """
    Analyze default-src directive values for security issues.
    
    Args:
        values: List of default-src values
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    if not values:
        findings.append("default-src directive is missing, each resource type will use its default behavior")
        return findings
    
    for value in values:
        value = value.strip("'").lower()
        
        if value == "'unsafe-inline'":
            findings.append("HIGH RISK: default-src allows 'unsafe-inline' which permits inline scripts and styles")
        
        elif value == "'unsafe-eval'":
            findings.append("HIGH RISK: default-src allows 'unsafe-eval' which permits the use of eval() and similar functions")
        
        elif value == "*":
            findings.append("HIGH RISK: default-src allows wildcard (*) which permits resources from any source")
        
        elif value in ("data:", "blob:"):
            findings.append(f"HIGH RISK: default-src allows {value} URI which can be used to bypass CSP")
        
        elif value in ("https:", "http:"):
            findings.append(f"HIGH RISK: default-src allows any {value} domain which significantly weakens CSP protection")
    
    return findings

def analyze_object_src(values, policy, findings):
    """
    Analyze object-src directive values for security issues.
    
    Args:
        values: List of object-src values
        policy: Full policy dictionary
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Check if object-src is specified
    if not values:
        # If not specified, check if default-src handles it
        if 'default-src' in policy:
            # object-src falls back to default-src
            pass
        else:
            findings.append("MEDIUM RISK: object-src directive is missing and no applicable default-src, allowing <object>, <embed>, and <applet> from any source")
        return findings
    
    # Check for 'none' which is the most secure option
    if "'none'" in values:
        findings.append("GOOD: object-src is set to 'none', blocking plugin content")
        return findings
        
    # Check for wildcards and other risky values
    for value in values:
        value = value.strip("'").lower()
        
        if value == "*":
            findings.append("HIGH RISK: object-src allows wildcard (*) which permits plugin content from any source")
        
        elif value in ("https:", "http:", "data:"):
            findings.append(f"MEDIUM RISK: object-src allows {value} which permits plugin content from many sources")
    
    return findings

def analyze_base_uri(values, policy, findings):
    """
    Analyze base-uri directive values for security issues.
    
    Args:
        values: List of base-uri values
        policy: Full policy dictionary
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Check if base-uri is specified
    if not values:
        findings.append("LOW RISK: base-uri directive is missing, allowing <base> tags to set the document base URL to any value")
        return findings
    
    # Check for 'none' or 'self'
    if "'none'" in values:
        findings.append("GOOD: base-uri is set to 'none', blocking all <base> tags")
        return findings
    
    if "'self'" in values and len(values) == 1:
        findings.append("GOOD: base-uri is restricted to 'self', limiting base URL to same origin")
        return findings
    
    # Check for wildcards and other risky values
    for value in values:
        value = value.strip("'").lower()
        
        if value == "*":
            findings.append("MEDIUM RISK: base-uri allows wildcard (*) which permits <base> tags to set any base URL")
        
        elif value in ("https:", "http:"):
            findings.append(f"LOW RISK: base-uri allows {value} which permits setting base URL to many possible domains")
    
    return findings

def analyze_frame_ancestors(values, findings):
    """
    Analyze frame-ancestors directive values for security issues.
    
    Args:
        values: List of frame-ancestors values
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Check if frame-ancestors is specified
    if not values:
        findings.append("MEDIUM RISK: frame-ancestors directive is missing, falling back to X-Frame-Options or allowing framing from any origin")
        return findings
    
    # Check for 'none' which is the most secure option for preventing clickjacking
    if "'none'" in values:
        findings.append("GOOD: frame-ancestors is set to 'none', preventing any framing (clickjacking protection)")
        return findings
    
    # Check if restricted to same origin
    if "'self'" in values and len(values) == 1:
        findings.append("GOOD: frame-ancestors is restricted to 'self', limiting framing to same origin")
        return findings
    
    # Check for wildcards and other risky values
    for value in values:
        value = value.strip("'").lower()
        
        if value == "*":
            findings.append("HIGH RISK: frame-ancestors allows wildcard (*) which permits framing from any origin (clickjacking risk)")
        
        elif value in ("https:", "http:"):
            findings.append(f"MEDIUM RISK: frame-ancestors allows {value} which permits framing from many possible domains")
    
    return findings

def analyze_missing_directives(policy, findings):
    """
    Check for important missing directives in the CSP policy.
    
    Args:
        policy: Dictionary of CSP directives
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    # Important directives that should be present
    important_directives = [
        ('script-src', "MEDIUM RISK: script-src directive is missing, falling back to default-src for script control"),
        ('object-src', "MEDIUM RISK: object-src directive is missing, allowing <object>, <embed> and <applet> from any source by default"),
        ('base-uri', "LOW RISK: base-uri directive is missing, allowing <base> tags to modify the document base URL"),
        ('frame-ancestors', "MEDIUM RISK: frame-ancestors directive is missing, providing no CSP-based clickjacking protection"),
        ('default-src', "MEDIUM RISK: default-src directive is missing, each resource type will use its default behavior"),
        ('upgrade-insecure-requests', "LOW RISK: upgrade-insecure-requests directive is missing, allowing HTTP resources to be loaded without upgrading"),
        ('form-action', "MEDIUM RISK: form-action directive is missing, allowing form submissions to any destination")
    ]
    
    for directive, message in important_directives:
        if directive not in policy:
            # For script-src, only report if default-src is also missing
            if directive == 'script-src' and 'default-src' in policy:
                continue
            findings.append(message)
    
    return findings

def check_csp_effectiveness(policy, findings):
    """
    Evaluate overall CSP policy effectiveness.
    
    Args:
        policy: Dictionary of CSP directives
        findings: List to append findings to
        
    Returns:
        Updated findings list, and effectiveness score (0-10)
    """
    score = 10  # Start with perfect score
    critical_issues = 0
    
    # Check for critical bypasses in script-src or default-src
    for directive in ['script-src', 'default-src']:
        if directive in policy:
            for value in policy[directive]:
                value = value.strip("'").lower()
                if value in CSP_BYPASSES[directive]:
                    if value in ['unsafe-inline', 'unsafe-eval', '*', 'data:', 'blob:']:
                        score -= 2  # Major reduction for critical bypass
                        critical_issues += 1
                    else:
                        score -= 1  # Minor reduction for less severe issues
    
    # Check if object-src and frame-ancestors are properly restricted
    for directive in ['object-src', 'frame-ancestors']:
        if directive not in policy:
            score -= 1
        elif policy[directive] and "'none'" not in policy[directive] and ('*' in policy[directive] or any(v in ['http:', 'https:'] for v in policy[directive])):
            score -= 1
    
    # Check for missing important directives
    important_missing = 0
    for directive in ['script-src', 'object-src', 'base-uri', 'frame-ancestors']:
        if directive not in policy:
            important_missing += 1
    
    if important_missing >= 3:
        score -= 2
    elif important_missing > 0:
        score -= 1
    
    # Ensure score remains within bounds
    score = max(0, min(score, 10))
    
    # Add effectiveness assessment to findings
    if score >= 8:
        findings.append(f"CSP Effectiveness: GOOD (Score: {score}/10)")
    elif score >= 5:
        findings.append(f"CSP Effectiveness: MODERATE (Score: {score}/10)")
    else:
        findings.append(f"CSP Effectiveness: WEAK (Score: {score}/10)")
    
    if critical_issues > 0:
        findings.append(f"CRITICAL: Found {critical_issues} severe security issues that may completely bypass CSP protection")
    
    return findings, score

def check_for_csp_reporting(policy, findings):
    """
    Check if CSP reporting is enabled and correctly configured.
    
    Args:
        policy: Dictionary of CSP directives
        findings: List to append findings to
        
    Returns:
        Updated findings list
    """
    has_reporting = False
    
    # Check report-uri (deprecated but still widely used)
    if 'report-uri' in policy and policy['report-uri']:
        has_reporting = True
        findings.append(f"CSP reporting enabled via report-uri: {' '.join(policy['report-uri'])}")
        findings.append("NOTE: report-uri is deprecated, consider using report-to instead")
    
    # Check report-to (newer standard)
    if 'report-to' in policy and policy['report-to']:
        has_reporting = True
        findings.append(f"CSP reporting enabled via report-to: {' '.join(policy['report-to'])}")
    
    if not has_reporting:
        findings.append("IMPROVEMENT: CSP reporting is not enabled. Consider adding report-to or report-uri directive for monitoring policy violations")
    
    return findings

def analyze_csp_header(header_value):
    """
    Analyze a CSP header value for common security issues.
    
    Args:
        header_value: The CSP header value string
        
    Returns:
        List of findings dictionaries
    """
    findings = []
    
    if not header_value:
        findings.append({
            'type': 'missing',
            'directive': None,
            'message': CSP_ISSUES['missing']['description'],
            'severity': CSP_ISSUES['missing']['severity'],
            'recommendation': CSP_ISSUES['missing']['recommendation'],
            'info_link': CSP_ISSUES['missing']['info_link']
        })
        return findings
    
    # Parse the CSP into its directives
    directives = parse_csp(header_value)
    
    # Check for default-src
    if 'default-src' not in directives:
        directives['default-src'] = ["'none'"]  # Assume strictest policy if not specified
    
    # Check for wildcards in default-src
    if any(src in WILDCARD_SOURCES for src in directives.get('default-src', [])):
        findings.append({
            'type': 'wildcard_default_src',
            'directive': 'default-src',
            'message': CSP_ISSUES['wildcard_default_src']['description'],
            'severity': CSP_ISSUES['wildcard_default_src']['severity'],
            'recommendation': CSP_ISSUES['wildcard_default_src']['recommendation'],
            'info_link': CSP_ISSUES['wildcard_default_src']['info_link']
        })
    
    # Check for unsafe-inline and unsafe-eval
    for directive, values in directives.items():
        if directive not in ['script-src', 'style-src', 'script-src-elem', 'style-src-elem', 'script-src-attr', 'style-src-attr']:
            continue
            
        for value in values:
            if "'unsafe-inline'" in value:
                findings.append({
                    'type': 'unsafe_inline',
                    'directive': directive,
                    'message': f"{directive} contains {CSP_ISSUES['unsafe_inline']['description']}",
                    'severity': CSP_ISSUES['unsafe_inline']['severity'],
                    'recommendation': CSP_ISSUES['unsafe_inline']['recommendation'],
                    'info_link': CSP_ISSUES['unsafe_inline']['info_link']
                })
            
            if "'unsafe-eval'" in value:
                findings.append({
                    'type': 'unsafe_eval',
                    'directive': directive,
                    'message': f"{directive} contains {CSP_ISSUES['unsafe_eval']['description']}",
                    'severity': CSP_ISSUES['unsafe_eval']['severity'],
                    'recommendation': CSP_ISSUES['unsafe_eval']['recommendation'],
                    'info_link': CSP_ISSUES['unsafe_eval']['info_link']
                })
    
    # Check script-src
    if 'script-src' not in directives and 'default-src' in directives:
        # script-src falls back to default-src
        if any(src in WILDCARD_SOURCES for src in directives['default-src']):
            findings.append({
                'type': 'missing_script_src',
                'directive': 'script-src',
                'message': CSP_ISSUES['missing_script_src']['description'],
                'severity': CSP_ISSUES['missing_script_src']['severity'],
                'recommendation': CSP_ISSUES['missing_script_src']['recommendation'],
                'info_link': CSP_ISSUES['missing_script_src']['info_link']
            })
    elif 'script-src' in directives:
        if any(src in WILDCARD_SOURCES for src in directives['script-src']):
            findings.append({
                'type': 'wildcard_script_src',
                'directive': 'script-src',
                'message': CSP_ISSUES['wildcard_script_src']['description'],
                'severity': CSP_ISSUES['wildcard_script_src']['severity'],
                'recommendation': CSP_ISSUES['wildcard_script_src']['recommendation'],
                'info_link': CSP_ISSUES['wildcard_script_src']['info_link']
            })
    
    # Check object-src
    if 'object-src' not in directives and not any(src == "'none'" for src in directives.get('default-src', [])):
        findings.append({
            'type': 'missing_object_src',
            'directive': 'object-src',
            'message': CSP_ISSUES['missing_object_src']['description'],
            'severity': CSP_ISSUES['missing_object_src']['severity'],
            'recommendation': CSP_ISSUES['missing_object_src']['recommendation'],
            'info_link': CSP_ISSUES['missing_object_src']['info_link']
        })
    
    # Check base-uri
    if 'base-uri' not in directives:
        findings.append({
            'type': 'missing_base_uri',
            'directive': 'base-uri',
            'message': CSP_ISSUES['missing_base_uri']['description'],
            'severity': CSP_ISSUES['missing_base_uri']['severity'],
            'recommendation': CSP_ISSUES['missing_base_uri']['recommendation'],
            'info_link': CSP_ISSUES['missing_base_uri']['info_link']
        })
    
    # Check frame-ancestors
    if 'frame-ancestors' not in directives:
        findings.append({
            'type': 'missing_frame_ancestors',
            'directive': 'frame-ancestors',
            'message': CSP_ISSUES['missing_frame_ancestors']['description'],
            'severity': CSP_ISSUES['missing_frame_ancestors']['severity'],
            'recommendation': CSP_ISSUES['missing_frame_ancestors']['recommendation'],
            'info_link': CSP_ISSUES['missing_frame_ancestors']['info_link']
        })
    
    # Check frame-src
    frame_src = directives.get('frame-src', directives.get('default-src', []))
    if not frame_src or any(src in WILDCARD_SOURCES for src in frame_src):
        findings.append({
            'type': 'weak_frame_src',
            'directive': 'frame-src',
            'message': CSP_ISSUES['weak_frame_src']['description'],
            'severity': CSP_ISSUES['weak_frame_src']['severity'],
            'recommendation': CSP_ISSUES['weak_frame_src']['recommendation'],
            'info_link': CSP_ISSUES['weak_frame_src']['info_link']
        })
    
    # Check img-src for data: URLs
    img_src = directives.get('img-src', directives.get('default-src', []))
    if any(src == 'data:' for src in img_src):
        findings.append({
            'type': 'data_img_src',
            'directive': 'img-src',
            'message': CSP_ISSUES['data_img_src']['description'],
            'severity': CSP_ISSUES['data_img_src']['severity'],
            'recommendation': CSP_ISSUES['data_img_src']['recommendation'],
            'info_link': CSP_ISSUES['data_img_src']['info_link']
        })
    
    # Check for upgrade-insecure-requests
    if 'upgrade-insecure-requests' not in directives:
        findings.append({
            'type': 'missing_upgrade_insecure',
            'directive': 'upgrade-insecure-requests',
            'message': CSP_ISSUES['missing_upgrade_insecure']['description'],
            'severity': CSP_ISSUES['missing_upgrade_insecure']['severity'],
            'recommendation': CSP_ISSUES['missing_upgrade_insecure']['recommendation'],
            'info_link': CSP_ISSUES['missing_upgrade_insecure']['info_link']
        })
    
    return findings

def check_for_inline_scripts(soup):
    """
    Check for inline scripts/styles in the HTML content
    
    Args:
        soup: BeautifulSoup object of the response
        
    Returns:
        Dictionary with count of inline elements
    """
    results = {
        'inline_scripts': 0,
        'inline_script_samples': [],
        'inline_styles': 0,
        'inline_style_samples': [],
        'event_handlers': 0,
        'event_handler_samples': []
    }
    
    # Check for inline scripts
    inline_scripts = soup.find_all('script', src=False)
    results['inline_scripts'] = len(inline_scripts)
    
    # Get samples of inline scripts
    for i, script in enumerate(inline_scripts[:3]):  # Limit to 3 samples
        if script.string:
            # Truncate long scripts
            sample = script.string[:100] + '...' if len(script.string) > 100 else script.string
            results['inline_script_samples'].append(sample)
    
    # Check for inline styles
    inline_styles = soup.find_all('style')
    results['inline_styles'] = len(inline_styles)
    
    # Get samples of inline styles
    for i, style in enumerate(inline_styles[:3]):  # Limit to 3 samples
        if style.string:
            # Truncate long styles
            sample = style.string[:100] + '...' if len(style.string) > 100 else style.string
            results['inline_style_samples'].append(sample)
    
    # Check for event handlers (onclick, onload, etc.)
    event_handlers = 0
    event_handler_samples = []
    
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.lower().startswith('on'):
                event_handlers += 1
                if len(event_handler_samples) < 3:  # Limit to 3 samples
                    event_handler_samples.append(f"{attr}={tag[attr][:50]}")
    
    results['event_handlers'] = event_handlers
    results['event_handler_samples'] = event_handler_samples
    
    return results

def generate_csp_recommendations(findings, inline_elements):
    """
    Generate CSP recommendations based on findings and inline elements
    
    Args:
        findings: List of finding dictionaries
        inline_elements: Dictionary with count of inline elements
        
    Returns:
        Recommended CSP header value
    """
    # Start with a strict CSP
    recommended_csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'"],
        'connect-src': ["'self'"],
        'font-src': ["'self'"],
        'object-src': ["'none'"],
        'media-src': ["'self'"],
        'frame-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'upgrade-insecure-requests': []
    }
    
    # If there are inline scripts, recommend nonces/hashes but provide unsafe-inline as fallback
    if inline_elements['inline_scripts'] > 0:
        recommended_csp['script-src'].append("'unsafe-inline' /* Replace with nonces or hashes */")
    
    # If there are inline styles, recommend nonces/hashes but provide unsafe-inline as fallback
    if inline_elements['inline_styles'] > 0:
        recommended_csp['style-src'].append("'unsafe-inline' /* Replace with nonces or hashes */")
    
    # Format the recommended CSP
    csp_parts = []
    for directive, sources in recommended_csp.items():
        if directive == 'upgrade-insecure-requests':
            csp_parts.append(directive)
        else:
            csp_parts.append(f"{directive} {' '.join(sources)}")
    
    return "; ".join(csp_parts)

def format_findings(findings, inline_elements, recommended_csp):
    """
    Format the findings list for better readability.
    
    Args:
        findings: List of finding dictionaries
        inline_elements: Dictionary with count of inline elements
        recommended_csp: Recommended CSP header value
        
    Returns:
        List of formatted finding strings
    """
    formatted_findings = []
    
    for finding in findings:
        severity = finding['severity']
        message = finding['message']
        recommendation = finding['recommendation']
        directive = finding['directive']
        
        formatted_finding = f"{severity} RISK: {message}"
        if directive:
            formatted_finding += f" (directive: {directive})"
        
        formatted_finding += f"\nRECOMMENDATION: {recommendation}"
        
        formatted_findings.append(formatted_finding)
    
    # Add information about inline elements
    if inline_elements['inline_scripts'] > 0 or inline_elements['inline_styles'] > 0 or inline_elements['event_handlers'] > 0:
        inline_summary = "INFORMATION: Detected inline elements that may require CSP adjustments:\n"
        
        if inline_elements['inline_scripts'] > 0:
            inline_summary += f"- {inline_elements['inline_scripts']} inline script tag(s) found\n"
        
        if inline_elements['inline_styles'] > 0:
            inline_summary += f"- {inline_elements['inline_styles']} inline style tag(s) found\n"
        
        if inline_elements['event_handlers'] > 0:
            inline_summary += f"- {inline_elements['event_handlers']} HTML event handler(s) found\n"
        
        inline_summary += "RECOMMENDATION: Use nonces or hashes for inline scripts/styles instead of 'unsafe-inline'"
        
        formatted_findings.append(inline_summary)
    
    # Add the recommended CSP
    if findings and recommended_csp:
        formatted_findings.append(f"RECOMMENDATION: Consider implementing the following Content-Security-Policy:\n{recommended_csp}")
    
    return formatted_findings

def check(session, url, soup, response, config):
    """
    Check for Content Security Policy issues.
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
    
    Returns:
        List of formatted findings
    """
    findings = []
    
    # Check for CSP header
    csp_header = response.headers.get('Content-Security-Policy')
    csp_report_only_header = response.headers.get('Content-Security-Policy-Report-Only')
    
    # If report-only CSP is present but regular CSP is not
    if not csp_header and csp_report_only_header:
        findings.append({
            'type': 'report_only',
            'directive': None,
            'message': CSP_ISSUES['report_only']['description'],
            'severity': CSP_ISSUES['report_only']['severity'],
            'recommendation': CSP_ISSUES['report_only']['recommendation'],
            'info_link': CSP_ISSUES['report_only']['info_link']
        })
    
    # Analyze the CSP header
    csp_findings = analyze_csp_header(csp_header)
    findings.extend(csp_findings)
    
    # Check for inline scripts and styles
    inline_elements = check_for_inline_scripts(soup)
    
    # Generate CSP recommendations based on findings and inline elements
    recommended_csp = generate_csp_recommendations(findings, inline_elements)
    
    # Format the findings for better readability
    formatted_findings = format_findings(findings, inline_elements, recommended_csp)
    
    # If no findings were reported but CSP header is present, add a positive message
    if not findings and csp_header:
        formatted_findings.append("INFO: Content Security Policy is implemented and no major issues were detected.")
    
    return formatted_findings 