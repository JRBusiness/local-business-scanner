import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


class TechnologyDetector:
    """
    In-house solution for detecting technologies used on websites.
    Uses pattern matching and signature detection instead of external APIs.
    """
    
    def __init__(self):
        # Load tech signatures
        self.signatures = self._load_signatures()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def _load_signatures(self):
        """Load technology signatures from the embedded dictionary"""
        # This would ideally load from a separate JSON file, but for simplicity we'll embed it here
        return {
            # Web Frameworks
            "frameworks": {
                "React": [
                    {"type": "js", "pattern": r"(?:react(?:\.\w+)?\.js|react-dom\.js)"},
                    {"type": "meta", "pattern": r"react"},
                    {"type": "html", "pattern": r"data-reactid|react-mount"},
                ],
                "Angular": [
                    {"type": "js", "pattern": r"angular(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"ng-app|ng-controller|ng-model"},
                    {"type": "meta", "pattern": r"angular"},
                ],
                "Vue.js": [
                    {"type": "js", "pattern": r"vue(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"v-if|v-for|v-model|v-bind"},
                    {"type": "meta", "pattern": r"vue"},
                ],
                "jQuery": [
                    {"type": "js", "pattern": r"jquery(?:\.min)?\.js"},
                    {"type": "meta", "pattern": r"jquery"},
                ],
                "Bootstrap": [
                    {"type": "css", "pattern": r"bootstrap(?:\.min)?\.css"},
                    {"type": "js", "pattern": r"bootstrap(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"class=\"(?:.*\s)?(?:btn|container|row|col-md)(?:\s.*)?\""},
                ],
                "Tailwind CSS": [
                    {"type": "css", "pattern": r"tailwind(?:\.min)?\.css"},
                    {"type": "html", "pattern": r"class=\"(?:.*\s)?(?:text-\w+|bg-\w+|flex|grid|p-\d+)(?:\s.*)?\""},
                ],
                "Next.js": [
                    {"type": "js", "pattern": r"_next/static"},
                    {"type": "html", "pattern": r"__NEXT_DATA__"},
                    {"type": "meta", "pattern": r"next-head"},
                ],
                "Nuxt.js": [
                    {"type": "js", "pattern": r"_nuxt/"},
                    {"type": "html", "pattern": r"__NUXT__"},
                    {"type": "meta", "pattern": r"nuxt"},
                ],
                "Svelte": [
                    {"type": "js", "pattern": r"svelte(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"svelte-\w+"},
                ],
                "Ember.js": [
                    {"type": "js", "pattern": r"ember(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"data-ember-action"},
                ],
                "Gatsby": [
                    {"type": "js", "pattern": r"gatsby-(?:runtime|chunk)"},
                    {"type": "html", "pattern": r"___gatsby"},
                ],
                "Backbone.js": [
                    {"type": "js", "pattern": r"backbone(?:\.min)?\.js"},
                    {"type": "meta", "pattern": r"backbone"},
                ],
                "Meteor": [
                    {"type": "js", "pattern": r"meteor(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"__meteor-bootstrap__"},
                ],
                "GSAP": [
                    {"type": "js", "pattern": r"gsap(?:\.min)?\.js|TweenMax(?:\.min)?\.js"},
                ],
                "Three.js": [
                    {"type": "js", "pattern": r"three(?:\.min)?\.js"},
                ],
                "D3.js": [
                    {"type": "js", "pattern": r"d3(?:\.min)?\.js"},
                ],
                "Lodash": [
                    {"type": "js", "pattern": r"lodash(?:\.min)?\.js"},
                ],
                "AMP": [
                    {"type": "html", "pattern": r"<html[^>]*\s+amp"},
                ],
            },
            # CSS Frameworks
            "css_frameworks": {
                "Bulma": [
                    {"type": "css", "pattern": r"bulma(?:\.min)?\.css"},
                    {"type": "html", "pattern": r"class=\"(?:.*\s)?(?:button is-|navbar-|column is-)(?:\s.*)?\""},
                ],
                "Foundation": [
                    {"type": "css", "pattern": r"foundation(?:\.min)?\.css"},
                    {"type": "js", "pattern": r"foundation(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"class=\"(?:.*\s)?(?:row|column|button)(?:\s.*)?\""},
                ],
                "Materialize": [
                    {"type": "css", "pattern": r"materialize(?:\.min)?\.css"},
                    {"type": "js", "pattern": r"materialize(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"class=\"(?:.*\s)?(?:btn|card|collection|collapsible|waves)(?:\s.*)?\""},
                ],
                "Semantic UI": [
                    {"type": "css", "pattern": r"semantic(?:\.min)?\.css"},
                    {"type": "js", "pattern": r"semantic(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"class=\"(?:.*\s)?(?:ui button|ui menu|ui grid|ui form)(?:\s.*)?\""},
                ],
                "Pure CSS": [
                    {"type": "css", "pattern": r"pure(?:\.min)?\.css"},
                    {"type": "html", "pattern": r"class=\"(?:.*\s)?(?:pure-button|pure-menu|pure-form|pure-g|pure-u)(?:\s.*)?\""},
                ],
            },
            # CMS
            "cms": {
                "WordPress": [
                    {"type": "meta", "pattern": r"wordpress"},
                    {"type": "html", "pattern": r"wp-content|wp-includes"},
                    {"type": "js", "pattern": r"wp-(?:content|includes|embed)"},
                ],
                "Drupal": [
                    {"type": "meta", "pattern": r"drupal"},
                    {"type": "html", "pattern": r"drupal.org"},
                    {"type": "js", "pattern": r"drupal.js"},
                ],
                "Joomla": [
                    {"type": "meta", "pattern": r"joomla"},
                    {"type": "html", "pattern": r"joomla!"},
                    {"type": "js", "pattern": r"joomla(?:\.min)?\.js"},
                ],
                "Wix": [
                    {"type": "meta", "pattern": r"wix"},
                    {"type": "html", "pattern": r"wix.com"},
                    {"type": "js", "pattern": r"wix.com"},
                ],
                "Shopify": [
                    {"type": "meta", "pattern": r"shopify"},
                    {"type": "html", "pattern": r"cdn.shopify.com"},
                    {"type": "js", "pattern": r"shopify"},
                ],
                "Squarespace": [
                    {"type": "meta", "pattern": r"squarespace"},
                    {"type": "html", "pattern": r"squarespace.com"},
                    {"type": "js", "pattern": r"squarespace.com"},
                ],
                "Ghost": [
                    {"type": "meta", "pattern": r"ghost"},
                    {"type": "html", "pattern": r"content=\"Ghost"},
                ],
                "Webflow": [
                    {"type": "meta", "pattern": r"webflow"},
                    {"type": "html", "pattern": r"webflow.com"},
                    {"type": "js", "pattern": r"webflow.js"},
                ],
                "Typo3": [
                    {"type": "meta", "pattern": r"typo3"},
                    {"type": "html", "pattern": r"typo3"},
                ],
                "Craft CMS": [
                    {"type": "meta", "pattern": r"Craft CMS"},
                    {"type": "html", "pattern": r"Powered by Craft CMS"},
                    {"type": "js", "pattern": r"craft.js"},
                ],
                "HubSpot": [
                    {"type": "js", "pattern": r"hubspot"},
                    {"type": "html", "pattern": r"hubspot.com"},
                    {"type": "meta", "pattern": r"hubspot"},
                ],
            },
            # Analytics
            "analytics": {
                "Google Analytics": [
                    {"type": "js", "pattern": r"google-analytics.com/analytics.js|ga\.js|gtag"},
                    {"type": "html", "pattern": r"google-analytics.com|gtag\("},
                ],
                "Google Tag Manager": [
                    {"type": "js", "pattern": r"googletagmanager.com"},
                    {"type": "html", "pattern": r"googletagmanager.com|gtm\.js"},
                ],
                "Facebook Pixel": [
                    {"type": "js", "pattern": r"facebook.com/tr|fbq\("},
                    {"type": "html", "pattern": r"facebook.com/tr|fbq\("},
                ],
                "Matomo/Piwik": [
                    {"type": "js", "pattern": r"matomo.js|piwik.js"},
                    {"type": "html", "pattern": r"matomo|piwik"},
                ],
                "Hotjar": [
                    {"type": "js", "pattern": r"hotjar|hj\("},
                    {"type": "html", "pattern": r"hotjar"},
                ],
                "Mixpanel": [
                    {"type": "js", "pattern": r"mixpanel"},
                    {"type": "html", "pattern": r"mixpanel"},
                ],
                "Amplitude": [
                    {"type": "js", "pattern": r"amplitude"},
                    {"type": "html", "pattern": r"amplitude"},
                ],
                "Segment": [
                    {"type": "js", "pattern": r"segment.io|segment.com"},
                    {"type": "html", "pattern": r"segment.io|segment.com"},
                ],
                "Intercom": [
                    {"type": "js", "pattern": r"intercom"},
                    {"type": "html", "pattern": r"intercom"},
                ],
                "Hubspot Analytics": [
                    {"type": "js", "pattern": r"hubspot.com/analytics"},
                    {"type": "html", "pattern": r"hs-analytics"},
                ],
            },
            # Server
            "server": {
                "Apache": [
                    {"type": "header", "name": "Server", "pattern": r"Apache"},
                ],
                "Nginx": [
                    {"type": "header", "name": "Server", "pattern": r"nginx"},
                ],
                "IIS": [
                    {"type": "header", "name": "Server", "pattern": r"IIS|Microsoft-IIS"},
                ],
                "Cloudflare": [
                    {"type": "header", "name": "Server", "pattern": r"cloudflare"},
                    {"type": "header", "name": "CF-Ray", "pattern": r".+"},
                ],
                "Vercel": [
                    {"type": "header", "name": "x-vercel", "pattern": r".+"},
                    {"type": "header", "name": "Server", "pattern": r"Vercel"},
                ],
                "Netlify": [
                    {"type": "header", "name": "Server", "pattern": r"Netlify"},
                    {"type": "header", "name": "x-nf", "pattern": r".+"},
                ],
                "Heroku": [
                    {"type": "header", "name": "Via", "pattern": r"vegur"},
                ],
                "AWS": [
                    {"type": "header", "name": "Server", "pattern": r"AmazonS3|cloudfront|ELB"},
                    {"type": "header", "name": "x-amz", "pattern": r".+"},
                    {"type": "header", "name": "X-Amz", "pattern": r".+"},
                ],
                "Google Cloud": [
                    {"type": "header", "name": "Server", "pattern": r"Google Frontend|gws"},
                    {"type": "header", "name": "X-Cloud-Trace-Context", "pattern": r".+"},
                ],
                "Fastly": [
                    {"type": "header", "name": "Fastly-Debug-Digest", "pattern": r".+"},
                    {"type": "header", "name": "X-Served-By", "pattern": r"cache-.*-fastly"},
                ],
                "Akamai": [
                    {"type": "header", "name": "X-Akamai", "pattern": r".+"},
                    {"type": "header", "name": "Server", "pattern": r"AkamaiGHost"},
                ],
            },
            # E-commerce
            "ecommerce": {
                "WooCommerce": [
                    {"type": "js", "pattern": r"woocommerce"},
                    {"type": "html", "pattern": r"woocommerce|wc-|product-category"},
                    {"type": "meta", "pattern": r"woocommerce"},
                ],
                "Magento": [
                    {"type": "js", "pattern": r"magento"},
                    {"type": "html", "pattern": r"magento|mage-"},
                    {"type": "meta", "pattern": r"magento"},
                ],
                "PrestaShop": [
                    {"type": "js", "pattern": r"prestashop"},
                    {"type": "html", "pattern": r"prestashop"},
                    {"type": "meta", "pattern": r"prestashop"},
                ],
                "Shopify": [
                    {"type": "js", "pattern": r"shopify"},
                    {"type": "html", "pattern": r"shopify"},
                    {"type": "meta", "pattern": r"shopify"},
                ],
                "BigCommerce": [
                    {"type": "js", "pattern": r"bigcommerce"},
                    {"type": "html", "pattern": r"bigcommerce"},
                    {"type": "meta", "pattern": r"bigcommerce"},
                ],
                "OpenCart": [
                    {"type": "js", "pattern": r"opencart"},
                    {"type": "html", "pattern": r"opencart"},
                    {"type": "meta", "pattern": r"opencart"},
                ],
                "Salesforce Commerce Cloud": [
                    {"type": "js", "pattern": r"demandware.js"},
                    {"type": "html", "pattern": r"demandware"},
                    {"type": "meta", "pattern": r"demandware"},
                ],
                "Shopware": [
                    {"type": "js", "pattern": r"shopware"},
                    {"type": "html", "pattern": r"shopware"},
                    {"type": "meta", "pattern": r"shopware"},
                ],
            },
            # Marketing Tools
            "marketing": {
                "HubSpot": [
                    {"type": "js", "pattern": r"hubspot"},
                    {"type": "html", "pattern": r"hubspot"},
                ],
                "Marketo": [
                    {"type": "js", "pattern": r"marketo"},
                    {"type": "html", "pattern": r"marketo"},
                ],
                "Pardot": [
                    {"type": "js", "pattern": r"pardot"},
                    {"type": "html", "pattern": r"pardot"},
                ],
                "Mailchimp": [
                    {"type": "js", "pattern": r"mailchimp|mc-"},
                    {"type": "html", "pattern": r"mailchimp|mc-"},
                ],
                "Drift": [
                    {"type": "js", "pattern": r"drift.com"},
                    {"type": "html", "pattern": r"drift.com"},
                ],
                "Zendesk": [
                    {"type": "js", "pattern": r"zendesk"},
                    {"type": "html", "pattern": r"zendesk"},
                ],
                "Olark": [
                    {"type": "js", "pattern": r"olark"},
                    {"type": "html", "pattern": r"olark"},
                ],
                "Optimizely": [
                    {"type": "js", "pattern": r"optimizely"},
                    {"type": "html", "pattern": r"optimizely"},
                ],
                "AB Tasty": [
                    {"type": "js", "pattern": r"abtasty"},
                    {"type": "html", "pattern": r"abtasty"},
                ],
            },
            # JavaScript Libraries
            "js_libraries": {
                "Moment.js": [
                    {"type": "js", "pattern": r"moment(?:\.min)?\.js"},
                ],
                "Chart.js": [
                    {"type": "js", "pattern": r"chart(?:\.min)?\.js"},
                ],
                "Highcharts": [
                    {"type": "js", "pattern": r"highcharts(?:\.min)?\.js"},
                ],
                "Lazy Load": [
                    {"type": "js", "pattern": r"lazyload(?:\.min)?\.js"},
                    {"type": "html", "pattern": r"lazy-load|lazyload"},
                ],
                "Slick Carousel": [
                    {"type": "js", "pattern": r"slick(?:\.min)?\.js"},
                    {"type": "css", "pattern": r"slick(?:\.min)?\.css"},
                    {"type": "html", "pattern": r"slick-slider|slick-carousel"},
                ],
                "Owl Carousel": [
                    {"type": "js", "pattern": r"owl\.carousel(?:\.min)?\.js"},
                    {"type": "css", "pattern": r"owl\.carousel(?:\.min)?\.css"},
                    {"type": "html", "pattern": r"owl-carousel"},
                ],
                "Swiper": [
                    {"type": "js", "pattern": r"swiper(?:\.min)?\.js"},
                    {"type": "css", "pattern": r"swiper(?:\.min)?\.css"},
                    {"type": "html", "pattern": r"swiper-container|swiper-slide"},
                ],
                "Popper.js": [
                    {"type": "js", "pattern": r"popper(?:\.min)?\.js"},
                ],
                "Anime.js": [
                    {"type": "js", "pattern": r"anime(?:\.min)?\.js"},
                ],
            }
        }
    
    def _extract_js_urls(self, soup):
        """Extract JavaScript URLs from the HTML"""
        js_urls = []
        for script in soup.find_all("script", src=True):
            js_urls.append(script.get("src", ""))
        return js_urls
    
    def _extract_css_urls(self, soup):
        """Extract CSS URLs from the HTML"""
        css_urls = []
        for link in soup.find_all("link", rel="stylesheet", href=True):
            css_urls.append(link.get("href", ""))
        return css_urls
    
    def _extract_meta_tags(self, soup):
        """Extract meta tag content from the HTML"""
        meta_content = []
        for meta in soup.find_all("meta"):
            if meta.get("content"):
                meta_content.append(meta.get("content", ""))
            if meta.get("name"):
                meta_content.append(meta.get("name", ""))
        return meta_content
    
    def _check_generator_meta(self, soup):
        """Check for generator meta tag which often reveals CMS info"""
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and "content" in generator.attrs:
            content = generator["content"].lower()
            
            # Check for common CMS patterns in generator tag
            cms_patterns = {
                "wordpress": "WordPress",
                "drupal": "Drupal",
                "joomla": "Joomla",
                "wix": "Wix",
                "shopify": "Shopify",
                "squarespace": "Squarespace",
                "ghost": "Ghost",
                "webflow": "Webflow",
                "typo3": "Typo3",
                "craft cms": "Craft CMS",
                "hubspot": "HubSpot"
            }
            
            for pattern, cms_name in cms_patterns.items():
                if pattern in content:
                    return cms_name
                
        return None
    
    def detect(self, url, html_content=None, response_headers=None):
        """
        Detect technologies used on a website
        
        Args:
            url (str): URL of the website
            html_content (str, optional): HTML content if already fetched
            response_headers (dict, optional): Response headers if already available
            
        Returns:
            dict: Detected technologies categorized
        """
        results = {}
        
        # Fetch the website if HTML content not provided
        if html_content is None or response_headers is None:
            try:
                print("    - Fetching website for technology detection...")
                response = requests.get(url, headers=self.headers, timeout=10)
                html_content = response.text
                response_headers = response.headers
            except Exception as e:
                return {"error": f"Failed to fetch website: {str(e)}"}
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        html_str = str(soup)
        
        # Get data for detection
        js_urls = self._extract_js_urls(soup)
        css_urls = self._extract_css_urls(soup)
        meta_content = self._extract_meta_tags(soup)
        
        # Check for generator meta tag (common for CMS detection)
        cms_from_generator = self._check_generator_meta(soup)
        if cms_from_generator:
            if "cms" not in results:
                results["cms"] = []
            if cms_from_generator not in results.get("cms", []):
                results["cms"].append(cms_from_generator)
        
        # Iterate through all technology signatures
        for category, technologies in self.signatures.items():
            for tech_name, patterns in technologies.items():
                detected = False
                
                for pattern in patterns:
                    if pattern["type"] == "js":
                        # Check JavaScript URLs
                        for js_url in js_urls:
                            if re.search(pattern["pattern"], js_url, re.IGNORECASE):
                                detected = True
                                break
                        # Check inline scripts
                        if not detected:
                            for script in soup.find_all("script"):
                                if script.string and re.search(pattern["pattern"], script.string, re.IGNORECASE):
                                    detected = True
                                    break
                    
                    elif pattern["type"] == "css":
                        # Check CSS URLs
                        for css_url in css_urls:
                            if re.search(pattern["pattern"], css_url, re.IGNORECASE):
                                detected = True
                                break
                    
                    elif pattern["type"] == "html":
                        # Check HTML content
                        if re.search(pattern["pattern"], html_str, re.IGNORECASE):
                            detected = True
                            break
                    
                    elif pattern["type"] == "meta":
                        # Check meta tags
                        for content in meta_content:
                            if re.search(pattern["pattern"], content, re.IGNORECASE):
                                detected = True
                                break
                    
                    elif pattern["type"] == "header" and response_headers:
                        # Check HTTP headers
                        header_name = pattern.get("name", "")
                        if header_name in response_headers:
                            if re.search(pattern["pattern"], response_headers[header_name], re.IGNORECASE):
                                detected = True
                                break
                
                if detected:
                    if category not in results:
                        results[category] = []
                    if tech_name not in results[category]:
                        results[category].append(tech_name)
        
        # Additional detection for specific technologies based on URL patterns
        domain = urlparse(url).netloc
        # Check for Wix
        if re.search(r'\.wix\.com', domain, re.IGNORECASE):
            if "cms" not in results:
                results["cms"] = []
            if "Wix" not in results.get("cms", []):
                results["cms"].append("Wix")
        
        # Check for Shopify
        if re.search(r'\.shopify\.com|\.myshopify\.com', domain, re.IGNORECASE):
            if "cms" not in results:
                results["cms"] = []
            if "Shopify" not in results.get("cms", []):
                results["cms"].append("Shopify")
            
            if "ecommerce" not in results:
                results["ecommerce"] = []
            if "Shopify" not in results.get("ecommerce", []):
                results["ecommerce"].append("Shopify")
        
        # Check for Squarespace
        if re.search(r'\.squarespace\.com', domain, re.IGNORECASE):
            if "cms" not in results:
                results["cms"] = []
            if "Squarespace" not in results.get("cms", []):
                results["cms"].append("Squarespace")
                
        # Check for Webflow
        if re.search(r'\.webflow\.io', domain, re.IGNORECASE):
            if "cms" not in results:
                results["cms"] = []
            if "Webflow" not in results.get("cms", []):
                results["cms"].append("Webflow")
        
        # Check for Netlify
        if re.search(r'\.netlify\.app', domain, re.IGNORECASE):
            if "server" not in results:
                results["server"] = []
            if "Netlify" not in results.get("server", []):
                results["server"].append("Netlify")
        
        # Check for WordPress subdomain hosting
        if re.search(r'\.wordpress\.com', domain, re.IGNORECASE):
            if "cms" not in results:
                results["cms"] = []
            if "WordPress" not in results.get("cms", []):
                results["cms"].append("WordPress")
        
        # Check for GitHub Pages
        if re.search(r'\.github\.io', domain, re.IGNORECASE):
            if "server" not in results:
                results["server"] = []
            if "GitHub Pages" not in results.get("server", []):
                results["server"].append("GitHub Pages")
        
        # Check for Heroku
        if re.search(r'\.herokuapp\.com', domain, re.IGNORECASE):
            if "server" not in results:
                results["server"] = []
            if "Heroku" not in results.get("server", []):
                results["server"].append("Heroku")
        
        # Check for Vercel
        if re.search(r'\.vercel\.app', domain, re.IGNORECASE):
            if "server" not in results:
                results["server"] = []
            if "Vercel" not in results.get("server", []):
                results["server"].append("Vercel")
                
        return results


def detect_technology_inhouse(url, html_content=None, response_headers=None):
    """
    Detect technologies used on a website using in-house detection.
    
    Args:
        url (str): URL of the website
        html_content (str, optional): HTML content if already fetched
        response_headers (dict, optional): Response headers if already available
        
    Returns:
        dict: Detected technologies
    """
    try:
        print("    - Running in-house technology detection...")
        detector = TechnologyDetector()
        tech_info = detector.detect(url, html_content, response_headers)
        if tech_info and not tech_info.get("error"):
            summary = []
            for category, techs in tech_info.items():
                summary.append(f"{category.title()}: {', '.join(techs)}")
            print(f"      * Detected: {'; '.join(summary)}")
        else:
            print(f"      * No technologies detected or error occurred")
        return tech_info
    except Exception as e:
        print(f"      * Technology detection error: {e}")
        return {"error": str(e)} 