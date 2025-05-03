"""
In-house PageSpeed Analyzer

This module provides functionality to analyze web page performance metrics
similar to Google PageSpeed Insights but without the external API dependency.
"""

import time
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import concurrent.futures
from collections import defaultdict
import math
import statistics

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_IMPORTED = True
except ImportError:
    SELENIUM_IMPORTED = False
    print("WARNING: Selenium not installed. Some PageSpeed metrics will be limited.")


class PageSpeedAnalyzer:
    """
    Analyzes web page performance metrics using various techniques
    to approximate Google PageSpeed Insights scores and recommendations.
    """
    
    def __init__(self, user_agent=None, headless=True, webdriver_path=None):
        """
        Initialize the PageSpeed analyzer.
        
        Args:
            user_agent (str): User agent string to use for requests
            headless (bool): Whether to run browser in headless mode
            webdriver_path (str): Path to webdriver executable
        """
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        self.headless = headless
        self.webdriver_path = webdriver_path
        self.headers = {'User-Agent': self.user_agent}
        
        # Default weights for calculating overall score
        self.metric_weights = {
            'fcp': 0.15,           # First Contentful Paint
            'lcp': 0.25,           # Largest Contentful Paint
            'fid': 0.20,           # First Input Delay (approximated)
            'cls': 0.15,           # Cumulative Layout Shift
            'ttfb': 0.10,          # Time to First Byte
            'resource_count': 0.05, # Number of resources
            'page_weight': 0.10,   # Total page weight
        }
        
        # Thresholds for good/medium/poor scores
        self.thresholds = {
            'fcp': {'good': 1.8, 'poor': 3.0},       # seconds
            'lcp': {'good': 2.5, 'poor': 4.0},       # seconds
            'fid': {'good': 0.1, 'poor': 0.3},       # seconds
            'cls': {'good': 0.1, 'poor': 0.25},      # unitless
            'ttfb': {'good': 0.2, 'poor': 0.6},      # seconds
            'resource_count': {'good': 50, 'poor': 100}, # count
            'page_weight': {'good': 1.5, 'poor': 3.0},   # MB
        }

    def _init_browser(self):
        """Initialize Selenium WebDriver browser instance."""
        if not SELENIUM_IMPORTED:
            raise ImportError("Selenium is required for browser-based metrics")
        
        options = ChromeOptions()
        if self.headless:
            options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument(f'user-agent={self.user_agent}')
        options.add_argument('--window-size=1920,1080')
        
        # Enable performance logs
        options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        
        if self.webdriver_path:
            from selenium.webdriver.chrome.service import Service
            service = Service(executable_path=self.webdriver_path)
            driver = webdriver.Chrome(service=service, options=options)
        else:
            driver = webdriver.Chrome(options=options)
            
        driver.set_page_load_timeout(30)
        return driver

    def _get_resource_size(self, url, session):
        """Get the size of a resource in bytes."""
        try:
            resp = session.head(url, headers=self.headers)
            size = int(resp.headers.get('content-length', 0))
            if size == 0 and resp.status_code == 200:
                # If content-length is not provided, fetch the content
                resp = session.get(url, headers=self.headers)
                size = len(resp.content)
            return size
        except Exception:
            return 0

    def _extract_resources(self, html_content, url):
        """
        Extract all external resources from HTML content.
        Returns a dictionary of resource types and their URLs.
        """
        base_url = url
        soup = BeautifulSoup(html_content, 'html.parser')
        resources = defaultdict(list)
        
        # Scripts
        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            if src and not src.startswith('data:'):
                resources['script'].append(urljoin(base_url, src))
        
        # Stylesheets
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link.get('href', '')
            if href and not href.startswith('data:'):
                resources['css'].append(urljoin(base_url, href))
        
        # Images
        for img in soup.find_all('img', src=True):
            src = img.get('src', '')
            if src and not src.startswith('data:'):
                resources['image'].append(urljoin(base_url, src))
        
        # Fonts
        for link in soup.find_all('link', href=True):
            href = link.get('href', '')
            if href and any(ext in href for ext in ['.woff', '.woff2', '.ttf', '.otf', '.eot']):
                resources['font'].append(urljoin(base_url, href))
        
        # Background images from inline styles
        for element in soup.find_all(style=True):
            style = element.get('style', '')
            urls = re.findall(r'url\([\'"]?([^\'")]+)[\'"]?\)', style)
            for url in urls:
                if url and not url.startswith('data:'):
                    resources['image'].append(urljoin(base_url, url))
        
        return resources

    def _analyze_resources(self, resources):
        """
        Analyze the resources to calculate total count, size, and type breakdown.
        Returns a dictionary of resource metrics.
        """
        metrics = {
            'total_resources': 0,
            'total_size_bytes': 0,
            'resource_breakdown': {},
        }
        
        session = requests.Session()
        session.headers.update(self.headers)
        
        for res_type, urls in resources.items():
            metrics['total_resources'] += len(urls)
            metrics['resource_breakdown'][res_type] = {
                'count': len(urls),
                'size_bytes': 0
            }
            
            # Use a thread pool to fetch resource sizes in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(self._get_resource_size, url, session): url for url in urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        size = future.result()
                        metrics['total_size_bytes'] += size
                        metrics['resource_breakdown'][res_type]['size_bytes'] += size
                    except Exception as e:
                        print(f"Error fetching size for {url}: {e}")
        
        # Convert to readable formats
        metrics['total_size_mb'] = metrics['total_size_bytes'] / (1024 * 1024)
        
        return metrics

    def _measure_ttfb(self, url):
        """Measure Time To First Byte (TTFB) in seconds."""
        start_time = time.time()
        try:
            response = requests.get(url, headers=self.headers, stream=True)
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:  # filter out keep-alive new chunks
                    ttfb = time.time() - start_time
                    return ttfb
        except Exception as e:
            print(f"Error measuring TTFB: {e}")
            return None
        return None

    def _measure_browser_metrics(self, url):
        """
        Use Selenium to measure browser-based metrics:
        - First Contentful Paint (FCP)
        - Largest Contentful Paint (LCP)
        - Cumulative Layout Shift (CLS)
        - First Input Delay approximation
        """
        if not SELENIUM_IMPORTED:
            return {
                'fcp': None,
                'lcp': None,
                'cls': None,
                'fid_approximation': None,
                'layout_shifts': None,
                'error': "Selenium not installed"
            }
            
        driver = None
        metrics = {
            'fcp': None,
            'lcp': None,
            'cls': None,
            'fid_approximation': None,
            'layout_shifts': None,
        }
        
        try:
            driver = self._init_browser()
            
            # Execute JavaScript to monitor performance metrics
            driver.execute_script("""
                window.performance_metrics = {};
                
                // FCP Observer
                const fcpObserver = new PerformanceObserver((entryList) => {
                    for (const entry of entryList.getEntries()) {
                        if (entry.name === 'first-contentful-paint') {
                            window.performance_metrics.fcp = entry.startTime / 1000;
                        }
                    }
                });
                fcpObserver.observe({ type: 'paint', buffered: true });
                
                // LCP Observer
                const lcpObserver = new PerformanceObserver((entryList) => {
                    const entries = entryList.getEntries();
                    const lastEntry = entries[entries.length - 1];
                    window.performance_metrics.lcp = lastEntry.startTime / 1000;
                });
                lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
                
                // Layout Shift Observer
                let cumulativeLayoutShift = 0;
                const layoutShiftObserver = new PerformanceObserver((entryList) => {
                    for (const entry of entryList.getEntries()) {
                        if (!entry.hadRecentInput) {
                            cumulativeLayoutShift += entry.value;
                        }
                    }
                    window.performance_metrics.cls = cumulativeLayoutShift;
                });
                layoutShiftObserver.observe({ type: 'layout-shift', buffered: true });
                
                // FID approximation using interaction timing
                let firstInputDelay = null;
                const fidObserver = new PerformanceObserver((entryList) => {
                    for (const entry of entryList.getEntries()) {
                        if (firstInputDelay === null) {
                            firstInputDelay = entry.processingStart - entry.startTime;
                            window.performance_metrics.fid_approximation = firstInputDelay / 1000;
                        }
                    }
                });
                fidObserver.observe({ type: 'first-input', buffered: true });
            """)
            
            # Load the page
            start_time = time.time()
            driver.get(url)
            
            # Wait for the page to load completely
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Scroll down slowly to trigger lazy loading
            total_height = driver.execute_script("return document.body.scrollHeight")
            viewport_height = driver.execute_script("return window.innerHeight")
            scrolls = max(1, math.ceil(total_height / viewport_height))
            
            for i in range(scrolls):
                driver.execute_script(f"window.scrollTo(0, {i * viewport_height})")
                time.sleep(0.5)
            
            # Scroll back to top
            driver.execute_script("window.scrollTo(0, 0)")
            
            # Wait a bit to ensure all metrics are collected
            time.sleep(3)
            
            # Retrieve the metrics from the page
            performance_metrics = driver.execute_script("return window.performance_metrics")
            
            if performance_metrics:
                metrics.update({
                    'fcp': performance_metrics.get('fcp'),
                    'lcp': performance_metrics.get('lcp'),
                    'cls': performance_metrics.get('cls'),
                    'fid_approximation': performance_metrics.get('fid_approximation'),
                })
                
            # If some metrics are missing, estimate them based on page load time
            page_load_time = time.time() - start_time
            if not metrics['fcp']:
                metrics['fcp'] = page_load_time * 0.4  # Estimate FCP as 40% of load time
            if not metrics['lcp']:
                metrics['lcp'] = page_load_time * 0.8  # Estimate LCP as 80% of load time
            if metrics['cls'] is None:
                metrics['cls'] = 0.05  # Default CLS value
            if not metrics['fid_approximation']:
                metrics['fid_approximation'] = page_load_time * 0.1  # Estimate FID as 10% of load time
                
        except TimeoutException:
            metrics['error'] = "Page load timed out"
        except WebDriverException as e:
            metrics['error'] = f"WebDriver error: {str(e)}"
        except Exception as e:
            metrics['error'] = f"Error measuring browser metrics: {str(e)}"
        finally:
            if driver:
                driver.quit()
                
        return metrics

    def _calculate_score(self, metrics):
        """
        Calculate an overall performance score (0-100) based on weighted metrics.
        Similar to how PageSpeed Insights calculates its score.
        """
        scores = {}
        
        # Convert each metric to a score between 0-1
        for metric, value in metrics.items():
            if metric not in self.thresholds or value is None:
                continue
                
            thresholds = self.thresholds[metric]
            
            if value <= thresholds['good']:
                # Good range (0.9 - 1.0)
                metric_score = 1.0
            elif value >= thresholds['poor']:
                # Poor range (0.0 - 0.5)
                metric_score = max(0, 0.5 - ((value - thresholds['poor']) / thresholds['poor'] * 0.5))
            else:
                # Needs improvement range (0.5 - 0.9)
                range_size = thresholds['poor'] - thresholds['good']
                position = (value - thresholds['good']) / range_size
                metric_score = 1.0 - (position * 0.4)  # 0.9 to 0.5
                
            scores[metric] = metric_score
        
        # Calculate weighted average
        weighted_sum = 0
        weight_sum = 0
        
        for metric, score in scores.items():
            weight = self.metric_weights.get(metric, 0)
            weighted_sum += score * weight
            weight_sum += weight
            
        # Normalize if not all metrics are available
        if weight_sum > 0:
            final_score = weighted_sum / weight_sum
        else:
            final_score = 0.5  # Default score
            
        # Convert to 0-100 scale
        return int(final_score * 100)

    def _generate_recommendations(self, metrics, resource_metrics):
        """Generate performance improvement recommendations based on analysis."""
        recommendations = []
        
        # Check page weight
        if metrics.get('page_weight', 0) > self.thresholds['page_weight']['good']:
            recommendations.append({
                'name': 'Reduce page weight',
                'description': f"Your page is {metrics['page_weight']:.2f}MB which exceeds the recommended size of {self.thresholds['page_weight']['good']}MB. Consider optimizing images and removing unnecessary resources."
            })
            
        # Check resource count
        if metrics.get('resource_count', 0) > self.thresholds['resource_count']['good']:
            recommendations.append({
                'name': 'Reduce number of resources',
                'description': f"Your page loads {metrics['resource_count']} resources which is more than the recommended {self.thresholds['resource_count']['good']}. Consider bundling files and removing unnecessary resources."
            })
            
        # Check image optimization
        if 'image' in resource_metrics.get('resource_breakdown', {}):
            image_metrics = resource_metrics['resource_breakdown']['image']
            total_image_size_mb = image_metrics['size_bytes'] / (1024 * 1024)
            if total_image_size_mb > 0.5 and image_metrics['count'] > 5:
                recommendations.append({
                    'name': 'Optimize images',
                    'description': f"Images account for {total_image_size_mb:.2f}MB of your page. Consider compressing images, using WebP format, and implementing lazy loading."
                })
                
        # Check render-blocking resources
        if 'css' in resource_metrics.get('resource_breakdown', {}) and resource_metrics['resource_breakdown']['css']['count'] > 3:
            recommendations.append({
                'name': 'Minimize render-blocking resources',
                'description': f"Your page has {resource_metrics['resource_breakdown']['css']['count']} CSS files which may block rendering. Consider inlining critical CSS and deferring non-critical CSS."
            })
            
        # Check JavaScript optimization
        if 'script' in resource_metrics.get('resource_breakdown', {}) and resource_metrics['resource_breakdown']['script']['count'] > 10:
            recommendations.append({
                'name': 'Optimize JavaScript',
                'description': f"Your page loads {resource_metrics['resource_breakdown']['script']['count']} JavaScript files. Consider bundling, minifying, and using async/defer attributes."
            })
            
        # Check LCP if available
        if metrics.get('lcp', 0) > self.thresholds['lcp']['good']:
            recommendations.append({
                'name': 'Improve Largest Contentful Paint',
                'description': f"Your LCP is {metrics['lcp']:.2f}s which is slower than the recommended {self.thresholds['lcp']['good']}s. Consider optimizing the main content, server response time, and critical rendering path."
            })
            
        # Check CLS if available
        if metrics.get('cls', 0) > self.thresholds['cls']['good']:
            recommendations.append({
                'name': 'Reduce layout shifts',
                'description': f"Your Cumulative Layout Shift score is {metrics['cls']:.2f} which is higher than the recommended {self.thresholds['cls']['good']}. Ensure elements have defined dimensions and avoid dynamically injecting content above existing content."
            })
            
        # Check TTFB if available
        if metrics.get('ttfb', 0) > self.thresholds['ttfb']['good']:
            recommendations.append({
                'name': 'Improve server response time',
                'description': f"Your Time to First Byte is {metrics['ttfb']:.2f}s which is slower than the recommended {self.thresholds['ttfb']['good']}s. Consider optimizing server performance, using a CDN, or implementing caching."
            })
            
        return recommendations

    def analyze(self, url):
        """
        Analyze a web page's performance and generate a report similar to PageSpeed Insights.
        
        Args:
            url (str): The URL of the web page to analyze
            
        Returns:
            dict: A dictionary containing performance metrics, scores, and recommendations
        """
        print(f"Analyzing PageSpeed for: {url}")
        result = {
            'url': url,
            'timestamp': time.time(),
            'metrics': {},
            'resource_metrics': {},
            'score': 0,
            'recommendations': [],
            'error': None
        }
        
        try:
            # Step 1: Measure TTFB
            print("- Measuring Time to First Byte...")
            ttfb = self._measure_ttfb(url)
            result['metrics']['ttfb'] = ttfb
            
            # Step 2: Fetch the HTML content
            print("- Fetching HTML content...")
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            html_content = response.text
            
            # Step 3: Extract and analyze resources
            print("- Analyzing page resources...")
            resources = self._extract_resources(html_content, url)
            resource_metrics = self._analyze_resources(resources)
            result['resource_metrics'] = resource_metrics
            
            # Add resource metrics to main metrics
            result['metrics']['resource_count'] = resource_metrics['total_resources']
            result['metrics']['page_weight'] = resource_metrics['total_size_mb']
            
            # Step 4: Measure browser-based metrics if Selenium is available
            print("- Measuring browser-based performance metrics...")
            browser_metrics = self._measure_browser_metrics(url)
            if 'error' in browser_metrics:
                print(f"  Warning: {browser_metrics['error']}")
                del browser_metrics['error']
                
            result['metrics'].update(browser_metrics)
            
            # Step 5: Calculate overall score
            print("- Calculating performance score...")
            result['score'] = self._calculate_score(result['metrics'])
            
            # Step 6: Generate recommendations
            print("- Generating recommendations...")
            result['recommendations'] = self._generate_recommendations(result['metrics'], resource_metrics)
            
            print(f"Analysis complete. Score: {result['score']}/100")
            
        except requests.exceptions.RequestException as e:
            result['error'] = f"Request error: {str(e)}"
            print(f"Error: {result['error']}")
        except Exception as e:
            result['error'] = f"Analysis error: {str(e)}"
            print(f"Error: {result['error']}")
            
        return result


def analyze_pagespeed_inhouse(url, config=None):
    """
    Analyze website performance using in-house PageSpeed analysis.
    
    Args:
        url (str): URL of the website to analyze
        config (dict): Configuration options
        
    Returns:
        dict: Performance analysis results
    """
    config = config or {}
    
    try:
        print("    - Running in-house PageSpeed analysis...")
        analyzer = PageSpeedAnalyzer(
            user_agent=config.get('user_agent'),
            headless=config.get('headless', True),
            webdriver_path=config.get('webdriver_path')
        )
        
        results = analyzer.analyze(url)
        
        # Format results for display
        if not results.get('error'):
            metrics = results.get('metrics', {})
            print(f"      * Score: {results['score']}/100")
            
            if 'lcp' in metrics:
                print(f"      * LCP: {metrics['lcp']:.2f}s")
            if 'cls' in metrics:
                print(f"      * CLS: {metrics['cls']:.2f}")
            if 'ttfb' in metrics:
                print(f"      * TTFB: {metrics['ttfb']:.2f}s")
            
            print(f"      * Page Weight: {metrics.get('page_weight', 0):.2f}MB")
            print(f"      * Resources: {metrics.get('resource_count', 0)}")
            
            if results.get('recommendations'):
                print(f"      * Top recommendations: {len(results['recommendations'])}")
        else:
            print(f"      * Error: {results['error']}")
        
        return results
        
    except Exception as e:
        print(f"      * PageSpeed analysis error: {e}")
        return {"error": str(e)} 