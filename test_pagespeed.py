import sys
import json
import time
from pagespeed_analyzer import analyze_pagespeed_inhouse

def test_pagespeed(url):
    """Test the PageSpeed analysis for a given URL."""
    print(f"Testing PageSpeed analysis for: {url}")
    start_time = time.time()
    
    # Configure analyzer
    config = {
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'headless': True,
        'webdriver_path': None
    }
    
    # Run analysis
    results = analyze_pagespeed_inhouse(url, config)
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    
    # Print results in a formatted way
    if results and not results.get('error'):
        metrics = results.get('metrics', {})
        score = results.get('score', 0)
        recommendations = results.get('recommendations', [])
        
        print("\nPageSpeed Results:")
        print("=================")
        print(f"Overall Score: {score}/100")
        
        print("\nKey Metrics:")
        print(f"- LCP (Largest Contentful Paint): {metrics.get('lcp', 'N/A'):.2f}s" if metrics.get('lcp') else f"- LCP: N/A")
        print(f"- FCP (First Contentful Paint): {metrics.get('fcp', 'N/A'):.2f}s" if metrics.get('fcp') else f"- FCP: N/A")
        print(f"- CLS (Cumulative Layout Shift): {metrics.get('cls', 'N/A'):.3f}" if metrics.get('cls') else f"- CLS: N/A")
        print(f"- TTFB (Time to First Byte): {metrics.get('ttfb', 'N/A'):.2f}s" if metrics.get('ttfb') else f"- TTFB: N/A")
        print(f"- Page Weight: {metrics.get('page_weight', 'N/A'):.2f}MB" if metrics.get('page_weight') else f"- Page Weight: N/A")
        print(f"- Resource Count: {metrics.get('resource_count', 'N/A')}" if metrics.get('resource_count') else f"- Resource Count: N/A")
        
        if recommendations:
            print("\nTop Recommendations:")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"{i}. {rec.get('name')}: {rec.get('description')}")
        
        # Print resource breakdown if available
        if 'resource_metrics' in results and 'resource_breakdown' in results['resource_metrics']:
            breakdown = results['resource_metrics']['resource_breakdown']
            print("\nResource Breakdown:")
            for res_type, data in breakdown.items():
                size_mb = data.get('size_bytes', 0) / (1024 * 1024)
                print(f"- {res_type.capitalize()}: {data.get('count', 0)} files, {size_mb:.2f}MB")
    else:
        print(f"\nError: {results.get('error', 'Unknown error occurred')}")
    
    print(f"\nAnalysis completed in {elapsed_time:.2f} seconds")
    
    # Output as JSON
    print("\nJSON Output (sample):")
    print("============")
    # Print a limited version for readability
    simplified = {
        "score": results.get('score'),
        "metrics": results.get('metrics'),
        "error": results.get('error')
    }
    print(json.dumps(simplified, indent=2))
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide a URL to test.")
        print("Usage: python test_pagespeed.py <url>")
        sys.exit(1)
        
    url = sys.argv[1]
    test_pagespeed(url) 