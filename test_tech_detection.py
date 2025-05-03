import sys
import json
from technology_detector import detect_technology_inhouse

def test_tech_detection(url):
    """Test the technology detection for a given URL."""
    print(f"Testing technology detection for: {url}")
    tech_info = detect_technology_inhouse(url)
    
    # Print results in a formatted way
    if tech_info and not tech_info.get("error"):
        print("\nDetected Technologies:")
        print("=====================")
        for category, technologies in tech_info.items():
            print(f"\n{category.upper()}:")
            for tech in technologies:
                print(f"  - {tech}")
    else:
        print(f"\nError: {tech_info.get('error', 'No technologies detected')}")
    
    # Output as JSON
    print("\nJSON Output:")
    print("============")
    print(json.dumps(tech_info, indent=2))
    
    return tech_info

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide a URL to test.")
        print("Usage: python test_tech_detection.py <url>")
        sys.exit(1)
        
    url = sys.argv[1]
    test_tech_detection(url) 