import json
import argparse # For command-line arguments eventually
from config import load_config
from finder import get_business_websites_via_places_api, get_business_websites_via_nearby_search
from scanner import scan_website_advanced
from reporting import save_results_csv, save_results_json, print_summary_report
import time
import sys
import logging
import os
from urllib.parse import urlparse

from security_scanner import scan_multiple_websites # Added for saving results filename and checking IP

# Map user-friendly business types to Google Places API types
# See https://developers.google.com/maps/documentation/places/web-service/place-types for the full list
PLACES_API_TYPE_MAPPING = {
    "cafes": "cafe",
    "coffee shops": "cafe",
    "bookstores": "book_store",
    "bike shops": "bicycle_store",
    "motoshops": "car_repair",
    "restaurants": "restaurant",
    "hotels": "lodging",
    "real estate": "real_estate_agency",
    "lawyers": "lawyer",
    "doctors": "doctor",
    "dentists": "dentist", 
    "electricians": "electrician",
    "nails salons": "beauty_salon",
    "massage parlors": "spa",
    "pet stores": "pet_store",
    "pet groomers": "pet_store",
    "pet sitters": "pet_store",
    "gyms": "gym",
    "pharmacies": "pharmacy",
    "hardware stores": "hardware_store",
    "clothing stores": "clothing_store",
    "shoe stores": "shoe_store",
    "jewelry stores": "jewelry_store",
    "furniture stores": "furniture_store",
    "electronics stores": "electronics_store",
    "department stores": "department_store",
    "car dealerships": "car_dealer",
    "car repair": "car_repair",
    "gas stations": "gas_station",
    "banks": "bank",
    "atms": "atm",
    "post offices": "post_office",
    "schools": "school",
    "universities": "university",
    "museums": "museum",
    "art galleries": "art_gallery",
    "parks": "park",
    "places of worship": "place_of_worship",
    "movie theaters": "movie_theater",
    "night clubs": "night_club",
    "bars": "bar",
    "travel agencies": "travel_agency",
    "storage": "storage",
    "parking": "parking",
    "accounting": "accounting",
    "tax services": "accounting",
    "financial advisors": "finance",
    "insurance": "insurance_agency",
    "office supplies": "store",
    "coworking spaces": "establishment",
    "business centers": "establishment",
    "consulting firms": "establishment",
    "marketing agencies": "establishment",
    "web design": "establishment",
    "printing services": "establishment",
    "shipping services": "establishment",
    "online retailers": "store",
    "e-commerce": "store",
    "shopping malls": "shopping_mall",
    "outlet stores": "store",
    "specialty shops": "store"
}

# Configure logging for the main script as well
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

def main():
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Discover local business websites OR scan provided URLs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        'urls',
        metavar='URL',
        type=str,
        nargs='*', # Changed to '*' to make it optional
        help='Optional: One or more target URLs to scan directly (must start with http:// or https://). If not provided, discovery using config.json will be attempted.'
    )
    # --- Scanner specific args ---
    parser.add_argument(
        '-L', '--find-login-only',
        action='store_true',
        help='Only process/output results for sites where potential login pages were found.'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=1, # Default taken from config or this value
        help='Number of concurrent websites to scan.'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=15, # Default taken from config or this value
        help='Request timeout in seconds for scanner checks.'
    )
    parser.add_argument(
        '--oob-server',
        type=str,
        default=None, # Default taken from config or None
        help='Domain/URL of your Out-of-Band interaction server (overrides config).'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging (DEBUG level) for scanner details (overrides config).'
    )
    parser.add_argument(
        '-o', '--output-dir',
        type=str,
        default='scan_reports', # Default taken from config or this value
        help='Directory to save detailed JSON reports for each processed site.'
    )
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Disable saving individual JSON reports to the output directory.'
    )
    # --- Discovery specific args (Optional Overrides) ---
    parser.add_argument(
        '--config',
        type=str,
        default='config.json',
        help='Path to the configuration file (used for discovery if no URLs provided).'
    )
    # Add more overrides for config settings if needed, e.g.:
    # parser.add_argument('--location', type=str, help='Override search location from config.')
    # parser.add_argument('--business-types', type=str, nargs='+', help='Override business types from config.')
    # parser.add_argument('--api-key', type=str, help='Override Google API key from config.')

    args = parser.parse_args()

    # Check the current external IP address to verify proxy settings
    config = load_config(args.config)
    proxy_enabled = config.get('proxy', {}).get('enabled', False)

    # --- Determine URLs to Scan ---
    urls_to_scan = []
    config = None # Initialize config

    if args.urls:
        # Mode 1: URLs provided via command line
        logging.info("URLs provided via command line. Skipping discovery.")
        for url in args.urls:
            if url.startswith('http://') or url.startswith('https://'):
                urls_to_scan.append(url)
            else:
                logging.warning(f"Skipping invalid URL (must start with http:// or https://): {url}")
    else:
        # Mode 2: No URLs provided, attempt discovery using config
        logging.info("No URLs provided. Attempting discovery using configuration...")
        config = load_config(args.config)

        location_display = config.get("search_location_name", config.get("search_location"))
        logging.info(f"Discovery Config: Location='{location_display}', UserAgent='{config.get('user_agent')}'")
        
        discovered_websites = set()
        api_key = config.get("google_api_key") # Use API key from loaded config
        skip_finding = False
        if api_key:
            search_types = config.get("search_query_business_types", [])
            search_location = config.get("search_location")
            max_results = config.get("max_results_per_type")
            search_radius = config.get("search_radius_meters", 5000)

            if not search_types or not search_location:
                 logging.error("Configuration error: 'search_query_business_types' and 'search_location' must be set in config for discovery.")
            else:
                with open('categories.txt', 'r') as f:
                    categories = f.readlines()
                    if categories:
                        ran_search_types = [category.strip() for category in categories]
                        if ran_search_types == search_types:
                            skip_finding = True
                            with open('discovered_websites.txt', 'r') as f:
                                websites = f.readlines()
                                if websites:
                                    discovered_websites = set(websites)
                if not skip_finding:
                    # Use the appropriate API method based on configuration
                    if config.get("use_new_places_api", False):
                        logging.info("Using new Google Places Nearby Search API for discovery...")
                        for business_type in search_types:
                            places_api_type = PLACES_API_TYPE_MAPPING.get(business_type.lower(), business_type)
                            logging.info(f"Searching for type: {business_type} (API type: {places_api_type})")
                            found = get_business_websites_via_nearby_search(
                                api_key, places_api_type, search_location,
                                radius=search_radius, max_results=max_results
                            )
                            discovered_websites.update(found)
                            time.sleep(0.5) # Small delay
                    else:
                        logging.info("Using legacy Google Places Text Search API for discovery...")
                        for business_type in search_types:
                            logging.info(f"Searching for type: {business_type}")
                            query = f"{business_type}" # Modify query if needed for text search
                            found = get_business_websites_via_places_api(
                                api_key, query, search_location, max_results
                            )
                            discovered_websites.update(found)
                            time.sleep(0.5) # Small delay
        else:
            logging.warning("Skipping Google Places API discovery - 'google_api_key' not found in config.")
            # Implement alternative finding methods here if desired

        if discovered_websites:
            logging.info(f"Discovery found {len(discovered_websites)} unique websites.")
            urls_to_scan = sorted(list(discovered_websites))
            with open('discovered_websites.txt', 'w') as f:
                for url in urls_to_scan:
                    f.write(url + '\n')
            with open("categories.txt", "w") as f:
                for business_type in search_types:
                    f.write(business_type + '\n')
        else:
             logging.warning("Discovery did not find any websites to scan based on the configuration.")

    # --- Exit if no URLs ---
    if not urls_to_scan:
        logging.error("No valid URLs to scan (either provided or discovered). Exiting.")
        sys.exit(1)

    # --- Build Scanner Configuration ---
    # Prioritize command-line args over config file values if config was loaded
    scanner_config = {}
    if config: # Load defaults from config if discovery mode was used
        scanner_config = {
            'scan_timeout': config.get('scan_timeout'),
            'max_threads': config.get('max_threads'),
            'verbose_security_scan': config.get('verbose_security_scan'),
            'oob_server_url': config.get('oob_server_url'),
            'user_agent': config.get('user_agent'), # Pass user agent from config
             # Pass other relevant config items needed by scanner/modules
        }
    if args.urls:
    # Always override with command-line args if they differ from defaults
        scanner_config['scan_timeout'] = args.timeout
        scanner_config['max_threads'] = args.threads
        scanner_config['verbose_security_scan'] = args.verbose
        if args.oob_server is not None: # Allow command line to explicitly set None
            scanner_config['oob_server_url'] = args.oob_server

    # Set logging level based on final verbosity setting
    log_level = logging.DEBUG if scanner_config['verbose_security_scan'] else logging.INFO
    logging.getLogger().setLevel(log_level)

    # --- Run Scans ---
    logging.info(f"Starting scans for {len(urls_to_scan)} URLs...")
    all_scan_results = scan_multiple_websites(urls_to_scan, scanner_config)
    logging.info("All scanning tasks completed.")

    # --- Filter Results (if requested) ---
    results_to_process = {}
    if args.find_login_only:
        logging.info("Filtering results for sites with potential login pages...")
        for url, result in all_scan_results.items():
             findings = result.get('findings', {})
             login_findings = findings.get('login_page_discovery')
             if login_findings and isinstance(login_findings, list) and len(login_findings) > 0:
                 results_to_process[url] = result
        logging.info(f"Found {len(results_to_process)} sites matching the login page criteria.")
        if not results_to_process: logging.info("No sites with potential login pages found.")
    else:
        results_to_process = all_scan_results

    # --- Save Individual Reports (Optional) ---
    output_dir = args.output_dir or (config and config.get("output_dir")) or "scan_reports" # Get output dir precedence
    if not args.no_save and results_to_process:
        logging.info(f"Saving detailed reports to directory: {output_dir}")
        os.makedirs(output_dir, exist_ok=True)
        for url, result in results_to_process.items():
            try:
                parsed_url = urlparse(url)
                filename_base = parsed_url.netloc.replace('.', '_').replace(':', '_p')
                path_part = parsed_url.path.replace('/', '_').strip('_')
                if path_part: filename_base += '_' + path_part[:30]
                filename = f"{filename_base}.json"
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=4, ensure_ascii=False)
            except Exception as e:
                logging.error(f"Failed to save report for {url} to {filepath}: {e}")

    elif args.no_save:
        logging.info("Skipping saving of individual reports as requested by --no-save.")

    # --- Final Summary ---
    logging.info(f"Processing complete. Processed results for {len(results_to_process)} sites.")
    # Note: Individual site summaries are printed by security_scanner.py during the scan


if __name__ == "__main__":
    # Required libraries check (basic)
    try:
        import googlemaps
        import requests
        import bs4
        import builtwith
        import re  # Required for in-house technology detection
        import concurrent.futures  # Required for in-house PageSpeed analysis
        import statistics  # Required for in-house PageSpeed analysis
        import urllib3  # Required for security scanner
        import dns.resolver  # Required for DNS checks in security scanner
        # import selenium # Optional
    except ImportError as e:
        print(f"ERROR: Missing required library: {e.name}. Please install requirements.")
        print("Try: pip install googlemaps requests beautifulsoup4 python-builtwith concurrent-futures statistics dnspython urllib3")
        # print("Optional for JS checks and PageSpeed: pip install selenium")
        exit(1)

    main()