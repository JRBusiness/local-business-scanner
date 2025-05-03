import googlemaps
import time
import json
import requests
from urllib.parse import urlparse

def get_business_websites_via_places_api(api_key, query, location, max_results=20):
    """Finds businesses and their websites using Google Places API Text Search."""
    print(f"Finding businesses for query: '{query}' near '{location}' via Google Places API...")
    gmaps = googlemaps.Client(key=api_key)
    websites = set()
    full_query = f"{query} in {location}"
    places_result = None

    try:
        places_result = gmaps.places(query=full_query)

        while places_result and len(websites) < max_results:
            for place in places_result.get('results', []):
                website = place.get('website')
                name = place.get('name')
                if website:
                    # Basic validation and normalization
                    parsed = urlparse(website)
                    if parsed.scheme and parsed.netloc:
                        # Prefer https if available, but store original if not specified
                        scheme = parsed.scheme if parsed.scheme else 'http'
                        # Remove www. for simpler comparison later? Maybe not necessary here.
                        normalized_url = f"{scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
                        if normalized_url not in websites:
                             print(f"  Found: {name} -> {normalized_url}")
                             websites.add(normalized_url)
                             if len(websites) >= max_results:
                                 break
                    else:
                        print(f"  Skipping invalid URL for {name}: {website}")


            if len(websites) >= max_results:
                break

            # Handle pagination
            next_page_token = places_result.get('next_page_token')
            if next_page_token:
                print("  Fetching next page...")
                time.sleep(2) # Required delay before requesting next page
                places_result = gmaps.places(query=full_query, page_token=next_page_token)
            else:
                break # No more pages

    except googlemaps.exceptions.ApiError as e:
        print(f"  ERROR: Google Places API Error: {e}")
    except Exception as e:
        print(f"  ERROR: Unexpected error during Places API call: {e}")

    print(f"Finder finished. Found {len(websites)} unique websites.")
    return list(websites)

def get_business_websites_via_nearby_search(api_key, business_type, location, radius=5000, max_results=20, language_code="en"):
    """
    Finds businesses and their websites using the new Google Places API Nearby Search endpoint.
    
    Args:
        api_key: Google Maps API key
        business_type: Type of business to search for (e.g. 'restaurant', 'cafe')
        location: Location name or coordinates as a string (e.g. "New York, NY" or "40.7128,-74.0060")
        radius: Radius to search within in meters (max 50000)
        max_results: Maximum number of results to return (max 20)
        language_code: Language code for results (default 'en')
        
    Returns:
        A list of unique website URLs for the found businesses
    """
    print(f"Finding {business_type} businesses near '{location}' via Google Places API Nearby Search...")
    
    # Ensure max_results is within allowed range
    if max_results > 20:
        max_results = 20
    
    # Check if location is already in lat,lng format
    lat = None
    lng = None
    
    # Check if location is in the format "lat,lng" or "lat, lng"
    if isinstance(location, str) and ',' in location:
        try:
            parts = location.split(',')
            if len(parts) == 2:
                lat = float(parts[0].strip())
                lng = float(parts[1].strip())
                print(f"  Using provided coordinates: {lat}, {lng}")
        except ValueError:
            # Not a valid lat,lng format, continue with geocoding
            pass
    
    # If we don't have valid lat/lng yet, try geocoding
    if lat is None or lng is None:
        print(f"  Geocoding address: {location}")
        geocode_url = f"https://maps.googleapis.com/maps/api/geocode/json?address={location}&key={api_key}"
        try:
            geocode_response = requests.get(geocode_url).json()
            if geocode_response['status'] != 'OK':
                print(f"  ERROR: Failed to geocode location: {geocode_response['status']}")
                if 'error_message' in geocode_response:
                    print(f"  ERROR Details: {geocode_response['error_message']}")
                return []
            
            lat = geocode_response['results'][0]['geometry']['location']['lat']
            lng = geocode_response['results'][0]['geometry']['location']['lng']
            print(f"  Geocoded to coordinates: {lat}, {lng}")
        except Exception as e:
            print(f"  ERROR: Failed to perform geocoding: {e}")
            return []
    
    try:
        # Create the request body for Nearby Search
        request_body = {
            "includedTypes": [business_type],
            "maxResultCount": max_results,
            "locationRestriction": {
                "circle": {
                    "center": {
                        "latitude": lat,
                        "longitude": lng
                    },
                    "radius": float(radius)
                }
            }
        }
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "X-Goog-Api-Key": api_key,
            "X-Goog-FieldMask": "places.displayName,places.formattedAddress,places.websiteUri"
        }
        
        # Make the request
        nearby_url = "https://places.googleapis.com/v1/places:searchNearby"
        response = requests.post(nearby_url, json=request_body, headers=headers)
        response.raise_for_status()
        
        # Process response
        places_data = response.json()
        websites = set()
        
        if 'places' in places_data:
            for place in places_data['places']:
                name = place.get('displayName', {}).get('text', 'Unknown')
                website = place.get('websiteUri')
                
                if website:
                    # Basic validation and normalization
                    parsed = urlparse(website)
                    if parsed.scheme and parsed.netloc:
                        # Prefer https if available, but store original if not specified
                        scheme = parsed.scheme if parsed.scheme else 'http'
                        normalized_url = f"{scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
                        if normalized_url not in websites:
                            print(f"  Found: {name} -> {normalized_url}")
                            websites.add(normalized_url)
                    else:
                        print(f"  Skipping invalid URL for {name}: {website}")
        
        print(f"Finder finished. Found {len(websites)} unique websites.")
        return list(websites)
    
    except requests.exceptions.RequestException as e:
        print(f"  ERROR: API Request Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                print(f"  ERROR Details: {error_data}")
            except:
                print(f"  Status Code: {e.response.status_code}")
                print(f"  Response Content: {e.response.text[:500]}")
    except Exception as e:
        print(f"  ERROR: Unexpected error during Nearby Search API call: {e}")
    
    return []

# --- Add fallback/alternative methods here if needed (e.g., scraping specific directories) ---
# Remember the caveats about scraping reliability and ToS.