import json

def load_config(config_path="config.json"):
    """Loads configuration from a JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            # Basic validation
            if not config.get("google_api_key"):
                print("WARNING: 'google_api_key' not found in config.json. Some features will be disabled.")
            if not config.get("builtwith_api_key"):
                print("WARNING: 'builtwith_api_key' not found in config.json. Some features will be disabled.")
            return config
    except FileNotFoundError:
        print(f"ERROR: Configuration file '{config_path}' not found.")
        exit(1)
    except json.JSONDecodeError:
        print(f"ERROR: Configuration file '{config_path}' contains invalid JSON.")
        exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        exit(1)
        
