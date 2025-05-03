import requests

def get_session(session=None):
    """
    Helper function to get a session object for making requests.
    Uses the provided session if available, otherwise creates a new one.
    This ensures that modules use the proxy configuration from the scanner.
    
    Args:
        session (requests.Session): Session object from scanner
        
    Returns:
        requests.Session: Session to use for requests
    """
    return session if session else requests.Session()
