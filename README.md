# Local Business Website Scanner

A comprehensive tool for discovering, analyzing, and security scanning websites of local businesses.

## Overview

This project provides an automated solution to discover local business websites via Google Places API and perform comprehensive technical analysis, including:

- Website technology detection (frameworks, CMS, libraries)
- Performance analysis (PageSpeed metrics)
- Security vulnerability scanning
- SEO and best practices assessment
- Login page detection

## Features

### Business Discovery
- Google Places API integration for finding local businesses by category and location
- Nearby search with configurable radius and result limits
- Support for numerous business categories

### Technology Detection
- In-house technology detection for frameworks (React, Angular, Vue, etc.)
- CMS identification (WordPress, Drupal, Shopify, etc.)
- Analytics tools detection (Google Analytics, Facebook Pixel, etc.)
- Server technology identification (Apache, Nginx, Cloudflare, etc.)

### Performance Analysis
- In-house PageSpeed analysis
- Integration with Google PageSpeed Insights API (optional)
- Core Web Vitals metrics (LCP, CLS, etc.)

### Security Scanning
- Comprehensive vulnerability scanning
- Header security analysis
- Login page detection
- SSL/TLS configuration checking
- XSS, SQL injection, and other vulnerability tests
- CSRF token validation
- Insecure dependencies detection

### Additional Features
- Multi-threaded scanning for better performance
- Proxy support (HTTP, HTTPS, SOCKS5)
- Retry mechanism with exponential backoff
- Detailed reporting in JSON and CSV formats
- Configurable scan parameters

## Requirements

- Python 3.7+
- Required packages listed in `requirements.txt`

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/local-business-scanner.git
cd local-business-scanner
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Configure your settings in `config.json`:
   - Add your Google API key
   - Set search location and business types
   - Configure proxy settings (if needed)
   - Adjust scanning parameters

## Usage

### Basic Usage

Run the scanner with default settings from config.json:

```
python main.py
```

### Scan Specific Websites

Provide one or more URLs to scan directly:

```
python main.py https://example1.com https://example2.com
```

### Command Line Options

```
python main.py --help
```

Some useful options:
- `-L, --find-login-only`: Only output results for sites with login pages
- `-t, --threads`: Set number of concurrent scans
- `--timeout`: Configure request timeout
- `-v, --verbose`: Enable verbose logging
- `-o, --output-dir`: Specify output directory for reports

## Configuration

The `config.json` file allows you to customize various aspects of the scanner:

- API keys and credentials
- Search parameters
- Proxy settings
- Scanning behavior and timeouts
- Output formats

## Output

- CSV summary reports of all scanned websites
- Detailed JSON reports for each website
- Option to only save sites with login pages detected

## License

See the LICENSE file for details.

## Disclaimer

This tool is intended for legitimate website analysis and security assessment. Always obtain proper authorization before scanning websites you don't own. The authors are not responsible for any misuse of this software. 