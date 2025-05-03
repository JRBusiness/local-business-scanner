import csv
import json

from config import load_config


config = load_config()

def save_results_csv(results, filename):
    """Saves the list of scan dictionaries to a CSV file."""
    if not results:
        print("No results to save.")
        return
    print(f"\nSaving results to {filename}...")
    try:
        # Define headers dynamically? Simpler to predefine expected top-level keys + some details
        # This needs refinement based on exactly what you want in the CSV.
        # Flattening the nested structure is key for CSV.
        headers = [
            'url', 'scan_timestamp', 'reachable', 'final_url', 'status_code', 'error',
            'is_https', 'seo_title', 'seo_meta_desc', 'seo_h1_count', 'seo_imgs_missing_alt',
            'sec_csp', 'sec_hsts', 'sec_xfo', 'sec_xcto', # Security headers
            'links_broken_internal_count', 'links_broken_external_count',
            'mixed_content_status',
            'tech_detected', # Example: Join detected tech names
            'pagespeed_score', 'pagespeed_lcp', 'pagespeed_cls' # Example PageSpeed
        ]

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore') # Ignore extra fields
            writer.writeheader()
            for result in results:
                flat_row = {
                    'url': result.get('url'),
                    'scan_timestamp': result.get('scan_timestamp'),
                    'reachable': result.get('reachable'),
                    'final_url': result.get('final_url'),
                    'status_code': result.get('status_code'),
                    'error': result.get('error'),
                }
                details = result.get('scan_details', {})
                flat_row['is_https'] = details.get('is_https')

                seo = details.get('seo_basics', {})
                flat_row['seo_title'] = seo.get('title')
                flat_row['seo_meta_desc'] = seo.get('meta_description')
                flat_row['seo_h1_count'] = seo.get('h1_count')
                flat_row['seo_imgs_missing_alt'] = seo.get('images_missing_alt')

                sec = details.get('security_headers', {})
                flat_row['sec_csp'] = sec.get('content_security_policy')
                flat_row['sec_hsts'] = sec.get('strict_transport_security')
                flat_row['sec_xfo'] = sec.get('x_frame_options')
                flat_row['sec_xcto'] = sec.get('x_content_type_options')

                links = details.get('links', {})
                flat_row['links_broken_internal_count'] = len(links.get('broken_internal', []))
                flat_row['links_broken_external_count'] = len(links.get('broken_external', []))

                flat_row['mixed_content_status'] = details.get('mixed_content', {}).get('status')

                tech = details.get('technology', {})
                if isinstance(tech, dict) and 'error' not in tech :
                     flat_row['tech_detected'] = ", ".join([f"{k}: {v}" for k, v_list in tech.items() for v in v_list])[:200] # Simple representation
                elif isinstance(tech, dict):
                     flat_row['tech_detected'] = tech.get('error', 'Detection Error')
                else:
                     flat_row['tech_detected'] = "N/A"


                ps = details.get('pagespeed', {})
                if 'error' not in ps:
                    flat_row['pagespeed_score'] = ps.get('performance_score')
                    flat_row['pagespeed_lcp'] = ps.get('lcp')
                    flat_row['pagespeed_cls'] = ps.get('cls')
                else:
                     flat_row['pagespeed_score'] = ps.get('error', 'API Error')

                js_info = details.get('js_errors_selenium', {})
                flat_row['js_errors_status'] = js_info.get('status')
                js_errors_list = js_info.get('js_errors', [])
                flat_row['js_errors_count'] = len(js_errors_list)
                if js_errors_list:
                    # Get first error message, truncate if long
                    first_msg = js_errors_list[0].get('message', '')
                    flat_row['js_errors_first_msg'] = (first_msg[:150] + '...') if len(first_msg) > 150 else first_msg
                else:
                    flat_row['js_errors_first_msg'] = ''
                writer.writerow(flat_row)
        print("CSV file saved successfully.")

    except IOError as e:
        print(f"Error saving CSV file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during CSV saving: {e}")


def save_results_json(results, filename):
    """Saves the list of raw scan result dictionaries to a JSON file."""
    if not results:
        return
    print(f"Saving results to {filename}...")
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        print("JSON file saved successfully.")
    except IOError as e:
        print(f"Error saving JSON file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during JSON saving: {e}")

def print_summary_report(results):
    """Prints a simple summary to the console."""
    print("\n\n--- Scan Summary Report ---")
    if not results:
        print("No websites were scanned.")
        return

    total_scanned = len(results)
    reachable_count = sum(1 for r in results if r['reachable'])
    error_count = total_scanned - reachable_count
    https_count = sum(1 for r in results if r['reachable'] and r.get('scan_details', {}).get('is_https'))
    missing_title = sum(1 for r in results if r['reachable'] and r.get('scan_details', {}).get('seo_basics', {}).get('title') == 'Missing')
    broken_links_sites = sum(1 for r in results if r['reachable'] and r.get('scan_details', {}).get('links', {}).get('broken_internal'))
    js_error_sites = sum(1 for r in results if r['reachable'] and r.get('scan_details', {}).get('js_errors_selenium', {}).get('js_errors')) # <-- Add this line

    print(f"Total Websites Processed: {total_scanned}")
    print(f"Successfully Reached & Scanned: {reachable_count}")
    print(f"Errors / Unreachable: {error_count}")
    print(f"Using HTTPS (of reachable): {https_count}")
    print(f"Sites with Missing Title Tag: {missing_title}")
    print(f"Sites with Broken Internal Links: {broken_links_sites}")
    print(f"Sites with Severe JS Errors: {js_error_sites}") # <-- Add this line

    # Add more summary points as needed

    print("\n--- End of Summary ---")
    print(f"Detailed results saved to {config.get('output_file_csv')} and {config.get('output_file_json')}")