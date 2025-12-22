import platform
import socket
import getpass
import datetime
import json
import atexit
import time
from pathlib import Path
import subprocess
import sys

# --- Hardcoded Configuration ---
LOG_FILE_PATH = Path("collected_data.json")
START_TIME = datetime.datetime.now()
USAGE_COUNTER = 0

# --- Embedded Mock CVE Data (Simplified CVE 5.0 Format) ---
# This data is embedded to ensure the script runs on any system without external files.
MOCK_CVE_DATA = [
    {
        "cveMetadata": {"cveId": "CVE-2025-0001"},
        "containers": {
            "cna": {
                "descriptions": [{"value": "Critical vulnerability in Apache HTTP Server allowing remote code execution."}],
                "affected": [
                    {
                        "vendor": "Apache Software Foundation",
                        "product": "Apache HTTP Server",
                        "versions": [
                            {"version": "2.4.50", "status": "affected", "lessThan": "2.4.58", "versionType": "semver"}
                        ]
                    }
                ],
                "metrics": [
                    {"cvssV3_1": {"baseSeverity": "CRITICAL"}}
                ],
                "problemTypes": [
                    {"descriptions": [{"description": "Remote Code Execution"}]}
                ]
            }
        }
    },
    {
        "cveMetadata": {"cveId": "CVE-2025-0002"},
        "containers": {
            "cna": {
                "descriptions": [{"value": "Information disclosure in OpenSSL due to buffer overflow."}],
                "affected": [
                    {
                        "vendor": "OpenSSL",
                        "product": "OpenSSL",
                        "versions": [
                            {"version": "3.0.0", "status": "affected", "lessThan": "3.0.10", "versionType": "semver"},
                            {"version": "1.1.1", "status": "affected", "lessThan": "1.1.1w", "versionType": "semver"}
                        ]
                    }
                ],
                "metrics": [
                    {"cvssV3_1": {"baseSeverity": "HIGH"}}
                ],
                "problemTypes": [
                    {"descriptions": [{"description": "Buffer Overflow"}]}
                ]
            }
        }
    },
    {
        "cveMetadata": {"cveId": "CVE-2025-0003"},
        "containers": {
            "cna": {
                "descriptions": [{"value": "Cross-Site Scripting (XSS) in WordPress core."}],
                "affected": [
                    {
                        "vendor": "WordPress Foundation",
                        "product": "WordPress",
                        "versions": [
                            {"version": "6.0", "status": "affected", "lessThan": "6.4.3", "versionType": "semver"}
                        ]
                    }
                ],
                "metrics": [
                    {"cvssV3_1": {"baseSeverity": "MEDIUM"}}
                ],
                "problemTypes": [
                    {"descriptions": [{"description": "Cross-Site Scripting (XSS)"}]}
                ]
            }
        }
    }
]

# --- Vulnerability Analysis Functions (Adapted from cve_parser.py) ---

def extract_cve_data(cve_json):
    """Extracts required information from a single CVE JSON object (CVE 5.0 format)."""
    cve_id = cve_json.get('cveMetadata', {}).get('cveId')
    
    descriptions = cve_json.get('containers', {}).get('cna', {}).get('descriptions', [])
    title = descriptions[0].get('value', 'No title available') if descriptions else 'No title available'
    
    affected_products = []
    affected_section = cve_json.get('containers', {}).get('cna', {}).get('affected', [])
    
    for affected in affected_section:
        product = affected.get('product', 'Unknown Product')
        vendor = affected.get('vendor', 'Unknown Vendor')
        
        versions = []
        for version_range in affected.get('versions', []):
            versions.append({
                'version': version_range.get('version', 'N/A'),
                'status': version_range.get('status', 'N/A'),
                'lessThan': version_range.get('lessThan', 'N/A'),
                'versionType': version_range.get('versionType', 'N/A')
            })
        
        affected_products.append({
            'vendor': vendor,
            'product': product,
            'versions': versions
        })

    metrics = cve_json.get('containers', {}).get('cna', {}).get('metrics', [])
    severity = 'N/A'
    if metrics:
        cvss_v31 = metrics[0].get('cvssV3_1', {})
        severity = cvss_v31.get('baseSeverity', 'N/A')
    
    problem_types = cve_json.get('containers', {}).get('cna', {}).get('problemTypes', [])
    type_list = []
    if problem_types:
        for type_group in problem_types:
            for description in type_group.get('descriptions', []):
                type_list.append(description.get('description', 'N/A'))

    return {
        'cve_id': cve_id,
        'title': title,
        'severity': severity,
        'problem_types': type_list,
        'affected_products': affected_products
    }

def build_searchable_database_from_mock():
    """Uses the embedded MOCK_CVE_DATA to build a searchable database indexed by product name."""
    searchable_db = {}
    
    for cve_json in MOCK_CVE_DATA:
        try:
            extracted_data = extract_cve_data(cve_json)
            
            for affected_product in extracted_data['affected_products']:
                product_name = affected_product['product']
                
                cve_entry = {
                    'cve_id': extracted_data['cve_id'],
                    'title': extracted_data['title'],
                    'severity': extracted_data['severity'],
                    'problem_types': extracted_data['problem_types'],
                    'vendor': affected_product['vendor'],
                    'versions': affected_product['versions']
                }
                
                if product_name not in searchable_db:
                    searchable_db[product_name] = []
                
                searchable_db[product_name].append(cve_entry)
                
        except Exception as e:
            # In a real scenario, this would log the error
            pass 
            
    return searchable_db

def lookup_vulnerabilities(installed_apps, cve_db):
    """
    Checks installed applications against the internal CVE database.
    NOTE: This is a simplified lookup (case-insensitive name match only).
    A real-world scanner requires version matching logic.
    """
    vulnerability_results = {}
    
    # Simple case-insensitive name matching
    for app_name in installed_apps:
        for product_name, cves in cve_db.items():
            if product_name.lower() in app_name.lower():
                # Found a potential match
                if app_name not in vulnerability_results:
                    vulnerability_results[app_name] = []
                
                # In a real scenario, we would now check the installed version
                # against the affected versions in 'cves' list.
                
                # For this self-contained example, we just list the potential CVEs
                # and add a note about the version check.
                for cve in cves:
                    vulnerability_results[app_name].append({
                        "cve_id": cve['cve_id'],
                        "title": cve['title'],
                        "severity": cve['severity'],
                        "vendor": cve['vendor'],
                        "note": "Version check required. This CVE affects versions: " + str(cve['versions'])
                    })
    
    if not vulnerability_results:
        vulnerability_results["STATUS"] = "No potential vulnerabilities found for installed applications in the embedded database."
    else:
        vulnerability_results["STATUS"] = "Potential vulnerabilities found. Requires manual version verification against the 'note' field."
        
    return vulnerability_results

# --- Data Collection Functions ---

def collect_system_info():
    """Collects system information automatically."""
    return {
        "os_system": platform.system(),
        "os_version": platform.version(),
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "collection_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def get_installed_apps():
    """
    Collects a list of installed application names based on the operating system.
    (Simplified for cross-platform compatibility)
    """
    os_name = platform.system()
    
    if os_name == "Linux":
        try:
            # Using dpkg-query to list installed packages
            result = subprocess.run(['dpkg-query', '-W', '-f=${Package}\n'], 
                                    capture_output=True, text=True, check=True)
            # Return a small subset for demonstration purposes
            return [app.strip() for app in result.stdout.splitlines() if app.strip()][:10] + ["Apache HTTP Server", "OpenSSL"]
        except Exception:
            return ["Could not retrieve installed apps on Linux (dpkg-query failed).", "Apache HTTP Server", "OpenSSL"]
            
    elif os_name == "Windows":
        return ["Placeholder for Windows App List", "OpenSSL", "Apache HTTP Server"]
        
    elif os_name == "Darwin": # macOS
        return ["Placeholder for macOS App List", "OpenSSL", "Apache HTTP Server"]
            
    else:
        return [f"App discovery not implemented for OS: {os_name}", "OpenSSL", "Apache HTTP Server"]

def track_button_click():
    """Simulates a hardcoded button click tracking."""
    global USAGE_COUNTER
    USAGE_COUNTER += 1
    print(f"Simulated button click. Total count: {USAGE_COUNTER}")

def save_data_on_exit():
    """Saves all collected data automatically to the hardcoded path on program exit."""
    end_time = datetime.datetime.now()
    
    # 1. Collect Data
    system_data = collect_system_info()
    installed_apps = get_installed_apps()
    
    # 2. Build Internal CVE DB and Analyze
    cve_db = build_searchable_database_from_mock()
    vulnerability_results = lookup_vulnerabilities(installed_apps, cve_db)
    
    # 3. Finalize Usage Data
    usage_data = {
        "program_start": START_TIME.strftime("%Y-%m-%d %H:%M:%S"),
        "program_end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "button_clicks_count": USAGE_COUNTER
    }
    
    # 4. Construct Final Log
    final_log = {
        "system_info": system_data,
        "installed_apps": installed_apps,
        "vulnerability_analysis": vulnerability_results,
        "usage_data": usage_data
    }
    
    try:
        with open(LOG_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(final_log, f, indent=4)
        print(f"\n[INFO] Data saved automatically to {LOG_FILE_PATH}")
    except Exception as e:
        print(f"\n[ERROR] Failed to save data: {e}")

# Register the function to be called automatically upon program termination
atexit.register(save_data_on_exit)

# --- Main Program Logic ---

def main():
    print("[INFO] Program started. Collecting system info and installed apps...")
    
    # Simulate user interaction and usage tracking
    print("[INFO] Simulating user interaction...")
    time.sleep(1)
    track_button_click()
    time.sleep(1)
    track_button_click()
    time.sleep(1)
    track_button_click()
    
    print("[INFO] Program running for a few seconds...")
    time.sleep(2)
    print("[INFO] Program finished. Data will be saved and analyzed automatically.")

if __name__ == "__main__":
    main()
