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
# Removed: import sqlite3

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

# --- NoSQL (MongoDB) Simulation Functions ---

def get_program_id(program_name, programs_collection, program_name_to_id):
    """Gets the program_id if it exists, otherwise creates it and returns the new ID."""
    if program_name in program_name_to_id:
        return program_name_to_id[program_name]
    
    # Simple auto-incrementing ID simulation
    new_id = len(programs_collection) + 1
    
    # Mock Aliases for the hardcoded products
    aliases = []
    if program_name == "Apache HTTP Server":
        aliases = ["httpd", "apache2"]
    elif program_name == "OpenSSL":
        aliases = ["libssl", "openssl-libs"]
        
    programs_collection[new_id] = {
        "program_id": new_id,
        "program_name": program_name,
        "vendor": "Unknown Vendor", # Extracted from CVE data later
        "aliases": aliases
    }
    program_name_to_id[program_name] = new_id
    return new_id

def build_nosql_collections_from_mock():
    """
    Populates the three in-memory collections (programs, cves, affected) 
    using the embedded MOCK_CVE_DATA.
    """
    programs_collection = {}  # {id: {name, aliases}}
    cves_collection = {}      # {cve_id: {title, severity}}
    affected_collection = []  # [{program_id, cve_id, versions}]
    
    # Helper map for quick lookup and preventing program name duplication
    program_name_to_id = {}
    
    print(f"[INFO] Building NoSQL collections with {len(MOCK_CVE_DATA)} embedded CVE entries...")
    
    for cve_json in MOCK_CVE_DATA:
        try:
            extracted_data = extract_cve_data(cve_json)
            cve_id = extracted_data['cve_id']
            
            # 1. Populate cves collection
            cves_collection[cve_id] = {
                "cve_id": cve_id,
                "title": extracted_data['title'],
                "severity": extracted_data['severity'],
                "vendor": extracted_data['affected_products'][0]['vendor']
            }
            
            # 2. Populate programs and affected collections
            for affected_product in extracted_data['affected_products']:
                program_name = affected_product['product']
                
                program_id = get_program_id(program_name, programs_collection, program_name_to_id)
                
                # Update vendor info in programs collection
                programs_collection[program_id]['vendor'] = affected_product['vendor']
                
                # Populate affected collection
                affected_collection.append({
                    "program_id": program_id,
                    "cve_id": cve_id,
                    "versions": affected_product['versions']
                })
            
        except Exception as e:
            print(f"[ERROR] Failed to process CVE {cve_json.get('cveMetadata', {}).get('cveId')}: {e}")
            
    print("[INFO] NoSQL collection build complete.")
    return programs_collection, cves_collection, affected_collection

# --- Vulnerability Analysis Functions (Core Logic) ---

def extract_cve_data(cve_json):
    """Extracts required information from a single CVE JSON object (CVE 5.0 format)."""
    # ... (Same as before) ...
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

def lookup_vulnerabilities(installed_apps, programs_collection, cves_collection, affected_collection):
    """
    Checks installed applications against the in-memory NoSQL-like collections.
    """
    vulnerability_results = {}
    
    # Helper map for quick lookup of program names/aliases to program_id
    alias_to_id = {}
    for p_id, program in programs_collection.items():
        alias_to_id[program['program_name'].lower()] = p_id
        for alias in program['aliases']:
            alias_to_id[alias.lower()] = p_id

    for app_name in installed_apps:
        # 1. Find matching program_id using name or alias
        app_name_lower = app_name.lower()
        
        # Simple exact match
        matching_program_id = alias_to_id.get(app_name_lower)
        
        # If no exact match, try fuzzy match (simple substring check)
        if not matching_program_id:
            for alias_lower, p_id in alias_to_id.items():
                if app_name_lower in alias_lower or alias_lower in app_name_lower:
                    matching_program_id = p_id
                    break
        
        if not matching_program_id:
            continue # No match found, move to the next app

        # 2. Find all CVEs linked to this program_id in the affected collection
        for affected_entry in affected_collection:
            if affected_entry['program_id'] == matching_program_id:
                cve_id = affected_entry['cve_id']
                cve_data = cves_collection.get(cve_id)
                program_data = programs_collection.get(matching_program_id)
                
                if app_name not in vulnerability_results:
                    vulnerability_results[app_name] = []
                
                # 3. Compile the final result
                vulnerability_results[app_name].append({
                    "cve_id": cve_id,
                    "title": cve_data['title'],
                    "severity": cve_data['severity'],
                    "vendor": cve_data['vendor'],
                    "affected_versions": affected_entry['versions'],
                    "note": "Version check required. This CVE affects versions listed in 'affected_versions'."
                })
    
    if not vulnerability_results:
        vulnerability_results["STATUS"] = "No potential vulnerabilities found for installed applications in the embedded database."
    else:
        vulnerability_results["STATUS"] = "Potential vulnerabilities found. Requires manual version verification against the 'affected_versions' field."
        
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
    
    # 2. Build Internal NoSQL Collections and Analyze
    programs_col, cves_col, affected_col = build_nosql_collections_from_mock()
    vulnerability_results = lookup_vulnerabilities(installed_apps, programs_col, cves_col, affected_col)
    
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
