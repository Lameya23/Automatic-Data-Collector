
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
import sqlite3

# --- Hardcoded Configuration ---
DB_FILE_PATH = Path("cve_database.db")
LOG_FILE_PATH = Path("collected_data.json")
START_TIME = datetime.datetime.now()
USAGE_COUNTER = 0

# --- Embedded Mock CVE Data (Simplified CVE 5.0 Format) ---
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

# --- Database Functions ---

def initialize_db():
    """Initializes the SQLite database with required tables."""
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()
    
    # Table 1: Vulnerabilities (Main CVE info)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT PRIMARY KEY,
            title TEXT,
            severity TEXT,
            vendor TEXT
        )
    """)
    
    # Table 2: Products (Software/Hardware affected)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    """)
    
    # Table 4: Aliases (Alternative names for products)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS aliases (
            alias_id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            alias_name TEXT UNIQUE,
            FOREIGN KEY (product_id) REFERENCES products(product_id)
        )
    """)
    
    # Table 3: Affected Versions (Detailed version info)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS affected_versions (
            version_id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            product_id INTEGER,
            version TEXT,
            status TEXT,
            less_than TEXT,
            version_type TEXT,
            FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id),
            FOREIGN KEY (product_id) REFERENCES products(product_id)
        )
    """)
    
    conn.commit()
    conn.close()

def get_or_create_product_id(cursor, product_name):
    """Gets the product_id if it exists, otherwise creates it and returns the new ID."""
    cursor.execute("SELECT product_id FROM products WHERE name = ?", (product_name,))
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        cursor.execute("INSERT INTO products (name) VALUES (?)", (product_name,))
        return cursor.lastrowid

def populate_db_from_mock():
    """Populates the SQLite database using the embedded MOCK_CVE_DATA."""
    initialize_db()
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()
    
    print(f"[INFO] Populating SQLite DB with {len(MOCK_CVE_DATA)} embedded CVE entries...")
    
    for cve_json in MOCK_CVE_DATA:
        try:
            extracted_data = extract_cve_data(cve_json)
            cve_id = extracted_data['cve_id']
            
            # 1. Insert into vulnerabilities table
            cursor.execute("INSERT OR IGNORE INTO vulnerabilities (cve_id, title, severity, vendor) VALUES (?, ?, ?, ?)",
                           (cve_id, extracted_data['title'], extracted_data['severity'], extracted_data['affected_products'][0]['vendor']))
            
            # 2. Insert into products and affected_versions tables
            for affected_product in extracted_data['affected_products']:
                product_name = affected_product['product']
                vendor = affected_product['vendor']
                
                product_id = get_or_create_product_id(cursor, product_name)
                
                # Insert mock aliases for the hardcoded products
                if product_name == "Apache HTTP Server":
                    cursor.execute("INSERT OR IGNORE INTO aliases (product_id, alias_name) VALUES (?, ?)", (product_id, "httpd"))
                    cursor.execute("INSERT OR IGNORE INTO aliases (product_id, alias_name) VALUES (?, ?)", (product_id, "apache2"))
                elif product_name == "OpenSSL":
                    cursor.execute("INSERT OR IGNORE INTO aliases (product_id, alias_name) VALUES (?, ?)", (product_id, "libssl"))
                    cursor.execute("INSERT OR IGNORE INTO aliases (product_id, alias_name) VALUES (?, ?)", (product_id, "openssl-libs"))
                
                for version_info in affected_product['versions']:
                    cursor.execute("""
                        INSERT INTO affected_versions 
                        (cve_id, product_id, version, status, less_than, version_type) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (cve_id, product_id, version_info['version'], version_info['status'], 
                          version_info['lessThan'], version_info['versionType']))
            
        except Exception as e:
            print(f"[ERROR] Failed to populate CVE {cve_json.get('cveMetadata', {}).get('cveId')}: {e}")
            
    conn.commit()
    conn.close()
    print("[INFO] SQLite DB population complete.")

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

def lookup_vulnerabilities(installed_apps):
    """
    Checks installed applications against the internal SQLite CVE database.
    NOTE: This is a simplified lookup (case-insensitive name match only).
    A real-world scanner requires version matching logic.
    """
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()
    vulnerability_results = {}
    
    # Placeholder for the actual lookup logic
    for app_name in installed_apps:
        # Find product_ids matching the app_name in either the products table or the aliases table
        cursor.execute("""
            SELECT product_id FROM products WHERE name = ?
            UNION
            SELECT product_id FROM aliases WHERE alias_name = ?
        """, (app_name, app_name))
        
        matching_product_ids = [row[0] for row in cursor.fetchall()]
        
        if not matching_product_ids:
            # Try a fuzzy match (LIKE) if exact match fails
            cursor.execute("""
                SELECT product_id FROM products WHERE name LIKE ?
                UNION
                SELECT product_id FROM aliases WHERE alias_name LIKE ?
            """, ('%' + app_name + '%', '%' + app_name + '%'))
            matching_product_ids = [row[0] for row in cursor.fetchall()]
            
        if not matching_product_ids:
            continue # No match found, move to the next app
            
        # Convert list of IDs to a comma-separated string for the IN clause
        product_ids_str = ','.join(map(str, matching_product_ids))
        
        # SQL query to retrieve all CVEs for the matching product IDs
        cursor.execute(f"""
            SELECT 
                v.cve_id, v.title, v.severity, v.vendor, 
                av.version, av.status, av.less_than, av.version_type
            FROM vulnerabilities v
            JOIN affected_versions av ON v.cve_id = av.cve_id
            WHERE av.product_id IN ({product_ids_str})
        """)
        
        results = cursor.fetchall()
        
        if results:
            if app_name not in vulnerability_results:
                vulnerability_results[app_name] = []
                
            for row in results:
                cve_id, title, severity, vendor, version, status, less_than, version_type = row
                
                vulnerability_results[app_name].append({
                    "cve_id": cve_id,
                    "title": title,
                    "severity": severity,
                    "vendor": vendor,
                    "affected_version": version,
                    "status": status,
                    "less_than": less_than,
                    "note": "Version check required. This CVE affects versions: " + str(version)
                })
    
    conn.close()
    
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
    # Initialize and populate the DB if it doesn't exist or is empty
    populate_db_from_mock()
    vulnerability_results = lookup_vulnerabilities(installed_apps)
    
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

