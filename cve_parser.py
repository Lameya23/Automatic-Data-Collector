import json
from pathlib import Path

# --- Hardcoded Mock CVE Data (Simplified CVE 5.0 Format) ---
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

OUTPUT_FILE = "cve_database.json"

def extract_cve_data(cve_json):
    """
    Extracts required information from a single CVE JSON object (CVE 5.0 format).
    """
    cve_id = cve_json.get('cveMetadata', {}).get('cveId')
    
    # Get the description (title)
    descriptions = cve_json.get('containers', {}).get('cna', {}).get('descriptions', [])
    title = descriptions[0].get('value', 'No title available') if descriptions else 'No title available'
    
    # Get the affected products and versions
    affected_products = []
    affected_section = cve_json.get('containers', {}).get('cna', {}).get('affected', [])
    
    for affected in affected_section:
        product = affected.get('product', 'Unknown Product')
        vendor = affected.get('vendor', 'Unknown Vendor')
        
        # Extract affected versions
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

    # Get severity and problem type
    metrics = cve_json.get('containers', {}).get('cna', {}).get('metrics', [])
    severity = 'N/A'
    if metrics:
        # Assuming CVSS v3.1 is preferred if available
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
    """
    Uses the embedded MOCK_CVE_DATA to build a searchable database
    indexed by product name.
    """
    # The final database structure: { "product_name": [ {cve_data}, {cve_data}, ... ] }
    searchable_db = {}
    
    print(f"Processing {len(MOCK_CVE_DATA)} embedded CVE entries...")
    
    for cve_json in MOCK_CVE_DATA:
        try:
            extracted_data = extract_cve_data(cve_json)
            
            # Restructure data to be indexed by product
            for affected_product in extracted_data['affected_products']:
                product_name = affected_product['product']
                
                # Create a simplified CVE entry for the product index
                cve_entry = {
                    'cve_id': extracted_data['cve_id'],
                    'title': extracted_data['title'],
                    'severity': extracted_data['severity'],
                    'problem_types': extracted_data['problem_types'],
                    'vendor': affected_product['vendor'],
                    'versions': affected_product['versions']
                }
                
                # Add to the searchable database
                if product_name not in searchable_db:
                    searchable_db[product_name] = []
                
                searchable_db[product_name].append(cve_entry)
                
        except Exception as e:
            print(f"Error processing CVE {cve_json.get('cveMetadata', {}).get('cveId')}: {e}")

    # Save the final searchable database
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(searchable_db, f, indent=4)
        
    print(f"\nSuccessfully created self-contained searchable database: {OUTPUT_FILE}")
    print(f"Total unique products indexed: {len(searchable_db)}")
    
    return searchable_db
if __name__ == "__main__":
    build_searchable_database_from_mock()
