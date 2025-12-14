import platform
import socket
import getpass
import datetime
import json
import atexit
import time # Used for simulating program runtime
from pathlib import Path
import subprocess
import sys

# --- Hardcoded Configuration ---
# Use pathlib to define the log file path relative to the script's execution directory
LOG_FILE_PATH = Path("collected_data.json")
START_TIME = datetime.datetime.now()
USAGE_COUNTER = 0 # Hardcoded counter for a specific action

# --- Data Collection Functions ---

def get_installed_apps():
    """
    Collects a list of installed application names based on the operating system.
    Returns a list of strings or a message if discovery is not possible.
    """
    os_name = platform.system()
    
    if os_name == "Linux":
        # For Debian/Ubuntu-based systems, query installed packages
        try:
            # Using dpkg-query to list installed packages
            result = subprocess.run(['dpkg-query', '-W', '-f=${Package}\n'], 
                                    capture_output=True, text=True, check=True)
            # Filter out empty lines and return the list of package names
            return [app.strip() for app in result.stdout.splitlines() if app.strip()]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return ["Could not retrieve installed apps on Linux (dpkg-query failed or not found)."]
            
    elif os_name == "Windows":
        # On Windows, the most reliable way is querying the registry, 
        # which requires the 'winreg' module (not available on non-Windows systems).
        # A simpler, less reliable method is using wmic, but it's often slow.
        return ["App discovery on Windows requires querying the registry (e.g., HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall). This function is a placeholder on non-Windows systems."]
        
    elif os_name == "Darwin": # macOS
        # On macOS, applications are typically in /Applications
        try:
            # List contents of the Applications folder
            result = subprocess.run(['ls', '/Applications'], 
                                    capture_output=True, text=True, check=True)
            # Filter out system files and return the list of app names
            return [app.strip() for app in result.stdout.splitlines() if app.strip() and not app.startswith('.')]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return ["Could not retrieve installed apps on macOS (/Applications access failed or ls not found)."]
            
    else:
        return [f"App discovery not implemented for OS: {os_name}"]

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

def track_button_click():
    """Simulates a hardcoded button click tracking."""
    global USAGE_COUNTER
    USAGE_COUNTER += 1
    print(f"Simulated button click. Total count: {USAGE_COUNTER}")

def save_data_on_exit():
    """Saves all collected data automatically to the hardcoded path on program exit."""
    end_time = datetime.datetime.now()
    
    system_data = collect_system_info()
    installed_apps = get_installed_apps()
    usage_data = {
        "program_start": START_TIME.strftime("%Y-%m-%d %H:%M:%S"),
        "program_end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "button_clicks_count": USAGE_COUNTER
    }
    
    final_log = {
        "system_info": system_data,
        "installed_apps": installed_apps,
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
    print("[INFO] Program started. System info collected automatically at startup.")
    
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
    print("[INFO] Program finished. Data will be saved automatically.")

if __name__ == "__main__":
    main()
