import platform
import socket
import getpass
import datetime
import json
import atexit
import time # Used for simulating program runtime

# --- Hardcoded Configuration ---
LOG_FILE_PATH = "/home/ubuntu/collected_data.json"
START_TIME = datetime.datetime.now()
USAGE_COUNTER = 0 # Hardcoded counter for a specific action

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
    usage_data = {
        "program_start": START_TIME.strftime("%Y-%m-%d %H:%M:%S"),
        "program_end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "button_clicks_count": USAGE_COUNTER
    }
    
    final_log = {
        "system_info": system_data,
        "usage_data": usage_data
    }
    
    try:
        with open(LOG_FILE_PATH, 'w') as f:
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
