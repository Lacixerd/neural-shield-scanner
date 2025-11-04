from ip_discover.ip_discover import discover_active_ips
import json
import time
import datetime
import os

with open("trusted_ips.json", "r") as f:
    trusted_ips = json.load(f)

with open("config.json", "r") as f:
    config = json.load(f)

SCAN_INTERVAL = int(config["unusual_ip_finder"]["scan_interval"])

def write_to_json(packet_data):
    file_path = 'logs/unusual_ip_finder_logs/unusual_ip_logs.json'
    
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)
    
    with open(file_path, 'r') as f:
        try:
            existing_data = json.load(f)
        except json.JSONDecodeError:
            existing_data = []
    
    existing_data.append(packet_data)
    
    with open(file_path, 'w') as f:
        json.dump(existing_data, f, indent=2)

def log_unusual_ips(unusual_ips):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"Unusual IP's detected: {', '.join(unusual_ips)}"
        packet_data = {
            "date": timestamp,
            "message": log_entry
        }
        write_to_json(packet_data)

    except Exception as e:
        print(f"Log file could not be written: {str(e)}")

def log_message(message):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        packet_data = {
            "date": timestamp,
            "message": message
        }
        write_to_json(packet_data)
    except Exception as e:
        print(f"Log file could not be written: {str(e)}")

def main(target_range=config["scanner"]["target_range"]):
    try:
        while True:
            log_message("[*] Unusual IP Finder starting...\n")
            active_ips = discover_active_ips(target_range)
            unusual_ips = [ip for ip in active_ips if ip not in trusted_ips]
            
            if unusual_ips:
                log_unusual_ips(unusual_ips)
            else:
                log_message("All active ips are trusted devices.\n")
            time.sleep(SCAN_INTERVAL)
    except Exception as e:
        log_message(f"[!] Error: {str(e)}\n")

if __name__ == "__main__":
    main()