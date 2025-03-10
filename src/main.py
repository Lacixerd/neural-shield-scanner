from port_scanner.port_scanner import run_scanner
from packet_sniffer.packet_sniffer import main as packet_sniffer_main
from ids.ids import IntrusionDetectionSystem
import time
from threading import Thread
import json
import requests

with open('config.json', 'r') as f:
    config = json.load(f)

def run_packet_sniffer():
    try:
        packet_sniffer_main()
    except Exception as e:
        print(f"Packet sniffer error: {e}")
    except KeyboardInterrupt:
        print("Packet sniffer stopping...")

def run_ids():
    try:
        ids = IntrusionDetectionSystem(
        syn_threshold=config['ids']['syn_threshold'],
        scan_threshold=config['ids']['scan_threshold'],
        time_window=config['ids']['time_window']
        )
        ids.start(iface=None)
    except KeyboardInterrupt:
        print("IDS stopping...")
    except Exception as e:
        print(f"IDS error: {e}")

def run_port_scanner():
    while True:
        try:
            run_scanner()
            print("Scanning completed successfully. Next scan in 1 hour...")
            time.sleep(3600)
        except KeyboardInterrupt:
            print("Port scanner stopping...")
            break
        except Exception as e:
            print(f"Port Scanner Error: {e}")
            time.sleep(5)
            continue

if __name__ == "__main__":
    try:
        if config['license_key'] == "":
            print("License key not found in config.json")
            exit()
        url = config['api_url'] + "authorize-license-key/"
        headers = {
            "Authorization": f"Token {config['api_token']}",
            "Content-Type": "application/json"
        }
        payload = {
            "license_key": config['license_key']
        }
        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.status_code == 200:
                print("License key authorized successfully.")
            else:
                print(f"License key authorization failed: {response.status_code}")
                exit()
        except Exception as e:
            print(f"License key authorization error: {e}")
        # sniffer_thread = Thread(target=run_packet_sniffer)
        # sniffer_thread.daemon = True
        # sniffer_thread.start()

        ids_thread = Thread(target=run_ids)
        ids_thread.daemon = True
        ids_thread.start()

        run_port_scanner()
    except KeyboardInterrupt:
        print("\nMain program stopping...")
    except Exception as e:
        print(f"Main program error: {e}")