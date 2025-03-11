from port_scanner.port_scanner import run_scanner
from packet_sniffer.packet_sniffer import main as packet_sniffer_main
from ids.ids import IntrusionDetectionSystem
import time
from threading import Thread
import json
import requests
import sys
import os
import argparse

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

config_path = os.path.join(BASE_DIR, 'config.json')

with open(config_path, 'r') as f:
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
        parser = argparse.ArgumentParser(description='Network Security System For Neural Shield')
        parser.add_argument('--no-sniffer', action='store_true', help='Disable packet sniffer (Not recommended)')
        parser.add_argument('--no-ids', action='store_true', help='Disable intrusion detection system (Not recommended)')
        parser.add_argument('--no-scanner', action='store_true', help='Disable port scanner (Not recommended)')
        parser.add_argument('--license-key', type=str, help='License key to authorize')
        args = parser.parse_args()
        if not args.license_key:
            if config['license_key'] == "":
                print("Please enter a license key to authorize. Use \"--license-key <key>\" to authorize.")
                exit()
        else:
            with open(config_path, 'w') as f:
                config['license_key'] = args.license_key
                json.dump(config, f, indent=2)
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
                    print(f"License key authorization failed: {response.status_code}\nError: {response.text}\nCheck your subscription status at https://neuralshieldai.com/.")
                    with open(config_path, 'w') as f:
                        config['license_key'] = ""
                        json.dump(config, f, indent=2)
                    print("Exiting...")
                    exit()
            except Exception as e:
                print(f"License key authorization error: {e}")
                print("Exiting...")
                exit()

        if not args.no_sniffer:
            sniffer_thread = Thread(target=run_packet_sniffer)
            sniffer_thread.daemon = True
            sniffer_thread.start()
        else:
            print("Packet sniffer disabled.")

        if not args.no_ids:
            ids_thread = Thread(target=run_ids)
            ids_thread.daemon = True
            ids_thread.start()
        else:
            print("Intrusion detection system disabled.")

        if not args.no_scanner:
            run_port_scanner()
        else:
            print("Port scanner disabled.")

    except KeyboardInterrupt:
        print("\nMain program stopping...")
    except Exception as e:
        print(f"Main program error: {e}")