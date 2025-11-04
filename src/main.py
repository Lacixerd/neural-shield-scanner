from port_scanner.port_scanner import run_scanner
from packet_sniffer.packet_sniffer import main as packet_sniffer_main
from ids.ids import IntrusionDetectionSystem
from unusual_ip_finder.unusual_ip_finder import main as unusual_ip_finder_main
import time
from threading import Thread
import json

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
        sniffer_thread = Thread(target=run_packet_sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()

        ids_thread = Thread(target=run_ids)
        ids_thread.daemon = True
        ids_thread.start()

        unusual_ip_finder_thread = Thread(target=unusual_ip_finder_main)
        unusual_ip_finder_thread.daemon = True
        unusual_ip_finder_thread.start()

        run_port_scanner()
    except KeyboardInterrupt:
        print("\nMain program stopping...")
    except Exception as e:
        print(f"Main program error: {e}")