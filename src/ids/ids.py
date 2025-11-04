"""
config dosyasından ids_log değişkenini 2 yaparsan loglar terminalde görünür.
"""

import time
from scapy.all import sniff, TCP, IP
from collections import defaultdict
import os
import sys
import json
from datetime import datetime

with open('config.json', 'r') as f:
    config = json.load(f)

def write_to_json(packet_data):
    file_path = 'logs/ids_logs/ids_logs.json'
    
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

class IntrusionDetectionSystem:
    def __init__(self, syn_threshold=20, scan_threshold=15, time_window=5):
        self.syn_threshold = syn_threshold
        self.scan_threshold = scan_threshold
        self.time_window = time_window
        
        self.syn_packets = defaultdict(lambda: {
            'count': 0,
            'first_seen': 0,
            'ports': set()
        })
        self.port_scan_tracker = {}

    def packet_callback(self, packet):
        if os.path.exists("scanner_running.signal"):
            return

        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip_src = packet[IP].src
        tcp_layer = packet[TCP]
        flags = tcp_layer.flags
        dest_port = tcp_layer.dport
        current_time = time.time()

        if flags & 0x02:
            if ip_src not in self.syn_packets:
                self.syn_packets[ip_src] = {
                    'count': 1,
                    'first_seen': current_time,
                    'ports': {dest_port}
                }
            else:
                if current_time - self.syn_packets[ip_src]['first_seen'] > self.time_window:
                    self.syn_packets[ip_src] = {
                        'count': 1,
                        'first_seen': current_time,
                        'ports': {dest_port}
                    }
                else:
                    self.syn_packets[ip_src]['count'] += 1
                    self.syn_packets[ip_src]['ports'].add(dest_port)
                    
                    if (self.syn_packets[ip_src]['count'] >= self.syn_threshold and
                        len(self.syn_packets[ip_src]['ports']) < 5):
                        alert_message = f"""[ALERT] SYN Flood attack detected! Date: {datetime.now()}
Source IP: {ip_src}
Last {self.time_window} seconds: {self.syn_packets[ip_src]['count']} SYN packets
Number of destination ports: {len(self.syn_packets[ip_src]['ports'])}
{'-' * 50}"""
                        packet_data = {
                            "alert_message": f"[ALERT] SYN Flood attack detected! Date: {datetime.now()}",
                            "source_ip": str(ip_src),
                            "packet_count": f"{self.syn_packets[ip_src]['count']} SYN packets in {self.time_window} seconds",
                            "number_of_destination_ports": len(self.syn_packets[ip_src]['ports'])
                        }
                        write_to_json(packet_data)
                        if config['ids']['ids_log'] == "config":
                            write_to_json(packet_data)
                        elif config['ids']['ids_log'] == "terminal":
                            print(alert_message)
                        
                        self.syn_packets[ip_src] = {
                            'count': 0,
                            'first_seen': current_time,
                            'ports': set()
                        }

        if ip_src not in self.port_scan_tracker:
            self.port_scan_tracker[ip_src] = {}
        self.port_scan_tracker[ip_src][dest_port] = current_time

        self.port_scan_tracker[ip_src] = {port: t for port, t in self.port_scan_tracker[ip_src].items() if current_time - t < self.time_window}
        if len(self.port_scan_tracker[ip_src]) >= self.scan_threshold:
            alert_message = {
                "alert_message": f"[ALERT] Potential port scan attack detected. {ip_src}! Date: {datetime.now()}",
                "source_ip": str(ip_src),
                "packet_count": f"{self.syn_packets[ip_src]['count']} SYN packets in {self.time_window} seconds",
                "number_of_destination_ports": len(self.port_scan_tracker[ip_src])
            }
            
            if config['ids']['ids_log'] == 'config':
                write_to_json(alert_message)
            elif config['ids']['ids_log'] == 'terminal':
                print(alert_message)
                
            self.port_scan_tracker[ip_src] = {}

    def start(self, iface=None):
        if os.geteuid() != 0:
            print("[!] This program requires root privileges.")
            print("Please run with 'sudo python src/ids/ids.py'")
            sys.exit(1)
        start_message ="[*] IDS system starting... Packet sniffing started..."
        packet_data = {
            "message": start_message
        }
        if config['ids']['ids_log'] == 'config':
            write_to_json(packet_data)
        elif config['ids']['ids_log'] == 'terminal':
            print(start_message)
        try:
            sniff(prn=self.packet_callback, iface=iface, store=False)
        except Exception as e:
            print(f"[!] Error: {e}")
        except KeyboardInterrupt:
            print("[*] IDS system stopped.")

if __name__ == "__main__":
    ids = IntrusionDetectionSystem(
        syn_threshold=config['ids']['syn_threshold'],
        scan_threshold=config['ids']['scan_threshold'],
        time_window=config['ids']['time_window']
    )
    ids.start(iface=None)