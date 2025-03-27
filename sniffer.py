#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Packet Sniffer
----------------------
An advanced packet capturing tool that monitors all network traffic and captures packets.

This tool performs low-level packet capturing using raw sockets and
displays all packets in detail. It also periodically sends collected logs
to the specified API URL.
"""

import socket
import struct
import time
import sys
import os
import argparse
import json
import binascii
import threading
import requests
from collections import defaultdict
from datetime import datetime

# Colors for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'
BOLD = '\033[1m'

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

config_path = os.path.join(BASE_DIR, 'config.json')

with open(config_path, "r") as f:
    config_file = json.load(f)

# API Settings
API_URL = config_file['api_url'] + "sniffer-log/"
API_TOKEN = config_file['api_token']
LICENSE_KEY = config_file['license_key']
LOG_INTERVAL = 120

# Global variables
total_packets = 0
ip_protocols = {}  # Tracks number of protocols
packet_stats = {
    'tcp': 0,
    'udp': 0,
    'icmp': 0,
    'dns': 0,
    'http': 0,
    'other': 0
}

# Variables for log collection
collected_logs = []
log_lock = threading.Lock()  # Lock for thread safety


class EthernetFrame:
    """Ethernet frame parser"""
    def __init__(self, raw_data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = self.get_mac_addr(dest_mac)
        self.src_mac = self.get_mac_addr(src_mac)
        self.proto = socket.htons(proto)
        self.data = raw_data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()


class IPv4Packet:
    """IPv4 packet parser"""
    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4_format(src)
        self.target = self.ipv4_format(target)
        self.data = raw_data[self.header_length:]

    def ipv4_format(self, addr):
        return '.'.join(map(str, addr))


class TCPSegment:
    """TCP segment parser"""
    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment,
         offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flags = offset_reserved_flags & 0x3F  # 6 bit flags
        self.flag_urg = (self.flags & 32) >> 5
        self.flag_ack = (self.flags & 16) >> 4
        self.flag_psh = (self.flags & 8) >> 3
        self.flag_rst = (self.flags & 4) >> 2
        self.flag_syn = (self.flags & 2) >> 1
        self.flag_fin = self.flags & 1
        self.data = raw_data[offset:]
        
        # HTTP detection (simple) - only checks the most common methods
        self.is_http = False
        if len(self.data) > 10:
            http_methods = [b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ']
            for method in http_methods:
                if self.data.startswith(method):
                    self.is_http = True
                    break


class UDPSegment:
    """UDP segment parser"""
    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H H 2x', raw_data[:8])
        self.data = raw_data[8:]
        
        # DNS packet detection (port 53)
        self.is_dns = (self.src_port == 53 or self.dest_port == 53)


class ICMPPacket:
    """ICMP packet parser"""
    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]


class DNSPacket:
    """DNS packet parser (simple)"""
    def __init__(self, raw_data):
        try:
            self.transaction_id = struct.unpack('! H', raw_data[:2])[0]
            self.flags = struct.unpack('! H', raw_data[2:4])[0]
            self.questions = struct.unpack('! H', raw_data[4:6])[0]
            self.is_query = (self.flags & 0x8000) == 0  # QR flag
            self.domain = self.parse_dns_name(raw_data, 12) if self.questions > 0 else ""
        except:
            self.domain = ""
            self.is_query = False
            
    def parse_dns_name(self, data, offset):
        """Parses DNS name fields."""
        domain_parts = []
        i = offset
        while True:
            length = data[i]
            if length == 0:
                break
            # Check for DNS name compression
            if (length & 0xC0) == 0xC0:  # If top 2 bits are 1, it's compressed
                pointer = struct.unpack('! H', data[i:i+2])[0] & 0x3FFF
                return '.'.join(domain_parts) + '.' + self.parse_dns_name(data, pointer)
            i += 1
            if i + length > len(data):
                return '.'.join(domain_parts)
            domain_parts.append(data[i:i+length].decode('utf-8', errors='ignore'))
            i += length
        return '.'.join(domain_parts)


def format_output(prefix, msg, color=WHITE):
    """Helper function for colored terminal output"""
    return f"{color}{prefix}{RESET} {msg}"


def print_ethernet_frame(frame):
    """Prints Ethernet frame information"""
    print(format_output("[ETH]", f"Source MAC: {frame.src_mac} -> Destination MAC: {frame.dest_mac}", BLUE))


def print_ipv4_packet(packet):
    """Prints IPv4 packet information"""
    print(format_output("[IPv4]", f"Source IP: {packet.src} -> Destination IP: {packet.target} (TTL: {packet.ttl})", GREEN))


def print_tcp_segment(segment):
    """Prints TCP segment information"""
    flags = []
    if segment.flag_urg: flags.append("URG")
    if segment.flag_ack: flags.append("ACK")
    if segment.flag_psh: flags.append("PSH")
    if segment.flag_rst: flags.append("RST")
    if segment.flag_syn: flags.append("SYN")
    if segment.flag_fin: flags.append("FIN")
    
    flags_str = ' '.join(flags) if flags else "None"
    
    print(format_output("[TCP]", 
          f"Port: {segment.src_port} -> {segment.dest_port} | "
          f"Flags: {flags_str}", YELLOW))


def print_udp_segment(segment):
    """Prints UDP segment information"""
    print(format_output("[UDP]", f"Port: {segment.src_port} -> {segment.dest_port} | Size: {segment.size}", MAGENTA))


def print_icmp_packet(packet):
    """Prints ICMP packet information"""
    icmp_types = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
        13: "Timestamp"
    }
    
    type_str = icmp_types.get(packet.type, f"Type {packet.type}")
    
    print(format_output("[ICMP]", f"{type_str} | Code: {packet.code}", CYAN))


def get_available_interfaces():
    """Returns available network interfaces on the system"""
    interfaces = []
    
    # Check interfaces on Linux via /sys/class/net
    if os.path.exists('/sys/class/net'):
        for iface in os.listdir('/sys/class/net'):
            interfaces.append(iface)
    
    return interfaces


def collect_log_entry(log_type, data):
    """Creates a log entry and adds it to the global log list"""
    global collected_logs
    
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'type': log_type,
        'data': data
    }
    
    # Use lock for thread safety
    with log_lock:
        collected_logs.append(log_entry)


def send_logs_to_api():
    """Sends collected logs to the API"""
    global collected_logs
    
    # Use lock for thread safety
    with log_lock:
        if not collected_logs:
            print(format_output("[API]", "No logs found to send.", YELLOW))
            return
        
        # Copy logs to send and clear the list
        logs_to_send = collected_logs.copy()
        collected_logs = []
    
    # Show log count
    print(format_output("[API]", f"Sending {len(logs_to_send)} logs to API...", CYAN))
    
    # Data preparation for API
    headers = {
        "Authorization": f"Token {API_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "license_key": LICENSE_KEY,
        "results": logs_to_send
    }
    
    # Send POST request to API
    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=10)
        
        if response.status_code == 200:
            print(format_output("[API]", f"Logs sent successfully. Response: {response.text}", GREEN))
        else:
            print(format_output("[API]", f"Log submission failed. Status code: {response.status_code}", RED))
            print(format_output("[API]", f"Response: {response.text}", RED))
            
            # Add logs back if failed
            with log_lock:
                collected_logs.extend(logs_to_send)
                
    except requests.exceptions.RequestException as e:
        print(format_output("[API]", f"API connection error: {str(e)}", RED))
        
        # Add logs back if connection error
        with log_lock:
            collected_logs.extend(logs_to_send)


def api_sender_thread():
    """Thread that periodically sends logs to the API"""
    print(format_output("[API]", f"Log sending service started. Logs will be sent every {LOG_INTERVAL} seconds.", GREEN))
    
    while True:
        # Wait for LOG_INTERVAL (2 minutes)
        time.sleep(LOG_INTERVAL)
        
        # Send logs to API
        send_logs_to_api()


def packet_handler():
    """Main packet processing function. Listens to the network and processes incoming packets."""
    global total_packets, ip_protocols, packet_stats
    
    # Start API log sender thread
    api_thread = threading.Thread(target=api_sender_thread, daemon=True)
    api_thread.start()
    
    # Create raw socket for IPv4
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    try:
        # Bind to specified interface
        if args.interface:
            conn.bind((args.interface, 0))
    except (socket.error, OSError) as e:
        print(format_output("[ERROR]", f"Interface binding error: {e}", RED))
        print(format_output("[INFO]", f"Available interfaces: {', '.join(get_available_interfaces())}", YELLOW))
        sys.exit(1)
    
    start_time = time.time()
    print(format_output("[START]", 
          f"Packet capture started - Interface: {args.interface or 'all'}", GREEN + BOLD))
    print(format_output("[INFO]", "Press CTRL+C to stop", YELLOW))
    
    try:
        while True:
            current_time = time.time()
            
            # Maximum duration check
            if args.duration > 0 and (current_time - start_time) > args.duration:
                print(format_output("[INFO]", f"Specified duration ({args.duration}s) has elapsed.", YELLOW))
                break
            
            raw_data, addr = conn.recvfrom(65536)
            total_packets += 1
            
            # Packet timestamp
            packet_time = datetime.fromtimestamp(current_time).strftime('%H:%M:%S.%f')[:-3]
            print(f"\n{BOLD}{packet_time}{RESET} - Packet #{total_packets}")
            
            # Parse Ethernet frame
            eth = EthernetFrame(raw_data)
            print_ethernet_frame(eth)
            
            # IPv4 Packet
            if eth.proto == 8:  # IPv4
                ipv4 = IPv4Packet(eth.data)
                print_ipv4_packet(ipv4)
                
                # Create log record - IPv4
                ipv4_log = {
                    'src_ip': ipv4.src,
                    'dst_ip': ipv4.target,
                    'ttl': ipv4.ttl,
                    'proto': ipv4.proto
                }
                collect_log_entry('ipv4', ipv4_log)
                
                # Update protocol statistics
                ip_protocols[ipv4.proto] = ip_protocols.get(ipv4.proto, 0) + 1
                
                # TCP
                if ipv4.proto == 6:  # TCP
                    packet_stats['tcp'] += 1
                    tcp = TCPSegment(ipv4.data)
                    print_tcp_segment(tcp)
                    
                    # Create log record - TCP
                    tcp_log = {
                        'src_ip': ipv4.src,
                        'dst_ip': ipv4.target,
                        'src_port': tcp.src_port,
                        'dst_port': tcp.dest_port,
                        'flags': {
                            'urg': tcp.flag_urg,
                            'ack': tcp.flag_ack,
                            'psh': tcp.flag_psh,
                            'rst': tcp.flag_rst,
                            'syn': tcp.flag_syn,
                            'fin': tcp.flag_fin
                        }
                    }
                    collect_log_entry('tcp', tcp_log)
                    
                    # Is it an HTTP packet?
                    if tcp.is_http:
                        packet_stats['http'] += 1
                        http_data = tcp.data[:100].decode('utf-8', 'ignore').replace('\n', ' ')
                        print(format_output("[HTTP]", http_data, CYAN))
                        
                        # Create log record - HTTP
                        http_log = {
                            'src_ip': ipv4.src,
                            'dst_ip': ipv4.target,
                            'src_port': tcp.src_port,
                            'dst_port': tcp.dest_port,
                            'data': http_data
                        }
                        collect_log_entry('http', http_log)
                    
                    # Show packet content (first 16 bytes in hex format)
                    if len(tcp.data) > 0:
                        data_hex = binascii.hexlify(tcp.data[:16]).decode('utf-8')
                        print(format_output("[CONTENT]", f"Hex: {data_hex}...", WHITE))
                
                # UDP
                elif ipv4.proto == 17:  # UDP
                    packet_stats['udp'] += 1
                    udp = UDPSegment(ipv4.data)
                    print_udp_segment(udp)
                    
                    # Create log record - UDP
                    udp_log = {
                        'src_ip': ipv4.src,
                        'dst_ip': ipv4.target,
                        'src_port': udp.src_port,
                        'dst_port': udp.dest_port,
                        'size': udp.size
                    }
                    collect_log_entry('udp', udp_log)
                    
                    # Is it a DNS packet?
                    if udp.is_dns:
                        packet_stats['dns'] += 1
                        dns = DNSPacket(udp.data)
                        if dns.domain:
                            query_type = "Query" if dns.is_query else "Response"
                            print(format_output("[DNS]", f"{query_type}: {dns.domain}", CYAN))
                            
                            # Create log record - DNS
                            dns_log = {
                                'src_ip': ipv4.src,
                                'dst_ip': ipv4.target,
                                'query_type': query_type,
                                'domain': dns.domain
                            }
                            collect_log_entry('dns', dns_log)
                    
                    # Show packet content (first 16 bytes in hex format)
                    if len(udp.data) > 0:
                        data_hex = binascii.hexlify(udp.data[:16]).decode('utf-8')
                        print(format_output("[CONTENT]", f"Hex: {data_hex}...", WHITE))
                
                # ICMP
                elif ipv4.proto == 1:  # ICMP
                    packet_stats['icmp'] += 1
                    icmp = ICMPPacket(ipv4.data)
                    print_icmp_packet(icmp)
                    
                    # Create log record - ICMP
                    icmp_log = {
                        'src_ip': ipv4.src,
                        'dst_ip': ipv4.target,
                        'type': icmp.type,
                        'code': icmp.code
                    }
                    collect_log_entry('icmp', icmp_log)
                
                # Other protocols
                else:
                    packet_stats['other'] += 1
                    print(format_output("[PROTO]", f"Protocol: {ipv4.proto}", WHITE))
            
            # Show statistics every 100 packets
            if total_packets % 100 == 0:
                print("\n" + "="*50)
                print(format_output("[STATISTICS]", 
                      f"Total Packets: {total_packets} | "
                      f"TCP: {packet_stats['tcp']} | UDP: {packet_stats['udp']} | "
                      f"ICMP: {packet_stats['icmp']} | DNS: {packet_stats['dns']} | "
                      f"HTTP: {packet_stats['http']}", GREEN))
                print("="*50)
                
                # Show collected log count
                with log_lock:
                    print(format_output("[LOG]", f"Total logs collected so far: {len(collected_logs)}", CYAN))
    
    except KeyboardInterrupt:
        print(format_output("\n[STOP]", "Stopped by user", YELLOW))
    
    finally:
        # Send remaining logs to API
        if len(collected_logs) > 0:
            print(format_output("[API]", "Sending remaining logs...", CYAN))
            send_logs_to_api()
            
        # Show results
        show_results(start_time)
        
        # Create JSON report if requested
        if args.output:
            save_report(start_time, args.output)


def show_results(start_time):
    """Shows capture results"""
    duration = time.time() - start_time
    print("\n" + "="*80)
    print(format_output("[RESULT]", f"Packet Capture Summary", GREEN + BOLD))
    print(format_output("[DURATION]", f"{duration:.2f} seconds", GREEN))
    print(format_output("[PACKETS]", f"Total packets captured: {total_packets}", GREEN))
    if total_packets > 0:
        print(format_output("[RATE]", f"Packets/second: {total_packets/duration:.2f}", GREEN))
    
    print("\n" + format_output("[STATISTICS]", f"Protocol Distribution", BLUE + BOLD))
    for proto, count in packet_stats.items():
        if count > 0:
            percent = (count / total_packets) * 100 if total_packets > 0 else 0
            print(format_output(f"[{proto.upper()}]", f"{count} packets ({percent:.1f}%)", BLUE))


def save_report(start_time, filename):
    """Saves results in JSON format"""
    duration = time.time() - start_time
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'duration': duration,
        'total_packets': total_packets,
        'packet_rate': total_packets/duration if duration > 0 else 0,
        'packet_stats': packet_stats
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(format_output("[SAVE]", f"Report saved to '{filename}'", GREEN))
    except Exception as e:
        print(format_output("[ERROR]", f"Could not save report: {e}", RED))


if __name__ == "__main__":
    # Root permission check
    if os.geteuid() != 0:
        print(format_output("[ERROR]", 
              "This application requires root privileges. Run with 'sudo'.", RED))
        sys.exit(1)
    
    # Process command line arguments
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument('-i', '--interface', help='Network interface to listen on (e.g.: eth0)')
    parser.add_argument('-v', '--verbose', action='store_true', default=True, help='Enable verbose output mode')
    parser.add_argument('-d', '--duration', type=int, default=0, 
                        help='Capture duration (seconds, 0=unlimited)')
    parser.add_argument('-o', '--output', help='JSON report output file')
    parser.add_argument('-l', '--list', action='store_true', help='List available network interfaces')
    parser.add_argument('-r', '--raw', action='store_true', help='Show raw packet content')
    
    args = parser.parse_args()
    
    # Update API settings from command line
    
    # List interfaces and exit
    if args.list:
        interfaces = get_available_interfaces()
        print(format_output("[INTERFACES]", "Available network interfaces:", GREEN))
        for i, iface in enumerate(interfaces, 1):
            print(format_output(f"  {i}.", iface, CYAN))
        sys.exit(0)
    
    # Ask user if no interface specified
    if not args.interface:
        interfaces = get_available_interfaces()
        print(format_output("[INTERFACES]", "Available network interfaces:", GREEN))
        for i, iface in enumerate(interfaces, 1):
            print(format_output(f"  {i}.", iface, CYAN))
        
        try:
            idx = int(input("\nEnter the number of the interface you want to select (or 0 for all interfaces): "))
            if idx > 0 and idx <= len(interfaces):
                args.interface = interfaces[idx-1]
            elif idx != 0:
                print(format_output("[ERROR]", "Invalid interface number.", RED))
                sys.exit(1)
        except ValueError:
            print(format_output("[ERROR]", "Invalid input.", RED))
            sys.exit(1)
    
    # Start main packet processing function
    packet_handler()
