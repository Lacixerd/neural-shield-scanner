"""
Bu Kod MacOs Cihazlarda çalışmaz çünkü AF_PACKET soket türü Macos Cihazlarda desteklenmiyor. 
Kod öalıştırılacaksa Linux cihazlarda çalışır anca.

Packet Sniffer loglarının yazıldığı dosya: logs/packet_sniffer_logs/sniffer_logs.json
Eğer terminalde gözükmesini istiyorsan printlerin başındaki commentleri kaldır ve sadece bu dosyayı çalıştır
"""

import socket
import struct
import textwrap
import json
from datetime import datetime
import os
import time
import sys
import zlib
import base64

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def is_scanner_running():
    return os.path.exists("scanner_running.signal")

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    def write_to_json(packet_data):
        if is_scanner_running():
            return
            
        file_path = 'logs/packet_sniffer_logs/sniffer_logs.json'
        
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
        
        # Veriyi sıkıştır ve terminalde göster
        compressed = compress_data(packet_data)
        
        # Sıkıştırma oranını hesapla
        original_size = len(json.dumps(packet_data))
        compressed_size = len(compressed)
        ratio = (1 - compressed_size / original_size) * 100 if original_size > 0 else 0
        
        print("\n" + "-" * 50)
        print(f"Orijinal Boyut: {original_size} byte")
        print(f"Sıkıştırılmış Boyut: {compressed_size} byte")
        print(f"Sıkıştırma Oranı: {ratio:.2f}%")
        print("\nSıkıştırılmış Veri (Backend'e gönderilecek):")
        print(compressed)
        print("-" * 50)
        
        # Test amaçlı olarak sıkıştırılmış veriyi açıp orijinalle karşılaştırma yapalım
        decompressed = decompress_data(compressed)
        is_same = decompressed == packet_data
        print(f"Veri doğru şekilde açılabildi mi: {is_same}")
        print("-" * 50)

    while True:
        try:
            if is_scanner_running():
                time.sleep(1)
                continue
                
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            # print('\nEthernet Frame:')
            # print(TAB_1 +'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
            
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'ethernet_frame': {
                    'destination': dest_mac,
                    'source': src_mac,
                    'protocol': eth_proto
                }
            }

            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                packet_data['ipv4_packet'] = {
                    'version': version,
                    'header_length': header_length,
                    'ttl': ttl,
                    'protocol': proto,
                    'source': src,
                    'target': target
                }
                # print(TAB_1 + 'IPv4 Packet:')
                # print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                # print(TAB_2 + 'Protocol: {}'.format(proto))
                # print(TAB_2 + 'Source: {}, Target: {}'.format(src, target))

                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    packet_data['icmp_packet'] = {
                        'type': icmp_type,
                        'code': code,
                        'checksum': checksum
                    }
                    # print(TAB_1 + 'ICMP Packet:')
                    # print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    # print(TAB_2 + 'Data:')
                    # print(format_multi_line(DATA_TAB_3, data))
                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    packet_data['tcp_segment'] = {
                        'source_port': src_port,
                        'destination_port': dest_port,
                        'sequence': sequence,
                        'acknowledgement': acknowledgement,
                        'flags': {
                            'URG': flag_urg,
                            'ACK': flag_ack,
                            'PSH': flag_psh,
                            'RST': flag_rst,
                            'SYN': flag_syn,
                            'FIN': flag_fin
                        }
                    }
                    # print(TAB_1 + 'TCP Segment:')
                    # print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    # print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                    # print(TAB_2 + 'Flags: {}')
                    # print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg ,flag_ack,flag_ack,flag_psh, flag_rst, flag_syn, flag_fin))
                    # print(TAB_2 + 'Data:')
                    # print(format_multi_line(DATA_TAB_3, data))
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    packet_data['udp_segment'] = {
                        'source_port': src_port,
                        'destination_port': dest_port,
                        'size': length
                    }
                    # print(TAB_1 + 'UDP Segment:')
                    # print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    # print(TAB_2 + 'Size: {}'.format(length))
                    # print(TAB_2 + 'Data:')
                    # print(format_multi_line(DATA_TAB_3, data))
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)
        except KeyboardInterrupt:
            print("Exiting program...")
            break
        
        write_to_json(packet_data)

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def compress_data(data):
    """
    JSON verisini sıkıştırır ve base64 ile encode eder.
    
    Args:
        data: JSON yapısı (dict/list)
    
    Returns:
        str: Base64 ile encode edilmiş sıkıştırılmış veri
    """
    # JSON verisini string'e dönüştür
    json_str = json.dumps(data)
    
    # String'i bytes'a dönüştür ve sıkıştır
    compressed = zlib.compress(json_str.encode('utf-8'), level=9)  # En yüksek sıkıştırma
    
    # Binary veriyi base64 ile encode et
    b64_encoded = base64.b64encode(compressed)
    
    # Bytes'dan string'e dönüştür
    return b64_encoded.decode('utf-8')

def decompress_data(compressed_data):
    """
    Sıkıştırılmış veriyi decode eder.
    
    Args:
        compressed_data (str): Base64 ile encode edilmiş sıkıştırılmış veri
    
    Returns:
        dict/list: Orijinal JSON yapısı
    """
    # String'i bytes'a dönüştür
    b64_bytes = compressed_data.encode('utf-8')
    
    # Base64 decode et
    compressed = base64.b64decode(b64_bytes)
    
    # Sıkıştırılmış veriyi aç
    json_str = zlib.decompress(compressed).decode('utf-8')
    
    # JSON string'i parse et
    return json.loads(json_str)

        
if __name__ == "__main__":
    main()