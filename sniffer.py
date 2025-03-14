"""
Bu Kod MacOs Cihazlarda çalışmaz çünkü AF_PACKET soket türü Macos Cihazlarda desteklenmiyor. 
Kod öalıştırılacaksa Linux cihazlarda çalışır anca.

Packet Sniffer loglarının yazıldığı dosya: logs/packet_sniffer_logs/sniffer_logs_<timestamp>.json
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
import threading
import queue
import requests
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

# Log rotasyonu için global değişkenler
LOG_ROTATION_INTERVAL = 120  # saniye (2 dakika)
log_queue = queue.Queue()
current_log_file = None
last_rotation_time = 0
log_writer_lock = threading.Lock()

with open('config.json', 'r') as f:
    config_file = json.load(f)

def log_message(packet_data):
    try:
        url = config_file['api_url'] + "network-scan/"

        headers = {
            "Authorization": f"Token {config_file['api_token']}",
            "Content-Type": "application/json"
        }

        payload = {
            "license_key": config_file['license_key'],
            "results": [packet_data]
        }

        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 201:
            print("Network Scan log saved successfully.")
        else:
            print(f"Network Scan log save failed: {response.status_code}\nError: {response.text}")
            print("Exiting...")
            sys.exit()
    except Exception as e:
        print(f"Network Scan log save error: {e}")
        print("Exiting...")
        sys.exit()

def is_scanner_running():
    return os.path.exists("scanner_running.signal")

def get_log_filename():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f'logs/packet_sniffer_logs/sniffer_logs_{timestamp}.json'

def initialize_log_file(filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        json.dump([], f)
    return filename

def log_writer_thread():
    global current_log_file, last_rotation_time
    
    current_log_file = initialize_log_file(get_log_filename())
    last_rotation_time = time.time()
    log_data = []
    
    while True:
        try:
            # En fazla 1 saniye bekle, böylece düzenli olarak rotasyon kontrolü yapılabilir
            packet = log_queue.get(timeout=1)
            log_data.append(packet)
            
            # Şu anki zaman
            current_time = time.time()
            
            # Log dosyasını periyodik olarak yaz ve gerekirse rotasyon yap
            if current_time - last_rotation_time >= LOG_ROTATION_INTERVAL or len(log_data) >= 1000:
                with log_writer_lock:
                    # Mevcut logları dosyaya yaz
                    with open(current_log_file, 'r') as f:
                        try:
                            existing_data = json.load(f)
                        except json.JSONDecodeError:
                            existing_data = []
                    
                    # Mevcut dosyaya logları ekle
                    existing_data.extend(log_data)
                    
                    # Atomik yazma için geçici dosya kullan
                    temp_file = f"{current_log_file}.tmp"
                    with open(temp_file, 'w') as f:
                        json.dump(existing_data, f, indent=2)
                    
                    # Geçici dosyayı asıl dosyaya taşı
                    os.replace(temp_file, current_log_file)
                    
                    # Eğer 2 dakika geçtiyse, yeni log dosyası oluştur ve logları API'ye gönder
                    if current_time - last_rotation_time >= LOG_ROTATION_INTERVAL:
                        # API'ye tüm logları gönder
                        if not is_scanner_running() and existing_data:
                            log_message(existing_data)
                            
                        # Yeni log dosyası oluştur
                        current_log_file = initialize_log_file(get_log_filename())
                        last_rotation_time = current_time
                    
                    # Log listesini temizle
                    log_data = []
            
            log_queue.task_done()
            
        except queue.Empty:
            # Timeout olduğunda, elimizdeki logları yaz
            if log_data:
                with log_writer_lock:
                    with open(current_log_file, 'r') as f:
                        try:
                            existing_data = json.load(f)
                        except json.JSONDecodeError:
                            existing_data = []
                    
                    existing_data.extend(log_data)
                    
                    temp_file = f"{current_log_file}.tmp"
                    with open(temp_file, 'w') as f:
                        json.dump(existing_data, f, indent=2)
                    
                    os.replace(temp_file, current_log_file)
                    log_data = []
        
        except Exception as e:
            print(f"Log yazarken hata: {e}")
            time.sleep(1)

def main():
    # Log writer thread'ini başlat
    log_thread = threading.Thread(target=log_writer_thread, daemon=True)
    log_thread.start()
    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    def write_to_json(packet_data):
        if is_scanner_running():
            return
        
        # Paketi kuyruğa ekle
        log_queue.put(packet_data)

    while True:
        try:
            if is_scanner_running():
                time.sleep(1)
                continue
                
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(TAB_1 +'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
            
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
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol: {}'.format(proto))
                print(TAB_2 + 'Source: {}, Target: {}'.format(src, target))

                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    packet_data['icmp_packet'] = {
                        'type': icmp_type,
                        'code': code,
                        'checksum': checksum,
                        'data': format_multi_line("",data)
                    }
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
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
                        },
                        'data': format_multi_line("",data)
                    }
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                    print(TAB_2 + 'Flags: {}')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg ,flag_ack,flag_ack,flag_psh, flag_rst, flag_syn, flag_fin))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    packet_data['udp_segment'] = {
                        'source_port': src_port,
                        'destination_port': dest_port,
                        'size': length,
                        'data': format_multi_line("",data)
                    }
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_2 + 'Size: {}'.format(length))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
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
    """
    Veriyi hem hex dump hem de ASCII formatında gösterir.
    
    Args:
        prefix: Her satırın başına eklenecek metin
        string: Formatlanacak bytes veya string verisi
        size: Her satırın maksimum uzunluğu
        
    Returns:
        Formatlanmış veri metni
    """
    if isinstance(string, bytes):
        # HEX ve ASCII formatını birlikte göster
        result = []
        for offset in range(0, len(string), 16):
            # Satır başında hex offset'i göster
            hex_offset = f"{offset:04x}"
            line = f"{hex_offset}  "
            
            # 16 byte'lık bir blok al
            chunk = string[offset:offset+16]
            
            # Hex formatını oluştur (8'li gruplar halinde)
            hex_line = ""
            for i, b in enumerate(chunk):
                if i == 8:  # 8. byte'tan sonra ekstra boşluk ekle
                    hex_line += " "
                hex_line += f"{b:02x} "
            
            # Hex satırını tamamla (eksik byte'lar için boşluk)
            hex_line = hex_line.ljust(49, ' ')  # 16 byte için 3 karakter/byte + ekstra boşluk
            line += hex_line
            
            # ASCII kısmını ekle
            ascii_part = ""
            for b in chunk:
                if 32 <= b <= 126:  # Yazdırılabilir ASCII karakterler
                    ascii_part += chr(b)
                else:
                    ascii_part += "."  # Yazdırılamayan karakterler için nokta
            
            # Her satırı birleştir
            line += ascii_part
            result.append(prefix + line)
        
        return "\n".join(result)
    else:
        # Eğer bytes değilse normal text wrap kullan
        string_str = str(string)
        size -= len(prefix)
        return '\n'.join([prefix + line for line in textwrap.wrap(string_str, size)])

if __name__ == "__main__":
    main()