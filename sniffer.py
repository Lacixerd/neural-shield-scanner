"""
Bu Kod MacOs Cihazlarda çalışmaz çünkü AF_PACKET soket türü Macos Cihazlarda desteklenmiyor. 
Kod öalıştırılacaksa Linux cihazlarda çalışır anca.

Artık loglar 2 dakikada bir API'ye gönderiliyor
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
log_writer_lock = threading.Lock()

# API yapılandırması
config = None

def load_config():
    """Config dosyasını yükler"""
    global config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Config yüklenirken hata oluştu: {e}")
        sys.exit(1)

def is_scanner_running():
    return os.path.exists("scanner_running.signal")

def send_logs_to_api(logs):
    """Logları API'ye gönderir"""
    if not config:
        print("Config yüklenmedi, loglar gönderilemedi")
        return False
    
    try:
        api_url = config["api_url"] + "sniffer-log/"
        headers = {
            "Authorization": f"Token {config['api_token']}",
            "Content-Type": "application/json"
        }

        payload = {
            "license_key": config["license_key"],
            "results": logs
        }
        
        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
        )
        
        if response.status_code == 200:
            print(f"{len(logs)} adet log başarıyla gönderildi")
            return True
        else:
            print(f"API yanıt hatası: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"Loglar API'ye gönderilirken hata: {e}")
        return False

def log_writer_thread():
    """Logları toplar ve belirli aralıklarla API'ye gönderir"""
    last_send_time = time.time()
    log_data = []
    
    while True:
        try:
            # En fazla 1 saniye bekle, böylece düzenli olarak gönderim kontrolü yapılabilir
            packet = log_queue.get(timeout=1)
            log_data.append(packet)
            
            # Şu anki zaman
            current_time = time.time()
            
            # Logları periyodik olarak API'ye gönder
            if current_time - last_send_time >= LOG_ROTATION_INTERVAL or len(log_data) >= 1000:
                with log_writer_lock:
                    if log_data:
                        if send_logs_to_api(log_data):
                            last_send_time = current_time
                            log_data = []
                
            log_queue.task_done()
            
        except queue.Empty:
            # Timeout olduğunda, elimizdeki logları gönder
            if log_data:
                with log_writer_lock:
                    if send_logs_to_api(log_data):
                        log_data = []
        
        except Exception as e:
            print(f"Log işlenirken hata: {e}")
            time.sleep(1)

def main():
    # Config dosyasını yükle
    load_config()
    
    # Log writer thread'ini başlat
    log_thread = threading.Thread(target=log_writer_thread, daemon=True)
    log_thread.start()
    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    def add_to_queue(packet_data):
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
                        'data': data
                    }
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'Data:')
                    print(DATA_TAB_3 + data)
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
                        'data': data
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
                        'data': data
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
        
        add_to_queue(packet_data)

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