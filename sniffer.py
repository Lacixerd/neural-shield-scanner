#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ağ Güvenliği Paket Yakalayıcı
------------------------------
Tüm ağ trafiğini izleyen ve potansiyel tehdit oluşturan paketleri tespit eden
gelişmiş bir paket yakalama aracı.

Bu araç, ham soketler kullanarak düşük seviyede paket yakalama yapar ve
güvenlik açısından şüpheli olabilecek paketleri tespit eder.
"""

import socket
import struct
import time
import sys
import os
import argparse
import json
import binascii
from collections import defaultdict, Counter
from datetime import datetime

# Renklendirme için terminalde renkli çıktı
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Tehdit tespiti için yapılandırma
PORT_SCAN_THRESHOLD = 10  # Tarama tespiti için eşik değeri
PORT_SCAN_WINDOW = 5  # Tarama tespiti için zaman penceresi (saniye)
SUSPICIOUS_FLAG_PATTERNS = {
    'null_scan': 0x00,  # Hiçbir bayrak ayarlanmamış
    'fin_scan': 0x01,   # Sadece FIN bayrağı
    'xmas_scan': 0x29,  # FIN, PSH, URG bayrakları 
    'syn_fin': 0x03     # SYN ve FIN birlikte (geçersiz)
}

# Global değişkenler
total_packets = 0
ip_protocols = {}  # Protokollerin sayısını takip eder
src_ip_ports = defaultdict(lambda: {'ports': set(), 'timestamp': time.time()})
detected_threats = []
packet_stats = {
    'tcp': 0,
    'udp': 0,
    'icmp': 0,
    'dns': 0,
    'http': 0,
    'other': 0
}


class EthernetFrame:
    """Ethernet çerçevesi ayrıştırıcı"""
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
    """IPv4 paketi ayrıştırıcı"""
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
    """TCP segmenti ayrıştırıcı"""
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
        
        # HTTP tespiti (basit) - yalnızca en yaygın metotları kontrol eder
        self.is_http = False
        if len(self.data) > 10:
            http_methods = [b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ']
            for method in http_methods:
                if self.data.startswith(method):
                    self.is_http = True
                    break


class UDPSegment:
    """UDP segmenti ayrıştırıcı"""
    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H H 2x', raw_data[:8])
        self.data = raw_data[8:]
        
        # DNS paketi tespiti (port 53)
        self.is_dns = (self.src_port == 53 or self.dest_port == 53)


class ICMPPacket:
    """ICMP paketi ayrıştırıcı"""
    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]


class DNSPacket:
    """DNS paketi ayrıştırıcı (basit)"""
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
        """DNS ad alanlarını ayrıştırır."""
        domain_parts = []
        i = offset
        while True:
            length = data[i]
            if length == 0:
                break
            # DNS ad sıkıştırmasını kontrol et
            if (length & 0xC0) == 0xC0:  # En yüksek 2 bit 1'se, sıkıştırılmış
                pointer = struct.unpack('! H', data[i:i+2])[0] & 0x3FFF
                return '.'.join(domain_parts) + '.' + self.parse_dns_name(data, pointer)
            i += 1
            if i + length > len(data):
                return '.'.join(domain_parts)
            domain_parts.append(data[i:i+length].decode('utf-8', errors='ignore'))
            i += length
        return '.'.join(domain_parts)


def format_output(prefix, msg, color=WHITE):
    """Terminalde renkli çıktı için yardımcı fonksiyon"""
    return f"{color}{prefix}{RESET} {msg}"


def print_ethernet_frame(frame):
    """Ethernet çerçevesi bilgilerini yazdırır"""
    if args.verbose:
        print(format_output("[ETH]", f"Kaynak MAC: {frame.src_mac} -> Hedef MAC: {frame.dest_mac}", BLUE))


def print_ipv4_packet(packet):
    """IPv4 paketi bilgilerini yazdırır"""
    if args.verbose:
        print(format_output("[IPv4]", f"Kaynak IP: {packet.src} -> Hedef IP: {packet.target} (TTL: {packet.ttl})", GREEN))


def print_tcp_segment(segment):
    """TCP segmenti bilgilerini yazdırır"""
    flags = []
    if segment.flag_urg: flags.append("URG")
    if segment.flag_ack: flags.append("ACK")
    if segment.flag_psh: flags.append("PSH")
    if segment.flag_rst: flags.append("RST")
    if segment.flag_syn: flags.append("SYN")
    if segment.flag_fin: flags.append("FIN")
    
    flags_str = ' '.join(flags) if flags else "None"
    
    if args.verbose or segment.is_http:
        print(format_output("[TCP]", 
              f"Port: {segment.src_port} -> {segment.dest_port} | "
              f"Flags: {flags_str}", YELLOW))


def print_udp_segment(segment):
    """UDP segmenti bilgilerini yazdırır"""
    if args.verbose or segment.is_dns:
        print(format_output("[UDP]", f"Port: {segment.src_port} -> {segment.dest_port} | Boyut: {segment.size}", MAGENTA))


def print_icmp_packet(packet):
    """ICMP paketi bilgilerini yazdırır"""
    icmp_types = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
        13: "Timestamp"
    }
    
    type_str = icmp_types.get(packet.type, f"Tip {packet.type}")
    
    if args.verbose:
        print(format_output("[ICMP]", f"{type_str} | Kod: {packet.code}", CYAN))


def check_port_scan(ip, port, timestamp):
    """
    Port tarama tespiti
    Bir IP adresinden kısa süre içinde çok sayıda farklı porta
    yapılan bağlantıları tespit eder
    """
    global src_ip_ports, detected_threats
    
    data = src_ip_ports[ip]
    current_time = timestamp
    
    # Zaman penceresi dışına çıktıysa sıfırla
    if current_time - data['timestamp'] > PORT_SCAN_WINDOW:
        data['ports'] = {port}
        data['timestamp'] = current_time
    else:
        data['ports'].add(port)
    
    # Port taraması tespit edildi mi?
    if len(data['ports']) > PORT_SCAN_THRESHOLD:
        threat = {
            'timestamp': datetime.fromtimestamp(current_time).isoformat(),
            'type': 'PORT_SCAN',
            'source_ip': ip,
            'details': f"{len(data['ports'])} farklı porta {PORT_SCAN_WINDOW} saniye içinde erişim"
        }
        # Aynı tehdidi tekrar rapor etmemek için kontrol
        if not any(t['type'] == 'PORT_SCAN' and t['source_ip'] == ip for t in detected_threats[-10:]):
            detected_threats.append(threat)
            print(format_output("[TEHDİT]", 
                  f"Port Tarama Tespiti - Kaynak: {ip}, "
                  f"{len(data['ports'])} port içinde {PORT_SCAN_WINDOW}s", RED + BOLD))
            # Tespit sonrası sıfırla
            data['ports'] = set()


def check_suspicious_flags(flags, src_ip, dst_ip, src_port, dst_port, timestamp):
    """Şüpheli TCP bayrak kombinasyonlarını kontrol eder"""
    global detected_threats
    
    # Şüpheli bayrak kalıplarını kontrol et
    if flags == SUSPICIOUS_FLAG_PATTERNS['null_scan']:
        flag_type = "NULL Scan"
        is_suspicious = True
    elif flags == SUSPICIOUS_FLAG_PATTERNS['fin_scan']:
        flag_type = "FIN Scan"
        is_suspicious = True
    elif flags == SUSPICIOUS_FLAG_PATTERNS['xmas_scan']:
        flag_type = "XMAS Scan"
        is_suspicious = True
    elif flags == SUSPICIOUS_FLAG_PATTERNS['syn_fin']:
        flag_type = "SYN+FIN (Geçersiz)"
        is_suspicious = True
    else:
        is_suspicious = False
    
    if is_suspicious:
        threat = {
            'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
            'type': 'SUSPICIOUS_FLAGS',
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'source_port': src_port,
            'dest_port': dst_port,
            'flag_type': flag_type
        }
        detected_threats.append(threat)
        print(format_output("[TEHDİT]", 
              f"Şüpheli TCP Bayrakları ({flag_type}) - "
              f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}", RED + BOLD))


def get_available_interfaces():
    """Sistemdeki kullanılabilir ağ arayüzlerini getirir"""
    interfaces = []
    
    # Linux'ta /sys/class/net yoluyla arayüzleri kontrol et
    if os.path.exists('/sys/class/net'):
        for iface in os.listdir('/sys/class/net'):
            interfaces.append(iface)
    
    return interfaces


def packet_handler():
    """Ana paket işleme fonksiyonu. Ağı dinler ve gelen paketleri işler."""
    global total_packets, ip_protocols, packet_stats
    
    # IPv4 için ham soket oluştur
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    try:
        # Belirtilen arayüzü bağla
        if args.interface:
            conn.bind((args.interface, 0))
    except (socket.error, OSError) as e:
        print(format_output("[HATA]", f"Arayüz bağlama hatası: {e}", RED))
        print(format_output("[BİLGİ]", f"Kullanılabilir arayüzler: {', '.join(get_available_interfaces())}", YELLOW))
        sys.exit(1)
    
    start_time = time.time()
    print(format_output("[BAŞLAT]", 
          f"Paket yakalama başlatıldı - Arayüz: {args.interface or 'tümü'}", GREEN + BOLD))
    print(format_output("[BİLGİ]", "Durdurmak için CTRL+C tuşlarına basın", YELLOW))
    
    try:
        while True:
            current_time = time.time()
            
            # Maksimum süre kontrolü
            if args.duration > 0 and (current_time - start_time) > args.duration:
                print(format_output("[BİLGİ]", f"Belirlenen süre ({args.duration}s) doldu.", YELLOW))
                break
            
            raw_data, addr = conn.recvfrom(65536)
            total_packets += 1
            
            # Ethernet çerçevesini ayrıştır
            eth = EthernetFrame(raw_data)
            print_ethernet_frame(eth)
            
            # IPv4 Paketi
            if eth.proto == 8:  # IPv4
                ipv4 = IPv4Packet(eth.data)
                print_ipv4_packet(ipv4)
                
                # Protokol istatistikleri güncelle
                ip_protocols[ipv4.proto] = ip_protocols.get(ipv4.proto, 0) + 1
                
                # TCP
                if ipv4.proto == 6:  # TCP
                    packet_stats['tcp'] += 1
                    tcp = TCPSegment(ipv4.data)
                    print_tcp_segment(tcp)
                    
                    # HTTP paketi mi?
                    if tcp.is_http:
                        packet_stats['http'] += 1
                        http_data = tcp.data[:100].decode('utf-8', 'ignore').replace('\n', ' ')
                        print(format_output("[HTTP]", http_data, CYAN))
                    
                    # Port tarama tespiti
                    check_port_scan(ipv4.src, tcp.dest_port, current_time)
                    
                    # Şüpheli TCP bayrak tespiti
                    check_suspicious_flags(tcp.flags, ipv4.src, ipv4.target, 
                                          tcp.src_port, tcp.dest_port, current_time)
                
                # UDP
                elif ipv4.proto == 17:  # UDP
                    packet_stats['udp'] += 1
                    udp = UDPSegment(ipv4.data)
                    print_udp_segment(udp)
                    
                    # DNS paketi mi?
                    if udp.is_dns:
                        packet_stats['dns'] += 1
                        dns = DNSPacket(udp.data)
                        if dns.domain:
                            query_type = "Sorgu" if dns.is_query else "Yanıt"
                            print(format_output("[DNS]", f"{query_type}: {dns.domain}", CYAN))
                
                # ICMP
                elif ipv4.proto == 1:  # ICMP
                    packet_stats['icmp'] += 1
                    icmp = ICMPPacket(ipv4.data)
                    print_icmp_packet(icmp)
                
                # Diğer protokoller
                else:
                    packet_stats['other'] += 1
                    if args.verbose:
                        print(format_output("[PROTO]", f"Protokol: {ipv4.proto}", WHITE))
            
            # Her 1000 pakette bir istatistikleri göster
            if total_packets % 1000 == 0:
                print(format_output("[İSTATİSTİK]", 
                      f"Toplam Paket: {total_packets} | "
                      f"TCP: {packet_stats['tcp']} | UDP: {packet_stats['udp']} | "
                      f"ICMP: {packet_stats['icmp']} | DNS: {packet_stats['dns']} | "
                      f"HTTP: {packet_stats['http']}", GREEN))
    
    except KeyboardInterrupt:
        print(format_output("\n[DURDUR]", "Kullanıcı tarafından durduruldu", YELLOW))
    
    finally:
        # Sonuçları göster
        show_results(start_time)
        
        # Güvenlik tehditleri raporu
        show_threats_report()
        
        # İstenirse JSON raporu oluştur
        if args.output:
            save_report(start_time, args.output)


def show_results(start_time):
    """Yakalama sonuçlarını gösterir"""
    duration = time.time() - start_time
    print("\n" + "="*80)
    print(format_output("[SONUÇ]", f"Paket Yakalama Özeti", GREEN + BOLD))
    print(format_output("[SÜRE]", f"{duration:.2f} saniye", GREEN))
    print(format_output("[PAKET]", f"Toplam yakalanan paket: {total_packets}", GREEN))
    if total_packets > 0:
        print(format_output("[ORAN]", f"Paket/saniye: {total_packets/duration:.2f}", GREEN))
    
    print("\n" + format_output("[İSTATİSTİK]", f"Protokol Dağılımı", BLUE + BOLD))
    for proto, count in packet_stats.items():
        if count > 0:
            percent = (count / total_packets) * 100 if total_packets > 0 else 0
            print(format_output(f"[{proto.upper()}]", f"{count} paket ({percent:.1f}%)", BLUE))


def show_threats_report():
    """Tespit edilen tehditleri gösterir"""
    if not detected_threats:
        print("\n" + format_output("[GÜVENLİK]", "Hiçbir tehdit tespit edilmedi", GREEN + BOLD))
        return
    
    print("\n" + format_output("[TEHDİT RAPORU]", f"{len(detected_threats)} potansiyel tehdit tespit edildi", RED + BOLD))
    
    # Tehdit türlerine göre sınıflandır
    threat_types = {}
    for threat in detected_threats:
        t_type = threat['type']
        if t_type not in threat_types:
            threat_types[t_type] = []
        threat_types[t_type].append(threat)
    
    # Her tehdit türü için özet göster
    for t_type, threats in threat_types.items():
        print(format_output(f"[{t_type}]", f"{len(threats)} olay", RED))
        
        # En fazla 5 örnek göster
        for i, threat in enumerate(threats[:5]):
            if t_type == 'PORT_SCAN':
                print(format_output(f"  {i+1}.", 
                      f"Kaynak: {threat['source_ip']} - {threat['details']} - "
                      f"Zaman: {threat['timestamp']}", YELLOW))
            elif t_type == 'SUSPICIOUS_FLAGS':
                print(format_output(f"  {i+1}.", 
                      f"{threat['flag_type']} - "
                      f"{threat['source_ip']}:{threat['source_port']} -> "
                      f"{threat['dest_ip']}:{threat['dest_port']} - "
                      f"Zaman: {threat['timestamp']}", YELLOW))
        
        if len(threats) > 5:
            print(format_output("  ...", f"ve {len(threats)-5} daha", YELLOW))


def save_report(start_time, filename):
    """Sonuçları JSON formatında kaydeder"""
    duration = time.time() - start_time
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'duration': duration,
        'total_packets': total_packets,
        'packet_rate': total_packets/duration if duration > 0 else 0,
        'packet_stats': packet_stats,
        'detected_threats': detected_threats
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(format_output("[KAYIT]", f"Rapor '{filename}' dosyasına kaydedildi", GREEN))
    except Exception as e:
        print(format_output("[HATA]", f"Rapor kaydedilemedi: {e}", RED))


if __name__ == "__main__":
    # Root yetkisi kontrolü
    if os.geteuid() != 0:
        print(format_output("[HATA]", 
              "Bu uygulama root yetkileri gerektirmektedir. 'sudo' ile çalıştırın.", RED))
        sys.exit(1)
    
    # Komut satırı argümanlarını işleme
    parser = argparse.ArgumentParser(description="Ağ Güvenliği Paket Yakalayıcı")
    parser.add_argument('-i', '--interface', help='Dinlenecek ağ arayüzü (örn: eth0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Ayrıntılı çıktı modunu etkinleştir')
    parser.add_argument('-d', '--duration', type=int, default=0, 
                        help='Yakalama süresi (saniye, 0=sınırsız)')
    parser.add_argument('-o', '--output', help='JSON rapor çıktı dosyası')
    parser.add_argument('-l', '--list', action='store_true', help='Kullanılabilir ağ arayüzlerini listele')
    
    args = parser.parse_args()
    
    # Arayüzleri listele ve çık
    if args.list:
        interfaces = get_available_interfaces()
        print(format_output("[ARAYÜZLER]", "Kullanılabilir ağ arayüzleri:", GREEN))
        for i, iface in enumerate(interfaces, 1):
            print(format_output(f"  {i}.", iface, CYAN))
        sys.exit(0)
    
    # Herhangi bir arayüz belirtilmemişse kullanıcıdan sor
    if not args.interface:
        interfaces = get_available_interfaces()
        print(format_output("[ARAYÜZLER]", "Kullanılabilir ağ arayüzleri:", GREEN))
        for i, iface in enumerate(interfaces, 1):
            print(format_output(f"  {i}.", iface, CYAN))
        
        try:
            idx = int(input("\nSeçmek istediğiniz arayüzün numarasını girin (veya tüm arayüzler için 0): "))
            if idx > 0 and idx <= len(interfaces):
                args.interface = interfaces[idx-1]
            elif idx != 0:
                print(format_output("[HATA]", "Geçersiz arayüz numarası.", RED))
                sys.exit(1)
        except ValueError:
            print(format_output("[HATA]", "Geçersiz giriş.", RED))
            sys.exit(1)
    
    # Ana paket işleme fonksiyonunu başlat
    packet_handler()
