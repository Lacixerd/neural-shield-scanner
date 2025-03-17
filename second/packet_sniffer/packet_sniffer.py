#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import argparse
import socket
import struct
import textwrap
import datetime
import threading
import json
import csv
from colorama import Fore, Style, init
from scapy.all import *

# Colorama başlatma
init()

class PacketSniffer:
    def __init__(self):
        self.captured_packets = []
        self.is_running = False
        self.filter_expression = None
        self.interface = None
        self.packet_count = 0
        self.start_time = None
        self.stop_time = None
    
    def start_sniffing(self, interface=None, packet_count=0, 
                      timeout=None, filter_expr=None):
        """Paket yakalamayı başlatır"""
        self.is_running = True
        self.interface = interface
        self.filter_expression = filter_expr
        self.packet_count = packet_count
        self.start_time = datetime.datetime.now()
        self.captured_packets = []
        
        # Kullanıcıya geri bildirim
        print(f"{Fore.GREEN}[*] Paket analizi başlatılıyor...")
        print(f"[*] Arayüz: {interface or 'Varsayılan'}")
        print(f"[*] Filtre: {filter_expr or 'Yok'}")
        print(f"[*] Paket Limiti: {packet_count if packet_count > 0 else 'Limitsiz'}")
        print(f"[*] Zaman Aşımı: {timeout if timeout else 'Yok'}{Style.RESET_ALL}")
        
        try:
            # Paket yakalama işlemi başlatılıyor
            sniff(iface=interface,
                 filter=filter_expr,
                 prn=self._process_packet,
                 count=packet_count if packet_count > 0 else None,
                 timeout=timeout,
                 store=0)
                 
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}\n[!] Kullanıcı tarafından durduruldu{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")
        finally:
            self.stop_time = datetime.datetime.now()
            self.is_running = False
            
        return self.captured_packets
    
    def _process_packet(self, packet):
        """Her yakalanan paketi işler ve kaydeder"""
        packet_info = self._extract_packet_info(packet)
        self.captured_packets.append(packet_info)
        
        # Canlı yakalama sırasında tamamlanmış paketleri gösterir
        self._print_packet_summary(packet_info)
        
        return packet
    
    def _extract_packet_info(self, packet):
        """Paketten önemli bilgileri çıkarır"""
        packet_info = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'length': len(packet),
            'ttl': None,
            'flags': None,
            'info': None
        }
        
        # Ethernet katmanını kontrol et
        if Ether in packet:
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
        
        # IP katmanını kontrol et
        if IP in packet:
            packet_info['protocol'] = 'IPv4'
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['ttl'] = packet[IP].ttl
            
            # TCP/UDP bilgilerini kontrol et
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                
                # TCP flag'lerini ekle
                flags = []
                if packet[TCP].flags.S: flags.append('SYN')
                if packet[TCP].flags.A: flags.append('ACK')
                if packet[TCP].flags.F: flags.append('FIN')
                if packet[TCP].flags.R: flags.append('RST')
                if packet[TCP].flags.P: flags.append('PSH')
                if packet[TCP].flags.U: flags.append('URG')
                packet_info['flags'] = ', '.join(flags)
                
                # HTTP trafiğini tespit et
                if packet_info['dst_port'] == 80 or packet_info['src_port'] == 80:
                    if Raw in packet and (b'HTTP/' in packet[Raw].load or b'GET ' in packet[Raw].load or b'POST ' in packet[Raw].load):
                        packet_info['protocol'] = 'HTTP'
                        packet_info['info'] = packet[Raw].load[:100].decode('utf-8', 'ignore')
                
                # HTTPS trafiğini tespit et
                if packet_info['dst_port'] == 443 or packet_info['src_port'] == 443:
                    packet_info['protocol'] = 'HTTPS'
                    
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
                # DNS trafiğini tespit et
                if packet_info['dst_port'] == 53 or packet_info['src_port'] == 53:
                    packet_info['protocol'] = 'DNS'
                    if DNS in packet:
                        if packet[DNS].qr == 0:
                            names = [packet[DNSQR].qname.decode('utf-8') for i in range(packet[DNS].qdcount)]
                            packet_info['info'] = f"Query: {', '.join(names)}"
                        else:
                            packet_info['info'] = f"Response"
            
            # ICMP paketlerini kontrol et
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
        
        # IPv6 paketlerini kontrol et  
        elif IPv6 in packet:
            packet_info['protocol'] = 'IPv6'
            packet_info['src_ip'] = packet[IPv6].src
            packet_info['dst_ip'] = packet[IPv6].dst
            packet_info['ttl'] = packet[IPv6].hlim
        
        # ARP paketlerini kontrol et
        elif ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            packet_info['info'] = f"{'Request' if packet[ARP].op == 1 else 'Reply'}"
        
        return packet_info
    
    def _print_packet_summary(self, packet_info):
        """Paket özetini ekrana yazdır"""
        protocol_colors = {
            'TCP': Fore.CYAN,
            'UDP': Fore.BLUE,
            'ICMP': Fore.MAGENTA,
            'HTTP': Fore.GREEN,
            'HTTPS': Fore.LIGHTGREEN_EX,
            'DNS': Fore.YELLOW,
            'ARP': Fore.LIGHTRED_EX,
            'IPv4': Fore.WHITE,
            'IPv6': Fore.LIGHTBLUE_EX
        }
        
        color = protocol_colors.get(packet_info['protocol'], Fore.WHITE)
        
        # Protokol bilgisini renklendir
        proto_display = f"{color}{packet_info['protocol']}{Style.RESET_ALL}"
        
        # Port bilgisini ekle (eğer varsa)
        port_info = ""
        if packet_info['src_port'] and packet_info['dst_port']:
            port_info = f"{packet_info['src_port']} → {packet_info['dst_port']}"
        
        # IP bilgisini ekle
        ip_info = ""
        if packet_info['src_ip'] and packet_info['dst_ip']:
            ip_info = f"{packet_info['src_ip']} → {packet_info['dst_ip']}"
        
        # Bayrak bilgisini ekle
        flags_info = f" [{packet_info['flags']}]" if packet_info['flags'] else ""
        
        # Ek bilgileri ekle
        info = f" ({packet_info['info']})" if packet_info['info'] else ""
        
        # Paket uzunluğu ve TTL
        length_ttl = f"Len={packet_info['length']}"
        if packet_info['ttl']:
            length_ttl += f", TTL={packet_info['ttl']}"
        
        # Sonuç çıktısını oluştur ve yazdır
        output = f"{packet_info['timestamp']} {proto_display} {ip_info} {port_info}{flags_info} {length_ttl}{info}"
        print(output)
    
    def save_to_file(self, filename, format='txt'):
        """Yakalanan paketleri dosyaya kaydeder"""
        if not self.captured_packets:
            print(f"{Fore.YELLOW}[!] Kaydedilecek paket bulunamadı{Style.RESET_ALL}")
            return False
        
        try:
            file_path = os.path.abspath(filename)
            if format.lower() == 'json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.captured_packets, f, ensure_ascii=False, indent=2)
            
            elif format.lower() == 'csv':
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if self.captured_packets:
                        writer = csv.DictWriter(f, fieldnames=self.captured_packets[0].keys())
                        writer.writeheader()
                        writer.writerows(self.captured_packets)
            
            else:  # txt formatı
                with open(file_path, 'w', encoding='utf-8') as f:
                    # Özet bilgiler
                    f.write(f"Paket Analiz Raporu\n")
                    f.write(f"===================\n\n")
                    f.write(f"Başlangıç: {self.start_time}\n")
                    f.write(f"Bitiş: {self.stop_time}\n")
                    f.write(f"Süre: {self.stop_time - self.start_time}\n")
                    f.write(f"Yakalanan Paket Sayısı: {len(self.captured_packets)}\n")
                    f.write(f"Arayüz: {self.interface or 'Varsayılan'}\n")
                    f.write(f"Filtre: {self.filter_expression or 'Yok'}\n\n")
                    
                    # Paket bilgileri
                    f.write(f"Paket Detayları\n")
                    f.write(f"---------------\n\n")
                    
                    for i, packet in enumerate(self.captured_packets, 1):
                        f.write(f"Paket #{i}\n")
                        for key, value in packet.items():
                            if value is not None:
                                f.write(f"  {key}: {value}\n")
                        f.write("\n")
            
            print(f"{Fore.GREEN}[+] Paketler '{file_path}' dosyasına kaydedildi{Style.RESET_ALL}")
            return True
        
        except Exception as e:
            print(f"{Fore.RED}[!] Dosya kaydetme hatası: {str(e)}{Style.RESET_ALL}")
            return False
    
    def get_statistics(self):
        """Yakalanan paketlerle ilgili istatistikler oluşturur"""
        if not self.captured_packets:
            return {"error": "Hiç paket yakalanmadı"}
        
        stats = {
            'total_packets': len(self.captured_packets),
            'protocols': {},
            'top_talkers': {},
            'start_time': str(self.start_time),
            'end_time': str(self.stop_time),
            'duration': str(self.stop_time - self.start_time) if self.stop_time else "Bilinmiyor",
            'avg_packet_size': 0
        }
        
        # Protokol sayılarını ve ortalama paket boyutunu hesapla
        total_size = 0
        for packet in self.captured_packets:
            # Protokol sayıları
            protocol = packet['protocol'] or 'Unknown'
            stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
            
            # IP adresi sayıları
            if packet['src_ip']:
                stats['top_talkers'][packet['src_ip']] = stats['top_talkers'].get(packet['src_ip'], 0) + 1
            
            # Paket boyutu
            total_size += packet['length']
        
        # Ortalama paket boyutu
        stats['avg_packet_size'] = total_size / len(self.captured_packets) if self.captured_packets else 0
        
        # IP adreslerini trafiğe göre sırala (en çok konuşan 10 IP)
        stats['top_talkers'] = dict(sorted(stats['top_talkers'].items(), 
                                           key=lambda x: x[1], reverse=True)[:10])
        
        return stats

    def print_statistics(self):
        """İstatistikleri ekrana yazdırır"""
        stats = self.get_statistics()
        
        if "error" in stats:
            print(f"{Fore.RED}[!] {stats['error']}{Style.RESET_ALL}")
            return
        
        print("\n" + "="*50)
        print(f"{Fore.CYAN}Paket Analiz İstatistikleri{Style.RESET_ALL}")
        print("="*50)
        
        print(f"\n{Fore.YELLOW}Genel Bilgiler:{Style.RESET_ALL}")
        print(f"  Toplam Paket: {stats['total_packets']}")
        print(f"  Başlangıç Zamanı: {stats['start_time']}")
        print(f"  Bitiş Zamanı: {stats['end_time']}")
        print(f"  Süre: {stats['duration']}")
        print(f"  Ortalama Paket Boyutu: {stats['avg_packet_size']:.2f} bayt")
        
        print(f"\n{Fore.YELLOW}Protokol Dağılımı:{Style.RESET_ALL}")
        for protocol, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_packets']) * 100
            print(f"  {protocol}: {count} ({percentage:.2f}%)")
        
        print(f"\n{Fore.YELLOW}En Çok Trafik Üreten IP Adresleri:{Style.RESET_ALL}")
        for ip, count in stats['top_talkers'].items():
            percentage = (count / stats['total_packets']) * 100
            print(f"  {ip}: {count} ({percentage:.2f}%)")
        
        print("\n" + "="*50 + "\n")


def main():
    """Ana program fonksiyonu"""
    # Root/sudo kontrolü
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Bu programın paket yakalaması için root/sudo yetkileri gereklidir.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Lütfen 'sudo python3 packet_sniffer.py' komutu ile programı çalıştırın.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Komut satırı argümanlarını ayarla
    parser = argparse.ArgumentParser(description="Linux Paket Analiz Aracı")
    parser.add_argument("-i", "--interface", help="Dinlenecek ağ arayüzü (örn: eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, 
                      help="Yakalanacak maksimum paket sayısı (varsayılan: limitsiz)")
    parser.add_argument("-t", "--timeout", type=int, 
                      help="Yakalama işlemi zaman aşımı (saniye)")
    parser.add_argument("-f", "--filter", 
                      help="BPF filtresi (örn: 'tcp port 80' veya 'udp' veya 'host 192.168.1.1')")
    parser.add_argument("-o", "--output", 
                      help="Sonuçların kaydedileceği dosya adı")
    parser.add_argument("--format", choices=["txt", "json", "csv"], default="txt",
                      help="Çıktı dosyası formatı (varsayılan: txt)")
    
    # Argümanları analiz et
    args = parser.parse_args()
    
    # Banner göster
    show_banner()
    
    # Paket yakalayıcı oluştur
    sniffer = PacketSniffer()
    
    try:
        # Paket yakalamayı başlat
        sniffer.start_sniffing(
            interface=args.interface,
            packet_count=args.count,
            timeout=args.timeout,
            filter_expr=args.filter
        )
        
        # İstatistikleri göster
        sniffer.print_statistics()
        
        # Sonuçları kaydet (eğer isteniyorsa)
        if args.output:
            sniffer.save_to_file(args.output, args.format)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Program kullanıcı tarafından sonlandırıldı{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

def show_banner():
    """Program başlık bannerini göster"""
    banner = f"""
    {Fore.CYAN}╔══════════════════════════════════════╗
    ║                                                 ║
    ║   ██████╗ ██╗  ██╗████████╗    ███████╗██████╗  ║
    ║   ██╔══██╗██║ ██╔╝╚══██╔══╝    ██╔════╝██╔══██╗ ║
    ║   ██████╔╝█████╔╝    ██║       ███████╗██████╔╝ ║
    ║   ██╔═══╝ ██╔═██╗    ██║       ╚════██║██╔═══╝  ║
    ║   ██║     ██║  ██╗   ██║       ███████║██║      ║
    ║   ╚═╝     ╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝      ║
    ║                                                 ║
    ║          Linux Paket Analiz Aracı v1.0          ║
    ║                                                 ║
    ╚═════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)
    print(f"{Fore.YELLOW}[*] Paketleri durdurmak için Ctrl+C tuşlarına basın{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
