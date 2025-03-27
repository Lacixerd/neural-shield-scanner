#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ağ Tehditlerini İzlemek İçin Gelişmiş Paket Yakalayıcı (PyShark kullanarak)

Bu betik, belirtilen ağ arayüzünde promiscuous modda çalışarak
ağ trafiğini yakalar ve potansiyel tehdit belirtilerini analiz eder.
"""

import pyshark
import sys
import os
import argparse
import time
from collections import defaultdict, Counter
from datetime import datetime

# Renklendirme için (opsiyonel, colorama kütüphanesi gerekir: pip install colorama)
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Colorama yoksa, renk kodlarını boş stringlerle değiştir
    class Fore:
        RED = YELLOW = GREEN = CYAN = WHITE = ''
    class Style:
        RESET_ALL = ''

# --- Potansiyel Tehdit Analizi Ayarları ---
SCAN_DETECTION_THRESHOLD = 10  # Bir IP'nin kısa sürede taradığı farklı port sayısı eşiği
SCAN_DETECTION_WINDOW = 10     # Tarama tespiti için zaman penceresi (saniye)

# Takip edilecek veriler için global değişkenler
source_ip_ports = defaultdict(lambda: {'ports': set(), 'timestamp': time.time()})
dns_queries = Counter()
suspicious_flags_log = []

def get_packet_timestamp(packet):
    """Paketten zaman damgasını alır."""
    try:
        return float(packet.sniff_timestamp)
    except AttributeError:
        return time.time()

def analyze_packet(packet):
    """
    Her bir paketi analiz eder ve potansiyel tehditleri arar.
    """
    global source_ip_ports, dns_queries, suspicious_flags_log
    timestamp = get_packet_timestamp(packet)
    current_time = time.time()

    try:
        # --- IP Katmanı Analizi ---
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # --- TCP Katmanı Analizi ---
            if 'TCP' in packet:
                dst_port = packet.tcp.dstport
                flags = int(packet.tcp.flags, 16) # Bayrakları integer olarak al

                # 1. Port Tarama Tespiti
                # Belirli bir zaman penceresinde aynı kaynaktan gelen farklı hedef portları izle
                data = source_ip_ports[src_ip]
                # Zaman penceresi dışındaki eski kayıtları temizle
                if current_time - data['timestamp'] > SCAN_DETECTION_WINDOW:
                    data['ports'] = {dst_port}
                    data['timestamp'] = current_time
                else:
                    data['ports'].add(dst_port)

                if len(data['ports']) > SCAN_DETECTION_THRESHOLD:
                    print(f"{Fore.RED}[!] POTANSİYEL PORT TARAMASI TESPİT EDİLDİ:"
                          f" Kaynak: {src_ip}, Hedef Port Sayısı: {len(data['ports'])} (Zaman Penceresi: {SCAN_DETECTION_WINDOW}s)")
                    # Tespit sonrası sıfırlama veya daha gelişmiş takip eklenebilir
                    data['ports'] = set() # Basit sıfırlama

                # 2. Şüpheli TCP Bayrakları
                # NULL Scan (Hiçbir bayrak set edilmemiş)
                if flags == 0:
                    log_entry = f"Zaman: {datetime.fromtimestamp(timestamp).isoformat()}, Kaynak: {src_ip}, Hedef: {dst_ip}:{dst_port}, Bayraklar: NULL"
                    suspicious_flags_log.append(log_entry)
                    print(f"{Fore.YELLOW}[!] Şüpheli TCP Bayrağı (NULL Scan): {src_ip} -> {dst_ip}:{dst_port}")

                # FIN Scan (Sadece FIN bayrağı set edilmiş)
                elif flags == 0x01:
                    log_entry = f"Zaman: {datetime.fromtimestamp(timestamp).isoformat()}, Kaynak: {src_ip}, Hedef: {dst_ip}:{dst_port}, Bayraklar: FIN"
                    suspicious_flags_log.append(log_entry)
                    print(f"{Fore.YELLOW}[!] Şüpheli TCP Bayrağı (FIN Scan): {src_ip} -> {dst_ip}:{dst_port}")

                # Xmas Scan (FIN, PSH, URG bayrakları set edilmiş)
                elif flags == 0x29:
                    log_entry = f"Zaman: {datetime.fromtimestamp(timestamp).isoformat()}, Kaynak: {src_ip}, Hedef: {dst_ip}:{dst_port}, Bayraklar: Xmas"
                    suspicious_flags_log.append(log_entry)
                    print(f"{Fore.YELLOW}[!] Şüpheli TCP Bayrağı (Xmas Scan): {src_ip} -> {dst_ip}:{dst_port}")

                # SYN/FIN Scan (SYN ve FIN aynı anda set edilmiş - geçersiz)
                elif (flags & 0x02) and (flags & 0x01):
                     log_entry = f"Zaman: {datetime.fromtimestamp(timestamp).isoformat()}, Kaynak: {src_ip}, Hedef: {dst_ip}:{dst_port}, Bayraklar: SYN+FIN"
                     suspicious_flags_log.append(log_entry)
                     print(f"{Fore.RED}[!] GEÇERSİZ TCP Bayrağı (SYN/FIN): {src_ip} -> {dst_ip}:{dst_port}")


            # --- UDP Katmanı ve DNS Analizi ---
            elif 'UDP' in packet and 'DNS' in packet:
                # Sadece DNS sorgularını (QR=0) işle
                if hasattr(packet.dns, 'qry_name') and packet.dns.flags_qr == '0':
                    query_name = packet.dns.qry_name
                    dns_queries[query_name] += 1
                    print(f"{Fore.CYAN}[+] DNS Sorgusu: {src_ip} -> {query_name}")

        # --- Genel Paket Bilgisi (İsteğe bağlı, çok fazla çıktı üretebilir) ---
        # print(f"Paket: {packet.number}, Zaman: {timestamp}, En Yüksek Katman: {packet.highest_layer}")

    except AttributeError as e:
        # Bazen pakette beklenen alanlar olmayabilir
        # print(f"{Fore.YELLOW}[?] Paket ayrıştırılamadı: {e} - Paket No: {packet.number}")
        pass
    except Exception as e:
        print(f"{Fore.RED}[!] Paket analizi sırasında hata: {e}")

def list_interfaces():
    """Mevcut ağ arayüzlerini listeler (Linux için)."""
    try:
        # Not: Bu yöntem her zaman tüm arayüzleri göstermeyebilir veya root gerektirebilir.
        # Daha güvenilir yöntemler için `netifaces` gibi kütüphaneler kullanılabilir.
        print(f"{Fore.GREEN}Mevcut Ağ Arayüzleri (tahmini):{Style.RESET_ALL}")
        for interface in os.listdir('/sys/class/net/'):
            print(f"  - {interface}")
    except FileNotFoundError:
        print(f"{Fore.YELLOW}[!] /sys/class/net/ dizini bulunamadı. Arayüzler otomatik listelenemedi.")
    except Exception as e:
        print(f"{Fore.RED}[!] Arayüzleri listelerken hata: {e}")

def main():
    """Ana fonksiyon: Argümanları işler ve yakalamayı başlatır."""
    parser = argparse.ArgumentParser(
        description="Ağ Tehditlerini İzlemek İçin Gelişmiş Paket Yakalayıcı",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-i', '--interface', type=str, required=True,
        help="Paket yakalamak için ağ arayüzü (örn: eth0, wlan0)."
    )
    parser.add_argument(
        '-f', '--filter', type=str, default=None,
        help='Yakalanacak paketler için BPF filtresi (örn: "tcp port 80", "host 192.168.1.1").'
    )
    parser.add_argument(
        '-c', '--count', type=int, default=0,
        help='Yakalanacak maksimum paket sayısı (0 = sınırsız).'
    )
    parser.add_argument(
        '--list-interfaces', action='store_true',
        help='Kullanılabilir ağ arayüzlerini listeler ve çıkar.'
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # Root yetkisi kontrolü
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Bu betik, ağ arayüzünü promiscuous modda dinlemek için root yetkileri gerektirir.")
        print(f"{Fore.YELLOW}Lütfen 'sudo python3 {sys.argv[0]} -i <arayüz>' komutuyla çalıştırın.")
        sys.exit(1)

    interface = args.interface
    bpf_filter = args.filter
    packet_count = args.count if args.count > 0 else None # PyShark None'ı sınırsız olarak anlar

    print(f"{Fore.GREEN}[*] Ağ Paket Yakalayıcı Başlatılıyor...")
    print(f"{Fore.CYAN}    Arayüz      : {interface}")
    print(f"{Fore.CYAN}    Promiscuous : True")
    if bpf_filter:
        print(f"{Fore.CYAN}    BPF Filtresi: {bpf_filter}")
    if packet_count:
        print(f"{Fore.CYAN}    Paket Limiti: {packet_count}")
    print(f"{Fore.YELLOW}[*] Yakalamayı durdurmak için CTRL+C tuşlarına basın.")

    try:
        # LiveCapture ile promiscuous modda yakalama başlat
        capture = pyshark.LiveCapture(
            interface=interface,
            bpf_filter=bpf_filter,
            promiscuous_mode=True, # Ağdaki tüm paketleri yakala
            # use_json=True, # JSON formatında daha hızlı ayrıştırma (opsiyonel)
            # include_raw=True # Ham paket verisi (opsiyonel)
        )

        # Paketleri analiz etmek için apply_on_packets kullan
        capture.apply_on_packets(analyze_packet, timeout=packet_count) # timeout burada paket sayısı gibi davranır

        # Alternatif: sniff_continuously ile sürekli yakalama
        # for packet in capture.sniff_continuously(packet_count=packet_count):
        #     analyze_packet(packet)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Kullanıcı tarafından durduruldu.")
    except Exception as e:
        # Arayüz bulunamadı veya izin hatası gibi durumlar
        print(f"\n{Fore.RED}[!] Yakalama sırasında bir hata oluştu: {e}")
        print(f"{Fore.YELLOW}    - Arayüz adının ('{interface}') doğru olduğundan emin olun.")
        print(f"{Fore.YELLOW}    - Betiği 'sudo' ile çalıştırdığınızdan emin olun.")
        print(f"{Fore.YELLOW}    - 'tshark' komutunun sisteminizde kurulu ve PATH içinde olduğundan emin olun.")
    finally:
        print(f"\n{Fore.GREEN}[*] Analiz Sonuçları Özeti:")

        # En çok sorgulanan DNS adresleri
        if dns_queries:
            print(f"\n{Fore.YELLOW}--- En Çok Sorgulanan DNS Adresleri (Top 10) ---{Style.RESET_ALL}")
            for domain, count in dns_queries.most_common(10):
                print(f"  {domain:<40} : {count}")
        else:
            print(f"{Fore.CYAN}  Yakalanan DNS sorgusu yok.")

        # Şüpheli bayrak logları
        if suspicious_flags_log:
            print(f"\n{Fore.YELLOW}--- Şüpheli/Geçersiz TCP Bayrakları Logları ({len(suspicious_flags_log)} adet) ---{Style.RESET_ALL}")
            # İstenirse loglar bir dosyaya yazılabilir
            for entry in suspicious_flags_log[:20]: # İlk 20'sini göster
                print(f"  {entry}")
            if len(suspicious_flags_log) > 20:
                print(f"  ... (toplam {len(suspicious_flags_log)} log)")
        else:
            print(f"{Fore.CYAN}  Şüpheli TCP bayrağı tespit edilmedi.")

        print(f"\n{Fore.GREEN}[*] Betik sonlandırıldı.")

if __name__ == "__main__":
    main()
