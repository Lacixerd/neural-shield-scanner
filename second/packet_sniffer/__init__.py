#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Linux Paket Analiz Aracı
------------------------

Bu modül, Linux işletim sistemlerinde ağ trafiğini izlemek ve analiz etmek için kullanılır.
Scapy kütüphanesi kullanılarak geliştirilmiştir.

Kullanım:
    sudo python3 -m packet_sniffer [parametreler]

    Parametreler:
    -i, --interface : Dinlenecek ağ arayüzü
    -c, --count     : Yakalanacak maksimum paket sayısı
    -t, --timeout   : Yakalama işlemi zaman aşımı (saniye)
    -f, --filter    : BPF filtresi
    -o, --output    : Sonuçların kaydedileceği dosya adı
    --format        : Çıktı dosyası formatı (txt, json, csv)

Gereksinimler:
    - Python 3.6+
    - Scapy
    - Colorama
"""

from .packet_sniffer import PacketSniffer, main, show_banner

__version__ = "1.0.0"
__author__ = "Paket Analiz Aracı"
