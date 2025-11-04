import platform
import subprocess
import re
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor
from typing import List

def ping_ip(ip: str) -> bool:

    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip)]
    
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=1)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

def arp_scan() -> set:

    active_ips = set()
    try:
        output = subprocess.check_output(["arp", "-a"], encoding="utf-8", errors="ignore")

        for line in output.splitlines():
            if "incomplete" in line:
                continue
            match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
            if match:
                active_ips.add(match.group(1))
    except Exception:
        pass
    return active_ips

def discover_active_ips(network: str, max_workers: int = 50) -> List[str]:

    active_ips = []
    net = IPv4Network(network)
    ip_list = [str(ip) for ip in net.hosts()]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(ping_ip, ip_list))
    
    arp_ips = arp_scan()

    for ip, is_active in zip(ip_list, results):
        if is_active or ip in arp_ips:
            active_ips.append(ip)
    
    return active_ips

def main(target_range):
    print(f"\nStarting IP discovery for {target_range}")
    
    active_ips = discover_active_ips(target_range)
    
    print("\nActive IPs:")
    for ip in active_ips:
        print(f"- {ip}")
    print(f"\n{len(active_ips)} active ip found.")

    if active_ips:
        print("\nIP addresses are being sent to port scanning...")
        return active_ips
    else:
        print("\nNo active ip address found.")
        return []