#!/usr/bin/env python3
# NetSweep - ARP Network Scanner by adhamhas

import scapy.all as scapy
from colorama import Fore, Style, init

init(autoreset=True)

def scan(ip_range):
    """
    Sends ARP requests to the IP range and collects responses.
    """
    print(Fore.CYAN + f"[~] Scanning IP range: {ip_range}\n")
    
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request

    try:
        answered_list = scapy.srp(arp_packet, timeout=1, verbose=False)[0]
    except PermissionError:
        print(Fore.RED + "[!] Run this script as root (sudo).")
        return []

    clients = []
    for sent, received in answered_list:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    return clients

def print_result(clients):
    """
    Displays results in a formatted table.
    """
    if not clients:
        print(Fore.RED + "[!] No devices found.")
        return

    print(Fore.GREEN + "IP Address\t\tMAC Address")
    print("-" * 50)
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")

def main():
    ip_range = input(Fore.YELLOW + "Enter IP range (e.g., 192.168.1.1/24): " + Style.RESET_ALL)
    results = scan(ip_range)
    print_result(results)

if __name__ == "__main__":
    main()
