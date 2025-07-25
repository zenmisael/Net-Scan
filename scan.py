#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import socket
import csv
import json
import sys
import ipaddress
from tqdm import tqdm

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP network scanner with reverse DNS and export options.")
    parser.add_argument("-i", "--ip", dest="target", required=True, help="Target IP or subnet (e.g., 192.168.1.1/24)")
    parser.add_argument("-o", "--output", dest="output", choices=["csv", "json"], help="Export format")
    return parser.parse_args()

def scan(target):
    try:
        ip_net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print("[!] Invalid IP/Subnet format.")
        sys.exit(1)

    result_list = []

    for ip in tqdm(ip_net.hosts(), desc="Scanning", unit="host"):
        arp_request = scapy.ARP(pdst=str(ip))
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered = scapy.srp(packet, timeout=1, verbose=False)[0]

        for sent, received in answered:
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except socket.herror:
                hostname = "N/A"

            result_list.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": hostname
            })

    return result_list

def print_results(results):
    print("""
######################################################################
#--> Network Scanner                                              <--#
#--> by BORG                                                      <--#
######################################################################
""")
    print("{:<16} {:<20} {}".format("IP Address", "MAC Address", "Hostname"))
    print("=" * 60)
    for r in results:
        print("{:<16} {:<20} {}".format(r["ip"], r["mac"], r["hostname"]))

def export_results(results, fmt, filename="scan_results"):
    if not results:
        print("[!] No results to export.")
        return

    try:
        if fmt == "csv":
            with open(f"{filename}.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "mac", "hostname"])
                writer.writeheader()
                writer.writerows(results)
            print(f"[+] Exported to {filename}.csv")
        elif fmt == "json":
            with open(f"{filename}.json", "w") as f:
                json.dump(results, f, indent=4)
            print(f"[+] Exported to {filename}.json")
    except Exception as e:
        print(f"[!] Export error: {e}")

if __name__ == "__main__":
    args = get_arguments()
    try:
        scan_result = scan(args.target)
        print_results(scan_result)
        if args.output:
            export_results(scan_result, args.output)
    except PermissionError:
        print("[!] Permission denied. Try running with sudo or as administrator.")
