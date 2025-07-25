#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import socket
import csv
import json

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="target", help="Target IP / IP Range")
    parser.add_argument("-o", "--output", dest="output", help="Export format: csv or json", choices=["csv", "json"])
    options = parser.parse_args()
    if not options.target:
        parser.error("[!] Please add a target IP or IP range (e.g., 192.168.1.1/24), --help for more information.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=1, verbose=False)[0]

    packet_list = []
    for sent, received in answered:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "N/A"
        packet_dict = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": hostname
        }
        packet_list.append(packet_dict)
    return packet_list

def print_res(res):
    print("""
######################################################################
#--> Network Scanner                                             <--# 
#--> by BORG                                                     <--# 
######################################################################
""")
    print("{:<16} {:<20} {}".format("IP", "MAC Address", "Hostname"))
    print("=" * 60)
    for n in res:
        print("{:<16} {:<20} {}".format(n["ip"], n["mac"], n["hostname"]))

def export_results(data, format, filename="scan_results"):
    if not data:
        print("[!] No data to export.")
        return

    if format == "csv":
        keys = data[0].keys()
        with open(f"{filename}.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        print(f"[+] Results exported to {filename}.csv")
    elif format == "json":
        with open(f"{filename}.json", "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Results exported to {filename}.json")

if __name__ == "__main__":
    options = get_arguments()
    scan_result = scan(options.target)
    print_res(scan_result)

    if options.output:
        export_results(scan_result, options.output)
