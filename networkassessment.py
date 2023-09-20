#!/usr/bin/python
# -*- coding: utf-8 -*-

#creator   : Alperen Uğurlu
#updated by: Halil Deniz


import os
import sys
import time
from collections import defaultdict, Counter
import argparse
import pyshark
from scapy.all import *
from scapy.layers.dns import DNS
from colorama import Fore, Style, init
from style.figletstyle import colorStyle

init(autoreset=True)  # Automatically reset color after each print statement

class NetworkCompromiseAssessment:
    def __init__(self, file_path, protocols=None):
        self.file_path = file_path
        self.protocols = protocols
        self.number_packet = args.number_packet
        self.suspicious_keywords = ["password", "login", "admin", "root", "bank", "credit", "card", "paypal", "malware", "virus", "trojan"]
        self.syn_counter = defaultdict(int)
        self.slowloris_counter = defaultdict(int)
        self.capture = pyshark.FileCapture(file_path, keep_packets=False)
        self.ip_addresses = self.get_all_ip_addresses()

    def save_to_file(self, message, file_path=None):
        if file_path:
            with open(file_path, 'a') as f:
                f.write(message + "\n")

    def get_all_ip_addresses(self):
        ip_addresses = set()
        index = 0
        for packet in self.capture:
            index += 1
            if hasattr(packet, 'IP'):
                ip_addresses.add(packet['IP'].src)
                ip_addresses.add(packet['IP'].dst)
            print(f"\r{Fore.CYAN}Scanned:{Style.RESET_ALL} {index}",end="")
        return ip_addresses

    def detect_dns_tunneling(self, packet):
        if 'DNS' in packet:
            dns_layer = packet['DNS']
            if hasattr(dns_layer, 'qr') and dns_layer.qr == '0':
                for i in range(len(dns_layer.answers)):
                    if 'type' in dns_layer.answers[i] and dns_layer.answers[i].type == 'TXT' and len(
                            dns_layer.answers[i].data) > 100:
                        msg = f"[+] Suspicious activity detected: DNS Tunneling"
                        print(msg)
                        print(packet)
                        self.save_to_file(msg, args.output)
                        self.save_to_file(str(packet), args.output)


    def detect_ssh_tunneling(self, packet):
        if hasattr(packet, 'SSH') and hasattr(packet, 'TCP') and (
                packet['TCP'].sport > 1024 or packet['TCP'].dport > 1024):
            msg = f"[+] Suspicious activity detected: SSH Tunneling"
            print(msg)
            print(packet)
            self.save_to_file(msg, args.output)
            self.save_to_file(str(packet), args.output)


    def detect_tcp_session_hijacking(self, packet):
        if hasattr(packet, 'TCP') and packet['TCP'].flags == 'FA' and int(packet['TCP'].seq) > 0 and int(
                packet['TCP'].ack) > 0:
            msg = f"[+] Suspicious activity detected: TCP Session Hijacking"
            print(msg)
            print(packet)
            if args.output:
                self.save_to_file(msg, args.output)
                self.save_to_file(str(packet), args.output)

    def detect_smb_attack(self, packet):
        if hasattr(packet, 'SMB2') and packet['SMB2'].command == 5:
            msg = f"[+] Suspicious activity detected: SMB Attack"
            print(msg)
            print(packet)
            if args.output:
                self.save_to_file(msg, args.output)
                self.save_to_file(str(packet), args.output)

    def detect_smtp_dns_attack(self, packet):
        if (hasattr(packet, 'SMTP') and packet['SMTP'].command == 'HELO') or (
                hasattr(packet, 'DNS') and hasattr(packet['DNS'], 'opcode') and packet['DNS'].opcode == 2):
            msg = f"[+] Suspicious activity detected: SMTP or DNS Attack"
            print(msg)
            print(packet)
            if args.output:
                self.save_to_file(msg, args.output)
                self.save_to_file(str(packet), args.output)

    def detect_ipv6_fragmentation_attack(self, packet):
        if hasattr(packet, 'IPv6') and hasattr(packet, 'IPv6ExtHdrFragment') and int(
                packet['IPv6ExtHdrFragment'].plen) > 1500:
            msg = f"[+] Suspicious activity detected: IPv6 Fragmentation Attack"
            print(msg)
            print(packet)
            if args.output:
                self.save_to_file(msg, args.output)
                self.save_to_file(str(packet), args.output)
    def detect_tcp_rst_attack(self, packet):
        if hasattr(packet, 'TCP') and packet['TCP'].flags == 'R' and int(packet['TCP'].window) == 0:
            msg = f"[+] Suspicious activity detected: TCP RST Attack"
            print(msg)
            print(packet)
            if args.output:
                self.save_to_file(msg, args.output)
                self.save_to_file(str(packet), args.output)
    def detect_syn_flood_attack(self, packet):
        if hasattr(packet, 'TCP') and packet['TCP'].flags == 'S' and int(packet['TCP'].window) > 0:
            self.syn_counter[packet['IP'].src] += 1
            if self.syn_counter[packet['IP'].src] > 100:  # Adjust the threshold as needed
                msg = f"[+] Suspicious activity detected: SYN Flood Attack"
                print(msg)
                print(packet)
                if args.output:
                    self.save_to_file(msg, args.output)
                    self.save_to_file(str(packet), args.output)
    def detect_udp_flood_attack(self, packet):
        if 'UDP' in packet and int(packet.udp.length) > 1024:
            msg = f"[+] Suspicious activity detected: UDP Flood Attack"
            print(msg)
            print(packet)
            if args.output:
                self.save_to_file(msg, args.output)
                self.save_to_file(str(packet), args.output)
    def detect_slowloris_attack(self, packet):
        if hasattr(packet, 'TCP') and packet['TCP'].flags == 'PA' and int(packet['TCP'].window) > 0 and int(
                packet['TCP'].len) < 10:
            self.slowloris_counter[packet['IP'].src] += 1
            if self.slowloris_counter[packet['IP'].src] > 100:  # Adjust the threshold as needed
                msg = f"[+] Suspicious activity detected: Slowloris Attack"
                print(msg)
                print(packet)
                if args.output:
                    self.save_to_file(msg, args.output)
                    self.save_to_file(str(packet), args.output)

    def main(self):
        start_time = time.time() # Save start time
        colorStyle()

        time.sleep(1.0)
        index = 0

        packet_count = 0
        if self.number_packet:
            self.ip_addresses = sorted(list(self.ip_addresses))[:self.number_packet]

        for source_ip in self.ip_addresses:
            index += 1
            print(f"\n{Fore.CYAN}[+] {index}: Checking for IP address:{Style.RESET_ALL} {source_ip}")
            self.capture.reset()
            for packet in self.capture:
                if hasattr(packet, 'IP') and packet['IP'].src == source_ip:
                    if self.protocols is None or packet.transport_layer in self.protocols:
                        self.detect_dns_tunneling(packet)
                        self.detect_ssh_tunneling(packet)
                        self.detect_tcp_session_hijacking(packet)
                        self.detect_smb_attack(packet)
                        self.detect_smtp_dns_attack(packet)
                        self.detect_ipv6_fragmentation_attack(packet)
                        self.detect_tcp_rst_attack(packet)
                        self.detect_syn_flood_attack(packet)
                        self.detect_udp_flood_attack(packet)
                        self.detect_slowloris_attack(packet)
                        for keyword in self.suspicious_keywords:
                            if keyword in str(packet):
                                msg = f"{Fore.RED}[+] Suspicious keyword detected:{Style.RESET_ALL} {keyword}"
                                print(msg)
                                print(packet)
                                if args.output:
                                    self.save_to_file(msg, args.output)
                                    self.save_to_file(str(packet), args.output)
                                    break
                packet_count += 1

        end_time = time.time()
        elapsed_time = end_time - start_time
        msg = f"Scanning completed in {elapsed_time:.2f} seconds"
        print(msg)
        if args.output:
            self.save_to_file(msg, args.output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Compromise Assessment Tool")
    parser.add_argument("-f","--file", type=str, required=True, help="Path to the .pcap or .pcapng file")
    parser.add_argument("-p","--protocols", nargs="+", type=str, choices=["TCP", "UDP", "DNS", "HTTP", "SMTP", "SMB"], help="Specify protocols to scan (e.g., TCP UDP)")
    parser.add_argument("-o", "--output", type=str, help="Path to save the scan results (optional)")
    parser.add_argument("-n", "--number-packet", type=int, help="Number of packets to scan (optional)")
    args = parser.parse_args()

    try:
        assessment = NetworkCompromiseAssessment(args.file, args.protocols)
        assessment.main()
    except KeyboardInterrupt:
        print("\n[!] Program by user request (Ctrl+C) was terminated.")
        sys.exit(0)
