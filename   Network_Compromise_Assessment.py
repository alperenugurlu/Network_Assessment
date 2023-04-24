#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import time
from collections import defaultdict, Counter

import pyshark
from scapy.all import *

# Color print functions
def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))
def prLightPurple(skk): print("\033[94m {}\033[00m" .format(skk))
def prPurple(skk): print("\033[95m {}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))
def prLightGray(skk): print("\033[97m {}\033[00m" .format(skk))
def prBlack(skk): print("\033[98m {}\033[00m" .format(skk))

prCyan('''
                                _                 ___  
                               | |               / _ \ 
  _ __ ___     ___  __      __ | |_  __      __ | | | -|
 | '_ ` _ \   / _ \ \ \ /\ / / | __| \ \ /\ / / | | |----|
 | | | | | | |  __/  \ V  V /  | |_   \ V  V /  | |_| --|
 |_| |_| |_|  \___|   \_/\_/    \__|   \_/\_/    \___/ 
                                                       
                                                                                                                         

         _                 
        //\lperen  |U|gurlu
                   `-'     

                      
''' )

prRed('''''''''''''''

        Network Compromise Assessment
         *    *      * * *  *   *  
        * *    ******          * * 
           **         *   ** **   *
                         *         
                      *   ** **    
        *     *                   *
           *    *   *          *   
          *            *    *   ** 
               *   *               
            *    *                 
                                   
         *        *  *             


''''''''''''''')

def get_user_input():
    file_path = input("Please enter the path to the .pcap or .pcapng file: ")
    return file_path

prGreen('''            Scanning In Progress......
''')

time.sleep(4.0)

def get_all_ip_addresses(capture):
    ip_addresses = set()
    for packet in capture:
        if hasattr(packet, 'IP'):
            ip_addresses.add(packet['IP'].src)
            ip_addresses.add(packet['IP'].dst)
    return ip_addresses

def detect_dns_tunneling(packet):
    if hasattr(packet, 'DNS') and packet.DNS.qr == 0:
        for i in range(packet[DNS].ancount):
            if packet[DNS].an[i].type == 16 and len(packet[DNS].an[i].rdata) > 100:
                print(f"[+] Suspicious activity detected: DNS Tunneling")
                print(packet)

def detect_ssh_tunneling(packet):
    if hasattr(packet, 'SSH') and hasattr(packet, 'TCP') and (packet['TCP'].sport > 1024 or packet['TCP'].dport > 1024):
        print(f"[+] Suspicious activity detected: SSH Tunneling")
        print(packet)

def detect_tcp_session_hijacking(packet):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'FA' and int(packet['TCP'].seq) > 0 and int(packet['TCP'].ack) > 0:
        print(f"[+] Suspicious activity detected: TCP Session Hijacking")
        print(packet)

def detect_smb_attack(packet):
    if hasattr(packet, 'SMB2') and packet['SMB2'].command == 5:
        print(f"[+] Suspicious activity detected: SMB Attack")
        print(packet)

def detect_smtp_dns_attack(packet):
    if (hasattr(packet, 'SMTP') and packet['SMTP'].command == 'HELO') or (hasattr(packet, 'DNS') and packet['DNS'].opcode == 2):
        print(f"[+] Suspicious activity detected: SMTP or DNS Attack")
        print(packet)

def detect_ipv6_fragmentation_attack(packet):
    if hasattr(packet, 'IPv6') and hasattr(packet, 'IPv6ExtHdrFragment') and int(packet['IPv6ExtHdrFragment'].plen) > 1500:
        print(f"[+] Suspicious activity detected: IPv6 Fragmentation Attack")
        print(packet)

def detect_tcp_rst_attack(packet):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'R' and int(packet['TCP'].window) == 0:
        print(f"[+] Suspicious activity detected: TCP RST Attack")
        print(packet)

def detect_syn_flood_attack(packet, syn_counter):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'S' and int(packet['TCP'].window) > 0:
        syn_counter[packet['IP'].src] += 1
        if syn_counter[packet['IP'].src] > 100:  # Adjust the threshold as needed
            print(f"[+] Suspicious activity detected: SYN Flood Attack")
            print(packet)

def detect_udp_flood_attack(packet):
    if hasattr(packet, 'UDP') and int(packet['UDP'].len) > 1024:
        print(f"[+] Suspicious activity detected: UDP Flood Attack")
        print(packet)

def detect_slowloris_attack(packet, slowloris_counter):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'PA' and int(packet['TCP'].window) > 0 and int(packet['TCP'].len) < 10:
        slowloris_counter[packet['IP'].src] += 1
        if slowloris_counter[packet['IP'].src] > 100:  # Adjust the threshold as needed
            print(f"[+] Suspicious activity detected: Slowloris Attack")
            print(packet)

def main():
    file_path = get_user_input()
    suspicious_keywords = ["password", "login", "admin", "root", "bank", "credit", "card", "paypal", "malware", "virus", "trojan"]

    capture = pyshark.FileCapture(file_path, keep_packets=False)
    ip_addresses = get_all_ip_addresses(capture)

    syn_counter = defaultdict(int)
    slowloris_counter = defaultdict(int)

    for source_ip in ip_addresses:
        print(f"\n[+] Checking for IP address {source_ip}")
        capture.reset()
        for packet in capture:
            if hasattr(packet, 'IP') and packet['IP'].src == source_ip:
                detect_dns_tunneling(packet)
                detect_ssh_tunneling(packet)
                detect_tcp_session_hijacking(packet)
                detect_smb_attack(packet)
                detect_smtp_dns_attack(packet)
                detect_ipv6_fragmentation_attack(packet)
                detect_tcp_rst_attack(packet)
                detect_syn_flood_attack(packet, syn_counter)
                detect_udp_flood_attack(packet)
                detect_slowloris_attack(packet, slowloris_counter)
                for keyword in suspicious_keywords:
                    if keyword in str(packet):
                        print(f"[+] Suspicious keyword detected: {keyword}")
                        print(packet)
                        break

if __name__ == "__main__":
    main()
