# Network Assessment

With Wireshark or TCPdump, you can determine whether there is harmful activity on your network traffic that you have recorded on the network you monitor.

This Python script analyzes network traffic in a given .pcap file and attempts to detect the following suspicious network activities and attacks:

1. DNS Tunneling
2. SSH Tunneling
3. TCP Session Hijacking
4. SMB Attack
5. SMTP or DNS Attack
6. IPv6 Fragmentation Attack
7. TCP RST Attack
8. SYN Flood Attack
9. UDP Flood Attack
10. Slowloris Attack

The script also tries to detect packages containing suspicious keywords (eg "password", "login", "admin", etc.). Detected suspicious activities and attacks are displayed to the user in the console.

The main functions are:

- `get_user_input()`: Gets the path of the .pcap file from the user.
- `get_all_ip_addresses(capture)`: Returns a set containing all source and destination IP addresses.
- `detect_*` functions: Used to detect specific attacks and suspicious activities.
- `main()`: Performs the main operations of the script. First, it gets the path of the .pcap file from the user, and then analyzes the file to try to detect the specified attacks and suspicious activity.

# How to Install Script?

`git clone https://github.com/alperenugurlu/Network_Assessment.git`

`pip3 install -r requirements.txt`

# How to Run the Script?

`python3 Network_Compromise_Assessment.py`

`Please enter the path to the .pcap or .pcapng file: /root/Desktop/TCP_RST_Attack.pcap` (Example)

![image](https://user-images.githubusercontent.com/64872731/234106703-c88a71c8-9150-47ae-a93e-d266426ce5e8.png)


# Script Creator

`Alperen Ugurlu`

# Social media:
