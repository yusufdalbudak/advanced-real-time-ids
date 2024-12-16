from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
import csv
import re
import socket
import time
from collections import defaultdict
import json
from dotenv import load_dotenv # type: ignore
import os
import os
import json

# Get the absolute path to config.json
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")   

# Load configuration from file
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

# Assign values from config
TARGET_IP = config["TARGET_IP"]
INTERFACE = config["INTERFACE"]
SUS_PATTERNS = [pattern.encode() for pattern in config["SUS_PATTERNS"]]
PAYLOAD_SIZE_THRESHOLD = config["PAYLOAD_SIZE_THRESHOLD"]
TRAFFIC_THRESHOLD = config["TRAFFIC_THRESHOLD"]







# Load environment variables from .env file
load_dotenv()

TARGET_IP = os.getenv("TARGET_IP")
INTERFACE = os.getenv("INTERFACE")
SUS_PATTERNS = os.getenv("SUS_PATTERNS").split(",")
PAYLOAD_SIZE_THRESHOLD = int(os.getenv("PAYLOAD_SIZE_THRESHOLD"))
TRAFFIC_THRESHOLD = int(os.getenv("TRAFFIC_THRESHOLD"))






# Configuration
TARGET_IP = "192.168.x.x"  # <-Target IP address
SUS_PATTERNS = [b'danger.com', b'unauthorized_access']
SUS_KEYWORDS = [b'login', b'admin', b'password', b'hack', b'attack']
TRAFFIC_THRESHOLD = 50
PAYLOAD_SIZE_THRESHOLD = 1000

# Generate a unique CSV file name
timestamp = time.strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"traffic_log_{timestamp}.csv"

# Traffic counters
ip_counters = defaultdict(int)
start_time = time.time()

# Initialize CSV file
def initialize_csv():
    with open(CSV_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Timestamp", "Source IP", "Source Hostname", "Destination IP",
                         "Destination Hostname", "Source Port", "Destination Port", 
                         "Protocol", "Payload Size", "Details", "Status"])

# Log packet details
def log_to_csv(data):
    with open(CSV_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(data)

# Perform reverse DNS lookup with fallback
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]  # Returns hostname
    except socket.herror:
        return "No PTR Record"  # Clarify when no hostname is available
    except Exception as e:
        return f"Error: {str(e)}"  # Handle other exceptions gracefully


# Analyze DNS Packets
def analyze_dns(packet):
    if packet.haslayer(DNSQR):  # DNS Query
        queried_domain = packet[DNSQR].qname.decode()
        details = f"DNS Query: {queried_domain}"
        if any(pattern.decode() in queried_domain for pattern in SUS_PATTERNS):
            return f"Suspicious DNS Query: {queried_domain}"
        return details
    return None

# Packet callback function
def packet_callback(packet):
    global start_time, ip_counters

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Get hostnames with fallback
        src_hostname = get_hostname(src_ip)
        dst_hostname = get_hostname(dst_ip)

        protocol = "Other"
        status = "Normal"
        details = "Normal Traffic"

        # Transport Layer: TCP and UDP
        src_port = "-"
        dst_port = "-"
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if packet.haslayer(DNS):
                dns_details = analyze_dns(packet)
                if dns_details:
                    status = "Suspicious" if "Suspicious" in dns_details else "Normal"
                    details = dns_details

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            details = f"ICMP Packet: Type={packet[ICMP].type}"

        # Application Layer: Raw Payload
        payload = b""
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            for pattern in SUS_PATTERNS:
                if re.search(pattern, payload):
                    status = "Suspicious"
                    details = f"Pattern Matched: {pattern.decode()}"
                    print(f"Signature Detected: {details}")
            if len(payload) > PAYLOAD_SIZE_THRESHOLD:
                status = "Suspicious"
                details = f"Large Payload Detected: {len(payload)} bytes"

        # Print packet details in the terminal
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
              f"Src: {src_ip} ({src_hostname}) -> Dst: {dst_ip} ({dst_hostname}), "
              f"Protocol: {protocol}, Status: {status}, Details: {details}")

        # Log to CSV file
        log_to_csv([time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, src_hostname, dst_ip, dst_hostname,
                    src_port, dst_port, protocol, len(payload), details, status])

        # Update IP counters
        ip_counters[src_ip] += 1
        ip_counters[dst_ip] += 1    

def main():
    print(f"Starting IDS... Logging to {CSV_FILE}")
    initialize_csv()

    # Start packet capture
    iface = "\\Device\\NPF_{E0A12ABF-94F4-4807-****-**********}" #<-- Write your iface. 
    try:
        sniff(iface=iface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nIDS Stopped. Check the CSV file for logged data.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
