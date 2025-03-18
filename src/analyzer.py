import scapy.all as scapy
from collections import defaultdict
import datetime
import os
import config
import logger

# Data structures for tracking network activity
syn_count = defaultdict(int)
port_scans = defaultdict(set)

def detect_suspicious_activity(packet):
    """Analyzes network packets to detect potential attacks."""
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        dst_port = packet[scapy.TCP].dport
        flags = packet[scapy.TCP].flags
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Detecting SYN Flood (Too many SYN requests from one source)
        if flags == 2:  # SYN flag
            syn_count[src_ip] += 1
            if syn_count[src_ip] > config.SYN_THRESHOLD:
                alert_message = f"[ALERT] {timestamp} - Possible SYN Flood attack from {src_ip}"
                print(alert_message)
                logger.log_suspicious_activity(alert_message)

        # Detecting Port Scanning (Multiple requests to different ports from one source)
        port_scans[src_ip].add(dst_port)
        if len(port_scans[src_ip]) > config.PORT_SCAN_THRESHOLD:
            alert_message = f"[ALERT] {timestamp} - Possible Port Scanning detected from {src_ip}"
            print(alert_message)
            logger.log_suspicious_activity(alert_message)

def start_sniffing():
    """Starts packet sniffing on TCP traffic."""
    print("Starting network traffic monitoring...")
    scapy.sniff(filter="tcp", prn=detect_suspicious_activity, store=False)

if __name__ == "__main__":
    start_sniffing()
