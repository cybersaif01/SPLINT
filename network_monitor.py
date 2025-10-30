import config
import requests
import os
import time
from scapy.all import sniff, IP, TCP, UDP
import urllib3

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER_REPORT_URL = f"{config.get_config('SERVER_URL')}/api/network/report"
SYSTEM_ID = os.uname().nodename
PACKET_BUFFER = []
BUFFER_SIZE = 20 # Send data in batches of 20 packets

def report_network_activity():
    """Sends the buffered network data to the central server."""
    global PACKET_BUFFER
    if not PACKET_BUFFER:
        return

    try:
        # Create a copy and clear the buffer immediately to prevent race conditions
        data_to_send = list(PACKET_BUFFER)
        PACKET_BUFFER.clear()

        payload = {
            "system_id": SYSTEM_ID,
            "connections": data_to_send
        }
        requests.post(SERVER_REPORT_URL, json=payload, verify=False, timeout=10)
    except requests.exceptions.RequestException as e:
        # Silently fail to avoid flooding the console in a busy network environment
        pass
    except Exception:
        pass


def packet_callback(packet):
    """
    This function is called for every packet captured by Scapy.
    It extracts metadata and adds it to the buffer.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        protocol_name = "Other"

        # Determine protocol and ports
        src_port, dst_port = 0, 0
        if TCP in packet:
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        connection_data = {
            "timestamp": time.time(),
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "protocol": protocol_name
        }
        PACKET_BUFFER.append(connection_data)

        # When the buffer is full, send the data
        if len(PACKET_BUFFER) >= BUFFER_SIZE:
            report_network_activity()


def start_network_monitoring():
    """Starts the Scapy network sniffer."""
    print("[Network Monitor] Starting real-time network traffic analysis...")
    try:
        # The 'prn' argument specifies the callback function for each packet.
        # 'store=0' tells Scapy not to store the packets in memory.
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"[Network Monitor] CRITICAL ERROR: Could not start packet sniffing. Ensure you are running as root and libpcap is installed.")
        print(f"  └── Error: {e}")
