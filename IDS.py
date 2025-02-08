from scapy.all import sniff, IP, TCP, UDP
import datetime

# Define suspicious patterns (e.g., excessive SYN requests, unusual ports)
suspicious_patterns = {
    "SYN_FLOOD": [],  # Track multiple SYN requests from same IP
    "PORT_SCANNING": []
}

# Function to analyze captured packets
def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == 2:  # SYN flag set
                suspicious_patterns["SYN_FLOOD"].append(src_ip)
                if suspicious_patterns["SYN_FLOOD"].count(src_ip) > 10:
                    print(f"[ALERT] Possible SYN flood attack from {src_ip}")
        
        print(f"{datetime.datetime.now()} - {src_ip} -> {dst_ip} [{protocol}]")

# Start packet sniffing
def start_sniffing(interface="MediaTek MT7921 Wi-Fi 6 802.11ax PCIe Adapter"):
    print("Starting network intrusion detection system...")
    sniff(iface=interface, prn=analyze_packet, store=False, timeout=10)

if __name__ == "__main__":
    start_sniffing()
