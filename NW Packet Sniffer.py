from scapy.all import *

# Function to process captured packets
def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"[+] Packet: {packet[IP].src} -> {packet[IP].dst} | Protocol: {packet.proto}")
    if packet.haslayer(Raw):
        print(f"[*] Data: {packet[Raw].load}")

# Function to start sniffing network packets
def start_sniffer(interface):
    print(f"[INFO] Sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=False, timeout=10)

# Example usage
if __name__ == "__main__":
    network_interface = input("Enter network interface (e.g., eth0, wlan0): ")
    start_sniffer(network_interface)
