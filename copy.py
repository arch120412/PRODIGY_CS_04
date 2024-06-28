from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Check for TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            print(f"Payload: {bytes(tcp_layer.payload)}")
        
        # Check for UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Packet: {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
            print(f"Payload: {bytes(udp_layer.payload)}")

# Ensure scapy uses npcap
conf.use_pcap = True

# Sniff packets
sniff(prn=packet_callback, filter="ip", store=0)
    
