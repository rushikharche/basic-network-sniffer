from scapy.all  import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine protocol name
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = str(proto)

        print(f"\n[+] {protocol} Packet:")
        print(f"    Source IP:      {src_ip}")
        print(f"    Destination IP: {dst_ip}")

        # Display port info if available
        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport
            print(f"    Source Port:    {sport}")
            print(f"    Destination Port: {dport}")

        # Display payload if present
        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"    Payload (str):  {payload.decode(errors='ignore')}")
            except:
                print(f"    Payload (bytes): {payload}")

# Start sniffing
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)