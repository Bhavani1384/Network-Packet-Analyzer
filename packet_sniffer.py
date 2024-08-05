from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")
        
        
        if TCP in packet:
            print(f"Protocol: TCP")
        elif UDP in packet:
            print(f"Protocol: UDP")
        else:
            print(f"Protocol: {packet.proto}")

        
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload Data: {payload.decode(errors='ignore')}")
        else:
            print("Payload Data: No payload")

        print("-" * 40)

def start_sniffing(interface=None):
   
    print("Starting packet sniffer...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffing(interface)

