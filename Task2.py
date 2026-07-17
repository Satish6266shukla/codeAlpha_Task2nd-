#this is the source code about of network instrusion detection system



from scapy.all import sniff
from scapy.layers.inet import IP

# Count packets from each IP
packet_count = {}

THRESHOLD = 20   # Alert after 20 packets


def detect(packet):
    if packet.haslayer(IP):
        src = packet[IP].src

        packet_count[src] = packet_count.get(src, 0) + 1

        print(f"Source IP: {src} | Packets: {packet_count[src]}")

        if packet_count[src] > THRESHOLD:
            print("=" * 50)
            print("ALERT!")
            print(f"Suspicious activity detected from {src}")
            print("=" * 50)


print("Network IDS Started...")
print("Press Ctrl+C to Stop.\n")

sniff(prn=detect, store=False)


# "pip install scapy" run this command in terminal for run this code 
