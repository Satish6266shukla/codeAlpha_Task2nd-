from scapy.all import sniff
from scapy.layers.inet import IP

def packet_callback(packet):
# this is the task 1st about of captured the network traffic packets 
    
    
    if packet.haslayer(IP):
        print("=" * 50)
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)
        print("Protocol       :", packet[IP].proto)

        if packet.payload:
            print("Payload:")
            print(packet.payload)

print("Starting Network Sniffer...")
print("Press Ctrl + C to Stop.\n")

sniff(prn=packet_callback, store=False)



# "pip instaall scapy " run this command to run this code in vs code 
