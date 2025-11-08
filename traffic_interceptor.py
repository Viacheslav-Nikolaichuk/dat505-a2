import argparse
import csv
from collections import Counter

import scapy.all as scapy
try:
    from scapy.layers.http import HTTPRequest
    HAS_HTTP = True
except ImportError:
    HTTPRequest = None
    HAS_HTTP = False


def process_packet(packet, output_file, urls, dns_queries, protocols, top_talkers):
    if packet.haslayer(scapy.IP):
        src = packet[scapy.IP].src
        dst = packet[scapy.IP].dst
        top_talkers[src] += 1
        top_talkers[dst] += 1
        proto = packet[scapy.IP].proto
        protocols[proto] += 1

        if packet.haslayer(scapy.ICMP):
            print(f"[+] ICMP {src} -> {dst}")

    if HAS_HTTP and packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        host = http_layer.Host or b""
        path = http_layer.Path or b"/"
        url = (host + path).decode(errors="ignore")
        urls.append(url)

    elif packet.haslayer(scapy.DNSQR):
        query = packet[scapy.DNSQR].qname.decode(errors="ignore")
        dns_queries.append(query)

    elif packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 22 or packet[scapy.TCP].sport == 22):
        print("[+] SSH packet detected")

    elif packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 21 or packet[scapy.TCP].sport == 21):
        print("[+] FTP packet detected")

    with open(output_file, "a") as f:
        f.write(packet.summary() + "\n")


def main():
    parser = argparse.ArgumentParser(description="Traffic Interceptor")
    parser.add_argument("interface", help="Interface to sniff (e.g. eth0)")
    parser.add_argument(
        "-o",
        "--output",
        default="capture.pcap",
        help="PCAP output file (default: capture.pcap)",
    )
    args = parser.parse_args()

    urls = []
    dns_queries = []
    protocols = Counter()
    top_talkers = Counter()

    print(f"[*] Sniffing on {args.interface}. Ctrl+C to stop.")
    print(f"[*] HTTP parsing: {'enabled' if HAS_HTTP else 'not available'}")

    packets = []
    try:
        # sniff returns a PacketList when store=True
        packets = scapy.sniff(
            iface=args.interface,
            store=True,
            prn=lambda p: process_packet(
                p,
                "logs.txt",
                urls,
                dns_queries,
                protocols,
                top_talkers,
            ),
        )
    except KeyboardInterrupt:
        print("[-] Stopping sniff.")

    if packets:
        scapy.wrpcap(args.output, packets)
    else:
        print("[!] No packets captured, PCAP will be empty or not very useful.")

    with open("extracts.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(["URLs"])
        for url in urls:
            writer.writerow([url])

        writer.writerow([])

        writer.writerow(["DNS Queries"])
        for q in dns_queries:
            writer.writerow([q])

        writer.writerow([])

        writer.writerow(["Top Talkers", "Count"])
        for talker, count in top_talkers.most_common(10):
            writer.writerow([talker, count])

        writer.writerow([])

        writer.writerow(["Protocol (IP proto number)", "Count"])
        for proto, count in protocols.items():
            writer.writerow([proto, count])

    print(f"[+] Saved PCAP to {args.output} and extracts to extracts.csv")
    print("[+] Logs in logs.txt")


if __name__ == "__main__":
    main()
