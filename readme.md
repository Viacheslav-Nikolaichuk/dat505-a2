# ARP Spoofing, Traffic Capture & DNS Spoofing (DAT505)

This repository contains three small Scapy-based tools used to complete an Ethical Hacking assignment:

1. **Task 1:** ARP spoofing to place the attacker in the middle.
2. **Task 2:** Traffic capture and lightweight parsing (URLs, DNS queries, top talkers, protocol counts).
3. **Task 3:** DNS spoofing to redirect a victim’s browser to the attacker’s web page.

The repo also includes evidence (Wireshark screenshots, ARP tables), PCAPs collected during the tasks, and CSV/log outputs produced by the scripts.

---

## Folder Structure

```text
arp_spoof.py
dns_spoof.py
traffic_interceptor.py
domains.txt

evidence/
  T1-arp_spoof_runnig.png
  T1-server-after.png
  T1-server-before.png
  T1-victim-after.png
  T1-victim-before.png
  T1-victim-spoof-ping.png
  T1-wireshark-f1.png
  T1-wireshark-f2.png
  T1-wireshark-f3.png
  T1-wireshark-f4.png
  T2-wireshark-dns.png
  T2-wireshark-http.png
  T3-victim-correct-page.png
  T3-victim-spoofed-page.png
  T3-wireshark-proof.png
  extracts.csv
  logs.txt

pcap_files/
  task1.pcap
  task2.pcap
  task3.pcap
```

- `evidence/` holds screenshots proving each step (before/after ARP tables, Wireshark frames, spoofed page, etc.).
- `pcap_files/` holds the captures saved during the assignment.
- `domains.txt` maps domains to the attacker IP for Task 3.

---

## Network Setup Used in the Assignment

All three VMs are on the same isolated network:

- **server-vm (gateway/DNS/web):** `192.168.1.1`
- **victim-vm:** `192.168.1.10`
- **attacker:** `192.168.1.20`

Interfaces in the examples below use `eth0`. Adjust if yours is different.

---

## Requirements

- Python 3
- `scapy` installed on the attacker VM (`sudo apt install python3-scapy` on Debian/Ubuntu/Kali)
- Root privileges (all scripts sniff or send crafted packets)
- Web server on attacker and server VMs (for demonstrating DNS spoofing)

Run everything with `sudo` unless your system is already running Python with the needed capabilities.

---

## Task 1 - ARP Spoofing

Goal: poison ARP tables of the victim and the server/gateway so traffic flows through the attacker.

### Run

```bash
sudo python3 arp_spoof.py 192.168.1.10 192.168.1.1 eth0 --forward -v
```

- `192.168.1.10` - victim
- `192.168.1.1` - gateway/server
- `eth0` - attacker interface
- `--forward` enables IP forwarding on the attacker so ping/HTTP still work
- `-v` prints number of ARP packets sent

This script keeps sending ARP replies to both ends until interrupted. On Ctrl+C it restores ARP tables.

### Capture for Task 1

While spoofing is active, the assignment captured ICMP through the attacker:

```bash
sudo tcpdump -i eth0 -w task1.pcap host 192.168.1.10 and icmp
```

The resulting file is saved as `pcap_files/task1.pcap` and illustrated in `evidence/T1-*.png`.

---

## Task 2 - Traffic Capture & Analysis

Goal: sniff common protocols during MitM and produce:
- a PCAP
- a human-readable log
- CSV extracts (URLs, DNS queries, top talkers, protocol counts)

First start ARP spoofing again (same as Task 1), then in a second terminal run:

```bash
sudo python3 traffic_interceptor.py eth0 -o task2.pcap
```

Now generate traffic from the **victim** (examples used in the report):

```bash
dig example.com
wget http://example.com/
ping 192.168.1.1
```

Then stop the interceptor with Ctrl+C. The script writes:

- `task2.pcap` (or the name you passed with `-o`) → stored under `pcap_files/`
- `logs.txt` → packet summaries (stored in `evidence/logs.txt` in this repo)
- `extracts.csv` → collected URLs, DNS queries, top talkers, protocol counts (stored in `evidence/extracts.csv`)

You can open `pcap_files/task2.pcap` in Wireshark; screenshots showing DNS and HTTP are in `evidence/T2-*`.

---

## Task 3 - DNS Spoofing

Goal: when the victim browses to `example.com`, they should get the page from the attacker (`192.168.1.20`) instead of the real server.

### 1. ARP spoof again

For DNS spoofing we ran ARP spoof **without** IP forwarding in the report (to show that the attacker MAC is the sender of the forged DNS):

```bash
sudo python3 arp_spoof.py 192.168.1.10 192.168.1.1 eth0 -v
```

### 2. Check spoof config

`domains.txt` contains:

```text
example.com 192.168.1.20
```

This means: if the victim asks for `example.com`, answer with attacker IP.

### 3. Run DNS spoofer

```bash
sudo python3 dns_spoof.py eth0 -c domains.txt -f 192.168.1.1
```

- `-c domains.txt` → domains to spoof
- `-f 192.168.1.1` → forward non-spoofed DNS to real server (gateway)

### 4. Capture proof

Parallel tcpdump to show forged DNS answers:

```bash
sudo tcpdump -i eth0 udp port 53 -w task3.pcap
```

The resulting capture is stored under `pcap_files/task3.pcap`. Screenshots:
- `evidence/T3-victim-correct-page.png` - real page
- `evidence/T3-victim-spoofed-page.png` - attacker page
- `evidence/T3-wireshark-proof.png` - Wireshark showing forged answer coming from attacker MAC

---

## Scripts Overview

### `arp_spoof.py`
- Resolves MACs using ARP
- Sends ARP replies to victim and gateway every 2 seconds
- Optional IP forwarding toggle
- Restores ARP on exit

### `traffic_interceptor.py`
- Sniffs on an interface
- Tries to parse HTTP (if Scapy HTTP layer is available)
- Logs packet summaries to `logs.txt`
- Writes structured data to `extracts.csv`
- Saves all sniffed packets to a PCAP file

### `dns_spoof.py`
- Loads a simple `domain → IP` mapping from a text file
- Listens for DNS queries
- If the query matches, sends a forged DNS response with attacker-chosen IP
- Otherwise optionally forwards to a real DNS/gateway

---

## Evidence

All screenshots referenced in the report are under `evidence/` and correspond 1:1 to the steps above:

- Task 1: ARP tables before/after, ICMP path through attacker, Wireshark frames 1-4
- Task 2: DNS and HTTP traffic observed during MitM
- Task 3: Correct vs spoofed page, plus Wireshark showing the forged DNS answer with attacker MAC

PCAPs that produced these screenshots are under `pcap_files/`.

---

## Notes

- All commands above were run from the project root.
- If your interface is not `eth0`, change it in the commands.
- These scripts are for educational/lab use on controlled networks only.
- I used Generative AI to help structure code and validate the implementation throughout Assignment 3. Generative AI was used as an assisting tool.