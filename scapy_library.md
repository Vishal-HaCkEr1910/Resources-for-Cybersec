# Scapy Library - Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Packet Creation](#packet-creation)
4. [Packet Manipulation](#packet-manipulation)
5. [Packet Sending](#packet-sending)
6. [Packet Sniffing](#packet-sniffing)
7. [Layer Functions](#layer-functions)
8. [Advanced Features](#advanced-features)

---

## Introduction

### What is Scapy?

Scapy is a Python library that enables users to send, sniff, dissect, and forge network packets. It can perform various tasks like network discovery, port scanning, tracerouting, and more. Scapy is a powerful tool for network engineering and security testing.

**Key Features:**
- Send and receive packets
- Sniff network traffic
- Dissect packet headers
- Forge custom packets
- Build network tools and protocols
- Perform network scanning and reconnaissance

---

## Installation

### Install Scapy

```bash
pip install scapy
```

### For Linux (with advanced features):

```bash
sudo apt-get install python3-scapy
pip install scapy[complete]
```

### Verify Installation

```python
from scapy.all import *
print("Scapy installed successfully!")
```

---

## Packet Creation

### Understanding Packet Layers

In networking, packets are structured in layers:
- **Layer 2 (Data Link):** Ethernet, ARP
- **Layer 3 (Network):** IP, ICMP
- **Layer 4 (Transport):** TCP, UDP
- **Layer 7 (Application):** HTTP, DNS, SMTP

### Basic Packet Creation

#### IP Packet Creation

```python
from scapy.all import IP, ICMP, TCP, UDP

# Create a simple IP packet
ip_packet = IP(dst="8.8.8.8")
print(ip_packet.show())

# IP packet with custom TTL
ip_custom = IP(dst="192.168.1.1", ttl=64, flags="DF")
print(ip_custom)
```

**Theory:** The IP layer contains source and destination IP addresses, TTL (Time To Live), and flags. TTL determines how many hops the packet can traverse.

#### ICMP Packet (Ping)

```python
from scapy.all import IP, ICMP

# Create an ICMP echo request (ping)
icmp_packet = IP(dst="8.8.8.8")/ICMP()
print(icmp_packet.show())

# ICMP with custom sequence
icmp_seq = IP(dst="1.1.1.1")/ICMP(type=8, code=0, id=1, seq=1)
```

**Theory:** ICMP is used for network diagnostics. Type 8 is echo request, and type 0 is echo reply.

#### TCP Packet

```python
from scapy.all import IP, TCP

# Create a TCP packet for port 80
tcp_packet = IP(dst="example.com")/TCP(dport=80, flags="S")
print(tcp_packet.show())

# TCP with multiple flags
tcp_flags = IP(dst="192.168.1.1")/TCP(sport=1234, dport=443, flags="SA", seq=1000, ack=2000)
```

**Theory:** TCP uses flags for connection management:
- **S (SYN):** Synchronize
- **A (ACK):** Acknowledgment
- **F (FIN):** Finish
- **R (RST):** Reset
- **P (PSH):** Push

#### UDP Packet

```python
from scapy.all import IP, UDP, DNSQR

# Create a UDP packet
udp_packet = IP(dst="8.8.8.8")/UDP(dport=53)
print(udp_packet.show())

# UDP with payload
udp_with_data = IP(dst="192.168.1.1")/UDP(sport=12345, dport=53)/Raw(load="test data")
```

**Theory:** UDP is connectionless and faster than TCP but doesn't guarantee delivery order or completeness.

#### ARP Packet

```python
from scapy.all import ARP

# Create ARP request
arp_request = ARP(pdst="192.168.1.1")
print(arp_request.show())

# ARP with custom fields
arp_custom = ARP(op="is-at", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
```

**Theory:** ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on local networks.

#### Ethernet Frame

```python
from scapy.all import Ether, IP, ICMP

# Create Ethernet frame with IP and ICMP
eth_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst="8.8.8.8")/ICMP()
print(eth_packet.show())

# Custom Ethernet
eth_custom = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff", type=0x0800)
```

**Theory:** Ethernet is the Layer 2 protocol defining MAC addresses and frame structure.

### Stacking Layers

```python
from scapy.all import IP, TCP, Raw

# Stack multiple layers
packet = IP(dst="example.com")/TCP(dport=80, flags="S")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
print(packet.show())

# Access individual layers
ip_layer = packet[IP]
tcp_layer = packet[TCP]
print(f"Destination IP: {ip_layer.dst}")
print(f"Destination Port: {tcp_layer.dport}")
```

---

## Packet Manipulation

### Accessing Packet Fields

```python
from scapy.all import IP, TCP

packet = IP(dst="192.168.1.1", ttl=64)/TCP(dport=80, seq=1000)

# Access fields
print(packet.dst)           # 192.168.1.1
print(packet[TCP].dport)    # 80
print(packet[IP].ttl)       # 64
print(packet[TCP].seq)      # 1000

# List all fields
packet.show()
```

### Modifying Packet Fields

```python
from scapy.all import IP, TCP

packet = IP(dst="8.8.8.8")/TCP(dport=443)

# Modify fields
packet[IP].ttl = 32
packet[TCP].flags = "S"
packet[TCP].sport = 12345

print(packet.show())
```

### Copying Packets

```python
from scapy.all import IP, TCP
import copy

packet1 = IP(dst="8.8.8.8")/TCP(dport=80)
packet2 = packet1.copy()

packet2[IP].dst = "1.1.1.1"
packet2[TCP].dport = 443

print("Original:", packet1[IP].dst)
print("Copy:", packet2[IP].dst)
```

### Checking Layer Presence

```python
from scapy.all import IP, TCP, Raw

packet = IP(dst="8.8.8.8")/TCP(dport=80)/Raw(load="data")

if IP in packet:
    print("IP layer present")
if TCP in packet:
    print("TCP layer present")
if UDP in packet:
    print("UDP layer present")
else:
    print("UDP layer NOT present")
```

### Payload Addition

```python
from scapy.all import IP, TCP, Raw

# Add payload to packet
packet = IP(dst="example.com")/TCP(dport=80)
packet = packet/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

print(packet.show())
print(f"Payload: {packet[Raw].load}")
```

---

## Packet Sending

### Sending Packets

#### Send (Layer 3)

```python
from scapy.all import IP, ICMP, send

# Send packet at Layer 3 (no return)
packet = IP(dst="8.8.8.8")/ICMP()
send(packet)  # Requires root/administrator privileges
```

**Theory:** `send()` sends raw IP packets, bypassing the OS networking stack. Requires elevated privileges.

#### Sendp (Layer 2)

```python
from scapy.all import Ether, IP, ICMP, sendp

# Send packet at Layer 2 (with Ethernet)
packet = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst="192.168.1.1")/ICMP()
sendp(packet, iface="eth0")  # Specify interface
```

**Theory:** `sendp()` sends packets at Layer 2, including Ethernet frames. Useful for local network tasks.

#### Sending Multiple Packets

```python
from scapy.all import IP, TCP, send

# Send multiple packets
for dport in [80, 443, 22, 3306]:
    packet = IP(dst="192.168.1.100")/TCP(dport=dport, flags="S")
    send(packet)
```

#### Sending with Receive (sr)

```python
from scapy.all import IP, ICMP, sr

# Send and receive packets
packets = IP(dst="8.8.8.8")/ICMP()
answered, unanswered = sr(packets, timeout=5)

# Process responses
for sent, received in answered:
    print(f"Reply from {received.src}: {received.show()}")

# Process unanswered
for packet in unanswered:
    print(f"No response from {packet.dst}")
```

**Theory:** `sr()` sends packets and waits for responses. Returns answered and unanswered packets separately.

#### Sending with Single Response (sr1)

```python
from scapy.all import IP, ICMP, sr1

# Send and get single response
response = sr1(IP(dst="8.8.8.8")/ICMP(), timeout=5)

if response:
    print(f"Received response from {response.src}")
    response.show()
else:
    print("No response received")
```

**Theory:** `sr1()` sends one packet and returns the first response received.

#### Sending with Layer 2 Response (srp)

```python
from scapy.all import Ether, ARP, srp

# Send and receive at Layer 2
packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1")
answered, unanswered = srp(packet, timeout=5, iface="eth0")

for sent, received in answered:
    print(f"MAC: {received.hwsrc}")
```

---

## Packet Sniffing

### Basic Packet Sniffing

```python
from scapy.all import sniff

# Sniff packets (requires root)
def packet_callback(packet):
    print(packet.summary())

sniff(prn=packet_callback, count=10)
```

**Theory:** `sniff()` captures packets from the network interface. The `prn` parameter specifies callback function.

### Sniffing with Filters

```python
from scapy.all import sniff

# Sniff only TCP traffic on port 80
sniff(filter="tcp port 80", prn=lambda x: x.show(), count=5)

# Sniff ICMP packets
sniff(filter="icmp", prn=lambda x: print(f"ICMP from {x[IP].src}"), count=5)

# Multiple filters
sniff(filter="tcp or udp", count=10, prn=lambda x: print(x.summary()))
```

**Common Filters:**
- `tcp`: TCP packets
- `udp`: UDP packets
- `icmp`: ICMP packets
- `port 80`: Port 80 traffic
- `dst 192.168.1.1`: Destination IP
- `src 8.8.8.8`: Source IP
- `tcp.flags.syn == 1`: SYN flag set

### Sniffing on Specific Interface

```python
from scapy.all import sniff

# Sniff on specific interface
sniff(iface="eth0", count=5, prn=lambda x: print(x.summary()))

# List available interfaces
from scapy.all import get_if_list
print(get_if_list())
```

### Sniffing with Processing

```python
from scapy.all import sniff, IP, TCP

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        if TCP in packet:
            print(f"TCP: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
        else:
            print(f"Packet from {ip_src} to {ip_dst}")

sniff(prn=process_packet, count=20)
```

### Sniffing and Storing Packets

```python
from scapy.all import sniff

# Sniff and store packets
packets = sniff(count=10)

# Access stored packets
for pkt in packets:
    print(pkt.summary())

# Save to file
packets.save("captured.pcap")

# Load from file
from scapy.all import rdpcap
loaded_packets = rdpcap("captured.pcap")
```

### Sniffing with Timeout

```python
from scapy.all import sniff
import time

# Sniff for 10 seconds
start_time = time.time()
packets = sniff(timeout=10, prn=lambda x: print(x.summary()))
print(f"Captured {len(packets)} packets")
```

---

## Layer Functions

### IP Layer Functions

#### IP Address Handling

```python
from scapy.all import IP

# Create IP packet
packet = IP(dst="192.168.1.0/24")
print(packet.dst)

# IP with various options
packet = IP(
    src="192.168.1.10",
    dst="8.8.8.8",
    ttl=64,
    id=1234,
    flags="DF",  # Don't Fragment
    proto=6      # TCP protocol number
)
print(packet.show())
```

### TCP Layer Functions

#### TCP Connection Simulation

```python
from scapy.all import IP, TCP, sr1

# SYN packet (connection initiation)
syn_packet = IP(dst="example.com")/TCP(dport=80, flags="S", seq=1000)
syn_ack = sr1(syn_packet, timeout=5)

if syn_ack:
    print("SYN-ACK received")
    
    # Send ACK packet (connection establishment)
    ack_packet = IP(dst="example.com")/TCP(
        dport=80,
        flags="A",
        seq=syn_ack[TCP].ack,
        ack=syn_ack[TCP].seq + 1
    )
    send(ack_packet)
```

### UDP Layer Functions

```python
from scapy.all import IP, UDP, Raw, sr1

# UDP packet with DNS query
dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/Raw(load=b"DNS query data")
response = sr1(dns_query, timeout=5)

if response:
    print(response.show())
```

### ICMP Layer Functions

```python
from scapy.all import IP, ICMP

# Various ICMP types
echo_request = IP(dst="8.8.8.8")/ICMP(type=8, code=0)
unreachable = ICMP(type=3, code=1)  # Host unreachable
time_exceeded = ICMP(type=11, code=0)  # TTL exceeded

print("Echo Request:", echo_request.show())
```

### DNS Layer Functions

```python
from scapy.all import IP, UDP, DNS, DNSQR

# DNS query packet
dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
    rd=1,
    qd=DNSQR(qname="example.com", qtype="A")
)
print(dns_query.show())
```

---

## Advanced Features

### Network Scanning

#### Port Scanning

```python
from scapy.all import IP, TCP, sr1

def port_scan(target, ports):
    for port in ports:
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        
        if response:
            if response[TCP].flags == "SA":
                print(f"Port {port} is OPEN")
            elif response[TCP].flags == "RA":
                print(f"Port {port} is CLOSED")
        else:
            print(f"Port {port} is FILTERED")

# Scan common ports
port_scan("192.168.1.1", [22, 80, 443, 3306, 5432])
```

### ARP Spoofing Detection

```python
from scapy.all import Ether, ARP, sendp

def send_arp_reply(target_ip, target_mac, spoof_ip):
    arp_reply = Ether(dst=target_mac)/ARP(
        op="is-at",
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip
    )
    sendp(arp_reply)

# Send ARP reply
send_arp_reply("192.168.1.10", "00:11:22:33:44:55", "192.168.1.1")
```

### Traceroute Implementation

```python
from scapy.all import IP, ICMP, sr1

def traceroute_custom(target, max_hops=30):
    for ttl in range(1, max_hops + 1):
        packet = IP(dst=target, ttl=ttl)/ICMP()
        response = sr1(packet, timeout=2, verbose=False)
        
        if response:
            print(f"Hop {ttl}: {response.src}")
            if response.src == target:
                break
        else:
            print(f"Hop {ttl}: *")

traceroute_custom("8.8.8.8")
```

### HTTP GET Request via Raw Packets

```python
from scapy.all import IP, TCP, Raw, send

# Craft HTTP GET request
http_request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
packet = IP(dst="example.com")/TCP(dport=80, flags="S")/Raw(load=http_request)

# Send packet
send(packet)
```

### Packet Injection

```python
from scapy.all import Ether, IP, ICMP, sendp
import time

def packet_injection_loop(target, count=100, interval=0.1):
    for i in range(count):
        packet = IP(dst=target)/ICMP()
        sendp(packet)
        time.sleep(interval)

# Inject 100 ICMP packets
packet_injection_loop("192.168.1.1")
```

### Creating Custom Protocols

```python
from scapy.all import Packet, ByteField, ShortField, IntField

class CustomProtocol(Packet):
    name = "Custom Protocol"
    fields_desc = [
        ByteField("version", 1),
        ByteField("message_type", 0),
        ShortField("length", 0),
        IntField("identifier", 0)
    ]

# Use custom protocol
custom_pkt = CustomProtocol(version=1, message_type=5, identifier=12345)
print(custom_pkt.show())
```

---

## Summary

Scapy provides powerful capabilities for network programming and security testing. Key takeaways:

1. **Packet Creation:** Layer-by-layer packet construction
2. **Packet Manipulation:** Access and modify packet fields
3. **Packet Sending:** Multiple sending methods with/without responses
4. **Packet Sniffing:** Capture and filter network traffic
5. **Advanced Features:** Scanning, spoofing, custom protocols

**Important Notes:**
- Most operations require root/administrator privileges
- Use responsibly and only on networks you own or have permission to test
- Scapy is for educational and authorized security testing purposes

