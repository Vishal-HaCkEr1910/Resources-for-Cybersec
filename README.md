# 🛡️ Cybersecurity Resources Repository

A comprehensive collection of cybersecurity notes, tools documentation, articles, books, and learning resources for security professionals and enthusiasts.

## 📋 Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Notes & Study Materials](#notes--study-materials)
- [Tools & Projects](#tools--projects)
- [Medium Articles](#medium-articles)
- [Books & Literature](#books--literature)
- [Certifications](#certifications)
- [Learning Paths](#learning-paths)
- [Resources by Category](#resources-by-category)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## Overview

This repository serves as a centralized knowledge base for cybersecurity concepts, practical tools, and advanced techniques. It contains:

- **📝 Personal Notes:** Detailed explanations of security concepts
- **🔧 Tools Documentation:** Guides for popular security tools (Burp Suite, Metasploit, Wireshark, etc.)
- **📚 Articles & Papers:** Links to Medium articles and research papers
- **📖 Books:** Recommended cybersecurity textbooks and resources
- **🎯 Projects:** Hands-on projects and CTF writeups
- **🏆 Certifications:** Study guides for OSCP, CEH, CISSP, etc.

---

## Repository Structure

```
cybersec-resources/
│
├── 📁 notes/
│   ├── fundamentals/
│   │   ├── networking-basics.md
│   │   ├── cryptography.md
│   │   ├── authentication.md
│   │   └── access-control.md
│   │
│   ├── attack-techniques/
│   │   ├── sql-injection.md
│   │   ├── xss-attacks.md
│   │   ├── phishing.md
│   │   └── privilege-escalation.md
│   │
│   ├── defense-strategies/
│   │   ├── firewall-configuration.md
│   │   ├── intrusion-detection.md
│   │   ├── incident-response.md
│   │   └── security-hardening.md
│   │
│   └── certifications/
│       ├── oscp-notes.md
│       ├── ceh-study-guide.md
│       └── cissp-domain-notes.md
│
├── 📁 tools/
│   ├── burp-suite/
│   │   ├── README.md
│   │   ├── installation-guide.md
│   │   ├── web-scanning.md
│   │   └── api-testing.md
│   │
│   ├── metasploit/
│   │   ├── README.md
│   │   ├── basic-commands.md
│   │   ├── exploit-development.md
│   │   └── payload-generation.md
│   │
│   ├── wireshark/
│   │   ├── README.md
│   │   ├── packet-analysis.md
│   │   ├── network-forensics.md
│   │   └── pcap-analysis.md
│   │
│   ├── nmap/
│   │   ├── README.md
│   │   ├── basic-scanning.md
│   │   ├── advanced-techniques.md
│   │   └── scripting-guide.md
│   │
│   └── other-tools/
│       ├── hashcat.md
│       ├── john-the-ripper.md
│       ├── sqlmap.md
│       ├── nikto.md
│       └── kali-linux-tools.md
│
├── 📁 articles/
│   ├── medium-articles.md
│   ├── research-papers.md
│   └── blog-posts.md
│
├── 📁 books/
│   ├── recommended-books.md
│   ├── pdfs/
│   └── book-summaries/
│
├── 📁 projects/
│   ├── ctf-writeups/
│   │   ├── htb-writeups.md
│   │   ├── tryhackme-writeups.md
│   │   └── ctf-challenge-solutions/
│   │
│   ├── practice-labs/
│   │   ├── web-security-lab.md
│   │   ├── network-security-lab.md
│   │   └── forensics-lab.md
│   │
│   └── personal-projects/
│       ├── vulnerability-scanner.md
│       ├── password-cracker.md
│       └── network-monitor.md
│
├── 📁 cheatsheets/
│   ├── linux-commands.md
│   ├── windows-commands.md
│   ├── network-commands.md
│   ├── sql-injection-cheatsheet.md
│   └── payload-cheatsheets.md
│
├── 📁 resources/
│   ├── learning-platforms.md
│   ├── free-tools.md
│   ├── vulnerable-apps.md
│   └── community-forums.md
│
└── README.md (this file)

```

---

## Getting Started

### Prerequisites

- Basic understanding of networking and operating systems
- Linux/Windows command line knowledge
- Interest in cybersecurity

### Installation & Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/cybersec-resources.git

# Navigate to repository
cd cybersec-resources

# Install required tools (Ubuntu/Debian)
sudo apt-get install nmap wireshark metasploit-framework burpsuite

# Install Python dependencies
pip install -r requirements.txt
```

### Quick Navigation

- **🚀 New to Security?** → Start with [Fundamentals Notes](notes/fundamentals/)
- **🔍 Want to Learn Tools?** → Check [Tools Documentation](tools/)
- **📖 Looking for Reading Material?** → See [Articles & Books](articles/) and [Books](books/)
- **🎯 Practice & Learn?** → Explore [Projects & CTF Writeups](projects/)

---

## Notes & Study Materials

### Fundamentals
- **[Networking Basics](notes/fundamentals/networking-basics.md)** - OSI Model, TCP/IP, DNS, HTTP/HTTPS
- **[Cryptography](notes/fundamentals/cryptography.md)** - Encryption, Hashing, Digital Signatures
- **[Authentication](notes/fundamentals/authentication.md)** - MFA, OAuth, SAML, Kerberos
- **[Access Control](notes/fundamentals/access-control.md)** - RBAC, ABAC, ACLs

### Attack Techniques
- **[SQL Injection](notes/attack-techniques/sql-injection.md)** - Types, Detection, Prevention
- **[XSS Attacks](notes/attack-techniques/xss-attacks.md)** - Reflected, Stored, DOM-based XSS
- **[Phishing](notes/attack-techniques/phishing.md)** - Techniques, Social Engineering
- **[Privilege Escalation](notes/attack-techniques/privilege-escalation.md)** - Windows & Linux privesc

### Defense Strategies
- **[Firewall Configuration](notes/defense-strategies/firewall-configuration.md)** - Rules, Policies
- **[Intrusion Detection](notes/defense-strategies/intrusion-detection.md)** - IDS/IPS Setup
- **[Incident Response](notes/defense-strategies/incident-response.md)** - IR Framework
- **[Security Hardening](notes/defense-strategies/security-hardening.md)** - Best Practices

---

## Tools & Projects

### Penetration Testing Tools

#### [Burp Suite](tools/burp-suite/README.md)
- Web application security testing
- Proxy functionality and interception
- Scanner and exploitation
- API testing and fuzzing

#### [Metasploit Framework](tools/metasploit/README.md)
- Exploitation framework
- Exploit development
- Payload generation
- Post-exploitation techniques

#### [Nmap](tools/nmap/README.md)
- Network discovery and scanning
- Port scanning techniques
- Service enumeration
- NSE scripting

#### [Wireshark](tools/wireshark/README.md)
- Packet sniffing and analysis
- Network troubleshooting
- Protocol dissection
- Forensic analysis

### Additional Tools

- **[Hashcat](tools/other-tools/hashcat.md)** - GPU-accelerated password cracking
- **[John the Ripper](tools/other-tools/john-the-ripper.md)** - CPU-based password cracking
- **[SQLMap](tools/other-tools/sqlmap.md)** - SQL injection automation
- **[Nikto](tools/other-tools/nikto.md)** - Web server scanner
- **[Kali Linux Tools](tools/other-tools/kali-linux-tools.md)** - Complete toolkit overview

---

## 🐍 Python Libraries for Cybersecurity

Python is one of the most popular languages for cybersecurity automation, scripting, and tool development. This section contains comprehensive guides for essential Python libraries used in security work.

### Network & Packet Manipulation

#### [Scapy](python/scapy_library.md)
**A powerful Python library for sending, sniffing, dissecting and forging network packets**

**Key Capabilities:**
- Send and receive custom packets
- Packet sniffing with filters
- Network discovery and scanning
- Packet dissection and analysis
- Building custom network tools
- ARP spoofing and network attacks
- Tracerouting and ICMP operations

**Use Cases:**
- Network penetration testing
- Packet analysis and forensics
- Custom exploit development
- Network protocol research
- Security tool development

**Common Functions:**
```python
from scapy.all import *

# Create and send packets
packet = IP(dst="8.8.8.8")/ICMP()
send(packet)

# Sniff network traffic
sniff(filter="tcp port 80", prn=lambda x: x.show())

# ARP operations
arp_req = ARP(pdst="192.168.1.1")
answered, unanswered = srp(arp_req, timeout=5)
```

**Documentation:** [Full Scapy Guide](python/scapy_library.md) - Theory, usage, examples, and advanced features

---

#### [Psutil](python/psutil_library.md)
**Cross-platform library for retrieving system and process information**

**Key Capabilities:**
- CPU usage monitoring and metrics
- Memory (RAM) and swap tracking
- Disk I/O statistics and usage
- Network interface information
- Active process monitoring
- System boot time and uptime
- Sensor data (temperature, fans)

**Use Cases:**
- System resource monitoring
- Performance analysis
- Process tracking and management
- Incident response and forensics
- Automated alerting systems
- System health dashboards

**Common Functions:**
```python
import psutil

# CPU monitoring
cpu_percent = psutil.cpu_percent(interval=1)
cores = psutil.cpu_count()

# Memory information
vm = psutil.virtual_memory()
print(f"Memory: {vm.percent}%")

# Process monitoring
p = psutil.Process(pid)
print(f"CPU: {p.cpu_percent()}%")
print(f"Memory: {p.memory_info().rss / (1024**2):.2f} MB")

# Network I/O
net_io = psutil.net_io_counters()
```

**Documentation:** [Full Psutil Guide](python/psutil_library.md) - Theory, usage, examples, and monitoring applications

---

### Python Libraries Directory

```
python/
├── scapy_library.md
│   ├── Packet Creation
│   ├── Packet Manipulation
│   ├── Packet Sending
│   ├── Packet Sniffing
│   ├── Layer Functions
│   └── Advanced Features
│
├── psutil_library.md
│   ├── CPU Functions
│   ├── Memory Functions
│   ├── Disk Functions
│   ├── Network Functions
│   ├── Process Functions
│   ├── System Functions
│   ├── Sensor Functions
│   └── Advanced Examples
│
├── requirements.txt (Python dependencies)
├── setup.py (Package configuration)
└── examples/ (Sample scripts)
    ├── network-scanner.py
    ├── packet-sniffer.py
    ├── system-monitor.py
    └── process-tracker.py
```

---

### Installation

Install required Python libraries:

```bash
# Install all cybersecurity Python libraries
pip install scapy psutil

# Or install from requirements.txt
pip install -r requirements.txt
```

**requirements.txt example:**
```
scapy>=2.5.0
psutil>=5.9.0
paramiko>=2.11.0
requests>=2.28.0
beautifulsoup4>=4.11.0
cryptography>=38.0.0
pycryptodome>=15.0.0
```

---

### Quick Reference Guide

#### Scapy Quick Reference

```python
from scapy.all import *

# === PACKET CREATION ===
# IP Packet
pkt = IP(dst="8.8.8.8")

# TCP Packet
pkt = IP(dst="example.com")/TCP(dport=80, flags="S")

# UDP Packet
pkt = IP(dst="8.8.8.8")/UDP(dport=53)

# ICMP Packet (Ping)
pkt = IP(dst="8.8.8.8")/ICMP()

# Ethernet Frame
pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst="192.168.1.1")/ICMP()

# === PACKET SENDING ===
send(pkt)                    # Layer 3 (IP)
sendp(pkt, iface="eth0")    # Layer 2 (Ethernet)
sr(pkt, timeout=5)          # Send & receive
sr1(pkt, timeout=5)         # Send & get one response
srp(pkt, timeout=5)         # Layer 2 send & receive

# === PACKET SNIFFING ===
sniff(count=10)                              # Sniff 10 packets
sniff(filter="tcp port 80", count=5)        # Sniff TCP port 80
sniff(iface="eth0", prn=lambda x: x.show()) # Custom function

# === PACKET ANALYSIS ===
pkt[IP].dst                  # Access field
pkt.show()                   # Display all fields
IP in pkt                    # Check layer presence
```

---

#### Psutil Quick Reference

```python
import psutil

# === CPU INFORMATION ===
psutil.cpu_count()              # Total logical cores
psutil.cpu_count(logical=False) # Physical cores
psutil.cpu_percent(interval=1)  # CPU usage %
psutil.cpu_freq()               # CPU frequency
psutil.cpu_times()              # CPU times breakdown

# === MEMORY INFORMATION ===
vm = psutil.virtual_memory()
vm.total, vm.used, vm.free, vm.percent

swap = psutil.swap_memory()
swap.total, swap.used, swap.free, swap.percent

# === DISK INFORMATION ===
psutil.disk_partitions()         # Disk partitions
psutil.disk_usage('/')           # Disk usage for path
psutil.disk_io_counters()        # Disk I/O stats

# === NETWORK INFORMATION ===
psutil.net_if_addrs()            # Network interfaces
psutil.net_io_counters()         # Network I/O stats
psutil.net_connections()         # Active connections

# === PROCESS INFORMATION ===
p = psutil.Process(pid)
p.name(), p.status(), p.cpu_percent()
p.memory_info(), p.io_counters()

# === SYSTEM INFORMATION ===
psutil.boot_time()               # Boot timestamp
psutil.getloadavg()              # Load average
psutil.users()                   # Logged-in users
```

---

### Python Security Scripts Examples

#### Network Scanner with Scapy

```python
#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import sys

def arp_scan(ip_range):
    """Scan network and find active hosts"""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    result = srp(packet, timeout=2, verbose=False)[0]
    
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return clients

if __name__ == "__main__":
    ip_range = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    clients = arp_scan(ip_range)
    
    print(f"{'IP':<15} {'MAC':<20}")
    print("-" * 35)
    for client in clients:
        print(f"{client['ip']:<15} {client['mac']:<20}")
```

---

#### System Monitor with Psutil

```python
#!/usr/bin/env python3
import psutil
import time

def monitor_system(interval=5, duration=60):
    """Monitor system resources"""
    start_time = time.time()
    
    while (time.time() - start_time) < duration:
        print("\n" + "="*50)
        print(f"System Status - {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50)
        
        # CPU
        cpu = psutil.cpu_percent(interval=1)
        print(f"CPU Usage: {cpu}%")
        
        # Memory
        vm = psutil.virtual_memory()
        print(f"Memory: {vm.percent}% ({vm.used/(1024**3):.2f}GB / {vm.total/(1024**3):.2f}GB)")
        
        # Disk
        disk = psutil.disk_usage('/')
        print(f"Disk: {disk.percent}% ({disk.used/(1024**3):.2f}GB / {disk.total/(1024**3):.2f}GB)")
        
        # Network
        net = psutil.net_io_counters()
        print(f"Network - Sent: {net.bytes_sent/(1024**3):.2f}GB, Recv: {net.bytes_recv/(1024**3):.2f}GB")
        
        time.sleep(interval)

if __name__ == "__main__":
    monitor_system(interval=5, duration=300)
```

---

### Learning Resources for Python Security

**Official Documentation:**
- Scapy: https://scapy.readthedocs.io
- Psutil: https://psutil.readthedocs.io

**Tutorials & Articles:**
- Real Python tutorials
- Medium articles on Python security
- YouTube channels focused on Python hacking
- OWASP Python Security guides

**GitHub Repositories:**
- Security tool examples
- Open-source projects using Scapy/Psutil
- Security automation scripts

---

### Python Security Best Practices

✅ **Always validate input** - Prevent code injection  
✅ **Use virtual environments** - Isolate dependencies  
✅ **Follow PEP 8** - Maintain code quality  
✅ **Error handling** - Use try/except blocks  
✅ **Logging** - Record important events  
✅ **Documentation** - Document all functions  
✅ **Security updates** - Keep libraries updated  
✅ **Code review** - Have others review code  

---

### Contributing Python Scripts

To add your Python security scripts:

1. **Create script in appropriate folder:**
   ```bash
   python/examples/[script-name].py
   ```

2. **Include documentation:**
   - Purpose and use case
   - Installation requirements
   - Usage examples
   - Output example

3. **Follow best practices:**
   - Add comments
   - Use functions
   - Handle errors
   - Add help/usage info

4. **Submit pull request** with your scripts

---

## Medium Articles

### Featured Articles

| Title | Topic | Link |
|-------|-------|------|
| **Understanding OAuth 2.0 Vulnerabilities** | Authentication | [Read](https://medium.com/@yourname/oauth-vulnerabilities) |
| **SQL Injection: From Theory to Practice** | Web Security | [Read](https://medium.com/@yourname/sql-injection-guide) |
| **Advanced Privilege Escalation Techniques** | Post-Exploitation | [Read](https://medium.com/@yourname/privesc-techniques) |
| **Network Forensics with Wireshark** | Forensics | [Read](https://medium.com/@yourname/wireshark-forensics) |
| **Secure Coding Best Practices** | Development | [Read](https://medium.com/@yourname/secure-coding) |
| **Zero Trust Architecture Deep Dive** | Security Architecture | [Read](https://medium.com/@yourname/zero-trust) |

### Article Categories

- **Web Security** - OWASP Top 10, WAF Bypass, API Security
- **Network Security** - Protocols, VPN, Network Segmentation
- **Incident Response** - IR Playbooks, Forensics, Recovery
- **Compliance & Governance** - GDPR, HIPAA, SOC 2
- **Cloud Security** - AWS, Azure, GCP Security
- **DevSecOps** - Secure SDLC, Container Security

👉 [View All Medium Articles](articles/medium-articles.md)

---

## Books & Literature

### Essential Reading

**Foundational Books**
- 🔷 **The Web Application Hacker's Handbook** - Stuttard & Pinto
- 🔷 **Penetration Testing** - Georgia Weidman
- 🔷 **The Hacker Playbook** Series - Peter Kim

**Advanced Topics**
- 🔶 **Real-World Cryptography** - David Wong
- 🔶 **Security Engineering** - Ross Anderson
- 🔶 **The Art of Software Security Testing** - Art Collins

**Offensive Security**
- 🔴 **Metasploit: The Penetration Tester's Guide** - Kennedy, O'Neill, Aharoni
- 🔴 **The Shellcoder's Handbook** - Koziol, Litchfield, Aitel
- 🔴 **Reversing: Secrets of Reverse Engineering** - Eilam

**Defensive Security**
- 🔵 **Incident Response & Computer Forensics** - Harris
- 🔵 **Security Monitoring with Splunk** - Besson & Friedberg
- 🔵 **Applied Network Security** - Douglas

👉 [View Book Summaries & Reviews](books/recommended-books.md)

---

## Certifications

### Certification Study Guides

#### [OSCP (Offensive Security Certified Professional)](notes/certifications/oscp-notes.md)
- **Difficulty:** Hard
- **Duration:** 90-hour exam
- **Cost:** $999
- **Topics:** Linux, Windows, Exploitation, Reporting
- **Resources:** HackTheBox, TryHackMe, Personal Labs

#### [CEH (Certified Ethical Hacker)](notes/certifications/ceh-study-guide.md)
- **Difficulty:** Medium
- **Duration:** 4 hours, 125 questions
- **Cost:** $500-$1000
- **Topics:** 19 domains of ethical hacking
- **Resources:** EC-Council materials, iClass platform

#### [CISSP (Certified Information Systems Security Professional)](notes/certifications/cissp-domain-notes.md)
- **Difficulty:** Hard
- **Requirements:** 5 years experience
- **Cost:** $749
- **Topics:** 8 domains of security
- **Resources:** ISC², Practice exams, bootcamps

#### Other Certifications
- **CompTIA Security+** - Beginner-friendly
- **CompTIA PenTest+** - Practical penetration testing
- **GIAC GSEC** - Security fundamentals
- **eLearnSecurity eCPPT** - Practical hacking

---

## Learning Paths

### Beginner Path (0-6 months)
```
1. Learn Networking Fundamentals
   └─ Notes: networking-basics.md
   └─ Resource: Professor Messer YouTube
   
2. Study Operating Systems
   └─ Linux & Windows basics
   └─ Command line proficiency
   
3. Introduction to Security
   └─ OWASP Top 10
   └─ Common vulnerabilities
   
4. Start with TryHackMe
   └─ Complete beginner rooms
   └─ Earn badges & points
```

### Intermediate Path (6-12 months)
```
1. Deepen Cryptography Knowledge
   └─ Symmetric & Asymmetric encryption
   └─ Hashing algorithms
   
2. Learn Web Application Security
   └─ OWASP Top 10 deep dive
   └─ Burp Suite hands-on
   
3. Network Security & Penetration Testing
   └─ Nmap advanced techniques
   └─ Network scanning methodology
   
4. HackTheBox Challenges
   └─ Complete 20+ boxes
   └─ Study writeups
```

### Advanced Path (12+ months)
```
1. Exploitation & Payload Development
   └─ Metasploit Framework
   └─ Custom exploit development
   
2. Advanced Privilege Escalation
   └─ Windows & Linux techniques
   └─ Post-exploitation methods
   
3. Incident Response & Forensics
   └─ IR frameworks
   └─ Digital forensics analysis
   
4. Prepare for OSCP
   └─ Penetration Testing with Kali
   └─ Lab exercises
   └─ Report writing
```

---

## Resources by Category

### 🌐 Web Security
- OWASP Foundation - https://owasp.org
- Portswigger Web Security Academy - https://portswigger.net/web-security
- HackTheBox Web Challenges - https://hackthebox.com
- PortSwigger Lab Exercises - https://portswigger.net/burp/labs

### 🔍 Network Security
- Cisco Learning Network - https://learningnetwork.cisco.com
- Professor Messer Networking - https://www.professormesser.com
- Wireshark Official Guides - https://wiki.wireshark.org
- Packet Life Subnetting - https://packetlife.net

### 🛡️ Defensive Security
- SANS Security Courses - https://www.sans.org
- Cybrary - https://www.cybrary.it
- Coursera Security Specializations - https://coursera.org
- edX Cybersecurity - https://edx.org

### 🎯 Practice Platforms
- **HackTheBox** - Realistic penetration testing labs
- **TryHackMe** - Guided security learning
- **OverTheWire** - Wargames and challenges
- **PicoCTF** - Capture the flag competitions
- **CyberDefenders** - SOC analyst challenges

### 📚 Vulnerable Applications
- **DVWA** - Damn Vulnerable Web Application
- **WebGoat** - OWASP intentionally vulnerable app
- **Juice Shop** - OWASP vulnerable web shop
- **bWAPP** - Vulnerable web application platform

### 👥 Community & Forums
- **Reddit:** r/cybersecurity, r/hacking, r/oscp
- **Discord:** Various security communities
- **GitHub:** Open-source security projects
- **Security StackExchange** - Q&A platform

---

## Cheatsheets

Quick reference guides for common commands and techniques:

- **[Linux Commands Cheatsheet](cheatsheets/linux-commands.md)** - Essential Linux commands
- **[Windows Commands Cheatsheet](cheatsheets/windows-commands.md)** - PowerShell & CMD
- **[Network Commands](cheatsheets/network-commands.md)** - Networking tools
- **[SQL Injection Cheatsheet](cheatsheets/sql-injection-cheatsheet.md)** - SQLi techniques
- **[Payload Cheatsheets](cheatsheets/payload-cheatsheets.md)** - Common payloads

---

## Projects & CTF Writeups

### HackTheBox Writeups
- [Easy Machines](projects/ctf-writeups/htb-writeups.md#easy)
- [Medium Machines](projects/ctf-writeups/htb-writeups.md#medium)
- [Hard Machines](projects/ctf-writeups/htb-writeups.md#hard)

### TryHackMe Writeups
- [Beginner Path](projects/ctf-writeups/tryhackme-writeups.md#beginner)
- [Intermediate Path](projects/ctf-writeups/tryhackme-writeups.md#intermediate)
- [Advanced Path](projects/ctf-writeups/tryhackme-writeups.md#advanced)

### Personal Projects
- **[Vulnerability Scanner](projects/personal-projects/vulnerability-scanner.md)** - Python-based scanner
- **[Password Cracker](projects/personal-projects/password-cracker.md)** - Hash cracking tool
- **[Network Monitor](projects/personal-projects/network-monitor.md)** - Real-time network monitoring

---

## 🎯 VulnHub Machines - Pathway Solutions

### About VulnHub

VulnHub is a free community platform that provides vulnerable machines and applications for practicing penetration testing and exploitation skills in a legal environment.

**Platform:** https://www.vulnhub.com  
**Format:** Download vulnerable VMs and run locally or on lab environment  
**Difficulty:** Beginner to Expert  
**Community:** Active community with writeups and discussions  

### VulnHub Learning Pathway

#### 🟢 Beginner Machines (Start Here)

These machines are perfect for beginners to learn fundamental penetration testing concepts.

| Machine | Difficulty | Key Concepts | Writeup |
|---------|------------|--------------|---------|
| **VulnHub #1: Kioptrix Level 1** | Beginner | Apache, Remote Include, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/kioptrix-level1.md) |
| **VulnHub #2: Kioptrix Level 1.1** | Beginner | Web Application, SQL Injection, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/kioptrix-level1.1.md) |
| **VulnHub #3: FristiLeaks 1.3** | Beginner | Web Enumeration, File Upload, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/fristileaks.md) |
| **VulnHub #4: Stapler 1** | Beginner | SMB, SSH, Web Services, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/stapler.md) |
| **VulnHub #5: Mr. Robot 1** | Beginner | WordPress, File Permissions, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/mr-robot.md) |
| **VulnHub #6: Mercy v2** | Beginner | Web Enumeration, Weak Credentials, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/mercy-v2.md) |

**Key Learning Points:**
- Port scanning and service enumeration
- Web application vulnerability identification
- Basic exploit techniques
- Linux privilege escalation fundamentals
- Report writing

---

#### 🟡 Intermediate Machines

Once comfortable with beginner machines, try these intermediate challenges.

| Machine | Difficulty | Key Concepts | Writeup |
|---------|------------|--------------|---------|
| **VulnHub #7: HackingStuffUp** | Intermediate | LDAP, SMB, Web Services | [Link to writeup](projects/ctf-writeups/vulnhub/hackingstuffup.md) |
| **VulnHub #8: SolidState** | Intermediate | Mail Server, Weak Credentials, Code Injection | [Link to writeup](projects/ctf-writeups/vulnhub/solidstate.md) |
| **VulnHub #9: CyberDefenders: Apt** | Intermediate | Forensics, Log Analysis, Incident Response | [Link to writeup](projects/ctf-writeups/vulnhub/cyberdefenders-apt.md) |
| **VulnHub #10: Typhoon** | Intermediate | Crypto, Web Application, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/typhoon.md) |
| **VulnHub #11: Breach 2.1** | Intermediate | Web Exploitation, Database Enumeration | [Link to writeup](projects/ctf-writeups/vulnhub/breach-2.1.md) |
| **VulnHub #12: Pwnlab.ws** | Intermediate | Web Upload, File Inclusion, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/pwnlab.md) |

**Key Learning Points:**
- Advanced web application exploitation
- Network service enumeration
- Custom privilege escalation techniques
- Forensic analysis
- Exploit chain development

---

#### 🔴 Advanced Machines (Expert Level)

Challenge yourself with these expert-level machines.

| Machine | Difficulty | Key Concepts | Writeup |
|---------|------------|--------------|---------|
| **VulnHub #13: Lord of the Root** | Advanced | Privilege Escalation, Kernel Exploits | [Link to writeup](projects/ctf-writeups/vulnhub/lord-of-the-root.md) |
| **VulnHub #14: Persistence** | Advanced | Persistence Mechanisms, Anti-Forensics | [Link to writeup](projects/ctf-writeups/vulnhub/persistence.md) |
| **VulnHub #15: Tr0ll Series** | Advanced | Obfuscation, Multi-stage Exploitation | [Link to writeup](projects/ctf-writeups/vulnhub/tr0ll-series.md) |
| **VulnHub #16: Pegasus** | Advanced | Network Pivoting, Complex Exploitation | [Link to writeup](projects/ctf-writeups/vulnhub/pegasus.md) |
| **VulnHub #17: Infosec Prep OSCP** | Advanced | OSCP Preparation, Multiple Techniques | [Link to writeup](projects/ctf-writeups/vulnhub/infosec-prep-oscp.md) |
| **VulnHub #18: Raven 2** | Advanced | WordPress, Apache Exploitation, Privilege Escalation | [Link to writeup](projects/ctf-writeups/vulnhub/raven-2.md) |

**Key Learning Points:**
- Complex multi-stage exploitation
- Kernel exploitation techniques
- Advanced privilege escalation
- Network segmentation and pivoting
- Custom tool development

---

### VulnHub Machine Writeup Template

When solving VulnHub machines, use this structure for your writeups:

```markdown
# VulnHub: [Machine Name]

## Machine Information
- **Platform:** VulnHub
- **Difficulty:** [Beginner/Intermediate/Advanced]
- **Creator:** [Creator Name]
- **Date Completed:** [Date]
- **Time Taken:** [Time]

## Reconnaissance
### Network Scanning
- Nmap results
- Service versions
- Open ports

### Web Application Enumeration
- Directory scanning
- Technology fingerprinting
- Vulnerability identification

## Exploitation
### Vulnerability Found
- Description
- CVSS Score
- Exploitation method

### Exploitation Steps
1. Step 1
2. Step 2
3. Step 3

## Privilege Escalation
### Initial Access
- User account obtained
- Permissions level

### Privilege Escalation Vector
- Vulnerability
- Exploitation technique
- Root access achieved

## Post-Exploitation
- Flags captured
- System hardening observations

## Key Learnings
- Technique 1
- Technique 2
- Technique 3

## Tools Used
- Tool 1
- Tool 2
- Tool 3

## References
- Reference 1
- Reference 2
```

---

### VulnHub Repository Structure

```
projects/
└── ctf-writeups/
    └── vulnhub/
        ├── README.md (VulnHub overview)
        ├── beginner/
        │   ├── kioptrix-level1.md
        │   ├── kioptrix-level1.1.md
        │   ├── fristileaks.md
        │   ├── stapler.md
        │   ├── mr-robot.md
        │   └── mercy-v2.md
        │
        ├── intermediate/
        │   ├── hackingstuffup.md
        │   ├── solidstate.md
        │   ├── cyberdefenders-apt.md
        │   ├── typhoon.md
        │   ├── breach-2.1.md
        │   └── pwnlab.md
        │
        └── advanced/
            ├── lord-of-the-root.md
            ├── persistence.md
            ├── tr0ll-series.md
            ├── pegasus.md
            ├── infosec-prep-oscp.md
            └── raven-2.md
```

---

### Getting Started with VulnHub

#### Step 1: Download VulnHub Machine
```bash
# Visit https://www.vulnhub.com and download a machine
# Or use torrent for faster downloads
```

#### Step 2: Import into Virtualization Platform
```bash
# For VirtualBox
VBoxManage import machine.ova

# For VMware
# Open with VMware Fusion/Player

# For KVM/QEMU
qemu-img convert machine.vmdk machine.qcow2
```

#### Step 3: Network Configuration
```bash
# Set VM network to NAT or Bridged mode
# Note: Usually provided in machine documentation
```

#### Step 4: Start Exploitation
```bash
# Begin reconnaissance
nmap -sV -sC <target-ip>

# Enumerate services
# Identify vulnerabilities
# Develop exploitation strategy
```

---

### Recommended VulnHub Progression Path

**Week 1-2: Fundamentals**
```
Kioptrix Level 1 → Kioptrix Level 1.1 → FristiLeaks 1.3
```

**Week 3-4: Intermediate Concepts**
```
Stapler 1 → Mr. Robot 1 → Mercy v2
```

**Week 5-8: Advanced Techniques**
```
HackingStuffUp → SolidState → Typhoon → Breach 2.1 → Pwnlab
```

**Week 9+: Expert Challenges**
```
Lord of the Root → Persistence → Tr0ll Series → Pegasus → Infosec Prep OSCP
```

---

### VulnHub Tips & Tricks

#### Finding Machines by Difficulty
```
Beginner: 1-3 flags
Intermediate: 3-5 flags or complex exploitation
Advanced: Multiple vectors, OSCP-style challenges
```

#### Common Exploitation Paths
1. **Web-based machines:**
   - Identify web technologies (WordPress, custom apps)
   - Find vulnerabilities (SQL injection, file upload, etc.)
   - Gain shell access
   - Privilege escalate

2. **Network service machines:**
   - Enumerate all open services
   - Find weak credentials or exploits
   - Gain access
   - Escalate privileges

3. **Cryptography/Forensics machines:**
   - Analyze provided files
   - Crack encryption if needed
   - Extract information
   - Capture flags

#### Debugging Tips
```bash
# Machine won't start?
- Check virtual machine settings
- Ensure NAT/Bridge network configured
- Verify sufficient RAM allocated

# Can't reach machine?
- Verify network connectivity: ping <machine-ip>
- Check firewall rules
- Confirm machine is running

# Stuck on exploitation?
- Re-enumerate thoroughly
- Check for hidden files/directories
- Review application logs
- Try different exploitation vectors
```

---

### VulnHub Community Resources

**Official Platform:** https://www.vulnhub.com

**Community Writeups:**
- Machine-specific forums on VulnHub
- Blog posts and Medium articles
- YouTube walkthroughs
- GitHub repositories with solutions

**Similar Platforms:**
- **HackTheBox** - Faster machines, more variety
- **TryHackMe** - Guided, beginner-friendly
- **OverTheWire** - Wargames and challenges
- **PicoCTF** - CTF competitions

---

### Contributing VulnHub Writeups

To add your VulnHub writeups to this repository:

1. **Create writeup file:**
   ```bash
   touch projects/ctf-writeups/vulnhub/[difficulty]/[machine-name].md
   ```

2. **Follow the writeup template** (see above)

3. **Include:**
   - Clear exploitation steps
   - Commands used with explanations
   - Screenshots (optional but helpful)
   - Key learnings and techniques
   - References and further reading

4. **Submit pull request** with your writeups

---

### Challenge Tracking

Keep track of your progress:

```markdown
## VulnHub Progress Tracker

### Beginner (Target: 6/6)
- [x] Kioptrix Level 1
- [x] Kioptrix Level 1.1
- [x] FristiLeaks 1.3
- [x] Stapler 1
- [x] Mr. Robot 1
- [x] Mercy v2

### Intermediate (Target: 6/6)
- [ ] HackingStuffUp
- [ ] SolidState
- [ ] CyberDefenders: Apt
- [ ] Typhoon
- [ ] Breach 2.1
- [ ] Pwnlab

### Advanced (Target: 6/6)
- [ ] Lord of the Root
- [ ] Persistence
- [ ] Tr0ll Series
- [ ] Pegasus
- [ ] Infosec Prep OSCP
- [ ] Raven 2
```

---

## Top Tips for Success

✅ **Consistent Practice** - Spend 2-3 hours daily on hands-on labs
✅ **Note Taking** - Document findings and learnings
✅ **Read Writeups** - Learn from others' approaches
✅ **Experiment Safely** - Use isolated lab environments
✅ **Join Communities** - Network with other security professionals
✅ **Stay Updated** - Follow security news and trends
✅ **Report Writing** - Practice clear and professional reporting
✅ **Ethical Hacking** - Always get written permission before testing

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/cybersec-resources.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b add/new-content
   ```

3. **Make your changes**
   - Add new notes, tools, or resources
   - Ensure content is accurate and well-organized
   - Follow the existing structure

4. **Commit and push**
   ```bash
   git add .
   git commit -m "Add: Comprehensive guide to XSS attacks"
   git push origin add/new-content
   ```

5. **Create a Pull Request**
   - Provide clear description of changes
   - Reference any related issues

### Content Guidelines

- Use clear, professional language
- Include practical examples
- Add relevant links and references
- Organize content logically
- Keep files up to date

---

## Resources

### Official Security Organizations
- **OWASP** - https://owasp.org (Open Web Application Security Project)
- **NIST** - https://www.nist.gov (National Institute of Standards & Technology)
- **SANS** - https://www.sans.org (Global cybersecurity training)
- **EC-Council** - https://www.eccouncil.org (Certifications & training)

### Security News & Updates
- **Krebs on Security** - https://krebsonsecurity.com
- **BleepingComputer** - https://bleepingcomputer.com
- **SecurityFocus** - https://www.securityfocus.com
- **Packet Storm Security** - https://packetstormsecurity.com

### Vulnerability Databases
- **CVE** - https://cve.mitre.org
- **NVD** - https://nvd.nist.gov
- **ExploitDB** - https://www.exploit-db.com
- **Shodan** - https://www.shodan.io

---

## Roadmap

### Planned Additions
- [ ] Advanced exploit development guide
- [ ] Cloud security deep dive (AWS, Azure, GCP)
- [ ] Blockchain security fundamentals
- [ ] AI/ML in cybersecurity
- [ ] Malware analysis guide
- [ ] Reverse engineering tutorial
- [ ] Supply chain security
- [ ] Video tutorials and walkthroughs

---

## Disclaimer

⚠️ **Legal & Ethical Notice:**

This repository is created for **educational purposes only**. All techniques and tools should be used:
- ✅ Only on systems you own or have explicit written permission to test
- ✅ In controlled lab environments
- ✅ Responsibly and ethically
- ✅ In compliance with all applicable laws

**Unauthorized access to computer systems is illegal.**
The author assumes no liability for misuse of information contained in this repository.

---

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

You are free to:
- ✅ Use for educational purposes
- ✅ Modify and distribute
- ✅ Include in your own projects
- ✅ Contribute improvements

---

## Authors & Contributors

### Primary Author
- **[Your Name]** - Cybersecurity enthusiast and researcher
  - Email: your.email@example.com
  - LinkedIn: https://linkedin.com/in/yourprofile
  - GitHub: https://github.com/yourusername

### Contributors
- [Contributor names here]
- Thanks to all community members who contributed!

---

## Support & Contact

### Get in Touch
- 📧 **Email:** your.email@example.com
- 🐦 **Twitter:** @yourhandle
- 💼 **LinkedIn:** /in/yourprofile
- 💬 **Discord:** YourUsername#1234

### Report Issues
- Found an error? [Open an issue on GitHub](https://github.com/yourusername/cybersec-resources/issues)
- Have suggestions? [Start a discussion](https://github.com/yourusername/cybersec-resources/discussions)

---

## Frequently Asked Questions (FAQ)

**Q: Is this repository updated regularly?**
A: Yes! Content is updated monthly with new resources, articles, and tools.

**Q: Can I use this for commercial purposes?**
A: Yes, under the MIT License. Please include attribution.

**Q: How can I contribute?**
A: Fork the repo, make changes, and submit a pull request!

**Q: Are there videos or tutorials?**
A: Currently text-based, but video tutorials are planned!

**Q: How do I get started with no security experience?**
A: Start with the Beginner Path in the Learning Paths section.

---

## Star History

If you find this repository helpful, please consider starring it! ⭐

---

## Final Notes

> "Security is not about being paranoid. It's about being prepared." - Unknown

This repository is a living document that grows with the community. Whether you're starting your cybersecurity journey or are an experienced professional, there's always something new to learn.

**Happy Learning! 🚀**

---

*Last Updated: February 2026*
*Follow for updates: ⭐ Star the repository | 👀 Watch for notifications*

