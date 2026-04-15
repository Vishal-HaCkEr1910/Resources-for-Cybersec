# 🌐 Complete Networking Lab Guide
### Your Step-by-Step Self-Study Manual — Experiments 1 through 6

> **How to use this guide:** Read each section *before* you open Packet Tracer or your IDE. Every button, every click, every command is explained. Alternate methods are shown where they exist. Tick off each ✅ checkpoint as you go.

---

## 📋 TABLE OF CONTENTS

| # | Experiment | Tool |
|---|-----------|------|
| 1 | [OSI Model, Topologies & Network Devices](#experiment-1) | Theory + Packet Tracer |
| 2 | [IP Addressing, Types & Classes](#experiment-2) | Theory |
| 3 | [Inter-VLAN Routing — Two Classes via Router](#experiment-3) | Cisco Packet Tracer |
| 4 | [Router-Switch Integration via Cisco CLI](#experiment-4) | Cisco Packet Tracer |
| 5 | [Single-Bit Parity Check in C++](#experiment-5) | C++ / Any IDE |
| 6 | [2D Parity Check in C++](#experiment-6) | C++ / Any IDE |

---

# 🛠️ CISCO PACKET TRACER — MASTER ORIENTATION
> Read this once before starting Experiments 3 and 4. You will never be confused by the interface again.

## What is Cisco Packet Tracer?
Packet Tracer is a **free network simulation software** made by Cisco. Instead of buying real routers and switches (which cost thousands of dollars), you drag virtual ones onto a canvas, cable them together, and configure them using the same commands as real hardware.

## Downloading & Installing
1. Go to **https://www.netacad.com** → Sign up for a free account
2. Navigate to **Resources → Download Packet Tracer**
3. Choose your OS (Windows/Linux/Mac) and install
4. Launch — log in with your NetAcad account when prompted

---

## The Packet Tracer Interface — Every Panel Explained

```
┌─────────────────────────────────────────────────────────┐
│  Menu Bar   [File] [Edit] [Options] [View] [Tools]       │
├──────────────────────────────┬──────────────────────────┤
│                              │                          │
│       WORKSPACE              │   DEVICE CONFIG PANEL    │
│   (Your network canvas)      │   (appears when you      │
│                              │    click a device)       │
│                              │                          │
├──────────────────────────────┴──────────────────────────┤
│  BOTTOM TOOLBAR                                          │
│  [Realtime ◀▶] [Simulation ◀▶]   Device Categories      │
│                                  [Routers][Switches]...  │
└─────────────────────────────────────────────────────────┘
```

### Panel-by-Panel Breakdown

| Panel | Location | What it does |
|-------|----------|-------------|
| **Workspace** | Center (big grey area) | Where you place and connect devices. Think of it as your desk. |
| **Device Box** | Bottom-left | Categories: Routers, Switches, End Devices, Connections, etc. |
| **Device List** | Bottom-right of Device Box | Changes based on category selected. Shows specific models. |
| **Realtime / Simulation toggle** | Bottom-center | Realtime = live network. Simulation = slow-motion, you see packets move. |
| **Config Panel** | Right side (appears on click) | Tabs: Physical, Config, CLI, Desktop — vary by device. |

---

## The Two Modes You Must Know

### 🟢 Realtime Mode
- Everything happens instantly, just like a real network
- Use this for **building** and **pinging**
- The clock in the bottom-right ticks in real time

### 🔵 Simulation Mode
- Time moves only when you press **Play ▶** or **Step ⏩**
- You can **see individual packets** travel between devices
- Click a packet envelope on the canvas to see its PDU (headers at each layer)
- **When to use:** When you want to visually confirm a ping or see where a packet drops

> **Pro Tip:** Build in Realtime, verify in Simulation.

---

## Placing Devices — Step by Step

1. Look at the **bottom-left panel** — you see icons for device categories
2. Click the icon that looks like a **small router** → this is the "Routers" category
3. The panel to its right now shows router models (e.g., 1841, 2901, 2911)
4. **Click and drag** a model onto the workspace — OR — **single click** the model, then **click anywhere on the workspace** to place it
5. The device appears with a default name (Router0, Router1, etc.)

### Device Categories Quick Reference

| Icon | Category | Devices inside |
|------|----------|---------------|
| 🔲 Box with antenna | Routers | 1841, 2901, **2911** ← use this |
| 🔲 Box flat | Switches | 2950, **2960** ← use this |
| 🖥️ Monitor | End Devices | **PC**, Laptop, Server |
| 〰️ Lightning bolt | Connections/Cables | Copper, Fiber, Console, Serial |
| 📡 Tower | Wireless Devices | Access Points |

---

## Cables — Which One to Use and When

| Cable Type | Color in PT | Use When |
|-----------|-------------|----------|
| **Copper Straight-Through** | Black solid line | PC → Switch, Switch → Router (different device types) |
| **Copper Cross-Over** | Black dashed line | PC → PC, Switch → Switch (same device types) |
| **Console Cable** | Blue rolled line | Management PC → Router/Switch (for CLI access) |
| **Serial DCE/DTE** | Red line | Router → Router (WAN links, older style) |
| **Fiber** | Orange line | Long-distance or fiber-specific ports |
| **Auto (Lightning bolt)** | — | PT picks the right cable automatically |

> **Beginner tip:** When in doubt, use the **lightning bolt (Auto)** cable — Packet Tracer picks the correct type automatically.

### How to Connect Two Devices
1. Click the **Connections** category (lightning bolt icon, bottom-left)
2. Click the **cable type** you want (e.g., Copper Straight-Through)
3. Your cursor becomes a **connector icon**
4. **Click Device A** → a popup shows available ports → **click a port**
5. **Click Device B** → same popup → **click a port**
6. A line appears between them. Link light colors:
   - 🔴 Red dot = Link is down (interface not configured or shutdown)
   - 🟠 Orange dot = Link is initializing (STP/booting)
   - 🟢 Green dot = Link is up and working

---

## Clicking on a Device — The Config Tabs Explained

When you **click** any device on the workspace, a window opens with tabs:

### For a Router:
| Tab | What's inside |
|-----|--------------|
| **Physical** | Visual of the router chassis. You can add module cards here (e.g., WIC-2T for serial ports). Drag modules into slots. |
| **Config** | GUI-based configuration (easier but limited). You can set hostname, interfaces, routing. Great for beginners. |
| **CLI** | The real command line. Same as SSH-ing into a real Cisco router. **Most important tab.** |
| **Attributes** | Device metadata (label, alt text) |

### For a PC:
| Tab | What's inside |
|-----|--------------|
| **Physical** | The PC chassis |
| **Config** | Set IP, Subnet, Gateway via GUI — no commands needed |
| **Desktop** | Contains: Command Prompt, Web Browser, IP Configuration app |

### For a Switch:
| Tab | What's inside |
|-----|--------------|
| **Physical** | Switch chassis |
| **Config** | Basic settings |
| **CLI** | Switch IOS command line |

---

## The CLI — Understanding Cisco IOS Modes

Every Cisco device has a **hierarchy of command modes**. You can only run certain commands in certain modes.

```
Power On
    │
    ▼
Router>          ← USER EXEC MODE (read-only, basic)
    │  type: enable
    ▼
Router#          ← PRIVILEGED EXEC MODE (can view everything, run diagnostics)
    │  type: configure terminal  (or: conf t)
    ▼
Router(config)#  ← GLOBAL CONFIG MODE (change device-wide settings)
    │  type: interface GigabitEthernet0/0
    ▼
Router(config-if)#  ← INTERFACE CONFIG MODE (change one port's settings)
    │  type: exit  OR  Ctrl+Z to jump back to Router#
    ▼
Router(config)#  ← back to Global Config
```

### How to Move Between Modes

| Command | From | Goes to |
|---------|------|---------|
| `enable` (or `en`) | `Router>` | `Router#` |
| `configure terminal` (or `conf t`) | `Router#` | `Router(config)#` |
| `interface Gig0/0` | `Router(config)#` | `Router(config-if)#` |
| `exit` | Any mode | One level up |
| `Ctrl + Z` or `end` | Any sub-mode | Back to `Router#` directly |
| `disable` | `Router#` | `Router>` |

---

## Essential CLI Commands — Quick Reference Card

```bash
# SHOW COMMANDS (run from Router# — Privileged mode)
show ip interface brief          # See all interfaces, IP, and status (UP/DOWN)
show running-config              # See current active configuration in RAM
show startup-config              # See saved configuration in NVRAM
show version                     # IOS version, uptime, hardware info
show ip route                    # Routing table — what networks does router know?

# SAVING YOUR WORK
copy running-config startup-config   # Save to NVRAM (persists after reboot)
# Shortcut:
write memory   (or just: wr)

# INTERFACE COMMANDS (run from Router(config-if)#)
ip address 192.168.1.1 255.255.255.0   # Assign IP and subnet mask
no shutdown                             # Turn the interface ON
shutdown                                # Turn the interface OFF
description Link to PC Lab              # Label the interface (good practice)

# SECURITY COMMANDS (run from Router(config)#)
hostname R1                        # Rename the device
enable secret cisco123             # Set encrypted privilege password
enable password cisco123           # Set unencrypted privilege password (less secure)
line vty 0 4                       # Configure virtual terminal lines (Telnet/SSH)
  password admin                   # Set password for VTY lines
  login                            # Require login on VTY

# TROUBLESHOOTING
ping 192.168.1.2                   # Test reachability (run from Router# or PC CMD)
traceroute 192.168.1.2             # See the path a packet takes
```

> **Tab Completion:** In the CLI, press **Tab** to auto-complete a command. Press **?** after a partial command to see valid options. This works exactly like a real Cisco device.

---
---

# EXPERIMENT 1
## OSI Model, Physical Topologies & Network Devices

> **Tool needed:** Paper + Brain (no software required, but you can build topologies in Packet Tracer for visualization)

---

## Part A — The 7 OSI Layers (Memorization + Understanding)

### The Mnemonic
**Top-down (Layer 7→1):** **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing
**Bottom-up (Layer 1→7):** **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way

---

### Layer-by-Layer Deep Dive

#### Layer 7 — Application
- **PDU name:** Data
- **What it does:** The layer your software touches. When you open Chrome and type a URL, HTTP runs here.
- **Key protocols:** HTTP (web browsing), HTTPS (secure web), FTP (file transfer), SSH (secure remote access), DNS (domain name lookup), SMTP (email sending)
- **Real example:** You press Enter on a web URL → Layer 7 creates an HTTP GET request

#### Layer 6 — Presentation
- **PDU name:** Data
- **What it does:** Translates data formats. Encrypts (TLS/SSL), compresses (JPEG, MPEG), converts character encoding (ASCII ↔ Unicode)
- **Real example:** When HTTPS encrypts your credit card number before sending, that's Layer 6

#### Layer 5 — Session
- **PDU name:** Data
- **What it does:** Manages the conversation (session) between two applications. Sets up, maintains, and tears down connections. Supports checkpointing (resume a broken download)
- **Key protocols:** NetBIOS, RPC (Remote Procedure Call), PPTP
- **Real example:** A video call staying connected for 2 hours — Layer 5 maintains that session

#### Layer 4 — Transport
- **PDU name:** Segment
- **What it does:** Breaks large data into segments, numbers them (sequencing), ensures delivery
- **Two main protocols:**

| Feature | TCP | UDP |
|---------|-----|-----|
| Full name | Transmission Control Protocol | User Datagram Protocol |
| Connection | Connection-oriented (handshake first) | Connectionless (fire and forget) |
| Reliability | ✅ Guaranteed delivery, retransmits lost packets | ❌ No guarantee |
| Speed | Slower (overhead) | Faster (no overhead) |
| Use case | Web pages, emails, file downloads | Video streaming, gaming, VoIP, DNS |
| Error checking | ✅ Yes | ❌ Basic checksum only |

- **Real example:** Downloading a file uses TCP. Watching YouTube live uses UDP.

#### Layer 3 — Network
- **PDU name:** Packet
- **What it does:** Logical addressing (IP addresses) and routing — finding the best path across multiple networks
- **Key protocols:** IPv4, IPv6, ICMP (ping), OSPF, BGP (internet routing), ARP
- **Key devices:** **Router**
- **Real example:** Your packet travels from India → UK passing through 15 routers — Layer 3 handles every hop

#### Layer 2 — Data Link
- **PDU name:** Frame
- **What it does:** Physical addressing (MAC addresses), error detection (CRC checksum), controls access to the medium
- **Sublayers:**
  - **LLC (Logical Link Control):** Error control, flow control
  - **MAC (Media Access Control):** Hardware addressing, CSMA/CD
- **Key protocols:** Ethernet, Wi-Fi (802.11), PPP
- **Key devices:** **Switch**, Bridge
- **Real example:** Your switch reads the destination MAC in the frame header to decide which port to forward it to

#### Layer 1 — Physical
- **PDU name:** Bits (1s and 0s)
- **What it does:** Converts bits to electrical signals (copper), light pulses (fiber), or radio waves (Wi-Fi). Defines voltage levels, cable specs, pin layouts
- **Key devices:** Hub, Repeater, Modem
- **Real example:** The RJ-45 Ethernet cable carrying voltage pulses is Layer 1

---

### Encapsulation — What Actually Happens When You Send Data

```
SENDER SIDE (adding headers going DOWN the stack):
─────────────────────────────────────────────────
App Layer 7:    [   DATA   ]
Transport L4:   [TCP Header][   DATA   ]       ← called a SEGMENT
Network L3:     [IP Header][TCP Header][DATA]  ← called a PACKET
Data Link L2:   [MAC Header][IP Hdr][TCP Hdr][DATA][FCS] ← called a FRAME
Physical L1:    101010110010101... (bits transmitted on wire)

RECEIVER SIDE (removing headers going UP the stack):
─────────────────────────────────────────────────
Physical L1:    Receives bits, reassembles into frame
Data Link L2:   Reads MAC header, removes it → hands Packet up
Network L3:     Reads IP header, removes it → hands Segment up
Transport L4:   Reads TCP header, reassembles segments → hands Data up
App Layer 7:    Application receives the original data ✅
```

---

### Network Devices — Where They Sit and Why

#### Hub (Layer 1)
- Receives a signal on one port → **blindly broadcasts it to ALL other ports**
- No intelligence whatsoever
- Creates **collision domains** — if two devices send simultaneously, data collides
- **Obsolete** — replaced by switches
- Think of it as a megaphone in a room: everyone hears everything

#### Switch (Layer 2)
- Reads the **destination MAC address** in each frame
- Forwards the frame **only to the port** where that MAC is connected
- Builds a **MAC Address Table** (CAM table) by learning source MACs
- **Eliminates collisions** between ports
- Think of it as a smart mail sorter that reads the address label

#### Router (Layer 3)
- Reads the **destination IP address** in each packet
- Consults its **routing table** to decide the best exit interface
- **Connects different networks** (subnets, VLANs, or the internet)
- Each interface on a router = a separate network

#### Repeater (Layer 1)
- Boosts signal strength to extend cable length
- No data processing — just amplifies (including noise!)
- Used for long cable runs before fiber became cheap

#### Bridge (Layer 2)
- Like a simple switch with only 2 ports
- Connects two LAN segments, filters traffic by MAC
- **Legacy device** — switches replaced bridges

#### Modem (Layer 1/2)
- **Mo**dulates and **Dem**odulates
- Converts digital data (bits) ↔ analog signal (for phone lines) or digital cable/fiber signal
- Your home internet box is technically a modem + router + switch combined

#### Gateway (All Layers)
- Translates between **completely different protocols** or architectures
- Example: Connecting a TCP/IP network to a legacy mainframe system
- Email gateway: converts between different email protocols

---

## Part B — Network Topologies

### How to Draw Each Topology (and remember it)

#### 1. Bus Topology
```
PC1 --- PC2 --- PC3 --- PC4 --- PC5
         ←— Single backbone cable —→
         Terminators on each end ‖     ‖
```
- **Pros:** Cheapest, easiest to set up, least cable used
- **Cons:** One break = entire network down. Hard to troubleshoot. High collisions.
- **Used in:** Old 10BASE2 Ethernet (coaxial cable, mostly obsolete)

#### 2. Star Topology ⭐ (Most Common Today)
```
        PC1
         |
PC5 — [Switch] — PC2
         |
        PC3
         |
        PC4
```
- **Pros:** One cable fails → only one device down. Easy to add/remove devices. Easy troubleshooting.
- **Cons:** Switch is a **single point of failure**. More cable needed than Bus.
- **Used in:** Every modern office, home network, school lab

#### 3. Ring Topology
```
PC1 → PC2 → PC3
 ↑              ↓
PC4 ← PC5 ← PC6
```
- Data travels in one direction (or both in Dual Ring / SONET)
- **Token Ring:** Only the device holding the "token" can transmit → no collisions
- **Pros:** Orderly, predictable performance
- **Cons:** One break = entire ring down (unless dual ring). High latency.
- **Used in:** Fiber Distributed Data Interface (FDDI), some industrial networks

#### 4. Mesh Topology (Full Mesh)
```
PC1 ——— PC2
 | ╲   ╱ |
 |   ╳   |
 | ╱   ╲ |
PC4 ——— PC3
```
- **Every device connects to every other device**
- Formula for links: n(n-1)/2 → 4 devices = 6 links
- **Pros:** Extremely redundant. No single point of failure. Self-healing.
- **Cons:** Very expensive. Complex cabling. Hard to scale.
- **Used in:** Internet backbone, military networks, critical infrastructure

#### 5. Tree (Hierarchical) Topology
```
           [Core Router]
           /            \
    [Dist SW1]        [Dist SW2]
    /        \        /        \
[Access] [Access] [Access] [Access]
  |          |        |        |
 PCs        PCs      PCs      PCs
```
- Combination of Star topologies connected hierarchically
- **Pros:** Very scalable. Easy to isolate faults. Organized.
- **Cons:** Root node failure is catastrophic. More expensive.
- **Used in:** Large corporate buildings, campuses, ISPs

#### 6. Hybrid Topology
- Mix of two or more types (e.g., Star + Mesh for redundancy, Star + Bus for cost)
- **Used in:** Almost every real enterprise network
- **Pros:** Flexible — take the best of multiple topologies
- **Cons:** Complex to design and maintain

---

## ✅ Experiment 1 Self-Check

Before moving on, make sure you can answer:
- [ ] What is the PDU at Layer 4? (Segment)
- [ ] What device operates at Layer 2 and reads MAC addresses? (Switch)
- [ ] Which topology has n(n-1)/2 links? (Mesh)
- [ ] What does encapsulation mean? (Adding headers going down the stack)
- [ ] Which layer encrypts data with TLS/SSL? (Layer 6 — Presentation)

---
---

# EXPERIMENT 2
## IP Addressing, Types & Classifications

> **Tool needed:** Calculator (or mental math). No software required.

---

## Understanding IPv4 Structure

An IPv4 address is **32 bits** long, written as **4 octets** separated by dots.

```
        192     .    168    .     1     .     1
     11000000   . 10101000  . 00000001  . 00000001
     (8 bits)     (8 bits)    (8 bits)    (8 bits)
     ←——————————— 32 bits total ——————————————→
```

### How to convert Decimal → Binary (for one octet)

Use powers of 2: **128 | 64 | 32 | 16 | 8 | 4 | 2 | 1**

Example: Convert **192** to binary
```
128+64 = 192 → Place 1 under 128, 1 under 64, 0 everywhere else
128  64  32  16   8   4   2   1
  1   1   0   0   0   0   0   0  = 11000000 = 192 ✓
```

Example: Convert **168** to binary
```
128+32+8 = 168
128  64  32  16   8   4   2   1
  1   0   1   0   1   0   0   0  = 10101000 = 168 ✓
```

---

## Types of IP Addresses

### By Scope

| Type | Description | Example | Routable on Internet? |
|------|-------------|---------|----------------------|
| **Private IP** | Used inside a LAN, assigned by your router | 192.168.1.5 | ❌ No |
| **Public IP** | Unique address on the global internet, given by ISP | 203.0.113.45 | ✅ Yes |
| **Loopback** | Points back to your own machine | 127.0.0.1 | ❌ No (local only) |

### Private IP Ranges (memorize these!)

| Class | Private Range | Example |
|-------|--------------|---------|
| A | 10.0.0.0 – 10.255.255.255 | 10.0.0.1 |
| B | 172.16.0.0 – 172.31.255.255 | 172.16.0.1 |
| C | 192.168.0.0 – 192.168.255.255 | 192.168.1.1 |

### By Assignment Method

| Type | Who sets it | Changes? | Use case |
|------|-------------|----------|---------|
| **Static IP** | Admin sets manually | Never changes | Servers, printers, routers |
| **Dynamic IP** | DHCP server assigns automatically | Changes on reconnect | PCs, laptops, phones |

> **DHCP** = Dynamic Host Configuration Protocol. Your home router runs a DHCP server. When your phone connects to Wi-Fi, DHCP automatically gives it an IP, subnet mask, gateway, and DNS server.

---

## IPv4 Address Classes — Full Breakdown

### The 5 Classes

| Class | 1st Octet Range | Network/Host Split | Default Subnet | Max Networks | Hosts per Network |
|-------|----------------|-------------------|---------------|-------------|------------------|
| **A** | 1 – 126 | **N**.H.H.H | 255.0.0.0 /8 | 126 | 16,777,214 |
| **B** | 128 – 191 | **N.N**.H.H | 255.255.0.0 /16 | 16,384 | 65,534 |
| **C** | 192 – 223 | **N.N.N**.H | 255.255.255.0 /24 | 2,097,152 | 254 |
| **D** | 224 – 239 | N/A (Multicast) | N/A | N/A | N/A |
| **E** | 240 – 255 | N/A (Experimental) | N/A | N/A | N/A |

### Special Addresses to Know

| Address | Purpose |
|---------|---------|
| 127.0.0.1 | Loopback (test your own NIC without sending to network) |
| 255.255.255.255 | Limited broadcast (to everyone on local network) |
| 0.0.0.0 | Default route / unassigned address |
| x.x.x.0 | Network address (not assignable to hosts) |
| x.x.x.255 | Broadcast address for that subnet (not assignable to hosts) |

### How to Identify a Class by First Octet

```
First octet:   1–126    → Class A
               127      → Loopback (reserved)
               128–191  → Class B
               192–223  → Class C
               224–239  → Class D (Multicast)
               240–255  → Class E (Experimental)
```

### How to Calculate Hosts per Network

Formula: **2^(host bits) - 2**
- The -2 subtracts the **network address** (all host bits = 0) and **broadcast address** (all host bits = 1)

Example — Class C:
- Subnet mask 255.255.255.0 → 8 host bits
- 2^8 - 2 = 256 - 2 = **254 usable hosts**

Example — Class A:
- Subnet mask 255.0.0.0 → 24 host bits
- 2^24 - 2 = 16,777,216 - 2 = **16,777,214 usable hosts**

---

## IPv4 vs IPv6 Comparison

| Feature | IPv4 | IPv6 |
|---------|------|------|
| Bit length | 32 bits | 128 bits |
| Address count | ~4.3 billion | 340 undecillion (3.4×10³⁸) |
| Notation | Dotted decimal (192.168.1.1) | Hexadecimal with colons (2001:db8::1) |
| Header size | 20 bytes minimum | 40 bytes fixed |
| NAT required? | Yes (to conserve IPs) | No |
| Security | Optional (IPsec) | Built-in IPsec |

---

## ✅ Experiment 2 Self-Check

- [ ] What class is 172.20.5.1? (Class B — first octet 172 is in 128-191)
- [ ] What class is 10.0.0.1? (Class A)
- [ ] What class is 192.168.10.5? (Class C)
- [ ] How many hosts can Class C support? (254)
- [ ] What is 127.0.0.1 used for? (Loopback / testing local machine)
- [ ] What does DHCP do? (Automatically assigns IP addresses to devices)

---
---

# EXPERIMENT 3
## Inter-VLAN Routing — Class A ↔ Class C via Router in Packet Tracer

> **Objective:** Make PC0 (on a Class A network: 10.0.0.0/8) talk to PC1 (on a Class C network: 192.168.1.0/24) through a router.

---

## Understanding the Concept First

Without a router, PC0 and PC1 are on **different logical networks**. They cannot communicate even if plugged into the same switch, because their IP addresses are in completely different ranges. A **router** bridges them by having one foot in each network.

```
Network A (Class A)          Router0           Network B (Class C)
    10.0.0.0/8                                   192.168.1.0/24

  [PC0: 10.0.0.2]  ——— [Switch0] ——— [G0/0: 10.0.0.1 | G0/1: 192.168.1.1] ——— [Switch1] ——— [PC1: 192.168.1.2]

  Default GW: 10.0.0.1                                      Default GW: 192.168.1.1
```

---

## Step 1 — Open Packet Tracer and Create New File

1. Launch Packet Tracer
2. Go to **File → New** (or Ctrl+N)
3. You'll see a blank grey workspace
4. **Save immediately:** File → Save As → name it `Experiment3_InterVLAN.pkt`

> **Why save early?** Packet Tracer doesn't auto-save. Saving often prevents losing work.

---

## Step 2 — Place Your Devices

### Place Router0 (Cisco 2911)
1. In the **bottom panel**, click the **Router icon** (looks like a cylinder with arrows)
2. In the device list that appears, find **2911**
3. Click once on **2911**, then click in the **center-top area** of your workspace to place it
4. The router appears labeled **Router0**

> **Why 2911?** It has 3 GigabitEthernet ports built-in. The 1841 only has 2 Fast Ethernet ports with different naming. 2911 is standard for labs.

### Place Switch0 (Cisco 2960)
1. Click the **Switch icon** (flat rectangular box icon) in the bottom panel
2. Find **2960** in the device list
3. Place it to the **left of Router0**
4. It appears as **Switch0**

### Place Switch1 (Cisco 2960)
1. Same process — place it to the **right of Router0**
2. It appears as **Switch1**

### Place PC0
1. Click the **End Devices** icon (monitor icon)
2. Click **PC** (the first option — generic PC)
3. Place it to the **left of Switch0**
4. Appears as **PC0**

### Place PC1
1. Same process — place to the **right of Switch1**
2. Appears as **PC1**

✅ **Checkpoint:** Your workspace should look like: `PC0 — Switch0 — Router0 — Switch1 — PC1`

---

## Step 3 — Cable the Devices

You'll use **Copper Straight-Through** cables throughout (PC→Switch, Switch→Router are different device types).

### Connect PC0 → Switch0
1. Click **Connections** (lightning bolt icon in bottom-left)
2. Click **Copper Straight-Through** (solid black line)
3. Click **PC0** → select **FastEthernet0** from the popup
4. Click **Switch0** → select **FastEthernet0/1** from the popup
5. A line appears. Link lights may be orange at first (STP initializing) → wait ~30 seconds → turns green

### Connect Switch0 → Router0
1. Same cable type (Copper Straight-Through)
2. Click **Switch0** → select **FastEthernet0/24** (or any unused port)
3. Click **Router0** → select **GigabitEthernet0/0**

### Connect PC1 → Switch1
1. Click **PC1** → **FastEthernet0**
2. Click **Switch1** → **FastEthernet0/1**

### Connect Switch1 → Router0
1. Click **Switch1** → **FastEthernet0/24**
2. Click **Router0** → **GigabitEthernet0/1**

> **Note:** If a port popup doesn't show GigabitEthernet, try another unused port. The 2911 has G0/0, G0/1, G0/2.

✅ **Checkpoint:** All devices are connected with lines. Some lights may be red — that's OK, we haven't configured IPs yet.

---

## Step 4 — Configure PC0 (Class A)

1. **Click on PC0** in the workspace → its config window opens
2. Click the **Desktop** tab
3. Click **IP Configuration** (the icon that looks like a network card)
4. A form appears — fill in:

| Field | Value |
|-------|-------|
| IP Address | `10.0.0.2` |
| Subnet Mask | `255.0.0.0` |
| Default Gateway | `10.0.0.1` |
| DNS Server | (leave blank for this experiment) |

5. Press **Tab** or click outside each field to apply
6. Close the PC0 window (click the X)

> **Alternative method:** Click Config tab → Interface → FastEthernet0 → enter same values there. Both methods work.

---

## Step 5 — Configure PC1 (Class C)

1. **Click on PC1**
2. **Desktop** tab → **IP Configuration**
3. Fill in:

| Field | Value |
|-------|-------|
| IP Address | `192.168.1.2` |
| Subnet Mask | `255.255.255.0` |
| Default Gateway | `192.168.1.1` |

4. Close the window

---

## Step 6 — Configure Router0 via CLI

This is the most important step. We must configure both router interfaces as gateways for each network.

1. **Click on Router0** → **CLI tab**
2. If prompted "Would you like to enter the initial configuration dialog?" → type **no** and press Enter
3. You'll see `Router>`

### Enter Configuration Mode
```
Router> enable
Router# configure terminal
Router(config)#
```

### Configure Interface GigabitEthernet0/0 (for Class A — PC0's side)
```
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip address 10.0.0.1 255.0.0.0
Router(config-if)# no shutdown
Router(config-if)# exit
```

**What each line does:**
- `interface GigabitEthernet0/0` → Enter configuration mode for this specific port
- `ip address 10.0.0.1 255.0.0.0` → Assign the IP (this becomes PC0's gateway) and subnet mask
- `no shutdown` → **Activate the interface** (Cisco interfaces are OFF by default — this is different from most home routers)
- `exit` → Go back to global config mode

### Configure Interface GigabitEthernet0/1 (for Class C — PC1's side)
```
Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip address 192.168.1.1 255.255.255.0
Router(config-if)# no shutdown
Router(config-if)# exit
```

### Save the configuration
```
Router(config)# exit
Router# copy running-config startup-config
```
When prompted `Destination filename [startup-config]?` → just press **Enter**

---

## Step 7 — Verify with show commands

In the Router CLI (at `Router#`):
```
Router# show ip interface brief
```

You should see output like:
```
Interface         IP-Address      OK? Method Status   Protocol
GigabitEthernet0/0 10.0.0.1      YES manual up       up
GigabitEthernet0/1 192.168.1.1   YES manual up       up
GigabitEthernet0/2 unassigned    YES unset  administratively down down
```

**Status: up, Protocol: up** = Interface is working ✅
**administratively down** = Interface hasn't been configured / `no shutdown` not run

---

## Step 8 — Test Connectivity with Ping

### From PC0's Command Prompt
1. Click **PC0** → **Desktop** tab → **Command Prompt**
2. Type:
```
ping 192.168.1.2
```
3. You should see:
```
Pinging 192.168.1.2 with 32 bytes of data:
Reply from 192.168.1.2: bytes=32 time=0ms TTL=127
Reply from 192.168.1.2: bytes=32 time=0ms TTL=127
Reply from 192.168.1.2: bytes=32 time=0ms TTL=127
Reply from 192.168.1.2: bytes=32 time=0ms TTL=127
Ping statistics for 192.168.1.2:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
```

> **First ping may fail!** This is normal. The first packet is used for ARP (discovering MAC addresses). The second through fourth succeed. This is expected behavior.

### Troubleshooting if ping fails

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Request timed out (all 4) | Router interface not up | Run `show ip int brief` — check status |
| First ping fails, rest succeed | Normal ARP behavior | Not a problem |
| Destination unreachable | Wrong gateway on PC | Re-check PC IP config |
| Link lights still red | `no shutdown` not run | Re-enter interface and run it |

---

## Step 9 — Visualize in Simulation Mode (Optional but Recommended)

1. Switch to **Simulation Mode** (bottom-right, click the clock icon)
2. In the "Event List Filters", ensure **ICMP** is checked
3. Go to PC0 Command Prompt and ping PC1
4. Click **Play ▶** slowly — you'll see packet envelopes moving across the topology
5. Click on any packet envelope to see its PDU details at each layer

---

## ✅ Experiment 3 Self-Check

- [ ] Can you ping from PC0 to PC1? (Should get replies)
- [ ] Does `show ip interface brief` show G0/0 and G0/1 as "up/up"?
- [ ] Do you understand why a router is needed between different IP classes?
- [ ] What command activates a Cisco interface? (`no shutdown`)

---
---

# EXPERIMENT 4
## Router-Switch Integration & Security via Cisco CLI

> **Objective:** Connect a router and switch, configure the router interface, apply security (passwords), and verify connectivity. This experiment focuses more on **CLI mastery** than topology.

---

## Understanding the Setup

```
[Management PC] ——(Console Cable)——→ [Router R1] ——(Straight-Through)——→ [Switch0]
                                           |
                                      (configured via CLI)
```

A **console cable** is a special cable used for **initial configuration** when you can't yet SSH/Telnet into the device (because there's no IP set yet). It connects your PC's RS-232 serial port (or USB via adapter) to the router's Console port.

In Packet Tracer, the console cable = **blue rolled cable**.

---

## Step 1 — Create New File and Place Devices

1. File → New → Save as `Experiment4_CLI_Security.pkt`
2. Place:
   - **Router 2911** (center of workspace) — will be renamed to R1
   - **Switch 2960** (right of router)
   - **PC0** (right of Switch — regular network user)
   - **PC1** (left of router — Management PC for console access)

---

## Step 2 — Cable the Devices

### Console Connection (Management PC → Router)
1. Click **Connections** → find **Console** cable (blue, rolled appearance)
2. Click **PC1** (Management PC) → select **RS-232** port
3. Click **Router0** → select **Console** port

> **What is RS-232?** It's the serial port. Old PCs had physical DB9 connectors. Modern PCs use USB-to-Serial adapters. Packet Tracer has RS-232 built into all PCs.

### Network Connection (Router → Switch → PC0)
1. Copper Straight-Through: **Router0 GigabitEthernet0/0** → **Switch0 FastEthernet0/24**
2. Copper Straight-Through: **Switch0 FastEthernet0/1** → **PC0 FastEthernet0**

---

## Step 3 — Access CLI via Console

1. Click **PC1** (Management PC) → **Desktop** tab → **Terminal**
2. A "Terminal Configuration" dialog appears:
   - Speed (baud): 9600
   - Data bits: 8
   - Parity: None
   - Stop bits: 1
   - Flow control: None
   - *(Leave all defaults — just click OK)*
3. Press **Enter** — you'll see the router's output
4. You're now in the Router CLI: `Router>`

> **Why these settings?** Console ports use RS-232 at 9600 baud by default. This is an industry standard. Real Cisco routers use these exact same settings.

---

## Step 4 — Basic Security Configuration

This is the most important part of this experiment. Follow each command exactly.

### Step 4a — Enter Privileged Mode and set Hostname
```
Router> enable
Router# configure terminal
Router(config)# hostname R1
```
Notice the prompt immediately changes to `R1(config)#`

> **Why rename?** In real networks with dozens of routers, knowing which device you're logged into is critical. The hostname appears in every CLI prompt.

### Step 4b — Set Encrypted Privilege Password
```
R1(config)# enable secret cisco123
```

> **`enable secret` vs `enable password`:**
> - `enable password cisco123` → stored in plain text in config (insecure ❌)
> - `enable secret cisco123` → stored as MD5 hash (secure ✅)
> - **Always use `enable secret`** in real environments
> - If both are set, `enable secret` takes precedence

### Step 4c — Set Console Access Password
```
R1(config)# line console 0
R1(config-line)# password console123
R1(config-line)# login
R1(config-line)# exit
```

**What this does:**
- `line console 0` → Enter configuration for the physical console port
- `password console123` → Anyone connecting via console must enter this password
- `login` → **Enable** the password check (without `login`, the password is set but not enforced!)

### Step 4d — Set Telnet/SSH Access Password
```
R1(config)# line vty 0 4
R1(config-line)# password telnet123
R1(config-line)# login
R1(config-line)# exit
```

**What this does:**
- `line vty 0 4` → Configure virtual terminal lines 0 through 4 (5 simultaneous remote sessions)
- VTY lines are used for Telnet and SSH remote access
- Without this, nobody can remotely manage the router

### Step 4e — Encrypt All Plaintext Passwords in Config
```
R1(config)# service password-encryption
```
This encrypts any passwords that are stored in plain text (like the VTY password). A useful catch-all security measure.

---

## Step 5 — Configure the Network Interface

```
R1(config)# interface GigabitEthernet0/0
R1(config-if)# description Link to Main Office Switch
R1(config-if)# ip address 192.168.10.1 255.255.255.0
R1(config-if)# no shutdown
R1(config-if)# exit
```

**What each command does:**
- `description` → Labels this interface. Purely informational. Shows up in `show` commands. Best practice to always add.
- `ip address` → Assigns the IP and subnet mask
- `no shutdown` → Turns the interface on

---

## Step 6 — Configure PC0

1. Click **PC0** → **Desktop** → **IP Configuration**

| Field | Value |
|-------|-------|
| IP Address | `192.168.10.2` |
| Subnet Mask | `255.255.255.0` |
| Default Gateway | `192.168.10.1` |

---

## Step 7 — Save the Configuration

**This is critical.** If you don't save, all configuration is lost when the router reboots.

```
R1# copy running-config startup-config
```
Or the shorter version:
```
R1# write memory
```
Or even shorter:
```
R1# wr
```

> **RAM vs NVRAM explained:**
> - `running-config` = what's in RAM (active right now, lost on reboot)
> - `startup-config` = what's in NVRAM (survives reboot, loaded on boot)
> - `copy running-config startup-config` = **"Save my work"**

---

## Step 8 — Verify Everything

### Check Interface Status
From `R1#`:
```
R1# show ip interface brief
```
Look for G0/0 showing `up / up`

### Check Running Configuration
```
R1# show running-config
```
Scroll through — you should see:
- hostname R1
- enable secret 5 $1$... (hashed password — not readable)
- interface GigabitEthernet0/0 with your IP

### Test Connectivity
From **PC0** Desktop → Command Prompt:
```
ping 192.168.10.1
```
Should receive 4 replies from the router.

From **Router CLI**:
```
R1# ping 192.168.10.2
```
Should receive replies from PC0.

---

## Step 9 — Verify Password Security

To confirm the enable secret is encrypted:
```
R1# show running-config | include secret
```
You'll see something like:
`enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0`

The `5` means MD5 encrypted. ✅ Not readable. Secure.

---

## Alternate Method — Using the Config Tab GUI (Not Recommended for Exams)

Instead of CLI, you can click **Router0 → Config tab** and:
- Set hostname in the "Global Settings" section
- Click on "GigabitEthernet0/0" in the left panel to set IP graphically
- Flip the "Port Status" toggle to On (equivalent to `no shutdown`)

> **Use GUI only to check your CLI work.** Exams and real jobs require CLI knowledge. GUI is training wheels.

---

## ✅ Experiment 4 Self-Check

- [ ] Can you ping the router from PC0?
- [ ] Does `show ip interface brief` show the interface as up/up?
- [ ] Is the enable secret stored as a hash (not plain text)?
- [ ] What's the difference between `running-config` and `startup-config`?
- [ ] What does `no shutdown` do, and why is it needed?
- [ ] What does `line vty 0 4` configure?

---
---

# EXPERIMENT 5
## Single-Bit Parity Check in C++

> **Tool needed:** Any C++ compiler — Code::Blocks, Dev-C++, VS Code with g++, or an online compiler (replit.com, onlinegdb.com)

---

## Understanding Parity Before Coding

### What is a Parity Bit?
When you send data over a network, bits can get corrupted (electromagnetic interference, signal degradation, etc.). A parity bit is a **single extra bit added to data** so the receiver can detect if something went wrong.

### Even Parity Rule
Count the number of **1s** in your data. Add a parity bit so the **total count of 1s (data + parity) is EVEN**.

```
Data: 1 0 1 0   → Count of 1s: 2 (already even)  → Parity bit: 0
Data: 1 1 1 0   → Count of 1s: 3 (odd)            → Parity bit: 1  (makes total = 4, even)
Data: 0 0 0 1   → Count of 1s: 1 (odd)            → Parity bit: 1  (makes total = 2, even)
Data: 1 1 0 0   → Count of 1s: 2 (already even)  → Parity bit: 0
```

### How Detection Works
```
Sender sends:    1 1 1 0 [parity=1]   → Total 1s: 4 (even ✅)
Receiver gets:   0 1 1 0 [parity=1]   → Count 1s: 3 (odd ❌) → Error detected!
```

### The Limitation
Parity only detects **odd numbers of bit errors**. If exactly 2 bits flip, the count stays even and the error goes undetected. That's why we have more advanced methods (CRC, 2D parity).

---

## The Data Layout

16 bits of data split into 4 frames of 4 bits each:

```
Frame 1:  1 0 1 0  → two 1s (even)   → parity = 0  → stored as [1,0,1,0,0]
Frame 2:  1 1 1 0  → three 1s (odd)  → parity = 1  → stored as [1,1,1,0,1]
Frame 3:  0 0 0 1  → one 1 (odd)     → parity = 1  → stored as [0,0,0,1,1]
Frame 4:  1 1 0 0  → two 1s (even)   → parity = 0  → stored as [1,1,0,0,0]
```

This gives us a 4×5 array (4 frames, 5 bits each — 4 data + 1 parity).

---

## Code Walkthrough — Line by Line

```cpp
#include <iostream>
using namespace std;
```
- `#include <iostream>` → Include the input/output library (needed for `cout`, `cin`)
- `using namespace std` → Allows writing `cout` instead of `std::cout`

---

```cpp
void checkParity(int frames[4][5]) {
```
- Defines a function `checkParity` that takes a 2D array of integers
- `int frames[4][5]` → 4 rows, 5 columns
- `void` → This function returns nothing

---

```cpp
    bool hasError = false;
```
- A boolean flag. Starts as false. Set to true if any frame has an error.

---

```cpp
    for (int i = 0; i < 4; i++) {
        int countOnes = 0;
        for (int j = 0; j < 4; j++) {
            if (frames[i][j] == 1) countOnes++;
        }
```
- Outer loop: goes through each **frame** (row 0 to 3)
- `countOnes` resets to 0 for each new frame
- Inner loop: goes through **bits 0 to 3** (the data bits, not the parity bit)
- If a bit is 1, increment the counter

---

```cpp
        int expectedParity = (countOnes % 2 == 0) ? 0 : 1;
```
- `countOnes % 2` = remainder when divided by 2
  - If 0 → count is even → parity should be 0
  - If 1 → count is odd → parity should be 1 (to make total even)
- This is the **ternary operator**: `condition ? value_if_true : value_if_false`
- Equivalent to:
  ```cpp
  if (countOnes % 2 == 0)
      expectedParity = 0;
  else
      expectedParity = 1;
  ```

---

```cpp
        if (expectedParity != frames[i][4]) {
            cout << "Frame " << i + 1 << ": Error Detected!" << endl;
            hasError = true;
        } else {
            cout << "Frame " << i + 1 << ": No Error." << endl;
        }
```
- `frames[i][4]` → The **5th column** (index 4) = the received parity bit
- If expected ≠ received → error!
- `i + 1` because arrays start at 0 but we say "Frame 1", not "Frame 0"

---

```cpp
    if (!hasError) cout << ">> RESULT: Transmission Successful." << endl;
    else cout << ">> RESULT: Data Corrupted." << endl;
```
- `!hasError` = "NOT hasError" → if no errors were found

---

```cpp
int main() {
    int senderData[4][5] = {
        {1, 0, 1, 0, 0},   // Frame 1: data=1010, parity=0
        {1, 1, 1, 0, 1},   // Frame 2: data=1110, parity=1
        {0, 0, 0, 1, 1},   // Frame 3: data=0001, parity=1
        {1, 1, 0, 0, 0}    // Frame 4: data=1100, parity=0
    };
```
- A 4×5 2D array initialized with our data
- The last element in each row is the parity bit

---

```cpp
    cout << "--- Scenario i: No Error at Receiver ---" << endl;
    checkParity(senderData);
```
- Print a label and call the function with unmodified data
- Expected output: All frames pass

---

```cpp
    cout << "\n--- Scenario ii: Error at Frame 2, Bit 1 ---" << endl;
    senderData[1][0] = 0; // Bit flip from 1 to 0
    checkParity(senderData);
```
- `senderData[1][0]` = Row index 1 (Frame 2), Column index 0 (first bit)
- Change it from 1 to 0 — simulating transmission noise
- Now Frame 2's data is `0110` but parity is still `1` (set for `1110`)
- New count of 1s in data = 2 (even) → expectedParity = 0 → doesn't match received parity 1 → **Error!**

---

## Expected Output

```
--- Scenario i: No Error at Receiver ---
Frame 1: No Error.
Frame 2: No Error.
Frame 3: No Error.
Frame 4: No Error.
>> RESULT: Transmission Successful.

--- Scenario ii: Error at Frame 2, Bit 1 ---
Frame 1: No Error.
Frame 2: Error Detected!
Frame 3: No Error.
Frame 4: No Error.
>> RESULT: Data Corrupted.
```

---

## How to Compile and Run

### Using Command Line (Linux/Mac)
```bash
g++ -o parity parity.cpp
./parity
```

### Using Online Compiler (easiest)
1. Go to **https://onlinegdb.com**
2. Set language to **C++**
3. Paste the code
4. Click **Run**

### Using VS Code
1. Install the C/C++ extension
2. Install MinGW (Windows) or use g++ (Linux/Mac)
3. Open terminal → compile and run as above

---

## ✅ Experiment 5 Self-Check

- [ ] What does `countOnes % 2` tell you?
- [ ] Why do we iterate `j < 4` (not `j < 5`) when counting 1s?
- [ ] What does `senderData[1][0] = 0` simulate?
- [ ] Why does single-bit parity fail to detect 2-bit errors?
- [ ] What does `bool hasError = false` do at the start?

---
---

# EXPERIMENT 6
## Two-Dimensional (2D) Parity Check in C++

> **Objective:** Extend parity checking to a 2D grid, enabling more powerful error detection.

---

## Understanding 2D Parity Before Coding

### Why 2D?
Simple (1D) parity only adds one bit per row. **2D parity adds a parity bit per row AND a parity bit per column**, creating a grid of redundancy.

```
Original 4×4 data:          After adding Row Parity:      After adding Column Parity:

1  0  1  1                  1  0  1  1 | 1               1  0  1  1 | 1
0  0  1  1                  0  0  1  1 | 0               0  0  1  1 | 0
1  1  0  1                  1  1  0  1 | 1               1  1  0  1 | 1
0  1  1  0                  0  1  1  0 | 0               0  1  1  0 | 0
                                                          ——————————————
                                                          0  0  1  1 | 0  ← Column parity row
```

The bottom row is calculated by applying even parity to each column (including the row parity column itself).

### Error Localization
If bit at position [1][2] is flipped:
- **Row 1 parity check fails** (row sum becomes odd)
- **Column 2 parity check fails** (column sum becomes odd)
- The intersection → **Row 1, Column 2** = exact error location

---

## The 5×5 Array Structure

```cpp
int networkBlock[5][5] = {
    {1, 0, 1, 1, 1},   // Row 0 data + row parity
    {0, 0, 1, 1, 0},   // Row 1 data + row parity
    {1, 1, 0, 1, 1},   // Row 2 data + row parity
    {0, 1, 1, 0, 0},   // Row 3 data + row parity
    {0, 0, 1, 1, 0}    // Column parity row
};
```

Verify Row 0: 1+0+1+1 = 3 (odd) → parity = 1 → stored sum = 1+0+1+1+1 = 4 (even ✅)
Verify Row 1: 0+0+1+1 = 2 (even) → parity = 0 → stored sum = 0+0+1+1+0 = 2 (even ✅)

---

## Code Walkthrough — Line by Line

```cpp
void verifyData(int block[5][5]) {
    int rowErrors = 0;
    int colErrors = 0;
```
- Two counters: how many rows have odd parity, how many columns have odd parity

---

```cpp
    for (int i = 0; i < 5; i++) {        // Check ALL 5 rows
        int rSum = 0;
        for (int j = 0; j < 5; j++) rSum += block[i][j];
        if (rSum % 2 != 0) rowErrors++;
    }
```
- Loop through all 5 rows (including the parity row at index 4)
- Sum ALL 5 elements in the row (data + parity bit)
- If sum is odd → parity is wrong → increment error count

---

```cpp
    for (int j = 0; j < 5; j++) {        // Check ALL 5 columns
        int cSum = 0;
        for (int i = 0; i < 5; i++) cSum += block[i][j];
        if (cSum % 2 != 0) colErrors++;
    }
```
- Loop through all 5 columns (including the parity column at index 4)
- Sum ALL 5 elements in the column
- Note the loop structure: outer loop is `j` (column), inner is `i` (row) — reversed from row check

---

```cpp
    if (rowErrors == 0 && colErrors == 0) {
        cout << "STATUS: Success. No errors detected." << endl;
    } else {
        cout << "STATUS: Error Detected! Integrity check failed." << endl;
    }
```
- Both must be zero for a clean transmission
- Even one odd row or column = error

---

```cpp
    networkBlock[1][2] = (networkBlock[1][2] == 0) ? 1 : 0;
```
- A compact bit-flip: if the value is 0, make it 1; if 1, make it 0
- Simulates a bit getting corrupted during transmission
- Position [1][2] = Row 1 (second row), Column 2 (third column)

---

## What Happens After the Bit Flip?

Before flip: `networkBlock[1]` = {0, 0, **1**, 1, 0} → Row sum = 2 (even ✅)
After flip:  `networkBlock[1]` = {0, 0, **0**, 1, 0} → Row sum = 1 (odd ❌) → **Row error!**

Column 2 before: 1, **1**, 0, 1, 1 → Sum = 4 (even ✅)
Column 2 after:  1, **0**, 0, 1, 1 → Sum = 3 (odd ❌) → **Column error!**

Result: `rowErrors = 1, colErrors = 1` → Error detected! ✅

---

## Expected Output

```
--- Testing Scenario 1: Clean Transmission ---
STATUS: Success. No errors detected.

--- Testing Scenario 2: Bit-Flip at [1][2] ---
STATUS: Error Detected! Integrity check failed.
```

---

## 2D Parity vs 1D Parity — Comparison

| Feature | 1D (Simple) Parity | 2D Parity |
|---------|-------------------|-----------|
| Extra bits added | 1 per row | 1 per row + 1 per column |
| Detects single-bit errors | ✅ Yes | ✅ Yes |
| Detects 2-bit errors in same row | ❌ No | ✅ Yes (column catches it) |
| Locates error position | ❌ No | ✅ Yes (row+column intersection) |
| Can correct errors | ❌ No | ✅ Single-bit errors only |
| Overhead | Low | Medium |

---

## ✅ Experiment 6 Self-Check

- [ ] What does the 5th row (index 4) in the 5×5 array represent? (Column parity row)
- [ ] Why do we check 5 rows and 5 columns, not just 4? (Must include parity row/column themselves)
- [ ] If row 2 and column 3 both fail, where is the error? (Position [2][3])
- [ ] What does `(networkBlock[1][2] == 0) ? 1 : 0` do? (Flips the bit)
- [ ] Can 2D parity detect all errors? (No — if 4 bits form a rectangle flip, it may miss)

---
---

# 📖 MASTER QUICK-REFERENCE

## Cisco IOS Cheat Sheet

```
MODES:
  Router>            User EXEC (monitoring only)
  Router#            Privileged EXEC (full view + diagnostics)
  Router(config)#    Global Config (device-wide changes)
  Router(config-if)# Interface Config (per-port changes)

NAVIGATION:
  enable             → goes to Router#
  conf t             → goes to Router(config)#
  int g0/0           → goes to Router(config-if)# for GigEth0/0
  exit               → one level up
  end or Ctrl+Z      → back to Router#

INTERFACE SETUP (must do in this order):
  ip address X.X.X.X Y.Y.Y.Y    → assign IP and mask
  no shutdown                     → turn interface on

VERIFICATION:
  show ip int brief              → all interfaces + status
  show run                       → current config (RAM)
  show start                     → saved config (NVRAM)
  show ip route                  → routing table

SAVE:
  copy run start                 → save to NVRAM
```

---

## OSI Model One-Liner Summary

| Layer | Number | PDU | Remember it as |
|-------|--------|-----|----------------|
| Application | 7 | Data | "Your Apps Live Here" (HTTP, DNS, FTP) |
| Presentation | 6 | Data | "The Translator" (encrypt, compress) |
| Session | 5 | Data | "The Conversation Manager" |
| Transport | 4 | Segment | "TCP/UDP — reliable vs fast" |
| Network | 3 | Packet | "Routers, IP addresses, routing" |
| Data Link | 2 | Frame | "Switches, MAC addresses, Ethernet" |
| Physical | 1 | Bits | "Cables, signals, hubs" |

---

## IP Class Quick Lookup

| First octet starts with... | Class | Subnet mask |
|---------------------------|-------|-------------|
| 1 to 126 | A | /8 (255.0.0.0) |
| 128 to 191 | B | /16 (255.255.0.0) |
| 192 to 223 | C | /24 (255.255.255.0) |
| 224 to 239 | D | Multicast |
| 240 to 255 | E | Experimental |
| 127 | — | Loopback |

---

## Parity Quick Reference

```
EVEN PARITY RULE: Total 1s in (data + parity bit) must be EVEN

1D (Simple) Parity:
  Data: 1010 → two 1s (even) → parity = 0
  Data: 1110 → three 1s (odd) → parity = 1

2D Parity adds:
  - Row parity for each row
  - Column parity for each column
  - Can locate single-bit errors at (row, column) intersection
```

---

*This guide was created to be completely self-sufficient. You should be able to complete all 6 experiments using only this document.*

**Good luck! 🚀**
