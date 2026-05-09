
# ═══════════════════════════════════════════════════════════════
# UNIT III — MOBILE DEVICE ANALYSIS (EXPANDED)
# ═══════════════════════════════════════════════════════════════

---

## 🔎 Interactive Index

<details open>
<summary><strong>Unit III — Mobile Device Analysis</strong></summary>

- [3.1 Data Extraction Methodologies (Deep Dive)](#31-data-extraction-methodologies-deep-dive)
- [3.2 Mobile Forensics Workflow (End-to-End)](#32-mobile-forensics-workflow-end-to-end)
- [3.3 Data Extraction and Analysis Tools](#33-data-extraction-and-analysis-tools)
- [3.4 Examination of Call Logs, SMS, Contacts, Emails](#34-examination-of-call-logs-sms-contacts-emails)
- [3.5 Digital Media Analysis (Photos, Videos, Audio)](#35-digital-media-analysis-photos-videos-audio)
- [3.6 Application Data Analysis](#36-application-data-analysis)
- [3.7 Cloud-Based Data Analysis](#37-cloud-based-data-analysis)
- [Unit III Q&A](#-unit-iii--questions--answers)

</details>

<details>
<summary><strong>Unit IV — Mobile Device Security</strong></summary>

- [4.1 Mobile Device Architecture and Storage Systems (Deep Dive)](#41-mobile-device-architecture-and-storage-systems-deep-dive)
- [4.2 Mobile Device Vulnerabilities and Threats](#42-mobile-device-vulnerabilities-and-threats)
- [4.3 Common Cyber Threats: Malware — Types, Analysis, Impact](#43-common-cyber-threats-malware--types-analysis-impact)
- [4.4 Cryptography — Fundamentals and Methods](#44-cryptography--fundamentals-and-methods)
- [4.5 Anti-Forensics Techniques](#45-anti-forensics-techniques)
- [4.6 Firewalls and Intrusion Detection Systems](#46-firewalls-and-intrusion-detection-systems)
- [4.7 Mobile Device Security Best Practices](#47-mobile-device-security-best-practices)
- [4.8 Incident Response and Digital Forensics](#48-incident-response-and-digital-forensics)
- [4.9 Mobile Network Security](#49-mobile-network-security)
- [4.10 SIM Card Forensics and Cellular Security](#410-sim-card-forensics-and-cellular-security)
- [4.11 Mobile Payment Security](#411-mobile-payment-security)
- [4.12 Wi-Fi Security](#412-wi-fi-security)
- [Unit IV Q&A](#-unit-iv--questions--answers)

</details>

<details>
<summary><strong>Unit V — Advanced Topics in Mobile Forensics</strong></summary>

- [5.1 Mobile Device Forensics in Criminal Investigations](#51-mobile-device-forensics-in-criminal-investigations)
- [5.2 Mobile Device Forensics in Civil Litigation](#52-mobile-device-forensics-in-civil-litigation)
- [5.3 Emerging Trends in Mobile Forensics](#53-emerging-trends-in-mobile-forensics)
- [5.4 Data Mining in Mobile Security](#54-data-mining-in-mobile-security)
- [5.5 Machine Learning in Mobile Forensics](#55-machine-learning-in-mobile-forensics)
- [5.6 Mobile Forensics Case Studies](#56-mobile-forensics-case-studies)
- [Unit V Q&A](#-unit-v--questions--answers)

</details>

<details>
<summary><strong>Master Q&A Bank and Appendix</strong></summary>

- [Master Q&A Bank — Units III, IV, V](#-master-qa-bank--units-iii-iv-v)
- [Q&A Section — Critical Concepts](#qa-section--critical-concepts)
- [Final Appendix — Quick Reference Tables and Diagrams](#-final-appendix--quick-reference-tables-and-diagrams)

</details>

---

## 3.1 DATA EXTRACTION METHODOLOGIES (Deep Dive)

### 🔍 What Is Data Extraction?

Data extraction in mobile forensics refers to the **systematic process of copying digital data from a mobile device** in a forensically sound manner — without altering the original evidence. The goal is to capture as much data as possible while maintaining integrity via hash verification.

> 📗 **Reiber (2020), §5.1:** "Data extraction is the most critical technical step in mobile forensics — the quality and completeness of everything that follows depends entirely on what data was captured and how."

---

### 🏛️ The Five Extraction Tiers — Pyramid Model

```
                    ┌─────────────────────┐
                    │   LEVEL 5: JTAG /   │  ← Maximum data, invasive
                    │   CHIP-OFF          │    hardware-level
                    ├─────────────────────┤
                    │   LEVEL 4: PHYSICAL │  ← Bit-for-bit image
                    │   ACQUISITION       │    includes deleted data
                    ├─────────────────────┤
                    │  LEVEL 3: FILE-SYS  │  ← Full file system,
                    │  ACQUISITION        │    no deleted data
                    ├─────────────────────┤
                    │  LEVEL 2: LOGICAL   │  ← Active files only,
                    │  ACQUISITION        │    via OS/backup API
                    ├─────────────────────┤
                    │  LEVEL 1: MANUAL    │  ← Screenshot,
                    │  EXTRACTION         │    photograph screen
                    └─────────────────────┘
                    
         Low Invasiveness ↑          High Invasiveness ↓
         Low Data Volume  ↑          High Data Volume   ↓
```

---

### 🔬 Level 1: Manual Extraction

**Definition:** The investigator directly interacts with the device's user interface and manually records or photographs information on the screen.

**When used:**
- Device is locked but screen is accessible (PIN entry fails)
- Device is damaged and only partially functional
- Quick triage before full acquisition

**Methods:**
- Photograph the screen with a camera
- Use a video camera to record scrolling through content
- Use a stylus if touchscreen is damaged

**Limitations:**
- Extremely time-consuming and incomplete
- Only captures what is visible on screen
- Cannot recover deleted data
- No automated parsing or search

**Forensic considerations:**
- Always photograph in a way that shows the device, its screen, and timestamps
- Document every action taken
- Use gloves to avoid fingerprint contamination

---

### 🔬 Level 2: Logical Acquisition

**Definition:** The extraction of data that is **currently accessible** through the device's operating system or backup APIs, without bypassing OS security.

```
┌──────────────────────────────────────────────────────────────┐
│                  LOGICAL ACQUISITION FLOW                     │
│                                                              │
│  ┌─────────┐    USB/Wi-Fi    ┌──────────────┐               │
│  │Forensic │ ─────────────► │  Mobile OS   │               │
│  │  Tool   │                │  (API Layer) │               │
│  │(Cellebrite│◄─────────────  │  Backup Mgr  │               │
│  │ OXYGEN  │   Backup/DB    │  File Manager│               │
│  │ etc.)   │                └──────────────┘               │
│  └─────────┘                       │                        │
│       │                            │                        │
│       ▼                            ▼                        │
│  ┌──────────┐              ┌───────────────┐               │
│  │Hash      │              │Active Files   │               │
│  │Verify    │              │(no deleted)   │               │
│  │MD5/SHA256│              └───────────────┘               │
└──────────────────────────────────────────────────────────────┘
```

**Android Logical Methods:**
- `adb backup` — creates an Android backup file (.ab)
- `adb pull /sdcard/` — pulls accessible storage
- Third-party forensic tool via MTP (Media Transfer Protocol)

**iOS Logical Methods:**
- iTunes/Finder backup (local)
- iCloud backup (via credentials or legal request)
- `libimobiledevice` suite

**Data Captured:**
- SMS/MMS messages
- Call logs
- Contacts
- Calendar
- Photos and videos (in accessible storage)
- App data (if backup-enabled)
- Emails (via mail client backup)

**Data NOT Captured:**
- Deleted files
- Unallocated space
- Encrypted app containers (not accessible via backup API)
- Keychain (without encrypted backup on iOS)

---

### 🔬 Level 3: File System Acquisition

**Definition:** Extraction of the entire **live file system** — all folders and files including hidden system files — but without capturing unallocated space (where deleted data lives).

**Requires:**
- Root access on Android
- Jailbreak on iOS
- Or a forensic exploit (e.g., checkm8 on older iPhones)

```
┌─────────────────────────────────────────────────────────────┐
│             FILE SYSTEM VS LOGICAL COMPARISON               │
├──────────────────────────────┬──────────────────────────────┤
│        LOGICAL               │       FILE SYSTEM            │
├──────────────────────────────┼──────────────────────────────┤
│ Only backup-enabled data     │ All files on the partition   │
│ OS API mediates access       │ Direct filesystem read       │
│ Cannot access /data/data     │ Can access /data/data/*      │
│ No system files              │ Includes system config files │
│ No deleted data              │ No deleted data (unalloc)    │
│ Fastest method               │ Moderate speed               │
│ No root needed               │ Root/jailbreak needed        │
└──────────────────────────────┴──────────────────────────────┘
```

**Tools for File System Acquisition:**
- Cellebrite UFED (with root exploit)
- Oxygen Forensic Detective
- MSAB XRY
- FFS (Full File System) mode in various tools
- `tar` or `dd` via ADB shell (with root)

---

### 🔬 Level 4: Physical Acquisition

**Definition:** A **bit-for-bit copy** of the entire physical storage media — including the operating system partition, user data partition, and **all unallocated space** where deleted data may still reside.

```
┌────────────────────────────────────────────────────────────┐
│              PHYSICAL ACQUISITION STRUCTURE                 │
│                                                            │
│  Physical Storage (e.g., 128GB eMMC/UFS chip)             │
│  ┌─────────┬─────────┬──────────┬───────────┬───────────┐ │
│  │ Boot    │ System  │ User     │ Cache     │Unallocated│ │
│  │Partition│Partition│ Data     │ Partition │  Space    │ │
│  │(kernel) │(Android │Partition │           │(DELETED   │ │
│  │         │ ROM)    │(/data)   │           │ DATA !)   │ │
│  └─────────┴─────────┴──────────┴───────────┴───────────┘ │
│                                                            │
│  Physical image = EVERYTHING above, byte-by-byte          │
│  Logical image  = Only accessible active files            │
└────────────────────────────────────────────────────────────┘
```

**Methods for Physical Acquisition:**
1. **JTAG** — connects via test points on PCB to read flash memory
2. **Fastboot/Bootloader** — boot custom recovery, dump partitions
3. **EDL (Emergency Download Mode)** — Qualcomm-specific deep access
4. **Custom recovery (TWRP)** — mount and dump partitions

**Command example (ADB + root):**
```bash
# Dump userdata partition physically
adb shell "su -c 'dd if=/dev/block/mmcblk0p25 | gzip -1'" | dd of=userdata.img.gz

# Verify with MD5
md5sum userdata.img.gz
```

**What physical acquisition captures that others miss:**
- Deleted SMS messages (SQLite freelist pages)
- Deleted photos (unallocated JPEG fragments)
- Partial app data from uninstalled apps
- Swap/cache partition data
- Previous encryption keys (in some cases)

---

### 🔬 Level 5: JTAG and Chip-Off

**JTAG (Joint Test Action Group):**

```
┌─────────────────────────────────────────────────────────────┐
│                    JTAG ARCHITECTURE                         │
│                                                             │
│  Forensic Workstation                                       │
│  ┌──────────────┐                                           │
│  │ JTAG Tool    │──────────────────┐                       │
│  │ (RIFF Box,   │                  │                       │
│  │  Z3X, etc.)  │                  ▼                       │
│  └──────────────┘         ┌────────────────┐               │
│                           │ Test Points on │               │
│                           │ Device PCB     │               │
│                           │ (TAP Interface)│               │
│                           └───────┬────────┘               │
│                                   │                        │
│                    TDI ───────────┤  (Test Data In)        │
│                    TDO ───────────┤  (Test Data Out)       │
│                    TCK ───────────┤  (Test Clock)          │
│                    TMS ───────────┤  (Test Mode Select)    │
│                    TRST ──────────┘  (Test Reset)          │
└─────────────────────────────────────────────────────────────┘
```

**How JTAG Works:**
1. Disassemble device to expose PCB
2. Identify JTAG test points (TDI, TDO, TCK, TMS, TRST)
3. Solder thin wires to test points (or use pogo pins)
4. Connect to JTAG adapter box
5. Use software (JTAG Manager, Easy-JTAG) to read memory
6. Extracts raw binary dump of flash storage

**Chip-Off:**
1. Heat or dissolve device PCB to remove NAND flash chip
2. Place chip in specialized reader
3. Read raw binary data
4. Reconstruct file system using FTL (Flash Translation Layer) emulation

**Comparison:**

| Feature | JTAG | Chip-Off |
|---------|------|----------|
| Device damage | Minimal (solder points) | High (chip removed) |
| Works on locked device | Yes | Yes |
| Works on damaged device | Sometimes | Often |
| Skill required | Moderate | Very High |
| Data obtained | Raw flash dump | Raw flash dump |
| Risk of data loss | Low | Medium |
| Cost of equipment | Moderate | High |

---

### 📊 Extraction Method Decision Tree

```
START: Device received for analysis
           │
           ▼
    Is device powered on?
    ┌──── YES ────┐         ┌──── NO ────┐
    ▼             │         ▼            │
Is USB debug     │    Power on          │
enabled?         │    (document)        │
    │            │         │            │
   YES           NO        └────────────┘
    │            │
    ▼            ▼
ADB/Logical   Attempt unlock
acquisition   techniques
    │            │
    ▼            ▼
Can you root?  Brute force?
    │          GrayKey?
   YES/NO       Cellebrite?
    │            │
    ▼            ▼
File System   Physical via
or Physical   EDL/JTAG/Chip-off
acquisition
```

---

## 3.2 MOBILE FORENSICS WORKFLOW (End-to-End)

### 🔄 Complete Forensic Workflow Model

The mobile forensics workflow is a **structured, repeatable process** that ensures evidence integrity from scene to courtroom. Every step must be documented.

```
┌─────────────────────────────────────────────────────────────────┐
│                  COMPLETE MOBILE FORENSICS WORKFLOW             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PHASE 1: SCENE RESPONSE & IDENTIFICATION                 │  │
│  │                                                          │  │
│  │  • Photograph device in place before touching           │  │
│  │  • Note network status (Wi-Fi/cellular/airplane mode)   │  │
│  │  • Record visible information (screen, notifications)   │  │
│  │  • Identify: Make, Model, IMEI (dial *#06#)             │  │
│  │  • Note: SIM card present? SD card? Case/accessories?   │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │                                   │
│                             ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PHASE 2: PRESERVATION & ISOLATION                        │  │
│  │                                                          │  │
│  │  Option A: Airplane Mode                                │  │
│  │    → Disable all radios (Wi-Fi, Bluetooth, cellular)    │  │
│  │    → Prevents remote wipe, new data sync               │  │
│  │                                                          │  │
│  │  Option B: Faraday Bag/Cage                             │  │
│  │    → Place device inside RF-shielding enclosure         │  │
│  │    → Completely blocks all radio frequencies            │  │
│  │                                                          │  │
│  │  Option C: Network Isolation + Charging                  │  │
│  │    → Block network but keep powered to prevent lock     │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │                                   │
│                             ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PHASE 3: DOCUMENTATION & CHAIN OF CUSTODY               │  │
│  │                                                          │  │
│  │  • Fill evidence form: date, time, location, officer    │  │
│  │  • Unique evidence number assigned                      │  │
│  │  • Tamper-evident bag used                              │  │
│  │  • Each transfer logged with signature                  │  │
│  │  • Storage in locked, climate-controlled evidence room  │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │                                   │
│                             ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PHASE 4: ACQUISITION (DATA EXTRACTION)                   │  │
│  │                                                          │  │
│  │  Step 1: Set up forensic workstation                    │  │
│  │  Step 2: Connect write-blocker (if applicable)          │  │
│  │  Step 3: Select extraction method (L1–L5)               │  │
│  │  Step 4: Run acquisition tool                           │  │
│  │  Step 5: Hash the acquisition (MD5 + SHA-256)           │  │
│  │  Step 6: Hash verification (compare to original)        │  │
│  │  Step 7: Store acquisition in secure location           │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │                                   │
│                             ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PHASE 5: EXAMINATION & ANALYSIS                          │  │
│  │                                                          │  │
│  │  • Parse file system structures                         │  │
│  │  • Extract and analyze: SMS, calls, emails, media       │  │
│  │  • Recover deleted files (carving)                      │  │
│  │  • Analyze app databases (SQLite)                       │  │
│  │  • Build timeline of events                             │  │
│  │  • Cross-correlate artifacts                            │  │
│  │  • Analyze cloud data (if applicable)                   │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │                                   │
│                             ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PHASE 6: REPORTING                                       │  │
│  │                                                          │  │
│  │  • Executive summary (non-technical)                    │  │
│  │  • Detailed technical methodology                       │  │
│  │  • Findings organized by category                       │  │
│  │  • Timeline reconstruction                              │  │
│  │  • Limitations and caveats                              │  │
│  │  • Hash verification appendix                           │  │
│  │  • Expert witness preparation                           │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 🔐 Hash Verification in the Workflow

Hash functions are the **mathematical fingerprint** of a dataset. If even one bit changes, the hash changes completely.

```
┌─────────────────────────────────────────────────────────────┐
│                    HASH VERIFICATION PROCESS                 │
│                                                             │
│  Original Device Storage                                    │
│  ┌────────────────────┐                                     │
│  │ Raw Data (128 GB)  │──── Acquisition Tool ────►         │
│  └────────────────────┘                                     │
│                                  ┌────────────────────┐    │
│                                  │ Forensic Image     │    │
│                                  │ (.dd / .E01 file)  │    │
│                                  └────────┬───────────┘    │
│                                           │                 │
│                              ┌────────────▼──────────┐     │
│                              │ Hash Algorithm Applied │     │
│                              │ MD5:    abc123def456   │     │
│                              │ SHA256: f9a3b2...     │     │
│                              └────────────┬──────────┘     │
│                                           │                 │
│  At any future point:                     │                 │
│  Re-hash the image ──────────────────────►│                 │
│  Compare hash values                      │                 │
│  MATCH = Evidence unaltered              │                 │
│  MISMATCH = Evidence compromised         │                 │
└─────────────────────────────────────────────────────────────┘
```

**Hash algorithms in use:**

| Algorithm | Output Length | Security Status | Forensic Use |
|-----------|--------------|-----------------|--------------|
| MD5 | 128-bit (32 hex chars) | Cryptographically broken | Legacy, still used for speed |
| SHA-1 | 160-bit | Broken (collision attacks) | Being phased out |
| SHA-256 | 256-bit | Secure | Current standard |
| SHA-512 | 512-bit | Highly secure | High-value evidence |

**Best practice:** Always compute BOTH MD5 and SHA-256. MD5 for quick verification; SHA-256 for court.

---

### ⚡ Triage Workflow (Rapid Field Assessment)

In the field, before full lab acquisition, investigators may perform rapid **triage** to determine if a device is relevant to an investigation.

```
TRIAGE DECISION MODEL:
═══════════════════════════════════════════

Device Received at Scene
        │
        ▼
Quick Visual Inspection (2 min)
• Visible content on screen?
• Any notifications visible?
• Network connected?
        │
        ▼
Rapid Keyword Search (Cellebrite UFED Triage / Oxygen)
• Search for: suspect names, locations, dates
• Flag relevant content
        │
        ▼
Relevance Determination
├── RELEVANT → Full acquisition warranted
│               Transport to forensic lab
│               Document chain of custody
└── NOT RELEVANT → Return device
                    Document actions taken
```

---

## 3.3 DATA EXTRACTION AND ANALYSIS TOOLS

### 🛠️ Commercial Forensic Tools

#### 1. Cellebrite UFED (Universal Forensic Extraction Device)

Cellebrite UFED is the **industry-leading** mobile forensic tool used by law enforcement worldwide.

```
┌──────────────────────────────────────────────────────────────┐
│                    CELLEBRITE UFED ECOSYSTEM                  │
│                                                              │
│   ┌────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│   │ UFED Touch │    │ UFED 4PC    │    │ UFED Cloud      │  │
│   │ (hardware) │    │ (software)  │    │ Analyzer        │  │
│   │ Field unit │    │ Lab version │    │ Cloud data      │  │
│   └─────┬──────┘    └──────┬──────┘    └────────┬────────┘  │
│         │                  │                     │           │
│         └──────────────────┼─────────────────────┘           │
│                            │                                 │
│                            ▼                                 │
│              ┌─────────────────────────┐                    │
│              │   PHYSICAL ANALYZER     │                    │
│              │  (Analysis Platform)    │                    │
│              │  • Decode 3000+ apps    │                    │
│              │  • Timeline analysis    │                    │
│              │  • Map visualization    │                    │
│              │  • Deleted data recovery│                    │
│              │  • AI-assisted analysis │                    │
│              └─────────────────────────┘                    │
└──────────────────────────────────────────────────────────────┘
```

**Capabilities:**
- Supports 30,000+ device profiles
- Logical, file system, and physical extraction
- Decodes data from 3,000+ applications
- Generates court-ready reports
- Includes Cellebrite Pathfinder for AI-assisted analysis

#### 2. Oxygen Forensic Detective

- Full logical, file system, and physical acquisition
- Cloud data extraction (Google, Apple, Microsoft)
- Drone forensics support
- Social media analysis
- Keyscout module for credential extraction

#### 3. MSAB XRY

- Hardware + software solution
- Used by Interpol, FBI, and 100+ countries
- XAMN Viewer for analysis
- Physical acquisition including JTAG/chip-off
- Strong iOS support

#### 4. Magnet AXIOM Mobile

```
┌──────────────────────────────────────────────────┐
│              MAGNET AXIOM WORKFLOW                │
│                                                  │
│  Acquire  →  Process  →  Analyze  →  Report      │
│                                                  │
│  AXIOM Process:          AXIOM Examine:          │
│  • Connect device        • Artifact view         │
│  • Select sources        • Timeline view         │
│  • Run acquisition       • Connections view      │
│  • Auto-parse artifacts  • Map view              │
│  • Create image          • Search across all     │
└──────────────────────────────────────────────────┘
```

#### 5. Open-Source Tools

| Tool | Purpose | Platform |
|------|---------|---------|
| Autopsy | Full forensic suite with mobile plugin | Windows/Linux/Mac |
| ADB | Android data extraction | All |
| libimobiledevice | iOS device communication | Linux/Mac |
| ALEAPP | Android Logs Events And Protobuf Parser | Python |
| iLEAPP | iOS Logs Events And Plists Parser | Python |
| MVT (Mobile Verification Toolkit) | Spyware detection | Linux/Mac |
| SIFT Workstation | Complete forensic environment | Linux VM |

---

### 🔧 Tool Selection Framework

```
┌──────────────────────────────────────────────────────────────┐
│               TOOL SELECTION DECISION MATRIX                  │
├──────────────────┬────────────┬────────────┬─────────────────┤
│ Scenario         │ First Tool │ Backup     │ Notes           │
├──────────────────┼────────────┼────────────┼─────────────────┤
│ Android unlocked │ ADB+ALEAPP │ Cellebrite │ Fastest method  │
│ Android locked   │ Cellebrite │ GrayKey    │ Need exploit    │
│ iOS unlocked     │ Cellebrite │ libimobile │ Passcode helps  │
│ iOS locked       │ GrayKey    │ Cellebrite │ Limited options │
│ Feature phone    │ Cellebrite │ MSAB XRY   │ Old protocols   │
│ Chip-off needed  │ JTAG first │ Chip-off   │ Last resort     │
│ Cloud data       │ Oxygen     │ Cellebrite │ Need credentials│
│ Drone/IoT        │ Oxygen     │ Autopsy    │ Non-standard    │
└──────────────────┴────────────┴────────────┴─────────────────┘
```

---

## 3.4 EXAMINATION OF CALL LOGS, SMS, CONTACTS, EMAILS

### 📞 Call Logs Analysis

Call logs are stored in **telephony databases** on both Android and iOS and represent critical evidence in many investigations.

#### Android Call Log Structure

```
DATABASE FILE: /data/data/com.android.providers.contacts/databases/contacts2.db

TABLE: calls
┌────┬─────────────┬───────────────┬──────┬──────────┬─────────────┐
│ _id│ number      │ date          │duration│ type   │ name        │
├────┼─────────────┼───────────────┼──────┼──────────┼─────────────┤
│  1 │ +9198765432 │ 1709123456789 │  127 │    1     │ John Doe    │
│  2 │ +9187654321 │ 1709123500000 │    0 │    3     │ Jane Smith  │
│  3 │ +9176543210 │ 1709124000000 │  340 │    2     │ Unknown     │
└────┴─────────────┴───────────────┴──────┴──────────┴─────────────┘

Call type values:
  1 = INCOMING
  2 = OUTGOING  
  3 = MISSED
  4 = VOICEMAIL
  5 = REJECTED
  6 = BLOCKED
```

**Forensic SQL Query to extract calls:**
```sql
SELECT 
    _id,
    number,
    datetime(date/1000, 'unixepoch', 'localtime') AS call_datetime,
    duration || ' seconds' AS call_duration,
    CASE type
        WHEN 1 THEN 'INCOMING'
        WHEN 2 THEN 'OUTGOING'
        WHEN 3 THEN 'MISSED'
        WHEN 4 THEN 'VOICEMAIL'
        WHEN 5 THEN 'REJECTED'
        ELSE 'UNKNOWN (' || type || ')'
    END AS call_type,
    name
FROM calls
ORDER BY date DESC;
```

#### iOS Call Log Structure

```
DATABASE: /private/var/mobile/Library/Application Support/
          CallHistory/CallHistory.storedata (Core Data)

TABLE: ZCALLRECORD
┌───────────────────────────────────────────────────────────┐
│ COLUMN          │ DESCRIPTION                             │
├─────────────────┼─────────────────────────────────────────┤
│ Z_PK            │ Primary key                             │
│ ZDATE           │ CoreData timestamp (seconds since       │
│                 │ Jan 1, 2001 — NOT Unix epoch!)          │
│ ZDURATION       │ Call duration in seconds                │
│ ZORIGINATED     │ 0 = incoming, 1 = outgoing              │
│ ZANSWERED       │ 0 = missed, 1 = answered                │
│ ZADDRESS        │ Phone number or FaceTime address        │
│ ZSERVICE_PROVIDER│ "Phone", "FaceTime", etc.             │
│ ZCALLERNAME     │ Caller name if available                │
└─────────────────┴─────────────────────────────────────────┘
```

**⚠️ iOS Date Conversion:**
iOS Core Data timestamps are seconds since January 1, 2001 (not Unix epoch 1970).
- Unix time = Core Data time + 978,307,200

---

### 💬 SMS/MMS Analysis

#### Android SMS Database

```
DATABASE: /data/data/com.android.providers.telephony/databases/mmssms.db

TABLE: sms
┌──────────────────────────────────────────────────────────────┐
│ IMPORTANT COLUMNS:                                           │
│                                                              │
│ _id      → Row identifier                                    │
│ thread_id → Groups messages in same conversation             │
│ address  → Phone number of sender/recipient                  │
│ date     → Unix timestamp (milliseconds)                     │
│ date_sent→ When message was sent by sender                   │
│ body     → Message text content                              │
│ type     → 1=Received, 2=Sent, 3=Draft, 5=Failed            │
│ read     → 0=Unread, 1=Read                                  │
│ status   → Delivery status                                   │
│ locked   → User has locked this message (1=locked)           │
└──────────────────────────────────────────────────────────────┘
```

**Recovering Deleted SMS:**

```
SQLITE FREELIST APPROACH:
══════════════════════════════════════════

Active SMS → Stored in sms table (B-tree pages)
Deleted SMS → Row deleted, page moved to freelist
              Binary data still in freelist pages
              
Recovery steps:
1. Open mmssms.db in hex editor
2. Parse SQLite page structure (4096-byte pages)
3. Locate freelist pages (referenced from page 1 header)
4. Search freelist pages for SMS row patterns
5. Manually parse or use Autopsy's SQLite recovery
```

#### MMS Structure

```
MMS messages span multiple tables:

pdu table:    message headers (date, from, to, subject)
part table:   message parts (text body, images, audio, video)
addr table:   participants in MMS thread

Relationship: pdu._id → part.mid (message ID link)
```

---

### 📒 Contacts Analysis

```
CONTACTS HIERARCHY (Android):

contacts2.db
├── contacts table        (one row per person)
│     └── _id (contact_id)
├── raw_contacts table    (one row per account source)
│     └── contact_id (links to contacts)
└── data table            (all actual data points)
      ├── raw_contact_id (links to raw_contacts)
      ├── mimetype_id    (what kind of data)
      └── data1–data15   (the actual values)

MIMETYPES:
  vnd.android.cursor.item/phone_v2  → Phone number
  vnd.android.cursor.item/email_v2  → Email address
  vnd.android.cursor.item/name      → Name
  vnd.android.cursor.item/photo     → Profile photo
  vnd.android.cursor.item/postal-address_v2 → Address
```

**SQL to reconstruct full contact records:**
```sql
SELECT 
    c._id AS contact_id,
    rc.account_name AS source_account,
    MAX(CASE WHEN mm.mimetype='vnd.android.cursor.item/name' 
        THEN d.data1 END) AS full_name,
    MAX(CASE WHEN mm.mimetype='vnd.android.cursor.item/phone_v2' 
        THEN d.data1 END) AS phone_number,
    MAX(CASE WHEN mm.mimetype='vnd.android.cursor.item/email_v2' 
        THEN d.data1 END) AS email
FROM contacts c
JOIN raw_contacts rc ON c._id = rc.contact_id
JOIN data d ON rc._id = d.raw_contact_id
JOIN mimetypes mm ON d.mimetype_id = mm._id
GROUP BY c._id;
```

---

### 📧 Email Analysis

Email forensics involves examining both **email client databases** and **email server logs**.

```
COMMON EMAIL CLIENT STORAGE LOCATIONS:

Gmail (Android):
  /data/data/com.google.android.gm/databases/bigTopDataDB.db
  Tables: messages, conversations, attachments, labels

iOS Mail:
  /private/var/mobile/Library/Mail/
  Folder structure mirrors IMAP mailbox
  .emlx format (modified RFC 2822)

Microsoft Outlook (Android):
  /data/data/com.microsoft.office.outlook/databases/*.db
  Encrypted with app-level key

Artifacts to examine:
┌────────────────────┬────────────────────────────────────────┐
│ Artifact           │ Forensic Value                         │
├────────────────────┼────────────────────────────────────────┤
│ Message headers    │ Routing path, IP addresses, timestamps │
│ Message body       │ Content, intent, relationships         │
│ Attachments        │ Documents, images, malware             │
│ Deleted emails     │ From trash folder or SQLite freelist   │
│ Draft emails       │ Intent even if never sent              │
│ Search history     │ What user looked for in email          │
│ Contact list       │ Known correspondents                   │
│ Folder structure   │ Organization of activities             │
└────────────────────┴────────────────────────────────────────┘
```

**Email Header Analysis:**
```
From: attacker@malicious.com
To: victim@company.com
Date: Sat, 09 May 2026 14:30:00 +0530
Message-ID: <abc123@malicious.com>
Received: from mail.malicious.com [192.168.1.100]
          by mail.company.com; Sat, 09 May 2026 14:30:01 +0530
X-Originating-IP: 203.0.113.45

FORENSIC ANALYSIS:
• "Received" headers chain = routing path (read bottom to top)
• X-Originating-IP = attacker's actual IP address
• Message-ID = unique identifier (cross-reference with server logs)
• Date discrepancy between sender/receiver = timezone issues or spoofing
```

---

## 3.5 DIGITAL MEDIA ANALYSIS (Photos, Videos, Audio)

### 📷 Photo Forensics

#### EXIF Metadata — The Hidden Story in Every Photo

EXIF (Exchangeable Image File Format) metadata is embedded in JPEG, TIFF, and many other image formats automatically by the camera or device.

```
┌─────────────────────────────────────────────────────────────┐
│                  EXIF METADATA STRUCTURE                     │
│                                                             │
│  JPEG File                                                  │
│  ┌─────────┬───────────────────────────────────────────┐   │
│  │ SOI     │ FF D8                                     │   │
│  ├─────────┼───────────────────────────────────────────┤   │
│  │ APP1    │ EXIF Header                               │   │
│  │ Marker  │ ┌─────────────────────────────────────┐  │   │
│  │         │ │ IFD0 (Main Image Directory)         │  │   │
│  │         │ │  • Make: Apple                      │  │   │
│  │         │ │  • Model: iPhone 15 Pro             │  │   │
│  │         │ │  • DateTime: 2026:05:09 14:30:22    │  │   │
│  │         │ │  • Orientation: 6 (rotated)         │  │   │
│  │         │ ├─────────────────────────────────────┤  │   │
│  │         │ │ ExifIFD (Detailed Settings)         │  │   │
│  │         │ │  • ExposureTime: 1/250              │  │   │
│  │         │ │  • FNumber: f/1.8                   │  │   │
│  │         │ │  • ISO: 64                          │  │   │
│  │         │ │  • DateTimeOriginal: 2026:05:09...  │  │   │
│  │         │ │  • SubSecTimeOriginal: 123          │  │   │
│  │         │ ├─────────────────────────────────────┤  │   │
│  │         │ │ GPS IFD (Location Data)              │  │   │
│  │         │ │  • GPSLatitude: 29.6857 N           │  │   │
│  │         │ │  • GPSLongitude: 76.9905 E          │  │   │
│  │         │ │  • GPSAltitude: 229 m               │  │   │
│  │         │ │  • GPSDateStamp: 2026:05:09         │  │   │
│  │         │ │  • GPSTimeStamp: 09:00:22           │  │   │
│  │         │ └─────────────────────────────────────┘  │   │
│  ├─────────┼───────────────────────────────────────────┤   │
│  │ Pixel   │ Actual Image Data                         │   │
│  │ Data    │ (compressed with JPEG algorithm)          │   │
│  └─────────┴───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Key EXIF fields for forensic investigation:**

| EXIF Field | Forensic Use |
|-----------|-------------|
| DateTimeOriginal | When the photo was actually taken |
| DateTime | When file was last modified (may differ!) |
| GPSLatitude/Longitude | Where the photo was taken |
| GPSAltitude | Elevation (useful for indoor/outdoor determination) |
| Make, Model | Corroborates device identification |
| Software | OS version that processed the image |
| ImageWidth/Height | Original vs. cropped detection |
| Thumbnail | May show edited-out content |
| MakerNote | Manufacturer-specific data (e.g., Apple stores face detection data) |

**Extracting EXIF with ExifTool:**
```bash
# Full EXIF dump
exiftool photo.jpg

# GPS only
exiftool -gps:all photo.jpg

# Batch process a directory
exiftool -csv -gps:all /evidence/photos/ > gps_data.csv

# Remove all EXIF (detect if suspect scrubbed metadata)
exiftool -all= photo.jpg
# If original has no EXIF, it may have been deliberately stripped
```

---

#### Image Authentication — Detecting Manipulation

```
APPROACHES TO DETECT IMAGE FORGERY:

1. METADATA ANALYSIS
   • DateTime vs. file system timestamp mismatch
   • Missing EXIF (stripped by editing software)
   • Inconsistent camera settings

2. ERROR LEVEL ANALYSIS (ELA)
   • Resave image at known quality
   • Compare to original
   • Edited areas show different compression artifacts

3. CLONE DETECTION
   • Identical pixel blocks at different locations = copied region
   • Statistical analysis of DCT coefficients

4. NOISE ANALYSIS
   • Different noise patterns in different image regions
   • Composite images show inconsistent noise

5. SHADOW/LIGHTING ANALYSIS
   • Inconsistent light source direction
   • Impossible shadow angles

6. PIXEL-LEVEL ANALYSIS
   • Double JPEG compression artifacts
   • Blocking artifacts at edited boundaries
```

---

### 🎬 Video Forensics

```
VIDEO FILE STRUCTURE (MP4/MOV):

┌─────────────────────────────────────────────────────────────┐
│                    MP4 CONTAINER STRUCTURE                   │
│                                                             │
│  ┌──────────┐  Contains: metadata about file               │
│  │  ftyp    │  (file type, version)                        │
│  ├──────────┤                                              │
│  │  moov    │  Movie container — KEY FORENSIC ARTIFACT     │
│  │  ┌─────┐ │   • mvhd: movie header (duration, creation)  │
│  │  │ trak│ │   • trak: track data (video/audio streams)   │
│  │  │ ┌──┐│ │     • tkhd: track header (creation date)     │
│  │  │ │mdia││ │     • mdia: media data                      │
│  │  │ └──┘│ │   • udta: user data (GPS, device info)       │
│  │  └─────┘ │                                              │
│  ├──────────┤                                              │
│  │  mdat    │  Actual video/audio frame data               │
│  └──────────┘                                              │
│                                                             │
│  FORENSIC VALUE OF moov ATOM:                               │
│  • Creation date (when recording started)                   │
│  • Modification date (when file was edited)                 │
│  • GPS location data (if embedded)                          │
│  • Device identifier                                        │
│  • Software used to create/edit                             │
└─────────────────────────────────────────────────────────────┘
```

**Video forensic analysis steps:**

1. **Integrity check** — hash the video file before analysis
2. **Metadata extraction** — use FFprobe or ExifTool
3. **Frame extraction** — extract key frames for analysis
4. **Authentication** — detect double encoding, splicing, insertion
5. **Enhancement** — CCTV enhancement, face extraction
6. **Audio analysis** — voice spectrography, background noise analysis

```bash
# Extract video metadata
ffprobe -v quiet -print_format json -show_format -show_streams video.mp4

# Extract all frames
ffmpeg -i video.mp4 -q:v 2 frames/frame_%04d.jpg

# Extract audio track
ffmpeg -i video.mp4 -vn -acodec pcm_s16le audio.wav
```

---

### 🎵 Audio Forensics

**Key analysis techniques:**

```
AUDIO FORENSIC ANALYSIS METHODS:

┌──────────────────────────────────────────────────────────┐
│  SPECTROGRAM ANALYSIS                                     │
│                                                          │
│  Frequency (Hz)                                          │
│  8000 ─┤                    ████                        │
│  4000 ─┤    ██          ████████████                    │
│  2000 ─┤ ██████████████████████████████                │
│  1000 ─┤████████████████████████████████████           │
│   500 ─┤████████████████████████████████████████       │
│         └───────────────────────────────────────        │
│                        Time →                           │
│                                                          │
│  Each horizontal band = frequency component             │
│  Intensity = amplitude at that frequency                │
│  Voice = characteristic frequency patterns              │
│  Cuts/splices = visible discontinuities                 │
│  Background noise = unique acoustic fingerprint         │
└──────────────────────────────────────────────────────────┘
```

| Technique | Purpose |
|-----------|---------|
| Speaker Identification | Match voice to known individual |
| ENF (Electric Network Frequency) | Match recording to power grid fluctuations at specific time |
| Audio Enhancement | Remove noise, amplify speech |
| Splice Detection | Detect cuts and edits |
| Codec Analysis | Identify recording device/software |
| Watermark Detection | Hidden ownership markers |

---

## 3.6 APPLICATION DATA ANALYSIS

### 📱 Understanding App Sandboxing

Every app on both Android and iOS runs in a **sandbox** — an isolated environment preventing access to other apps' data.

```
┌──────────────────────────────────────────────────────────────┐
│                    APP SANDBOX MODEL                          │
│                                                              │
│  ANDROID                        iOS                         │
│                                                              │
│  /data/data/                    /private/var/mobile/        │
│  └── com.whatsapp/              └── Containers/             │
│      ├── databases/                 └── Data/               │
│      │   ├── msgstore.db                └── Application/    │
│      │   └── wa.db                          └── [UUID]/     │
│      ├── shared_prefs/                           ├── Documents/
│      │   └── *.xml                              ├── Library/
│      ├── cache/                                 └── tmp/
│      └── files/                                             │
│                                                              │
│  Each app's directory is:                                    │
│  • Owned by unique Linux UID                                 │
│  • chmod 700 (only owner can access)                         │
│  • Root required to read across apps                         │
└──────────────────────────────────────────────────────────────┘
```

---

### 📊 WhatsApp Forensics (Case Study)

WhatsApp stores data in two key SQLite databases:

```
DATABASE 1: msgstore.db — Messages
TABLE: messages
┌───┬──────────────┬────────────────┬──────────────┬──────────┐
│_id│ key_remote_jid│ timestamp      │ data         │ media_url│
├───┼──────────────┼────────────────┼──────────────┼──────────┤
│ 1 │ 91987@s.whats│ 1709123456000  │ "Meet at 8pm"│ NULL     │
│ 2 │ 91987@s.whats│ 1709123500000  │ NULL         │ https://…│
└───┴──────────────┴────────────────┴──────────────┴──────────┘

key_remote_jid format:
  [country_code][number]@s.whatsapp.net  → individual
  [group_id]@g.us                        → group chat

media types (media_wa_type column):
  0 = text message
  1 = image
  2 = audio
  3 = video
  4 = contact vCard
  5 = location
  7 = URL link
  9 = document
  13 = GIF

DATABASE 2: wa.db — Contacts
TABLE: wa_contacts
  • jid (WhatsApp ID)
  • display_name (contact alias in WhatsApp)
  • number (phone number)
  • is_whatsapp_user (0/1)
```

**Deleted WhatsApp messages:**
- Messages deleted via "Delete for Me" → removed from messages table but SQLite freelist may contain them
- Messages deleted via "Delete for Everyone" → message data replaced with placeholder
- `msgstore.db.crypt15` → encrypted backup; requires WhatsApp encryption key

**Key file: `/data/data/com.whatsapp/files/key`**
This file contains the WhatsApp encryption key (32 bytes) used for `.crypt15` backups. With this key, all encrypted backups can be decrypted.

---

### 🗺️ Location Data Analysis

Mobile devices accumulate location data from multiple sources:

```
LOCATION DATA SOURCES ON A MOBILE DEVICE:

Source 1: GPS Chip
  → High accuracy (1-5m)
  → Stored in photo EXIF, app databases
  → Requires outdoor visibility or A-GPS

Source 2: Cell Tower Data
  → Lower accuracy (100m - 5km)
  → Network carrier records
  → Always-on, hard to disable
  → Stored in carrier records, sometimes device caches

Source 3: Wi-Fi Location
  → Medium accuracy (10-50m)
  → MAC address of nearby APs → location database
  → Google/Apple maintain global AP location databases

Source 4: Bluetooth Beacons
  → Very accurate indoors (1-3m)
  → iBeacon/Eddystone protocols
  → Mall navigation, indoor tracking

CONSOLIDATED ON DEVICE:
  Android: /data/data/com.google.android.gms/databases/
           → herrevents.db (Location History)
  iOS:     /private/var/mobile/Library/Caches/locationd/
           → consolidated.db (older iOS)
           → Various plists
```

**Google Timeline (significant locations):**
```sql
-- From herrevents.db (Android Google Location History)
SELECT 
    datetime(timestamp_ms/1000, 'unixepoch') as event_time,
    latitude_e7/10000000.0 as latitude,
    longitude_e7/10000000.0 as longitude,
    accuracy_meters,
    place_id,
    place_name
FROM raw_events
ORDER BY timestamp_ms DESC;
```

---

## 3.7 CLOUD-BASED DATA ANALYSIS

### ☁️ Cloud Forensics Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CLOUD DATA ECOSYSTEM                      │
│                                                             │
│  Mobile Device                Cloud Services               │
│  ┌──────────┐                ┌───────────────────────────┐ │
│  │          │◄──── Sync ────►│  iCloud / Google One /    │ │
│  │ iPhone / │                │  OneDrive / Dropbox       │ │
│  │ Android  │                │                           │ │
│  │          │◄── Messages ──►│  iMessage / WhatsApp Web  │ │
│  │          │                │  Telegram Cloud           │ │
│  │          │◄─── Email ────►│  Gmail / Outlook / Yahoo  │ │
│  │          │                │                           │ │
│  │          │◄─── Photos ───►│  Google Photos / iCloud   │ │
│  └──────────┘                │  Photos                   │ │
│                              └───────────────────────────┘ │
│                                                             │
│  FORENSIC CHALLENGE: Data may exist ONLY in cloud          │
│  Device may have minimal local storage                     │
│  Cloud data requires separate legal authorization          │
└─────────────────────────────────────────────────────────────┘
```

### 🍎 iCloud Forensics

```
iCloud SERVICE CATEGORIES:

┌────────────────────┬──────────────────────────────────────┐
│ Service            │ Forensic Value                       │
├────────────────────┼──────────────────────────────────────┤
│ iCloud Backup      │ Device backup: SMS, voicemail,       │
│                    │ photos, app data, call history       │
├────────────────────┼──────────────────────────────────────┤
│ iCloud Drive       │ Files and documents                  │
├────────────────────┼──────────────────────────────────────┤
│ iCloud Photos      │ Photo library with location metadata │
├────────────────────┼──────────────────────────────────────┤
│ iCloud Mail        │ Email messages                       │
├────────────────────┼──────────────────────────────────────┤
│ iCloud Keychain    │ Passwords and credentials            │
├────────────────────┼──────────────────────────────────────┤
│ Find My            │ Device location history              │
├────────────────────┼──────────────────────────────────────┤
│ iMessage in Cloud  │ Synced message history               │
├────────────────────┼──────────────────────────────────────┤
│ Screen Time        │ App usage, restrictions data         │
└────────────────────┴──────────────────────────────────────┘
```

**Access Methods:**

1. **With Apple ID + Password + 2FA** → Direct API access (Oxygen Forensic, Elcomsoft Phone Breaker)
2. **With legal process (US law)** → Apple responds within 7-14 days for account content
3. **Advanced Data Protection (ADP)** → End-to-end encrypted; Apple CANNOT provide content

**Apple Legal Response Data:**
Apple provides different data under different legal instruments:
- **Subpoena:** Account registration info, iCloud subscriber information
- **Court Order:** Icloud backup, iCloud email, contacts, calendar
- **Search Warrant:** All of the above plus iCloud Drive, Photos, iMessage (if no E2E)

---

### 🤖 Google Cloud Forensics

```
GOOGLE ACCOUNT DATA (via Google Takeout / Legal Process):

Category                    Contents
─────────────────────────── ────────────────────────────────
Google Account Info         Account creation, recovery info
Location History            Every location, timestamped
Google Maps                 Searches, directions, saved places
Chrome History              Browse history, downloads, bookmarks
Gmail                       All emails, drafts, labels
Google Photos               Photos with EXIF/GPS data
Google Drive                All documents and files
Google Calendar             Events, attendees, locations
YouTube                     Watch history, search history
Google Pay                  Transaction history
Android Backup              App data, Wi-Fi passwords, SMS (if enabled)
Google Fit                  Health/fitness data
Search History              All Google searches
```

**Legal request process for Google:**
1. Law enforcement submits request via LERS (Law Enforcement Request System)
2. Google verifies legal authority
3. Responds with data in specified format
4. Response time: 1-4 weeks (standard), expedited for emergencies

---

### 🔐 Cloud Forensic Challenges

| Challenge | Description | Mitigation |
|-----------|-------------|------------|
| Jurisdiction | Cloud servers may be in different country | MLAT treaties, bilateral agreements |
| Encryption | E2E encryption prevents provider access | Obtain device, extract keys locally |
| Ephemeral data | Auto-delete settings destroy evidence | Act quickly, preservation order |
| Multi-tenancy | Provider serves many customers | Minimal over-collection, targeted warrants |
| Chain of custody | Digital transfer from cloud | Hash data upon receipt, document transfer |
| Data completeness | Provider may not store all data | Know what each provider stores |

---

## 🧪 UNIT III — Questions & Answers

### Q-III-1: Explain the five levels of mobile data extraction with advantages and limitations.

**Answer:**

Mobile data extraction exists on a continuum of **invasiveness vs. data richness**. The five levels are:

**Level 1 — Manual Extraction:**
The investigator manually reads and records content visible on the device screen through photography or manual transcription. This requires no technical tools and is useful for quick observations, but is extremely slow, incomplete (only visible data), and cannot recover deleted content.

**Level 2 — Logical Acquisition:**
Data is extracted via the device's operating system APIs (ADB on Android, iTunes on iOS). This captures active user data — messages, contacts, photos — but misses deleted files and system-level data. No special hardware is needed but the device must be accessible.

**Level 3 — File System Acquisition:**
The entire live file system is extracted, including hidden system files and app private directories. This requires root access or a jailbreak. More data than logical but still no unallocated space (no deleted file recovery).

**Level 4 — Physical Acquisition:**
A bit-for-bit copy of the raw storage is made, including the OS partition, user data, cache, AND unallocated space. This is the gold standard for evidence recovery because it can recover deleted files, fragmented data, and prior app data. Requires exploits or hardware methods.

**Level 5 — JTAG / Chip-Off:**
Hardware-level extraction by directly interfacing with or removing the flash memory chip. Used as a last resort for locked, damaged, or encrypted devices. Provides the same raw binary dump as physical acquisition. Very invasive — chip-off may destroy the device.

---

### Q-III-2: How does SQLite database forensics help recover deleted messages? Describe the freelist mechanism.

**Answer:**

SQLite is the database format used by virtually all mobile apps on both Android and iOS to store structured data including messages, contacts, and app state.

**Normal deletion process in SQLite:**
When a user deletes a record (e.g., an SMS message), SQLite does NOT immediately overwrite the data. Instead:

1. The database row is deleted from the active B-tree structure
2. The page(s) containing the deleted row are added to the **freelist** — a chain of pages marked as available for reuse
3. The deleted data remains physically in those freelist pages until SQLite needs to write new data there

**Freelist structure:**
```
Page 1 (Database Header):
  - Contains pointer to first freelist trunk page
  - Contains total count of freelist pages

Freelist Trunk Page:
  - Byte 0-3: Pointer to next trunk page (0 if none)
  - Byte 4-7: Count of leaf page numbers
  - Bytes 8+: Array of leaf page numbers

Freelist Leaf Page:
  - Contains binary data from previously deleted records
  - Data survives until page is reused for new data
```

**Recovery approach:**
1. Open the .db file in a hex editor or forensic tool
2. Locate freelist pages via the header
3. Parse those pages manually or use automated tools
4. Extract patterns matching the deleted record format
5. Reconstruct the original row data

**Tools:** Autopsy SQLite Ingest Module, DB Browser for SQLite with forensic plugins, sqlparse forensic script.

**Limitation:** If the device has been heavily used after deletion, freelist pages may have been overwritten. TRIM on eMMC can proactively erase freed pages, reducing recovery window.

---

### Q-III-3: What is EXIF metadata? Explain its forensic significance with examples.

**Answer:**

EXIF (Exchangeable Image File Format) is a standard for storing technical metadata directly inside image files (JPEG, TIFF, HEIC) at the time of capture.

**Structure:** EXIF data is embedded in the APP1 segment of the JPEG file, organized into Image File Directories (IFDs) — IFD0 for general data, ExifIFD for camera settings, and GPS IFD for location.

**Forensic significance:**

*Proving when a photo was taken:* The `DateTimeOriginal` field records the exact time of capture including sub-second precision. This can corroborate or contradict an alibi.

*Proving where a photo was taken:* GPS coordinates can place a suspect at the scene of a crime. Coordinates are stored as degrees/minutes/seconds with reference (N/S/E/W).

*Proving which device was used:* Make, Model, and Serial Number fields identify the capturing device. Combined with device seizure, this can prove a specific phone took a specific photo.

*Detecting manipulation:* If `DateTime` (file modification time) differs significantly from `DateTimeOriginal` (capture time), the image may have been edited. Missing EXIF in a photo claiming to be taken by a camera is suspicious.

**Example case application:**
A suspect claims they were 200km away when a crime occurred. A photo found on their device shows `DateTimeOriginal: 2026:05:09 14:30:22` and `GPSLatitude: 29.6857 N, GPSLongitude: 76.9905 E` (placing them at the crime scene at the exact time of the incident). This EXIF data directly contradicts their alibi.

---

### Q-III-4: Explain cloud forensics challenges and the legal mechanisms for obtaining cloud data.

**Answer:**

**Cloud forensics challenges:**

*Technical challenges:*
- Data may be stored across multiple data centers in different countries
- End-to-end encryption (Signal, WhatsApp E2E, iCloud ADP) prevents provider from accessing content
- Data may be ephemeral (auto-delete features, Snapchat, etc.)
- Logs and access records may not be retained long enough
- Multi-tenancy means investigators must be precise to avoid over-collection

*Legal challenges:*
- Cloud providers operate under the laws of their home jurisdiction
- A US provider's data about an Indian user is governed by US law, requiring cooperation
- GDPR in Europe creates conflicts with some countries' legal process requirements
- Real-time interception requires different authorization than retrospective access to stored records

**Legal mechanisms:**

*1. Voluntary disclosure:* Emergency situations; providers may voluntarily provide limited data to prevent imminent harm.

*2. Subpoena (US):* Compels production of basic subscriber information and billing records. Lower threshold.

*3. Court Order (18 U.S.C. § 2703(d)):* For non-content data like metadata, traffic records.

*4. Search Warrant:* Required for content of communications under ECPA in the US. Highest threshold.

*5. Mutual Legal Assistance Treaties (MLATs):* Formal international cooperation agreements between countries. Slow (months) but legally robust.

*6. CLOUD Act (2018):* US legislation allowing direct law enforcement access to data stored abroad by US-based providers; also allows foreign governments to negotiate bilateral agreements for direct access.

*7. Preservation Request:* Asks the provider to preserve specific data pending formal legal process. Prevents deletion while warrant is obtained.

---

# ═══════════════════════════════════════════════════════════════
# UNIT IV — MOBILE DEVICE SECURITY
# ═══════════════════════════════════════════════════════════════

---

## 📚 UNIT IV — Table of Contents

| # | Topic |
|---|-------|
| 4.1 | Mobile Device Architecture and Storage Systems (Deep Dive) |
| 4.2 | Mobile Device Vulnerabilities and Threats |
| 4.3 | Common Cyber Threats: Malware — Types, Analysis, Impact |
| 4.4 | Cryptography — Fundamentals and Methods |
| 4.5 | Anti-Forensics Techniques |
| 4.6 | Firewalls and Intrusion Detection Systems |
| 4.7 | Mobile Device Security Best Practices |
| 4.8 | Incident Response and Digital Forensics |
| 4.9 | Mobile Network Security |
| 4.10 | SIM Card Forensics and Cellular Security |
| 4.11 | Mobile Payment Security |
| 4.12 | Wi-Fi Security |
| 4.13 | Unit IV Q&A |

---

## 4.1 MOBILE DEVICE ARCHITECTURE AND STORAGE SYSTEMS (Deep Dive)

### 🏗️ Complete Mobile Device Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              COMPLETE MOBILE DEVICE ARCHITECTURE                 │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    USER INTERFACE LAYER                   │   │
│  │  Touchscreen · Display · Microphone · Speaker · Camera   │   │
│  └───────────────────────────────┬─────────────────────────┘   │
│                                  │                              │
│  ┌───────────────────────────────▼─────────────────────────┐   │
│  │                   APPLICATION LAYER                       │   │
│  │  User Apps · System Apps · Services · Widgets            │   │
│  └───────────────────────────────┬─────────────────────────┘   │
│                                  │                              │
│  ┌───────────────────────────────▼─────────────────────────┐   │
│  │                 MIDDLEWARE / FRAMEWORK LAYER             │   │
│  │  Android: ART/Dalvik VM · Java APIs · Native Libraries   │   │
│  │  iOS: Core OS · Core Services · Media · Cocoa Touch      │   │
│  └───────────────────────────────┬─────────────────────────┘   │
│                                  │                              │
│  ┌───────────────────────────────▼─────────────────────────┐   │
│  │                    KERNEL LAYER                           │   │
│  │  Linux Kernel (Android) · XNU Kernel (iOS)               │   │
│  │  Process Management · Memory Management · File System     │   │
│  │  Device Drivers · Network Stack · Security Module         │   │
│  └───────────────────────────────┬─────────────────────────┘   │
│                                  │                              │
│  ┌───────────────────────────────▼─────────────────────────┐   │
│  │                   HARDWARE LAYER                          │   │
│  │                                                          │   │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │   │
│  │  │  SoC    │  │  RAM     │  │  Flash   │  │  Secure │  │   │
│  │  │(CPU+GPU │  │(4-16 GB) │  │  Storage │  │ Element │  │   │
│  │  │+NPU+DSP)│  │  LPDDR5  │  │(eMMC/UFS)│  │(TEE/SE) │  │   │
│  │  └─────────┘  └──────────┘  └──────────┘  └─────────┘  │   │
│  │                                                          │   │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │   │
│  │  │Cellular │  │  Wi-Fi   │  │Bluetooth │  │   GPS   │  │   │
│  │  │ Modem   │  │  Chip    │  │  Chip    │  │  Chip   │  │   │
│  │  └─────────┘  └──────────┘  └──────────┘  └─────────┘  │   │
│  │                                                          │   │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │   │
│  │  │  NFC    │  │   IMU    │  │ Biometric│  │ Battery │  │   │
│  │  │  Chip   │  │(Accel/  │  │(Finger-  │  │ + PMIC  │  │   │
│  │  │         │  │ Gyro)   │  │print/FaceID│ │         │  │   │
│  │  └─────────┘  └──────────┘  └──────────┘  └─────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

### 💾 Storage System Deep Dive

#### NAND Flash Memory Architecture

NAND flash is the dominant storage technology in mobile devices. Understanding its structure is essential for forensic analysis.

```
NAND FLASH HIERARCHY:

DEVICE (128 GB chip)
  │
  ├── PLANE 0 (Parallel operation plane)
  │     ├── BLOCK 0 (smallest erasable unit — 128KB - 4MB)
  │     │     ├── PAGE 0 (smallest R/W unit — 2KB - 16KB)
  │     │     │     ├── Main Area (data: 2048 bytes typically)
  │     │     │     └── Spare Area (OOB: 64 bytes — ECC, metadata)
  │     │     ├── PAGE 1
  │     │     ├── PAGE 2
  │     │     └── ... (64-256 pages per block)
  │     ├── BLOCK 1
  │     └── ... (thousands of blocks per plane)
  │
  └── PLANE 1

CRITICAL FORENSIC RULES:
  ✓ Pages can be WRITTEN individually
  ✗ Pages CANNOT be erased individually — whole BLOCK must erase
  ✓ Blocks can be erased in ~2ms
  ✗ Frequent erase degrades flash (P/E cycle limit: 1,000-10,000 MLC)
```

#### Flash Translation Layer (FTL)

The FTL is firmware in the storage controller that makes NAND flash behave like a traditional block device (HDD-like interface) — hiding the complexity of pages/blocks/planes.

```
┌─────────────────────────────────────────────────────────────┐
│                FLASH TRANSLATION LAYER (FTL)                 │
│                                                             │
│  OS/Filesystem sees:          FTL manages:                  │
│  LBA 0 → LBA N               Physical flash pages          │
│  (Logical Block Addresses)    (complex geometry)            │
│                                                             │
│  Write Request: LBA 100                                     │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ FTL Mapping Table:                                   │  │
│  │  LBA 100 → Physical Page 5,234                      │  │
│  │  LBA 101 → Physical Page 5,235                      │  │
│  │  LBA 200 → Physical Page 8,001                      │  │
│  │  (Dynamic — changes as pages wear out)               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  WRITE FLOW (Out-of-Place Update):                          │
│  1. Find a FREE page (e.g., Page 9,000)                    │
│  2. Write new data to Page 9,000                           │
│  3. Mark old Page 5,234 as STALE (not immediately erased)  │
│  4. Update mapping: LBA 100 → Page 9,000                   │
│                                                             │
│  STALE PAGES = FORENSIC GOLD!                              │
│  Old data survives in stale pages until garbage collection  │
│  → This is how deleted data can be recovered               │
└─────────────────────────────────────────────────────────────┘
```

#### Storage Types Comparison

```
┌──────────────────────────────────────────────────────────────┐
│            MOBILE STORAGE TYPES COMPARISON                    │
├───────────────┬────────────┬────────────┬────────────────────┤
│ Feature       │  eMMC 5.1  │  UFS 3.1   │ UFS 4.0 (latest)   │
├───────────────┼────────────┼────────────┼────────────────────┤
│ Interface     │ Parallel   │ Serial LVDS│ Serial LVDS        │
│ Lanes         │ 8 parallel │ 2 lanes    │ 2 lanes (faster)   │
│ Max Read      │ ~400 MB/s  │ ~2100 MB/s │ ~4200 MB/s         │
│ Max Write     │ ~250 MB/s  │ ~1200 MB/s │ ~2800 MB/s         │
│ Command Queue │ Single     │32 per lane │ 32 per lane        │
│ Power         │ Higher     │ Lower      │ Lowest             │
│ Use case      │ Budget     │ Mid/high   │ Flagship 2024+     │
│               │ phones     │ phones     │ phones             │
│ Forensic      │ Easier     │ More       │ Most complex       │
│ difficulty    │            │ complex    │                    │
└───────────────┴────────────┴────────────┴────────────────────┘
```

#### Android Partition Structure

```
ANDROID PARTITION MAP (Typical Flagship):

┌────────────────────────────────────────────────────────────┐
│                  ANDROID STORAGE LAYOUT                     │
│                                                            │
│  Physical NAND Flash (e.g., 256 GB)                       │
│                                                            │
│  ┌──────┐ bootloader — loads OS, CANNOT be bypassed       │
│  │ boot │ without exploit                                  │
│  ├──────┤                                                  │
│  │ dtbo │ Device Tree Blob (hardware descriptions)        │
│  ├──────┤                                                  │
│  │ boot │ Kernel + initramfs (Linux kernel)               │
│  ├──────┤                                                  │
│  │vbmeta│ Verified Boot metadata (SHA-256 chain)          │
│  ├──────┤                                                  │
│  │system│ Android OS (read-only) — /system mount point    │
│  │      │ Contains: framework, system apps, libs          │
│  ├──────┤                                                  │
│  │vendor│ Manufacturer-specific drivers and HAL           │
│  ├──────┤                                                  │
│  │ data │ ★ PRIMARY FORENSIC TARGET ★                    │
│  │      │ /data/data/[app packages]/     (app private)   │
│  │      │ /data/media/0/                 (user files)    │
│  │      │ /data/system/                  (system state)  │
│  │      │ /data/user/0/                  (user profile)  │
│  │      │ Encrypted with FBE/FDE                         │
│  ├──────┤                                                  │
│  │cache │ OTA update staging, temporary data              │
│  ├──────┤                                                  │
│  │ misc │ Boot mode, recovery flags                       │
│  ├──────┤                                                  │
│  │efs   │ IMEI, radio calibration data (CRITICAL!)        │
│  └──────┘                                                  │
└────────────────────────────────────────────────────────────┘
```

**⚠️ The EFS partition is critically important:** It contains the IMEI and radio calibration data. Corrupting it can permanently disable the device's cellular capability. Never write to EFS.

---

### 🔐 Trusted Execution Environment (TEE) and Secure Enclave

```
┌──────────────────────────────────────────────────────────────┐
│              TRUSTED EXECUTION ENVIRONMENT (TEE)              │
│                                                              │
│  Normal World                    Secure World               │
│  (Rich OS - Android/iOS)         (TEE - TrustZone)         │
│  ┌────────────────────┐          ┌──────────────────────┐   │
│  │  User Apps         │          │  Trusted Apps (TAs)  │   │
│  │  Android OS        │◄────────►│  Keymaster TA        │   │
│  │  Linux Kernel      │  SMC     │  Fingerprint TA      │   │
│  │                    │ syscall  │  DRM TA              │   │
│  └────────────────────┘          │  Secure Storage TA   │   │
│                                  └──────────────────────┘   │
│                                                              │
│  SEPARATION enforced by ARM TrustZone hardware              │
│  Normal World CANNOT read Secure World memory               │
│  Even root in Android CANNOT access TEE secrets             │
│                                                              │
│  FORENSIC IMPACT:                                            │
│  • Device encryption keys stored in TEE                     │
│  • Biometric templates stored in TEE                        │
│  • Cannot brute-force PIN without TEE cooperation           │
│  • GrayKey/Cellebrite exploits target TEE or kernel        │
└──────────────────────────────────────────────────────────────┘
```

---

## 4.2 MOBILE DEVICE VULNERABILITIES AND THREATS

### 🔓 Vulnerability Categories

```
MOBILE VULNERABILITY TAXONOMY:

├── HARDWARE VULNERABILITIES
│     ├── Side-channel attacks (power analysis, EM emissions)
│     ├── Physical access attacks (JTAG, chip-off)
│     ├── BadUSB / Juice-jacking (malicious chargers)
│     └── Fault injection (voltage glitching, laser)
│
├── OS / KERNEL VULNERABILITIES
│     ├── Privilege escalation (root exploits)
│     ├── Kernel memory corruption (use-after-free, heap overflow)
│     ├── Race conditions in system calls
│     └── Bootloader vulnerabilities
│
├── APPLICATION VULNERABILITIES
│     ├── Insecure data storage (unencrypted SQLite, logs)
│     ├── Insecure communication (HTTP, weak TLS)
│     ├── Broken authentication (weak PIN, no 2FA)
│     ├── Code injection (SQL injection, intent injection)
│     ├── Improper session management
│     └── Third-party library vulnerabilities
│
├── NETWORK VULNERABILITIES
│     ├── Man-in-the-Middle (MitM) on insecure Wi-Fi
│     ├── Rogue access points / Evil Twin attacks
│     ├── SSL/TLS downgrade attacks
│     ├── SS7 protocol vulnerabilities (cellular)
│     └── DNS spoofing / cache poisoning
│
└── USER/SOCIAL VULNERABILITIES
      ├── Phishing (smishing, vishing)
      ├── Social engineering
      ├── Shoulder surfing
      └── SIM swapping
```

---

## 4.3 COMMON CYBER THREATS: MALWARE — TYPES, ANALYSIS, IMPACT

### 🦠 What Is Mobile Malware?

Mobile malware is **malicious software** designed to execute on mobile devices without the user's knowledge or consent, with objectives ranging from data theft to financial fraud to device control.

> 📕 **Bhardwaj & Kaushik (2023), §11.1:** "Mobile malware represents one of the fastest-growing threat vectors in cybersecurity, driven by the volume of sensitive data carried on mobile devices and the relative ease of distribution through unofficial app stores and phishing."

---

### 🗂️ Malware Classification

#### 1. Viruses
A virus is malicious code that **attaches itself to a legitimate program** and replicates when that program runs. On mobile, this typically targets app packages.

```
VIRUS LIFECYCLE:
  Dormant → Triggered → Replicating → Active Damage
  
  1. Dormant: Virus code embedded in app, waiting
  2. Triggered: User opens app, specific date, specific action
  3. Replicating: Copies itself to other apps/storage
  4. Active: Payload executes (data theft, display damage, etc.)
```

#### 2. Worms
A worm is **self-propagating malware** that spreads without user interaction, using network connections.

```
WORM PROPAGATION PATHS:

Device A (infected)
    │
    ├── Bluetooth worm → Scans nearby Bluetooth devices
    │                    → Sends exploit payload
    │                    → Device B gets infected
    │
    ├── MMS worm → Sends malicious MMS to contact list
    │              → Recipient opens → infected
    │
    └── Wi-Fi worm → Scans local network
                     → Exploits vulnerable devices
                     → Self-replicates
```

#### 3. Trojans
A Trojan appears to be **legitimate software** but contains hidden malicious functionality. The most common mobile malware type.

**Banking Trojan Example (Cerberus/Alien):**
```
User downloads "FlashlightPro" from unofficial store
          │
          ▼
App requests permissions:
  • Accessibility Service ← KEY: enables overlay attacks
  • SMS read/write
  • Device administrator
          │
          ▼
Trojan activities:
  • Monitors running apps
  • Detects banking app launch
  • Displays fake login overlay (identical to real bank UI)
  • User types credentials into fake overlay
  • Credentials sent to C&C (Command and Control) server
  • Intercepted 2FA SMS forwarded to attacker
  • Bank account emptied
```

#### 4. Ransomware
Ransomware **encrypts the device or its data** and demands payment for decryption.

```
MOBILE RANSOMWARE FLOW:

┌──────────────────────────────────────────────────────────┐
│                  RANSOMWARE ATTACK CHAIN                  │
│                                                          │
│  1. DELIVERY                                             │
│     Phishing SMS, malicious APK, trojanized app          │
│                 │                                        │
│                 ▼                                        │
│  2. INSTALLATION                                         │
│     APK sideloaded, requests device admin rights        │
│                 │                                        │
│                 ▼                                        │
│  3. KEY GENERATION                                       │
│     Generates AES-256 key locally                       │
│     Sends public key to C&C server                      │
│     Private key stays on server (attacker holds it)     │
│                 │                                        │
│                 ▼                                        │
│  4. ENCRYPTION                                           │
│     Encrypts: /sdcard (photos, docs, downloads)         │
│     May encrypt: contacts, messages databases           │
│     Locks screen with PIN controlled by attacker        │
│                 │                                        │
│  5. RANSOM DEMAND │                                      │
│     Message displayed: "Pay 0.5 BTC to [address]"       │
│     Timer counts down (threat: files deleted at 0)      │
│                 │                                        │
│  6. PAYMENT/RECOVERY                                     │
│     With payment: decryption key sent                   │
│     Without: files permanently encrypted                │
└──────────────────────────────────────────────────────────┘
```

#### 5. Spyware

Spyware **silently monitors and exfiltrates user data** without consent. It includes commercial stalkerware and nation-state tools.

```
SPYWARE DATA COLLECTION CAPABILITIES:

┌──────────────────────────────────────────────────────────┐
│              SPYWARE COLLECTION MATRIX                    │
├─────────────────────────┬────────────────────────────────┤
│ Data Type               │ Method                         │
├─────────────────────────┼────────────────────────────────┤
│ SMS/MMS messages        │ Content Provider hook          │
├─────────────────────────┼────────────────────────────────┤
│ Calls (metadata)        │ PhoneStateListener             │
├─────────────────────────┼────────────────────────────────┤
│ Calls (audio)           │ MediaRecorder on phone calls   │
├─────────────────────────┼────────────────────────────────┤
│ GPS location            │ LocationManager (real-time)    │
├─────────────────────────┼────────────────────────────────┤
│ WhatsApp messages       │ Accessibility Service hook     │
├─────────────────────────┼────────────────────────────────┤
│ Email content           │ IMAP hook or screen reading    │
├─────────────────────────┼────────────────────────────────┤
│ Camera photos           │ Silent photo via Camera API   │
├─────────────────────────┼────────────────────────────────┤
│ Microphone audio        │ Background MediaRecorder       │
├─────────────────────────┼────────────────────────────────┤
│ Keystrokes              │ InputMethodService hook        │
├─────────────────────────┼────────────────────────────────┤
│ Screen content          │ Screenshot API / Accessibility │
├─────────────────────────┼────────────────────────────────┤
│ Browser history         │ ContentProvider access         │
└─────────────────────────┴────────────────────────────────┘
```

**Pegasus Spyware (NSO Group) — Case Study:**
Pegasus is a sophisticated nation-state spyware capable of "zero-click" infection (no user interaction needed).

- **Zero-click attack:** Sends malformed iMessage, WhatsApp call, or SMS containing exploit payload
- **Kernel exploit:** Escalates to kernel level, bypassing all sandboxing
- **Persistence:** Survives reboots through boot partition modification
- **Detection:** MVT (Mobile Verification Toolkit) can detect Pegasus IOCs (Indicators of Compromise)
- **Target:** Journalists, activists, politicians, government officials

#### 6. Adware
Displays **intrusive advertisements**, collects browsing behavior, may redirect traffic.

#### 7. Cryptomining Malware
Uses device's CPU/GPU to **mine cryptocurrency** for attacker.

#### 8. Rootkits
Hides malware and attacker activities from the OS and user by **modifying kernel components**.

```
ROOTKIT DETECTION AVOIDANCE:
  Normal malware scan: Asks OS "what files exist?" → OS shows all files
  Rootkit: Hooks OS file listing → Hides malicious files from query
  
  Detection bypass:
  • Boot from external image
  • Hardware-level inspection (JTAG)
  • Behavioral analysis (unexpected network traffic)
```

---

### 🔍 Malware Analysis Methods

#### Static Analysis
Analyze the malware code **without executing it**.

```
STATIC ANALYSIS WORKFLOW:

1. DISASSEMBLY
   APK → DEX → SMALI (bytecode)
   Tools: jadx, apktool, dex2jar
   
2. CODE REVIEW
   Look for:
   • Suspicious permissions in AndroidManifest.xml
   • Hardcoded C&C IP addresses / domains
   • Encryption routines
   • Anti-analysis code (emulator detection)
   • Obfuscated strings (base64, XOR)

3. STRING EXTRACTION
   Tools: strings, JADX, grep
   Look for: IP addresses, URLs, API keys, commands

4. SIGNATURE ANALYSIS
   Hash against VirusTotal (70+ AV engines)
   YARA rules matching

EXAMPLE (AndroidManifest.xml red flags):
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
← All four together = very likely spyware/banking trojan
```

#### Dynamic Analysis
**Execute** the malware in a controlled environment and observe behavior.

```
DYNAMIC ANALYSIS SANDBOX SETUP:

Physical or Emulated Device (isolated network)
         │
         ▼
     Install Malware
         │
         ├── Network Traffic Monitor (Wireshark, mitmproxy)
         │     → Capture all outbound connections
         │     → Identify C&C servers
         │
         ├── System Call Tracer (strace, ltrace)
         │     → Log every OS call made by malware
         │
         ├── File System Monitor (inotify)
         │     → Track file creation, modification, deletion
         │
         ├── Log Capture (logcat on Android)
         │     → Application logs, crash reports, debug output
         │
         └── Memory Dump
               → Capture decrypted code (if malware is packed)

Tools: Cuckoo Sandbox, Android Tamer, MobSF (Mobile Security Framework)
```

---

## 4.4 CRYPTOGRAPHY — FUNDAMENTALS AND METHODS

### 🔐 What Is Cryptography?

Cryptography is the science of **securing communication and data** by transforming readable information (plaintext) into an unreadable form (ciphertext) using mathematical algorithms and keys.

```
BASIC CRYPTOGRAPHIC MODEL:

Plaintext ──[Encryption Algorithm + Key]──► Ciphertext
              (Ek(P) = C)

Ciphertext ──[Decryption Algorithm + Key]──► Plaintext
              (Dk(C) = P)
```

---

### 📚 Core Cryptographic Concepts

#### 1. Symmetric Key Cryptography

One **shared secret key** is used for both encryption and decryption.

```
SYMMETRIC ENCRYPTION:

Alice                              Bob
  │                                 │
  │  Plaintext: "Attack at dawn"    │
  │      + Secret Key: K            │
  │           │                     │
  │      ┌────▼────┐                │
  │      │   AES   │                │
  │      │Encrypt  │                │
  │      └────┬────┘                │
  │           │                     │
  │  Ciphertext: X4#@%K9...  ──────►│
  │                                 │
  │                          ┌──────▼──────┐
  │                          │     AES     │
  │                          │   Decrypt   │
  │                          │  + Key: K   │
  │                          └──────┬──────┘
  │                                 │
  │                     Plaintext: "Attack at dawn"

KEY PROBLEM: How do Alice and Bob securely share K?
→ Solution: Asymmetric cryptography (see below)
```

**Common Symmetric Algorithms:**

| Algorithm | Key Size | Block Size | Status |
|-----------|----------|------------|--------|
| DES | 56-bit | 64-bit | Broken (1998) |
| 3DES | 112/168-bit | 64-bit | Deprecated |
| AES-128 | 128-bit | 128-bit | Secure |
| AES-256 | 256-bit | 128-bit | Very secure (current standard) |
| ChaCha20 | 256-bit | Stream | Secure, fast on mobile |
| Blowfish | 32-448-bit | 64-bit | Older, still used |

**AES Operation Modes:**

```
MODE: ECB (Electronic Codebook) — NEVER USE FOR IMAGES
  Same plaintext block → Same ciphertext block
  Reveals patterns in data (see "ECB penguin" example)

MODE: CBC (Cipher Block Chaining)
  Each block XOR'd with previous ciphertext before encryption
  Requires IV (Initialization Vector)
  Most common for disk encryption

MODE: CTR (Counter Mode)
  Converts block cipher to stream cipher
  Allows random access (good for databases)
  
MODE: GCM (Galois/Counter Mode)
  CTR + authentication tag
  Provides both encryption AND integrity verification
  Used in TLS 1.3, Android FBE
  
┌─────────────────────────────────────────────────────┐
│  AES-GCM = AES-256 in GCM mode                     │
│  = Confidentiality + Integrity + Authenticity       │
│  = AEAD (Authenticated Encryption with Assoc. Data) │
│  = Used in: Android FBE, WhatsApp, Signal, TLS 1.3  │
└─────────────────────────────────────────────────────┘
```

---

#### 2. Asymmetric Key Cryptography (Public Key Cryptography)

Two mathematically related keys: **public key** (shared openly) and **private key** (secret). What one encrypts, only the other can decrypt.

```
ASYMMETRIC KEY PAIR:

Key Generation:
  → Generate large prime numbers p, q
  → Compute n = p × q (RSA modulus)
  → Public key = (n, e)   [share freely]
  → Private key = (n, d)  [keep secret]
  
  Mathematical relationship: e × d ≡ 1 (mod φ(n))
  Security: Factoring n back into p,q is computationally infeasible
            (RSA-2048 would take longer than age of universe to break)

ENCRYPTION FLOW:
  Alice wants to send secure message to Bob
  
  1. Bob's public key: publicly available
  2. Alice encrypts with Bob's PUBLIC key
  3. Only Bob's PRIVATE key can decrypt it
  
  Alice          →→→→→→→→→→→→→→→→→→→→→→→→→→→        Bob
  "secret msg"  Encrypt with Bob's public key   Ciphertext
                                                     │
                                              Decrypt with
                                              Bob's private key
                                                     │
                                              "secret msg"

DIGITAL SIGNATURE (reverse):
  Bob signs with PRIVATE key → Anyone verifies with Bob's PUBLIC key
  → Proves the message came from Bob (non-repudiation)
```

**Common Asymmetric Algorithms:**

| Algorithm | Key Type | Key Size | Use |
|-----------|----------|----------|-----|
| RSA | Integer factorization | 2048-4096 bit | Encryption, signatures |
| ECC (Elliptic Curve) | Elliptic curves | 256-521 bit | TLS, mobile crypto |
| ECDSA | ECC-based signature | 256-384 bit | Digital signatures |
| ECDH | Key exchange | 256-384 bit | TLS key exchange |
| Ed25519 | EdDSA | 256-bit | Modern signatures |
| DSA | Discrete log | 1024-3072 bit | Legacy signatures |

**Why ECC is preferred for mobile:**
- Equivalent security to RSA with much smaller key size
- RSA-3072 ≈ ECC-256 in security strength
- Faster operations → less battery drain → critical for mobile

---

#### 3. Hash Functions

A hash function maps input data of **any size** to a **fixed-size output** (digest). It is a **one-way function** — the input cannot be recovered from the hash.

```
HASH FUNCTION PROPERTIES:

Input: "Hello World"  ──[SHA-256]──► a591a6d40bf420404a011733cfb7b190...
Input: "hello world"  ──[SHA-256]──► b94d27b9934d3e08a52e52d7da7dabfa...
                                      ↑ Completely different! (Avalanche effect)

Input: "Hello World"  ──[SHA-256]──► a591a6d40bf420404a011733cfb7b190...
                                      ↑ Same input ALWAYS same output (deterministic)

PROPERTIES:
  1. Deterministic: Same input → Same output always
  2. One-way: Cannot reverse hash to get input
  3. Avalanche effect: Small input change → completely different output
  4. Collision resistant: Infeasible to find two inputs with same hash
  5. Fixed output: SHA-256 always 256 bits regardless of input size

HASH ALGORITHM COMPARISON:
  MD5:    128-bit, BROKEN (collision attacks found)
  SHA-1:  160-bit, BROKEN (Google SHAttered attack, 2017)
  SHA-256: 256-bit, SECURE (current standard)
  SHA-3:  256/512-bit, SECURE (different algorithm family)
  bcrypt: Variable, designed for passwords (slow + salted)
  PBKDF2: Variable, key derivation from passwords
```

**Forensic applications of hashing:**
- Evidence integrity (hash image before/after = same → unmodified)
- Known file identification (NSRL database of known-good hashes)
- CSAM detection (PhotoDNA perceptual hash)
- Password cracking (compare hash to dictionary)

---

#### 4. Key Exchange — Diffie-Hellman

Diffie-Hellman (DH) allows two parties to agree on a **shared secret over an insecure channel** without ever transmitting the secret itself.

```
DIFFIE-HELLMAN KEY EXCHANGE:

Public parameters: g=5, p=23 (very small for illustration; real: 2048+ bit)

Alice                              Bob
  │                                 │
  │ Chooses private: a=6            │ Chooses private: b=15
  │                                 │
  │ Computes: A = g^a mod p         │ Computes: B = g^b mod p
  │         = 5^6 mod 23            │         = 5^15 mod 23
  │         = 8                     │         = 19
  │                                 │
  │ Sends A=8 ──────────────────────►│
  │◄─────────────────────────── B=19│
  │                                 │
  │ Computes shared secret:         │ Computes shared secret:
  │ s = B^a mod p                   │ s = A^b mod p
  │   = 19^6 mod 23                 │   = 8^15 mod 23
  │   = 2                           │   = 2     ← SAME!
  │                                 │
  Shared secret = 2 (never transmitted!)
  Attacker sees only: g=5, p=23, A=8, B=19
  Cannot compute secret without solving discrete log problem
  
ECDH = Elliptic Curve Diffie-Hellman (modern mobile version)
  → Same concept, ECC math → smaller keys, faster
  → Used in: Signal, WhatsApp, TLS 1.3
```

---

#### 5. Digital Certificates and PKI

```
PUBLIC KEY INFRASTRUCTURE (PKI):

Certificate Authority (CA)
  (Trusted third party: DigiCert, Let's Encrypt, etc.)
  │
  │ Signs (with CA private key)
  │
  ▼
Digital Certificate (X.509 format)
  ┌────────────────────────────────────┐
  │ Version: 3                         │
  │ Serial: 1A:2B:3C...                │
  │ Subject: CN=www.bank.com           │
  │ Issuer: CN=DigiCert Global Root CA │
  │ Valid From: 2026-01-01             │
  │ Valid Until: 2027-01-01            │
  │ Public Key: [2048-bit RSA key]     │
  │ Signature: [CA's digital sig]      │
  └────────────────────────────────────┘
  
When you visit https://bank.com:
  1. Bank sends its certificate
  2. Your phone verifies CA's signature (CA's public key is pre-installed)
  3. Verified → use bank's public key for TLS session
  4. Encrypted channel established
  
FORENSIC SIGNIFICANCE:
  • Certificate pinning bypassed? → Possible MitM attack
  • Expired/self-signed certificate accepted? → App vulnerability
  • Rogue CA installed? → Device compromised
```

---

#### 6. End-to-End Encryption (E2EE) — Signal Protocol

```
SIGNAL PROTOCOL (used by Signal, WhatsApp, iMessage):

Components:
  1. X3DH (Extended Triple Diffie-Hellman) — Initial key agreement
  2. Double Ratchet Algorithm — Per-message key derivation
  
DOUBLE RATCHET PROPERTY:
  Message 1: Key K1 derived → Encrypted with K1
  Message 2: Key K2 derived from K1 → Encrypted with K2
  ...
  
  If attacker compromises K3:
  → Can decrypt message 3
  → CANNOT decrypt messages 1, 2 (forward secrecy)
  → CANNOT decrypt messages 4,5... (break-in recovery)
  
  This property = Perfect Forward Secrecy (PFS)

FORENSIC IMPLICATION:
  • E2E encrypted messages cannot be obtained from server
  • Only accessible on unlocked device with decryption keys
  • Cloud backup (iCloud/Google) may contain unencrypted copy
    (unless E2E backup is enabled — WhatsApp now offers this)
```

---

## 4.5 ANTI-FORENSICS TECHNIQUES

### 🚫 What Are Anti-Forensics?

Anti-forensics encompasses techniques used to **hinder, frustrate, or prevent** the recovery of digital evidence by investigators.

> 📙 **Dejey (2018), §8.3:** "Anti-forensics is not merely the province of criminals — security professionals use the same techniques to test forensic tools and measure their effectiveness."

---

### 🗂️ Anti-Forensics Taxonomy

```
┌─────────────────────────────────────────────────────────────────┐
│                    ANTI-FORENSICS CATEGORIES                     │
│                                                                 │
│  ┌────────────────────┐   ┌────────────────────┐               │
│  │  DATA DESTRUCTION   │   │ DATA CONCEALMENT   │               │
│  │                    │   │                    │               │
│  │ • Factory reset    │   │ • Steganography    │               │
│  │ • Secure delete    │   │ • Encryption       │               │
│  │ • Overwrite tools  │   │ • Hidden volumes   │               │
│  │ • Physical destroy │   │ • Alternate streams│               │
│  └────────────────────┘   └────────────────────┘               │
│                                                                 │
│  ┌────────────────────┐   ┌────────────────────┐               │
│  │  TRAIL OBFUSCATION │   │ TOOL ATTACKS        │               │
│  │                    │   │                    │               │
│  │ • Log deletion     │   │ • Exploit forensic │               │
│  │ • Timestamp mod    │   │   tool bugs        │               │
│  │ • Metadata wiping  │   │ • Corrupt evidence │               │
│  │ • Anonymization    │   │   containers       │               │
│  │ • VPN/Tor          │   │ • Hash collisions  │               │
│  └────────────────────┘   └────────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

---

### 🔍 Detailed Anti-Forensics Methods

#### 1. Encryption as Anti-Forensics

Full Device Encryption (FDE/FBE) renders all data unreadable without the correct key.

```
ANDROID FILE-BASED ENCRYPTION (FBE):

Each file encrypted with unique key derived from:
  User credential (PIN/password/biometric)
  + Hardware-bound key (stored in TEE)
  + Per-file salt
  ↓
  File encryption key (AES-256-XTS)
  
Without user credential:
  → Hardware key alone CANNOT decrypt
  → TEE enforces attempt limit (10 attempts → wipe)
  → Brute force: 6-digit PIN = 1,000,000 combinations
    At TEE-limited 1 attempt/30 seconds → 
    1,000,000 / 2 per minute = ~500,000 minutes = ~347 days
    
FORENSIC BYPASS METHODS:
  • GrayKey: Exploits kernel vulnerability to bypass TEE
  • Cellebrite Premium: Vendor-specific exploits
  • Physical memory dump (if device is on and unlocked)
  • Cold boot attack (freezing RAM preserves keys briefly)
```

#### 2. Steganography

Hiding data **inside other data** — e.g., hiding a message inside an image.

```
IMAGE STEGANOGRAPHY (LSB Method):

Each pixel = 3 bytes (R, G, B)
R = 11001010  → change last bit (LSB) to 0 or 1
G = 10110111  → imperceptible to human eye
B = 01101101  → but each pixel hides 3 bits of secret data

Example: Hide letter 'A' (ASCII 65 = 01000001):
  Pixel 1 R: 1100101[0]  ← bit 0
  Pixel 1 G: 1011011[1]  ← bit 1
  Pixel 1 B: 0110110[0]  ← bit 0
  Pixel 2 R: 1001100[0]  ← bit 3
  Pixel 2 G: 0110101[0]  ← bit 4
  Pixel 2 B: 1010011[0]  ← bit 5
  Pixel 3 R: 1100001[0]  ← bit 6
  Pixel 3 G: 0010110[1]  ← bit 7
                           → 01000001 = 'A'

Detection methods:
  • Chi-square statistical analysis
  • RS (Regular-Singular) steganalysis
  • Machine learning classifiers
  • Visual inspection (subtle color banding)
```

#### 3. Data Wiping and Secure Deletion

```
DATA WIPING STANDARDS:

Standard        Passes  Pattern
──────────────  ──────  ─────────────────────────────────
DoD 5220.22-M    7      0s, 1s, random, 0s, 1s, random, verify
Gutmann          35     Patterns designed for various MFM/RLL
NIST 800-88      1      Zero overwrite (sufficient for flash)
Random           1-3    Random data (common on mobile)

MOBILE-SPECIFIC: Factory Reset
  Android < 6.0: Logical reset — data NOT overwritten → recoverable!
  Android 6.0+:  Encryption key deleted → data cryptographically erased
  iOS:            Always cryptographic erase (key deletion since iOS 3.x)
  
FORENSIC DETECTION:
  If user performed factory reset:
  • /data partition key deleted but NAND may contain old data
  • FTL stale pages may still contain old data
  • JTAG/Chip-off may recover pre-wipe data
  • Wear leveling means physical pages may not be overwritten
```

#### 4. Log Manipulation

```
ANDROID LOG SYSTEM:

logcat (in-memory ring buffer):
  Cleared on reboot
  App log injection possible (false events)

System logs (/data/system/):
  audit.log, events.log, syslog
  Can be deleted by root user
  
Forensic indicators of log tampering:
  • Timestamps with gaps (missing time periods)
  • Log file modification time newer than entries within
  • Inconsistency between multiple log sources
  • Unusually small log files (truncated)
```

#### 5. Anonymization and Obfuscation

```
PRIVACY TOOLS (Dual use — legitimate & anti-forensic):

VPN (Virtual Private Network):
  → Encrypts all traffic between device and VPN server
  → ISP/network sees only encrypted VPN tunnel
  → Forensic recovery: device-side traffic is pre-encryption
                        VPN logs require legal request to provider

Tor Network:
  Device → Entry Guard → Middle Relay → Exit Node → Server
  → Traffic encrypted at each hop
  → Each node knows only previous and next node
  → Attacker needs to control entry+exit to deanonymize
  → Slow (multi-hop latency)
  → Browser fingerprinting may deanonymize

Signal App:
  → E2E encrypted messages
  → Minimal metadata retained by Signal (only last connect time)
  → Sealed sender (hides sender identity even from Signal)
```

---

## 4.6 FIREWALLS AND INTRUSION DETECTION SYSTEMS

### 🔥 Firewalls

A firewall is a **network security device** (hardware or software) that monitors and controls incoming and outgoing network traffic based on predefined security rules.

```
FIREWALL ARCHITECTURE:

  Internet                              Internal Network
    │                                        │
    │        ┌─────────────────┐             │
    └────────►   FIREWALL       ├─────────────┘
             │                 │
             │  Rule Engine:   │
             │  ┌───────────┐  │
             │  │ Rule 1:   │  │
             │  │ ALLOW     │  │
             │  │ TCP 443   │  │
             │  ├───────────┤  │
             │  │ Rule 2:   │  │
             │  │ BLOCK     │  │
             │  │ UDP 53    │  │
             │  │ from EXT  │  │
             │  ├───────────┤  │
             │  │ Default:  │  │
             │  │ DENY ALL  │  │
             │  └───────────┘  │
             └─────────────────┘
```

**Types of Firewalls:**

| Type | OSI Layer | What It Inspects | Performance |
|------|----------|-----------------|------------|
| Packet Filter | Layer 3-4 | IP header, TCP/UDP ports | Very fast |
| Stateful Inspection | Layer 4 | Connection state tracking | Fast |
| Application Layer (WAF) | Layer 7 | Application protocol content | Slower |
| Next-Gen (NGFW) | Layer 7 | Deep packet inspection + threat intelligence | Slowest |
| Mobile MDM Firewall | Layer 4-7 | Per-app rules on mobile device | Device-based |

**Mobile Firewall Applications:**
- NetGuard (Android — no-root per-app firewall using VpnService)
- Little Snitch (iOS — network monitor)
- MDM-deployed firewalls (enterprise control of mobile traffic)

---

### 🚨 Intrusion Detection Systems (IDS)

An IDS monitors network or system activity for **malicious behavior or policy violations** and generates alerts.

```
IDS CLASSIFICATION:

┌─────────────────────────────────────────────────────────────┐
│                      IDS TAXONOMY                            │
│                                                             │
│  By Deployment:                                             │
│  ├── NIDS (Network IDS)  — Monitors network traffic        │
│  └── HIDS (Host IDS)     — Monitors single host/device     │
│                                                             │
│  By Detection Method:                                       │
│  ├── Signature-based                                        │
│  │     Matches against known attack patterns               │
│  │     ✓ Low false positives for known attacks            │
│  │     ✗ Cannot detect zero-day (unknown) attacks         │
│  │                                                         │
│  ├── Anomaly-based                                          │
│  │     Establishes baseline, flags deviations             │
│  │     ✓ Can detect novel attacks                         │
│  │     ✗ Higher false positive rate                       │
│  │                                                         │
│  └── Hybrid (combines both)                                 │
│        Used in modern enterprise systems                    │
└─────────────────────────────────────────────────────────────┘
```

**IDS vs IPS:**

| Feature | IDS (Intrusion Detection) | IPS (Intrusion Prevention) |
|---------|--------------------------|---------------------------|
| Action | Monitor + Alert | Monitor + Block + Alert |
| Placement | Out-of-band (mirror port) | Inline (in traffic path) |
| Risk | False negatives miss attacks | False positives block legit traffic |
| Performance impact | Low | Higher |

**Mobile-Context IDS:**
- **MTD (Mobile Threat Defense):** Lookout, Zimperium zIPS, CrowdStrike Falcon for Mobile
- Monitors: App behavior, network traffic, device configuration changes
- Detects: Malware, MitM attacks, device compromise, policy violations

---

## 4.7 MOBILE DEVICE SECURITY BEST PRACTICES

```
SECURITY HARDENING CHECKLIST:

DEVICE LEVEL:
  ✓ Enable full device encryption (enabled by default on Android 7+, iOS 8+)
  ✓ Use strong authentication: 6+ digit PIN, or alphanumeric password
  ✓ Enable biometric (fingerprint/face) as convenience only (not security)
  ✓ Set auto-lock timeout: 30 seconds to 1 minute
  ✓ Enable remote wipe (Find My iPhone / Find My Device)
  ✓ Keep OS updated (patch security vulnerabilities)
  ✓ Disable developer options and USB debugging
  ✓ Do not root/jailbreak (removes security boundaries)

APP LEVEL:
  ✓ Install apps only from official stores (Play Store, App Store)
  ✓ Review permissions before granting (principle of least privilege)
  ✓ Keep apps updated (security patches)
  ✓ Remove unused apps
  ✓ Use app-lock for sensitive apps (banking, email)
  ✓ Enable 2FA on all important accounts

NETWORK LEVEL:
  ✓ Avoid public Wi-Fi for sensitive transactions
  ✓ Use VPN on untrusted networks
  ✓ Verify SSL certificates (look for HTTPS lock)
  ✓ Disable Wi-Fi auto-connect to open networks
  ✓ Disable Bluetooth when not in use

BACKUP AND RECOVERY:
  ✓ Enable encrypted cloud backup
  ✓ Test restore procedure periodically
  ✓ Keep local encrypted backup as secondary
```

---

## 4.8 INCIDENT RESPONSE AND DIGITAL FORENSICS

### 🚨 Mobile Incident Response Framework

```
MOBILE INCIDENT RESPONSE LIFECYCLE (NIST SP 800-61 Adapted):

PHASE 1: PREPARATION
  • Deploy MDM with remote wipe capability
  • Establish forensic lab and tool inventory
  • Train response team
  • Define escalation procedures
  • Prepare legal templates (warrant forms, consent forms)
  
PHASE 2: DETECTION AND ANALYSIS
  • Identify incident indicators:
    - Unusual data usage
    - Unknown apps installed
    - Battery drain anomaly
    - Performance degradation
    - Unauthorized account access
  • Classify severity (P1-P4)
  • Assign incident handler
  
PHASE 3: CONTAINMENT
  SHORT-TERM: Isolate device (airplane mode / Faraday)
  LONG-TERM:  MDM policy push, remote wipe if needed
  
PHASE 4: ERADICATION
  • Remove malware
  • Factory reset if necessary
  • Patch vulnerability exploited
  
PHASE 5: RECOVERY
  • Restore from clean backup
  • Monitor for recurrence
  • Confirm eradication
  
PHASE 6: POST-INCIDENT ACTIVITY
  • Write incident report
  • Update security policies
  • Conduct lessons-learned review
  • Improve detection capabilities
```

---

## 4.9 MOBILE NETWORK SECURITY

### 📡 Mobile Network Architecture and Protocols

```
CELLULAR NETWORK GENERATIONS:

2G (GSM — Global System for Mobile):
  • Year: 1991
  • Voice: circuit-switched
  • Data: GPRS/EDGE (up to 384 kbps)
  • Encryption: A5/1, A5/2 (both broken)
  • Security weakness: No mutual authentication
                       (device authenticates to network but NOT vice versa)
                       → Allows IMSI catchers / Stingrays
  
3G (UMTS — Universal Mobile Telecommunication System):
  • Year: 1998
  • Data: up to 7.2 Mbps (HSPA)
  • Encryption: KASUMI cipher (weaknesses found)
  • Improvement: Mutual authentication added
  • Security weakness: Downgrade attacks to 2G
  
4G LTE (Long Term Evolution):
  • Year: 2009
  • Data: 100 Mbps - 1 Gbps
  • All-IP network (no circuit switching)
  • Encryption: AES-128
  • Authentication: EPS-AKA (Evolved Packet System AKA)
  • Security weakness: VoLTE security issues, IMSI exposure in some cases
  
5G NR (New Radio):
  • Year: 2019
  • Data: up to 20 Gbps
  • SUPI (Subscriber Permanent Identifier) protected with SUCI
    (Subscriber Concealed Identifier) — prevents IMSI catchers
  • 256-bit algorithms available
  • Network slicing security considerations
  • Most secure cellular standard to date
```

#### 4G LTE Network Architecture

```
LTE ARCHITECTURE:

UE                 RAN                    EPC (Core)
(Mobile) ───────► (eNodeB) ──────────────────────────► Internet
  │         Radio   │        S1-MME/S1-U               
  │         Air     │         
  │         Interface        MME (Mobility Mgmt Entity)
  │                          SGW (Serving Gateway)
  │                          PGW (PDN Gateway)
  │                          HSS (Home Subscriber Server)
  │                               ↑ Contains subscriber auth data
  │                               
Authentication (EPS-AKA):
  1. MME requests authentication from HSS
  2. HSS generates authentication vector (RAND, XRES, AUTN, KASME)
  3. MME sends RAND+AUTN to UE
  4. UE verifies AUTN (mutual authentication)
  5. UE computes RES using SIM card K value
  6. UE sends RES to MME
  7. MME compares RES to XRES
  8. Match → Authentication successful, session keys derived
```

---

## 4.10 SIM CARD FORENSICS AND CELLULAR SECURITY

### 📱 SIM Card Architecture — Deep Dive

The SIM (Subscriber Identity Module) is a **secure microcontroller** with a CPU, ROM, RAM, EEPROM, and a crypto coprocessor, embedded in a card form factor.

```
SIM CARD PHYSICAL STRUCTURE:

┌──────────────────────────────────────────────────────────┐
│                    SIM CARD INTERNALS                     │
│                                                          │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────────┐ │
│  │   CPU     │  │   ROM     │  │      EEPROM          │ │
│  │ (8/16/32  │  │ (OS +     │  │ (NVRAM — Persistent) │ │
│  │  bit MCU) │  │  Algos)   │  │  • IMSI              │ │
│  └─────┬─────┘  └─────┬─────┘  │  • Ki (auth key)     │ │
│        │              │        │  • OPc (operator key) │ │
│  ┌─────▼─────┐        │        │  • SMS storage        │ │
│  │   RAM     │        │        │  • Phonebook          │ │
│  │ (Working  │◄───────┘        │  • Last numbers dialed│ │
│  │  memory)  │                 │  • Network settings   │ │
│  └───────────┘                 └──────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │            CRYPTO COPROCESSOR                      │  │
│  │  • AES engine                                      │  │
│  │  • A3/A8 algorithms (GSM authentication)           │  │
│  │  • A5 encryption (over-air)                       │  │
│  │  • MILENAGE (3G/4G/5G authentication)              │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  CONTACTS (C7 gold pads):                                │
│  C1=Vcc  C2=RST  C3=CLK  C5=GND  C6=Vpp  C7=I/O       │
└──────────────────────────────────────────────────────────┘
```

---

### 📁 SIM Card File System (Elementary Files)

The SIM file system is organized as a **hierarchical tree** of files:

```
SIM FILE SYSTEM HIERARCHY:

MF (Master File — Root)  [3F00]
│
├── EF(ICCID) [2FE2]   → SIM card serial number (20 digits)
│
├── DF(GSM) [7F20]     → GSM directory
│   ├── EF(IMSI) [6F07]    → International Mobile Subscriber ID
│   ├── EF(Ki)  [6F1B]    → Authentication key (CANNOT be read externally!)
│   ├── EF(LOCI) [6F7E]   → Location information (LAI, TMSI)
│   ├── EF(ADN) [6F3A]    → Abbreviated Dialing Numbers (phonebook)
│   ├── EF(LND) [6F44]    → Last Numbers Dialed
│   ├── EF(SMS) [6F3C]    → Short Messages (up to 250 SMS)
│   ├── EF(SMSP)[6F42]    → SMS Parameters (SMSC number)
│   ├── EF(MSISDN)[6F40]  → Mobile Station ISDN (your phone number)
│   ├── EF(PLMNsel)[6F30] → Preferred network list
│   └── EF(FPLMN)[6F7B]  → Forbidden PLMNs
│
└── DF(TELECOM) [7F10]  → Telecom directory
    ├── EF(ADN) [6F3A]   → Phonebook (telecom level)
    └── EF(CCP) [6F3D]   → Capability Configuration Parameters
```

**Key forensic targets on SIM:**

| Elementary File | Forensic Value |
|----------------|---------------|
| EF(IMSI) | Links SIM to subscriber account |
| EF(ICCID) | Unique SIM identifier |
| EF(LOCI) | Last known location (Cell Tower ID + LAI) |
| EF(ADN) | Phonebook contacts stored on SIM |
| EF(SMS) | SMS messages stored on SIM (not device) |
| EF(LND) | Last dialed numbers |
| EF(MSISDN) | Phone number associated with SIM |

---

### 🔐 SIM Authentication Process

```
SIM AUTHENTICATION (MILENAGE for 4G):

SIM Card contains secret: K (128-bit)
Network (HSS) contains: K (same copy, for same subscriber)
                         OP (Operator Parameter — 128-bit)
                         Compute: OPc = AES-128(OP, K) ⊕ OP

CHALLENGE-RESPONSE:
  Network generates: RAND (128-bit random)
  
  SIM computes:
    XMAC = f1(K, RAND, SQN, AMF, OPc)   [authentication code]
    RES  = f2(K, RAND, OPc)             [response = proof of K knowledge]
    CK   = f3(K, RAND, OPc)             [cipher key for session]
    IK   = f4(K, RAND, OPc)             [integrity key for session]
    AK   = f5(K, RAND, OPc)             [anonymity key]
  
  Network computes same values, verifies:
    XMAC from SIM == MAC it computed? → SIM is legitimate
    RES from SIM  == XRES it computed? → Subscriber authenticated
  
  RESULT: Both sides derive CK and IK independently
          → Session keys never transmitted over air
          → Ki NEVER leaves the SIM card
```

---

### 📡 IMSI Catchers (Stingrays)

An IMSI Catcher is a **rogue base station** that impersonates a legitimate cellular tower to intercept communications.

```
IMSI CATCHER OPERATION:

Legitimate Network:
  Phone ←──────────────────────────────► Tower A (real)
  
With IMSI Catcher:
  
  Phone ←── Stronger signal ──► IMSI Catcher ──► Tower A (real)
             (Stingray)          Man-in-Middle
             
HOW IT WORKS:
  1. Stingray broadcasts stronger signal than legitimate tower
  2. Phone connects to Stingray (follows strongest signal)
  3. Stingray requests IMSI from phone (2G: no mutual auth needed!)
  4. Phone sends IMSI in plaintext
  5. Stingray relays to real tower (transparent proxy)
  
IN 2G (GSM):
  • No mutual authentication → Phone cannot verify tower legitimacy
  • Stingray can force 2G connection even if 4G available
  • A5/1 encryption of 2G can be broken in real-time
  
IN 4G/5G:
  • Mutual authentication → harder to impersonate
  • 4G: IMSI still exposed in some attach messages
  • 5G: SUCI (Subscriber Concealed Identity) — IMSI encrypted
        → IMSI catchers much less effective in 5G
        
FORENSIC DETECTION:
  • AIMSICD app (Android) — detects suspicious base stations
  • Unusual tower signal strength spikes
  • Sudden 4G→2G downgrade
  • Base station with unusual cell ID patterns
```

---

### 📦 SS7 Protocol Vulnerabilities

SS7 (Signaling System 7) is the **global telecommunications signaling protocol** used by carriers to route calls, SMS, and manage roaming — designed in 1975 with NO security in mind.

```
SS7 ATTACK CAPABILITIES:

LOCATION TRACKING:
  Attacker with SS7 access → sends SRI-for-SM query
  → Network responds with MSC (Mobile Switching Center) location
  → Cell tower data reveals subscriber location
  
SMS INTERCEPTION:
  Attacker registers false "roaming" entry for victim's MSISDN
  → SMS addressed to victim routed through attacker's node
  → 2FA SMS codes intercepted
  
CALL FORWARDING:
  SS7 RegisterSS message → activate call forwarding to attacker
  → Victim receives no calls (all go to attacker)

WHY SS7 IS STILL USED:
  • Retrofitting 800+ carriers worldwide is enormously expensive
  • Required for global SMS interoperability (A2P SMS)
  • Carriers have begun deploying SS7 firewalls (filtering)
  
MITIGATION:
  • SS7 firewalls (filtering anomalous messages)
  • Use app-based 2FA (TOTP) instead of SMS 2FA
  • Signal/E2E encrypted calls instead of PSTN
  • 5G reduces SS7 exposure by using different signaling
```

---

## 4.11 MOBILE PAYMENT SECURITY

```
MOBILE PAYMENT ECOSYSTEM:

┌────────────────────────────────────────────────────────────┐
│              MOBILE PAYMENT SECURITY LAYERS                 │
│                                                            │
│  Layer 1: DEVICE SECURITY                                  │
│    • Device must be unlocked to authorize payment          │
│    • Biometric verification for each transaction           │
│    • Device attestation (SafetyNet/DeviceCheck)            │
│                                                            │
│  Layer 2: TOKENIZATION                                     │
│    Real Card: 4111 1111 1111 1111 → Device Token (DAN)    │
│    Merchant never sees real card number                    │
│    Token usable only on specific device                    │
│    Token revocable without affecting real card             │
│                                                            │
│  Layer 3: CRYPTOGRAPHIC AUTHENTICATION                     │
│    EMV (Europay/Mastercard/Visa) dynamic code             │
│    ARQC (Authorization Request Cryptogram) per-transaction │
│    NFC contactless: ISO 14443 protocol                     │
│                                                            │
│  Layer 4: SECURE ELEMENT (SE)                              │
│    Payment credentials in tamper-resistant chip            │
│    Separate from main CPU — isolated execution             │
│    SE types: Embedded SE / SIM-based / microSD             │
└────────────────────────────────────────────────────────────┘
```

**Apple Pay Security:**
- Card number never stored on device or Apple servers
- Device Account Number (DAN) stored in Secure Enclave
- Face ID/Touch ID required for each transaction
- Dynamic security code with each payment

**Google Pay Security:**
- Virtual Account Number (VAN) instead of real card
- Host Card Emulation (HCE) — SE emulation in software
- Requires device unlock
- Tokenization via Mastercard/Visa network

---

## 4.12 WI-FI SECURITY

### 📶 Wi-Fi Security Protocols Evolution

```
WI-FI SECURITY EVOLUTION:

1997: WEP (Wired Equivalent Privacy)
  Algorithm: RC4 stream cipher, 64/128-bit key
  BROKEN: 2001 — IV reuse allows key recovery in minutes
  Status: COMPLETELY INSECURE — never use
  
2003: WPA (Wi-Fi Protected Access)
  Algorithm: TKIP (RC4 with longer key + MIC)
  BROKEN: 2008 — Beck-Tews attack on TKIP
  Status: DEPRECATED
  
2004: WPA2 (802.11i)
  Algorithm: AES-CCMP (AES in CCM mode)
  BROKEN: 2017 — KRACK (Key Reinstallation Attack)
  Status: STILL COMMON, use with WPA2-Enterprise or VPN
  
2018: WPA3
  Algorithm: AES-GCMP-256 (stronger), SAE handshake
  SAE (Simultaneous Authentication of Equals):
    → Replaces PSK 4-way handshake
    → Resistant to offline dictionary attacks
    → Forward secrecy (even if password compromised later)
  Status: CURRENT STANDARD — use WPA3 wherever available
```

**Common Wi-Fi Attacks:**

```
EVIL TWIN ATTACK:
  Legitimate AP: "CafeWifi" (SSID)
  Attacker AP: "CafeWifi" (same SSID, stronger signal)
  
  Phone auto-connects to attacker's AP (stronger signal)
  All traffic passes through attacker
  → HTTP traffic: attacker reads everything
  → HTTPS traffic: attacker attempts SSL stripping
  
DETECTION: Certificate errors, HSTS warnings
PREVENTION: VPN, verify AP BSSID (MAC), use WPA3-Enterprise

DEAUTHENTICATION ATTACK (802.11 Deauth):
  802.11 management frames are NOT authenticated (WPA2)
  Attacker sends deauth frame → devices disconnect
  → Force reconnection attempt → capture 4-way handshake
  → Offline dictionary attack on captured handshake
  
WPA3 FIX: Protected Management Frames (PMF) mandatory
           → Deauth frames are authenticated → attack fails

KRACK (Key Reinstallation Attack):
  WPA2 4-way handshake vulnerability
  Nonce reuse → XOR keystream reuse → traffic decryption
  PATCHED: All major OSes patched (2017-2018)
```

---

## 🧪 UNIT IV — Questions & Answers

### Q-IV-1: Describe the NAND flash storage architecture and explain why it is important for mobile forensics.

**Answer:**

NAND flash is the primary storage technology in all modern smartphones. Understanding its architecture is critical for forensic practitioners for two main reasons: data recovery opportunities and the FTL's impact on acquisition.

**Physical hierarchy:** NAND is organized into cells → pages → blocks → planes → devices. The critical distinction is that pages (typically 4-16KB) are the smallest unit that can be read or written, but blocks (typically 128KB-4MB, containing 64-256 pages) are the smallest unit that can be erased. This asymmetry creates an important forensic opportunity.

**Out-of-place writes:** Because erasing a block takes time and degrades the flash (limited P/E cycles), the Flash Translation Layer (FTL) never overwrites data in-place. Instead, when data is updated, the new version is written to a fresh page and the old page is marked "stale." The stale page retains its old data until the block it belongs to is garbage collected and erased.

**Forensic implication:** Stale pages containing old/deleted data persist in NAND flash. A physical acquisition (Level 4 or Level 5) that obtains a raw bit-for-bit image of the flash chip will include stale pages. Investigators can parse these pages to recover:
- Previously deleted messages
- Older versions of files
- Data from uninstalled applications
- File fragments

**TRIM command impact:** Modern eMMC and UFS storage supports TRIM, which proactively marks free pages for erasure during idle periods. When TRIM is active, deleted data may be erased before acquisition, significantly reducing recovery prospects. This is why timeliness in evidence collection matters — the longer between deletion and acquisition, the more TRIM may have erased.

---

### Q-IV-2: Explain AES encryption with modes of operation. Why is AES-GCM preferred for mobile encryption?

**Answer:**

AES (Advanced Encryption Standard) is a symmetric block cipher standardized by NIST in 2001, operating on 128-bit blocks with key sizes of 128, 192, or 256 bits.

**How AES works (simplified):**
AES processes data through 10, 12, or 14 rounds (depending on key size), each round applying four operations: SubBytes (byte substitution using S-box), ShiftRows (row permutation), MixColumns (column mixing), and AddRoundKey (XOR with round key). These operations are designed so that after each round, a single bit change in input or key affects every output bit (confusion and diffusion properties).

**Modes of operation** are necessary because AES encrypts exactly one 128-bit block at a time, but real data is longer:

*ECB (Electronic Codebook):* Each block encrypted independently with same key. Identical plaintext blocks produce identical ciphertext — this reveals data patterns (famously demonstrated with the "ECB penguin"). Never used for data.

*CBC (Cipher Block Chaining):* Each block XOR'd with the previous ciphertext block before encryption. Requires an Initialization Vector (IV) for the first block. Hides patterns but requires sequential processing (not parallelizable for encryption). Used in AES-CBC for disk encryption in older Android versions.

*CTR (Counter Mode):* A counter is encrypted to produce a keystream, which is XOR'd with plaintext. Converts AES into a stream cipher. Allows random access and parallel processing. No padding needed.

*GCM (Galois/Counter Mode):* CTR mode plus a GHASH authentication function. GCM provides Authenticated Encryption with Associated Data (AEAD) — it simultaneously encrypts data AND generates a 128-bit authentication tag. Any modification to the ciphertext causes tag verification failure.

**Why AES-GCM is preferred for mobile:**
1. **Authentication:** Unlike AES-CBC which only provides confidentiality, GCM also verifies integrity — modifications are detected. This is critical for file encryption where tampering must be detected.
2. **Performance:** CTR-based parallelism means modern 64-bit mobile processors can use SIMD (single instruction multiple data) instructions for extremely fast encryption — often 1-2 GB/s on modern SoCs.
3. **Hardware acceleration:** ARM Cortex-A processors include AES and PMULL instructions specifically for AES-GCM, enabling encryption without significant CPU overhead.
4. **Standard:** TLS 1.3, Android FBE, and WhatsApp all use AES-256-GCM, making it the universal choice.

---

### Q-IV-3: What is an IMSI catcher? Explain how it works and what forensic/security implications it has.

**Answer:**

An IMSI catcher (commonly called a Stingray after the brand name of one commercial version) is a portable device that impersonates a legitimate cellular base station to force nearby mobile devices to connect to it, enabling the operator to capture the IMSI (International Mobile Subscriber Identity) and potentially intercept communications.

**How it works:**
Cellular devices always connect to the strongest available signal. An IMSI catcher broadcasts at high power on the same frequencies as legitimate towers, forcing nearby phones to "handover" to it. In 2G/GSM networks, which lack mutual authentication, the phone cannot verify that the tower is legitimate — it simply connects.

Once connected, the phone transmits its IMSI (a unique 15-digit subscriber identifier) during the attach procedure. The catcher records this and can then relay the connection to the real network (transparent proxy mode) or simply record metadata (passive mode).

**Attack capabilities:**
- IMSI capture: Identifies specific subscriber devices in an area
- Location tracking: Determines that a specific IMSI is within range
- Call and SMS interception (2G): With A5/1 decryption capability
- Forced 2G downgrade: Even if device supports 4G, catcher can force degradation

**4G/5G improvements:**
4G added mutual authentication (AKA protocol), making full impersonation harder. However, IMSI was still exposed in some 4G attach messages. 5G introduced SUCI (Subscriber Concealed Identifier) — the IMSI is now encrypted using the network's public key before transmission, so passive IMSI capture is no longer possible in a properly deployed 5G network.

**Forensic and legal implications:**
Law enforcement agencies in many countries use IMSI catchers legally (with court orders) to locate suspects. However, they are controversial because they indiscriminately capture IMSI data from all devices in an area, not just targets. Defense attorneys may challenge evidence obtained via IMSI catchers on Fourth Amendment (US) or equivalent grounds.

---

### Q-IV-4: Explain anti-forensics techniques and how investigators can counter them.

**Answer:**

Anti-forensics comprises deliberate actions taken to prevent, hinder, or misdirect forensic investigation. Major categories and countermeasures:

**Data destruction and wiping:**
- Factory reset on modern encrypted devices cryptographically erases the key, rendering data unreadable without recovery of the key
- Overwriting tools (via ADB): `adb shell dd if=/dev/urandom of=/dev/block/userdata` overwrites raw partition
- Countermeasure: JTAG/chip-off before factory reset; check FTL stale pages; examine EFS partition separately

**Encryption:**
Full device encryption with strong authentication makes data inaccessible without credentials. Separate containers (encrypted apps like Signal, encrypted vaults) add layers.
- Countermeasure: Legal compulsion for password; exploit-based unlock (GrayKey/Cellebrite); examine cloud backups which may be less protected

**Steganography:**
Data hidden within innocent-looking image or audio files using LSB manipulation or other methods.
- Countermeasure: Statistical steganalysis (chi-square test), examine file sizes (larger than expected for content), look for unusual tools on device

**Log manipulation:**
Clearing logcat, deleting system logs, manipulating timestamps via `adb shell date` or root tools.
- Countermeasure: Cross-reference multiple log sources; carrier records; cloud service timestamps; network packet captures which have independent timestamps

**Obfuscation (VPN/Tor):**
Traffic encrypted and routed through anonymizing services.
- Countermeasure: VPN traffic still visible as encrypted connection to a VPN server; device-local app data still readable; legal requests to VPN provider if jurisdiction permits

**Malware self-deletion:**
Malware that deletes itself after execution leaves no easily visible trace.
- Countermeasure: Physical acquisition may recover deleted malware binary from unallocated space; memory dump (if device is live) captures running processes; logcat captures process names and API calls

---

# ═══════════════════════════════════════════════════════════════
# UNIT V — ADVANCED TOPICS IN MOBILE FORENSICS
# ═══════════════════════════════════════════════════════════════

---

## 📚 UNIT V — Table of Contents

| # | Topic |
|---|-------|
| 5.1 | Mobile Device Forensics in Criminal Investigations |
| 5.2 | Mobile Device Forensics in Civil Litigation |
| 5.3 | Emerging Trends in Mobile Forensics |
| 5.4 | Data Mining in Mobile Security |
| 5.5 | Machine Learning in Mobile Forensics |
| 5.6 | Mobile Forensics Case Studies |
| 5.7 | Unit V Q&A |

---

## 5.1 MOBILE DEVICE FORENSICS IN CRIMINAL INVESTIGATIONS

### ⚖️ Role of Mobile Evidence in Criminal Cases

Mobile devices have become the **single most valuable source of evidence** in modern criminal investigations, often providing more actionable intelligence than any other source.

```
TYPES OF CRIMINAL INVESTIGATIONS WHERE MOBILE EVIDENCE IS CRITICAL:

├── VIOLENT CRIMES
│     • Location data places suspect at scene
│     • Communication records show coordination
│     • Photos/videos may capture event
│     • Social media establishes motive
│
├── DRUG TRAFFICKING
│     • Encrypted messaging (but metadata visible)
│     • Financial app records
│     • GPS logs showing distribution routes
│     • Contact networks
│
├── FINANCIAL CRIMES / FRAUD
│     • Email evidence of scheme coordination
│     • Banking app records
│     • Messaging showing conspiracy
│     • Wire transfer confirmations
│
├── CYBERCRIME
│     • App data showing tools used
│     • Network logs showing attack origin
│     • Cryptocurrency wallet addresses
│     • Malware artifacts
│
├── TERRORISM / EXTREMISM
│     • Encrypted app communications
│     • Propaganda consumption history
│     • Location data (target surveillance)
│     • Contact networks (co-conspirators)
│
└── CHILD EXPLOITATION (CSAM)
      • Photo/video evidence
      • Communication with victims
      • Cloud storage
      • P2P sharing records
```

---

### 📋 Evidence Admissibility Requirements

For mobile evidence to be admissible in court, it must satisfy:

```
EVIDENCE ADMISSIBILITY FRAMEWORK:

1. AUTHENTICITY
   • Must prove the data came from the claimed device
   • Hash verification (MD5/SHA-256) proves data unchanged
   • Chain of custody document proves unbroken possession
   • Tool validation (tool accurately represents device data)

2. RELEVANCE
   • Evidence must be material to the case
   • Data must relate to the crime charged
   • Expert must explain connection to alleged offense

3. RELIABILITY
   • Forensic tools must be validated and accepted in legal community
   • Examiner must be qualified (training, certifications)
   • Methodology must be reproducible
   • Opposing expert must be able to test and replicate

4. BEST EVIDENCE RULE
   • Original or verified forensic copy preferred
   • Screenshots alone generally insufficient (no hash verification)
   • Full acquisition with hash verification = best evidence

5. HEARSAY CONSIDERATIONS
   • Machine-generated records (logs, timestamps) generally not hearsay
   • Human-authored communications (SMS, email) may require exception
```

**Common challenges to mobile evidence:**

| Challenge | Defense Argument | Investigator Response |
|-----------|-----------------|----------------------|
| Authentication | "That data could have been altered" | Hash verification, write-blocker logs |
| Tool reliability | "The tool made errors" | Validation studies, cross-tool verification |
| Chain of custody | "Device changed hands improperly" | Complete CoC documentation |
| Timestamp accuracy | "Timestamps are unreliable" | Multiple corroborating sources |
| Deleted data | "Recovered data is speculative" | SQLite freelist forensics explanation |
| Context | "Messages are out of context" | Full conversation thread |

---

## 5.2 MOBILE DEVICE FORENSICS IN CIVIL LITIGATION

### 📄 Civil vs Criminal Context

```
COMPARISON: CRIMINAL VS CIVIL MOBILE FORENSICS

Feature                 Criminal                Civil (Litigation)
──────────────────────  ──────────────────────  ──────────────────────
Legal authority         Search warrant          Court order / eDiscovery
                        Subpoena                subpoena

Standard of proof       Beyond reasonable doubt Preponderance of evidence
                                                (more likely than not)

Primary concern         Criminal conviction     Damages / contract /
                                                employment dispute

Typical cases           Homicide, drug, fraud   Employment, divorce,
                                                IP theft, harassment

Device ownership        Suspect's device        May be employer-owned
                        (4th Amendment issues)  (fewer privacy issues)

Evidence format         Court exhibit           eDiscovery production set

Tools used              Same tools              Same tools
                                                + litigation hold focus

Attorney involvement    Prosecution + Defense   Plaintiff + Defense counsels

Expert role             Expert witness          Consulting + testifying
```

---

### 📑 eDiscovery and Mobile Forensics

eDiscovery (electronic discovery) is the process of identifying, collecting, and producing electronically stored information (ESI) in legal proceedings.

```
EISCOVERY WORKFLOW (EDRM Model):

Information
Management  → Identification → Preservation → Collection
                                                  │
                                                  ▼
                                             Processing
                                                  │
                                                  ▼
Review → Analysis → Production → Presentation
                        │
                  Mobile-specific concerns:
                  • BYOD vs corporate device
                  • Personal data mixed with work data
                  • Proportionality (not all data must be produced)
                  • Privilege protection (attorney-client communications)
                  • Privacy of non-party communications
```

**Mobile-specific eDiscovery challenges:**
- BYOD policies create mixed personal/work data on same device
- Proportionality — court balances relevance vs burden of collection
- Employee privacy rights (even on partially employer-used devices)
- Messaging apps with ephemeral messaging features (Snapchat, Signal's disappearing messages)
- Cross-platform data (iMessage on Mac + iPhone + iPad)

---

## 5.3 EMERGING TRENDS IN MOBILE FORENSICS

### 🔮 Key Emerging Trends

#### 1. Zero-Click Exploits and Advanced Persistent Threats

Nation-state actors increasingly deploy **zero-click vulnerabilities** — exploits requiring zero user interaction — to silently compromise devices.

```
ZERO-CLICK ATTACK CHAIN EXAMPLE:

External Actor
     │
     ▼
Malicious iMessage Payload
     │
     ▼
ImageIO parsing vulnerability (heap overflow)
     │
     ▼
Memory corruption → code execution
     │
     ▼
Kernel exploit (privilege escalation)
     │
     ▼
Full device compromise (persistent)
     │
     ▼
Data exfiltration (calls, messages, location, camera)

FORENSIC DETECTION:
  • Anomalous background network connections
  • Unexpected processes in running process list
  • IOC lists from threat intelligence (Amnesty Tech, Lookout)
  • MVT (Mobile Verification Toolkit) analysis of backup/filesystem
```

#### 2. IoT and Wearable Device Forensics

The proliferation of smartwatches, fitness trackers, smart home devices, and connected vehicles creates new forensic opportunities.

```
WEARABLE DEVICE FORENSIC DATA:

Smartwatch (e.g., Apple Watch, Galaxy Watch):
  • Heart rate history (proves physical state at a time)
  • Sleep tracking (alibi corroboration)
  • GPS tracks (independent location source)
  • Fall detection events (timestamped)
  • Payment history (Apple Pay on watch)
  • Communication logs (paired phone interactions)
  
Fitness Tracker:
  • Step count and movement patterns
  • Sleep data
  • GPS routes
  • Heart rate anomalies (stress indicators)

Smart Home Device (Amazon Echo, Google Home):
  • Voice command logs (timestamped)
  • Smart lock events (who entered when)
  • Connected camera footage
  • Smart appliance usage patterns

Connected Vehicle:
  • GPS route history (often 90+ days)
  • Paired phone contacts (Bluetooth sync)
  • Call logs via Bluetooth
  • Door lock/unlock events
  • Speed and acceleration data
```

#### 3. 5G Network Forensics

5G introduces new forensic challenges and opportunities.

```
5G FORENSIC IMPLICATIONS:

Network Slicing:
  • Multiple virtual networks on same physical infrastructure
  • Different slices have different logging/retention
  • Forensic requests may need slice-specific data

Edge Computing:
  • Data processed closer to device (lower latency)
  • May reduce data reaching central cloud servers
  • Forensic data collection more distributed

SUCI/SUPI Protection:
  • IMSI now encrypted over air (SUCI)
  • IMSI catchers much less effective
  • Legitimate network operator still has SUPI
  • Law enforcement needs carrier cooperation even more

Massive IoT:
  • Billions of 5G-connected devices
  • Each potential evidence source
  • Massive data volume challenges
```

#### 4. Encryption Challenges — "Going Dark" Problem

```
THE "GOING DARK" DEBATE:

Law Enforcement Position:
  "Modern encryption and E2E messaging mean we cannot access
   evidence even with lawful authority. Backdoors needed."

Industry/Privacy Position:
  "Backdoors for law enforcement create vulnerabilities for
   ALL attackers. You cannot have a backdoor only good guys
   can use — math doesn't work that way."

Current Reality:
  ┌──────────────────────────────────────────────────────┐
  │ ACCESSIBLE                   NOT ACCESSIBLE           │
  │                                                       │
  │ • iCloud backups (non-ADP)  • Signal E2E messages    │
  │ • Google backup             • WhatsApp if E2E backup  │
  │ • iTunes backup (no pwd)    • iOS with ADP enabled    │
  │ • Unlocked device data      • Locked encrypted device │
  │ • Carrier call records      • End-to-end voice calls  │
  │ • App data on unlocked dev  • Passwords in TEE        │
  └──────────────────────────────────────────────────────┘
```

---

## 5.4 DATA MINING IN MOBILE SECURITY

### ⛏️ What Is Data Mining?

Data mining is the process of **discovering patterns, anomalies, and useful information** from large datasets using statistical, mathematical, and computational techniques.

```
DATA MINING PROCESS (CRISP-DM):

Business/Forensic Understanding
          │
          ▼
    Data Understanding
    (What data exists? Quality?)
          │
          ▼
    Data Preparation
    (Cleaning, transformation, feature extraction)
          │
          ▼
      Modeling
    (Apply algorithms)
          │
          ▼
     Evaluation
    (Assess results, accuracy)
          │
          ▼
    Deployment/Reporting
```

---

### 📊 Data Mining Techniques in Mobile Forensics

#### 1. Association Rule Mining

Discovers relationships between variables in a dataset.

```
EXAMPLE — MOBILE CALL PATTERN ANALYSIS:

Dataset: CDR (Call Detail Records) for suspect

Rule: {Contact_A, Contact_B} → {Location_X}
      Support: 0.75 (75% of calls to A+B happened at location X)
      Confidence: 0.90 (90% of time A+B are called, location is X)
      
Forensic interpretation:
  → Suspect regularly contacts A and B from location X
  → If X is known drug distribution point → corroborating evidence
  → If one of A/B is a known criminal → network association

Algorithm: Apriori, FP-Growth
```

#### 2. Clustering — Behavioral Analysis

Groups similar behaviors together without predefined labels (unsupervised learning).

```
CLUSTERING IN MOBILE FORENSICS:

K-Means Clustering on Call Data:

Cluster 1: {7:00-9:00, home location, family contacts}
  → Morning routine cluster

Cluster 2: {22:00-02:00, unknown location, anonymous numbers}
  → Anomalous cluster → investigate

Cluster 3: {12:00-14:00, work location, work contacts}
  → Lunch hour cluster

FORENSIC APPLICATION:
  • Identify behavioral anomalies (Cluster 2 above)
  • Detect insider threats (unusual after-hours access patterns)
  • Malware detection (unusual network connection clusters)
  • User profiling for civil investigations

Visualization: 
  Plot calls on map colored by cluster
  → Geographic patterns become immediately visible
```

#### 3. Link Analysis / Social Network Analysis (SNA)

Maps relationships between entities (people, places, communications).

```
SOCIAL NETWORK ANALYSIS IN MOBILE FORENSICS:

Nodes: Phone numbers / people
Edges: Communications (calls, messages)
Edge weight: Frequency of communication

                    [Unknown #1]
                        │
          [Contact A] ──┤── [SUSPECT] ──── [Contact B]
                        │        │
                    [Contact C]  └────── [Contact D]
                                               │
                                         [Unknown #2]

Analysis metrics:
  Degree centrality: Number of connections (who knows the most people)
  Betweenness centrality: Who is the intermediary/broker
  Closeness centrality: How quickly can reach all others
  
  High betweenness = coordinator/broker in criminal network
  → Key target for investigation focus

Tools: Maltego, i2 Analyst's Notebook, Gephi
```

#### 4. Temporal Analysis / Timeline Mining

```
TEMPORAL ANALYSIS:

Activity Timeline for Suspect Device:

06:00  │ ████░░░░░░░░░░░░░░░░░░░░░░░  Low activity (sleep)
08:00  │ ████████░░░░░░░░░░░░░░░░░░░  Morning activity
10:00  │ ████████████████████░░░░░░░  High activity (work)
12:00  │ ██████████████████████████░  Peak (lunch comm)
14:00  │ ████████████████████████████ Peak
16:00  │ ████████████████████░░░░░░░  Work hours
18:00  │ ████████████░░░░░░░░░░░░░░░  Evening
20:00  │ ████████████████░░░░░░░░░░░  Evening comms
22:00  │ ████████░░░░░░░░░░░░░░░░░░░  Pre-sleep
00:00  │ ██████████████████████████░  ← ANOMALY! High activity at midnight
02:00  │ ████░░░░░░░░░░░░░░░░░░░░░░░  Low again

Anomaly at midnight on the night of the incident → significant evidence

TOOLS: Timeline Explorer (Eric Zimmermann), Plaso, log2timeline
```

---

## 5.5 MACHINE LEARNING IN MOBILE FORENSICS

### 🤖 ML Applications in Mobile Security and Forensics

Machine learning (ML) enables **automated pattern recognition** at scale — critical when investigating devices with terabytes of data.

```
ML APPLICATION MAP IN MOBILE FORENSICS:

ML Techniques
├── Supervised Learning (labeled training data)
│     ├── Malware Classification
│     ├── Phishing Detection
│     ├── User Authentication (behavioral biometrics)
│     └── CSAM Image Detection
│
├── Unsupervised Learning (no labels)
│     ├── Anomaly Detection
│     ├── Clustering (behavioral grouping)
│     ├── Topic Modeling (document analysis)
│     └── Network traffic analysis
│
└── Deep Learning / Neural Networks
      ├── Image and video analysis (CNNs)
      ├── Natural Language Processing (messages)
      ├── Voice identification (speaker recognition)
      └── Deepfake detection
```

---

### 🦠 ML for Malware Detection

```
TRADITIONAL VS ML MALWARE DETECTION:

TRADITIONAL (Signature-based):
  Malware → Hash → Compare to database
  ✓ Zero false positives for known malware
  ✗ Unknown malware (zero-day) passes undetected
  ✗ Simple obfuscation changes hash → evades detection

ML-BASED:
  
  Training Phase:
  Benign Apps ──►                  ┌─────────────┐
  Malicious Apps ──► Feature ────► │   ML Model  │
                     Extraction    │  (trained)  │
                                   └─────────────┘
  
  Detection Phase:
  Unknown App ──► Feature ──► Trained Model ──► Benign/Malicious
                  Extraction                      + Confidence %

FEATURES USED:
  Static:
    • API calls (permission usage patterns)
    • Control flow graphs (code structure)
    • Strings and constants
    • DEX bytecode patterns
  
  Dynamic:
    • System calls during execution
    • Network connections made
    • File system operations
    • Battery and CPU usage patterns
    
ML ALGORITHMS:
  Random Forest: Good baseline, interpretable
  SVM: Effective for high-dimensional feature spaces
  CNN: For image-based malware visualization
  LSTM/RNN: For sequential API call analysis
  
PERFORMANCE BENCHMARKS:
  Best models achieve 97-99% accuracy on known malware families
  Adversarial malware (designed to evade ML) reduces accuracy to 85-90%
```

---

### 🧠 Deep Learning for Image and Video Analysis

```
CNN FOR CSAM AND ILLEGAL CONTENT DETECTION:

Input: Image (e.g., 224×224×3 pixels)
         │
         ▼
┌─────────────────────────────────────────────────────┐
│          CONVOLUTIONAL NEURAL NETWORK               │
│                                                     │
│ Conv Layer 1: 64 filters, 3×3 kernel               │
│   → Detects edges, basic shapes                    │
│         │                                           │
│ Pool Layer 1: 2×2 max pooling                      │
│   → Reduces spatial dimensions                     │
│         │                                           │
│ Conv Layer 2: 128 filters                          │
│   → Detects textures, patterns                     │
│         │                                           │
│ Conv Layer 3: 256 filters                          │
│   → Detects complex features (body parts, etc.)    │
│         │                                           │
│ Fully Connected: 1024 neurons                      │
│   → Combines all features                          │
│         │                                           │
│ Output Layer: Sigmoid (binary) or Softmax          │
│   → Probability: [Safe: 0.03, Illegal: 0.97]       │
└─────────────────────────────────────────────────────┘

PHOTODNA (Microsoft):
  • Perceptual hashing — not pixel-level comparison
  • Creates a 144-byte "fingerprint" of image content
  • Resilient to: resizing, recompression, color changes, cropping
  • Fingerprint matches against database of known illegal content
  • Used by: Facebook, Instagram, Bing, iCloud, Dropbox
```

---

### 📝 NLP for Communication Analysis

```
NLP PIPELINE FOR MESSAGE ANALYSIS:

Raw Messages (thousands/millions)
          │
          ▼
    Preprocessing
    • Tokenization
    • Stop word removal
    • Stemming/lemmatization
    • Emoji/slang normalization
          │
          ▼
  Feature Extraction
  • TF-IDF (term frequency)
  • Word embeddings (Word2Vec, BERT)
  • Sentiment scores
  • Named entity recognition (names, places, dates)
          │
          ▼
     Analysis Tasks:
     ┌──────────────────────────────────────────┐
     │ Sentiment Analysis:                      │
     │   "I'm going to make him pay" → Negative │
     │   Intent classification → Threat         │
     │                                          │
     │ Topic Modeling (LDA):                    │
     │   Cluster: ["meet", "location", "cash"]  │
     │   → Drug transaction topic               │
     │                                          │
     │ Entity Extraction:                       │
     │   "Meet at Sector 7 on Tuesday at 10"   │
     │   → Location: Sector 7                  │
     │   → Time: Tuesday 10:00                 │
     │                                          │
     │ Threat Detection:                        │
     │   Pattern matching + ML classifier      │
     │   → Flags threatening language          │
     └──────────────────────────────────────────┘
```

---

### 🔍 Behavioral Biometrics — User Authentication and Attribution

```
BEHAVIORAL BIOMETRICS IN MOBILE:

Traditional auth: Know (PIN) or Have (phone) or Are (fingerprint)
Behavioral auth: HOW you use the device

Features captured:
  • Touch pressure and size
  • Swipe velocity and curvature
  • Typing rhythm (dwell time, flight time between keys)
  • Gesture patterns (how you scroll, zoom)
  • Device orientation preferences
  • App usage patterns
  • Gait (accelerometer while walking)
  
ML Model:
  Builds baseline of "normal" behavior
  Continuously authenticates in background
  If behavior deviates significantly → require re-authentication
  
FORENSIC APPLICATION:
  • Prove who was using the device at a specific time
  • Distinguish between device owner and impostor
  • Corporate: detect stolen credentials (behavioral mismatch)
  • Civil: prove who sent disputed messages
```

---

### ⚠️ ML Limitations and Adversarial Attacks

```
ADVERSARIAL ATTACKS ON ML SYSTEMS:

Adversarial Malware:
  Standard malware → ML classifier → MALICIOUS (detected)
  
  Adversarial malware = malware + carefully crafted perturbation
  → ML classifier → BENIGN (evaded detection!)
  
  Technique: Gradient-based optimization
  Add dead code (benign API calls) to confuse classifier
  
DEEPFAKE THREAT:
  AI-generated video/audio that appears authentic
  → "Evidence" could be fabricated
  → Forensic deepfake detection algorithms:
      • Blink rate analysis (early deepfakes had wrong blink patterns)
      • Facial landmarks consistency
      • Compression artifact analysis
      • Temporal consistency analysis
      • GAN fingerprint detection

ADVERSARIAL TEXT:
  "Let's ki//the deal" → human reads as "kill the deal"
                       → NLP classifier reads as benign (typo)
  Or Unicode substitution: "k\u0456ll" (Cyrillic і)
  → Bypasses keyword filters
  → ML models need Unicode normalization
```

---

## 5.6 MOBILE FORENSICS CASE STUDIES

### 📁 Case Study 1: The San Bernardino iPhone (2016)

**Background:** After the 2015 San Bernardino terrorist attack, FBI seized the attacker's iPhone 5C. The device was locked with a PIN and had "erase after 10 attempts" enabled.

**The forensic challenge:**
- iOS 9 full device encryption
- 10-attempt lockout with erase
- Apple refused to create a backdoor iOS version
- Court ordered Apple to assist → Apple challenged the order

**Resolution:**
The FBI paid approximately $1 million to an unnamed vendor (reportedly Cellebrite or Azimuth Security) who found an iOS 9 vulnerability allowing unlimited PIN attempts without triggering erase.

**Forensic lessons:**
- Strong encryption is effective against even government-level forensic tools
- Zero-day exploit market for mobile devices is significant
- Legal framework for compelling tech company assistance is unresolved
- Encryption debate ("going dark") became central policy issue

**Outcome:** The phone data was accessed but reportedly contained no significant intelligence connecting to a broader network.

---

### 📁 Case Study 2: WhatsApp in Criminal Investigation

**Scenario:** Drug trafficking network using WhatsApp for coordination.

**Evidence recovered:**
- Encrypted device obtained with physical acquisition (suspect provided passcode during arrest)
- WhatsApp `msgstore.db` decrypted using key file
- Group chats revealed: supplier contacts, delivery schedules, payment arrangements
- Deleted messages recovered from SQLite freelist
- Photo metadata (EXIF GPS) placed suspects at specific locations at specific times
- WhatsApp voice call logs corroborated CDR (Call Detail Records) from carrier

**Forensic analysis:**
```
EVIDENCE CORRELATION:
  
  Device evidence:          Carrier records:        Location data:
  WhatsApp message          CDR shows call to       EXIF GPS shows
  "Delivery at 3pm          same number at          photo taken at
  Sector 7" sent            2:58pm (pre-delivery)   Sector 7 at 3:02pm
  at 14:45                                          
  
  CORRELATION: Message → Call → Physical presence → Delivery
  → Corroborated from three independent sources
  → Very difficult to challenge in court
```

**Legal outcome:** Evidence admitted; conviction secured.

---

### 📁 Case Study 3: Social Media and Location — Alibi Investigation

**Scenario:** Murder suspect claims alibi — "I was in Delhi when the crime occurred in Mumbai."

**Mobile forensic analysis:**
- Instagram photos geotagged within 5km of crime scene (Mumbai), posted 1 hour before crime
- Cell tower data from carrier: device connected to Mumbai tower during crime window
- Google Location History: continuous tracking showing Mumbai location
- WhatsApp "last seen" timestamp inconsistent with claimed Delhi location (wrong timezone)
- Travel booking apps: No train/flight booking to Delhi found in email or apps
- Wi-Fi connection logs: Device connected to Mumbai Wi-Fi networks

**Result:** Alibi completely contradicted by convergent mobile evidence from six independent sources. Conviction.

---

## 🧪 UNIT V — Questions & Answers

### Q-V-1: Explain the role of machine learning in mobile malware detection. What features are used and how are models trained?

**Answer:**

Machine learning has transformed mobile malware detection from reactive (signature-based) to proactive (behavior-based) by enabling classification of previously unseen malware families.

**Feature engineering — the foundation of ML malware detection:**

*Static features (extracted without running the code):*
API call sequences — malicious apps typically call different APIs than benign ones (e.g., SEND_SMS + READ_CONTACTS + INTERNET together is suspicious). These are extracted from the DEX bytecode. Permissions in AndroidManifest.xml form another feature set. Control flow graphs (CFG) represent code logic; malware often has characteristic graph structures. String constants (URLs, commands) and certificates are additional features.

*Dynamic features (extracted by running the app in a sandbox):*
System call sequences capture actual runtime behavior regardless of obfuscation. Network connections (domains, IPs, protocols) reveal C&C communication. File system operations (files created/deleted) and battery/CPU consumption patterns complete the dynamic picture.

**Training process:**
A labeled dataset of known benign and malicious APKs is assembled. Features are extracted from each sample and vectorized. The feature matrix (samples × features) is split into training/validation/test sets (typically 70/15/15). A classification algorithm (Random Forest, Gradient Boosting, CNN for image-based representation, or LSTM for sequential API calls) is trained to minimize classification error. The model is validated and threshold-tuned to balance false positives and false negatives, then deployed.

**Challenges:**
Adversarial malware authors use gradient-based optimization to add perturbations (dead code, benign API calls) that shift ML feature vectors toward the benign class. Class imbalance (far more benign apps than malicious) requires techniques like SMOTE oversampling. Concept drift — malware evolves faster than models retrain — necessitates continuous learning systems.

**Performance:** State-of-the-art models achieve 97-99% detection accuracy on standard benchmarks, though real-world performance against adversarially crafted malware is lower (85-90%).

---

### Q-V-2: What are the key considerations in mobile forensics for criminal investigations? Discuss evidence admissibility.

**Answer:**

Mobile forensics in criminal investigations is governed by strict legal, procedural, and technical requirements that must be followed to ensure evidence admissibility.

**Legal prerequisites:**
Before examining any device, investigators must have lawful authority — typically a search warrant specifically describing the device and scope of search, consent from the device owner, or exigent circumstances (imminent destruction of evidence). Without proper authority, all extracted evidence may be inadmissible and may expose investigators to liability.

**Technical requirements for admissibility:**

*Authenticity:* The prosecution must demonstrate that evidence accurately represents data from the specific device. Hash verification (SHA-256) mathematically proves the forensic image is an unaltered copy of the original. Chain of custody documents prove the device was not tampered with between seizure and analysis.

*Reliability of methods:* Courts apply the Daubert standard (in the US) requiring: the methodology has been tested, subjected to peer review, has known error rates, and is generally accepted in the forensic community. Well-established tools (Cellebrite, UFED) with published validation studies meet this standard more readily than novel approaches.

*Examiner qualifications:* The expert must be qualified by education, training, or experience. Certifications (Cellebrite CCFE, SANS FOR585, IACIS MCFE) demonstrate competence. The examiner should be able to explain their methodology clearly to a non-technical jury.

*Reproducibility:* Any opposing expert should be able to receive the forensic image and replicate the analysis, arriving at the same findings. Complete documentation of tools, settings, commands, and versions is essential.

**Common defense challenges and responses:**
Timestamp reliability is frequently challenged — the investigator should be prepared to explain timestamp sources (multiple corroborating timestamps from different sources), timezone conversions, and the difference between file system timestamps, application timestamps, and carrier records. The "recovered deleted data is speculative" argument is countered by explaining SQLite freelist forensics — the data is physically present in the database file, not reconstructed or interpolated.

---

### Q-V-3: Describe data mining techniques used in mobile forensics investigations. How is social network analysis applied?

**Answer:**

Data mining in mobile forensics transforms raw digital evidence — millions of messages, calls, locations — into actionable intelligence by discovering patterns invisible to manual review.

**Key data mining techniques:**

*Association rule mining:* Discovers co-occurrence patterns. Applied to CDR (Call Detail Records), it can reveal: "80% of calls between Suspect A and Contact B were followed within 1 hour by Contact B calling a known drug supplier" — suggesting A is dispatching orders through B. The Apriori algorithm generates rules of the form {antecedent} → {consequent} with support (frequency) and confidence (reliability) metrics.

*Clustering:* Groups communications or behaviors without predefined categories. K-means or DBSCAN clustering of location data can identify regularly visited locations — home, work, and potentially undisclosed meeting points. Clustering of communication times can reveal shift patterns in criminal activity.

*Temporal sequence mining:* Identifies patterns in the order of events. "Every time Suspect calls Number X, within 30 minutes they travel to Location Y" — this temporal pattern is discovered across hundreds of events automatically.

**Social Network Analysis (SNA):**

SNA treats communication data as a graph where nodes are individuals (identified by phone number, email, or social media account) and edges represent communications. Edge weight reflects communication frequency or intensity.

Key SNA metrics applied to criminal investigations:

Degree centrality measures how many connections a node has — high-degree nodes are highly connected individuals who may be key participants. Betweenness centrality identifies nodes on the shortest path between many pairs — these "broker" nodes are often coordinators or middlemen who bridge different groups. In organized crime, the betweenness-central individual may be the logistics coordinator even if not directly involved in operations.

Visualization of the resulting network graph (using tools like Maltego, i2 Analyst's Notebook, or Gephi) allows investigators and jurors to visually comprehend complex relationship structures that would be impossible to grasp from raw data. A cluster of highly connected nodes that is tenuously connected to the main network might represent a cell structure in a criminal organization.

**Practical application:** In a drug trafficking investigation, SNA of 6 months of CDR data revealed a three-tier structure: street dealers (leaf nodes with few connections), mid-level distributors (high betweenness), and a single coordinator (highest betweenness centrality). Focusing investigation resources on the high-betweenness individuals led to the identification of the organization's leadership, which was invisible from manual analysis of any single suspect's contacts.

---

### Q-V-4: What are the emerging trends and challenges in mobile forensics? Focus on encryption and machine learning.

**Answer:**

Mobile forensics faces an escalating tension between increasingly sophisticated security technologies and the need for lawful evidence access.

**Encryption challenges — the "Going Dark" problem:**

Modern mobile devices implement multiple encryption layers that collectively create significant forensic barriers. Full-disk encryption using AES-256 with hardware-bound keys (TEE/Secure Enclave) means that without the correct PIN or biometric, device data is mathematically inaccessible. The TEE enforces attempt limits, making brute force impractical for strong PINs.

At the application layer, Signal Protocol with Double Ratchet key derivation provides Perfect Forward Secrecy — even if a device's current key is compromised, past messages remain protected. Apple's Advanced Data Protection (iCloud E2E encryption) means even Apple cannot provide content to law enforcement.

The "going dark" debate centers on whether law enforcement should have guaranteed access. The cryptographic consensus is that backdoors cannot be made available to "good guys only" — the same mathematical weakness that would let police in would be exploitable by criminals, foreign intelligence services, and hackers. This debate remains unresolved at the policy level.

**Machine learning — dual role:**

ML accelerates forensic analysis by automating the review of massive datasets (millions of messages, thousands of images). PhotoDNA and CNN-based classifiers can scan an entire device image for CSAM in minutes. NLP classifiers can flag relevant communications from a 2-year message history automatically.

However, adversarial ML attacks present new challenges. Sophisticated actors deliberately craft malware or communications to evade ML classifiers — adding noise to images to defeat PhotoDNA-like systems, or inserting benign API calls to confuse malware classifiers. Deepfakes represent a genuinely new threat to evidence integrity — AI-generated video and audio that appears authentic can be produced to fabricate or contest evidence.

**Emerging frontiers:**
IoT device proliferation creates new evidence sources (smartwatches, smart home devices, connected vehicles) with non-standard operating systems and file formats requiring new forensic tools and methodologies. 5G's SUCI mechanism defeats IMSI catchers, requiring greater reliance on lawful carrier cooperation. Blockchain and cryptocurrency forensics is increasingly intertwined with mobile forensics as criminal proceeds are managed via mobile crypto wallets.

---

# ═══════════════════════════════════════════════════════════════
# MASTER Q&A BANK — UNITS III, IV, V
# ═══════════════════════════════════════════════════════════════

## Q&A SECTION — Critical Concepts

### Q-ADV-1: Describe the SIM card file system completely. What are Elementary Files (EFs) and how are they forensically extracted?

**Answer:**

The SIM card implements a hierarchical file system standardized under ETSI TS 102.221. The hierarchy consists of the Master File (MF) at the root, Dedicated Files (DFs) as directories, and Elementary Files (EFs) as actual data storage units.

**Master File (MF) [3F00]:** The root of the entire file system. Every SIM access starts here.

**Dedicated Files (DFs):** Directories containing related EFs. Key DFs include DF(GSM) [7F20] for GSM-specific data, DF(TELECOM) [7F10] for telecom functions, and DF(USIM) [7FFF] for USIM/4G data.

**Elementary Files (EFs):** The actual data containers. Each has a unique file identifier (e.g., [6F07] for IMSI). EFs have three types: transparent (one record, direct access), linear fixed (fixed-length records), and cyclic (ring-buffer of fixed records, oldest overwritten when full — used for LND to keep most recent numbers).

**Forensic extraction methods:**

*Software extraction* using SIM readers and tools like TULP2G, SIMbrush, or Oxygen Forensic Detective's SIM extraction module. The investigator inserts the SIM into a card reader, and the tool issues APDUs (Application Protocol Data Units) to read each EF according to the GSM/USIM specification.

*APDU commands used:*
```
SELECT FILE [3F00]     → Select Master File
SELECT FILE [7F20]     → Select DF(GSM)
SELECT FILE [6F3C]     → Select EF(SMS)
READ RECORD [01]       → Read first SMS record
```

*Deleted SMS recovery:* Cyclic EFs use a status byte per record (00=free, 01=read, 03=unread). When SMS is "deleted" from SIM, the status byte is set to 00 but the data remains. Recovery reads all records including "free" status ones and extracts data.

*Physical extraction:* SIM chip-off with dedicated SIM microprobe reader for damaged cards.

**Critical EFs for forensic value:**
LOCI [6F7E] contains the Location Area Information (LAI) from when the SIM last authenticated — this is the cell tower area where the phone last had service, providing a historical location data point. IMSI [6F07] is the immutable subscriber identifier. LND [6F44] stores the last 5-10 numbers dialed.

---

### Q-ADV-2: Explain SS7 vulnerabilities in complete detail. What attacks are possible and what is the impact?

**Answer:**

SS7 (Signaling System 7) is the set of telephony protocols designed in 1975 to coordinate how telephone networks exchange information to complete calls and manage subscribers. Its fundamental design flaw is that it was built with no authentication — any node in the network was trusted implicitly.

**Attack capabilities:**

*Location tracking:* An attacker with access to an SS7 node (which can be obtained through a rogue carrier, compromised network element, or purchased access on underground markets) can send a SRI-for-SM (Send Routing Information for Short Message) query for any MSISDN. The network responds with the subscriber's current MSC (Mobile Switching Center) and IMSI. By querying which cell tower the MSC is tracking the subscriber at, the attacker can localize them to a geographic area. Repeated queries enable tracking of movement.

*SMS interception:* The attacker registers a fraudulent location update making the network believe the subscriber is roaming through the attacker's node. Subsequent SMS messages destined for the victim are routed through the attacker's system. This is particularly devastating for 2FA — an attacker can steal the victim's MSISDN, intercept SMS-based OTPs (One-Time Passwords), and take over online banking, email, or social media accounts.

*Call forwarding:* SS7 RegisterSS messages allow activation of call forwarding without subscriber consent. The attacker registers unconditional forwarding to their number, receives all the victim's calls.

*Denial of service:* Cancelling location registrations prevents the device from making or receiving calls.

**Why the vulnerability persists:**
The global PSTN is built on SS7 interconnection between 800+ carriers worldwide. Replacing it would require a coordinated global infrastructure overhaul costing hundreds of billions of dollars. Carriers have begun deploying SS7 firewalls that filter suspicious signaling messages, but the underlying protocol remains insecure.

**Mitigation recommendations:**
SMS-based 2FA should be replaced with TOTP (Time-based One-Time Password) apps (Google Authenticator, Authy) or hardware FIDO2 keys. Voice calls containing sensitive information should use E2E encrypted alternatives (Signal). Users at high risk (journalists, executives, officials) should be aware that their location can be tracked via SS7 regardless of device-level security.

---

### Q-ADV-3: Explain the complete process of mobile malware analysis — from receipt to report.

**Answer:**

Mobile malware analysis follows a structured methodology ensuring thoroughness while maintaining a forensically defensible process.

**Phase 1 — Sample acquisition and verification:**
The malware sample (APK for Android, IPA for iOS) is obtained and hashed with SHA-256 to establish a reference fingerprint. It is checked against VirusTotal (aggregates 70+ AV engines) to determine if it is already known, and the VT report is documented. The sample is stored in an encrypted container with access logging.

**Phase 2 — Static analysis:**
The APK is decompiled using JADX or apktool. The AndroidManifest.xml is examined for: declared permissions (especially RECEIVE_SMS, READ_CONTACTS, RECORD_AUDIO, PROCESS_OUTGOING_CALLS indicating potential spyware/banking Trojan), registered receivers and services (long-running background services are suspicious), intent filters (particularly BOOT_COMPLETED suggesting persistence), and declared activities.

The DEX bytecode is decompiled to Java/Smali. Suspicious code patterns are identified: hardcoded IP addresses or domains (C&C servers), encryption key constants, obfuscated strings (decoded with custom scripts), reflection-based code execution (bypasses static analysis), and root detection/anti-debug routines.

String extraction identifies: embedded C&C URLs (e.g., http://evil.com/cmd), cryptocurrency wallet addresses, admin panel paths, encoded payloads (base64 decoded), and device identifiers collected.

**Phase 3 — Dynamic analysis:**
The sample is loaded into a controlled environment — either an isolated physical device (preferred, as emulators are often detected) or a hardened emulator. Network traffic is captured via mitmproxy. System calls are traced (strace, frida hooks). File system changes are monitored (inotify). Logcat is captured continuously.

The app is exercised manually and/or via automated UI testing (Monkey, AppCrawler). All behaviors are documented: domains/IPs contacted, files created, permissions requested and used, data exfiltrated (captured via network monitor), SMS sent, calls made.

**Phase 4 — Classification and IOC extraction:**
Based on analysis, the malware is classified (banking Trojan, ransomware, spyware, adware). Indicators of Compromise (IOCs) are extracted: C&C domains and IPs, package name and certificate hash, unique strings or code patterns for YARA rules, behavioral signatures.

**Phase 5 — Reporting:**
A complete technical report documents: executive summary (classification, risk level), static analysis findings, dynamic analysis observations, IOC list, YARA rules, recommended remediation (uninstall, factory reset, credential reset), and all supporting evidence with hashes.

---

### Q-ADV-4: Define and explain all major cryptographic concepts: symmetric, asymmetric, hashing, digital signatures, PKI, and TLS.

**Answer:**

**Symmetric Cryptography:**
Uses a single shared secret key for both encryption and decryption. The strength lies in the key remaining secret between parties. AES-256 is the current gold standard — its 256-bit key space (2^256 possible keys) makes brute force computationally infeasible. The challenge is secure key exchange — both parties must already share the key, creating a chicken-and-egg problem solved by asymmetric cryptography.

**Asymmetric Cryptography (Public Key):**
Uses a mathematically linked key pair. The public key (distributed freely) encrypts; only the private key (secret) decrypts. RSA relies on the practical impossibility of factoring the product of two large primes. ECC achieves equivalent security with smaller keys using elliptic curve discrete logarithm — preferred for mobile due to computational efficiency.

**Hash Functions:**
One-way functions producing fixed-length digests. SHA-256 produces a 256-bit hash of any input. They are deterministic (same input = same hash), one-way (hash cannot be reversed), and collision-resistant (infeasible to find two inputs with the same hash). Forensic use: integrity verification, password storage (salted), and known-file databases.

**Digital Signatures:**
Reverse of encryption asymmetry. The signer uses their private key to sign (produce a hash of the document encrypted with private key). Recipients verify using the signer's public key. Proves authenticity (message came from key holder) and non-repudiation (signer cannot deny signing). Used in code signing (ensuring apps are from authentic developers) and document authentication.

**PKI (Public Key Infrastructure):**
The system of Certificate Authorities (CAs), certificates (X.509 format), and protocols that allows parties who have never met to trust each other's public keys. A CA's digital signature on a certificate vouches for the binding of the public key to the named identity. Root CA certificates are pre-installed in operating systems (iOS/Android).

**TLS (Transport Layer Security):**
TLS 1.3 (current) establishes encrypted channels using: ECDH for key exchange (generating a shared session key), AES-256-GCM for symmetric encryption of the session, and X.509 certificates for authentication. The handshake takes one round trip (1-RTT), producing session keys. All subsequent traffic is encrypted symmetrically (faster than asymmetric). Perfect Forward Secrecy is achieved because ephemeral ECDH keys are discarded after the session — even if the server's private key is later compromised, past sessions remain secure.

---

# ═══════════════════════════════════════════════════════════════
# FINAL APPENDIX — QUICK REFERENCE TABLES AND DIAGRAMS
# ═══════════════════════════════════════════════════════════════

## 📊 Complete Forensic Tools Reference

| Tool | Type | Platform | Primary Use | Cost |
|------|------|---------|------------|------|
| Cellebrite UFED | Commercial | Windows | Full mobile acquisition | High |
| Cellebrite Physical Analyzer | Commercial | Windows | Analysis | With UFED |
| Oxygen Forensic Detective | Commercial | Windows | Acquisition + Analysis | High |
| MSAB XRY | Commercial | Windows | Acquisition | High |
| Magnet AXIOM | Commercial | Windows | Analysis | High |
| Magnet GRAYKEY | Commercial | Hardware | iOS unlock | Very High |
| Autopsy | Open Source | Win/Lin/Mac | Analysis | Free |
| ALEAPP | Open Source | Python | Android analysis | Free |
| iLEAPP | Open Source | Python | iOS analysis | Free |
| MVT | Open Source | Linux/Mac | Spyware detection | Free |
| ADB | Built-in | All | Android acquisition | Free |
| libimobiledevice | Open Source | Linux/Mac | iOS acquisition | Free |
| DB Browser for SQLite | Open Source | All | Database analysis | Free |
| ExifTool | Open Source | All | Metadata extraction | Free |
| Wireshark | Open Source | All | Network analysis | Free |
| FFmpeg/FFprobe | Open Source | All | Video forensics | Free |
| Jadx | Open Source | All | APK decompilation | Free |
| MobSF | Open Source | All | Malware analysis | Free |
| Maltego | Commercial | All | Link analysis | Med-High |
| Plaso/log2timeline | Open Source | All | Timeline creation | Free |

---

## 📊 Cryptography Quick Reference

| Algorithm | Type | Key Size | Security | Use Case |
|-----------|------|----------|---------|---------|
| AES-256-GCM | Symmetric | 256-bit | Excellent | Device encryption, TLS |
| ChaCha20-Poly1305 | Symmetric | 256-bit | Excellent | Mobile TLS (no AES HW) |
| RSA-2048 | Asymmetric | 2048-bit | Good | Legacy certificates |
| RSA-4096 | Asymmetric | 4096-bit | Excellent | High-value signing |
| ECC P-256 | Asymmetric | 256-bit | Excellent | TLS, mobile crypto |
| Ed25519 | Asymmetric | 256-bit | Excellent | Modern signatures |
| ECDH P-256 | Key Exchange | 256-bit | Excellent | TLS 1.3 key exchange |
| SHA-256 | Hash | 256-bit output | Secure | File integrity |
| SHA-512 | Hash | 512-bit output | Very secure | High-value hashing |
| bcrypt | Key Derivation | Variable | Secure | Password hashing |
| PBKDF2-HMAC-SHA256 | Key Derivation | Variable | Secure | Key from password |
| MD5 | Hash | 128-bit output | BROKEN | Legacy only |
| SHA-1 | Hash | 160-bit output | BROKEN | Avoid |

---

## 📊 Mobile Malware Types — Quick Reference

| Type | Propagation | Primary Goal | Example |
|------|------------|-------------|--------|
| Virus | User action on infected file | Damage/spread | Rare on mobile |
| Worm | Self-propagating, network | Spread/recruit | Cabir (2004) |
| Trojan | Social engineering install | Data theft | Cerberus, Alien |
| Ransomware | Social engineering | Extortion | Simplocker, WannaLocker |
| Spyware | Social engineering/exploit | Surveillance | Pegasus, FinFisher |
| Adware | Bundled with legit apps | Ad revenue | HummingBad |
| Cryptominer | Social engineering | Mine crypto | CoinMiner variants |
| Rootkit | Exploit + social engineering | Persist + hide | Chamois |
| Banking Trojan | Social engineering | Financial theft | EventBot, Anubis |

---

## 📊 Wi-Fi Security Protocols Comparison

| Protocol | Year | Algorithm | Security | Status |
|----------|------|----------|---------|--------|
| WEP | 1997 | RC4, 40/104-bit IV | NONE | Completely broken |
| WPA | 2003 | TKIP (RC4) | Very Low | Deprecated |
| WPA2-Personal | 2004 | AES-CCMP | Moderate | KRACK vulnerable (patched) |
| WPA2-Enterprise | 2004 | AES-CCMP + 802.1X | High | Still widely used |
| WPA3-Personal | 2018 | AES-GCMP + SAE | High | Current standard |
| WPA3-Enterprise | 2018 | AES-GCMP-256 + 802.1X | Very High | Enterprise standard |

---

## 📊 Cellular Network Security Comparison

| Generation | Auth | Mutual Auth | Encryption | IMSI Protect | Vulnerabilities |
|-----------|------|------------|-----------|-------------|----------------|
| 2G (GSM) | A3/A8 | NO | A5/1 (broken) | None | IMSI catchers, A5/1 crack |
| 3G (UMTS) | AKA | YES | KASUMI | Partial | Downgrade to 2G |
| 4G (LTE) | EPS-AKA | YES | AES-128 | Partial | IMSI in some attach msgs |
| 5G (NR) | 5G-AKA | YES | AES/ZUC-256 | SUCI (full) | Implementation issues |

---

## 📊 Evidence Admissibility Checklist

```
PRE-ACQUISITION:
  □ Legal authority obtained (warrant/consent documented)
  □ Device photographed in situ
  □ Device state documented (on/off, screen content)
  □ Network isolated (Faraday/airplane mode)
  □ Chain of custody form started

ACQUISITION:
  □ Write-blocker used (or documented reason if not)
  □ Forensic tool validated
  □ Acquisition hash computed (MD5 + SHA-256)
  □ Hash logged in chain of custody
  □ All acquisition steps documented with timestamps

ANALYSIS:
  □ Working on forensic copy (not original)
  □ All tools and versions documented
  □ All commands run documented
  □ Findings independently verifiable
  □ Alternative explanations considered

REPORTING:
  □ Executive summary (non-technical)
  □ Methodology detailed
  □ Findings clearly presented
  □ Limitations stated
  □ Hash verification appendix included
  □ All exhibits numbered and hashed
```

---

## 📊 Final Exam Priority Guide — All Units

### 🔴 Highest Priority (Most Frequently Examined)

| Topic | Key Concepts |
|-------|------------|
| Data extraction levels (L1-L5) | Manual → Logical → File System → Physical → JTAG/Chip-off |
| Mobile forensics workflow | 6 phases: Prep → ID → Preserve → Acquire → Analyze → Report |
| Android partition structure | /data, /system, /efs, boot, vendor |
| SIM card EF structure | IMSI, ICCID, LOCI, ADN, SMS, LND |
| NAND flash + FTL | Pages/blocks/planes, out-of-place writes, stale pages |
| AES encryption | Symmetric, modes (ECB/CBC/GCM), why GCM |
| Hash functions | MD5 (broken), SHA-256 (standard), forensic use |
| SS7 vulnerabilities | Location tracking, SMS interception, call forwarding |
| IMSI catchers | How they work, 2G vs 4G vs 5G |
| Mobile malware types | Virus, worm, Trojan, ransomware, spyware |
| Anti-forensics techniques | Encryption, wiping, steganography, log manipulation |
| SQLite forensics | Freelist, WAL, deleted data recovery |

### 🟡 Medium Priority

| Topic | Key Concepts |
|-------|------------|
| Asymmetric cryptography | RSA, ECC, public/private keys, digital signatures |
| PKI and TLS | Certificates, CA, TLS handshake |
| Signal protocol | Double Ratchet, PFS, E2E |
| Wi-Fi attacks | KRACK, Evil Twin, deauth, WPA3 improvements |
| ML for malware detection | Features, training, adversarial attacks |
| Data mining in forensics | Association rules, clustering, SNA |
| Cloud forensics | iCloud vs Google, legal access, ADP |
| EXIF metadata | GPS coordinates, timestamps, camera info |
| Call log database structure | SQLite tables, columns, type values |
| Incident response | NIST lifecycle, phases |

### 🟢 Also Covered

| Topic | Key Concepts |
|-------|------------|
| Diffie-Hellman | Key exchange, shared secret, ECDH |
| TEE/Secure Enclave | TrustZone, forensic impact, key protection |
| WhatsApp forensics | msgstore.db, key file, crypt15 |
| Mobile payment security | Tokenization, Secure Element, EMV |
| 5G security | SUCI/SUPI, network slicing, SA vs NSA |
| Behavioral biometrics | Features, continuous auth, attribution |
| Deepfake detection | CNN-based, temporal consistency |
| Case studies | San Bernardino, WhatsApp evidence |
| Civil litigation forensics | eDiscovery, BYOD, proportionality |
| Zero-click exploits | Pegasus, NSO Group, detection |

---

*APPENDIX COMPLETE — Units III, IV, V added with: Mobile Forensics Workflow, Data Extraction Methodologies, Mobile Device Architecture & Storage, SIM Card Forensics, Malware Types & Analysis, Cryptography (all methods), Anti-Forensics, Firewalls & IDS, Data Mining, Machine Learning, and Case Studies. Document now covers full syllabus. Last updated: May 2026.*

ENDOFAPPEND
Output

Command argument is 208_416 bytes, exceeding the 100_000-byte per-argument limit. For large content, pipe via stdin or use a file-write API instead of embedding the content inline in the command. Argument preview: "cat >> /home/claude/mobile_forensics_combined.md << 'ENDOFAPPEND'\n\n\n---\n\n---\n\n# ═══════════════════════════════════════════════════════════════\n# UNIT III — MOBILE DEVICE ANALYSIS (EXPANDED)\n# ═══════"
Done

