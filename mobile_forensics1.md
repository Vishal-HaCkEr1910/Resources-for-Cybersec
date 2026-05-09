
# 📱 Mobile Forensics — Complete Study Notes
### Units I · II · III | Book-Referenced | Industry Standard

> **Primary References:**
> - 📘 *Digital Forensic: The Fascinating World of Digital Evidences* — Nilakshi Jain & Dhananjay R. Kalbande, Wiley, 2016
> - 📗 *Mobile Forensic Investigations* — Lee Reiber, McGraw Hill, 2nd Ed., 2020
> - 📙 *Cyber Forensics* — Dejey, Oxford University Press, 1st Ed., 2018
> - 📕 *Practical Digital Forensics* — Dr. Akashdeep Bhardwaj & Keshav Kaushik, Apress, 2023
> - 📓 *Guide to Computer Forensics and Investigations* — Steuart, Nelson & Phillips, Cengage, 4th Ed., 2013

---

## 📚 Table of Contents

| # | Unit | Topic |
|---|------|-------|
| 1 | UNIT I | Overview of Mobile Forensics |
| 2 | UNIT I | Legal and Ethical Considerations |
| 3 | UNIT I | Mobile Device Architecture & Operating Systems |
| 4 | UNIT I | Mobile Device Data Types and Storage |
| 5 | UNIT I | Understanding Logical and Physical Memory |
| 6 | UNIT II | Types of Mobile Device Acquisition |
| 7 | UNIT II | Acquisition Tools and Techniques |
| 8 | UNIT II | Chip-off Acquisition |
| 9 | UNIT II | Data Recovery Methods |
| 10 | UNIT II | Challenges and Best Practices |
| 11 | UNIT III | Data Extraction and Analysis Tools |
| 12 | UNIT III | Examination of Call Logs, SMS, Contacts, Emails |
| 13 | UNIT III | Digital Media Analysis |
| 14 | UNIT III | Application Data Analysis |
| 15 | UNIT III | Cloud-Based Data Analysis |
| 16 | Q&A | Top 50 Questions (5 Marks Each) |

---

---

# ═══════════════════════════════════════
# UNIT I — INTRODUCTION TO MOBILE FORENSICS
# ═══════════════════════════════════════

---

## 1.1 Overview of Mobile Forensics

### 🔍 What Is Mobile Forensics?

Mobile forensics is a specialized branch of digital forensics that deals with the **recovery, preservation, examination, and analysis** of digital evidence from mobile devices — including smartphones, tablets, wearables, and GPS units — in a manner that is **forensically sound** and **legally admissible**.

> 📘 **Jain & Kalbande (2016)** define digital forensics as *"the science of identifying, collecting, preserving, examining and analyzing digital evidence so that it is admissible in a court of law."* Mobile forensics is the direct application of these principles to mobile platforms.

> 📗 **Lee Reiber (2020)** emphasizes that mobile forensics differs from traditional computer forensics because mobile devices are always-on, location-aware, and tightly integrated with cloud services — making them among the **richest sources of evidence** in modern investigations.

---

### 🎯 Why Mobile Forensics Matters

Mobile devices today contain:
- Personal communications (calls, SMS, chats)
- Financial transactions and banking data
- GPS and location history
- Photographs, videos, audio recordings
- Application data (social media, email, dating apps)
- Health and biometric data
- Deleted files that may still be recoverable

According to **Reiber (2020)**, over **95% of criminal investigations** in the United States involved mobile device evidence in some capacity. This number has only grown with smartphone proliferation.

---

### 🔄 The Mobile Forensics Process (PPEAAR Model)

The standard forensic process, described across all reference books, follows these phases:

```
┌─────────────────────────────────────────────────────────┐
│              MOBILE FORENSICS PROCESS FLOW              │
├──────────┬──────────────────────────────────────────────┤
│  PHASE 1 │  PREPARATION                                 │
│          │  → Obtain legal authority (warrant/consent)  │
│          │  → Prepare forensic tools and environment    │
├──────────┼──────────────────────────────────────────────┤
│  PHASE 2 │  IDENTIFICATION                              │
│          │  → Identify device make, model, OS           │
│          │  → Record IMEI, ICCID, serial number         │
├──────────┼──────────────────────────────────────────────┤
│  PHASE 3 │  PRESERVATION                                │
│          │  → Isolate device (Faraday bag / airplane)   │
│          │  → Document scene, photograph device         │
├──────────┼──────────────────────────────────────────────┤
│  PHASE 4 │  ACQUISITION                                 │
│          │  → Logical / File-System / Physical dump     │
│          │  → Hash image (MD5 / SHA-256)                │
├──────────┼──────────────────────────────────────────────┤
│  PHASE 5 │  ANALYSIS                                    │
│          │  → Parse artifacts, recover deleted data     │
│          │  → Build timelines, correlate evidence       │
├──────────┼──────────────────────────────────────────────┤
│  PHASE 6 │  REPORTING                                   │
│          │  → Write legally defensible report           │
│          │  → Present findings to court/stakeholders    │
└──────────┴──────────────────────────────────────────────┘
```

> 📓 **Steuart, Nelson & Phillips (2013)** describe this as the **"systematic investigative process"** and stress that each phase must be documented to maintain chain-of-custody.

---

### 📊 Scope and Challenges of Mobile Forensics

| Challenge | Description |
|-----------|-------------|
| **Device Diversity** | Thousands of Android models from different manufacturers |
| **OS Fragmentation** | Multiple Android versions (4.x to 15.x) with different security models |
| **Encryption** | Full-disk and file-based encryption on modern devices |
| **Cloud Integration** | Data may exist only in cloud (iCloud, Google Drive, etc.) |
| **Rapid Technology Change** | New chips, OS features, and security measures appear constantly |
| **Anti-Forensics** | Factory resets, secure erase, encrypted containers |
| **Legal Complexity** | Cross-jurisdiction, privacy laws, warrant scope |

---

## 1.2 Legal and Ethical Considerations

### ⚖️ The Legal Framework

Before touching any mobile device, an investigator **must** have proper legal authority. Without it, all evidence gathered may be inadmissible and the investigator may face criminal liability.

> 📙 **Dejey (2018)** states: *"Any evidence obtained in violation of applicable laws is not only inadmissible but may also expose the investigating agency to civil and criminal liability."*

---

### 📜 Types of Legal Authority

#### 1. Search Warrant
- Issued by a judge or magistrate
- Must specify the **device**, **location**, and **scope** of search
- Cannot search areas beyond the scope (e.g., if warrant covers device, cloud data needs separate authorization)

#### 2. Consent
- Written voluntary consent from the device owner
- Must be **informed** (person understands what they're consenting to)
- Can be withdrawn at any time before search is complete
- Document with signatures and witnesses

#### 3. Exigent Circumstances
- Emergency situations where evidence may be destroyed
- Example: Device about to be remotely wiped
- Still requires subsequent legal ratification

#### 4. Incident Response / Corporate Investigations
- Employer-owned devices typically allow forensic examination per policy
- Employee must have been notified via acceptable-use policy (AUP)

---

### 🔐 Key Legal Principles

```
┌─────────────────────────────────────────────────────────┐
│                  LEGAL PRINCIPLES TABLE                  │
├───────────────────────┬─────────────────────────────────┤
│ Principle             │ What It Means                   │
├───────────────────────┼─────────────────────────────────┤
│ Lawful Interception   │ Authorization before access      │
│ Privacy Rights        │ 4th Amendment / GDPR / IT Act   │
│ Proportionality       │ Access only what is relevant    │
│ Admissibility         │ Evidence must meet court rules  │
│ Integrity             │ Data must not be altered        │
│ Chain of Custody      │ Track evidence at all times     │
└───────────────────────┴─────────────────────────────────┘
```

---

### 🌍 International Legal Considerations

- **MLAT (Mutual Legal Assistance Treaty):** Required when evidence is in another country's jurisdiction (e.g., iCloud servers in the US, suspect in India).
- **GDPR (EU):** Personal data of EU citizens is protected; accessing it requires justification.
- **IT Act 2000 (India):** Section 65B governs admissibility of electronic records.
- **CLOUD Act (USA):** Allows US law enforcement to request data from US tech companies even if stored abroad.

---

### 🧭 Ethical Considerations

> 📕 **Bhardwaj & Kaushik (2023)** emphasize that forensic investigators carry a **dual ethical responsibility**: to the truth and to the subject's rights.

Key ethical duties:
1. **Objectivity:** Report what you find — not what you're expected to find.
2. **Minimization:** Don't access personal data beyond the investigation scope.
3. **Confidentiality:** Protect sensitive information discovered during analysis.
4. **Competence:** Only perform examinations you are qualified for.
5. **Transparency:** Fully disclose methods, tools, and limitations in your report.

---

### 📋 Chain-of-Custody Documentation Form

```
CHAIN-OF-CUSTODY FORM — MOBILE DEVICE EVIDENCE

Case Number     : ____________________
Investigator    : ____________________
Date/Time       : ____________________

DEVICE INFORMATION:
  Make/Model    : ____________________
  IMEI          : ____________________
  Serial Number : ____________________
  SIM ICCID     : ____________________
  Phone Number  : ____________________

SCENE NOTES:
  Power State   : [ ] ON  [ ] OFF  [ ] Unknown
  Screen State  : [ ] Locked  [ ] Unlocked  [ ] Damaged
  Visible Damage: ____________________
  Accessories   : ____________________

EVIDENCE HANDLING LOG:
  Time Collected: ____________________
  Collected By  : ____________________
  Transfer 1    : From _______ To _______ Time _______
  Transfer 2    : From _______ To _______ Time _______

HASH VALUES:
  MD5           : ____________________
  SHA-256       : ____________________
  Verified By   : ____________________
```

---

## 1.3 Mobile Device Architecture and Operating Systems

### 🏗️ Hardware Architecture of a Modern Smartphone

A smartphone is a complex computing system. Understanding its hardware is essential for understanding where data lives and how to access it forensically.

```
┌─────────────────────────────────────────────────────────────┐
│              SMARTPHONE HARDWARE ARCHITECTURE               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────────┐    ┌──────────────────────────────┐  │
│   │   APPLICATION     │    │        BASEBAND / MODEM      │  │
│   │   PROCESSOR (SoC) │    │  (Cellular: 2G/3G/4G/5G)    │  │
│   │  ┌─────────────┐  │    │  Separate OS, separate RAM   │  │
│   │  │  CPU Cores  │  │    │  Stores: IMEI, keys, logs   │  │
│   │  │  (ARM A-x)  │  │    └──────────────────────────────┘  │
│   │  ├─────────────┤  │                                     │
│   │  │     GPU     │  │    ┌──────────────────────────────┐  │
│   │  ├─────────────┤  │    │         MEMORY               │  │
│   │  │  Neural/AI  │  │    │  RAM: LPDDR4/5 (Volatile)    │  │
│   │  │  Engine     │  │    │  Flash: eMMC/UFS (Persistent) │  │
│   │  ├─────────────┤  │    │  Secure Element (SE/TEE)     │  │
│   │  │  TrustZone  │  │    └──────────────────────────────┘  │
│   │  │  (TEE/SE)   │  │                                     │
│   │  └─────────────┘  │    ┌──────────────────────────────┐  │
│   └──────────────────┘    │        RADIOS & I/O           │  │
│                            │  Wi-Fi, BT, NFC, GPS, USB    │  │
│                            └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

### 🔩 Key Hardware Components Explained

#### Application Processor (SoC)
The System-on-Chip (e.g., Qualcomm Snapdragon, Apple A-series, Samsung Exynos) integrates:
- **CPU cores** for general computation
- **GPU** for graphics
- **DSP/NPU** for signal and AI processing
- **Memory controller** managing RAM and flash
- **TrustZone / Secure Enclave** for hardware-backed security

#### Baseband Processor
A completely separate processor that handles all cellular communication:
- Has its own OS (often proprietary RTOS)
- Has its own memory and storage
- Stores IMEI, network keys, and communication logs
- Forensically important but very difficult to access directly

> ⚠️ **Forensic Note (Reiber, 2020):** The baseband processor is often ignored in investigations, yet it may contain evidence of calls, SMS, and network activity independent of the main OS.

#### RAM (Volatile Memory)
- **Type:** LPDDR4 or LPDDR5
- **Contents when running:** Decryption keys, running apps, network connections, clipboard, screen buffer
- **Forensic Value:** Extremely high — may contain keys that unlock encrypted storage
- **Challenge:** Lost immediately on power-off

#### Trusted Execution Environment (TEE) / Secure Enclave
- Hardware-isolated execution environment separate from main OS
- Stores: cryptographic keys, biometric templates, DRM keys, payment credentials
- **On Android:** ARM TrustZone implements TEE
- **On iOS:** Apple's Secure Enclave Processor (SEP) is a separate co-processor
- **Forensic Impact:** Even with a full NAND dump, TEE-protected data cannot be read without the device passcode

---

### 🤖 Android OS Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   ANDROID OS LAYERS                         │
├──────────┬──────────────────────────────────────────────────┤
│  LAYER 5 │ APPLICATIONS (Gmail, WhatsApp, Chrome...)        │
├──────────┼──────────────────────────────────────────────────┤
│  LAYER 4 │ APPLICATION FRAMEWORK                            │
│          │ Activity Manager, Content Providers, etc.        │
├──────────┼──────────────────────────────────────────────────┤
│  LAYER 3 │ ANDROID RUNTIME (ART) + CORE LIBRARIES           │
│          │ JVM-like runtime, Java/Kotlin libraries           │
├──────────┼──────────────────────────────────────────────────┤
│  LAYER 2 │ HARDWARE ABSTRACTION LAYER (HAL)                 │
│          │ Camera, Bluetooth, GPS HAL interfaces             │
├──────────┼──────────────────────────────────────────────────┤
│  LAYER 1 │ LINUX KERNEL                                     │
│          │ Process mgmt, memory mgmt, drivers, SELinux      │
└──────────┴──────────────────────────────────────────────────┘
```

**Key Forensic Paths on Android:**

| Data Type | File Path |
|-----------|-----------|
| SMS/MMS Database | `/data/data/com.android.providers.telephony/databases/mmssms.db` |
| Call Log | `/data/data/com.android.providers.contacts/databases/calllog.db` |
| Contacts | `/data/data/com.android.providers.contacts/databases/contacts2.db` |
| Browser History | `/data/data/com.android.browser/databases/browser.db` |
| WhatsApp Messages | `/data/data/com.whatsapp/databases/msgstore.db` |
| App Private Data | `/data/data/<package_name>/` |
| External / Shared | `/storage/emulated/0/` or `/sdcard/` |
| System Logs | `/data/log/`, `/proc/`, `/sys/` |

---

### 🍎 iOS Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      iOS OS LAYERS                          │
├──────────┬──────────────────────────────────────────────────┤
│  LAYER 4 │ COCOA TOUCH (UIKit, Swift, Obj-C frameworks)     │
├──────────┼──────────────────────────────────────────────────┤
│  LAYER 3 │ MEDIA LAYER (CoreGraphics, AVFoundation, etc.)   │
├──────────┼──────────────────────────────────────────────────┤
│  LAYER 2 │ CORE SERVICES (CoreData, CoreLocation, SQLite)   │
├──────────┼──────────────────────────────────────────────────┤
│  LAYER 1 │ DARWIN KERNEL (XNU: Mach + BSD + IOKit)          │
└──────────┴──────────────────────────────────────────────────┘
```

**Key Forensic Paths on iOS:**

| Data Type | File Path |
|-----------|-----------|
| SMS Database | `/var/mobile/Library/SMS/sms.db` |
| Call History | `/var/mobile/Library/CallHistoryDB/CallHistory.storedata` |
| Contacts | `/var/mobile/Library/AddressBook/AddressBook.sqlitedb` |
| Photos | `/var/mobile/Media/DCIM/` |
| Notes | `/var/mobile/Library/Notes/notes.sqlite` |
| Safari History | `/var/mobile/Library/Safari/History.db` |
| Keychain | `/private/var/Keychains/keychain-2.db` |
| App Containers | `/var/mobile/Containers/Data/Application/<UUID>/` |

---

## 1.4 Mobile Device Data Types and Storage

### 📂 Categories of Forensic Data

> 📗 **Reiber (2020)** classifies mobile device data into three broad categories: **active data**, **deleted data**, and **latent data**.

#### Active Data
Currently accessible files and records — what you see when you browse the device normally.
- Contacts, messages, photos, apps, settings

#### Deleted Data
Data marked as deleted by the OS but not yet overwritten.
- Recoverable from unallocated space, SQLite freelists, WAL files
- Recovery window depends on device usage after deletion

#### Latent Data
Data not directly accessible but derivable or reconstructed.
- EXIF metadata embedded in photos
- File fragments in unallocated space
- Cached thumbnails of deleted photos
- Log entries referencing deleted items

---

### 🗄️ Storage Technologies Explained

#### eMMC (embedded MultiMediaCard)
- Older flash storage standard (pre-2016 devices)
- Single data lane, slower speeds; soldered to board
- Forensically: easier chip-off due to standardized pinouts

#### UFS (Universal Flash Storage)
- Modern standard (2016 onward); multiple lanes, faster (up to 2100 MB/s)
- Forensically: harder to read raw due to complex controller

#### NAND Flash Internal Structure

```
NAND FLASH HIERARCHY:
┌───────────────────────────────────────┐
│               DEVICE                  │
│  ┌───────────┐    ┌───────────┐        │
│  │   DIE 0   │    │   DIE 1   │  ...   │
│  │ ┌───────┐ │    │ ┌───────┐ │        │
│  │ │ PLANE │ │    │ │ PLANE │ │        │
│  │ │┌─────┐│ │    │ │┌─────┐│ │        │
│  │ ││BLOCK││ │    │ ││BLOCK││ │        │
│  │ ││┌───┐││ │    │ ││┌───┐││ │        │
│  │ │││PAGE│││ │    │ │││PAGE│││ │       │
│  │ ││└───┘││ │    │ ││└───┘││ │        │
└───────────────────────────────────────┘

Hierarchy: Device → Die → Plane → Block → Page → Cell
- Pages: smallest readable unit (~4–16 KB)
- Blocks: smallest erasable unit (~256–512 pages)
- Cell types: SLC (1 bit) / MLC (2 bit) / TLC (3 bit) / QLC (4 bit)
  → SLC: fastest, most durable; QLC: densest, least durable
```

#### SIM Card Forensic Data
- **IMSI:** International Mobile Subscriber Identity (15 digits) — identifies subscriber on network
- **ICCID:** Integrated Circuit Card Identifier (19–20 digits) — identifies SIM card itself
- **EF_SMS:** Elementary File for SMS (up to 40 messages on older SIMs)
- **ADN:** Abbreviated Dialing Numbers (phonebook)
- **LOCI:** Last Location Information (last known cell tower)

> ⚠️ Modern smartphones store most data internally, not on SIM. But IMSI/ICCID are critical for linking a device to a subscriber and telecom records.

---

### 🔐 Encryption on Mobile Storage

#### Android Full-Disk Encryption (FDE) — Android 5.0 to 9
- Encrypts entire `/data` partition with a key derived from the user's PIN/password
- Key stored in TEE; without the PIN, the NAND dump is a wall of ciphertext

#### Android File-Based Encryption (FBE) — Android 7.0+
- Different files encrypted with different keys
- **CE keys** (Credential Encrypted): unlocked only after user authenticates
- **DE keys** (Device Encrypted): available at boot, before user login
- More granular — some data accessible at boot, most only after unlock

#### iOS Data Protection Classes

| Class | Name | Accessible When |
|-------|------|-----------------|
| A | Complete Protection | Only when device is unlocked |
| B | Protected Unless Open | When file was open at time of lock |
| C | Protected Until First Auth | After first unlock since reboot |
| D | No Protection | Always accessible |

> 📘 **Jain & Kalbande (2016):** *"Understanding encryption is not optional for modern mobile forensics — it is the central challenge."*

---

## 1.5 Understanding Logical and Physical Memory

### 🧠 Complete Memory Taxonomy

#### Volatile Memory (RAM) — Deep Dive

RAM is the **working memory** of a device:
- **Type used:** LPDDR4 / LPDDR5 (Low Power Double Data Rate)
- **Speed:** Nanosecond access times; ~34–51 GB/s bandwidth
- **Loses content:** Immediately on power-off

**What lives in RAM during operation:**

| RAM Contents | Forensic Significance |
|-------------|----------------------|
| Running app code and data | Active user activity |
| Decryption keys for storage | Can unlock encrypted NAND |
| Network socket buffers | Active communications |
| Clipboard contents | Recently copied data |
| Credential tokens | Login sessions |
| OS kernel structures | System state |

---

#### Physical Memory vs. Virtual Memory — Complete Explanation

##### Physical Memory
Physical memory = the **actual RAM chips** on the device motherboard. It is a finite array of memory cells. The CPU accesses it through the **memory bus** and **memory controller**.

```
PHYSICAL MEMORY LAYOUT (RAM):
┌─────────────────────────────────────┐
│       Physical Address Space        │
│  0x00000000                         │
│       ┌───────────────────┐         │
│       │   Kernel Code     │         │
│       ├───────────────────┤         │
│       │   Kernel Data     │         │
│       ├───────────────────┤         │
│       │  Process A Frames │         │
│       ├───────────────────┤         │
│       │  Process B Frames │         │
│       ├───────────────────┤         │
│       │    Free Frames    │         │
│  0xFFFFFFFF                         │
│       └───────────────────┘         │
└─────────────────────────────────────┘
```

##### Virtual Memory — How It Is Created and How It Works

Virtual memory is an **OS-level abstraction** that gives every process the illusion of having its own large, contiguous address space — even though physical RAM is shared and fragmented among many processes.

**Step-by-step construction of virtual memory:**

**Step 1 — MMU (Memory Management Unit):**
A hardware unit built into the CPU. Every time a process accesses a memory address, the MMU intercepts the virtual address and translates it to a physical address in real-time using page tables.

**Step 2 — Page Tables:**
The OS kernel maintains a **page table** for each process. A page table is a data structure that maps:
- Virtual Page Number (VPN) → Physical Frame Number (PFN)

**Step 3 — Pages and Frames:**
- Virtual address space is split into fixed-size blocks called **pages** (typically 4 KB)
- Physical RAM is split into same-sized **frames**
- The page table maps pages to frames — the mapping is dynamic and can change

**Step 4 — Demand Paging:**
Pages are only loaded into physical RAM when they are actually accessed. On first access to a new page, the CPU generates a **page fault** interrupt, the OS handles it by loading the page from disk/storage into a free frame, then updates the page table.

**Step 5 — Memory Compression (Mobile-specific):**
Mobile OSes rarely swap to disk (it's too slow and wears flash). Instead:
- **Android uses zRAM:** A compressed swap device in RAM itself. Rarely-used pages are compressed and stored in a small RAM region, freeing physical frames.
- **iOS uses compressed memory:** Similar concept — inactive pages are compressed in RAM.

```
VIRTUAL MEMORY MAPPING DIAGRAM:

 Process A                    Physical RAM
 Virtual Space                (Frames)
 ┌──────────────┐            ┌─────────────┐
 │   Page 0     │──────────→ │  Frame  5   │
 │   Page 1     │──────────→ │  Frame  2   │
 │   Page 2     │──────────→ │  Frame  9   │
 │   Page 3     │──(fault)─→ [Loaded on demand]
 └──────────────┘
                              ┌─────────────┐
 Process B                    │  Frame  1   │ ← Process B Page 0
 Virtual Space                │  Frame  3   │ ← Process B Page 1
 ┌──────────────┐             │  Frame  7   │ ← OS Kernel
 │   Page 0     │──────────→ │  Frame  1   │
 │   Page 1     │──────────→ │  Frame  3   │
 └──────────────┘            └─────────────┘

KEY INSIGHT: Both Process A and Process B have a "Page 0"
starting at virtual address 0x00000000, but they map to
completely different physical frames. This is isolation.
```

**Physical Memory vs. Virtual Memory — Comparison Table:**

| Aspect | Physical Memory | Virtual Memory |
|--------|----------------|----------------|
| **What it is** | Actual RAM silicon chips | OS software abstraction |
| **Address space size** | Fixed (= RAM capacity) | Much larger (64-bit = 16 exabytes) |
| **Unique per process?** | No — shared by all | Yes — each process has its own |
| **Appears contiguous?** | Yes | Yes (but isn't physically) |
| **Who uses addresses?** | Hardware (DMA, MMIO) | All software (processes) |
| **Forensic dump type** | Physical memory image | Cannot be dumped directly |
| **Contains encryption keys?** | Yes (in-use keys) | Process-level view of same keys |

---

#### Non-Volatile Storage (Flash Memory)

Unlike RAM, **NAND flash retains data after power is removed** — this is where file systems and long-term evidence reside.

| Property | RAM (LPDDR5) | NAND Flash (UFS 3.x) |
|----------|-------------|---------------------|
| Speed | ~51 GB/s | ~2.1 GB/s read |
| Volatile? | YES | NO |
| Write cycles | Unlimited | ~1,000–100,000 |
| Primary forensic value | Keys, active state | Long-term user data |

---

#### Acquisition Type vs. Memory Type

```
WHAT EACH ACQUISITION TYPE CAPTURES:

┌──────────────────────┬────────────────────────────────────────┐
│ ACQUISITION TYPE     │ DATA CAPTURED                          │
├──────────────────────┼────────────────────────────────────────┤
│ Logical              │ Active files only (OS-presented view)  │
│                      │ ✗ No deleted data                      │
│                      │ ✗ No unallocated space                 │
│                      │ ✗ No raw flash content                 │
├──────────────────────┼────────────────────────────────────────┤
│ File System          │ All files + filesystem metadata        │
│                      │ ✓ App private data (if root)          │
│                      │ ~ Some deleted entries                 │
│                      │ ✗ No raw flash artifacts               │
├──────────────────────┼────────────────────────────────────────┤
│ Physical             │ Bit-for-bit image of storage chip      │
│                      │ ✓ Active files                        │
│                      │ ✓ Deleted files (until overwritten)   │
│                      │ ✓ Unallocated space                   │
│                      │ ✓ Slack space, file fragments         │
├──────────────────────┼────────────────────────────────────────┤
│ RAM / Memory         │ Volatile memory snapshot               │
│                      │ ✓ Encryption keys                     │
│                      │ ✓ Running process state               │
│                      │ ✓ Network connections                 │
│                      │ Must be done BEFORE power-off         │
└──────────────────────┴────────────────────────────────────────┘
```

> 📗 **Reiber (2020):** *"The investigator must always start with the least invasive method and escalate only when necessary. This preserves evidence integrity and supports defensibility."*

---

*[End of UNIT I — Sections 1.1 through 1.5]*

---

# ═══════════════════════════════════════
# UNIT II — MOBILE DEVICE ACQUISITION
# ═══════════════════════════════════════

Acquisition is the process of creating a **forensically sound copy** of data from a mobile device. The method depends on device model, OS version, lock state, encryption, and legal constraints.

> 📗 **Reiber (2020):** *"Acquisition is the most critical phase. A mistake here cannot be undone — you only get one chance to preserve the original evidence correctly."*

---

## 2.1 Types of Mobile Device Acquisition

### The Acquisition Pyramid

```
         ┌──────────────────┐
         │   CHIP-OFF /     │  ← Most invasive, most complete
         │     JTAG         │    Destroyed device possible
         ├──────────────────┤
         │    PHYSICAL      │  ← Bit-for-bit image
         │   ACQUISITION    │    Requires deep access
         ├──────────────────┤
         │   FILE SYSTEM    │  ← All visible files + metadata
         │   ACQUISITION    │    Requires elevated access
         ├──────────────────┤
         │    LOGICAL       │  ← OS-presented data only
         │   ACQUISITION    │    Least invasive, least complete
         └──────────────────┘
```

> 📕 **Bhardwaj & Kaushik (2023):** *"Always begin with logical acquisition and escalate to more invasive methods only when required and legally authorized."*

---

### 🔵 Type 1: Logical Acquisition

**What it is:** Uses OS-level APIs, backup protocols, and synchronization interfaces to extract data the OS presents.

**What you get:**
- ✅ Contacts, SMS, call logs, calendars, media files
- ❌ Deleted data, unallocated space, app-private data protected from backup

**Android Logical — ADB commands:**
```bash
# Check connected devices
adb devices

# Pull shared storage
adb pull /sdcard/DCIM/ ./output/DCIM/

# Create full backup (Android < 12)
adb backup -apk -shared -all -f full_backup.ab

# Unpack backup to tar
java -jar abe.jar unpack full_backup.ab backup_extracted.tar
```

**iOS Logical — libimobiledevice:**
```bash
ideviceinfo                                    # device info
idevicebackup2 backup --full ./ios_backup/    # full backup
```

---

### 🟡 Type 2: File System Acquisition

**What it is:** Accesses the file system directly — bypassing OS access controls — to extract all files including app-private data and system files. Requires root (Android) or jailbreak (iOS).

**What you get over logical:**
- ✅ App-private databases (WhatsApp, Telegram, etc.)
- ✅ System logs, file metadata (timestamps)
- ❌ Still no unallocated space or deleted files

**Android File System (rooted):**
```bash
# Pull entire /data/data
adb shell "su -c 'tar -czf /sdcard/data_backup.tar.gz /data/data/'"
adb pull /sdcard/data_backup.tar.gz ./output/

# Image a single partition
adb shell "su -c 'dd if=/dev/block/by-name/userdata of=/sdcard/userdata.img'"
adb pull /sdcard/userdata.img ./output/
```

---

### 🔴 Type 3: Physical Acquisition

**What it is:** Bit-for-bit, sector-by-sector copy of the entire storage chip — the gold standard of mobile forensics.

```
PHYSICAL ACQUISITION METHODS:
┌──────────────────────────────────────────────────────────────┐
│ METHOD          │ HOW IT WORKS              │ INVASIVENESS  │
├─────────────────┼───────────────────────────┼───────────────┤
│ dd (via ADB)    │ Use dd on rooted device   │ Low-Medium    │
│ Bootloader      │ Boot forensic image       │ Medium        │
│ EDL Mode        │ Qualcomm Emergency DL     │ Medium        │
│ JTAG            │ Debug port memory access  │ High          │
│ Chip-Off        │ Remove chip, read raw     │ Very High     │
│ ISP             │ In-System Programming     │ High          │
└──────────────────────────────────────────────────────────────┘
```

**Using dd (rooted Android):**
```bash
# Find block device
adb shell "ls -la /dev/block/by-name/" | grep userdata

# Image it
adb shell "su -c 'dd if=/dev/block/mmcblk0 bs=512'" | dd of=./full_image.dd

# Hash immediately
sha256sum full_image.dd > full_image.sha256
```

---

### ⚫ Type 4: JTAG Acquisition

**What it is:** Uses JTAG debug interface (IEEE 1149.1 standard) present on most SoCs to directly access memory content via test points on the PCB.

```
JTAG ACQUISITION STEPS:
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Identify JTAG test points on PCB (via docs/X-ray)   │
│ Step 2: Solder fine wires to JTAG pins (TDI,TDO,TCK,TMS)   │
│ Step 3: Connect to JTAG adapter (Riff Box, JTAG Pro, etc.)  │
│ Step 4: Load device-specific profile in forensic tool       │
│ Step 5: Extract memory dump via JTAG interface              │
│ Step 6: Hash dump and begin analysis                        │
└─────────────────────────────────────────────────────────────┘
```

**Advantages:** Works on locked/broken-screen devices; does not modify storage.
**Disadvantages:** Requires soldering precision; device-specific knowledge required.

---

## 2.2 Acquisition Tools and Techniques

### 🛠️ Commercial Tools

| Tool | Vendor | Strengths |
|------|--------|-----------|
| **Cellebrite UFED** | Cellebrite | Widest device support, physical+logical+cloud |
| **Magnet AXIOM** | Magnet Forensics | Excellent analysis, cloud acquisition |
| **Oxygen Forensic Detective** | Oxygen Forensics | Strong app analysis, cloud support |
| **MSAB XRY** | MSAB | Strong iOS support, good reporting |
| **GrayKey** | Grayshift | iOS passcode bypass (law enforcement only) |

> 📘 **Jain & Kalbande (2016):** *"Commercial tools provide validated, court-accepted methods. Always verify the tool has been validated against known test images before using in live investigations."*

---

### 🔧 Open-Source Tools

| Tool | Use |
|------|-----|
| **ADB / Fastboot** | Android device communication and imaging |
| **libimobiledevice** | iOS communication (idevicebackup2) |
| **Autopsy + Sleuth Kit** | Full forensic analysis suite |
| **Bulk Extractor** | Fast artifact extraction from images |
| **PhotoRec / Scalpel** | File carving from raw images |
| **SQLite Browser** | Visual inspection of SQLite databases |
| **ExifTool** | Media metadata extraction |
| **Plaso / log2timeline** | Timeline creation |

---

### 🔄 Acquisition Decision Flowchart

```
DEVICE RECEIVED — WHAT TO DO?
                │
         ┌──────▼──────┐
         │ Is device   │
         │  powered ON?│
         └──────┬──────┘
          YES   │    NO
    ┌───────────┘    └────────────────────┐
    ▼                                     ▼
Is it unlocked?              Do NOT power on.
    │                        Faraday bag.
  YES │   NO                 Assess JTAG/Chip-off.
    ▼   ▼
Capture RAM      Note lock type
then FS/Logical  Seek warrant +
acquisition      vendor/cloud
```

---

## 2.3 Chip-off Acquisition

### 🔬 What Is Chip-Off?

Chip-off physically removes the NAND flash chip from the PCB and reads its raw contents with a specialized reader. Last resort — most invasive.

> 📙 **Dejey (2018):** *"Chip-off is destructive by nature. It must only be used when all other methods have been exhausted and proper authorization obtained."*

**Equipment Required:**
```
CHIP-OFF LAB SETUP:
  • Hot air rework station (BGA: 350–400°C)
  • Infrared preheating station (prevents thermal shock)
  • Anti-static mat, wrist strap, flux, tweezers
  • NAND chip reader (UP-818P, MEDUSA Pro, Hydra)
  • BGA reballing kit (for chip re-installation)
  • Microscope for inspection
  • Vendor-specific NAND analysis software
```

**Step-by-Step Process:**
```
STEP 1: DOCUMENTATION
  → Photograph all sides; record IMEI, model, serial

STEP 2: DISASSEMBLY
  → Remove cover, battery, SIM, SD card
  → Photograph PCB; identify NAND chip

STEP 3: THERMAL PREP
  → Apply flux to chip BGA pads
  → Preheat board to ~150°C (prevents cracking)

STEP 4: CHIP REMOVAL
  → Hot air at 350–380°C until solder reflows
  → Lift chip gently with tweezers

STEP 5: CLEANING
  → Remove excess solder; inspect under microscope

STEP 6: READING
  → Place chip in reader socket
  → Configure for chip geometry
  → Read and verify (re-read to confirm)

STEP 7: RECONSTRUCTION
  → Apply FTL reverse-mapping
  → ECC processing
  → Reconstruct filesystem partitions
  → Hash all output images
```

---

### ⚡ Flash Translation Layer (FTL) — Why It Matters

```
FTL SITS BETWEEN OS AND PHYSICAL NAND:

    OS (logical view)          Physical NAND
    LBA 0 → /system/           Physical Page 847
    LBA 1 → /data/app/         Physical Page 23
    LBA 2 → [DELETED]          Physical Page 512 (may still have data!)
                    ↑
              FTL manages this mapping
              including wear leveling,
              bad block remapping,
              and garbage collection
```

**FTL Responsibilities:**
1. **Wear Leveling** — spreads writes evenly; prevents early block death
2. **Bad Block Management** — maps around dead blocks
3. **Garbage Collection** — reclaims erased blocks (may destroy deleted data)
4. **ECC** — detects and corrects NAND bit errors

> ⚠️ A raw chip-off dump shows physical page order, NOT logical filesystem order. Vendor-specific FTL tools or reverse-engineering required to reconstruct filesystem.

---

## 2.4 Data Recovery Methods

### 🔍 File Carving

Recovers files from raw data by searching for known **file signatures (magic bytes)** without filesystem metadata.

```
FILE CARVING — HOW IT WORKS:

Raw image: [....FF D8 FF .....JPEG data.....FF D9....]
                 ↑ JPEG Header              ↑ JPEG Footer
                 └──────────── extract ─────┘

Common Signatures:
┌───────────┬──────────────────────┬────────────────────┐
│ File Type │ Header (hex)         │ Footer (hex)       │
├───────────┼──────────────────────┼────────────────────┤
│ JPEG      │ FF D8 FF             │ FF D9              │
│ PNG       │ 89 50 4E 47 0D 0A    │ 49 45 4E 44 AE 42  │
│ PDF       │ 25 50 44 46          │ 25 25 45 4F 46     │
│ MP4       │ 66 74 79 70          │ (size-based)       │
│ ZIP/APK   │ 50 4B 03 04          │ 50 4B 05 06        │
│ SQLite DB │ 53 51 4C 69 74 65    │ (size-based)       │
└───────────┴──────────────────────┴────────────────────┘
```

**Scalpel (carving):**
```bash
scalpel -c scalpel.conf -o ./carved_output/ image.dd
```

**PhotoRec (carving):**
```bash
photorec image.dd   # interactive mode
```

---

### 🗃️ SQLite Database Recovery

SQLite is used by virtually every app on Android and iOS for structured data.

**SQLite File Structure (forensically annotated):**
```
┌─────────────────────────────────────────────────────┐
│  HEADER (100 bytes)                                 │
│  Magic: "SQLite format 3\000" → verify authenticity │
├─────────────────────────────────────────────────────┤
│  B-TREE PAGES → active records                      │
├─────────────────────────────────────────────────────┤
│  FREELIST PAGES ← 🔑 FORENSIC GOLD                  │
│  Released after DELETE; may still hold row data     │
├─────────────────────────────────────────────────────┤
│  WAL FILE (.db-wal)                                 │
│  Recent uncommitted changes — old + new row data    │
├─────────────────────────────────────────────────────┤
│  JOURNAL FILE (.db-journal)                         │
│  Pre-modification data for rollback                 │
└─────────────────────────────────────────────────────┘
```

**Recovery with sqlite3:**
```bash
sqlite3 sms.db

.schema sms                        # view table structure
SELECT rowid, address, date, body FROM sms;   # active records
PRAGMA freelist_count;             # higher = more deleted data
PRAGMA page_count;
```

> 📓 **Steuart, Nelson & Phillips (2013):** *"SQLite forensics requires examining not just active data pages but also WAL, journal, and free pages. Deleted rows often remain in free pages until reclaimed."*

---

## 2.5 Challenges and Best Practices

### 🚧 Major Challenges

| Challenge | Details |
|-----------|---------|
| **Device Lock + Encryption** | NAND dump is ciphertext without passcode |
| **Android Fragmentation** | 1000+ device models, custom ROMs, different schemas |
| **Anti-Forensics** | Factory reset, secure wipe, remote wipe via MDM |
| **Cloud Dependency** | Critical evidence may be server-side only |
| **Fast OS Updates** | Exploits patched quickly; tools lag behind |

---

### ✅ Complete Best Practices Checklist

> 📘 **Jain & Kalbande (2016) + Reiber (2020):**

```
ON-SCENE:
  □ Photograph device in situ before touching
  □ Note ALL visible info on screen
  □ Do NOT plug in charger (may trigger trust prompts)
  □ Do NOT accept fingerprint unlock prompts
  □ Record IMEI (*#06#)
  □ Remove SIM + SD card into separate evidence bags
  □ Place device in Faraday bag OR airplane mode
  □ Complete chain-of-custody form

IN-LAB:
  □ Work in isolated network environment
  □ Use validated, version-tracked tools
  □ Start with least-invasive method
  □ Hash images BEFORE and AFTER all steps
  □ Work ONLY on copies, never originals
  □ Log every command with timestamps

REPORTING:
  □ Include full tool versions and settings
  □ Include all hash values
  □ State clearly what could NOT be recovered
  □ Peer-review report before submission
```

---

### 🔋 Faraday Bag Decision Matrix

```
Situation                 │ Action
──────────────────────────┼──────────────────────────────────────
Device ON, UNLOCKED       │ Capture screen first. Consider RAM.
                          │ Then isolate.
Device ON, LOCKED         │ Immediate Faraday bag.
Device OFF                │ Keep off. Store in Faraday bag.
MDM-enrolled device       │ Immediate Faraday (MDM can wipe).
Device in active call     │ Let complete if evidence value.
                          │ Document call. Then isolate.
```

> ⚠️ **Reiber (2020):** *"A Faraday bag does not stop battery drain. Provide power inside the Faraday enclosure or risk device powering off."*

---

*[End of UNIT II — Sections 2.1 through 2.5]*

---

# UNIT III — MOBILE DEVICE ANALYSIS 🔬

> **Scope:** UNIT III covers how acquired data is examined and interpreted. It spans tool selection and workflow, parsing call/SMS/contact/email artifacts, digital media forensics, application-level data analysis, cloud forensics, timeline construction, and court-ready reporting. Every step is grounded in the five reference textbooks.

---

## § 3.1 — Data Extraction and Analysis Tools

### 3.1.1 Why Tool Selection Matters

Selecting the right tool chain directly affects what evidence you can surface and whether courts will accept it. Three criteria drive selection (📗 Reiber 2020, Ch. 4):

1. **Validation** — tool must be tested against known datasets (NIST CFReDS) before operational use.
2. **Repeatability** — same image + same tool + same settings → same output every run.
3. **Documentation** — tool version, license, command-line options, and output hash must all be logged.

> 📘 *Jain & Kalbande (2016):* "Forensic tools must be validated using standard reference data sets so that the examiner can testify to the tool's accuracy."

---

### 3.1.2 Commercial Forensic Suites

```
┌─────────────────────────────────────────────────────────────────┐
│              COMMERCIAL MOBILE FORENSIC SUITES                  │
├──────────────────┬──────────────────────────────────────────────┤
│ Tool             │ Key Capabilities                             │
├──────────────────┼──────────────────────────────────────────────┤
│ Cellebrite UFED  │ Physical/logical/cloud extraction; 30,000+   │
│                  │ device profiles; UFED Analytics for AI-based │
│                  │ entity extraction; hash verification         │
├──────────────────┼──────────────────────────────────────────────┤
│ Magnet AXIOM     │ Unified artifact view; cloud acquisition;    │
│                  │ AI-assisted review; SQLite carving built-in  │
├──────────────────┼──────────────────────────────────────────────┤
│ Oxygen Forensic  │ Drone forensics; messenger decryption;       │
│ Detective        │ cloud token-based acquisition; password      │
│                  │ recovery module                              │
├──────────────────┼──────────────────────────────────────────────┤
│ MSAB XRY         │ Hardware-in-loop acquisition; XRY CLOUD for  │
│                  │ cloud data; Court XML report format          │
├──────────────────┼──────────────────────────────────────────────┤
│ Belkasoft        │ App artifact parsing; AI-powered chat        │
│ Evidence Center  │ analysis; SQLite + plist + LevelDB support   │
└──────────────────┴──────────────────────────────────────────────┘
```

> 📗 *Reiber (2020):* "No single tool covers every device or every artifact class. Build a validated toolkit of complementary tools."

---

### 3.1.3 Open-Source and Free Tools

```
┌──────────────────────────────────────────────────────────────────┐
│               OPEN-SOURCE FORENSIC TOOL STACK                   │
├───────────────────┬──────────────────────────────────────────────┤
│ Tool              │ Role                                         │
├───────────────────┼──────────────────────────────────────────────┤
│ Autopsy           │ GUI front-end for Sleuth Kit; timeline,      │
│ (+ Sleuth Kit)    │ keyword search, hash DB, module plugins       │
├───────────────────┼──────────────────────────────────────────────┤
│ ADB / fastboot    │ Android device access (USB debugging mode)   │
├───────────────────┼──────────────────────────────────────────────┤
│ libimobiledevice  │ iOS device backup, crash log, app data       │
│                   │ extraction without iTunes                    │
├───────────────────┼──────────────────────────────────────────────┤
│ sqlite3 (CLI)     │ Direct SQLite query; schema inspection;      │
│                   │ WAL and journal analysis                     │
├───────────────────┼──────────────────────────────────────────────┤
│ ExifTool          │ Read/write/parse metadata from 200+ formats  │
├───────────────────┼──────────────────────────────────────────────┤
│ Plaso / log2tl    │ Ingest 30+ artifact types into supertimeline │
├───────────────────┼──────────────────────────────────────────────┤
│ Bulk Extractor    │ Carve emails, URLs, credit cards from raw    │
│                   │ images without file-system parsing           │
├───────────────────┼──────────────────────────────────────────────┤
│ scalpel / photorec│ Header-footer file carving                   │
├───────────────────┼──────────────────────────────────────────────┤
│ strings + grep    │ Quick pattern search in binaries/raw images  │
├───────────────────┼──────────────────────────────────────────────┤
│ Wireshark / tshark│ PCAP analysis; DNS, HTTP, TLS metadata       │
└───────────────────┴──────────────────────────────────────────────┘
```

> 📙 *Dejey (2018):* "Open-source tools must be validated before court use just as commercial tools are — publish test results in your case notes."

---

### 3.1.4 Analysis Workflow (Step-by-Step)

```
  ┌──────────────────────────────────────────────────────────┐
  │                ANALYSIS WORKFLOW                         │
  │                                                          │
  │  1. RECEIVE IMAGE                                        │
  │     └─ Verify SHA-256 hash against acquisition record    │
  │                                                          │
  │  2. MOUNT / PARSE                                        │
  │     └─ Load into Autopsy or AXIOM; do NOT modify        │
  │        original — always work on verified copy           │
  │                                                          │
  │  3. FILE SYSTEM TRIAGE                                   │
  │     └─ Identify OS version, partition layout,            │
  │        encryption state, key artifact directories        │
  │                                                          │
  │  4. ARTIFACT EXTRACTION                                  │
  │     ├─ Databases (SQLite): SMS, calls, contacts, apps    │
  │     ├─ Media (JPEG, MP4): EXIF, GPS, thumbnails          │
  │     ├─ Logs: system, crash, app, network                 │
  │     └─ Cloud tokens / OAuth credentials                  │
  │                                                          │
  │  5. DELETED DATA RECOVERY                                │
  │     ├─ SQLite freelist / WAL carving                     │
  │     └─ Raw image file carving (scalpel / photorec)       │
  │                                                          │
  │  6. TIMELINE CONSTRUCTION                                │
  │     └─ Merge all timestamps → Plaso supertimeline        │
  │                                                          │
  │  7. REPORTING                                            │
  │     └─ Structured report with hashes, exhibits, limits   │
  └──────────────────────────────────────────────────────────┘
```

> 📓 *Steuart, Nelson & Phillips (2013):* "The analysis phase must be systematic and repeatable. An examiner who cannot reproduce their own findings cannot defend them."

---

### 3.1.5 Loading an Image into Autopsy (Detailed Steps)

```bash
# Step 1 — Hash verify before loading
sha256sum /evidence/device_physical.dd
# compare output to acquisition hash log

# Step 2 — Launch Autopsy (CLI headless mode)
autopsy --nogui

# Step 3 — Create a new case (GUI) or from CLI:
# Cases → New Case → set Case Name, Base Directory, Case Number

# Step 4 — Add Data Source → Disk Image → browse to .dd file
# Autopsy auto-detects partitions, volumes, file systems

# Step 5 — Select Ingest Modules:
#   ✓ Hash Lookup (NSRL known-good database)
#   ✓ Keyword Search
#   ✓ Android Analyzer
#   ✓ EXIF Parser
#   ✓ Recent Activity

# Step 6 — After ingest, export artifacts to CSV/Excel for reporting
```

> 📕 *Bhardwaj & Kaushik (2023):* "Always verify image hash before loading into any analysis platform. A corrupted image produces unreliable results that can lead to wrongful conclusions."

---

## § 3.2 — Examination of Call Logs, SMS/MMS, Contacts & Emails

### 3.2.1 How Call Logs Work Internally

Every phone maintains a **call log database** updated by the telephony stack after each call event. Understanding its schema is essential.

#### Android Call Log Architecture

```
  Android Telephony Stack
       │
       ▼
  CallLogProvider (ContentProvider)
       │
       ▼
  /data/data/com.android.providers.contacts/databases/
       ├── calllog.db       ← primary call history
       └── contacts2.db     ← contacts (linked by number)

  calllog.db → TABLE: calls
  ┌──────────────┬────────────────────────────────────────────────┐
  │ Column       │ Meaning                                        │
  ├──────────────┼────────────────────────────────────────────────┤
  │ _id          │ Auto-increment primary key                     │
  │ number       │ Remote phone number (may be null for unknown)  │
  │ date         │ Unix epoch in milliseconds (UTC)               │
  │ duration     │ Call length in seconds                         │
  │ type         │ 1=Incoming 2=Outgoing 3=Missed 4=Voicemail     │
  │              │ 5=Rejected 6=Blocked                           │
  │ name         │ Cached contact name at time of call            │
  │ geocoded_loc │ Carrier-derived city/country                   │
  │ subscription_│ Which SIM slot (dual-SIM phones)               │
  │ id           │                                                │
  │ is_read      │ 0=unread  1=read (for missed/voicemail)        │
  └──────────────┴────────────────────────────────────────────────┘
```

**Forensic query to extract all calls sorted by time:**
```sql
-- Open calllog.db with sqlite3
.open calllog.db
.headers on
.mode column

SELECT
    _id,
    number,
    name,
    datetime(date/1000, 'unixepoch', 'localtime') AS call_time,
    duration || ' sec'                             AS duration,
    CASE type
        WHEN 1 THEN 'INCOMING'
        WHEN 2 THEN 'OUTGOING'
        WHEN 3 THEN 'MISSED'
        WHEN 4 THEN 'VOICEMAIL'
        WHEN 5 THEN 'REJECTED'
        WHEN 6 THEN 'BLOCKED'
        ELSE 'UNKNOWN'
    END                                            AS call_type,
    geocoded_location
FROM calls
ORDER BY date DESC;
```

> 📗 *Reiber (2020):* "Call duration of zero for an 'INCOMING' type entry strongly suggests the call was rejected or unanswered — never assume it was answered."

---

#### iOS Call Log Architecture

```
  iOS CallKit / Phone.app
       │
       ▼
  /private/var/mobile/Library/
       └── CallHistoryDB/
               └── CallHistory.storedata   ← SQLite

  TABLE: ZCALLRECORD
  ┌──────────────────┬─────────────────────────────────────────────┐
  │ Column           │ Meaning                                     │
  ├──────────────────┼─────────────────────────────────────────────┤
  │ Z_PK             │ Primary key                                 │
  │ ZADDRESS         │ Remote number or handle                     │
  │ ZDURATION        │ Seconds (float)                             │
  │ ZDATE            │ Apple epoch (seconds since 2001-01-01 UTC)  │
  │ ZORIGINATED      │ 1=Outgoing  0=Incoming                      │
  │ ZANSWERED        │ 1=Answered  0=Missed/Rejected               │
  │ ZCALLTYPE        │ 1=Phone  8=FaceTime Audio  16=FaceTime Video│
  │ ZSERVICE_PROVIDER│ "com.apple.facetime" etc.                   │
  └──────────────────┴─────────────────────────────────────────────┘
```

**Apple epoch conversion:**
```sql
-- Apple uses seconds since 2001-01-01, not Unix (1970-01-01)
-- Offset = 978307200 seconds

SELECT
    ZADDRESS,
    ZDURATION || ' sec'                                     AS duration,
    datetime(ZDATE + 978307200, 'unixepoch', 'localtime')  AS call_time,
    CASE ZORIGINATED WHEN 1 THEN 'OUTGOING' ELSE 'INCOMING' END AS direction,
    CASE ZANSWERED   WHEN 1 THEN 'ANSWERED' ELSE 'MISSED'   END AS status,
    CASE ZCALLTYPE
        WHEN 1  THEN 'Phone'
        WHEN 8  THEN 'FaceTime Audio'
        WHEN 16 THEN 'FaceTime Video'
        ELSE 'Other'
    END AS call_type
FROM ZCALLRECORD
ORDER BY ZDATE DESC;
```

> 📘 *Jain & Kalbande (2016):* "The Apple CoreData epoch difference is a common source of timestamp errors in iOS forensics. Always verify with at least two independent sources."

---

### 3.2.2 SMS and MMS Forensics

#### Android SMS/MMS Database

```
  /data/data/com.android.providers.telephony/databases/
       └── mmssms.db

  Key Tables:
  ┌──────────────┬──────────────────────────────────────────────────┐
  │ Table        │ Contents                                         │
  ├──────────────┼──────────────────────────────────────────────────┤
  │ sms          │ SMS messages (body, address, date, type, read)   │
  │ pdu          │ MMS protocol data units (message parts)          │
  │ addr         │ MMS address entries (To/From/CC/BCC per message) │
  │ part         │ MMS parts: text bodies + media attachments       │
  │ threads      │ Conversation groupings (thread_id links sms/pdu) │
  │ canonical_   │ Phone number → canonical address mapping         │
  │ addresses    │                                                  │
  └──────────────┴──────────────────────────────────────────────────┘
```

**SMS schema deep dive:**
```sql
.open mmssms.db
.schema sms

-- Relevant columns:
-- _id       : row id
-- thread_id : conversation thread
-- address   : sender/recipient number
-- date      : Unix ms (UTC for sent/received at server)
-- date_sent : Unix ms when client sent (may differ from date)
-- body      : message text (plaintext if not E2E encrypted)
-- type      : 1=Received  2=Sent  3=Draft  4=Outbox  5=Failed
-- read      : 0=unread  1=read
-- status    : -1=none  0=Complete  32=Pending  64=Failed (delivery)
-- locked    : 1=user-locked (cannot be auto-deleted)
-- error_code: non-zero = delivery failure code

SELECT
    _id,
    address,
    datetime(date/1000,'unixepoch','localtime') AS msg_time,
    CASE type
        WHEN 1 THEN 'RECEIVED'
        WHEN 2 THEN 'SENT'
        WHEN 3 THEN 'DRAFT'
        WHEN 4 THEN 'OUTBOX (unsent)'
        WHEN 5 THEN 'FAILED'
    END AS direction,
    body
FROM sms
ORDER BY date DESC;
```

> 📙 *Dejey (2018):* "Draft messages (type=3) are critical — they may contain intended communications that were never sent, revealing state of mind."

#### Recovering Deleted SMS Rows

```
  SQLite Deletion Mechanism:
  ─────────────────────────────────────────────────────────────
  Normal DELETE FROM sms WHERE _id = X;
       │
       ▼
  Row removed from B-tree but page NOT immediately zeroed.
  Page added to freelist if fully empty, or left as unallocated
  slack within a partially-full page.
       │
       ▼
  Recovery approach:
  ┌─────────────────────────────────────────────────────────┐
  │ 1. Copy mmssms.db out of image (work on copy)          │
  │ 2. Open in hex editor — locate page boundaries         │
  │    (SQLite page size stored at offset 16 of DB header) │
  │ 3. Scan freelist pages for row patterns                │
  │ 4. Use SQLite recovery tools (e.g., sqliterecovery,    │
  │    undark, sqlite-parser) to extract deleted rows      │
  │ 5. Also examine WAL file (mmssms.db-wal) — contains    │
  │    recent uncommitted or checkpointed transactions     │
  │ 6. Hash both DB and WAL before and after analysis      │
  └─────────────────────────────────────────────────────────┘
```

**WAL file inspection:**
```bash
# Check if WAL exists
ls -la /path/to/mmssms.db-wal

# Inspect WAL header (first 32 bytes)
xxd /path/to/mmssms.db-wal | head -4

# Use sqliterecovery Python tool
pip install sqlite-dissect
sqlite-dissect --export-csv /output/ /path/to/mmssms.db
```

> 📕 *Bhardwaj & Kaushik (2023):* "The WAL file is one of the most overlooked recovery sources. Always check for -wal and -shm companion files alongside every SQLite database."

---

#### iOS SMS Architecture

```
  /private/var/mobile/Library/SMS/
       ├── sms.db          ← primary message database
       └── Attachments/    ← MMS/iMessage media files

  sms.db Key Tables:
  ┌──────────────┬──────────────────────────────────────────────────┐
  │ Table        │ Contents                                         │
  ├──────────────┼──────────────────────────────────────────────────┤
  │ message      │ All SMS + iMessage rows                          │
  │ chat         │ Conversation threads                             │
  │ handle       │ Phone numbers / Apple IDs                        │
  │ attachment   │ Media files linked to messages                   │
  │ chat_message_│ Many-to-many: message ↔ chat mapping            │
  │ join         │                                                  │
  └──────────────┴──────────────────────────────────────────────────┘

  message table key columns:
  ─ rowid / ROWID     : primary key
  ─ text              : message body
  ─ date              : Apple epoch nanoseconds (÷ 1e9 + 978307200 for Unix)
  ─ date_read         : when recipient read the message
  ─ date_delivered    : delivery confirmation timestamp
  ─ is_from_me        : 1=sent by device owner  0=received
  ─ is_read           : 1=read
  ─ service           : 'SMS' or 'iMessage'
  ─ handle_id         : foreign key → handle.rowid (sender/recipient)
  ─ cache_has_attachments : 1=has media
```

```sql
-- iOS: Full conversation reconstruction with participant
SELECT
    m.rowid,
    h.id                                                       AS participant,
    CASE m.is_from_me WHEN 1 THEN 'ME → '||h.id
                      ELSE h.id||' → ME' END                  AS direction,
    datetime(m.date/1000000000 + 978307200,'unixepoch','localtime') AS msg_time,
    m.text,
    m.service,
    CASE m.cache_has_attachments WHEN 1 THEN 'YES' ELSE 'NO' END AS has_media
FROM message m
LEFT JOIN handle h ON m.handle_id = h.rowid
ORDER BY m.date ASC;
```

---

### 3.2.3 Contacts Forensics

#### Android Contacts Database

```
  /data/data/com.android.providers.contacts/databases/
       └── contacts2.db

  Key Tables:
  ┌──────────────────┬──────────────────────────────────────────────┐
  │ Table            │ Contents                                     │
  ├──────────────────┼──────────────────────────────────────────────┤
  │ contacts         │ Aggregate contact records                    │
  │ raw_contacts     │ Per-account contact data (Google, device)    │
  │ data             │ Actual values (phone, email, name, address)  │
  │ mimetypes        │ Maps mimetype_id → string                    │
  │ accounts         │ Sync accounts (Google accounts)              │
  │ deleted_contacts │ Soft-deleted contacts (tombstone entries!)   │
  └──────────────────┴──────────────────────────────────────────────┘
```

> 📗 *Reiber (2020):* "The `deleted_contacts` table is forensic gold — Android keeps soft-delete tombstones with timestamps for sync purposes. Check this FIRST."

```sql
-- Extract all deleted contacts with deletion timestamp
SELECT
    _id,
    contact_id,
    datetime(deleted_contact_id,'unixepoch','localtime') AS deleted_at
FROM deleted_contacts;

-- Extract full contact details
SELECT
    rc.display_name_primary AS name,
    d.data1                  AS value,
    mt.mimetype              AS type,
    datetime(d.data_version,'unixepoch') AS last_modified
FROM raw_contacts rc
JOIN data d        ON d.raw_contact_id = rc._id
JOIN mimetypes mt  ON mt._id = d.mimetype_id
WHERE mt.mimetype IN (
    'vnd.android.cursor.item/phone_v2',
    'vnd.android.cursor.item/email_v2',
    'vnd.android.cursor.item/postal-address_v2'
)
ORDER BY rc.display_name_primary;
```

---

### 3.2.4 Email Forensics on Mobile

```
  Email Artifact Locations:
  ┌──────────────────┬─────────────────────────────────────────────┐
  │ App              │ Artifact Path / Format                      │
  ├──────────────────┼─────────────────────────────────────────────┤
  │ Gmail (Android)  │ /data/data/com.google.android.gm/databases/ │
  │                  │   mailstore.<account>.db  (SQLite)          │
  ├──────────────────┼─────────────────────────────────────────────┤
  │ iOS Mail         │ /private/var/mobile/Library/Mail/           │
  │                  │   Envelope Index (SQLite)                   │
  │                  │   <UUID>.mbox/  (individual messages)       │
  ├──────────────────┼─────────────────────────────────────────────┤
  │ Outlook (Android)│ /data/data/com.microsoft.office.outlook/    │
  │                  │   databases/  (proprietary + SQLite mix)    │
  └──────────────────┴─────────────────────────────────────────────┘
```

**Key fields to extract from email databases:**
- `from_address`, `to_address`, `cc_address`, `bcc_address`
- `subject`, `body_text` / `body_html` (may be cached)
- `date_received`, `date_sent` — watch for server vs. local time
- `read_state`, `flagged`, `deleted` (soft-delete flags)
- `message_id` header — globally unique; links to server copies
- `attachment_count`, attachment filenames

> 📘 *Jain & Kalbande (2016):* "Email headers contain the full routing path of a message. The `Received:` header chain can prove server hops, timestamps, and originating IP addresses."

---

## § 3.3 — Digital Media Analysis (Photos, Videos, Audio)

### 3.3.1 EXIF Metadata Deep Dive

EXIF (Exchangeable Image File Format) embeds metadata inside JPEG, TIFF, RAW, and some PNG/HEIC files. It is written by camera firmware at the moment of capture and may include GPS coordinates, device identifiers, and scene parameters.

```
  EXIF Structure inside a JPEG file:
  ─────────────────────────────────────────────────────────────────
  [SOI Marker: FF D8]
  [APP1 Marker: FF E1] ← EXIF data segment
      ├── EXIF Header ("Exif\0\0")
      ├── TIFF Header (byte order + IFD0 offset)
      │   IFD0 (Image File Directory — main image)
      │   ├── Tag 0x010F: Make           = "Apple"
      │   ├── Tag 0x0110: Model          = "iPhone 14 Pro"
      │   ├── Tag 0x0132: DateTime       = "2025:08:15 14:22:05"
      │   └── Offset → Sub-IFD (Exif IFD)
      │       ├── Tag 0x9003: DateTimeOriginal
      │       ├── Tag 0x9004: DateTimeDigitized
      │       ├── Tag 0x8827: ISOSpeedRatings
      │       ├── Tag 0x920A: FocalLength
      │       └── Tag 0x9286: UserComment
      └── GPS IFD (if location enabled)
          ├── Tag 0x0001: GPSLatitudeRef  = "N"
          ├── Tag 0x0002: GPSLatitude     = [37, 46, 29.12]
          ├── Tag 0x0003: GPSLongitudeRef = "W"
          ├── Tag 0x0004: GPSLongitude    = [122, 25, 9.88]
          ├── Tag 0x0005: GPSAltitudeRef  = 0 (above sea level)
          ├── Tag 0x0006: GPSAltitude     = 52.3 m
          └── Tag 0x001D: GPSDateStamp    = "2025:08:15"
  [SOS / Image Data: FF DA ...]
  [EOI Marker: FF D9]
```

> 📙 *Dejey (2018):* "GPS coordinates inside EXIF use degrees-minutes-seconds in rational number format. Analysts must convert to decimal degrees for mapping tools."

**GPS coordinate conversion:**
```
  Decimal Degrees = Degrees + (Minutes/60) + (Seconds/3600)

  Example: GPSLatitude = [37, 46, 29.12] with Ref = N
  DD = 37 + (46/60) + (29.12/3600) = 37.7747°N

  Longitude = [122, 25, 9.88] with Ref = W
  DD = -(122 + (25/60) + (9.88/3600)) = -122.4194°W
  (negative because West)
```

**ExifTool command examples:**
```bash
# Extract all EXIF from a single image
exiftool image.jpg

# Extract GPS only, in decimal degrees
exiftool -GPSLatitude -GPSLongitude -GPSAltitude -c "%.6f" image.jpg

# Batch extract from all JPEGs, output CSV
exiftool -csv -r /path/to/photos/ > exif_report.csv

# Show date fields only
exiftool -DateTimeOriginal -CreateDate -ModifyDate image.jpg

# Extract GPS for all images, write KML for Google Earth
exiftool -p gpx.fmt -r /photos/ > track.gpx

# CRITICAL: Detect timestamp tampering — compare all 3 dates
exiftool -FileModifyDate -DateTimeOriginal -CreateDate image.jpg
# If FileModifyDate is newer than DateTimeOriginal → possible tampering
```

---

### 3.3.2 Video Metadata

Video files (MP4, MOV, AVI, 3GP) embed metadata in container atoms/boxes:

```
  MP4 Container Atom Structure:
  ─────────────────────────────────────────────────────
  ftyp  → file type and compatibility
  moov  → container for all metadata
   ├─ mvhd  → movie header: creation time, duration,
   │           time scale (ticks/sec), next track ID
   ├─ trak  → track container (one per video/audio track)
   │   ├─ tkhd  → track header: creation, modification,
   │   │           width, height, volume
   │   └─ mdia  → media data
   │       ├─ mdhd  → media header: language, timescale
   │       └─ minf  → media information
   └─ udta  → user data (often contains GPS, device info)
       └─ ©xyz  → GPS location atom (Apple/iPhone)
  mdat  → actual audio/video data
  ─────────────────────────────────────────────────────
  Timestamps in MP4 use Mac epoch: seconds since 1904-01-01
  Convert: Unix_time = Mac_epoch_time - 2082844800
```

```bash
# Extract video metadata with exiftool
exiftool -GPSLatitude -GPSLongitude -CreateDate -Duration video.mp4

# Using ffprobe (ffmpeg suite) for full container metadata
ffprobe -v quiet -print_format json -show_format -show_streams video.mp4

# Extract GPS from iPhone MOV file
exiftool -ee -p '$GPSDateTime  $GPSLatitude $GPSLongitude' video.mov
```

---

### 3.3.3 Thumbnail Cache Forensics

```
  Android Thumbnail Cache:
  ┌──────────────────────────────────────────────────────────────┐
  │ Location: /data/data/com.android.providers.media/databases/ │
  │           thumbnails/                                        │
  │           /sdcard/.thumbnails/  (external)                  │
  │                                                              │
  │ Database: external.db / internal.db                         │
  │ Table: thumbnails                                            │
  │   Columns: _id, _data (path), image_id, kind, width, height │
  │                                                              │
  │ Forensic value: thumbnails may persist AFTER the original   │
  │ image has been deleted, providing evidence of prior existence│
  └──────────────────────────────────────────────────────────────┘

  iOS Thumbnail Cache:
  ┌──────────────────────────────────────────────────────────────┐
  │ /private/var/mobile/Media/PhotoData/Thumbnails/             │
  │   ├── V2/  ← per-asset thumbnail pyramid                    │
  │   └── Photos.sqlite ← CoreData store for Photos.app         │
  │                                                              │
  │ ZASSET table in Photos.sqlite:                               │
  │   ZTITLE, ZLATITUDE, ZLONGITUDE, ZDATECREATED,              │
  │   ZMODIFICATIONDATE, ZDIRECTORY, ZFILENAME,                  │
  │   ZTRASHEDSTATE (0=active, 1=in trash), ZISDELETED           │
  └──────────────────────────────────────────────────────────────┘
```

```sql
-- iOS: Find all images ever in trash (soft-deleted)
SELECT
    ZFILENAME,
    ZDIRECTORY,
    datetime(ZDATECREATED + 978307200, 'unixepoch','localtime') AS created,
    datetime(ZMODIFICATIONDATE + 978307200,'unixepoch','localtime') AS modified,
    ZLATITUDE,
    ZLONGITUDE,
    ZTRASHEDSTATE
FROM ZASSET
WHERE ZTRASHEDSTATE = 1 OR ZISDELETED = 1
ORDER BY ZDATECREATED DESC;
```

> 📗 *Reiber (2020):* "Never dismiss thumbnail databases. A thumbnail of a deleted child exploitation image has been ruled admissible evidence in multiple jurisdictions — the thumbnail proves the original existed on the device."

---

### 3.3.4 Error Level Analysis (ELA) — Detecting Tampered Images

ELA detects JPEG compression inconsistencies that suggest digital manipulation:

```
  ELA Principle:
  ──────────────────────────────────────────────────────────────
  JPEG uses lossy compression. Each save reduces quality.
  In an authentic image, all regions have similar error levels
  after a known re-compression step.

  In a COMPOSITED/TAMPERED image:
  - Pasted regions were last saved at a DIFFERENT quality level
  - They show HIGHER error levels vs surrounding pixels
  - Detectable as bright patches in ELA output

  Process:
  1. Re-save original at known quality (e.g., 95%)
  2. Compute pixel-wise absolute difference vs original
  3. Amplify differences × 10–20 for visibility
  4. Bright areas = recently modified / pasted regions
  ──────────────────────────────────────────────────────────────
```

```bash
# ELA using ImageMagick
convert original.jpg -quality 95 resaved.jpg
composite -compose difference original.jpg resaved.jpg diff.jpg
convert diff.jpg -level 0%,10% ela_output.jpg

# Python-based ELA (using PIL/Pillow)
python3 -c "
from PIL import Image, ImageChops, ImageEnhance
img = Image.open('original.jpg')
img.save('/tmp/resaved.jpg', quality=95)
ela = ImageChops.difference(img, Image.open('/tmp/resaved.jpg'))
ela = ImageEnhance.Brightness(ela).enhance(15)
ela.save('ela_result.jpg')
"
```

> 📕 *Bhardwaj & Kaushik (2023):* "ELA is an indicator, not definitive proof. A clean ELA result does not rule out manipulation; combine with metadata analysis and chain-of-custody for definitive conclusions."

---

Acquisition is the process of creating a forensically sound copy of data from a mobile device. The method depends on device model, OS, lock state, encryption, and legal constraints.

### 1. Types of Mobile Device Acquisition

Logical Acquisition:
- Description: Use OS-level APIs, backup utilities, or synchronization protocols to extract accessible files and system-provided exports.
- Pros: Non-destructive, often available without root/jailbreak. Good for quick triage.
- Cons: Misses deleted data, unallocated space, and low-level artifacts. Depends on OS permissions.
- Examples: Android `adb backup` (deprecated on newer devices), iTunes/iCloud backups (iOS logical backup), MTP file copy.

File System Acquisition:
- Description: Acquire full visible file system and metadata, using higher privileges. May require rooting/jailbreak or vendor support.
- Pros: Captures app private data and metadata that logical exports might omit.
- Cons: May still miss unallocated space and raw flash artifacts. May require invasive steps.

Physical Acquisition:
- Description: Bit-for-bit copy of the entire storage medium (eMMC/NAND) or RAM.
- Pros: Can recover deleted data, unallocated space, and low-level artifacts; best for deep recovery and carving.
- Cons: Often technically challenging, may require disassembly, chip-off, JTAG, or circumventing secure boot and encryption. Higher risk of altering device state.

Specialized acquisition methods:
- Chip-off: Physically removing flash chips and reading them with a reader.
- JTAG: Using the device's debug interface to access memory and storage.
- UART/Serial and Bootloader exploitation: Use serial console or bootloader to boot a forensic image or dump partitions.
- OF: Over-the-air/cloud acquisition via provider cooperation and legal requests.

### 2. Acquisition Tools and Techniques

Common tool categories:
- Commercial forensic suites: Cellebrite UFED, Magnet AXIOM, Oxygen Forensic Detective, MSAB.
- Open-source/Free: ADB/fastboot, libimobiledevice (idevicebackup2, idevicedebug), Autopsy/Sleuth Kit, Scrounger, Wireshark for network captures, Bulk Extractor, xxd/hex editors, sqlite3.
- Hardware tools: chip readers, write-blockers, JTAG adapters, ISP cables, and test fixtures.

Acquisition technique decisions flow:
1. Document device state (on/off), record photos, and capture IMSI/IMEI and SIM info.
2. If device is powered on and unlocked, prioritize volatile data: perform RAM capture if possible and safe.
3. If locked/power-off and physical acquisition is required, evaluate non-destructive options first (logical/file system, bootloader exploit).
4. For encrypted or locked devices, consider vendor or cloud cooperation; document legal steps.

Example: Android acquisition decision tree (simplified):
- Device unlocked and USB debugging enabled: use `adb` to pull app data, create a logical backup if possible.
- Device unlocked but no USB debugging: consider using custom recovery or exploit (risk assessment required).
- Device locked: photograph, preserve, acquire chip-off/JTAG if warranted and permitted.

### 3. Chip-off Acquisition

Chip-off defined: physically removing the flash memory chip from the device PCB and reading raw NAND contents using a specialized reader.

Steps (high-level):
1. Obtain permission and risk sign-off; chip-off is destructive and may void warranties.
2. Document the device state with photographs and notes.
3. De-solder or heat and detach the target NAND chip carefully.
4. Place chip in a socket or specialized reader and read raw dumps using vendor tools.
5. Use NAND-specific tools to reconstruct partitions and handle wear-leveling, bad block remapping, and flash translation layer (FTL).
6. Verify integrity by hashing and proceed to carve files and analyze.

Challenges:
- Destroying or damaging the chip during removal.
- Interpreting raw NAND dumps due to wear-leveling, ECC, and vendor-specific controllers.
- Time-consuming and requires specialized equipment and skill.

### 4. Data Recovery Methods

When analyzing physical dumps, you can:
- Recover deleted files by parsing file system metadata and scanning unallocated space for file signatures (carving).
- Recover SMS/MMS/DB records from SQLite databases by parsing journal and unallocated pages.
- Reconstruct fragmented media using carving and metadata correlation.

Important techniques:
- File carving: Search raw data for file headers/footers (JPEG, PNG, MP4, etc.). Reconstruct file offsets and validate with headers and metadata.
- SQLite recovery: Inspect WAL/journal files, unallocated pages, and freelist to recover deleted rows.
- Metadata correlation: Use timestamps across artifacts (filesystem, EXIF, logs) to build timelines.

Tools for recovery:
- scalpel, photorec for carving
- sqlite3, recovery tools for SQLite
- vendor-specific NAND parsing libraries

### 5. Challenges and Best Practices in Mobile Device Acquisition

Common challenges:
- Device locks and encryption.
- Rapid patching and OS changes across vendors.
- Fragmented Android ecosystem: vendor modifications and custom file systems (e.g., F2FS, YAFFS).
- Cloud synchronization: crucial data may be remote.
- Legal and privacy constraints.

Best practices:
1. Document every action; photograph and maintain chain-of-custody.
2. Use write-blocking where possible; minimize changes to device state.
3. Prioritize volatile data if device unlocked/powered-on.
4. Validate tools and preserve original evidence; work on copies whenever possible.
5. Hash images and verify before/after any processing.
6. Keep tool versions and logs to support reproducibility in court.

Checklist when receiving a mobile device:
- Photograph device and packaging.
- Record device identifiers (IMEI, MEID, serial, phone number, SIM ICCID).
- Note power state; if on and unlocked, consider live RAM capture.
- If on and locked, do not input passcodes—document and consult warrant.
- Place in Faraday bag if network isolation is required (but be aware of remote wipe risks tied to network separation).

Forensics-friendly handling of powered-on devices:
- If the device is powered on and unlocked and there's immediate risk of remote wipe, isolating network connectivity may be better than placing in Faraday bag — weigh the risk of remote wipe vs. incoming data

---


## UNIT III — MOBILE DEVICE ANALYSIS

Analysis converts acquired data into actionable intelligence. It consists of parsing, reconstructing user activity, correlating artifacts across sources, and preparing court-ready reports. This revised UNIT III focuses on practical techniques, per-app examples, and cloud integration workflows.

### 3.1 Data Extraction and Analysis Tools (revisited)

Tool types and recommended uses:
- Forensic suites: full-process convenience (extraction, parsing, reporting). Use for rapid triage and standardized output (Cellebrite UFED, Magnet AXIOM, Oxygen). Verify outputs with independent tools.
- Command-line tools: `sqlite3`, `strings`, `plutil`, `plutil -convert xml1`, `xxd`, `exiftool`, `ffprobe`, `photorec`/`scalpel` for carving.
- Timeline & analysis: Plaso/log2timeline for ingestion, Timesketch for collaborative review, ELK stack for custom pipelines.
- Hex and low-level: 010 Editor, Bless, or HxD (for pattern matching, carving and manual reconstruction).

Validation and reproducibility:
- Always compute SHA-256 hashes of images and key artifacts (`shasum -a 256`).
- Record tool versions and exact command lines. Save parsing logs and exported CSVs for audit.

### 3.2 Examination of Calls, Texts, Contacts, Emails (practical)

Schema and parsing patterns:
- Android: Look for `mmssms.db`, `contacts2.db`, `calllog.db` under app/provider storage. Use `sqlite3` and `PRAGMA table_info(table)` to inspect schemas.
- iOS: Search for `sms.db`, `CallHistory.storedata`, and address book SQLite files under app containers or `/private/var/mobile/Library` paths. Convert Apple epoch values (Apple epoch starts 2001-01-01) to Unix for normalization.

Sample queries (Android WhatsApp-style message DBs):
```
sqlite3 msgstore.db "SELECT datetime(date/1000,'unixepoch','localtime') AS sent_time, key_from_me, data FROM messages ORDER BY date DESC LIMIT 50;"
```
Notes: WhatsApp stores dates as milliseconds since epoch; other apps vary (seconds vs milliseconds).

Deleted record recovery:
- Examine WAL (`-wal`) and journal files. Use `sqlite3` to `.dump` or specialized tools (e.g., `sqlite3_analyzer`, `bulk_extractor`) to parse unallocated DB pages.

### 3.3 Digital Media Forensics (expanded)

EXIF deep-dive:
- Use `exiftool -a -G1 -s image.jpg` to list all EXIF tags, maker notes, and nested tags.
- Extract GPS in decimal: `exiftool -gpslatitude -gpslongitude -gpsdatetime image.jpg`.
- Validate consistency: compare EXIF DateTimeOriginal vs filesystem mtime and app-side timestamps (social media upload times).

Image authenticity checks:
- Error Level Analysis (ELA) with ImageMagick/Pillow to highlight recompression artifacts.
- Examine thumbnail consistency: device-created thumbnails in cache directories vs original files.

Video/container metadata:
- Use `ffprobe -v quiet -print_format json -show_format -show_streams video.mp4` to inspect container atoms and embedded timestamps (creation_time, tags).

### 3.4 Application Data Analysis (deep technical)

Overview and attacker/investigator model:
- Applications are the richest source of user intent: chat logs, media, location check-ins, transactional records, and tokens.
- Forensic goals: locate app storage, extract and parse DBs/configs, recover deleted records, extract credentials/tokens, and correlate with server-side artifacts.

Detailed steps:
1. Identify app binaries and package name (Android: `com.example.app`; iOS: bundle ID). Use `/data/data/<pkg>` or app container paths to locate storage.
2. Enumerate files: `find . -type f -printf "%p %s %TY-%Tm-%Td %TH:%TM:%TS\n"` (on exported copy) or `tar` the container for hashing and archival.
3. Inspect common data stores:
   - SQLite DBs: `sqlite3` + schema inspection (`.schema`, `PRAGMA table_info()`), export to CSV for analysis.
   - JSON/Flat files: parse with jq or python for timeline events and tokens.
   - SharedPreferences / plist files: read with `plutil` (iOS) or decode Android XML prefs.
4. Search for secrets and tokens:
   - Look in `shared_prefs`, `files`, and `databases` for OAuth tokens, refresh tokens, API keys, and session IDs.
   - Check filesystem permissions and key locations (Android keystore, iOS keychain). Note: keystore/keychain contents are usually inaccessible without device credentials.

Per-app practical examples
- WhatsApp (Android):
  - Files: `/data/data/com.whatsapp/databases/msgstore.db`, `/data/data/com.whatsapp/files/key` (encryption key), `/sdcard/WhatsApp/Media/`.
  - Decryption: `msgstore.db` encrypted with AES; the key is commonly stored in the app container (varies by version). With the key and a decrypted DB, run SQL queries to extract messages and metadata. Example message query:
```
sqlite3 decrypted_msgstore.db "SELECT datetime(timestamp/1000,'unixepoch','localtime') AS ts, key_remote_jid, data FROM messages ORDER BY timestamp DESC LIMIT 100;"
```
  - Media mapping: `messages` table references `media_wa_url` or local file paths—cross-reference with `/WhatsApp/Media`.

- Signal/Telegram:
  - Signal stores messages encrypted with a user key; Signal Desktop and backups vary. Telegram caches often include message IDs and media thumbnails; `tg` protocol specifics require app-version knowledge.

- Facebook/Instagram:
  - Cache directories may hold JSON fragments, message caches, and thumbnails. SDK-level logs may reveal network endpoints and message metadata.

Decryption and keys
- Android keystore: keys may be hardware-backed and inaccessible. If keys are stored in app files or exported backups, they may enable DB decryption. For rooted/physical images, search for key files and key derivation code in the app APK.
- iOS keychain: items may be extracted from logical backups (unencrypted or with known backup password) or via agent-based extraction if the device is unlocked and trusted pairing exists.

Automating per-app extraction
- Build small Python scripts that parse known schemas into CSVs and generate timeline CSVs. Keep scripts versioned and record app version compatibility.

Artifact correlation
- Cross-reference message timestamps with network logs, notification logs, and media EXIF to validate message delivery and content timeline.

Forensic caveats
- App schema changes across versions—always inspect schema before applying queries.
- Encrypted containers require careful handling and legal authorization for key extraction.

### 3.5 Cloud-based Data Analysis (expanded operational guidance)

Why cloud matters:
- Many services synchronize critical content to cloud backends—photos, messages, backups, telemetry, and contacts. When local data is encrypted or unavailable, cloud copies can be decisive.

Preservation and legal steps:
1. Identify provider and account details from device (account settings, app preferences, cached tokens, email addresses).
2. Immediately send a preservation request/preservation letter to the provider to avoid retention deletion.
3. Prepare legal process (subpoena, warrant, or MLAT) depending on jurisdiction and provider location.

Token-based access (technical pathway—use only with explicit legal authorization):
- OAuth 2.0 flow: devices often store access tokens and refresh tokens in app storage. Access tokens are short-lived; refresh tokens can obtain new access tokens. If refresh tokens are present and legal authority exists, investigators may obtain data programmatically.
- Example: locating Google OAuth tokens in Android app storage or Chrome's `Cookies`/`Local Storage` entries. Use care—tokens represent live credentials and must be handled as highly-sensitive evidence.

Provider-specific notes:
- Google: `Takeout` and Google Cloud eDiscovery are formal channels. Account activity and Drive/Photos exports are available via legal requests. Look for `Accounts` entries and `com.google.android.apps.photos` caches.
- Apple/iCloud: iCloud data is accessible via Apple's legal channels; metadata (photo thumbnails, device backups) may be stored in iCloud. iCloud backups often contain decrypted copies of some app data.
- Messaging providers (WhatsApp, Telegram): WhatsApp backups to Google Drive or iCloud may contain full message histories; provider cooperation or user-provided backup passwords may be required.

Practical acquisition patterns:
- Preserve device-side artifacts that indicate cloud sync (sync timestamps, backup manifests, account identifiers). These help scope provider requests and narrow time windows.
- Collect tokens if available: example paths include app config files, `shared_prefs`, `Local Storage` for webviews, or Chrome's cookie stores. Use `sqlite3`/`jq` to parse.

Example: Extract OAuth token from app JSON cache (simplified):
```
cat /path/to/app/cache/auth.json | jq '.access_token, .refresh_token'
```
Legal note: Using tokens to query provider APIs requires explicit legal authority and should be coordinated with legal counsel.

Cloud timeline correlation
- Combine cloud event timestamps (server logs, uploaded file timestamps) with device-side timestamps. Note that server timestamps are authoritative for server actions (uploads, deletes), while device timestamps show local action time.

Handling cross-border data
- When provider servers or accounts are outside the investigator's jurisdiction, engage MLAT or mutual legal assistance. Document the chain of requests and provider responses.

### 3.6 Timeline Construction and Correlation (practical commands)

Collect artifacts for ingestion:
- Filesystem metadata (MAC times), app DBs (SQLite), EXIF/MP4 metadata, system logs, network logs, and carved artifacts.

Plaso example ingestion pipeline:
```
# install and run plaso (example)
log2timeline.py /tmp/timeline.plaso /path/to/evidence
psort.py -o L2tcsv /tmp/timeline.plaso "" > merged_timeline.csv
```
Tips:
- Normalize all timestamps to UTC and keep original timezone metadata in the dataset. Document conversions (e.g., Apple epoch offset: add 978307200 to convert to Unix epoch).
- Use Timesketch to visualize and tag events by confidence level.

Correlating events:
- Use message send/receive timestamps, notification records, and network flows to triangulate when a user action occurred and when the server processed it.

### 3.7 Reporting and Evidence Presentation (templates and exhibits)

Essential report sections:
1. Executive summary: concise findings, impact statement.
2. Scope and authority: warrants, consents, limitations.
3. Evidence summary: list of devices, IDs, and images with SHA-256 hashes.
4. Methodology: step-by-step acquisition and analysis commands/tools.
5. Findings: categorized artifacts (communications, media, location) with references to exhibits.
6. Timeline: key events with timestamps and cross-references.
7. Exhibits: numbered images, screenshots, CSV extracts, and relevant raw artifacts.
8. Appendices: tool logs, full SQL query outputs, and raw artifact hashes.

Exhibit example format:
- Exhibit 1 (E1): Photo `IMG_001.jpg` — path: `/media/DCIM/100MEDIA/IMG_001.jpg` — EXIF DateTimeOriginal: 2020-03-10T14:23:10 — SHA256: <hash> — Interpretation: Photo taken at location X corroborating user presence.

Presentation best practices:
- Use clear labels, avoid excessive jargon in the executive summary, but include technical annexes for expert review.
- Provide reproducibility: include scripts, sample commands, and environment details so results can be independently replicated.

---

---

# ═══════════════════════════════════════
# APPENDICES — PRACTICAL REFERENCE
# ═══════════════════════════════════════

> 📗 **Reiber (2020), Ch. 4–5** — detailed on-scene and lab procedures.
> 📘 **Jain & Kalbande (2016), Ch. 3** — legal steps, evidence handling, and admissibility.
> 📕 **Bhardwaj & Kaushik (2023), Ch. 6–8** — tool-by-tool command references for Android/iOS.
> 📙 **Dejey (2018), Ch. 5** — SIM and hardware extraction procedures.
> 📓 **Steuart et al. (2013), Ch. 10–11** — chain-of-custody and documentation standards.

---

## Appendix A — On-Scene Acquisition Checklist

> 📗 Source: **Reiber (2020), Ch. 4 "First Response Procedures"**

### A.1 Pre-Arrival Preparation
- [ ] Confirm legal authority (warrant, consent, incident response authorization).
- [ ] Prepare evidence bags, labels, Faraday bags, anti-static packaging.
- [ ] Ensure tools are updated, validated, and licensed.
- [ ] Confirm chain-of-custody forms and photo/video equipment is ready.

### A.2 On-Scene — Device Discovery
- [ ] Secure the scene; prevent unauthorized access.
- [ ] Photograph the device **in situ** before touching it (capture screen, cables, position).
- [ ] Note the power state: ON / OFF / locked / unlocked / low battery indicator.
- [ ] **Do not** plug in a charger before photographing (may alter charging data).
- [ ] Record device identifiers from packaging or label if possible (IMEI, MEID, serial).

### A.3 On-Scene — Device State Decisions

| Device State | Recommended Action | Reference |
|---|---|---|
| ON, unlocked | Screen-capture visible data; consider live capture before Faraday | Reiber (2020) §4.3 |
| ON, locked | Do NOT attempt passcode; Faraday + transport to lab | Bhardwaj (2023) §6.2 |
| OFF | Place in anti-static bag; transport to lab | Reiber (2020) §4.4 |
| Plugged in | Photograph first; then decide on Faraday isolation | Dejey (2018) §5.1 |
| SIM present | Note ICCID; do not remove SIM at scene unless instructed | Jain (2016) §3.2 |

### A.4 Faraday Bag Decision Matrix

```
Is device at risk of remote wipe?
        │
        ├─ YES ──► Place in Faraday immediately
        │           (note: incoming messages blocked)
        │
        └─ NO ───► Keep network active to capture
                    incoming data; place in Faraday
                    only when directed by legal authority
```

> ⚠️ **Reiber (2020), §4.5:** "Placing a device in airplane mode is not always sufficient — some malware and some MDM solutions can survive brief network outages and execute wipe commands on next connection. Use a Faraday enclosure AND airplane mode in high-risk scenarios."

### A.5 Chain-of-Custody (CoC) Entry — Minimum Fields

```
Item #:          ___________
Collected by:    ___________  Date/Time: ___________
Location:        ___________
Device make/model: _________  IMEI/Serial: __________
Device state:    ON / OFF / Locked / Unlocked
Photographs taken: YES / NO  Photo IDs: ___________
Packaged in:     ___________
Notes:           ___________
```

> 📓 **Steuart et al. (2013), Ch. 11:** Every entry must be signed and dated. Chain-of-custody gaps invalidate evidence in most jurisdictions.

### A.6 Transport
- [ ] Place in anti-static bag (for electronics); Faraday outer layer if network isolation needed.
- [ ] Label the bag with item number matching CoC.
- [ ] Keep device charged in Faraday using a Faraday-compatible USB charger if battery is low.
- [ ] Deliver to secure evidence storage; log transfer with CoC signature.

---

## Appendix B — Lab Command Reference

> 📕 Source: **Bhardwaj & Kaushik (2023), Ch. 7–8 "Practical Extraction Commands"**
> 📗 Source: **Reiber (2020), Ch. 5 "Laboratory Examination"**

> ⚠️ All commands below are for **laboratory use on authorized copies only**. Never run acquisition commands directly against the original evidence device without a write-blocker or equivalent safeguard.

---

### B.1 Hashing and Integrity Verification

```zsh
# SHA-256 hash of a raw image (macOS zsh)
shasum -a 256 evidence.dd | tee evidence.dd.sha256

# Verify an existing hash file
shasum -a 256 -c evidence.dd.sha256

# MD5 (legacy, not preferred alone — combine with SHA-256)
md5 evidence.dd

# Hash multiple files in a directory
find /evidence -type f -exec shasum -a 256 {} \; | tee hashes_$(date +%Y%m%d).txt
```

> 📘 **Jain & Kalbande (2016), §3.4:** "Dual hashing (MD5 + SHA-256) is recommended by NIST SP 800-101 to ensure forward-compatible integrity verification."

---

### B.2 Android — ADB Acquisition and Triage

```zsh
# --- SETUP ---
# Verify device is visible and trusted
adb devices
# Expected output: <serial>  device

# Get device info
adb shell getprop ro.product.model
adb shell getprop ro.product.manufacturer
adb shell getprop ro.serialno
adb shell settings get secure android_id

# Get IMEI (if accessible)
adb shell service call iphonesubinfo 1

# --- LOGICAL BACKUP ---
# Full logical backup (Android < 9; prompts screen confirmation)
adb backup -apk -obb -shared -all -f backup_$(date +%Y%m%d).ab

# Backup a single app
adb backup -f whatsapp_$(date +%Y%m%d).ab com.whatsapp

# Convert .ab to .tar for inspection (requires Android Backup Extractor)
java -jar abe.jar unpack backup.ab backup.tar

# --- FILE PULLS ---
# Pull app data (root or run-as required)
adb shell run-as com.example.app cp -r /data/data/com.example.app/databases /sdcard/tmp_db/
adb pull /sdcard/tmp_db/ /lab/evidence/appdata/

# Pull all accessible media
adb pull /sdcard/DCIM/ /lab/evidence/media/

# Pull call logs DB (root required)
adb shell "su -c 'cp /data/data/com.android.providers.contacts/databases/calllog.db /sdcard/calllog.db'"
adb pull /sdcard/calllog.db /lab/evidence/

# Pull SMS DB
adb shell "su -c 'cp /data/data/com.android.providers.telephony/databases/mmssms.db /sdcard/mmssms.db'"
adb pull /sdcard/mmssms.db /lab/evidence/

# --- PHYSICAL IMAGE (rooted or custom recovery) ---
# List block devices
adb shell "ls -la /dev/block/by-name/"

# Image userdata partition over ADB (slow but effective)
adb shell "su -c 'dd if=/dev/block/by-name/userdata bs=4096 | gzip -1'" > userdata_$(date +%Y%m%d).gz

# Verify image size
adb shell "su -c 'blockdev --getsize64 /dev/block/by-name/userdata'"
```

> 📕 **Bhardwaj & Kaushik (2023), §7.3:** "For Android 10+, `adb backup` may be restricted by apps using `allowBackup=false`. Prefer physical imaging or JTAG/ISP methods when logical extraction is incomplete."

---

### B.3 iOS — libimobiledevice and Backup Acquisition

```zsh
# --- SETUP ---
# Install libimobiledevice (Homebrew, macOS)
brew install libimobiledevice ideviceinstaller

# Verify device is paired and trusted
ideviceinfo | head -20

# Get device identifiers
ideviceinfo | grep -E "UniqueDeviceID|SerialNumber|ProductType|ProductVersion|WiFiAddress|BluetoothAddress|PhoneNumber|IMEI"

# --- LOGICAL BACKUP ---
# Full encrypted backup (preserves more data — keychain, health, etc.)
idevicebackup2 backup --full /lab/evidence/ios_backup_$(date +%Y%m%d)/

# If the device has an existing backup password and you know it:
idevicebackup2 backup --password <backup_password> /lab/evidence/ios_backup/

# Change backup password to known value (CAUTION: modifies device — document this action)
idevicebackup2 encryption on <new_password>

# --- BACKUP INSPECTION ---
# List backup contents
idevicebackup2 info /lab/evidence/ios_backup/

# Use iMazing, AFC2, or python-idevicebackup2 tools to inspect Manifest.db
sqlite3 /lab/evidence/ios_backup/<udid>/Manifest.db ".tables"
sqlite3 /lab/evidence/ios_backup/<udid>/Manifest.db "SELECT relativePath, fileID FROM Files WHERE relativePath LIKE '%sms%';"

# --- FILE-SYSTEM LEVEL (jailbroken device via AFC2) ---
ifuse --root /mnt/ios_root/
ls /mnt/ios_root/private/var/mobile/Library/

# SMS database
cp /mnt/ios_root/private/var/mobile/Library/SMS/sms.db /lab/evidence/

# Call history
cp /mnt/ios_root/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata /lab/evidence/
```

> 📗 **Reiber (2020), §5.4:** "iOS encrypted backups include keychain data (passwords, certificates) whereas unencrypted backups do not. Always opt for encrypted backups with a known password during forensic acquisition."

---

### B.4 SQLite Forensic Queries

```zsh
# Open a database and inspect schema
sqlite3 mmssms.db
.tables
.schema sms
PRAGMA table_info(sms);

# Export SMS to CSV
sqlite3 -header -csv mmssms.db \
  "SELECT datetime(date/1000,'unixepoch','localtime') AS ts,
          address, body, type
   FROM sms ORDER BY date DESC LIMIT 200;" > sms_export.csv

# Android call log query
sqlite3 calllog.db \
  "SELECT datetime(date/1000,'unixepoch','localtime') AS ts,
          number, duration, type
   FROM calls ORDER BY date DESC LIMIT 100;"

# iOS call history (Apple epoch = Unix epoch - 978307200)
sqlite3 CallHistory.storedata \
  "SELECT datetime(ZDATE + 978307200,'unixepoch','localtime') AS call_time,
          ZADDRESS, ZDURATION, ZORIGINATED
   FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 50;"

# iOS SMS (sms.db)
sqlite3 sms.db \
  "SELECT datetime(date/1000000000 + 978307200,'unixepoch','localtime') AS ts,
          address, text, is_from_me
   FROM message ORDER BY date DESC LIMIT 100;"

# WhatsApp messages (Android, decrypted msgstore.db)
sqlite3 msgstore.db \
  "SELECT datetime(timestamp/1000,'unixepoch','localtime') AS ts,
          key_remote_jid, data, key_from_me
   FROM messages
   WHERE data IS NOT NULL
   ORDER BY timestamp DESC LIMIT 100;"

# Recover deleted rows from SQLite WAL
sqlite3 mmssms.db "PRAGMA wal_checkpoint(TRUNCATE);"
# Then re-examine DB with a forensic SQLite parser to check freed pages

# Check SQLite integrity
sqlite3 mmssms.db "PRAGMA integrity_check;"
```

> 📕 **Bhardwaj & Kaushik (2023), §8.1:** "SQLite WAL mode keeps shadow copies of changed pages until a checkpoint. Forensic examiners should always preserve the `-wal` and `-shm` files alongside the main `.db` file."

---

### B.5 Media and EXIF Analysis

```zsh
# Full EXIF dump (all tags, all groups)
exiftool -a -G1 -s image.jpg

# Extract GPS coordinates only
exiftool -GPSLatitude -GPSLongitude -GPSDateStamp -GPSTimeStamp image.jpg

# Batch extract GPS to CSV from all JPEGs in a directory
exiftool -csv -GPSLatitude -GPSLongitude -DateTimeOriginal -Model /evidence/media/*.jpg > gps_batch.csv

# Check for EXIF inconsistencies (DateTimeOriginal vs FileModifyDate)
exiftool -DateTimeOriginal -FileModifyDate -CreateDate image.jpg

# Strip EXIF for privacy (only on working copies — never original evidence)
exiftool -all= -o stripped_copy.jpg image.jpg

# Video container metadata
ffprobe -v quiet -print_format json -show_format -show_streams video.mp4

# Extract creation_time from video
ffprobe -v quiet -select_streams v:0 -show_entries format_tags=creation_time -of default=noprint_wrappers=1 video.mp4

# Thumbnail cache location (Android)
# ls /sdcard/Android/data/com.android.gallery3d/cache/
# ls /data/data/com.google.android.apps.photos/cache/
```

> 📘 **Jain & Kalbande (2016), §6.3:** "EXIF metadata is reliable only when corroborated with filesystem timestamps and cloud upload timestamps. Discrepancies may indicate timestamp forgery or timezone misconfiguration."

---

### B.6 File Carving Commands

```zsh
# Photorec — GUI/CLI carving tool (part of TestDisk)
photorec /log /d /output_dir userdata.img

# Scalpel (configuration-based carver)
# Edit /etc/scalpel/scalpel.conf to enable desired file types
scalpel -o /output_carve/ userdata.img

# Bulk Extractor — extract patterns (emails, URLs, credit cards) from raw image
bulk_extractor -o /bulk_output/ userdata.img
cat /bulk_output/email.txt | head -50

# foremost — another common carver
foremost -i userdata.img -o /output_foremost/ -t jpg,png,mp4,pdf

# String searching in binary image
strings -el userdata.img | grep -i "@gmail.com" | head -30   # wide char (UTF-16)
strings -e8 userdata.img | grep -i "whatsapp" | head -30     # UTF-8
```

> 📗 **Reiber (2020), §5.7:** "File carving should be applied to unallocated space only, separated from the active filesystem, to avoid flooding the output with duplicates of live files."

---

### B.7 Timeline Construction with Plaso

```zsh
# Install Plaso (macOS via pip)
pip3 install plaso

# Ingest an Android image
log2timeline.py --storage-file android_timeline.plaso userdata.img

# Ingest an iOS backup directory
log2timeline.py --storage-file ios_timeline.plaso /lab/evidence/ios_backup/<udid>/

# Sort and output as CSV
psort.py -o L2tcsv -w merged_timeline.csv android_timeline.plaso ""

# Filter by time range (e.g., one specific day)
psort.py -o L2tcsv -w filtered.csv android_timeline.plaso \
  "date > '2024-01-01 00:00:00' AND date < '2024-01-02 00:00:00'"

# Push to Timesketch for visualization (requires Timesketch server)
timesketch_importer --sketch_id 1 --timeline_name "Android Evidence" merged_timeline.csv
```

> 📕 **Bhardwaj & Kaushik (2023), §9.2:** "Plaso parsers cover 50+ artifact types on Android and iOS, including SQLite databases, system logs, browser history, and app-specific artifacts. Always record the parser list used (`log2timeline.py --parsers list`)."

---

### B.8 SIM Card Forensics

```zsh
# List available SIM readers (Linux/macOS with pcscd)
opensc-tool -l

# Get SIM card info (ATR, card type)
opensc-tool --info

# Read SIM using sim-tools (pySIM)
# Install: pip3 install pysim
pySIM-shell --pcsc-device 0
> select MF
> select DF_TELECOM
> select EF_MSISDN
> read_binary

# Dump IMSI (EF_IMSI under DF_GSM)
> select DF_GSM
> select EF_IMSI
> read_binary

# Read SMS stored on SIM (EF_SMS under DF_TELECOM)
> select EF_SMS
> read_record
```

> 📙 **Dejey (2018), §5.3:** "SIM cards follow ISO 7816 smart card standards. EF (Elementary File) contents such as EF_MSISDN, EF_IMSI, and EF_SMS are key targets. Always dump raw binary and decode separately to preserve original data."

---

## Appendix C — Visual Diagrams

### C.1 Device Storage Stack

```
    ┌─────────────────────────────────────────────┐
    │             USER APPLICATIONS               │
    │    (SQLite DBs, SharedPrefs, Media Files)   │
    ├─────────────────────────────────────────────┤
    │               APP SANDBOX / FS              │
    │      (ext4 / F2FS / APFS — OS managed)      │
    ├─────────────────────────────────────────────┤
    │               OS / SYSTEM FILES             │
    │     (bootloader, kernel, system partition)  │
    ├─────────────────────────────────────────────┤
    │          FLASH TRANSLATION LAYER (FTL)      │
    │  (LBA → Physical page mapping, wear level)  │
    ├─────────────────────────────────────────────┤
    │           NAND FLASH / eMMC / UFS           │
    │        (Physical storage medium)            │
    └─────────────────────────────────────────────┘

Forensic access layers:
  Logical  ──► App data via OS APIs (ADB/idevicebackup2)
  FS-level ──► Mount and browse filesystem (AFC2, TWRP)
  Physical ──► Raw NAND/eMMC dump (JTAG, ISP, chip-off)
```

> 📘 **Jain & Kalbande (2016), §4.1** | 📗 **Reiber (2020), §3.2**

---

### C.2 Memory Hierarchy and Virtual Memory Mapping

```
    ┌─────────────────────────────────────────────┐
    │         CPU REGISTERS (fastest, ~1ns)       │
    ├─────────────────────────────────────────────┤
    │         L1 / L2 / L3 CACHE (SRAM)           │
    ├─────────────────────────────────────────────┤
    │           MAIN MEMORY (LPDDR RAM)           │
    │   Process A VAddr 0x1000 ──► Phys 0xA000   │
    │   Process B VAddr 0x1000 ──► Phys 0xB000   │
    │           (MMU handles translation)         │
    ├─────────────────────────────────────────────┤
    │        PERSISTENT FLASH STORAGE (NAND)      │
    │       (swap, userdata, system partitions)   │
    └─────────────────────────────────────────────┘

Forensic implication:
  RAM is VOLATILE — lost on power-off. Capture FIRST if device is on.
  Flash is NON-VOLATILE — survives power-off. Primary acquisition target.
```

---

### C.3 Acquisition Method Decision Tree

```
                        ┌──────────────────────┐
                        │   Mobile Device       │
                        └────────┬─────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
         POWERED ON         POWERED ON         POWERED OFF
         UNLOCKED            LOCKED
              │                  │                  │
      ┌───────▼──────┐   ┌───────▼──────┐   ┌──────▼───────┐
      │ Live capture │   │ Faraday bag  │   │ Lab imaging  │
      │ → ADB/AFC2   │   │ + transport  │   │ → dd/JTAG    │
      │ → dd image   │   │ to lab       │   │ → chip-off   │
      └──────────────┘   └──────────────┘   └──────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │                         │
             Passcode known           Passcode unknown
                    │                         │
             Unlock + acquire          Legal compulsion
             file-system image         Vendor cooperation
                                        JTAG / ISP / chip-off
```

> 📗 **Reiber (2020), §4.2** — decision logic for powered-on devices.
> 📕 **Bhardwaj & Kaushik (2023), §6.4** — acquisition fallback hierarchy.

---

### C.4 Android File System Key Forensic Paths

```
/data/
├── data/
│   ├── com.android.providers.telephony/
│   │   └── databases/
│   │       └── mmssms.db          ← SMS/MMS
│   ├── com.android.providers.contacts/
│   │   └── databases/
│   │       ├── contacts2.db       ← Contacts
│   │       └── calllog.db         ← Call logs
│   ├── com.whatsapp/
│   │   ├── databases/
│   │   │   └── msgstore.db        ← WhatsApp messages (encrypted)
│   │   └── files/
│   │       └── key                ← Encryption key
│   └── com.google.android.apps.photos/
│       └── cache/                 ← Thumbnail cache
├── media/
│   └── 0/
│       └── DCIM/                  ← Photos & Videos
└── misc/
    └── keystore/                  ← Android Keystore entries
```

---

### C.5 iOS Key Forensic Paths

```
/private/var/mobile/
├── Library/
│   ├── SMS/
│   │   ├── sms.db                 ← SMS/iMessage database
│   │   └── Attachments/           ← MMS attachments
│   ├── CallHistoryDB/
│   │   └── CallHistory.storedata  ← Call log (ZCALLRECORD table)
│   ├── AddressBook/
│   │   └── AddressBook.sqlitedb   ← Contacts
│   ├── Safari/
│   │   ├── History.db             ← Browser history
│   │   └── Bookmarks.db
│   └── Keychains/
│       └── keychain-2.db          ← Encrypted credentials
├── Media/
│   └── DCIM/
│       └── 100APPLE/              ← Photos & Videos
└── Containers/
    └── Data/
        └── Application/
            └── <GUID>/            ← App sandboxed storage
```

> 📗 **Reiber (2020), §8.3** | 📕 **Bhardwaj & Kaushik (2023), §10.1**

---

### C.6 SQLite Database Forensics — Internal Structure

```
SQLite Database File Layout:
┌─────────────────────────────────────┐
│  File Header (100 bytes)            │
│  (magic: "SQLite format 3\000")     │
├─────────────────────────────────────┤
│  B-Tree Pages (page size: 512–65536)│
│  ├── Table leaf pages (live rows)   │
│  ├── Table interior pages (index)   │
│  └── Freelist pages ←── DELETED     │
│       data may still be here!       │
├─────────────────────────────────────┤
│  WAL File (db-wal) — if WAL mode    │
│  (contains recent transactions not  │
│   yet checkpointed to main DB)      │
└─────────────────────────────────────┘

Forensic recovery path:
  1. Preserve db + db-wal + db-shm together
  2. Parse freelist pages with forensic SQLite tools
  3. Scan unallocated space in image for table row patterns
  4. Reconstruct deleted rows from WAL frames
```

> 📕 **Bhardwaj & Kaushik (2023), §8.2** — SQLite forensics chapter.

---

### C.7 Timeline Correlation — Multi-Source Merge

```
SOURCE              ARTIFACT TYPE          TIMESTAMP FORMAT
──────────────────────────────────────────────────────────
Android SMS DB    │ Message send/recv    │ Unix epoch (ms)
iOS SMS DB        │ Message send/recv    │ Apple epoch (ns)
CallHistory       │ Call start time      │ Apple epoch (s)
EXIF/JPEG         │ Photo taken time     │ YYYY:MM:DD HH:MM:SS local
Filesystem mtime  │ File last-modified   │ Unix epoch (s)
Google Takeout    │ Location history     │ ISO 8601 UTC
Network PCAP      │ Packet timestamps    │ Unix epoch (µs)
──────────────────────────────────────────────────────────

Normalize all to UTC:
  Apple epoch    → add 978307200 → Unix epoch
  Unix ms epoch  → divide by 1000 → Unix epoch
  Unix ns epoch  → divide by 1000000000 → Unix epoch
  All UTC → single sortable timeline
```

> 📗 **Reiber (2020), §11.2** | 📕 **Bhardwaj & Kaushik (2023), §9.3**

---

# ═══════════════════════════════════════
# TOP 50 QUESTIONS — 5 MARKS EACH
# ═══════════════════════════════════════

> 📗 **Reiber (2020)** · 📘 **Jain & Kalbande (2016)** · 📙 **Dejey (2018)** · 📕 **Bhardwaj & Kaushik (2023)** · 📓 **Steuart et al. (2013)**
>
> Each answer is exam-ready (5–15 lines) with book citations. Use for exam prep, interviews, and viva.

---

### Q1. Define mobile forensics and list its primary objectives.

**A1.**
Mobile forensics is a specialized branch of digital forensics dealing with the **identification, preservation, acquisition, examination, analysis, and presentation** of digital evidence from mobile devices (smartphones, tablets, wearables, GPS devices) in a forensically sound and legally admissible manner.

**Primary objectives:**
1. **Preserve integrity** — document device state, hash all evidence, maintain an unbroken chain-of-custody.
2. **Acquire data** using validated, reproducible methods (logical, file-system, or physical).
3. **Recover artifacts** — call records, SMS/MMS, app data, media, GPS history, and deleted content.
4. **Reconstruct user activity** — build multi-source timelines from heterogeneous artifacts.
5. **Present findings** clearly and in a legally defensible format for court admissibility.

> 📗 **Reiber (2020), §1.2:** "The goal of mobile forensics is not simply to retrieve data but to retrieve it in a manner that will withstand legal scrutiny."
> 📘 **Jain & Kalbande (2016), §1.1:** "Digital forensics is the science of identifying, collecting, preserving, examining and analyzing digital evidence so that it is admissible in a court of law."

---

### Q2. What are the legal considerations an investigator must follow before acquiring a mobile device?

**A2.**
Legal authority is the foundation of every forensic investigation. Before acquisition:

1. **Warrant or consent** — obtain a search warrant, written consent, or incident response authorization (Steuart §3.1). Scope must explicitly cover the types of data sought.
2. **Warrant scope** — over-collection outside warrant scope risks evidence suppression. Each category (device-local, cloud, carrier records) may need separate authority.
3. **Cross-border data** — data on foreign servers requires MLATs (Mutual Legal Assistance Treaties) or provider cooperation under their local law.
4. **Privacy rights** — Fourth Amendment (US), GDPR (EU), or local equivalents constrain collection. Minimize unrelated personal data.
5. **Passcode policy** — do NOT bypass passcodes without explicit authorization; compelled-decryption laws vary by jurisdiction.
6. **Document pre-acquisition** — chain-of-custody forms, device identifiers, consent signatures, and tool versions logged before any action.

> 📓 **Steuart et al. (2013), §3.1:** "Operating outside the limits of a warrant or consent authorization risks suppression of all collected evidence."
> 📘 **Jain & Kalbande (2016), §2.3:** "Legal compliance is not a formality — it defines the admissible boundary of evidence."

---

### Q3. Explain chain-of-custody and why it is critical in mobile forensics.

**A3.**
**Chain-of-custody (CoC)** is a documented, chronological record accounting for every person who collected, transferred, examined, or stored evidence — from initial seizure to courtroom presentation.

**Every CoC entry records:** who, what action, date/time, location, and reason.

**Why it is critical:**
- **Integrity proof** — demonstrates evidence has not been altered or tampered with.
- **Admissibility** — courts require a complete, unbroken CoC for digital evidence.
- **Accountability** — any unexplained gap creates reasonable doubt for opposing counsel.
- **Reproducibility** — documents methodology so findings can be independently verified.
- **Audit trail** — identifies every person who accessed evidence, supporting or excluding insider compromise.

Proper CoC includes: signed transfer forms, secure evidence storage (tamper-evident bags), hashed images, and documentation of every authorized examination step.

> 📓 **Steuart et al. (2013), §11.2:** "A broken chain-of-custody is one of the most common reasons digital evidence is excluded in court proceedings."
> 📗 **Reiber (2020), §4.1:** "Evidence must be stored in tamper-evident containers and every handler documented with a signature."

---

### Q4. Describe logical, file-system, and physical acquisition with one advantage and one disadvantage each.

**A4.**

| Acquisition Type | Method | Advantage | Disadvantage |
|---|---|---|---|
| **Logical** | OS-level APIs, `adb backup`, `idevicebackup2` | Fast, non-invasive, no device damage | Misses deleted/unallocated data; app sandbox limits access |
| **File-System** | AFC2, TWRP read-only mount, full FS export | App-private files, hidden dirs accessible | Requires elevated access; may miss raw NAND artifacts |
| **Physical** | `dd` block device, JTAG, ISP, chip-off | Complete bit-for-bit image; carving recovers deleted data | Complex; potentially destructive (chip-off); slow |

**Selection logic (Reiber §3.4):** start logical → escalate to file-system → physical only when completeness justifies risk. Chip-off is last resort — irreversible.

> 📗 **Reiber (2020), §3.4:** "The acquisition method chosen must balance forensic completeness with the risk of evidence damage."
> 📕 **Bhardwaj & Kaushik (2023), §6.1:** "Physical acquisition is the gold standard but is not always legally required or technically feasible."

---

### Q5. What is chip-off forensics and what are its main risks?

**A5.**
**Chip-off forensics** is the physical removal of NAND flash memory chips from a device PCB and reading the raw binary data with specialized readers (UP-828, Xeltek) outside the device context.

**Procedure:**
1. Preheat PCB in infrared rework station (~200–250°C).
2. Desolder NAND chip using hot-air reflow.
3. Clean pads and mount chip in socket/carrier board.
4. Read raw dump using universal programmer.
5. Apply FTL reconstruction to interpret logical filesystem from physical pages.

**Risks:**
- **Irreversible** — desoldering is destructive; no fallback if chip is damaged.
- **Thermal damage** — overheating corrupts flash cells permanently.
- **FTL complexity** — vendor-specific page mapping must be reverse-engineered; incorrect mapping yields unreadable data.
- **Legal requirement** — documented, court-approved authorization required before proceeding.

> 📙 **Dejey (2018), §5.4:** "Chip-off requires laboratory-grade equipment and trained examiners — it is reserved for last-resort scenarios where all other methods have failed."
> 📗 **Reiber (2020), §6.3:** "A failed chip-off renders the evidence permanently inaccessible."

---

### Q6. How does virtual memory differ from physical memory, and why is RAM capture critical in forensics?

**A6.**
- **Physical memory (RAM):** actual LPDDR DRAM chips; volatile — contents lost on power-off.
- **Virtual memory:** OS abstraction — each process sees a private logical address space. The **MMU** (Memory Management Unit) translates virtual addresses → physical frames using page tables. Process A and Process B can have the same virtual address mapping to completely different physical frames.

**RAM forensic value:**
- Decrypted content of encrypted storage (crypto keys are loaded into RAM at runtime for use).
- Active session tokens, OAuth tokens, private keys that never touch persistent storage.
- Running process states, open file handles, network socket descriptors.
- Draft/unsaved user content (clipboard, uncommitted text).
- Evidence of malware injection or code executing in memory.

**Challenge on mobile:** live RAM capture requires root/jailbreak or specialized hardware. Capture must occur **before power-off** to be meaningful.

> 📘 **Jain & Kalbande (2016), §4.2:** "Memory forensics provides access to data that encryption would otherwise conceal on persistent storage."
> 📕 **Bhardwaj & Kaushik (2023), §5.3:** "LPDDR RAM holds active encryption keys — capturing RAM before shutdown is often the only path to decrypted data on a locked device."

---

### Q7. How does encryption on modern mobile OSes impact forensic acquisition?

**A7.**
Modern mobile OSes implement layered encryption:
- **Android 7+ (File-Based Encryption / FBE):** each file encrypted with individual keys derived from user credentials + hardware key (Keymaster / StrongBox TEE).
- **iOS Data Protection:** four protection classes (`CompleteProtection`, `ProtectedUnlessOpen`, `ProtectedUntilFirstUserAuthentication`, `NoProtection`) tied to device passcode + Secure Enclave.

**Forensic impact:**
1. Raw NAND/eMMC dumps are **ciphertext** — unreadable without keys.
2. Keys are hardware-bound — cannot be extracted without device passcode or vendor cooperation.
3. Logical/backup acquisition may yield **decrypted data** if device is unlocked and paired.
4. **BFU (Before First Unlock):** very limited data accessible even with logical tools.
5. **AFU (After First Unlock):** most app data keys are resident in RAM — broader data access window.

**Investigator responses:** prioritize live acquisition when device is unlocked; pursue legal compulsion or vendor cooperation when locked; consider RAM capture for key recovery on powered-on devices.

> 📗 **Reiber (2020), §9.2:** "The shift to file-based encryption in Android 7 significantly complicated forensic extraction — each file now has its own key."
> 📕 **Bhardwaj & Kaushik (2023), §5.4:** "iOS Secure Enclave wraps keys in hardware — no software exploit can bypass it without the device passcode."

---

### Q8. What is Wear Leveling in NAND flash and how does it complicate forensic analysis?

**A8.**
**Wear leveling** is a Flash Translation Layer (FTL) algorithm that distributes writes evenly across all NAND blocks to prevent premature failure from repeated erasure cycles.

**Types:** static (also moves cold/static data) vs. dynamic (only considers actively-written blocks).

**Mechanism:** FTL maintains a **LBA → physical page mapping table**. Logical addresses presented to the OS do not correspond to fixed physical locations — they are remapped constantly.

**Forensic complications:**
1. Raw NAND dump is in **physical page order** — requires FTL reconstruction for a coherent logical image.
2. Mapping tables may be spread across NAND or in a dedicated OOB (out-of-band) management area.
3. Previously deleted data may reside in **out-of-map pages** not visible at the logical level.
4. Bad-block management adds further remapping.
5. Each vendor uses proprietary FTL formats — no universal solution exists.

> 📙 **Dejey (2018), §4.2:** "Wear leveling breaks the assumption that logical and physical addresses correspond — this is the central challenge of chip-off forensics."

---

### Q9. Describe the role of TEE / Secure Enclave in mobile devices and its forensic impact.

**A9.**
A **Trusted Execution Environment (TEE)** is a hardware-isolated secure processor running alongside the main OS, with dedicated memory regions inaccessible to the main OS or any software running on it.

**Apple Secure Enclave:** dedicated co-processor with its own memory, entropy source, and AES engine — manages Touch ID/Face ID keys, data protection class keys, and Apple Pay credentials.

**Android TEE (ARM TrustZone / Qualcomm QSEE / Google Titan M):** provides equivalent via Android Keymaster HAL.

**Forensic impact:**
- Encryption keys stored in TEE/Secure Enclave **cannot be extracted by any software method** on the main OS.
- Physical attacks on the enclave chip are impractical and legally prohibited without authorization.
- Data protected by TEE requires the correct passcode/biometric — the only legitimate path.
- TEE provides **secure boot attestation** — OS modification to bypass protection causes TEE to refuse key release.

> 📘 **Jain & Kalbande (2016), §4.4:** "Hardware-backed key storage represents the highest level of cryptographic protection available on consumer devices."
> 📕 **Bhardwaj & Kaushik (2023), §5.5:** "The Secure Enclave implements a hardware UID fused at manufacturing — even Apple cannot reconstruct keys without the individual device."

---

### Q10. Explain file carving and its key limitation for media recovery.

**A10.**
**File carving** reconstructs files from raw binary data by identifying known **file signatures** (magic bytes / headers) and optionally footers, without needing filesystem metadata.

**Process:** scan image for headers (JPEG: `FF D8 FF`, PNG: `89 50 4E 47`, MP4: `66 74 79 70`), extract from header to footer/fixed size, output candidate files.

**Tools:** `photorec`, `scalpel`, `foremost`, `bulk_extractor`

**Key limitation — fragmentation:**
- Modern filesystems (ext4, F2FS, APFS) may store a single file across non-contiguous blocks.
- Carving assumes contiguous layout — fragmented files produce truncated/corrupted recoveries.
- NAND wear leveling scatters physical pages, compounding fragmentation.
- **No filename, path, or original timestamp** is recovered from carved files — must be reconstructed from context.
- False positives occur when header bytes appear in non-file binary data.

> 📗 **Reiber (2020), §5.7:** "File carving is powerful but produces imperfect results on heavily written devices where fragmentation is high."
> 📕 **Bhardwaj & Kaushik (2023), §8.4:** "Carve from unallocated space only to avoid flooding output with live file duplicates."

---

### Q11. Outline steps to forensically image an Android device that is unlocked with USB debugging enabled.

**A11.**

| Step | Action | Command |
|---|---|---|
| 1 | Document device state, photograph, record IMEI | `adb shell getprop ro.serialno` |
| 2 | Verify ADB trust | `adb devices` → must show `device` not `unauthorized` |
| 3 | Logical backup | `adb backup -apk -shared -all -f backup.ab` |
| 4 | Pull accessible media | `adb pull /sdcard/DCIM/ /lab/evidence/` |
| 5 | Physical image (if rooted) | `adb shell "su -c 'dd if=/dev/block/by-name/userdata bs=4096 | gzip'"` > userdata.gz |
| 6 | Hash verification | `shasum -a 256 userdata.img | tee userdata.sha256` |
| 7 | Preserve original | Return device to evidence bag; all analysis on working copy |

> 📗 **Reiber (2020), §5.2:** "All ADB commands must be logged; redirect `adb logcat` to a session file for chain-of-custody documentation."
> 📕 **Bhardwaj & Kaushik (2023), §7.3:** "For Android 10+, `adb backup` may be restricted by apps using `allowBackup=false` — prefer physical imaging."

---

### Q12. How are SMS and MMS stored on Android, and how can deleted messages be recovered?

**A12.**
**Storage:**
- `mmssms.db` under `/data/data/com.android.providers.telephony/databases/`
- Key tables: `sms` (text), `mms` (MMS headers), `part` (MMS media parts), `threads` (conversations)
- MMS media: `/data/data/com.android.providers.telephony/app_parts/`

**SMS schema fields:** `_id, thread_id, address, date (ms Unix epoch), type (1=inbox/2=sent), body, read, status`

**Recovery of deleted messages:**
1. **WAL file:** preserve `mmssms.db-wal` — contains uncommitted transactions including deletions.
2. **Freelist pages:** parse unallocated SQLite pages with tools (`undark`, `sqlite-dissect`) for deleted row remnants.
3. **Physical image carving:** search raw image for SQLite row patterns matching `sms` schema.
4. **Backup sources:** Google Messages backup to Google Drive may contain messages deleted from device.

```zsh
sqlite3 mmssms.db "SELECT datetime(date/1000,'unixepoch','localtime'),address,body,type FROM sms ORDER BY date DESC LIMIT 50;"
```

> 📕 **Bhardwaj & Kaushik (2023), §8.1:** "SQLite freelist pages are the primary recovery path for deleted messages — they retain deleted row data until overwritten."

---

### Q13. How does EXIF metadata in photos support a forensic timeline?

**A13.**

| EXIF Field | Forensic Use |
|---|---|
| `DateTimeOriginal` | Exact moment shutter was pressed (camera clock) |
| `GPSLatitude / GPSLongitude` | Geolocation of photo capture |
| `GPSDateStamp / GPSTimeStamp` | GPS-sourced UTC time — compare with `DateTimeOriginal` for clock skew |
| `Make / Model` | Device identification — corroborate with case records |
| `Software` | App/OS version that last processed the image |
| `Orientation` | Device orientation (portrait/landscape) at capture |

**Timeline building:** correlate `DateTimeOriginal` with message send timestamps, call records, and GPS location history. Cross-validate `GPSDateStamp` (UTC) vs `DateTimeOriginal` (local clock) to detect clock manipulation.

```zsh
exiftool -DateTimeOriginal -GPSLatitude -GPSLongitude -GPSDateStamp -Model image.jpg
```

> 📘 **Jain & Kalbande (2016), §6.3:** "EXIF data can be modified with simple tools — always corroborate with filesystem timestamps and upload records before asserting EXIF dates in court."

---

### Q14. What are SQLite WAL files and how do they aid deleted row recovery?

**A14.**
**WAL (Write-Ahead Log)** is a SQLite journaling mode where modifications are appended to a `-wal` file **before** being checkpointed into the main database, enabling concurrent readers and crash recovery.

**Internal structure:**
- WAL contains sequential **frames** — each frame is a complete copy of a modified page at a transaction boundary.
- Multiple versions of the same page can exist in the WAL (prior states).
- `-shm` (shared memory) file coordinates concurrent WAL access.

**Forensic value:**
1. **Recent deletions:** rows deleted but not yet checkpointed remain in WAL frames.
2. **Historical page states:** older frames hold pre-deletion versions of rows.
3. **Recovery method:** parse each WAL frame independently with forensic SQLite tools to reconstruct prior database states.

**Critical rule:** collect `database.db` + `database.db-wal` + `database.db-shm` together as one evidence unit.

```zsh
sqlite3 mmssms.db "PRAGMA journal_mode;"  # confirm 'wal' mode
# Then preserve all three files before any DB operations
```

> 📕 **Bhardwaj & Kaushik (2023), §8.2:** "The WAL file is often more valuable than the main DB — preserve it before performing any database operations."

---

### Q15. How does a Faraday bag both help and hinder evidence preservation?

**A15.**
A **Faraday bag** attenuates RF signals, blocking cellular, Wi-Fi, Bluetooth, and GPS communication.

**Benefits:**
- Prevents remote wipe commands (MDM, Find My Device, "Erase iPhone") from reaching the device.
- Stops new data writes (incoming messages, cloud sync) from altering the evidence state.
- Blocks GPS tracking of the evidence bag during transport.

**Drawbacks:**
- Blocks incoming messages/calls that might constitute additional evidence.
- Accelerates battery drain as device continuously searches for networks at high power.
- Some MDMs queue wipe commands and execute them on next network connection — Faraday only delays, not prevents.
- If device powers off due to battery depletion inside the bag, RAM contents are lost.

**Best practice:** Faraday bag + Airplane Mode + Faraday-compatible charger for sustained isolation without battery loss.

> 📗 **Reiber (2020), §4.5:** "Faraday isolation and airplane mode together provide overlapping protection — neither alone is fully reliable against all modern MDM configurations."

---

### Q16. Describe the role of SIM cards in mobile forensics.

**A16.**
A **SIM (Subscriber Identity Module)** is a tamper-resistant ISO 7816 smart card authenticating a subscriber to a mobile network.

**Key forensic data (elementary files):**

| Elementary File | Contents |
|---|---|
| EF_IMSI | International Mobile Subscriber Identity |
| EF_MSISDN | Subscriber phone number |
| EF_ICCID | SIM serial number |
| EF_SMS | SMS messages (capacity: 10–40 records) |
| EF_ADN | Abbreviated Dialing Numbers (phonebook) |
| EF_LND | Last Numbers Dialled |
| EF_LOCI | Last registered cell location area (LAI) |

**Acquisition:**
```zsh
pySIM-shell --pcsc-device 0
> select MF; select DF_TELECOM; select EF_SMS; read_record
```

> 📙 **Dejey (2018), §5.3:** "Even with a damaged or encrypted device, the SIM card can independently yield subscriber identity, location, and stored messages."

---

### Q17. How can investigators access cloud-synchronized data when the device is encrypted?

**A17.**
**Step 1 — Legal preservation:** Send a preservation letter to the provider immediately — most retain data 90–180 days under preservation. Delayed requests risk data deletion.

**Step 2 — Legal process:**
- **Subpoena** → non-content metadata (subscriber info, account activity).
- **Search warrant / court order** → message bodies, media, emails.
- **MLAT** → for providers with data in foreign jurisdictions.

**Step 3 — Token-based access (with explicit legal authorization):**
- Locate OAuth tokens in app storage: `shared_prefs/*.xml`, cache JSON files, `databases/*.db`.
- Use tokens to query provider APIs within authorized scope.

**Step 4 — Backup exploitation:**
- iCloud/Google Drive backups often contain decrypted app data — request via legal process.
- Device-side cloud tokens may allow investigator-controlled access to provider backup APIs.

> 📗 **Reiber (2020), §10.3:** "Cloud providers often hold the most complete evidence precisely because they receive synchronized, unencrypted data from the device."

---

### Q18. What is a write-blocker and why is it important in mobile forensics?

**A18.**
A **write-blocker** intercepts and blocks all write commands to a storage medium during acquisition, ensuring the original evidence is not modified.

**Hardware write-blockers** (Tableau T8-R2, WiebeTech): intercept SATA/USB/PCIe commands at hardware level — no OS driver can bypass them.

**Software write-blockers:** mount options (`-o ro`), registry settings, or forensic tool flags — less reliable.

**Mobile context:**
- Traditional hardware write-blockers don't apply to mobile USB interfaces.
- Equivalents: read-only mounts in TWRP, forensic software with no-write guarantees, ADB restricted to read-only commands.
- ADB has **no built-in write-block** — every `adb shell` command could write to device; document all commands used.

> 📓 **Steuart et al. (2013), §10.3:** "Using a write-blocker is not optional — its absence is a standard challenge point for opposing experts in court."

---

### Q19. How can Wi-Fi artifacts and MAC addresses assist an investigation?

**A19.**

| Artifact | Android Path | iOS Path |
|---|---|---|
| Known SSIDs | `/data/misc/wifi/WifiConfigStore.xml` | `com.apple.wifi.plist` |
| Connection timestamps | System logs / `wifilog.db` | `WiFiManagerDef.plist` |
| BSSID (AP MAC) | In SSID config entries | In WiFi preference plist |

**Investigative uses:**
- **Geolocation:** BSSID → geolocate AP via WiGLE.net → place device near that location.
- **Co-location:** Two devices with matching BSSID history → probable co-presence.
- **Timestamp anchoring:** Wi-Fi connect/disconnect events anchor other artifacts to a time window.

**Caveat:** modern Android/iOS use **MAC address randomization** per-network — device MAC is not a stable hardware identifier. Use BSSID (AP side) not the device MAC for location correlation.

> 📘 **Jain & Kalbande (2016), §7.2:** "Wi-Fi probe records and connection logs are persistent artifacts that often outlast deletion of other user data."

---

### Q20. What are the key advantages of timeline analysis in mobile forensics?

**A20.**
Timeline analysis merges timestamped artifacts from heterogeneous sources into a single chronological view:

1. **Activity reconstruction** — establish sequence of user actions (message → photo → location check-in → cloud sync).
2. **Causality detection** — identify which event preceded another; critical for establishing intent or alibi.
3. **Anomaly detection** — clock manipulation, impossible sequences, or unexplained gaps in continuous logs.
4. **Multi-source corroboration** — concordance across 4–5 independent sources (EXIF, SMS DB, call log, Wi-Fi, PCAP) is far harder to fabricate than a single artifact.
5. **Court presentation** — a visual timeline is more comprehensible to juries than raw database dumps.

**Tools:** Plaso/log2timeline (ingestion), Timesketch (visualization), Excel/LibreOffice (simple timelines).

> 📗 **Reiber (2020), §11.1:** "Timeline analysis transforms isolated artifacts into a coherent narrative of events — it is the core analytical framework of mobile forensics."

---

### Q21. How do Android and iOS differ in app sandboxing and data storage?

**A21.**

| Aspect | Android | iOS |
|---|---|---|
| App data root | `/data/data/<package>/` | `/private/var/mobile/Containers/Data/Application/<GUID>/` |
| Sandbox enforcement | Unix permissions + SELinux MAC | Code-signing entitlements + sandbox profiles |
| Credential storage | Android Keystore (hardware-backed) | Keychain + Secure Enclave |
| Config files | SharedPreferences XML (`shared_prefs/`) | NSUserDefaults → plist files |
| External storage | `/sdcard/`, `/storage/emulated/0/` | Sandboxed `Files` app container |
| Path discoverability | Predictable: package name → path | Requires `Manifest.db` lookup for GUID-based paths |

**Forensic implication:** iOS GUID paths require `Manifest.db` from the backup to map `relativePath → fileID`; Android paths are predictable by package name but require root for protected data.

> 📕 **Bhardwaj & Kaushik (2023), §10.1:** "The GUID-based iOS directory structure means examiners must always consult `Manifest.db` to map evidence file paths."

---

### Q22. Describe the SQLite freelist and why it is forensically valuable.

**A22.**
SQLite uses a **B-Tree page structure**. When rows are deleted, their pages are added to the **freelist** — a linked list of unused page numbers embedded in the database header — rather than being immediately zeroed.

**Freelist structure in header:** bytes 36–39 = first freelist trunk page; bytes 32–35 = freelist page count.

**Recovery process:**
1. Open raw `.db` file in hex editor or forensic tool.
2. Navigate to freelist trunk page → freelist leaf pages.
3. Extract raw binary content from freelist pages — deleted row data is typically still present.
4. Use tools like `sqlite-dissect`, `undark`, or `sqlparse` to automate.

**Limitation:** if a freelist page has been reallocated and overwritten with new data, deleted content is gone.

```zsh
sqlite3 mmssms.db "PRAGMA freelist_count;"  # shows pages available on freelist
```

> 📕 **Bhardwaj & Kaushik (2023), §8.2:** "The freelist is unencrypted even on encrypted devices — once the DB is extracted in decrypted form, freelist pages yield deleted evidence."

---

### Q23. What is the forensic significance of iOS Keychain and Android Keystore?

**A23.**

| Aspect | iOS Keychain | Android Keystore |
|---|---|---|
| Storage | Encrypted DB in `/private/var/Keychains/` | Hardware-backed TEE / StrongBox |
| Protection | Protection classes (e.g., `WhenUnlocked`) + Secure Enclave | Hardware binding — key never leaves TEE |
| Backup accessibility | **Yes** — in encrypted backups if password is known | **No** — not extractable via ADB or root |
| Contents | Passwords, tokens, certificates, Wi-Fi creds | Cryptographic keys, signing keys, key derivation |
| Forensic access path | Encrypted iOS backup + known backup password | None (hardware-binding is the enforcement) |

**Forensic value of Keychain in practice:** unencrypted iOS backups **exclude** Keychain items. Always capture encrypted backups with a known password to include Keychain data.

> 📗 **Reiber (2020), §8.5:** "Unencrypted iOS backups exclude keychain items — always use encrypted backups to capture the full credential set."

---

### Q24. How can deleted files on flash storage be recovered despite wear-leveling and garbage collection?

**A24.**
**Why recovery is sometimes possible:**
1. **GC lag:** Flash controllers batch-erase blocks — data in not-yet-erased blocks is still readable.
2. **Out-of-map pages:** Wear leveling may leave old physical pages logically orphaned but physically unearased.
3. **Tombstoning:** Some FTL implementations mark pages as invalid (tombstone) before eventual erase.

**Recovery technique:**
1. Obtain **raw physical NAND dump** (chip-off most complete; JTAG/ISP for accessible interfaces).
2. Identify FTL metadata (OOB spare area, management blocks).
3. Reconstruct historical LBA→physical mapping from FTL state.
4. Carve out-of-map physical pages for file signatures.

**Factors reducing recovery chances:**
- TRIM support in eMMC/UFS — proactive block erasure on delete.
- High device activity overwrites old data quickly.
- Vendor-specific FTL proprietary formats require reverse engineering.

> 📙 **Dejey (2018), §4.3:** "The window for NAND data recovery narrows rapidly with device use — immediate physical acquisition after seizure is critical."

---

### Q25. How can an investigator extract evidence from WhatsApp on Android?

**A25.**
**File locations:**
- Message DB: `/data/data/com.whatsapp/databases/msgstore.db` (AES-256-CBC encrypted)
- Encryption key: `/data/data/com.whatsapp/files/key`
- Media: `/sdcard/WhatsApp/Media/` (images, videos, voice notes organized by type)

**Extraction and decryption:**
1. Extract `msgstore.db` and `key` file (requires root or older ADB backup method).
2. Decrypt using `wa-crypt-tools` or `whatsapp-viewer` with the key file.
3. Open decrypted DB with `sqlite3`.

**Key queries:**
```zsh
# All messages with timestamp, sender, content
sqlite3 decrypted_msgstore.db \
  "SELECT datetime(timestamp/1000,'unixepoch','localtime') AS ts,
          key_remote_jid, data, key_from_me
   FROM messages WHERE data IS NOT NULL ORDER BY timestamp DESC LIMIT 100;"

# Media references
sqlite3 decrypted_msgstore.db \
  "SELECT datetime(timestamp/1000,'unixepoch','localtime'), media_wa_url, media_name
   FROM messages WHERE media_wa_url IS NOT NULL LIMIT 50;"
```

**iOS:** extract app container from iOS backup → locate `ChatStorage.sqlite` → same SQL analysis approach; schema differs by version.

> 📕 **Bhardwaj & Kaushik (2023), §10.3:** "WhatsApp encryption key management changes across app versions — always verify the encryption scheme against the installed app version."

---

### Q26. What steps verify the integrity of an acquired forensic image?

**A26.**
**Integrity verification procedure:**
1. **Pre-acquisition hash:** hash the original medium or partition *before* imaging (if accessible read-only).
2. **Post-acquisition hash:** immediately hash the acquired image file.
3. **Verify match:** pre- and post-acquisition hashes must match to prove acquisition fidelity.
4. **Transfer verification:** re-hash image after every transfer (network copy, USB copy) to confirm no corruption.
5. **Pre-analysis verification:** hash working copy before any analysis; compare to master image hash.
6. **Document:** record algorithm (SHA-256 preferred), tool, version, date/time, and hash values in the CoC.

```zsh
shasum -a 256 evidence.dd | tee evidence.dd.sha256
# Transfer to workstation...
shasum -a 256 -c evidence.dd.sha256   # verify after transfer
```

> 📘 **Jain & Kalbande (2016), §3.4:** "NIST SP 800-101 recommends dual hashing (MD5 + SHA-256) for forward-compatible integrity verification."
> 📓 **Steuart et al. (2013), §10.4:** "Hashes documented in the chain-of-custody demonstrate that evidence is identical to what was originally acquired."

---

### Q27. Why is documenting tool versions and exact commands critical?

**A27.**
Documenting tools and commands ensures **reproducibility, transparency, and admissibility**:

1. **Reproducibility:** courts and peer reviewers may require independent replication; different tool versions can produce different parsing results for the same input.
2. **Methodology defense:** opposing experts will challenge every step — documented commands provide an auditable, defensible record.
3. **Error identification:** if a tool version had a known bug affecting a specific artifact type, documentation allows retrospective assessment.
4. **Admissibility:** expert testimony standards (Daubert in US courts) require methodology to be testable and reproducible — documentation is the proof.

**Minimum documentation:** tool name, version number, exact command line with all flags, input file hash, output file(s), and run timestamp. Save tool logs and configuration files.

> 📓 **Steuart et al. (2013), §12.1:** "Reproducibility is a cornerstone of forensic science — if your results cannot be independently replicated, they may be inadmissible."

---

### Q28. How do application caches and temporary files help in investigations?

**A28.**
**App caches** are storage areas where applications retain recently used data for performance — often containing:
- **Thumbnail images** of recently viewed photos, messages, or media.
- **Recently accessed content** (web pages, documents, messages displayed on screen).
- **Session tokens** and authentication cookies.
- **Transient artifacts** reflecting user activity even after primary records are deleted.

**Forensic value:**
- Even if the main database is deleted or encrypted, **cache files may retain plaintext copies** of recent content.
- Thumbnail cache analysis can reveal what images were viewed even when originals are deleted.
- Browser/app HTTP cache shows recently accessed URLs and page content.
- Cache timestamps reveal recent access patterns.

**Locations:** Android `/data/data/<package>/cache/`; iOS `<AppContainer>/Library/Caches/`

> 📗 **Reiber (2020), §7.4:** "App caches are often overlooked but contain contemporaneous evidence of user activity that persists even after deliberate deletion of primary records."

---

### Q29. How should investigators handle a locked Android device with USB debugging disabled?

**A29.**
When USB debugging is disabled and the device is locked, options are progressively escalating:

| Option | Method | Notes |
|---|---|---|
| **Legal compulsion** | Court order compelling passcode disclosure | Jurisdiction-dependent; most effective |
| **Vendor cooperation** | Google/Samsung may provide data via legal process | Data may be partial/logical only |
| **Cloud backup** | Google Account backup via legal request | Decrypted copy at provider |
| **JTAG/ISP** | Hardware-level access to flash via test pads | Requires lab equipment; image is encrypted |
| **Chip-off** | Physical NAND extraction | Last resort; yields encrypted image |
| **Authorized exploitation** | Certified vendor tools (GrayKey, Cellebrite Premium) | Requires formal authorization; legal restrictions vary |

**Critical rule:** do NOT attempt brute-force passcode entry — Android may implement attempt limits with factory reset wipe after threshold.

> 📕 **Bhardwaj & Kaushik (2023), §6.2:** "Locked devices require legal authorization before any bypass technique; document all attempted methods even if unsuccessful."

---

### Q30. What metadata fields are found in call logs and how are they used forensically?

**A30.**
**Android call log fields** (`calllog.db` / `calls` table):

| Field | Forensic Use |
|---|---|
| `number` | Caller/callee phone number |
| `duration` | Call length in seconds — short duration may suggest unanswered/voicemail |
| `date` | Call start time (Unix epoch ms) |
| `type` | 1=incoming, 2=outgoing, 3=missed, 4=voicemail |
| `name` | Contact name if matched |
| `geocoded_location` | Country/region of number (carrier-level) |

**Investigative applications:**
- **Communication pattern analysis:** frequency, duration, and timing of calls between parties.
- **Alibi correlation:** call timestamps vs location records — was the device near the alleged location at the time of a call?
- **Missed call analysis:** missed calls may indicate urgency or avoidance.
- **Carrier record corroboration:** cross-validate device-side call log with carrier CDRs (Call Detail Records).

```zsh
sqlite3 calllog.db "SELECT datetime(date/1000,'unixepoch','localtime'),number,duration,type FROM calls ORDER BY date DESC;"
```

> 📗 **Reiber (2020), §7.1:** "Call logs are among the most reliable timeline artifacts — they represent carrier-logged events that are difficult to fabricate locally."

---

### Q31. How can SIM card extractions complement mobile device evidence?

**A31.**
SIM cards yield evidence independently of device storage — even from damaged or encrypted devices:

- **IMSI** → uniquely identifies the subscriber; cross-reference with carrier records to confirm account ownership.
- **ICCID** → identifies the specific SIM card; useful to trace SIM swaps.
- **EF_SMS** → up to 40 SMS messages stored on SIM (many users unknowingly retain messages here).
- **EF_LOCI** → last registered Location Area Identity (LAI) — approximates last known network location.
- **EF_LND** → last numbers dialled — may differ from device call log (dialled before SIM was inserted in current device).

**Complementary value:** if device data is encrypted and inaccessible, SIM artifacts provide an independent corroborating data stream. Combined with carrier CDRs, SIM analysis can reconstruct significant communication history.

> 📙 **Dejey (2018), §5.2:** "The SIM card is an independent evidence artifact that survives device encryption and should always be examined separately."

---

### Q32. Discuss the forensic implications of cloud backups for mobile investigations.

**A32.**
Cloud backups (iCloud, Google Drive/One, Samsung Cloud) often contain **decrypted, complete copies** of device data and are held under the provider's control — making them critical when local device data is encrypted or destroyed.

**Key implications:**
1. **Availability:** providers retain backups for varying periods; preservation letters must be sent immediately.
2. **Completeness:** iCloud encrypted backups include keychain data, Health data, and app data — often more complete than local device acquisition.
3. **Legal access path:** warrant/court order required for content (message bodies, photos); subpoena sufficient for metadata (account records, backup timestamps).
4. **Encryption model:** Google and Apple hold encryption keys for standard backups (they can comply with legal requests); Advanced Data Protection (Apple, opt-in) uses end-to-end encryption — Apple cannot provide plaintext.
5. **On-device indicators:** `LastBackupDate` in backup plist files, account settings, sync timestamps reveal if/when cloud backup occurred.

> 📗 **Reiber (2020), §10.2:** "Cloud backups are often the most accessible and complete source of evidence — providers hold decrypted data under standard backup models."

---

### Q33. Explain the differences between FTL (Flash Translation Layer) and a file system.

**A33.**

| Layer | FTL | File System |
|---|---|---|
| Level | Firmware (inside flash controller) | OS software layer |
| Function | Maps logical block addresses → physical NAND pages; manages wear leveling, bad blocks, GC | Organizes files, directories, and metadata |
| Visibility to OS | Transparent — OS sees a block device | Fully visible — OS mounts and uses it |
| Forensic challenge | Physical pages may not correspond to logical order; vendor-specific format | Standard formats (ext4, F2FS, APFS) have known parsers |
| Recovery path | Requires FTL reconstruction (chip-off → physical dump → FTL reverse engineering) | Standard filesystem forensics tools apply |

**Combined forensic view:** a file system view shows logical files and directories; a raw NAND dump shows physical pages under FTL mapping. Reconciling both is required for comprehensive physical-layer forensics.

> 📙 **Dejey (2018), §4.1:** "The FTL abstracts hardware details from the OS — but forensic examiners who bypass the OS must deal with FTL complexity directly."

---

### Q34. How can network artifacts on a device help an investigation?

**A34.**
Network artifacts reflect device connectivity history and can place a device in space and time:

| Artifact | Location | Forensic Use |
|---|---|---|
| Wi-Fi SSIDs + BSSIDs | `WifiConfigStore.xml` / `com.apple.wifi.plist` | Location correlation via AP geolocation |
| Wi-Fi timestamps | System logs / wifi logs | Time-anchor events |
| DNS cache | System log, network monitor | Domains contacted (even if traffic encrypted) |
| HTTP cache | App caches, WebView storage | URLs and page content retrieved |
| ARP cache | Volatile (RAM only) | Other devices on same network |
| Network interfaces | System info | MAC addresses, IP assignments |

**Advanced use:** correlate DNS queries with message timestamps → prove a specific URL was accessed before/after a suspect event. HTTP cache content can include fragments of encrypted communications viewed in a WebView.

> 📘 **Jain & Kalbande (2016), §7.3:** "Network artifacts are a persistent fingerprint of a device's connectivity history — particularly valuable when GPS data is absent."

---

### Q35. How do you analyze app-specific encryption of message databases?

**A35.**
**Step-by-step approach:**

1. **Identify the encryption scheme:** examine the app's APK (Android) or IPA (iOS) binary; look for `javax.crypto`, `AES`, `ChaCha20`, or third-party crypto library imports via `jadx` (Android decompiler) or `Hopper` (iOS disassembler).

2. **Locate the key:** common locations:
   - App files directory (`/data/data/<pkg>/files/key` — WhatsApp pattern)
   - Keystore/Keychain (hardware-bound — may be inaccessible)
   - Derived from device IMEI/serial + a static salt (weaker apps)
   - Network-fetched on first run (requires capture of network traffic at initialization)

3. **Decrypt:** use extracted key with appropriate cipher (AES-GCM, AES-CBC, ChaCha20-Poly1305) — verify IV/nonce location in file header.

4. **Validate:** hash decrypted output and verify structural integrity (SQLite magic bytes, JSON structure) to confirm correct decryption.

5. **Document:** record key source, cipher used, tool/script, and hash of both encrypted and decrypted versions.

> 📕 **Bhardwaj & Kaushik (2023), §10.4:** "App-level encryption adds a third layer above OS encryption — the app's key management model must be reverse-engineered for each target application."

---

### Q36. What is the purpose of hashing evidence images before and after analysis?

**A36.**
Hashing provides a **cryptographic fingerprint** that proves data has not been altered:

| Point | Hash purpose |
|---|---|
| After acquisition | Proves acquired image is identical to source |
| After every transfer | Confirms no corruption during copying |
| Before any analysis | Confirms working copy matches master |
| In final report | Ties court-presented evidence to original acquisition |

**Algorithm selection:** SHA-256 is the current standard (NIST SP 800-101 Rev 2). MD5 alone is considered insufficient due to collision vulnerabilities — use alongside SHA-256 for backward compatibility with older procedures.

**Best practice:** store hashes in a separate, signed document (digital or physical) alongside the chain-of-custody log. Any hash mismatch is a red flag requiring documentation and potential re-examination.

```zsh
shasum -a 256 evidence.dd > evidence.dd.sha256      # acquisition
shasum -a 256 -c evidence.dd.sha256                  # verification
```

> 📓 **Steuart et al. (2013), §10.4:** "A hash mismatch between acquisition and presentation is arguably the most damaging issue for digital evidence admissibility."

---

### Q37. Explain timestamp and timezone normalization in forensic timelines.

**A37.**
**Why normalization matters:** timestamps originate in different formats and reference points across artifact sources.

| Source | Format | Reference point |
|---|---|---|
| Android SMS DB | Unix ms (integer) | 1970-01-01 UTC |
| iOS SMS DB | Apple ns (integer) | 2001-01-01 UTC |
| iOS CallHistory | Apple s (float) | 2001-01-01 UTC |
| EXIF DateTimeOriginal | `YYYY:MM:DD HH:MM:SS` | **Local device time** (no timezone) |
| GPSDateStamp | `YYYY:MM:DD` + GPSTimeStamp | **UTC** |
| Plaso output | ISO 8601 | UTC |

**Normalization steps:**
1. Convert all to Unix epoch (seconds, UTC).
2. Apple epoch: `unix_ts = apple_ts + 978307200`
3. EXIF: determine device timezone from GPS timestamps or system logs; apply offset.
4. Document every conversion formula in the report.
5. Flag discrepancies between sources as potential evidence of clock manipulation.

> 📗 **Reiber (2020), §11.3:** "Failing to normalize timestamps is one of the most common analytical errors in mobile forensics — resulting in event sequences that are months out of order."

---

### Q38. How can investigators detect anti-forensic measures on a mobile device?

**A38.**
**Anti-forensic indicators on mobile devices:**

| Indicator | What it suggests |
|---|---|
| Factory reset logs / low data volume | Intentional data destruction |
| Presence of secure-delete apps (Eraser, iShredder) | Deliberate evidence destruction attempt |
| Gaps in continuous system logs | Log tampering or selective deletion |
| EXIF timestamps earlier than device manufacture date | Timestamp forgery |
| SQLite VACUUM marks or empty freelists | DB has been compacted — deleted rows overwritten |
| App uninstall timestamps just before/after incident | Evidence-relevant apps removed |
| Modified OS image (rooted with custom ROM) | Potential anti-forensic tooling installed |

**Responses:**
- Correlate with **carrier CDRs** — call and data records held by carriers are independent of device control.
- Examine **cloud provider records** — logs of account activity are server-controlled.
- Note and document anti-forensic indicators explicitly in the forensic report — they are themselves evidence.

> 📕 **Bhardwaj & Kaushik (2023), §12.1:** "Anti-forensic activity is not merely an obstacle — it is evidence of consciousness of guilt and should be documented thoroughly."

---

### Q39. How do you recover deleted SQLite records from a forensic image?

**A39.**
**Complete recovery procedure:**

**Step 1:** Extract DB, WAL, and SHM files together from the image (preserve as a set).
```zsh
cp mmssms.db mmssms.db-wal mmssms.db-shm /lab/recovered_dbs/
```

**Step 2:** Check WAL for uncommitted deleted rows.
```zsh
sqlite3 mmssms.db "PRAGMA journal_mode;"   # confirm WAL mode
sqlite3 mmssms.db "PRAGMA wal_checkpoint;" # checkpoint (only on copy!)
```

**Step 3:** Parse freelist pages using forensic tools.
```zsh
# Using undark (open source SQLite forensics tool)
undark -i mmssms.db --table sms > recovered_sms.txt

# Using sqlite-dissect
sqlite-dissect --export-csv mmssms.db /output/
```

**Step 4:** Carve raw image for SQLite row patterns (for rows whose pages were freed and unallocated).
```zsh
bulk_extractor -o /bulk_output/ -x all -e sqlite userdata.img
```

**Step 5:** Validate recovered data — cross-reference with WAL content and any cloud backup copy to confirm authenticity.

> 📕 **Bhardwaj & Kaushik (2023), §8.3:** "The combination of WAL parsing, freelist analysis, and raw carving provides the best chance of recovering deleted SQLite records."

---

### Q40. What is the forensic significance of media metadata beyond EXIF?

**A40.**
Beyond EXIF tags, media files carry additional metadata layers:

| Metadata type | Location | Forensic value |
|---|---|---|
| Filesystem timestamps (mtime, ctime, atime) | FS metadata | Last modification, creation, access times |
| MP4 container atoms (`moov`, `mvhd`) | MP4 file header | Video creation time, duration, encoder |
| MPEG-4 `creation_time` atom | `ffprobe` readable | UTC time when video was recorded |
| XMP metadata | Embedded in JPEG/PNG | Editing software, geolocation, copyright |
| Thumbnail cache | Device cache dirs | Shows image was viewed on device |
| Video GPS track | Some cameras embed GPS track in MP4 | Geolocation trail during recording |

```zsh
ffprobe -v quiet -print_format json -show_format -show_streams video.mp4 | grep -i "creation_time\|location"
exiftool -a -G1 -s -XMP:all image.jpg
```

> 📘 **Jain & Kalbande (2016), §6.4:** "Container-level metadata in MP4 files provides evidence independent of EXIF — it reflects the recording device's internal clock, not editable by standard photo tools."

---

### Q41. How can investigators extract evidence from cloud-only messaging services?

**A41.**
When messages are not stored locally (Telegram Cloud-only chats, server-only web apps):

**Path 1 — Legal process:**
- Subpoena non-content metadata (account info, IP logs, timestamps) — most providers comply.
- Search warrant for message content — compliance varies by provider jurisdiction and policy.
- MLAT for foreign providers.

**Path 2 — Device-side artifacts:**
- **Notification records** — notification service DBs may cache message previews, sender IDs, and timestamps.
- **App database** — even cloud-only apps may cache recent messages locally.
- **OAuth/session tokens** — authorize legal investigator-controlled access to provider API.

**Path 3 — Linked devices:**
- Desktop or tablet versions of the app may sync message history locally.

**Path 4 — Provider data exports:**
- Some providers (Google, Meta) offer account data exports via legal channels.

> 📗 **Reiber (2020), §10.4:** "Cloud-first applications require cloud-first investigation strategies — the legal process must be initiated as early as possible before provider retention windows expire."

---

### Q42. How do differential backups help recover missing evidence?

**A42.**
**Differential backup model:** each backup captures all changes since a base (full) backup — multiple differentials allow time-travel reconstruction of data state.

**Forensic workflow:**
1. Collect all available backups: device-local, iCloud/Google Drive, iTunes backup history.
2. Reconstruct device state at each backup point by applying differentials in sequence.
3. Compare consecutive backups to identify:
   - **Files added between backups** → creation events.
   - **Files missing in later backup** → deletion events with approximate timestamps.
   - **File content changes** → modification history.
4. Present a timeline of data lifecycle based on backup deltas.

**Practical tools:** `idevicebackup2` for iOS backup history; Google Takeout exports; commercial tools (Elcomsoft Phone Breaker, AXIOM) automate backup diff analysis.

> 📕 **Bhardwaj & Kaushik (2023), §11.3:** "Multiple cloud backups are time-machine evidence — comparing them reveals deleted content that may no longer exist on the device."

---

### Q43. Describe a defensible method to image a locked iOS device with unknown passcode.

**A43.**
**Decision matrix for locked iOS:**

| Method | Requires | Notes |
|---|---|---|
| **Logical via paired computer backup** | Prior trusted pairing on a lab computer | Use `idevicebackup2` — encrypted backup preferred |
| **iCloud backup via legal request** | Provider warrant | Apple provides decrypted backup data |
| **Certified commercial tool (Cellebrite Premium, GrayKey)** | Formal authorization + contract | Performs passcode recovery via bootrom/OS exploits — jurisdiction and version dependent |
| **Vendor cooperation (Apple)** | Specific legal process | Limited — Apple can extract iCloud data but not bypass Secure Enclave on device |
| **Chip-off** | Physical access + expertise | Yields encrypted image — not decryptable without passcode |

**Documentation requirements:** record every attempted method, outcome, tool version, legal authority reference, and why each was pursued. A defensible report explicitly acknowledges limitations.

> 📕 **Bhardwaj & Kaushik (2023), §6.3:** "Commercial tools that bypass iOS passcodes must be used strictly within authorized legal frameworks — their use without a valid warrant constitutes unauthorized access."

---

### Q44. What is forensic triage and when is it used?

**A44.**
**Forensic triage** is a rapid, targeted assessment to quickly identify the presence, relevance, and priority of evidence on a device — without full forensic acquisition.

**When used:**
- Scene with multiple devices — triage prioritizes which to acquire fully.
- Time-sensitive investigations (fugitive tracking, imminent threat).
- Live device at risk of remote wipe — triage preserves critical artifacts immediately.

**Triage targets:**
- Recent messages, contacts, and call records.
- Recent photos and their GPS metadata.
- Browser history and search queries.
- Cloud tokens and account information.
- Device identifiers (IMEI, phone number).

**Tools:** Cellebrite UFED Touch (field device), Magnet AXIOM Examine, targeted `adb pull` scripts, MSAB XRY for rapid on-scene access.

**Important:** triage is not a substitute for full acquisition — document all triage actions and hash any extracted artifacts immediately.

> 📗 **Reiber (2020), §4.6:** "Forensic triage is a risk-management decision — it accepts partial data in exchange for speed. Always document what was triaged and what was not."

---

### Q45. How can message timestamps be manipulated and how is manipulation detected?

**A45.**
**Manipulation methods:**
1. **Change device clock** before/after sending messages → shifts `DateTimeOriginal` in DB.
2. **Edit DB file directly** (on rooted/jailbroken device) → modify `date` field in `sms` table.
3. **Replay messages** → send same message to recreate activity at controlled time.
4. **Metadata editing tools** → exiftool, hex editors can alter EXIF timestamps.

**Detection techniques:**

| Method | What it reveals |
|---|---|
| Cross-source comparison | SMS DB timestamp vs carrier CDR → discrepancy exposes local tampering |
| GPS timestamp vs EXIF clock | GPS time is satellite-authoritative; mismatch reveals device clock forgery |
| NTP sync logs | Device logs of clock sync events from authoritative time servers |
| SQLite row ID order | Row IDs auto-increment; if timestamps go backwards, they were edited |
| Server-side timestamps | Provider log of message delivery is independent of device |

> 📘 **Jain & Kalbande (2016), §8.2:** "Server-side timestamps are authoritative — a discrepancy between server-assigned and device-stored timestamps is strong evidence of local manipulation."

---

### Q46. How are network packet captures (PCAPs) analyzed in mobile forensic investigations?

**A46.**
**Collection:** PCAPs are captured at the network level (router, Wi-Fi AP, or using `tcpdump` on the device if rooted) — not from device storage.

**Analysis workflow:**
1. Open PCAP in **Wireshark** or **NetworkMiner**.
2. Extract **DNS queries** → domains contacted (even if HTTPS traffic is encrypted).
3. Inspect **HTTP traffic** (port 80) for cleartext content, URLs, user agents, and cookies.
4. Analyze **TLS metadata** (SNI, certificate subject) → identify services accessed without decrypting.
5. Correlate IP addresses → geolocate servers; identify cloud providers or C2 infrastructure.
6. Extract **file carve** from PCAP (NetworkMiner extracts transferred files from unencrypted sessions).

**Correlation with device artifacts:**
```
DNS query to api.whatsapp.com at 14:32:01 UTC
  → matches WhatsApp message timestamp in DB at 14:32:03
  → confirms message was sent over cellular, not cached
```

> 📕 **Bhardwaj & Kaushik (2023), §13.2:** "PCAPs are authoritative for network activity timing — they corroborate or contradict device-side timestamps independently."

---

### Q47. What is 'deleted-but-not-overwritten' data and how does it apply to mobile storage?

**A47.**
**Concept:** when a file is deleted, the OS marks its storage space as available but does not immediately zero out the data. The actual binary content remains until new data is written to those physical locations.

**Application to flash storage:**
- **NAND flash:** deletion marks LBA as free in FTL mapping, but physical page may not be erased until a garbage collection cycle reclaims the block.
- **SQLite databases:** deleted rows are moved to freelist — pages contain original row data until reused.
- **File system:** `inode` freed and directory entry removed, but data blocks remain until reallocated.

**Recovery window factors:**
- Time since deletion (longer = more overwrites = less recoverable).
- Device activity level (heavily used device reclaims space faster).
- TRIM support in eMMC/UFS (proactively erases freed blocks — reduces recovery window dramatically).
- Flash controller garbage collection aggressiveness.

> 📗 **Reiber (2020), §5.6:** "Timeliness is the most critical factor in mobile evidence recovery — the longer you wait, the less is recoverable."

---

### Q48. Describe the role and limitations of ADB in forensic acquisitions.

**A48.**
**ADB (Android Debug Bridge)** is the primary interface for Android forensic acquisition on unlocked devices.

**Capabilities:**
- File pulls (`adb pull`), shell access, log capture (`adb logcat`), backup creation (`adb backup`).
- `adb shell` allows running commands as device user or root (if device is rooted).
- Screen capture: `adb shell screencap -p /sdcard/screen.png && adb pull /sdcard/screen.png`.

**Forensic limitations:**
1. **Requires USB debugging enabled** — disabled on most locked/seized devices.
2. **Requires device trust authorization** — user must accept on screen (not possible on locked device).
3. **No built-in write-block** — every shell command could write to device; rigorously restrict to read-only.
4. **Logical data only** — `adb pull` misses deleted data and unallocated space.
5. **Root required for protected data** — app private directories are inaccessible without root or `run-as`.
6. **Android 10+** — `adb backup` is deprecated; many apps use `allowBackup=false`.

```zsh
adb shell "su -c 'ls /data/data/com.whatsapp/'"  # root required
adb logcat -d > session_log.txt                    # dump current logcat to file
```

> 📕 **Bhardwaj & Kaushik (2023), §7.2:** "ADB forensics is best treated as a first-pass triage tool — comprehensive acquisition requires physical imaging for deleted data recovery."

---

### Q49. How should investigators handle encrypted iOS and iTunes backups?

**A49.**
**iTunes/local encrypted backups:**
- Password-protected with a user-set backup password (not the device passcode).
- Encrypting a backup enables inclusion of Keychain items, Health data, and saved passwords.
- `Manifest.plist` in backup root contains backup metadata and encryption salt.

**If backup password is known:**
```zsh
idevicebackup2 backup --password <backup_password> /lab/evidence/backup/
# Then use libimobiledevice or commercial tools to decrypt
```

**If password is unknown:**
- Tools like `Elcomsoft Phone Breaker` offer GPU-accelerated dictionary/brute-force attack on backup encryption.
- Check device itself — if unlocked, the backup password can be reset via `Settings → General → Reset → Reset All Settings` (changes backup password to empty — **document this action** as it modifies the device).
- Legal compulsion to disclose password is jurisdiction-dependent.

**iCloud encrypted backups:**
- Standard iCloud backup: Apple holds keys → request via legal process.
- Advanced Data Protection (ADP, opt-in): end-to-end encrypted → Apple cannot provide plaintext even with legal process.

> 📗 **Reiber (2020), §8.4:** "Always attempt to obtain the backup password before resorting to reset — resetting modifies the device and must be justified and documented in the chain-of-custody."

---

### Q50. Summarize best practices for reporting mobile forensic findings to a non-technical audience.

**A50.**
**Report structure for mixed technical/legal audiences:**

| Section | Audience | Content |
|---|---|---|
| **Executive Summary** | Non-technical (judges, attorneys, management) | Key findings, timeline highlights, significance — no jargon |
| **Scope and Authority** | Legal | Warrants, consents, legal constraints |
| **Evidence Summary** | All | Device inventory, acquisition methods, SHA-256 hashes |
| **Methodology** | Technical/legal | Step-by-step acquisition and analysis commands and tools |
| **Findings** | All | Organized by category: communications, media, location, apps |
| **Timeline** | All | Visual chronological summary — use tables or diagrams |
| **Limitations** | All | What could not be recovered; encryption barriers; assumptions |
| **Exhibits** | All | Numbered, hashed, annotated screenshots and artifact excerpts |
| **Technical Appendix** | Expert reviewers | Full SQL queries, raw outputs, tool version logs |

**Key principles:**
- **Reproducibility:** provide exact commands and tool versions so findings can be independently replicated.
- **Objectivity:** report what the evidence shows — do not advocate; state limitations clearly.
- **Accessibility:** use plain language in the executive summary; reserve technical detail for appendices.

> 📓 **Steuart et al. (2013), §13.1:** "The forensic report is the primary deliverable — it must be accurate, objective, and comprehensible to audiences with no technical background."
> 📗 **Reiber (2020), §12.2:** "The best forensic report is one where a non-expert reader can understand the key findings, and an expert reviewer can independently replicate every step."

---

# ═══════════════════════════════════════
# CONCLUSION AND STUDY GUIDE
# ═══════════════════════════════════════

## Summary of Key Themes

This document covers the full syllabus for mobile forensics across three units:

| Unit | Core Theme | Key Skills |
|---|---|---|
| **UNIT I** | Foundations and architecture | Legal authority, memory types, OS internals, chain-of-custody |
| **UNIT II** | Acquisition methods | ADB/idevicebackup2, chip-off, FTL, SQLite carving, write-blocking |
| **UNIT III** | Analysis and reporting | App forensics, cloud acquisition, timeline normalization, report writing |

## Book-to-Topic Quick Reference

| Topic | Primary Reference |
|---|---|
| Legal and ethical framework | 📓 Steuart et al. (2013), Ch. 3; 📘 Jain (2016), Ch. 2 |
| Chain-of-custody | 📓 Steuart et al. (2013), Ch. 11; 📗 Reiber (2020), Ch. 4 |
| Android acquisition | 📕 Bhardwaj (2023), Ch. 7; 📗 Reiber (2020), Ch. 5 |
| iOS acquisition | 📗 Reiber (2020), Ch. 8; 📕 Bhardwaj (2023), Ch. 10 |
| Chip-off and NAND forensics | 📙 Dejey (2018), Ch. 4–5; 📗 Reiber (2020), Ch. 6 |
| SQLite forensics | 📕 Bhardwaj (2023), Ch. 8 |
| App data analysis | 📕 Bhardwaj (2023), Ch. 10; 📗 Reiber (2020), Ch. 7 |
| Cloud forensics | 📗 Reiber (2020), Ch. 10 |
| Timeline analysis | 📗 Reiber (2020), Ch. 11; 📕 Bhardwaj (2023), Ch. 9 |
| Reporting | 📓 Steuart et al. (2013), Ch. 13; 📗 Reiber (2020), Ch. 12 |

## Exam Priority Topics

🔴 **High priority (appear frequently):**
- Chain-of-custody definition and requirements
- Logical vs. physical acquisition comparison
- SQLite WAL and freelist for deleted data recovery
- EXIF metadata and forensic timeline
- Android vs. iOS app sandboxing differences

🟡 **Medium priority:**
- Chip-off risks and procedure
- TEE / Secure Enclave forensic impact
- Cloud backup legal access framework
- Write-blocker purpose and mobile alternatives
- Timestamp normalization (epoch conversions)

🟢 **Also important:**
- SIM card elementary files and extraction
- Faraday bag advantages and drawbacks
- ADB capabilities and limitations
- Anti-forensic detection methods
- Report structure for non-technical audiences

---

*Document complete — UNIT I, UNIT II, UNIT III, Appendices A–C (with full command reference), and 50 enhanced Q&A with book citations. Last updated: March 2026.*

