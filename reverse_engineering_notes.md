# 🔬 Complete Reverse Engineering Notes
### Packed C++ Binaries · Stripped Files · Anti-Debug · Anti-VM · Python Binaries · Automated RE with angr

> **Goal:** After reading this, you should be able to tackle **any hard-level binary on crackmes.one** — from packed PE/ELF files to Python bytecode to obfuscated C++ with every trick in the book.

---

## Table of Contents

1. [Foundations — The RE Mindset](#1-foundations)
2. [Tools of the Trade](#2-tools-of-the-trade)
3. [ELF & PE Binary Internals](#3-elf--pe-binary-internals)
4. [Stripped Binaries — Recovering Structure](#4-stripped-binaries)
5. [Packed Binaries — Detection & Unpacking](#5-packed-binaries)
6. [Reversing C++ Binaries (vtables, RTTI, STL)](#6-reversing-c-binaries)
7. [Anti-Debugging Techniques & Bypasses](#7-anti-debugging-techniques)
8. [Anti-VM & Anti-Analysis Techniques](#8-anti-vm--anti-analysis-techniques)
9. [Anti-Reversing / Obfuscation Techniques](#9-anti-reversing--obfuscation)
10. [Reversing Python Binaries](#10-reversing-python-binaries)
11. [Automated Reverse Engineering with angr](#11-automated-re-with-angr)
12. [Automated RE with Python (Scripting IDA/Ghidra/radare2)](#12-automated-re-with-python-scripts)
13. [Full Crackme Walkthrough Examples](#13-full-crackme-walkthroughs)
14. [Quick-Reference Cheat Sheet](#14-cheat-sheet)

---

## 1. Foundations

### The RE Mindset

Reverse engineering is **structured deduction**. You are reading a machine's language and reconstructing human intent. The workflow is always:

```
Static Analysis → Dynamic Analysis → Patch / Keygen / Understand
      ↑___________________________|
            (iterate until solved)
```

**Static Analysis** = examining the binary without running it (Ghidra, IDA, radare2, strings, objdump)  
**Dynamic Analysis** = running the binary and observing behavior (GDB, x64dbg, strace, ltrace, Frida)

### Golden Rules

- **Never reverse from the top.** Find the "interesting" code first — strings, error messages, crypto constants.
- **Follow data, not just code.** The secret comparison is what matters.
- **Name everything as you go.** Rename functions/variables in IDA/Ghidra immediately. It compounds.
- **Trust but verify the decompiler.** Ghidra/IDA decompile approximations. When in doubt, read the assembly.
- **Assume nothing is what it looks like.** Anti-debug changes control flow. Packers hide real code.

---

## 2. Tools of the Trade

### Static Analysis

| Tool | Purpose | Install |
|------|---------|---------|
| **Ghidra** | Free NSA decompiler, excellent for C++ | `sudo apt install ghidra` or download |
| **IDA Free / Pro** | Industry standard disassembler | ida64.com |
| **Binary Ninja** | Clean API for scripting | binary.ninja |
| **radare2 / Cutter** | CLI powerhouse + GUI frontend | `sudo apt install radare2` |
| **objdump** | Quick section/symbol dump | pre-installed |
| **readelf** | ELF header/section analysis | pre-installed |
| **strings** | Extract printable strings | pre-installed |
| **file / exiftool** | File type & metadata | pre-installed |
| **DIE (Detect It Easy)** | Packer/compiler detection | github.com/horsicq/DIE |
| **ExeinfoPE** | PE packer/protector detection | Windows tool |

### Dynamic Analysis

| Tool | Purpose | Install |
|------|---------|---------|
| **GDB + pwndbg/peda** | Linux debugger + enhancements | `pip install pwndbg` |
| **x64dbg / x32dbg** | Windows debugger (open source) | x64dbg.com |
| **strace** | Syscall tracer | `sudo apt install strace` |
| **ltrace** | Library call tracer | `sudo apt install ltrace` |
| **Frida** | Dynamic instrumentation framework | `pip install frida-tools` |
| **PIN / DynamoRIO** | Binary instrumentation platforms | pintool.intel.com |
| **Valgrind** | Memory analysis + callgrind | `sudo apt install valgrind` |

### Specialty Tools

| Tool | Purpose |
|------|---------|
| **angr** | Symbolic execution / automated solving |
| **z3** | SMT solver (used by angr) |
| **pycdc / uncompyle6** | Python bytecode → source |
| **pyinstxtractor** | Extract PyInstaller bundles |
| **UPX** | Most common packer (also unpacks) |
| **Scylla / ImpRec** | IAT rebuilding after unpacking |
| **de4dot** | .NET deobfuscator |
| **dnSpy** | .NET debugger + decompiler |

---

## 3. ELF & PE Binary Internals

Understanding file formats is **non-negotiable**. Every trick in this guide exploits or abuses these structures.

### ELF (Linux/Unix Binaries)

```
ELF Header
├── Magic: \x7fELF
├── Class: 32/64 bit
├── Entry Point: where execution starts
├── Program Header Table → segments (LOAD, DYNAMIC, NOTE...)
└── Section Header Table → sections (.text, .data, .bss, .rodata...)

Key Sections:
  .text    → executable code
  .data    → initialized global variables
  .bss     → uninitialized globals (zeroed at start)
  .rodata  → read-only data (strings, constants)
  .plt     → Procedure Linkage Table (external function stubs)
  .got     → Global Offset Table (resolved function addresses)
  .got.plt → GOT entries for PLT
  .symtab  → symbol table (present in non-stripped)
  .strtab  → string table (symbol names)
  .dynsym  → dynamic symbol table
  .debug_* → DWARF debug info
```

**Quick ELF triage:**
```bash
file binary                    # type, arch, stripped?
readelf -h binary              # header info
readelf -S binary              # all sections
readelf -l binary              # program headers (segments)
readelf -d binary              # dynamic section
readelf --syms binary          # symbols (empty if stripped)
objdump -d binary              # disassemble
strings -a -n 6 binary         # all strings ≥ 6 chars
strings -a -n 6 binary | grep -i "pass\|key\|flag\|secret\|wrong\|correct"
```

### PE (Windows Binaries)

```
DOS Header → PE Signature (PE\0\0) → COFF Header → Optional Header
├── Optional Header
│   ├── AddressOfEntryPoint
│   ├── ImageBase (default: 0x400000 for exe, 0x10000000 for dll)
│   └── DataDirectory[16] → imports, exports, resources, TLS, etc.
└── Section Table
    ├── .text   → code
    ├── .rdata  → read-only data + imports
    ├── .data   → writable data
    ├── .rsrc   → resources (icons, dialogs, version info)
    └── .reloc  → relocation table

Key Structures:
  Import Directory Table → DLL names + function names/ordinals
  Export Directory Table → exported functions (in DLLs)
  TLS Directory         → Thread Local Storage callbacks (run BEFORE entry point!)
  Debug Directory       → PDB path, CODEVIEW info
```

**Quick PE triage (Linux):**
```bash
file binary.exe
strings -a -n 6 binary.exe | less
python3 -c "import pefile; pe=pefile.parse('binary.exe'); print(pe.dump_info())"
diec binary.exe           # Detect It Easy
```

### How PLT/GOT Works (Important for hooking & analysis)

```
Call to printf:
  1. call printf@plt         ← your code
  2. JMP [printf@got.plt]    ← PLT stub jumps through GOT entry
  3. First call: GOT has address of resolver (lazy binding)
  4. Resolver fills GOT entry with real printf address
  5. Subsequent calls: GOT already has real address

Why it matters:
  - GOT entries can be overwritten (GOT overwrite exploit)
  - ltrace hooks here to trace library calls
  - Frida intercepts PLT entries
  - Stripped binaries still have .dynsym for external functions!
```

---

## 4. Stripped Binaries

A **stripped binary** has had its symbol table removed. `objdump` shows function addresses but no names. `strings --syms` returns nothing. This is the default for release builds.

### Detecting if a Binary is Stripped

```bash
file ./crackme
# "ELF 64-bit LSB executable... not stripped"  ← has symbols
# "ELF 64-bit LSB executable... stripped"       ← no symbols

readelf --syms ./crackme | grep -c "FUNC"      # 0 = stripped
nm ./crackme 2>&1 | head                        # "no symbols" if stripped
```

### Strategy for Stripped Binaries

The key insight: **external library calls are NEVER stripped** (they're in `.dynsym`). Dynamic symbols tell you what libraries the binary uses, which tells you what it DOES.

```bash
readelf --dyn-syms ./crackme
# You'll see: strcmp, strlen, printf, fopen, malloc, etc.
# This tells you: the binary compares strings (strcmp) → likely a password check!

ltrace ./crackme myinput 2>&1
# Traces ALL library calls with arguments!
# strcmp("myinput", "s3cr3t_p4ss") ← gold!
```

### Recovering Structure in Ghidra/IDA

**Step 1: Find main()**

For x86-64 Linux ELF, execution flow is:
```
_start → __libc_start_main(main, argc, argv, ...) → main()
```

In Ghidra: look for `__libc_start_main` call. The **first argument** is `main`. Double-click it.

For Windows PE: Find `WinMainCRTStartup` or `mainCRTStartup`, which calls `main`/`WinMain`.

**Step 2: Find interesting functions via cross-references**

```
Ghidra: Search → For Strings → find "Wrong password" → Right-click → References
This shows you every code location that uses this string → that's your target function!
```

**Step 3: Function signature recovery**

Look at how many arguments a function receives (RDI, RSI, RDX, RCX, R8, R9 in x86-64 SysV ABI) and what it returns (RAX). Rename accordingly.

**Step 4: Use FLIRT signatures**

FLIRT (Fast Library Identification and Recognition Technology) can identify standard library functions even in stripped binaries.

In IDA: `File → Load File → FLIRT Signature File` → load signatures for your target compiler/libc  
In Ghidra: Install the `FLIRT` plugin or use `sigmake`-generated `.sig` files.

```bash
# Generate FLIRT signatures from a known library
sigmake -n "libc-2.31" libc.a libc.sig
# Then load in IDA
```

**Step 5: Recover function prototypes from context**

```c
// Assembly says:
// mov rdi, [rbp-0x18]    ← first arg = some pointer
// call FUN_00401234
// test eax, eax          ← return value used as boolean
// je "Wrong"

// Conclusion: FUN_00401234 is bool check_password(char* input)
// Rename it immediately!
```

### Practical Example: Stripped Crackme

```bash
$ file crackme
crackme: ELF 64-bit LSB pie executable, stripped

$ ltrace ./crackme AAAA 2>&1 | grep -E "str|mem"
strlen("AAAA") = 4
strcmp("AAAA", "h4x0r_rules") = 1    ← FOUND IT!

$ ./crackme h4x0r_rules
Correct! You win!
```

When `ltrace` doesn't work (binary checks for it), use **strace** instead:
```bash
strace ./crackme 2>&1 | grep -E "read|write|open"
# read(0, ...) might reveal the comparison value
```

---

## 5. Packed Binaries

A **packer** compresses/encrypts the real binary and attaches a **stub** that decompresses/decrypts and runs the payload at runtime. The stub IS the binary you see — the real code is hidden.

### Detecting Packers

```bash
# Method 1: Detect It Easy (most reliable)
diec ./crackme
# Output: "UPX 3.96 [ELF32, NRV2B, NRV2D]"

# Method 2: High entropy sections
python3 -c "
import pefile, math
def entropy(data):
    if not data: return 0
    freq = [data.count(bytes([i])) for i in range(256)]
    return -sum(f/len(data) * math.log2(f/len(data)) for f in freq if f)
pe = pefile.PE('crackme.exe')
for s in pe.sections:
    e = entropy(s.get_data())
    print(f'{s.Name.decode().strip()}: entropy={e:.2f}')
"
# Normal: .text ~6.0, .data ~4.0
# Packed: ALL sections ≥ 7.5 → definitely packed

# Method 3: Strings output
strings ./crackme | wc -l   # < 20 strings = probably packed
strings ./crackme | grep "UPX"  # UPX leaves its name!

# Method 4: Few imports
readelf --dyn-syms crackme | wc -l  # 3-4 imports = likely packed stub
```

### Entropy Explained

Shannon entropy measures randomness (0 = all same bytes, 8 = maximum randomness):
- **Plain code/data:** 5.0–6.5
- **Compressed data:** 7.5–8.0
- **Encrypted data:** 7.8–8.0

A packed binary looks like a blob of high-entropy data with a small low-entropy stub.

### UPX — The Most Common Packer

UPX is so common it has a built-in unpack flag:

```bash
upx -d ./packed_crackme -o ./unpacked_crackme
./unpacked_crackme   # now runs normally

# If UPX header was tampered (anti-tamper):
# Fix: Change "UPX!" magic back, or use upx with --force
hexedit packed_crackme
# Find and restore UPX! signatures if mangled
```

If UPX header magic was changed to prevent `upx -d`:
```bash
# Original UPX magic bytes: 55 50 58 21 ("UPX!")
# Find them (they may be modified to e.g. "UPX." or "UPZ!")
strings packed_crackme | grep -i upx
hexdump -C packed_crackme | grep "55 50"
# Patch back to UPX! using a hex editor, then upx -d works
```

### Generic Unpacking Strategy (Manual)

The fundamental insight: **the packer stub must eventually jump to the OEP (Original Entry Point)**. If you can find and intercept that jump, you can dump the decrypted binary.

**The OEP Jump Pattern:**
```asm
; Stub decrypts/decompresses real code into memory
; Then does something like:
jmp rax              ; indirect jump to OEP
jmp [rbp-8]          ; memory-based jump
push 0x401000        ; push OEP
ret                  ; "return" to OEP
call [rbp+0]         ; call through pointer
```

#### Method 1: Hardware Breakpoint on ESP (x64dbg)

This classic trick works because the packer stub:
1. Saves registers (pushes them)
2. Does its work
3. Restores registers (pops them) → ESP returns to original value
4. Jumps to OEP

```
1. Open packed binary in x64dbg
2. Run until it reaches the stub entry point (F9)
3. Note the current ESP value (e.g., 0x0019FF50)
4. Right-click ESP → "Set hardware breakpoint on address" → On Access → DWORD
   (Or: Debug → Hardware Breakpoints → Add → Address=ESP, Type=Write, Size=DWORD)
5. F9 to run
6. The breakpoint hits when packer pops the stack = near OEP!
7. Step a few instructions (F8) until you see a "JMP to suspicious address"
8. That's the OEP → dump the process here
```

#### Method 2: Find OEP via entropy graph

In x64dbg: View → Memory Map → Look for a region that becomes executable after stub runs (RWX memory is suspicious).

#### Method 3: Strace to find the real entry

```bash
strace -e trace=mmap,mprotect,execve ./packed_crackme
# Look for mprotect(..., PROT_EXEC) calls → that's where code gets mapped
# The last mprotect before execution = likely where OEP is
```

#### Dumping the Unpacked Process

**Linux:**
```bash
# While the process is running (paused at OEP in GDB):
gdb -p PID
(gdb) info proc mappings       # find code region
(gdb) dump binary memory dump.bin 0x400000 0x500000
# Then fix ELF header in dump.bin
```

```python
# Python method: read /proc/PID/maps and dump
import subprocess, struct

pid = int(subprocess.check_output(["pgrep", "crackme"]))
with open(f"/proc/{pid}/maps") as f:
    maps = f.readlines()

with open(f"/proc/{pid}/mem", "rb") as mem:
    for line in maps:
        parts = line.split()
        if 'r-xp' in parts[1] or 'rwxp' in parts[1]:
            start, end = [int(x, 16) for x in parts[0].split('-')]
            mem.seek(start)
            data = mem.read(end - start)
            with open(f"dump_{hex(start)}.bin", "wb") as out:
                out.write(data)
            print(f"Dumped {hex(start)}-{hex(end)}")
```

**Windows (x64dbg + Scylla):**
```
1. Reach OEP in x64dbg
2. Plugins → Scylla (or OllyDump)
3. "IAT Autosearch" → "Get Imports"
4. Fix any invalid imports
5. "Dump" to create the unpacked executable
6. "Fix Dump" to rebuild the import table
```

### Custom Packers / Protectors

Beyond UPX, you'll encounter:
- **Themida / WinLicense / VMProtect** — commercial protectors, extremely complex
- **Custom XOR loops** — simple but common in CTF
- **Self-modifying code** — writes new instructions over itself

**Detecting Custom XOR:**
```bash
# In Ghidra, look for loops that write to executable sections:
# for(i=0; i<size; i++) code[i] ^= key;
# These appear as: XOR [rbx+rax*1], dl patterns

# In gdb, watch memory:
watch -l *(int*)0x401000   # hardware watchpoint — triggers when code section modified
```

**Tracing Self-Modification:**
```bash
# Use PIN tool or DynamoRIO to trace every instruction
# Build a trace of all unique addresses executed
# Filter to find the "real" code that ran after modification
```

---

## 6. Reversing C++ Binaries

C++ adds significant complexity: name mangling, vtables, RTTI, templates, STL containers, exceptions.

### Name Mangling

C++ mangles function names to encode type information. A stripped binary loses these names, but if you find them in `.dynsym` or `.dynstr`, you can demangle:

```bash
c++filt _ZN6CrackMe13checkPasswordEPKc
# Output: CrackMe::checkPassword(char const*)

# Or in Python:
import subprocess
result = subprocess.run(['c++filt', '_ZN6CrackMe13checkPasswordEPKc'], capture_output=True, text=True)
print(result.stdout)
```

Common mangled name patterns:
```
_Z       → start of mangled name
N...E    → nested name (namespace::class)
Kc       → const char
Pc       → char*
i        → int
v        → void
```

### Virtual Tables (vtables)

Every C++ class with `virtual` functions has a vtable — a read-only array of function pointers. The object's first field is a pointer to its vtable.

```cpp
// C++ source:
class Animal {
    virtual void speak() { ... }
    virtual void move() { ... }
};

// Memory layout of an Animal object:
// [0x00] → vtable_ptr → [speak_addr, move_addr]
// [0x08] → member data...
```

**Identifying vtables in Ghidra:**
```
1. Look for read-only arrays of function pointers in .rodata or .data.rel.ro
2. These arrays are referenced by constructor code: "MOV [RDI], vtable_addr"
3. Right-click the array → "Define Structure" or manually annotate

In Ghidra:
- Search for: MOV [param_1], DAT_  (stores a pointer to the start of object = vtable init)
- The value stored is a .rodata address
- That address contains an array of function pointers → vtable!
```

**Example vtable reconstruction:**
```
Address    Value          Name
0x403000   0x4011a0       → Animal::speak()
0x403008   0x4011c0       → Animal::move()
0x403010   0x4011e0       → Animal::~Animal() (destructor)

Constructor:
  mov qword ptr [rdi], 0x403000   ← sets vtable pointer
  → This tells us: object at RDI is of type Animal (or subclass)
```

### RTTI (Run-Time Type Information)

If the binary is not compiled with `-fno-rtti`, RTTI structures exist in `.rodata`:

```
type_info structure:
  [0x00] → pointer to __class_type_info vtable (identifies this as type_info)
  [0x08] → pointer to mangled class name string (e.g., "N6Animal3CatE")
  [0x10] → base class info array

Where to find it:
  The vtable is usually preceded by:
    vtable - 0x10 → offset to top (usually 0)
    vtable - 0x08 → RTTI pointer → type_info struct
    vtable + 0x00 → first virtual function

In Ghidra: Look 0x10 bytes before each vtable.
The string there is the mangled class name → demangle it!
```

```bash
# Find RTTI class names in binary:
strings ./crackme | grep -E "^\*[A-Z][0-9]"  # mangled names start with *N or similar
readelf -p .rodata crackme | grep -oP '_ZT[A-Za-z0-9_]+' | xargs -I{} c++filt {}
```

### STL Containers in Disassembly

Recognizing STL patterns speeds up analysis enormously:

**std::string** (small string optimization, SSO):
```
struct std::string {
    union {
        char buf[16];      // small string: stored inline if len < 16
        char* ptr;         // large string: heap allocated
    };
    size_t size;
    size_t capacity;       // or 15 for inline
};

// Test: if [obj+0x10] (capacity field) == 0xF → SSO, string is at [obj]
// Otherwise: string is at *[obj] (heap pointer)
```

**std::vector<T>**:
```
struct vector {
    T* begin;          // [obj+0x00]
    T* end;            // [obj+0x08]  end - begin = size * sizeof(T)
    T* capacity_end;   // [obj+0x10]
};
```

**std::map / std::set** (Red-Black tree):
```
struct _Rb_tree_node {
    _Rb_tree_color  color;    // 0=RED, 1=BLACK
    node*           parent;
    node*           left;
    node*           right;
    T               value;    // actual key/value here
};
```

---

## 7. Anti-Debugging Techniques

Anti-debug tricks detect or prevent debugger attachment. There are three categories:
1. **Detection** — binary checks if debugger is present, behaves differently
2. **Interference** — binary actively breaks the debugger
3. **Evasion** — binary avoids patterns that debuggers use

### Linux Anti-Debug Techniques

#### 1. ptrace(PTRACE_TRACEME) Check

`ptrace(PTRACE_TRACEME)` fails if a tracer is already attached (each process can only have one tracer, and a debugger IS a tracer).

```c
// Anti-debug code:
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    puts("Debugger detected! Exiting.");
    exit(1);
}

// In disassembly:
// mov  edi, 0        ← PTRACE_TRACEME = 0
// xor  esi, esi
// xor  edx, edx
// xor  ecx, ecx
// call ptrace
// cmp  eax, -1       ← check return value
// je   anti_debug_exit
```

**Bypass:**
```bash
# Method 1: NOP out the check in Ghidra, save patched binary
# Change: JE anti_debug_exit → NOP NOP (0x90 0x90)

# Method 2: Use LD_PRELOAD to hook ptrace
cat > fake_ptrace.c << 'EOF'
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request req, ...) {
    return 0;  // always succeed
}
EOF
gcc -shared -fPIC -o fake_ptrace.so fake_ptrace.c
LD_PRELOAD=./fake_ptrace.so ./crackme

# Method 3: GDB catch + return
catch syscall ptrace
commands
  set $rax = 0
  continue
end

# Method 4: Frida hook
```python
import frida, sys
session = frida.attach("crackme")
script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
    onLeave: function(retval) { retval.replace(0); }
});
""")
script.load()
```

#### 2. /proc/self/status Check

```c
// Reads TracerPid field:
FILE* f = fopen("/proc/self/status", "r");
// If TracerPid != 0 → debugger attached

// Detection in disassembly: look for fopen("/proc/self/status", ...)
// followed by string search for "TracerPid"
```

**Bypass:**
```bash
# Method 1: Patch the binary to skip the check
# Method 2: Use a kernel module or seccomp to fake /proc reads
# Method 3: Frida hook on fopen/fread to return fake content
```

#### 3. Timing Attacks

A debugger slows execution significantly. The binary measures time between two points:

```c
struct timespec t1, t2;
clock_gettime(CLOCK_MONOTONIC, &t1);
// ... code ...
clock_gettime(CLOCK_MONOTONIC, &t2);
long diff = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec);
if (diff > 1000000) { // 1ms threshold
    // debugger detected!
}
```

**Bypass:**
```bash
# Method 1: Hook clock_gettime to always return the same time
# Method 2: Patch the comparison to invert/remove it
# Method 3: Frida:
Interceptor.attach(Module.findExportByName(null, 'clock_gettime'), {
    onLeave: function(retval) {
        // Set tv_sec and tv_nsec to fixed values
        let ts = this.context.rsi; // struct timespec*
        Memory.writeS64(ts, ptr(1000));
        Memory.writeS64(ts.add(8), ptr(0));
    }
});
```

#### 4. Signal Handler Tricks

```c
// SIGTRAP is used by debuggers for breakpoints
// Binary installs its own SIGTRAP handler:
signal(SIGTRAP, handler);
raise(SIGTRAP);
// If no debugger: handler runs, sets a flag
// If debugger: debugger intercepts SIGTRAP, handler never runs, flag unset
```

**Bypass in GDB:**
```
handle SIGTRAP nopass   ← don't pass SIGTRAP to the process
```

#### 5. /proc/self/cmdline or Parent Process Check

```c
// Check if parent is gdb/strace:
char cmdline[256];
readlink("/proc/self/exe", cmdline, 256);
// or read /proc/getppid()/cmdline
if (strstr(cmdline, "gdb") || strstr(cmdline, "strace"))
    exit(1);
```

**Bypass:** Hook `readlink` or patch the string comparison.

### Windows Anti-Debug Techniques

#### 1. IsDebuggerPresent

```c
if (IsDebuggerPresent()) exit(1);
// Reads PEB.BeingDebugged byte directly:
// MOV EAX, [FS:30h]   ← get PEB
// MOVZX EAX, [EAX+2]  ← read BeingDebugged
// TEST EAX, EAX
// JNZ debugger_detected
```

**Bypass in x64dbg:**
```
ScyllaHide plugin (most comprehensive anti-anti-debug for Windows)
Or manually: Plugin → ScyllaHide → Options → Check all IsDebuggerPresent options

Manual: Set a breakpoint on IsDebuggerPresent, change EAX to 0 before return
Or: In-memory patch PEB.BeingDebugged to 0
  x64dbg → Memory Map → find PEB → navigate to offset 0x2 → change byte to 0x00
```

#### 2. CheckRemoteDebuggerPresent

```c
BOOL dbg; 
CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
if (dbg) exit(1);
// Same bypass as IsDebuggerPresent (via NtQueryInformationProcess internally)
```

#### 3. NtQueryInformationProcess

The low-level API that most checks ultimately call:

```c
ULONG debugPort = 0;
NtQueryInformationProcess(handle, ProcessDebugPort, &debugPort, 4, NULL);
if (debugPort != 0) exit(1);

// Bypass: Hook NtQueryInformationProcess, zero out the output buffer
```

#### 4. Heap Flags (PEB)

```c
// Debugged processes have different heap flags:
PEB* peb = (PEB*)__readfsdword(0x30);
if (peb->NtGlobalFlag & 0x70)  // ForceFlags, Flags set when debugging
    exit(1);

// Bypass: Set NtGlobalFlag to 0 in PEB
```

#### 5. Hardware Breakpoint Detection

```c
CONTEXT ctx;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)  // debug registers
    exit(1);
```

**Bypass:** x64dbg uses software breakpoints by default (INT3 = 0xCC). But if hardware BPs detected, switch to software.

#### 6. Interrupt-Based Tricks

```asm
; Binary inserts INT 3 (0xCC) into code stream:
INT 3         ; debugger will catch this (its breakpoint)
; anti-debug handler checks if SEH handled it or debugger did
```

**Bypass:** In x64dbg, set "Ignore exceptions" for INT3 under `Debug → Exceptions → Ignore all`

#### 7. OutputDebugString Trick

```c
SetLastError(0xDEAD);
OutputDebugString("testing");
if (GetLastError() == 0) // in a debugger, error is reset
    exit(1);
```

### Universal Bypass Tool: ScyllaHide (Windows)

ScyllaHide is an x64dbg plugin that bypasses nearly all standard Windows anti-debug:
```
Plugins → ScyllaHide → Options
Check: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtSetInformationThread,
       NtQueryInformationProcess, OutputDebugString, BlockInput,
       NtGetContextThread, FindWindow, ParentProcess Spoofing
```

### Linux Universal Bypass: GDB Init Script

```python
# ~/.gdbinit or ./gdbinit_crackme
# Auto-bypass common anti-debug:

set follow-fork-mode child         # follow forked child
set detach-on-fork off
catch syscall ptrace               # catch ptrace syscall
commands
  silent
  set $rax = 0                     # make ptrace return 0
  continue
end

# Hook clock_gettime
break *clock_gettime
commands
  silent
  finish
  set *(long*)($rdi + 0) = 1000   # fake time
  set *(long*)($rdi + 8) = 0
  continue
end
```

---

## 8. Anti-VM & Anti-Analysis Techniques

VMs (VirtualBox, VMware, QEMU, etc.) leave detectable artifacts. Malware and protectors check for them.

### VM Detection Methods

#### 1. CPUID Check

```c
// Run CPUID instruction with EAX=1
// Hypervisor bit: ECX bit 31 (0x80000000)
// If set → running in VM

uint32_t ecx = 0;
asm("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");
if (ecx >> 31 & 1)  // hypervisor present
    exit(1);

// Also CPUID EAX=0x40000000 returns hypervisor signature:
// VMware: "VMwareVMware"
// VirtualBox: "VBoxVBoxVBox"
// QEMU: "TCGTCGTCGTCG"
// Hyper-V: "Microsoft Hv"
```

**Bypass:**
```
VirtualBox: In VM settings → System → uncheck "Enable VT-x/AMD-V" and "Enable Nested Paging"
Or: Use raw QEMU with custom CPUID spoofing:
  -cpu host,hypervisor=off,vmx=off

In GDB: intercept the CPUID instruction (hard). Better: run on bare metal or patch check.
```

#### 2. VMware Specific: I/O Port Magic

```c
// VMware responds on I/O port 0x5658 with magic value
__asm__ volatile(
    "movl $0x564D5868, %%eax\n"  // 'VMXh' magic
    "movl $0x0A, %%ecx\n"        // GETVERSION command
    "movl $0x5658, %%edx\n"      // I/O port
    "in %%dx, %%eax\n"           // execute backdoor
    : "=a"(result) : : "ecx","edx"
);
if (result == 0x564D5868) // VMware detected
```

**Bypass:** Run in VirtualBox instead of VMware, or patch the port check.

#### 3. Registry / File System Artifacts (Windows)

```c
// Checks for VMware registry keys:
RegOpenKey(HKLM, "SOFTWARE\\VMware, Inc.\\VMware Tools", ...)
RegOpenKey(HKLM, "SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware", ...)

// VirtualBox:
RegOpenKey(HKLM, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", ...)

// Common driver files:
"C:\\Windows\\System32\\drivers\\vboxdrv.sys"
"C:\\Windows\\System32\\drivers\\vmnet.sys"
```

**Bypass:** Delete/rename these registry keys and files, or hook the registry APIs.

#### 4. MAC Address Check

```
VMware:   00:0C:29:xx:xx:xx or 00:50:56:xx:xx:xx
VirtualBox: 08:00:27:xx:xx:xx
QEMU:     52:54:00:xx:xx:xx
```

**Bypass:** Change the MAC address of the VM's virtual NIC to a real vendor's OUI.

#### 5. Process List / Window Name Check

```c
// Checks for running analysis tools:
char* suspicious[] = {"wireshark", "ida", "x64dbg", "procmon",
                       "procexp", "ollydbg", "fiddler", "immunity"};
// Enumerates processes and compares names
```

**Bypass:** Rename x64dbg.exe to something innocent like "calc.exe".

#### 6. Timing (RDTSC)

```asm
rdtsc                ; read timestamp counter → EAX:EDX
; ... some instructions ...
rdtsc                ; read again
sub eax, [saved_eax]
cmp eax, THRESHOLD  ; if too long = single-stepped (VM is slower)
```

**Bypass:** Patch the comparison, or use a fast CPU in VM settings.

#### 7. Disk Size / RAM Size

```c
// Real systems have large disks/RAM
// VMs often have small defaults (8GB disk, 2GB RAM)
ULONGLONG diskSize = ...;
if (diskSize < 100LL * 1024 * 1024 * 1024) // < 100GB
    exit(1);
```

**Bypass:** Increase VM disk/RAM, or patch the check.

### Anti-VM in Linux Crackmes

```bash
# Detect what the binary checks:
strace ./crackme 2>&1 | grep -E "open|read" | grep -i "proc\|sys\|cpu"
# Look for: /proc/cpuinfo, /sys/class/dmi/..., /dev/disk/...

ltrace ./crackme 2>&1 | grep -E "strcmp|strstr" | head -20
# May reveal: strstr(cpuinfo_content, "QEMU") or strcmp(vendor, "VMware")

# Quick fix: 
cat /proc/cpuinfo | grep "model name"
# If it shows "QEMU Virtual CPU" → the binary might detect it
# Solution: run in a proper VM with CPU passthrough, or on bare metal
# Or: intercept the file reads with Frida and return fake content
```

---

## 9. Anti-Reversing / Obfuscation

These techniques make **static analysis** harder without necessarily detecting debuggers.

### 1. Control Flow Obfuscation (Opaque Predicates)

An **opaque predicate** is a conditional branch whose outcome is always the same, but looks like it could go either way to static analysis.

```c
// Always true, but hard to determine statically:
int x = argc * argc - argc;  // always 0 for main()
if (x * x == 0) {
    // real code
} else {
    // dead code (garbage/misleading)
}
```

**In disassembly, you see:**
```asm
; Looks like real branch:
mov  eax, [rbp-4]     
imul eax, eax          
test eax, eax          
jne  dead_branch       ← actually never taken
; real code follows
```

**Bypass:** Run the binary. Set breakpoints at both branch targets. Only one will ever be reached.

### 2. Control Flow Flattening

Converts a normal function into a giant switch statement. All "basic blocks" are in a loop, dispatched by a state variable.

```c
// Original:
// A → B → C → D

// Flattened:
int state = 0x1234;
while (1) {
    switch(state) {
        case 0x1234: /* block A */ state = 0xABCD; break;
        case 0xABCD: /* block B */ state = 0x5678; break;
        case 0x5678: /* block C */ state = 0x9999; break;
        case 0x9999: /* block D */ return result;
    }
}
```

**Bypass:**
- Use **miasm** or **angr** to recover control flow
- Trace execution dynamically: log state values, reconstruct real order
- In Ghidra: manually connect the blocks in the right order

### 3. Instruction Substitution

Replace simple instructions with equivalents:
```asm
; ADD EAX, 1  →  SUB EAX, -1
; XOR EAX, EAX  →  SUB EAX, EAX  →  AND EAX, 0  →  IMUL EAX, 0
; MOV EAX, 5  →  PUSH 5; POP EAX
```

**Bypass:** Just understand what the equivalent does, rename accordingly.

### 4. String Encryption

```c
// Strings not stored as plaintext:
char key[] = {0x73, 0x65, 0x63, 0x72, 0x65, 0x74};  // XOR key
char enc[] = {0x1A, 0x06, 0x18, 0x1E, 0x1F, 0x06};  // encrypted "secret"
// Decrypt at runtime: enc[i] ^= key[i % sizeof(key)]
```

**Finding encrypted strings:**
```bash
# Look for XOR loops in disassembly:
# Pattern: XOR [rbx+rax], dl followed by INC rax and CMP rax, length

# Use Ghidra script to find XOR decryption:
# Search → Program Text → "xor" in disassembly context

# Dynamic: run with strace and capture write() calls
# They'll write the decrypted strings
strace -e trace=write ./crackme 2>&1

# Or set breakpoint AFTER decryption loop and dump the buffer
```

**Automated decryption script:**
```python
# If you found: XOR key = 0x42, encrypted bytes at 0x403000
encrypted = bytes([0x21, 0x27, 0x36, 0x2D, 0x28, 0x27])
key = 0x42
decrypted = bytes([b ^ key for b in encrypted])
print(decrypted.decode())  # → "wacky!"
```

### 5. Junk Code Insertion

```asm
; Useless instructions inserted to confuse disassemblers:
nop
nop nop
xchg eax, eax
push eax
pop eax
add eax, 0
lea eax, [eax+0]  ; common junk
```

**Bypass:** In Ghidra, mark them as NOPs manually or write a script to remove them.

### 6. Overlapping Instructions (Disassembler Confusion)

```asm
; Code placed at offset N:
EB 01          ; JMP +1 (jump over the next byte)
E8             ; ← this byte is ALSO the start of "CALL" if disassembled linearly
00 00 00       ; ...

; Real disassembly: JMP → lands at E8 as data, then continues
; Linear disassembler thinks: E8 xx xx xx xx = CALL somewhere fake
```

**Bypass:** Use a **recursive descent disassembler** (IDA, Ghidra) not a linear one. Or trace execution in a debugger.

### 7. Position-Independent Code Tricks

```asm
; Binary uses call/pop to find its own address (PIC pattern):
call next
next:
pop rbx        ; rbx = address of 'next' label
sub rbx, 5     ; rbx = base address (offset to start of function)
; Then all accesses are relative to rbx
```

This makes static analysis harder because addresses are computed at runtime.

---

## 10. Reversing Python Binaries

Python programs distributed as binaries are usually:
1. **PyInstaller** bundles (most common)
2. **py2exe** or **cx_Freeze** packages
3. Raw `.pyc` files

### PyInstaller Binaries

PyInstaller bundles the Python interpreter + all modules + your script into one executable. The real Python bytecode is hidden inside.

**Step 1: Extract the bundle**
```bash
pip install pyinstxtractor
python3 pyinstxtractor.py crackme
# Creates: crackme_extracted/
# Inside: crackme.pyc (your target), plus all dependencies
```

**Step 2: Decompile the .pyc**

`.pyc` files are Python bytecode with a magic number header.

```bash
# Method 1: uncompyle6 (Python 2 & 3.0-3.8)
pip install uncompyle6
uncompyle6 crackme_extracted/crackme.pyc > crackme_source.py

# Method 2: decompile3 (Python 3.9+)
pip install decompile3
pycdc crackme_extracted/crackme.pyc

# Method 3: pycdc (C++ based, most reliable for new versions)
git clone https://github.com/zrax/pycdc
cd pycdc && cmake . && make
./pycdc crackme.pyc
```

**Step 3: If decompilation fails, read bytecode**

```bash
# Disassemble bytecode:
python3 -c "
import dis, marshal, struct
with open('crackme.pyc', 'rb') as f:
    f.read(16)  # skip header (magic + mtime + size)
    code = marshal.load(f)
dis.dis(code)
"

# For nested functions:
python3 -c "
import dis, marshal
with open('crackme.pyc', 'rb') as f:
    f.read(16)
    code = marshal.load(f)
    
def disassemble_all(code, depth=0):
    prefix = '  ' * depth
    print(f'{prefix}=== {code.co_name} ===')
    dis.dis(code)
    for const in code.co_consts:
        if hasattr(const, 'co_code'):
            disassemble_all(const, depth+1)

disassemble_all(code)
"
```

### Reading Python Bytecode

Key opcodes to know:
```
LOAD_CONST   → push a constant onto the stack (string, int, etc.)
LOAD_FAST    → push a local variable
STORE_FAST   → pop and store to local variable
LOAD_GLOBAL  → load a global function/variable
CALL_FUNCTION → call a function with N args from stack
COMPARE_OP   → == != < > etc.
POP_JUMP_IF_FALSE / POP_JUMP_IF_TRUE → conditional branch
RETURN_VALUE → return top of stack
BUILD_STRING / FORMAT_VALUE → f-string construction
```

**Example bytecode analysis:**
```
  2           0 LOAD_FAST                0 (password)
              2 LOAD_CONST               1 ('s3cr3t')
              4 COMPARE_OP               2 (==)
              6 POP_JUMP_IF_FALSE       12
              8 LOAD_CONST               2 ('Correct!')
             10 RETURN_VALUE
        >>   12 LOAD_CONST               3 ('Wrong!')
             14 RETURN_VALUE

→ Simply comparing password == 's3cr3t'. Answer: s3cr3t
```

### PyInstaller Version Detection & Magic Header

```bash
# The .pyc magic number identifies Python version:
python3 -c "
import importlib.util
with open('crackme.pyc', 'rb') as f:
    magic = f.read(4)
print(f'Magic: {magic.hex()}')

# Common magic numbers:
# 0D 0D 0D 0A → Python 2.7
# 42 0D 0D 0A → Python 3.3
# 33 0D 0D 0A → Python 3.8
# 61 0D 0D 0A → Python 3.9
# 6F 0D 0D 0A → Python 3.11
# Full list: https://github.com/nicowillis/python-magic-bytes
"
```

### Obfuscated Python (PyArmor, etc.)

Some Python crackmes use **PyArmor** or **Nuitka**:

```bash
# PyArmor adds an encrypted runtime:
# crackme_extracted/ will have pytransform.so + encrypted .pyc
# Approach: dynamic analysis — run the binary and hook Python at runtime

# Frida on Python process:
frida -l hook_python.js crackme
```

```javascript
// hook_python.js — intercept Python string comparisons
var PyUnicode_CompareWithASCIIString = Module.findExportByName(null, 'PyUnicode_CompareWithASCIIString');
if (PyUnicode_CompareWithASCIIString) {
    Interceptor.attach(PyUnicode_CompareWithASCIIString, {
        onEnter: function(args) {
            // args[0] = Python string object, args[1] = C string
            console.log('Comparing with: ' + args[1].readCString());
        }
    });
}
```

### Nuitka Binaries

Nuitka compiles Python to C then to native binary. Much harder to reverse:

```bash
# Use a normal binary RE approach — it IS a native binary
# But look for Python-like patterns: lots of PyObject*, refcount operations
# String constants are still in .rodata
strings ./crackme | grep -v "^[^a-zA-Z]" | head -50
# Often reveals the key or parts of the comparison
```

---

## 11. Automated RE with angr

**angr** is a Python binary analysis framework that performs **symbolic execution**: instead of running with real values, it runs with symbolic variables and tracks all possible paths.

### Core Concept: Symbolic Execution

```
Normal execution: input="AAAA" → program follows ONE path → prints "Wrong"

Symbolic execution: input=symbolic("?") → angr explores ALL paths simultaneously
    → finds the path that leads to "Correct!" 
    → reconstructs what input must have been to reach it
    → output: "s3cr3t_k3y!"
```

### Installation

```bash
pip install angr
# For visualization:
pip install angr[dev]
```

### angr Quick-Start Template

```python
import angr
import claripy

# Load the binary
proj = angr.Project('./crackme', auto_load_libs=False)

# Find addresses first (in Ghidra/objdump):
# "Correct" string reference → find_addr
# "Wrong" / "fail" string reference → avoid_addr

find_addr  = 0x401234   # address of "Correct!" print
avoid_addr = 0x401567   # address of "Wrong!" print

# Create symbolic input
# Method 1: Symbolic stdin
state = proj.factory.entry_state(
    stdin=angr.SimFile('/dev/stdin', content=claripy.BVS('input', 100 * 8))
)

# Method 2: Symbolic argv
password_len = 20
password = claripy.BVS('password', password_len * 8)
state = proj.factory.entry_state(
    args=['./crackme', password],
    add_options=angr.options.unicorn  # faster with unicorn engine
)

# Create simulation manager
simgr = proj.factory.simulation_manager(state)

# Explore!
simgr.explore(find=find_addr, avoid=avoid_addr)

# Extract result
if simgr.found:
    found_state = simgr.found[0]
    # Method 1: Read stdin
    result = found_state.posix.dumps(0)
    print(f"Input: {result}")
    # Method 2: Read argv
    result = found_state.solver.eval(password, cast_to=bytes)
    print(f"Password: {result}")
```

### Finding Addresses for angr

```bash
# Method 1: strings + objdump
strings -a -t x ./crackme | grep -i "correct\|good\|win\|flag"
# e.g., " 1234 Correct!"
# Then: objdump -d crackme | grep -B5 "1234"

# Method 2: radare2
r2 ./crackme
> aaa                          # analyze all
> iz                           # list strings
> / Correct!                   # search for string
> axt 0x<string_addr>          # find xrefs to string = code that prints it
> s 0x<function_addr>
> pdf                          # disassemble to verify

# Method 3: Ghidra
# Search → For Strings → "Correct!" → Right-click → References → Go to code
```

### Advanced angr Usage

#### Dealing with stdin vs argv

```python
# ARGV-based crackme:
import angr, claripy

proj = angr.Project('./crackme', auto_load_libs=False)

# Known password length = 12:
flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(12)]
flag = claripy.Concat(*flag_chars)

state = proj.factory.entry_state(args=['./crackme', flag])

# Add constraints: printable ASCII only
for c in flag_chars:
    state.solver.add(c >= 0x20)   # space
    state.solver.add(c <= 0x7e)   # tilde

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=find_addr, avoid=avoid_addr)

if simgr.found:
    s = simgr.found[0]
    result = s.solver.eval(flag, cast_to=bytes)
    print(f"Flag: {result.decode()}")
```

#### Hooking Functions

```python
# Binary calls some external function we don't want to simulate:
@proj.hook(0x401100, length=5)  # hook a 5-byte instruction at 0x401100
def skip_anti_debug(state):
    state.regs.rax = 0  # pretend ptrace returned 0

# Or hook a library function:
@proj.hook_symbol('ptrace')
def hook_ptrace(state):
    state.regs.rax = 0
    return
```

#### Using veritesting for loops

```python
simgr = proj.factory.simulation_manager(state, veritesting=True)
# veritesting merges states inside loops = faster for loop-heavy code
```

#### Finding the flag address automatically

```python
import angr

proj = angr.Project('./crackme', auto_load_libs=False)

# Let angr find "WIN" vs "LOSE" automatically using CFG:
cfg = proj.analyses.CFGFast()

# Find all string references:
for addr, func in proj.kb.functions.items():
    for block in func.blocks:
        for insn in block.capstone.insns:
            if insn.mnemonic == 'lea':
                # Check if it references a string in .rodata
                pass

# Better: use angr's string finder
for string in proj.loader.main_object.memory.backers[0]:
    pass  # custom walk
```

#### Full Automated Solver

```python
#!/usr/bin/env python3
"""
Auto-solve crackme: find input that reaches "Correct" but not "Wrong"
Usage: python3 solve.py ./crackme
"""
import angr, claripy, sys, subprocess

binary = sys.argv[1]

# Find interesting addresses using strings
result = subprocess.run(['strings', '-a', '-t', 'x', binary], 
                       capture_output=True, text=True)
good_offset = bad_offset = None

for line in result.stdout.splitlines():
    parts = line.strip().split(maxsplit=1)
    if len(parts) == 2:
        offset, string = parts
        if any(w in string.lower() for w in ['correct', 'congrat', 'good', 'win', 'flag']):
            good_offset = int(offset, 16)
            print(f"[+] Good string at offset: {hex(good_offset)}: {string}")
        elif any(w in string.lower() for w in ['wrong', 'fail', 'bad', 'invalid', 'error']):
            bad_offset = int(offset, 16)
            print(f"[-] Bad string at offset:  {hex(bad_offset)}: {string}")

proj = angr.Project(binary, auto_load_libs=False)
base = proj.loader.main_object.min_addr
print(f"[*] Binary base: {hex(base)}")

find_addr  = base + good_offset if good_offset else None
avoid_addr = base + bad_offset  if bad_offset  else None

print(f"[*] Find:  {hex(find_addr) if find_addr else 'N/A'}")
print(f"[*] Avoid: {hex(avoid_addr) if avoid_addr else 'N/A'}")

# Try varying input lengths
for length in range(4, 50):
    print(f"[*] Trying length {length}...")
    chars = [claripy.BVS(f'c{i}', 8) for i in range(length)]
    flag = claripy.Concat(*chars)
    
    state = proj.factory.entry_state(args=[binary, flag])
    for c in chars:
        state.solver.add(c >= 0x20, c <= 0x7e)
    
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=find_addr, avoid=avoid_addr, timeout=30)
    
    if simgr.found:
        s = simgr.found[0]
        answer = s.solver.eval(flag, cast_to=bytes)
        print(f"\n[!!!] SOLVED! Input (len={length}): {answer}")
        break
```

### angr Troubleshooting

| Problem | Solution |
|---------|---------|
| Very slow / hangs | Add `avoid` addresses aggressively; use `veritesting=True`; add more constraints |
| "No found states" | Wrong find/avoid addresses; try `find=lambda s: b"Correct" in s.posix.dumps(1)` |
| Symbolic execution explosion | Binary has too many branches; use hooks to skip complex checks |
| Anti-debug crashes angr | `proj.hook_symbol('ptrace', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'])` |
| Shared library needed | `auto_load_libs=True` (slower) or `extern-address` hooks |

```python
# Alternative find strategy: search stdout content
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),
    avoid=lambda s: b"Wrong" in s.posix.dumps(1)
)
```

---

## 12. Automated RE with Python Scripts

### Scripting radare2 (r2pipe)

```python
import r2pipe, json

r2 = r2pipe.open('./crackme')
r2.cmd('aaa')                         # analyze all (takes time)

# Get all functions
functions = json.loads(r2.cmd('aflj'))
for fn in functions:
    print(f"{hex(fn['offset'])}: {fn['name']} ({fn['size']} bytes)")

# Get all strings
strings = json.loads(r2.cmd('izj'))
for s in strings:
    print(f"{hex(s['vaddr'])}: {s['string']}")

# Find XREFs to a string
r2.cmd(f's {hex(string_addr)}')       # seek to string
xrefs = json.loads(r2.cmd('axtj'))   # get XREFs to current address
for xref in xrefs:
    print(f"Referenced from: {hex(xref['from'])}")

# Disassemble a function:
r2.cmd(f's {hex(func_addr)}')
print(r2.cmd('pdf'))                  # disassemble function

# Extract constants from a function:
r2.cmd(f's {hex(func_addr)}')
ops = json.loads(r2.cmd('pdfj'))['ops']
for op in ops:
    if op.get('val'):
        print(f"Constant at {hex(op['offset'])}: {hex(op['val'])}")

r2.quit()
```

### Scripting Ghidra (Python / Flat API)

Ghidra scripts go in `~/ghidra_scripts/` or run via Script Manager.

```python
# GhidraScript: find_comparisons.py
# Run in Ghidra Script Manager

from ghidra.program.model.listing import CodeUnitIterator
from ghidra.app.decompiler import DecompInterface

# Find all strcmp calls and their arguments
for func in currentProgram.getFunctionManager().getFunctions(True):
    for ref in getReferencesTo(func.getEntryPoint()):
        if "strcmp" in func.getName():
            addr = ref.getFromAddress()
            print(f"strcmp called from: {addr}")

# Find all string constants in a function:
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

func = getFunctionContaining(currentAddress)
result = decompiler.decompileFunction(func, 30, monitor)
if result.decompileCompleted():
    code = result.getDecompiledFunction().getC()
    print(code)
```

### Scripting IDA (IDAPython)

```python
import idc, idautils, ida_bytes, ida_funcs

# Find all cross-references to a string
str_addr = idc.get_name_ea_simple("aCorrect")  # find by name
for xref in idautils.XrefsTo(str_addr):
    print(f"Used at: {hex(xref.frm)} in {idc.get_func_name(xref.frm)}")

# Rename all functions based on strings they reference:
for func_addr in idautils.Functions():
    func = ida_funcs.get_func(func_addr)
    for item_addr in idautils.FuncItems(func_addr):
        # Check all operands for string references
        for i in range(2):
            op = idc.get_operand_value(item_addr, i)
            s = idc.get_strlit_contents(op, -1, idc.STRTYPE_C)
            if s:
                name = f"fn_uses_{s[:20].decode(errors='replace')}"
                idc.set_name(func_addr, name, idc.SN_NOWARN)

# Dump all constants (potential keys):
for func_addr in idautils.Functions():
    for item in idautils.FuncItems(func_addr):
        for n in range(idc.get_operands_count(item)):
            if idc.get_operand_type(item, n) == idc.o_imm:
                val = idc.get_operand_value(item, n)
                if 0x20 <= val <= 0x7e:  # printable ASCII
                    print(f"{hex(item)}: immediate {hex(val)} = '{chr(val)}'")
```

### Frida for Dynamic Analysis

```python
# frida_hook.py — intercept string comparisons dynamically
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")

session = frida.spawn(['./crackme', 'AAAA'], stdio='pipe')
pid = session
process = frida.attach(pid)

script = process.create_script("""
// Hook strcmp
var strcmp_ptr = Module.findExportByName(null, 'strcmp');
if (strcmp_ptr) {
    Interceptor.attach(strcmp_ptr, {
        onEnter: function(args) {
            this.s1 = args[0].readUtf8String();
            this.s2 = args[1].readUtf8String();
        },
        onLeave: function(retval) {
            send('[strcmp] "' + this.s1 + '" vs "' + this.s2 + '" → ' + retval);
        }
    });
}

// Hook memcmp
var memcmp_ptr = Module.findExportByName(null, 'memcmp');
if (memcmp_ptr) {
    Interceptor.attach(memcmp_ptr, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            this.buf1 = args[0].readByteArray(len);
            this.buf2 = args[1].readByteArray(len);
            this.len = len;
        },
        onLeave: function(retval) {
            send('[memcmp] len=' + this.len + 
                 ' buf1=' + hexdump(this.buf1, {header:false}) +
                 ' buf2=' + hexdump(this.buf2, {header:false}));
        }
    });
}
""")

script.on('message', on_message)
script.load()
frida.resume(session)
sys.stdin.read()
```

### Automated XOR Key Recovery

```python
#!/usr/bin/env python3
"""
Find XOR-encrypted strings in a binary.
Looks for patterns: encrypted_blob XOR key_blob = printable ASCII
"""
import sys
from itertools import product

def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def is_printable(data):
    return all(0x20 <= b <= 0x7e for b in data)

def find_xor_strings(binary_path, min_len=4, max_key=4):
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    results = []
    # Try single-byte XOR keys
    for offset in range(len(data) - min_len):
        for key_byte in range(256):
            chunk = data[offset:offset+min_len]
            decrypted = xor_decrypt(chunk, bytes([key_byte]))
            if is_printable(decrypted):
                # Extend to find full string
                length = min_len
                while offset + length < len(data):
                    c = data[offset + length] ^ key_byte
                    if 0x20 <= c <= 0x7e:
                        length += 1
                    else:
                        break
                if length >= min_len:
                    full_dec = xor_decrypt(data[offset:offset+length], bytes([key_byte]))
                    results.append((offset, key_byte, full_dec.decode()))
    
    # Deduplicate and sort
    seen = set()
    for r in results:
        if r[2] not in seen and len(r[2]) > 3:
            seen.add(r[2])
            print(f"Offset {hex(r[0])}, key=0x{r[1]:02x}: {r[2]!r}")

find_xor_strings(sys.argv[1])
```

---

## 13. Full Crackme Walkthroughs

### Example 1: Stripped ELF with strcmp

**Scenario:** `crackme1` — stripped ELF, no symbols, takes password as argv[1]

**Step 1: Triage**
```bash
file crackme1
# ELF 64-bit, stripped

strings crackme1 | head -20
# "Usage: %s <password>"
# "Correct! Here is your flag: %s"  ← promising
# "Wrong password"
# "CTF{" ← partial flag or hint

ltrace ./crackme1 test123 2>&1
# strcmp("test123", "g0t_em_b0ss")  ← DONE!
./crackme1 g0t_em_b0ss
# Correct! Here is your flag: CTF{g0t_em_b0ss}
```

### Example 2: Packed Binary with Anti-Debug

**Scenario:** `crackme2.exe` — UPX-packed, IsDebuggerPresent check, compares to MD5

**Step 1: Detect packer**
```bash
diec crackme2.exe
# UPX 3.95 [PE32+, LZMA]
```

**Step 2: Unpack**
```bash
upx -d crackme2.exe -o crackme2_unpacked.exe
```

**Step 3: Open in x64dbg, enable ScyllaHide**
```
Plugins → ScyllaHide → Apply All
```

**Step 4: Find the check in Ghidra**
```
Open crackme2_unpacked.exe in Ghidra
Search → For Strings → "Wrong" → Click reference → opens check function

Decompiler shows:
void check(char* input) {
    char md5[33];
    compute_md5(input, md5);
    if (strcmp(md5, "5f4dcc3b5aa765d61d8327deb882cf99") == 0)
        win();
    else
        lose();
}

// 5f4dcc3b5aa765d61d8327deb882cf99 is MD5 of "password"!
```

```bash
echo -n "password" | md5sum
# 5f4dcc3b5aa765d61d8327deb882cf99  ← matches!
./crackme2_unpacked.exe password
# Correct!
```

### Example 3: Anti-Debug + Custom Algorithm

**Scenario:** `crackme3` — ptrace check + custom encoding

**Step 1: Bypass ptrace**
```bash
LD_PRELOAD=./fake_ptrace.so ./crackme3 AAAA
# Now runs without exiting
```

**Step 2: Trace with strace**
```bash
strace ./crackme3 AAAA 2>&1 | tail -20
# write(1, "Wrong password\n", 15)
# No useful comparisons visible
```

**Step 3: Open in Ghidra**
```
Found check function. Decompiler output:
int check(char* s) {
    int n = strlen(s);
    if (n != 8) return 0;
    char enc[9];
    for (int i = 0; i < 8; i++) {
        enc[i] = (s[i] ^ 0x2A) + i;
    }
    enc[8] = 0;
    return strcmp(enc, "\x4b\x4e\x53\x57\x6c\x76\x6a\x77") == 0;
}
```

**Step 4: Reverse the algorithm**
```python
target = bytes([0x4b, 0x4e, 0x53, 0x57, 0x6c, 0x76, 0x6a, 0x77])
result = bytearray(8)
for i in range(8):
    # enc[i] = (s[i] ^ 0x2A) + i  →  s[i] = (enc[i] - i) ^ 0x2A
    result[i] = (target[i] - i) ^ 0x2A

print(result.decode())  # → "p4ssw0rd"
```

### Example 4: Python Crackme (PyInstaller)

**Scenario:** `crackme4` — PyInstaller bundle

```bash
# Extract
python3 pyinstxtractor.py crackme4
ls crackme4_extracted/
# crackme4.pyc  struct.pyc  ...

# Decompile
uncompyle6 crackme4_extracted/crackme4.pyc

# Output:
import hashlib

def check(password):
    h = hashlib.sha256(password.encode()).hexdigest()
    return h == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

# sha256("hello") = 2cf24dba...
# Google the hash → 'hello'
./crackme4 hello
# Correct!
```

### Example 5: angr Solve

**Scenario:** `crackme5` — complex algorithm, not easily reversible manually

```python
#!/usr/bin/env python3
import angr, claripy

proj = angr.Project('./crackme5', auto_load_libs=False)

# From Ghidra: win() is at 0x401456, fail() at 0x4014a2
FIND  = 0x401456
AVOID = 0x4014a2

# 16-char password via argv[1]
chars = [claripy.BVS(f'c{i}', 8) for i in range(16)]
password = claripy.Concat(*chars)

state = proj.factory.entry_state(args=['./crackme5', password])

# Constrain to printable ASCII
for c in chars:
    state.solver.add(c >= 0x21)   # '!'
    state.solver.add(c <= 0x7e)   # '~'

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=FIND, avoid=AVOID)

if simgr.found:
    sol = simgr.found[0]
    answer = sol.solver.eval(password, cast_to=bytes)
    print(f"[+] Password: {answer.decode()}")
    
    # Verify:
    import subprocess
    out = subprocess.run(['./crackme5', answer.decode()], capture_output=True)
    print(out.stdout.decode())
```

### Example 6: C++ vtable Crackme

**Scenario:** `crackme6` — C++ OOP, multiple classes, virtual dispatch

**Step 1: Find vtables in Ghidra**
```
View → Data Type Preview
Search for patterns: 
- In .rodata: arrays of function pointers
- References to them in code: mov [rdi], <rodata_addr>

Found:
0x403000: [fn_at_4011a0, fn_at_4011c0, fn_at_4011e0]  ← vtable for class A
0x403018: [fn_at_4012a0, fn_at_4011c0, fn_at_4011e0]  ← vtable for class B (inherits A, overrides first method)
```

**Step 2: Find RTTI**
```
At 0x402ff0 (vtable-16): pointer to type_info
Follow pointer → string "_ZN1AE" → demangle → class A
```

**Step 3: Trace virtual call**
```
; virtual call pattern:
mov rax, [rdi]          ; load vtable pointer from object
call [rax + 0x0]        ; call first virtual function
; RDI = object pointer, so first field = vtable
; Object is class A or B depending on vtable at [rdi]
```

**Step 4: Understand class hierarchy, solve as normal function**

---

## 14. Cheat Sheet

### Quick Triage Commands

```bash
# File type
file ./binary

# Strings (grep for juicy stuff)
strings -a -n 6 ./binary | grep -iE "pass|key|flag|correct|wrong|secret"

# Packer detection
diec ./binary                    # DIE
strings ./binary | grep -i upx   # UPX check

# Entropy (packed if > 7.5)
python3 -c "
import sys, math
data = open(sys.argv[1],'rb').read()
freq = [data.count(bytes([i])) for i in range(256)]
e = -sum(f/len(data)*math.log2(f/len(data)) for f in freq if f)
print(f'Entropy: {e:.2f}')
" ./binary

# Dynamic library calls (best for quick win)
ltrace ./binary ARG 2>&1 | grep -E "strcmp|memcmp|strncmp|bcmp"

# System calls
strace ./binary 2>&1 | tail -30

# Symbols?
nm ./binary 2>&1 | grep " T "    # non-stripped = has symbols
```

### GDB Quick Reference

```bash
gdb ./crackme
(gdb) set args AAAA            # set program arguments
(gdb) r                        # run
(gdb) b *0x401234              # breakpoint at address
(gdb) b strcmp                 # breakpoint at function
(gdb) ni                       # next instruction (step over)
(gdb) si                       # step into
(gdb) c                        # continue
(gdb) x/s $rdi                 # examine string at RDI
(gdb) x/20wx $rsp              # examine 20 words at RSP
(gdb) info registers           # show all registers
(gdb) set $rax = 0             # modify register
(gdb) set *((int*)0x601000) = 1  # modify memory
(gdb) watch *0x601000          # watchpoint
(gdb) disas $pc, +50           # disassemble near PC
(gdb) finish                   # run until return
(gdb) catch syscall ptrace     # catch ptrace calls
```

### x86-64 Register Calling Convention

```
Function call: arg1=RDI, arg2=RSI, arg3=RDX, arg4=RCX, arg5=R8, arg6=R9
Return value: RAX (or RAX:RDX for 128-bit)
Callee-saved: RBP, RBX, R12-R15
Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11
```

### Common Anti-Debug Bypasses

| Technique | Detection | Bypass |
|-----------|-----------|--------|
| ptrace(TRACEME) | `ptrace` in ltrace output | LD_PRELOAD hook / GDB catch syscall |
| IsDebuggerPresent | PEB.BeingDebugged read | ScyllaHide / patch PEB |
| /proc/self/status | `open("/proc/self/status")` in strace | Frida hook / file redirect |
| Timing (RDTSC) | Two rdtsc + comparison | Patch comparison / high-speed CPU |
| NtQueryInformationProcess | ntdll.dll call | ScyllaHide hook |
| SIGTRAP handler | signal(SIGTRAP,...) | `handle SIGTRAP nopass` in GDB |

### angr One-Liners

```python
# Find password via stdin:
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1))

# Find password via argv[1]:
p = claripy.BVS('p', 8*20)
state = proj.factory.entry_state(args=['./c', p])
simgr.explore(find=WIN, avoid=FAIL)
sol = simgr.found[0].solver.eval(p, cast_to=bytes)

# Hook anti-debug:
@proj.hook_symbol('ptrace')
def h(s): s.regs.rax = 0

# Skip a check entirely:
@proj.hook(0x401234, length=5)
def skip(s): pass
```

### Python Bytecode Quick Decode

```bash
# Show bytecode of a .pyc:
python3 -c "
import dis, marshal
data = open('x.pyc','rb').read()
# skip 16-byte header (Python 3.8+), 12 bytes for older
code = marshal.loads(data[16:])
dis.dis(code)
"

# Extract PyInstaller bundle:
python3 pyinstxtractor.py bundle.exe

# Decompile .pyc:
uncompyle6 x.pyc       # Python ≤ 3.8
pycdc x.pyc            # Python ≥ 3.9
```

### Decision Tree for Crackmes

```
Start
│
├── Packed?  (diec, entropy > 7.5, few strings)
│   └── YES → UPX? → upx -d
│             Custom? → OEP hunt (ESP trick / x64dbg + Scylla)
│
├── Python binary? (strings show "python", "pyinstaller")
│   └── pyinstxtractor → uncompyle6/pycdc
│
├── ltrace/strace quick win?
│   └── YES → strcmp/memcmp shows the key → done!
│
├── Static analysis (Ghidra/IDA)
│   ├── Find "Correct"/"Wrong" strings → XREFs → key function
│   ├── Understand algorithm
│   └── Simple algo? → reverse manually
│                 Complex? → angr
│
├── Anti-debug triggered? (exits immediately)
│   ├── Linux: LD_PRELOAD ptrace hook / GDB ptrace bypass
│   └── Windows: ScyllaHide
│
└── Anti-VM? (doesn't run in VM)
    ├── CPUID: patch or run on bare metal
    └── Registry/file checks: remove artifacts or hook
```

---

> 📌 **Final Tips for crackmes.one**
> 
> 1. **Always start with `file`, `strings`, and `ltrace`** — 30% of easy/medium crackmes are solved in 60 seconds this way.
> 2. **Ghidra is free and excellent** — spend the time to learn the decompiler view. It often produces near-compilable C code.
> 3. **Name things as you go** — your first 10 minutes renaming functions and variables saves hours later.
> 4. **angr for hard algorithms** — if you can't easily invert the math, let angr solve it.
> 5. **Frida for anti-analysis** — when ptrace/anti-VM tricks are stacked, Frida's dynamic hooking cuts through all of them.
> 6. **Read other writeups** — after solving, read how others solved the same crackme. You'll always learn a new technique.

---

*Notes cover: ELF/PE internals · stripped binaries · UPX + custom packers · C++ vtables/RTTI/STL · ptrace/IsDebuggerPresent/RDTSC/timing anti-debug · CPUID/registry/MAC anti-VM · control flow obfuscation · string encryption · PyInstaller reverse engineering · angr symbolic execution · r2pipe/IDAPython/Frida scripting*
