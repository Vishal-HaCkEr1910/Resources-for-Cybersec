# Psutil Library - Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [CPU Functions](#cpu-functions)
4. [Memory Functions](#memory-functions)
5. [Disk Functions](#disk-functions)
6. [Network Functions](#network-functions)
7. [Process Functions](#process-functions)
8. [System Functions](#system-functions)
9. [Sensors Functions](#sensors-functions)
10. [Advanced Examples](#advanced-examples)

---

## Introduction

### What is Psutil?

Psutil (Python System and Process Utilities) is a cross-platform library for retrieving information on running processes and system utilization (CPU, memory, disks, network, sensors) in Python.

**Key Features:**
- CPU usage monitoring
- Memory usage tracking
- Disk I/O statistics
- Network interface information
- Process management and monitoring
- System information retrieval
- Cross-platform compatibility (Linux, Windows, macOS, BSD)

**Advantages:**
- Simple and intuitive API
- Cross-platform support
- Real-time monitoring capabilities
- Process management without external tools
- Lightweight and efficient

---

## Installation

### Install Psutil

```bash
pip install psutil
```

### For Development (with C extensions):

```bash
pip install --upgrade psutil
```

### Verify Installation

```python
import psutil
print(f"Psutil version: {psutil.VERSION}")
print(f"Platform: {psutil.OPSYS}")
```

---

## CPU Functions

### Theory

The CPU (Central Processing Unit) is the processor of a computer. Key concepts:
- **CPU Percent:** Utilization percentage of CPU
- **CPU Count:** Number of physical and logical cores
- **CPU Times:** Time spent in different states (user, system, idle, iowait)
- **CPU Frequency:** Current clock speed of the processor

### Get CPU Count

```python
import psutil

# Get total logical CPU cores
logical_cores = psutil.cpu_count(logical=True)
print(f"Logical CPU cores: {logical_cores}")

# Get physical CPU cores
physical_cores = psutil.cpu_count(logical=False)
print(f"Physical CPU cores: {physical_cores}")

# Example output:
# Logical CPU cores: 8
# Physical CPU cores: 4
```

**Theory:** Logical cores include hyper-threaded cores, while physical cores are actual processors.

### Get CPU Times

```python
import psutil

# Get CPU times for the entire system
cpu_times = psutil.cpu_times()
print(f"User time: {cpu_times.user}")
print(f"System time: {cpu_times.system}")
print(f"Idle time: {cpu_times.idle}")
print(f"Nice time: {cpu_times.nice}")
print(f"IOWait time: {cpu_times.iowait}")
print(f"IRQ time: {cpu_times.irq}")

# Full breakdown
print(cpu_times)
# scpufreq(user=2255.6, system=1456.5, idle=45231.1, nice=0.0, iowait=123.2, irq=12.3, softirq=5.2)
```

**Theory:**
- **User:** Time running user processes
- **System:** Time running kernel processes
- **Idle:** Time when CPU is idle
- **Nice:** Time running low-priority processes
- **IOWait:** Time waiting for I/O
- **IRQ:** Time servicing interrupts

### Get CPU Usage Percent

```python
import psutil
import time

# Single call (returns percentage since last boot)
overall_percent = psutil.cpu_percent(interval=1)
print(f"Overall CPU usage: {overall_percent}%")

# Per-core CPU usage
per_core = psutil.cpu_percent(interval=1, percpu=True)
for i, percent in enumerate(per_core):
    print(f"Core {i}: {percent}%")

# Repeated measurements
print("Monitoring CPU for 10 seconds:")
for i in range(10):
    percent = psutil.cpu_percent(interval=1)
    print(f"Measurement {i+1}: {percent}%")
```

**Theory:** The interval parameter specifies the time window for measurement. Without interval, it uses the last measurement.

### Get CPU Frequency

```python
import psutil

# Get CPU frequency
freq = psutil.cpu_freq()
print(f"Current frequency: {freq.current} MHz")
print(f"Minimum frequency: {freq.min} MHz")
print(f"Maximum frequency: {freq.max} MHz")

# Per-core frequency
per_core_freq = psutil.cpu_freq(percpu=True)
for i, freq in enumerate(per_core_freq):
    print(f"Core {i}: {freq.current} MHz")
```

### CPU Statistics

```python
import psutil

# Get CPU statistics
stats = psutil.cpu_stats()
print(f"Context switches: {stats.ctx_switches}")
print(f"Interrupts: {stats.interrupts}")
print(f"Soft interrupts: {stats.soft_interrupts}")
print(f"Syscalls: {stats.syscalls}")

# Example output:
# Context switches: 1234567
# Interrupts: 2345678
# Soft interrupts: 345678
# Syscalls: 456789
```

### Advanced CPU Monitoring Example

```python
import psutil
import time

def monitor_cpu(duration=10, interval=1):
    print(f"Monitoring CPU for {duration} seconds...\n")
    
    for i in range(duration):
        # Overall usage
        overall = psutil.cpu_percent(interval=interval)
        
        # Per-core usage
        per_core = psutil.cpu_percent(interval=0, percpu=True)
        
        # Frequency
        freq = psutil.cpu_freq()
        
        print(f"Time {i+1}s:")
        print(f"  Overall: {overall}%")
        print(f"  Cores: {per_core}")
        print(f"  Frequency: {freq.current:.0f} MHz")
        print()

monitor_cpu(5)
```

---

## Memory Functions

### Theory

Memory refers to RAM (Random Access Memory). Key concepts:
- **Total:** Total physical memory
- **Available:** Memory available for processes
- **Used:** Memory currently in use
- **Free:** Free memory (not available immediately)
- **Percent:** Memory usage percentage
- **Virtual Memory:** Disk space used as memory (swap)

### Get Memory Information

```python
import psutil

# Get virtual memory information
vm = psutil.virtual_memory()
print(f"Total: {vm.total / (1024**3):.2f} GB")
print(f"Available: {vm.available / (1024**3):.2f} GB")
print(f"Used: {vm.used / (1024**3):.2f} GB")
print(f"Free: {vm.free / (1024**3):.2f} GB")
print(f"Percent: {vm.percent}%")
print(f"Active: {vm.active / (1024**3):.2f} GB")
print(f"Inactive: {vm.inactive / (1024**3):.2f} GB")
print(f"Buffers: {vm.buffers / (1024**3):.2f} GB")
print(f"Cached: {vm.cached / (1024**3):.2f} GB")

# Example output:
# Total: 15.62 GB
# Available: 8.45 GB
# Used: 7.17 GB
# Free: 2.14 GB
# Percent: 45.9%
```

### Get Swap Memory

```python
import psutil

# Get swap memory information
swap = psutil.swap_memory()
print(f"Total swap: {swap.total / (1024**3):.2f} GB")
print(f"Used swap: {swap.used / (1024**3):.2f} GB")
print(f"Free swap: {swap.free / (1024**3):.2f} GB")
print(f"Swap percent: {swap.percent}%")

# Example output:
# Total swap: 2.00 GB
# Used swap: 0.05 GB
# Free swap: 1.95 GB
# Swap percent: 2.5%
```

### Memory Usage Monitoring

```python
import psutil

def monitor_memory(duration=5, interval=1):
    print(f"Monitoring memory for {duration} seconds...\n")
    
    for i in range(duration):
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        print(f"Time {i+1}s:")
        print(f"  Virtual Memory: {vm.percent}% ({vm.used / (1024**3):.2f} GB used)")
        print(f"  Swap: {swap.percent}% ({swap.used / (1024**3):.2f} GB used)")
        print()
        import time
        time.sleep(interval)

monitor_memory()
```

### Memory Threshold Alert

```python
import psutil

def check_memory_alert(threshold=80):
    vm = psutil.virtual_memory()
    
    if vm.percent > threshold:
        print(f"WARNING: Memory usage is {vm.percent}%!")
        print(f"Available memory: {vm.available / (1024**3):.2f} GB")
        return True
    else:
        print(f"Memory usage OK: {vm.percent}%")
        return False

check_memory_alert(threshold=50)
```

---

## Disk Functions

### Theory

Disk operations involve storage devices. Key concepts:
- **Disk Partitions:** Logical divisions of storage
- **Disk Usage:** Space used and available
- **Disk I/O:** Read/write operations and bytes
- **Disk I/O Counters:** Statistics on disk operations

### Get Disk Partitions

```python
import psutil

# Get all disk partitions
partitions = psutil.disk_partitions()

for partition in partitions:
    print(f"Device: {partition.device}")
    print(f"Mount point: {partition.mountpoint}")
    print(f"File system: {partition.fstype}")
    print(f"Options: {partition.opts}")
    print()

# Example output:
# Device: /dev/sda1
# Mount point: /
# File system: ext4
# Options: rw,relatime,errors=remount-ro
```

### Get Disk Usage

```python
import psutil

# Get disk usage for all partitions
partitions = psutil.disk_partitions()

for partition in partitions:
    try:
        usage = psutil.disk_usage(partition.mountpoint)
        print(f"Mount: {partition.mountpoint}")
        print(f"  Total: {usage.total / (1024**3):.2f} GB")
        print(f"  Used: {usage.used / (1024**3):.2f} GB")
        print(f"  Free: {usage.free / (1024**3):.2f} GB")
        print(f"  Percent: {usage.percent}%")
        print()
    except PermissionError:
        pass

# For specific path
home_usage = psutil.disk_usage('/')
print(f"Root usage: {home_usage.percent}%")
```

### Get Disk I/O Counters

```python
import psutil

# Get disk I/O statistics
io_counters = psutil.disk_io_counters()
print(f"Read count: {io_counters.read_count}")
print(f"Write count: {io_counters.write_count}")
print(f"Read bytes: {io_counters.read_bytes / (1024**3):.2f} GB")
print(f"Write bytes: {io_counters.write_bytes / (1024**3):.2f} GB")
print(f"Read time: {io_counters.read_time} ms")
print(f"Write time: {io_counters.write_time} ms")

# Per-disk I/O counters
per_disk = psutil.disk_io_counters(perdisk=True)
for disk, counters in per_disk.items():
    print(f"{disk}: {counters.read_bytes / (1024**3):.2f} GB read")
```

### Disk Monitoring Example

```python
import psutil
import time

def monitor_disk(duration=10, interval=2):
    print(f"Monitoring disk for {duration} seconds...\n")
    
    last_io = psutil.disk_io_counters()
    
    for i in range(duration // interval):
        time.sleep(interval)
        
        current_io = psutil.disk_io_counters()
        
        # Calculate rates
        read_rate = (current_io.read_bytes - last_io.read_bytes) / interval / (1024**2)
        write_rate = (current_io.write_bytes - last_io.write_bytes) / interval / (1024**2)
        
        print(f"Time {i+1}:")
        print(f"  Read rate: {read_rate:.2f} MB/s")
        print(f"  Write rate: {write_rate:.2f} MB/s")
        print()
        
        last_io = current_io

monitor_disk(10)
```

---

## Network Functions

### Theory

Network functions provide information about network interfaces and connections. Key concepts:
- **Network Interfaces:** Physical or virtual network adapters
- **Network Stats:** Sent/received packets and bytes
- **Network Connections:** Active connections (sockets)

### Get Network Interface Information

```python
import psutil

# Get all network interfaces
if_addrs = psutil.net_if_addrs()

for interface_name, interface_addrs in if_addrs.items():
    print(f"Interface: {interface_name}")
    for addr in interface_addrs:
        print(f"  Family: {addr.family.name}")
        print(f"  Address: {addr.address}")
        print(f"  Netmask: {addr.netmask}")
        print()

# Example output:
# Interface: lo
#   Family: AF_INET
#   Address: 127.0.0.1
#   Netmask: 255.0.0.0
```

### Get Network Interface Statistics

```python
import psutil

# Get network I/O statistics
net_io = psutil.net_io_counters()
print(f"Bytes sent: {net_io.bytes_sent / (1024**3):.2f} GB")
print(f"Bytes recv: {net_io.bytes_recv / (1024**3):.2f} GB")
print(f"Packets sent: {net_io.packets_sent}")
print(f"Packets recv: {net_io.packets_recv}")
print(f"Errors in: {net_io.errin}")
print(f"Errors out: {net_io.errout}")
print(f"Dropped in: {net_io.dropin}")
print(f"Dropped out: {net_io.dropout}")

# Per-interface statistics
if_stats = psutil.net_io_counters(pernic=True)
for interface, stats in if_stats.items():
    print(f"{interface}: {stats.bytes_sent / (1024**2):.2f} MB sent")
```

### Get Network Connections

```python
import psutil

# Get all network connections
connections = psutil.net_connections()

for conn in connections:
    print(f"File descriptor: {conn.fd}")
    print(f"Family: {conn.family.name}")
    print(f"Type: {conn.type.name}")
    print(f"Local address: {conn.laddr}")
    print(f"Remote address: {conn.raddr}")
    print(f"Status: {conn.status}")
    print(f"PID: {conn.pid}")
    print()

# Example output:
# File descriptor: 3
# Family: AF_INET
# Type: SOCK_STREAM
# Local address: addr(ip='127.0.0.1', port=8000)
# Remote address: addr(ip='127.0.0.1', port=54321)
# Status: ESTABLISHED
# PID: 1234
```

### Network Monitoring Example

```python
import psutil
import time

def monitor_network(duration=10, interval=2):
    print(f"Monitoring network for {duration} seconds...\n")
    
    last_io = psutil.net_io_counters()
    
    for i in range(duration // interval):
        time.sleep(interval)
        
        current_io = psutil.net_io_counters()
        
        # Calculate rates
        sent_rate = (current_io.bytes_sent - last_io.bytes_sent) / interval / (1024**2)
        recv_rate = (current_io.bytes_recv - last_io.bytes_recv) / interval / (1024**2)
        
        print(f"Time {i+1}:")
        print(f"  Upload: {sent_rate:.2f} MB/s")
        print(f"  Download: {recv_rate:.2f} MB/s")
        print()
        
        last_io = current_io

monitor_network(10)
```

### Get Interface Status

```python
import psutil

# Get interface status
if_stats = psutil.net_if_stats()

for interface_name, stats in if_stats.items():
    print(f"Interface: {interface_name}")
    print(f"  Is up: {stats.isup}")
    print(f"  Speed: {stats.speed} Mbps")
    print(f"  MTU: {stats.mtu} bytes")
    print()
```

---

## Process Functions

### Theory

Processes are running instances of programs. Psutil allows monitoring individual processes with details about:
- **Process Information:** PID, name, status
- **Process Resources:** CPU, memory, I/O usage
- **Process Relationships:** Parent, children, threads

### Get Process Information

```python
import psutil
import os

# Get process object
pid = os.getpid()  # Current process
p = psutil.Process(pid)

print(f"PID: {p.pid}")
print(f"Name: {p.name()}")
print(f"Status: {p.status()}")
print(f"Create time: {p.create_time()}")
print(f"Executable: {p.exe()}")
print(f"Command line: {p.cmdline()}")
print(f"CWD: {p.cwd()}")

# Example output:
# PID: 1234
# Name: python
# Status: running
# Create time: 1609459200.0
# Executable: /usr/bin/python3
```

### Get All Running Processes

```python
import psutil

# Get all processes
for proc in psutil.process_iter(['pid', 'name', 'status']):
    try:
        print(f"PID: {proc.info['pid']}, Name: {proc.info['name']}, Status: {proc.info['status']}")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
```

### Get Process CPU Usage

```python
import psutil
import os
import time

# Get current process
p = psutil.Process(os.getpid())

# CPU percent (since last call)
print("First call (no baseline):", p.cpu_percent(interval=None))
time.sleep(1)
print("Second call:", p.cpu_percent(interval=1))

# CPU number
print(f"Running on CPU: {p.cpu_num()}")

# CPU times
cpu_times = p.cpu_times()
print(f"User time: {cpu_times.user}s")
print(f"System time: {cpu_times.system}s")
```

### Get Process Memory Usage

```python
import psutil
import os

# Get current process
p = psutil.Process(os.getpid())

# Memory info
mem_info = p.memory_info()
print(f"RSS (Resident Set Size): {mem_info.rss / (1024**2):.2f} MB")
print(f"VMS (Virtual Memory Size): {mem_info.vms / (1024**2):.2f} MB")

# Memory percent
mem_percent = p.memory_percent()
print(f"Memory percent: {mem_percent}%")

# Memory full info
mem_full = p.memory_full_info()
print(f"USS (Unique Set Size): {mem_full.uss / (1024**2):.2f} MB")
print(f"PSS (Proportional Set Size): {mem_full.pss / (1024**2):.2f} MB")
```

### Get Process I/O Statistics

```python
import psutil
import os

# Get current process
p = psutil.Process(os.getpid())

# I/O counters
io_counters = p.io_counters()
print(f"Read count: {io_counters.read_count}")
print(f"Write count: {io_counters.write_count}")
print(f"Read bytes: {io_counters.read_bytes / (1024**2):.2f} MB")
print(f"Write bytes: {io_counters.write_bytes / (1024**2):.2f} MB")
```

### Get Process Threads and Connections

```python
import psutil
import os

# Get current process
p = psutil.Process(os.getpid())

# Number of threads
num_threads = p.num_threads()
print(f"Number of threads: {num_threads}")

# Thread information
threads = p.threads()
for thread in threads:
    print(f"Thread ID: {thread.id}, User time: {thread.user_time}s, System time: {thread.system_time}s")

# Network connections by process
connections = p.connections()
for conn in connections:
    print(f"Connection: {conn.laddr} -> {conn.raddr} ({conn.status})")
```

### Process Termination

```python
import psutil
import os

# Get process
p = psutil.Process(os.getpid())

# Check if running
if p.is_running():
    print("Process is running")

# Terminate gracefully
# p.terminate()

# Kill forcefully
# p.kill()

# Wait for termination
# p.wait(timeout=3)
```

### Process Monitoring Example

```python
import psutil
import time

def monitor_process(pid, duration=10, interval=1):
    try:
        p = psutil.Process(pid)
        print(f"Monitoring process {pid}: {p.name()}\n")
        
        for i in range(duration):
            cpu = p.cpu_percent(interval=interval)
            mem = p.memory_info()
            
            print(f"Time {i+1}:")
            print(f"  CPU: {cpu}%")
            print(f"  Memory: {mem.rss / (1024**2):.2f} MB")
            print()
    except psutil.NoSuchProcess:
        print(f"Process {pid} not found")

monitor_process(os.getpid(), 5)
```

### Find Process by Name

```python
import psutil

def find_processes_by_name(name):
    """Find all processes by name"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if name.lower() in proc.info['name'].lower():
                processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

# Find Python processes
python_procs = find_processes_by_name("python")
for proc in python_procs:
    print(f"PID: {proc.pid}, Name: {proc.name()}")
```

---

## System Functions

### Theory

System functions provide information about the entire computer system, including boot time, users, and overall statistics.

### Get Boot Time

```python
import psutil
from datetime import datetime

# Get boot time
boot_time = psutil.boot_time()
boot_datetime = datetime.fromtimestamp(boot_time)

print(f"Boot time (timestamp): {boot_time}")
print(f"Boot time (formatted): {boot_datetime}")

# Uptime
uptime_seconds = time.time() - boot_time
uptime_hours = uptime_seconds / 3600
print(f"System uptime: {uptime_hours:.2f} hours")
```

### Get Logged-in Users

```python
import psutil

# Get logged-in users
users = psutil.users()

for user in users:
    print(f"User: {user.name}")
    print(f"Terminal: {user.terminal}")
    print(f"Host: {user.host}")
    print(f"Started: {user.started}")
    print()
```

### Get System Statistics

```python
import psutil

# Get load average
load_avg = psutil.getloadavg()
print(f"Load average: {load_avg}")
print(f"1 minute: {load_avg[0]}")
print(f"5 minutes: {load_avg[1]}")
print(f"15 minutes: {load_avg[2]}")
```

### Comprehensive System Report

```python
import psutil
from datetime import datetime

def system_report():
    print("=" * 50)
    print("SYSTEM REPORT")
    print("=" * 50)
    
    # CPU
    print("\nCPU Information:")
    print(f"  Physical cores: {psutil.cpu_count(logical=False)}")
    print(f"  Logical cores: {psutil.cpu_count(logical=True)}")
    print(f"  Usage: {psutil.cpu_percent(interval=1)}%")
    
    # Memory
    vm = psutil.virtual_memory()
    print("\nMemory Information:")
    print(f"  Total: {vm.total / (1024**3):.2f} GB")
    print(f"  Used: {vm.used / (1024**3):.2f} GB")
    print(f"  Free: {vm.free / (1024**3):.2f} GB")
    print(f"  Usage: {vm.percent}%")
    
    # Disk
    print("\nDisk Information:")
    disk_usage = psutil.disk_usage('/')
    print(f"  Total: {disk_usage.total / (1024**3):.2f} GB")
    print(f"  Used: {disk_usage.used / (1024**3):.2f} GB")
    print(f"  Free: {disk_usage.free / (1024**3):.2f} GB")
    print(f"  Usage: {disk_usage.percent}%")
    
    # Boot Time
    print("\nBoot Information:")
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    print(f"  Boot time: {boot_time}")
    
    # Users
    print("\nActive Users:")
    for user in psutil.users():
        print(f"  {user.name} on {user.terminal}")
    
    print("\n" + "=" * 50)

system_report()
```

---

## Sensors Functions

### Theory

Sensors functions provide access to hardware sensor data like temperature and fan speeds (where available and supported by the OS).

### Get Temperature Information

```python
import psutil

# Get temperature information
temps = psutil.sensors_temperatures()

for name, entries in temps.items():
    print(f"Sensor: {name}")
    for entry in entries:
        print(f"  {entry.label}: {entry.current}°C")
        if entry.high:
            print(f"    High: {entry.high}°C")
        if entry.critical:
            print(f"    Critical: {entry.critical}°C")
    print()
```

### Get Fan Speeds

```python
import psutil

# Get fan speeds
fans = psutil.sensors_fans()

for name, entries in fans.items():
    print(f"Fan Controller: {name}")
    for entry in entries:
        print(f"  {entry.label}: {entry.current} RPM")
    print()
```

### Get Battery Information

```python
import psutil

# Get battery information
battery = psutil.sensors_battery()

if battery:
    print(f"Percent: {battery.percent}%")
    print(f"Time left: {battery.secsleft} seconds")
    print(f"Power plugged in: {battery.power_plugged}")
else:
    print("No battery found")
```

---

## Advanced Examples

### System Monitor Dashboard

```python
import psutil
import time
from datetime import datetime

def system_monitor_dashboard(duration=30, interval=2):
    """Display a live system monitoring dashboard"""
    
    print("Starting System Monitor Dashboard...")
    print("Press Ctrl+C to stop\n")
    
    try:
        last_io = psutil.net_io_counters()
        last_disk = psutil.disk_io_counters()
        
        for i in range(duration // interval):
            # Clear screen (optional)
            # os.system('clear')  # Linux/Mac
            # os.system('cls')    # Windows
            
            print(f"\n{'='*60}")
            print(f"System Status - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*60}")
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_freq = psutil.cpu_freq()
            print(f"\nCPU:")
            print(f"  Usage: {cpu_percent}%")
            print(f"  Frequency: {cpu_freq.current:.0f} MHz")
            
            # Memory
            vm = psutil.virtual_memory()
            print(f"\nMemory:")
            print(f"  Usage: {vm.percent}% ({vm.used / (1024**3):.2f} GB / {vm.total / (1024**3):.2f} GB)")
            
            # Disk
            disk = psutil.disk_usage('/')
            print(f"\nDisk:")
            print(f"  Usage: {disk.percent}% ({disk.used / (1024**3):.2f} GB / {disk.total / (1024**3):.2f} GB)")
            
            # Network
            current_io = psutil.net_io_counters()
            sent_rate = (current_io.bytes_sent - last_io.bytes_sent) / interval / (1024**2)
            recv_rate = (current_io.bytes_recv - last_io.bytes_recv) / interval / (1024**2)
            print(f"\nNetwork:")
            print(f"  Upload: {sent_rate:.2f} MB/s")
            print(f"  Download: {recv_rate:.2f} MB/s")
            
            # Processes
            print(f"\nTop 5 Processes by Memory:")
            for i, proc in enumerate(sorted(psutil.process_iter(['pid', 'name', 'memory_percent']),
                                           key=lambda p: p.info['memory_percent'], reverse=True)[:5]):
                try:
                    print(f"  {i+1}. {proc.info['name'][:30]:30} - {proc.info['memory_percent']:.1f}%")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            last_io = current_io
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped")

system_monitor_dashboard(30, 2)
```

### Process Tracker

```python
import psutil
import time

class ProcessTracker:
    def __init__(self, pid):
        self.pid = pid
        self.process = psutil.Process(pid)
        self.history = {
            'cpu': [],
            'memory': [],
            'io_read': [],
            'io_write': []
        }
    
    def record_metrics(self):
        """Record current metrics"""
        try:
            self.history['cpu'].append(self.process.cpu_percent(interval=0.1))
            self.history['memory'].append(self.process.memory_info().rss / (1024**2))
            
            io = self.process.io_counters()
            self.history['io_read'].append(io.read_bytes / (1024**2))
            self.history['io_write'].append(io.write_bytes / (1024**2))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def get_average_cpu(self):
        return sum(self.history['cpu']) / len(self.history['cpu']) if self.history['cpu'] else 0
    
    def get_average_memory(self):
        return sum(self.history['memory']) / len(self.history['memory']) if self.history['memory'] else 0
    
    def get_statistics(self):
        """Get statistics"""
        print(f"Process: {self.process.name()}")
        print(f"  Average CPU: {self.get_average_cpu():.2f}%")
        print(f"  Average Memory: {self.get_average_memory():.2f} MB")
        print(f"  Peak Memory: {max(self.history['memory']) if self.history['memory'] else 0:.2f} MB")

# Usage
import os
tracker = ProcessTracker(os.getpid())
for i in range(10):
    tracker.record_metrics()
    time.sleep(0.5)

tracker.get_statistics()
```

### Resource Alert System

```python
import psutil
import time

class ResourceAlert:
    def __init__(self, cpu_threshold=80, mem_threshold=80, disk_threshold=90):
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold
        self.disk_threshold = disk_threshold
        self.alerts = []
    
    def check_resources(self):
        """Check system resources and generate alerts"""
        self.alerts = []
        
        # Check CPU
        cpu = psutil.cpu_percent(interval=1)
        if cpu > self.cpu_threshold:
            self.alerts.append(f"HIGH CPU: {cpu}%")
        
        # Check Memory
        vm = psutil.virtual_memory()
        if vm.percent > self.mem_threshold:
            self.alerts.append(f"HIGH MEMORY: {vm.percent}%")
        
        # Check Disk
        disk = psutil.disk_usage('/')
        if disk.percent > self.disk_threshold:
            self.alerts.append(f"HIGH DISK: {disk.percent}%")
        
        return self.alerts
    
    def print_alerts(self):
        """Print current alerts"""
        alerts = self.check_resources()
        if alerts:
            print("⚠️  ALERTS:")
            for alert in alerts:
                print(f"  - {alert}")
        else:
            print("✓ All resources OK")

# Usage
alert_system = ResourceAlert(cpu_threshold=50, mem_threshold=70, disk_threshold=80)
for i in range(5):
    alert_system.print_alerts()
    time.sleep(2)
```

---

## Summary

Psutil provides comprehensive system and process monitoring capabilities. Key takeaways:

1. **CPU Monitoring:** Usage, frequency, cores, and statistics
2. **Memory Tracking:** Virtual memory, swap, and detailed usage
3. **Disk Management:** Partitions, usage, and I/O statistics
4. **Network Monitoring:** Interfaces, statistics, and connections
5. **Process Management:** Information, resources, and monitoring
6. **System Information:** Boot time, users, and overall statistics
7. **Sensors:** Temperature, fans, and battery information

**Best Practices:**
- Use context managers for process handling
- Handle exceptions for permission issues
- Use intervals for meaningful CPU measurements
- Monitor in threads for real-time data
- Cache results to reduce overhead

**Use Cases:**
- System resource monitoring
- Process tracking and management
- Performance optimization
- Alerting systems
- Log analysis and diagnostics

