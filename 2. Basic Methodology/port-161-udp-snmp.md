# Basic Methodology - Port 161 (UDP-SNMP)

This README explores exploiting the Simple Network Management Protocol (SNMP) service on port 161, focusing on enumerating community strings, walking the MIB tree, using enumeration tools, scanning for vulnerabilities, and brute-forcing credentials.

## Table of Contents

- Introduction
- Setup and Prerequisites
- Enumerating Community Strings with Onesixtyone
- Walking the MIB Tree with Snmpwalk
- SNMP Enumeration with Snmp-check
- SNMP Enumeration with Snmpcheck
- Nmap NSE Scripts
- Brute-Force Attacks
- Black Hat Mindset
- Resources

## Introduction

SNMP on port 161 (UDP) is used for managing network devices, often exposing sensitive information through default or weak community strings. This guide covers enumerating community strings, extracting device details via the MIB tree, using enumeration tools, scanning for vulnerabilities with Nmap, and brute-forcing community strings to gain unauthorized access.

## Setup and Prerequisites

### Environment
- Linux host with network access to the target SNMP server.
- Tools: Install `onesixtyone`, `snmpwalk`, `snmp-check`, `snmpcheck`, `nmap`, and `hydra`:
  ```bash
  apt install snmp snmp-mibs-downloader onesixtyone hydra nmap
  ```

### Required Files
- Create `community.txt` with common community strings (e.g., public, private, manager)
- Create `list_of_ips.txt` with target IP addresses
- Prepare a password file (e.g., `password-file.txt`) for brute-forcing

### Target Information
- IP Address: Identify the target IP address (e.g., `<IP address>`)

## Enumerating Community Strings with Onesixtyone

Guess SNMP community strings to gain access.

```bash
onesixtyone -c community.txt -i list_of_ips.txt
```

Example Output:
```
Scanning 1 hosts, 3 communities
192.168.1.100 [public] Software: Linux
192.168.1.100 [private] Software: Linux
```

## Walking the MIB Tree with Snmpwalk

Extract detailed device information via the MIB tree.

```bash
snmpwalk -c <community string> -v1 <IP address>
```

Example:
```bash
snmpwalk -c public -v1 192.168.1.100
```

Output includes system info, interfaces, processes, etc.:
```
SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.15.0-73-generic
SNMPv2-MIB::sysContact.0 = STRING: admin@example.com
```

## SNMP Enumeration with Snmp-check

Perform detailed enumeration of SNMP data.

```bash
snmp-check <IP address>
```

Example Output:
```
[*] System information:
Hostname: router.example.com
Description: Linux router 5.15.0-73-generic
Contact: admin@example.com
```

## SNMP Enumeration with Snmpcheck

Alternative enumeration tool for SNMP.

```bash
snmpcheck -c <community string> -t <IP address>
```

Example:
```bash
snmpcheck -c public -t 192.168.1.100
```

Output includes users, processes, and network details.

## Nmap NSE Scripts

Scan for SNMP vulnerabilities.

List available SNMP scripts:
```bash
ls -la /usr/share/nmap/scripts | grep "snmp"
```

Example usage:
```bash
# Retrieve basic SNMP information (UDP scan)
nmap -p 161 --script snmp-info <IP address> -sU

# Attempt to brute-force community strings
nmap -p 161 --script snmp-brute <IP address> -sU
```

## Brute-Force Attacks

Guess SNMP community strings.

```bash
# Using a custom password file
hydra -P password-file.txt <IP address> snmp

# Using rockyou wordlist with limited threads
hydra -P /usr/share/wordlists/rockyou.txt <IP address> snmp -t 4
```

## Black Hat Mindset

- **Guess Defaults**: Start with common community strings (public, private) to quickly access devices.
- **Extract Sensitive Data**: Use `snmpwalk` or `snmp-check` to gather system details, users, and network configurations.
- **Target Misconfigs**: Exploit devices with default or weak community strings for reconnaissance or privilege escalation.
- **Stay Silent**: Limit brute-force attempts to avoid triggering rate-limiting or logging.

## Resources

- SNMP Protocol
- Onesixtyone GitHub
- Snmpwalk Manual
- Nmap NSE Documentation
- Hydra Manual

