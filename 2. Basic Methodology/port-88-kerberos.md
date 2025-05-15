# Basic Methodology - Port 88 (Kerberos)

This README explores exploiting the Kerberos authentication service on port 88, with a focus on identifying Windows Domain Controllers and checking for the MS14-068 vulnerability.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Identifying Domain Controllers](#identifying-domain-controllers)
- [Checking MS14-068 Vulnerability](#checking-ms14-068-vulnerability)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Kerberos on port 88 is the default authentication protocol for Windows Active Directory, commonly hosted on Domain Controllers. The MS14-068 vulnerability (CVE-2014-6324) in Kerberos allows privilege escalation if the Domain Controller is unpatched. This guide covers identifying Domain Controllers and assessing them for this exploit.

## Setup and Prerequisites

- **Environment**: Linux or Windows host with network access to the target Domain Controller.
- **Tools**: Install nmap, Python, and download the MS14-068 exploit from its repository.
- **IP Address**: Identify the target IP address (e.g., `<IP address>`) with port 88 open.
- **Dependencies**: Ensure Python libraries (e.g., `pyasn1`) are available for the MS14-068 script.
- **Credentials**: Compromised user credentials or hashes may be needed for exploitation.

## Identifying Domain Controllers

Detect systems running Kerberos, likely Domain Controllers.

```bash
$ nmap -p 88 <IP address>
```

This command uses nmap to scan port 88 and confirm Kerberos service. A response indicates a potential Domain Controller (Linux/Windows).

**Observation**: If port 88 is open, it's a strong indicator of a Windows Domain Controller, as Kerberos is integral to Active Directory.

## Checking MS14-068 Vulnerability

Test for the MS14-068 Kerberos privilege escalation vulnerability.

**Exploit Source**: The MS14-068 exploit is available at a repository containing Python scripts to exploit this vulnerability.

### Usage:

1. Download the exploit: Clone the repository and navigate to the MS14-068 directory.
2. Run the script:

```bash
python ms14-068.py -u <username>@<domain> -p <password> -s <userSID> -d <DC_IP>
```

**Example**:
```bash
python ms14-068.py -u hx@demo.com -p pwd_of_hx -s S-1-5-21-3813283032-1038476579-1047458262-1110 -d DCwin03.demo.com
```

This script attempts to generate a Kerberos ticket with elevated privileges by exploiting a flaw in Kerberos checksum validation.

### Requirements:

- Valid domain credentials (`-u` and `-p` or `-rc4` for NTLM hash)
- User SID (`-s`) obtainable via tools like Get-DomainUser from PowerView
- Domain Controller IP (`-d`)

**Outcome**: If successful, it creates a ticket granting ticket (TGT) for the specified user with elevated group memberships, which can be used with tools like mimikatz for further exploitation.

## Black Hat Mindset

- **Target Domain Controllers**: Focus on port 88 to pinpoint unpatched Windows Domain Controllers.
- **Exploit MS14-068**: Use the vulnerability to escalate from a low-privileged user to a higher-privileged account.
- **Stealthy Escalation**: Leverage Kerberos tickets to move laterally without triggering typical detection mechanisms.
- **Validate Patches**: Assume unpatched systems unless proven otherwise, as MS14-068 was a critical issue.

## Resources

- Kerberos Protocol
- MS14-068 Details
- Nmap Documentation
- Active Directory Exploitation

