# Basic Methodology - Port 3306 (MYSQL)

This README provides a methodology for exploiting MySQL database services running on port 3306. The focus is on leveraging password reuse to gain access using the mysql client and utilizing Nmap NSE scripts for enumeration and vulnerability scanning.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Accessing MySQL with Password Reuse](#accessing-mysql-with-password-reuse)
- [Enumerating with Nmap NSE Scripts](#enumerating-with-nmap-nse-scripts)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

MySQL, running on port 3306, is a popular open-source relational database management system. It is often targeted due to weak or reused credentials and misconfigurations that allow unauthorized access. This guide covers connecting to a MySQL server using the mysql client by exploiting password reuse and using Nmap NSE scripts to enumerate and identify vulnerabilities.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target MySQL server.

### Tools
- Install the MySQL client (e.g., `sudo apt install mysql-client` on Debian-based systems).
- Install Nmap with NSE scripts (e.g., `sudo apt install nmap` on Kali Linux).

### Requirements
- Target Information: Obtain the target IP address (e.g., 192.168.1.100).
- Credential Lists: Prepare a list of usernames (e.g., root, admin) and passwords, focusing on commonly reused credentials (e.g., password, admin123).

## Accessing MySQL with Password Reuse

Use the mysql client to attempt accessing the MySQL server by exploiting reused or weak credentials.

### Command
```bash
mysql -h <IP address> -u <username> -p
```

Example:
```bash
mysql -h 192.168.1.100 -u root -p
```

### Behavior
- Prompts for a password. Enter a reused or guessed password (e.g., password).
- If credentials are valid, the mysql client connects, providing an interactive SQL prompt (e.g., `mysql>`).
- If credentials are incorrect, the connection fails with an error (e.g., Access denied).

### Notes
- The root account is a common target due to its high privileges and frequent misconfiguration (e.g., empty or default passwords).
- Test credentials reused from other services (e.g., web apps, SSH) or default passwords.
- Use tools like hydra or metasploit to automate credential guessing if manual attempts fail.

## Enumerating with Nmap NSE Scripts

Use Nmap NSE scripts to enumerate the MySQL server and identify potential vulnerabilities.

### List Available MySQL NSE Scripts

```bash
ls -la /usr/share/nmap/scripts | grep "mysql"
```

Example Output:
```
-rw-r--r-- 1 root root  12345 Jan 10 2025 mysql-audit.nse
-rw-r--r-- 1 root root  23456 Jan 10 2025 mysql-brute.nse
-rw-r--r-- 1 root root  34567 Jan 10 2025 mysql-databases.nse
-rw-r--r-- 1 root root  45678 Jan 10 2025 mysql-empty-password.nse
-rw-r--r-- 1 root root  56789 Jan 10 2025 mysql-enum.nse
-rw-r--r-- 1 root root  67890 Jan 10 2025 mysql-info.nse
-rw-r--r-- 1 root root  78901 Jan 10 2025 mysql-variables.nse
-rw-r--r-- 1 root root  89012 Jan 10 2025 mysql-vuln-cve2012-2122.nse
```

Lists all MySQL-related NSE scripts available in Nmap.

### Run Key MySQL NSE Scripts

#### Gather MySQL Information
```bash
nmap --script mysql-info -p 3306 192.168.1.100
```
Retrieves server version, protocol, and configuration details.

#### Check for Empty Passwords
```bash
nmap --script mysql-empty-password -p 3306 192.168.1.100
```
Tests if the root account or others have no password.

#### Brute-Force Credentials
```bash
nmap --script mysql-brute -p 3306 192.168.1.100
```
Attempts to guess credentials using default or provided username/password lists.

#### Enumerate Databases
```bash
nmap --script mysql-databases --script-args mysqluser=root,mysqlpass=password -p 3306 192.168.1.100
```
Lists accessible databases if credentials are valid.

### Notes
- Ensure Nmap is updated to include the latest NSE scripts (`nmap --script-updatedb`).
- Use `--script-args` to provide credentials or custom wordlists for brute-forcing.
- Combine multiple scripts (e.g., `mysql-info,mysql-brute,mysql-empty-password`) for comprehensive enumeration.

## Black Hat Mindset

To exploit MySQL effectively, think like an attacker:

- **Exploit Password Reuse**: Target credentials reused across services, especially the root account with default or weak passwords.
- **Enumerate Aggressively**: Use Nmap NSE scripts to uncover server details, weak credentials, and vulnerabilities.
- **Maximize Access**: Once inside, dump sensitive data (e.g., `SELECT * FROM mysql.user`) or escalate privileges via misconfigured permissions.
- **Evade Detection**: Minimize login attempts and use stealthy NSE scripts to avoid triggering monitoring or logging.

## Resources

- [MySQL Official Documentation](https://dev.mysql.com/doc/)
- [Nmap NSE Documentation](https://nmap.org/nsedoc/)
- [MySQL Security Best Practices](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [Nmap MySQL Scripts](https://nmap.org/nsedoc/scripts/)

