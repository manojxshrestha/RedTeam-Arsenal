# Basic Methodology - Port 5432 (PostgreSQL)

This README provides a methodology for exploiting PostgreSQL database services running on port 5432. The focus is on leveraging password reuse to gain access using the psql client and utilizing Nmap NSE scripts for enumeration and vulnerability scanning.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Accessing PostgreSQL with Password Reuse](#accessing-postgresql-with-password-reuse)
- [Enumerating with Nmap NSE Scripts](#enumerating-with-nmap-nse-scripts)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

PostgreSQL, running on port 5432, is a powerful open-source relational database management system. It is frequently targeted due to weak or reused credentials and misconfigurations that allow unauthorized access. This guide covers connecting to a PostgreSQL server using the psql client by exploiting password reuse and using Nmap NSE scripts to enumerate and identify vulnerabilities.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target PostgreSQL server.

### Tools
- Install the PostgreSQL client (e.g., `sudo apt install postgresql-client` on Debian-based systems).
- Install Nmap with NSE scripts (e.g., `sudo apt install nmap`).

### Requirements
- Target Information: Obtain the target IP address (e.g., `192.168.1.100`).
- Credential Lists: Prepare a list of usernames (e.g., `postgres`, `admin`) and passwords, focusing on commonly reused credentials (e.g., `postgres`, `password123`).

## Accessing PostgreSQL with Password Reuse

Use the psql client to attempt accessing the PostgreSQL server by exploiting reused or weak credentials.

### Command
```bash
psql -h <IP address> -U <username> -d <database>
```

Example:
```bash
psql -h 192.168.1.100 -U postgres -d postgres
```

### Behavior
- Prompts for a password. Enter a reused or guessed password (e.g., `postgres`).
- If credentials are valid, psql connects, providing an interactive SQL prompt (e.g., `postgres=#`).
- If credentials are incorrect, the connection fails with an error (e.g., authentication failed).

### Notes

- The `postgres` user is a common target due to its default superuser privileges and frequent misconfiguration.
- Test credentials reused from other services (e.g., web apps, SSH) or default passwords like `postgres` or blank.
- Use tools like `hydra` or `metasploit` to automate credential guessing if manual attempts fail.
- Specify a database (e.g., `-d postgres`) as PostgreSQL requires a target database for connection.

## Enumerating with Nmap NSE Scripts

Use Nmap NSE scripts to enumerate the PostgreSQL server and identify potential vulnerabilities.

### List Available PostgreSQL NSE Scripts

```bash
ls -la /usr/share/nmap/scripts | grep "pgsql"
```

Example Output:
```
-rw-r--r-- 1 root root  12345 Jan 10 2025 pgsql-brute.nse
```

Lists all PostgreSQL-related NSE scripts available in Nmap (note: `pgsql` is used in Nmap script naming).

### Run Key PostgreSQL NSE Script

Brute-Force Credentials:
```bash
nmap --script pgsql-brute -p 5432 192.168.1.100
```

Attempts to guess credentials using default or provided username/password lists.

Example Output:
```
PORT     STATE SERVICE
5432/tcp open  postgresql
| pgsql-brute:
|   Accounts
|     postgres:password123 - Valid credentials
|_  Statistics: Performed 150 guesses in 10 seconds
```

### Notes

- The `pgsql-brute.nse` script is the primary NSE script for PostgreSQL, focusing on credential guessing.
- Ensure Nmap is updated to include the latest NSE scripts (`nmap --script-updatedb`).
- Use `--script-args` to provide custom username/password lists (e.g., `--script-args userdb=users.txt,passdb=pass.txt`).
- Check for open port 5432 with a basic scan (`nmap -p 5432 192.168.1.100`) before running scripts.

## Black Hat Mindset

To exploit PostgreSQL effectively, think like an attacker:

- **Exploit Password Reuse**: Target credentials reused across services, especially the postgres superuser with default or weak passwords.
- **Enumerate Aggressively**: Use Nmap NSE scripts and manual probes to uncover server details and weak credentials.
- **Maximize Access**: Once inside, query sensitive data (e.g., `SELECT * FROM pg_shadow`) or escalate privileges via misconfigured roles.
- **Evade Detection**: Minimize login attempts and use stealthy enumeration to avoid triggering monitoring or logging.

## Resources

- [PostgreSQL Official Documentation](https://www.postgresql.org/docs/)
- [Nmap NSE Documentation](https://nmap.org/nsedoc/)
- [PostgreSQL Security Best Practices](https://www.postgresql.org/docs/current/security.html)
- [Nmap pgsql-brute Script](https://nmap.org/nsedoc/scripts/pgsql-brute.html)

