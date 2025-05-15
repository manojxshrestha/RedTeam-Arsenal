# Basic Methodology - Password Mutations README

This README explores techniques for generating customized wordlists and potential usernames to enhance password cracking efforts.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Generating Wordlists with Cewl](#generating-wordlists-with-cewl)
- [Mutating Passwords with Hashcat](#mutating-passwords-with-hashcat)
- [Generating Usernames with Username-Anarchy](#generating-usernames-with-username-anarchy)
- [Extracting File Extensions for Password Searches](#extracting-file-extensions-for-password-searches)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Password mutations involve creating tailored wordlists and usernames to improve the efficiency of password cracking attacks. This guide covers using cewl to crawl websites for keywords, hashcat to mutate passwords with custom rules, username-anarchy to generate usernames, and a Linux command chain to extract file extensions for targeted searches.

## Setup and Prerequisites

### Environment:
- Linux host with network access and internet connectivity.

### Tools:
- Install `cewl` (e.g., `gem install cewl`)
- Install `hashcat` (e.g., `apt install hashcat`)
- Install `username-anarchy` (download from its repository)
- `curl`, `html2text`, `awk`, `grep`, and `tee` (typically pre-installed)

### Files:
- `password.list`: Initial password list to mutate
- `inlane.wordlist`: Output wordlist from cewl
- `mut_password.list`: Mutated password list from hashcat
- `listoffirstandlastnames.txt`: Input file for username-anarchy
- `compressed_ext.txt`: Output file for file extensions

### Requirements:
- Internet Access: Required for cewl and curl commands

## Generating Wordlists with Cewl

Create a wordlist based on a website's content.

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

This command uses cewl to crawl https://www.inlanefreight.com to a depth of 4 levels, with a minimum word length of 6, converting to lowercase, and saving to inlane.wordlist (Linux).

**Example Output:**
- `inlane.wordlist` contains words like freight, inlane, login.

## Mutating Passwords with Hashcat

Generate mutated password combinations.

```bash
hashcat --force password.list -r custom.rule --stdout > mut_password.list
```

This command uses hashcat to apply a custom rule (`custom.rule`) to `password.list`, outputting mutated passwords to `mut_password.list` (Linux).

**Example:**
- If `password.list` has "password" and `custom.rule` adds "123", output might include "password123"
- Create `custom.rule` with rules like: `append(123)` or `toggle @case`

## Generating Usernames with Username-Anarchy

Create potential usernames from name lists.

```bash
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```

Uses username-anarchy with an input file `listoffirstandlastnames.txt` (e.g., John Doe) to generate usernames like jdoe, johnd, or doej (Linux).

**Example Input:**
```
listoffirstandlastnames.txt: John Doe
                            Jane Smith
```

**Example Output:**
- jdoe, johndoe, doej, janesmith

## Extracting File Extensions for Password Searches

Download a list of compressed file extensions for targeted searches.

```bash
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "." | tee -a compressed_ext.txt
```

Uses curl to fetch compressed file types, converts to text with html2text, extracts extensions with awk, filters with grep, and appends to compressed_ext.txt (Linux).

**Example Output:**
- `compressed_ext.txt` might contain `.zip`, `.rar`, `.7z`

## Black Hat Mindset

- **Target Specific Content:** Use cewl to build wordlists tailored to the target's website for more effective attacks
- **Mutate Creatively:** Apply custom hashcat rules to generate complex password variations
- **Generate Usernames:** Leverage username-anarchy to create plausible usernames for brute-force attempts
- **Search Smart:** Use extracted file extensions to focus on files likely to contain credentials
- **Stay Silent:** Perform mutations offline to avoid network detection

## Resources

- [Cewl GitHub](https://github.com/digininja/CeWL)
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [Username-Anarchy GitHub](https://github.com/urbanadventurer/username-anarchy)
- [FileInfo Compressed File Types](https://fileinfo.com/filetypes/compressed)

