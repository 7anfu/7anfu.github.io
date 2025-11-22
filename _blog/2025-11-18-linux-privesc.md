---
layout: post
title: "Linux Privilege Escalation: From Low-Privileged User to Root"
category: "Post-Exploitation"
date: 2025-11-18
readTime: "16 min"
tags: [linux, privilege-escalation, kernel, docker, capabilities, suid, privesc]
excerpt: "After gaining initial access to a Linux system with limited privileges, the path to root demands systematic enumeration and exploitation of misconfigurations."
---

# Linux Privilege Escalation: From Low-Privileged User to Root

## The Privilege Model

Linux's privilege model is binary at first glance but nuanced in practice. Root, the user with UID 0, possesses unrestricted access to the entire system. Every other user (UIDs typically 1000 or higher) operates within defined boundaries. A process running as `www-data` (the web server user) cannot read files owned by root with restrictive permissions. It cannot modify system configuration. It cannot directly execute commands as other users.

Yet systems are rarely perfectly isolated. Misconfigurations, legacy permissions, and design choices create bridges between privilege levels. These bridges are what privilege escalation exploits.

The attacker's initial access typically lands at a constrained privilege level. A web vulnerability grants code execution as the web server user. An SSH brute-force success uses a weak user account. A local exploit reaches a low-privileged shell. From this position, root access seems distant. But systematic enumeration often reveals a path forward.

## Enumeration: The Foundation

Before attempting any exploit, comprehensive enumeration is essential. You're searching for misconfigurations, leftover permissions, or outdated software. These are the artifacts of imperfect system administration.

Automated scripts accelerate this process. LinPEAS (Linux Privilege Escalation Awesome Script) examines system state comprehensively: installed software, file permissions, network listeners, scheduled tasks, and more. The script highlights findings with color coding. Red indicates likely escalation vectors.

However, automation misses context. You might see a SUID binary and not recognize its exploitation path. You might find a cron job and not understand its implications. The best approach combines automated enumeration with manual analysis.

Key areas to examine:

**Sudo permissions**: The `sudo -l` command reveals which commands your user can execute as root (or other users) without providing a password. A single misconfigured line can be a complete escalation path.

**SUID binaries**: Files with the setuid bit execute with the owner's privileges, typically root. If a SUID binary contains a vulnerability, exploiting it grants root access.

**File permissions**: Writable files in critical locations (like `/etc/shadow` or `/etc/cron.d/`) can be modified to create escalation paths.

**Kernel version**: Older kernels contain public exploits. Determining the exact version is the first step toward kernel exploitation.

**Running services**: Services executing with elevated privileges might be exploitable if they contain vulnerabilities.

## Sudo Misconfigurations

The `sudo` command permits users to execute commands with elevated privileges, typically root. When configured correctly, it's secure. When misconfigured, it's one of the most direct escalation paths.

### NOPASSWD Bypass

The most obvious misconfiguration allows commands via sudo without a password:

```
user ALL=(ALL) NOPASSWD: /usr/bin/find
```

This line permits the user to run `find` as root without authentication. The attacker then leverages `find`'s capabilities to execute arbitrary commands:

```bash
sudo find . -exec /bin/sh \; -quit
```

The `-exec` option runs commands on found files. `/bin/sh` spawns a shell. The semicolon is a find syntax requirement, `-quit` exits after the first result. The result is a root shell.

GTFOBins, an online database of Unix binaries and their exploitation methods, contains exploitation techniques for hundreds of common utilities. Many common commands (vim, less, python, perl, etc.) have built-in functionality that can execute arbitrary code. When these are available via sudo NOPASSWD, privilege escalation is trivial.

### Wildcard Injection

Some administrators attempt to restrict sudo access by permitting only specific arguments:

```
user ALL=(ALL) NOPASSWD: /usr/bin/tar
```

But they fail to consider argument injection. The attacker crafts arguments that change the tool's behavior:

```bash
sudo tar xf /dev/null --to-command '/bin/sh'
```

Here, `--to-command` isn't restricted. Tar extracts files and pipes them to a command. That command is a shell, and it runs as root.

### Sudo Version Exploits

Older sudo versions contain security vulnerabilities. CVE-2021-3156, known as "Baron Samedit," affects sudo versions before 1.9.5p2. It's a heap-based buffer overflow in the argument parsing code. Exploitation is reliable and grants root access on vulnerable systems.

Checking the sudo version is straightforward:

```bash
sudo --version
```

If the version is vulnerable and matches your target environment, public exploits are available and typically reliable.

## SUID Binaries: Dangerous Permissions

SUID (Set User ID) binaries run with the privileges of their owner, regardless of who executes them. If a binary is owned by root and has the SUID bit set, executing it grants temporary root privileges.

Locating SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
```

The `-perm -4000` matches files with the setuid bit. This search often reveals dozens of binaries. Most are legitimate system tools that require elevated privileges (like `passwd`, which modifies the password database).

However, some are unusual. Custom scripts compiled locally, utilities in non-standard locations, or outdated versions of common tools might contain vulnerabilities or design flaws.

### Exploiting Vulnerable SUID Binaries

A vulnerable SUID binary might:

**Path traversal**: Accept file paths as arguments and operate on files outside intended directories. By manipulating these paths, an attacker reads or writes files as root.

**String format vulnerabilities**: Accept format strings in arguments. Format string bugs allow reading and writing arbitrary memory.

**Command injection**: Execute user-supplied input via shell commands without proper sanitization. Injecting shell metacharacters executes arbitrary code.

**Buffer overflows**: Classic memory safety vulnerabilities. Supplying oversized inputs corrupts memory and hijacks execution flow.

Each type requires different exploitation techniques. The common thread: the SUID privilege elevation is the mechanism, the vulnerability is the method.

## Linux Capabilities: Fine-Grained Privileges

Linux capabilities divide the privileges traditionally granted to root into distinct, independently grantable units. Rather than conferring "all root powers" to a process, administrators assign specific capabilities: `CAP_SETUID` (can change UID), `CAP_DAC_READ_SEARCH` (bypass file read permissions), etc.

This architecture theoretically improves security. A web server process doesn't need every root privilege, it needs specific capabilities related to network binding and file access.

In practice, misconfigurations grant dangerous capabilities to unnecessary binaries.

Finding capabilities:

```bash
getcap -r / 2>/dev/null
```

This recursively checks every file for capabilities. A result like:

```
/usr/bin/python3 = cap_setuid+ep
```

Indicates that python3 has the `setuid` capability. An attacker can invoke Python and use it to change the process UID to 0 (root):

```python
import os
os.setuid(0)
os.system('/bin/bash')
```

The result is a root shell. Python is legitimate software for system administration, but assigning it this capability is dangerous and not unprecedented in misconfigured environments.

Other dangerous capabilities:

- `CAP_DAC_READ_SEARCH`: Bypass file read permissions, accessing `/etc/shadow` or private keys
- `CAP_DAC_OVERRIDE`: Bypass file write permissions, modifying configuration files
- `CAP_NET_ADMIN`: Configure network interfaces, intercept traffic, or inject packets
- `CAP_SYS_ADMIN`: Perform miscellaneous administrative functions, often a catch-all for dangerous operations

## Kernel Exploits: The Nuclear Option

Kernel vulnerabilities are the most powerful but also the most dangerous privilege escalation vector. A successful kernel exploit typically grants immediate root access. However, kernel exploits are unstable. Failed exploitation can crash the system.

The first step is determining the exact kernel version:

```bash
uname -a
cat /proc/version
```

Then searching for public exploits:

```bash
searchsploit "Linux kernel 5.4"
```

Several well-known kernel exploits have become classics:

**Dirty COW (CVE-2016-5195)**: A race condition in the copy-on-write mechanism of the Linux kernel. By carefully timing reads and writes to the same memory page, an attacker can make the kernel overwrite normally read-only memory. This allows modifying SUID binaries or system libraries, granting root access. Affected kernels: 2.6.22 through 4.8.2 (and various stable branches).

**Dirty Pipe (CVE-2022-0847)**: A vulnerability in the pipe buffer mechanism allowing writes to read-only files. Similar in impact to Dirty COW but with a simpler exploitation path.

**PwnKit (CVE-2021-4034)**: A vulnerability in the polkit authentication mechanism, affecting systems with older versions. Requires the specific vulnerable version but is highly reliable when applicable.

Kernel exploits are situation-dependent. They only work on specific kernel versions. Attempting an exploit on a non-vulnerable kernel wastes time or, if you're unlucky, crashes the system.

## Docker Breakout: Container Escape

Some Linux systems are virtualized, actually running inside Docker containers. While containers provide isolation, they're not true VMs. A container with certain configurations can break out to the host.

First, detect the container environment:

```bash
ls -la /.dockerenv
cat /proc/1/cgroup | grep docker
```

If these reveal you're in a container, and if the container is privileged:

```bash
# Test if privileged
ip link add dummy0 type dummy
```

If this succeeds, you're in a privileged container. The next step is straightforward:

```bash
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
```

You've mounted the host filesystem and changed root to it. Now you're running as root on the host.

Alternatively, if the Docker socket (`/var/run/docker.sock`) is mounted:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

This creates a new container with the host filesystem mounted and enters a root shell within it.

## Cron Jobs and Scheduled Tasks

Cron executes commands on a schedule. If a cron job runs a script as root, and that script is world-writable, modifying it grants root code execution.

Examining cron jobs:

```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
```

Look for scripts with permissive permissions:

```bash
ls -la /etc/cron.d/backup.sh
# -rwxrwxrwx 1 root root 256 Nov 20 02:00 backup.sh
```

If writable by your user:

```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /etc/cron.d/backup.sh
```

Wait for the cron job to execute (check the schedule in `/etc/crontab`), then:

```bash
/tmp/rootbash -p
```

The `-p` flag preserves the SUID privilege when spawning the shell.

## Escalation Strategy

Privilege escalation is rarely a single guaranteed path. Systems have multiple vectors, some more reliable than others. Effective enumeration identifies several possible approaches. The attacker selects the most reliable or quickest.

A prioritized approach:

1. **Sudo permissions** (fastest if available, NOPASSWD is immediate root)
2. **SUID binaries** (common misconfiguration, exploitation varies)
3. **File permissions** (if writable system files exist, modification is direct)
4. **Cron jobs** (requires waiting for execution, but reliable)
5. **Capabilities** (less common, but devastating if present)
6. **Kernel exploits** (most reliable technically, but risky and time-consuming)

Each step consumes time. Operators typically focus on the quickest viable path while documenting alternatives for later use.

## Conclusion

Linux privilege escalation is less about exotic techniques and more about systematic enumeration and understanding system architecture. Misconfigurations are ubiquitous. File permissions, software versions, and administrative choices create security boundaries that privilege escalation exploits.

The methodical approach (enumerate, identify vectors, exploit the most reliable) consistently yields results. Tools like LinPEAS accelerate enumeration. Understanding the underlying system allows precise exploitation. Together, they transform a low-privileged shell into root access.
