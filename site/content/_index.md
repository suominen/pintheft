---
title: "PinTheft — RDS zerocopy double-free LPE tracking"
description: "Linux kernel RDS zerocopy double-free → io_uring page-cache overwrite LPE — distro patch status tracker"
layout: "single"
date: 2026-05-20
lastmod: 2026-05-20
cover:
  image: "pintheft-tracker.png"
  alt: "PinTheft — RDS zerocopy double-free → io_uring page-cache overwrite LPE tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | Not yet assigned — placeholder `CVE-2026-XXXXX` |
| Alias | PinTheft |
| Component | `net/rds/message.c` — RDS zerocopy send path (`rds_message_zcopy_from_user()`, `rds_message_purge()`) |
| Type | Local Privilege Escalation (LPE) — RDS zerocopy double-free turned into an `io_uring` page-cache overwrite |
| CWE | [CWE-415][cwe-415] Double Free |
| CVSS | Not yet scored — no CVE assigned |
| Discoverer | Aaron Esau, [V12 security team][v12] |
| Public disclosure | 2026-05-19 on [oss-security][oss-sec] |
| Public PoC | [v12-security/pocs][upstream-repo] (`pintheft/poc.c`) |
| KEV listed | not yet |
| EPSS | not yet — no CVE assigned |

An unprivileged local user can obtain root on a kernel that exposes the
RDS (Reliable Datagram Sockets) subsystem.  The bug is a reference-count
double-free in the RDS zero-copy send path:

- `rds_message_zcopy_from_user()` pins user pages one at a time.  If a
  later page faults, the error path releases the pages it has already
  pinned — but leaves the scatterlist entries and the `op_nents` count
  live after clearing `op_mmp_znotifier`.  When `rds_message_purge()`
  later runs from `rds_sendmsg()`, its cleanup loop iterates the stale
  `op_nents` and frees the same pages a second time.
- Each failing zero-copy `sendmsg()` therefore steals exactly one
  reference from the first page of the send buffer.

On its own this is a refcount underflow.  The PoC weaponises it with
`io_uring`: it registers an anonymous page as an `io_uring` fixed buffer
(`IORING_REGISTER_BUFFERS`), which adds a `FOLL_PIN` bias of
`GUP_PIN_COUNTING_BIAS` (1024) to the page.  1024 failing RDS zero-copy
sends then drain that bias while `io_uring` still holds the raw
`struct page *`.  The page is freed cleanly, reclaimed as page cache for
a readable SUID-root binary, and the stale fixed-buffer entry is used via
`IORING_OP_READ_FIXED` to overwrite that page cache with a small ELF
payload.  Executing the SUID binary then drops into a root shell.

Because the corruption lands in the host-wide page cache, the on-disk
file is never modified — checksums, `inotify`, `auditd` file watches,
and tripwire-style integrity tools do not detect exploitation.  The
overwrite is transient: dropping the page cache or rebooting clears it.

> :information_source: PinTheft is only exploitable where the RDS
> subsystem is actually reachable.  Kernels built with
> `# CONFIG_RDS is not set` are not affected at all; kernels that ship
> RDS as a module (`CONFIG_RDS=m`) are affected only while the attacker
> can get `rds`/`rds_tcp` loaded — see **Mitigation** and the per-distro
> notes below.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`0cebaccef3ac`][rds-introduced] | Introduced | `rds: zerocopy Tx support.` — Sowmini Varadhan, 2018-02-15; first released in **v4.17** |
| [`44b550d88b26`][fix-1] | Fix (part 1) | `net/rds: handle zerocopy send cleanup before the message is queued` — uses `op_mmp_znotifier` as the cleanup discriminator; mainline **v7.1-rc3**, merged 2026-05-05; carries `Cc: stable` |
| [`e17492979319`][fix-2] | Fix (part 2) | `net/rds: reset op_nents when zerocopy page pin fails` — clears the stale `op_nents` directly; mainline **v7.1-rc4**, merged 2026-05-11 |

Both fixes name the same introducing commit in their `Fixes:` tag
(`0cebaccef3ac "rds: zerocopy Tx support."`).  The effective lifetime of
the bug is therefore about **8 years** (2018–2026): every supported
stable branch contains the vulnerable code.

The complete fix is **both** commits.  `44b550d88b26` restructures the
early-failure cleanup and is the one carrying `Cc: stable`, so it is the
commit expected to flow into the stable trees; `e17492979319` is a
smaller follow-up correctness fix.  A distro backport should include
both — verifying only the presence of `44b550d88b26` is insufficient.

## Upstream fixed versions

| Branch | Status | Current | Notes |
|---|---|---|---|
| Linus mainline | :white_check_mark: Present by 7.1-rc4 | 7.1-rc4 | `44b550d88b26` in 7.1-rc3, `e17492979319` in 7.1-rc4; 7.1 not yet released |
| 7.0.x  | :x: Vulnerable | 7.0.9    | no backport yet |
| 6.18.x | :x: Vulnerable | 6.18.32  | LTS 2028-12 — backport expected (`Cc: stable`) |
| 6.12.x | :x: Vulnerable | 6.12.90  | LTS 2028-12 — backport expected (`Cc: stable`) |
| 6.6.x  | :x: Vulnerable | 6.6.140  | LTS 2026-12 — backport expected (`Cc: stable`) |
| 6.1.x  | :x: Vulnerable | 6.1.173  | LTS 2026-12 — backport expected (`Cc: stable`) |
| 5.15.x | :x: Vulnerable | 5.15.207 | LTS 2026-12 — backport expected (`Cc: stable`) |
| 5.10.x | :x: Vulnerable | 5.10.256 | LTS 2026-12 — backport expected (`Cc: stable`) |

RDS zero-copy Tx support landed in v4.17, so every branch above carries
the vulnerable code.  As of 2026-05-20 neither fix commit has appeared
in a stable point release — the disclosure is one day old.  `44b550d88b26`
carries `Cc: stable@kernel.org`, so backports across the active branches
are expected to follow in the next round of stable releases.

## Distribution status

A distribution is exploitable only if RDS is built (`=y` or `=m`) **and**
the attacker can reach it.  Where RDS ships as a module, the PoC relies
on the `SO_RDS_TRANSPORT=2` (`RDS_TRANS_TCP`) socket option autoloading
`rds_tcp`; distributions that block unprivileged module autoloading
raise the bar accordingly.

### Debian

Debian ships the RDS subsystem as a module (`CONFIG_RDS=m`,
`CONFIG_RDS_TCP=m`) across all current suites.

| Release | RDS | Status |
|---|---|---|
| Debian 13 (trixie) | `CONFIG_RDS=m` | :x: Vulnerable — no fixed kernel yet; apply the modprobe workaround |
| Debian 12 (bookworm) | `CONFIG_RDS=m` | :x: Vulnerable — no fixed kernel yet; apply the modprobe workaround |
| Debian 11 (bullseye) | `CONFIG_RDS=m` | :x: Vulnerable — no fixed kernel yet; apply the modprobe workaround |

`CONFIG_RDS=m` on Debian 11 and 13 was confirmed by direct kernel-config
inspection; Debian 12 carries the same long-standing module setting.

Debian additionally carries a kernel patch that disables on-demand
autoloading of the RDS protocol family for unprivileged users, which
blunts the PoC's `SO_RDS_TRANSPORT=2` autoload trigger.  That is a
hardening measure, not a fix for the double-free — treat it as
defence-in-depth and still apply the modprobe blacklist.  No DSA/DLA has
been issued for PinTheft as of 2026-05-20.

### Proxmox Virtual Environment

Proxmox ships its own `proxmox-kernel` packages built on an
Ubuntu-derived kernel tree.

| Version | RDS | Status |
|---|---|---|
| PVE 9 | `CONFIG_RDS=m` | :x: Vulnerable — no fixed kernel yet; apply the modprobe workaround |
| PVE 8 | `CONFIG_RDS=m` (expected) | :grey_question: Unverified — kernel config not yet inspected |

`CONFIG_RDS=m` on PVE 9 was confirmed by kernel-config inspection.  The
Ubuntu kernel base also blacklists the RDS protocol family
(`net-pf-21`) via a `modprobe.d` drop-in shipped in the `kmod` package;
confirm whether the Proxmox kernel packaging carries that drop-in before
relying on it, and apply the modprobe blacklist regardless.

### NixOS

NixOS ships RDS as a module (`CONFIG_RDS=m`) and does not blacklist it,
so the module autoloads on demand — a NixOS host with RDS available is
fully exposed until patched.

| Channel | RDS | Status |
|---|---|---|
| `nixos-unstable` | `CONFIG_RDS=m` | :x: Vulnerable — no fixed kernel yet; apply the modprobe workaround |
| `nixos-25.11` | `CONFIG_RDS=m` (expected) | :x: Vulnerable (likely) — `nixos-unstable` confirmed; 25.11 shares the kernel config |

### Rocky Linux

| Release | Kernel series | RDS | Status |
|---|---|---|---|
| Rocky Linux 10 | 6.12.x | `# CONFIG_RDS is not set` | :white_check_mark: Not affected — RDS not built |
| Rocky Linux 9 | 5.14.x | `# CONFIG_RDS is not set` | :white_check_mark: Not affected — RDS not built |
| Rocky Linux 8 | 4.18.x | `# CONFIG_RDS is not set` | :white_check_mark: Not affected — RDS not built |

The RHEL family does not build the RDS subsystem — the kernel config
ships `# CONFIG_RDS is not set`, so the vulnerable code is absent
entirely and no mitigation is required.  Rocky 8 and 9 were confirmed by
the user from installed kernels; Rocky 10 was confirmed against the
Rocky `r10` kernel config in [git.rockylinux.org][rocky-r10-config]
(`SOURCES/kernel-x86_64-rhel.config`).  The same is expected to hold for
RHEL, AlmaLinux, and other RHEL rebuilds, but verify per build if in
doubt.

### Amazon Linux

| Release | RDS | Status |
|---|---|---|
| Amazon Linux 2023 | unknown | :grey_question: Unverified — kernel config not yet inspected |
| Amazon Linux 2 | unknown | :grey_question: Unverified — kernel config not yet inspected |

No authoritative published kernel config for the Amazon Linux kernels
was located while drafting this tracker.  CIS benchmarks for Amazon
Linux include an "ensure the `rds` kernel module is not available"
control, which hints that RDS may be built as a module — but that is not
confirmation.  Check directly on a running instance:

```bash
grep -E 'CONFIG_RDS\b|CONFIG_RDS_TCP|CONFIG_IO_URING' /boot/config-$(uname -r)
```

### Arch Linux

Arch Linux's stock `linux` kernel ships `CONFIG_RDS=m` /
`CONFIG_RDS_TCP=m` and does **not** blacklist the module, so it
autoloads on demand.  Per V12, Arch is the one common distribution where
PinTheft works out of the box — it is the primary real-world target.

| Release | RDS | Status |
|---|---|---|
| Arch Linux (`linux`) | `CONFIG_RDS=m` | :x: Vulnerable — no fixed kernel yet; apply the modprobe workaround |

### Fedora

Fedora builds RDS as a module (`CONFIG_RDS=m`) but ships it in the
separate `kernel-modules-extra` package, which is not installed on
Fedora Cloud Edition by default.  Fedora also ships a `modprobe.d`
drop-in that blacklists the RDS module.  Exploitation therefore requires
both installing `kernel-modules-extra` and overriding the blacklist —
two deliberate administrative actions.

| Release | RDS | Status |
|---|---|---|
| Fedora (current) | `CONFIG_RDS=m`, in `kernel-modules-extra` + blacklisted | :white_check_mark: Low exposure — vulnerable code present but not reachable in a default install |

Source: Jelle van der Waa, [oss-security][oss-sec-fedora].  This is
defence-in-depth, not a fix — a Fedora host that has installed
`kernel-modules-extra` and removed the blacklist is vulnerable until the
kernel is patched.

## Detection

### Check whether RDS is built, and how

```bash
lsmod | grep -E '^(rds|rds_tcp|rds_rdma) '
```

If the output is empty, check whether the kernel was built with RDS at
all:

```bash
grep -E 'CONFIG_RDS\b|CONFIG_RDS_TCP|CONFIG_IO_URING' /boot/config-$(uname -r)
```

Interpret the output:

- `# CONFIG_RDS is not set` → RDS is not built — the kernel is **not
  affected** regardless of `io_uring`.
- `CONFIG_RDS=m` → loadable module — affected; the modprobe blacklist
  works.  Check whether the module is currently loaded with `lsmod`.
- `CONFIG_RDS=y` → built in — affected and the module cannot be
  unloaded; the modprobe blacklist will not help.
- `CONFIG_IO_URING=y` is the exploit's second ingredient.  The PoC also
  needs `io_uring_disabled=0` (the default on most distributions).

Fallback if `/boot/config-*` is unreadable and `CONFIG_IKCONFIG_PROC=y`:

```bash
zgrep -E 'CONFIG_RDS\b|CONFIG_RDS_TCP|CONFIG_IO_URING' /proc/config.gz
```

### Public PoC

The upstream PoC is in [v12-security/pocs][upstream-repo]
(`pintheft/poc.c`):

```bash
git clone https://github.com/v12-security/pocs.git
cd pocs/pintheft
gcc -o exp poc.c
./exp
```

Do **not** run this on a system you are not authorised to test.  The
exploit overwrites the page cache of a readable SUID-root binary
(`/usr/bin/su`, `/usr/bin/mount`, `/usr/bin/passwd`, `/usr/bin/pkexec`,
…) with an ELF payload.  It backs up the on-disk binary first and prints
a restore command, but a corrupted SUID binary served from cache is
dangerous until the cache is dropped or the host is rebooted.

## Mitigation

### Modprobe blacklist (when RDS is a loadable module)

Following the upstream README, block the RDS modules and remove them if
loaded:

```bash
printf 'install rds /bin/false\ninstall rds_tcp /bin/false\n' > /etc/modprobe.d/pintheft.conf
```

```bash
rmmod rds_tcp rds 2>/dev/null || true
```

Verify:

```bash
lsmod | grep -E '^(rds|rds_tcp) ' && echo "STILL LOADED" || echo "Not loaded"
```

**What this breaks:** any application that uses AF_RDS sockets — RDS is
used mainly by Oracle Database / Oracle RAC interconnects and some HPC
workloads.  Ordinary servers, desktops, and containers do not use RDS.

### io_uring hardening (defence-in-depth)

The page-cache overwrite step depends on `io_uring` fixed buffers.
Disabling `io_uring` blocks the demonstrated exploit chain, though it
does not fix the RDS double-free itself:

```bash
sysctl -w kernel.io_uring_disabled=2
```

Persist it via `/etc/sysctl.d/`.  `io_uring_disabled=2` disables
`io_uring` for all processes; value `1` restricts it to processes with
`CAP_SYS_ADMIN`.  Treat the RDS modprobe blacklist as the primary
mitigation and `io_uring` hardening as a secondary layer.

### Built-in RDS (`CONFIG_RDS=y`)

If RDS is compiled in rather than modular, neither `rmmod` nor the
modprobe blacklist help.  No mainstream distribution builds RDS in;
if a custom kernel does, the only options are rebuilding without
`CONFIG_RDS` or disabling `io_uring` as above, until a patched kernel
is available.

## Risk notes

- **Container hosts:** the page cache is host-wide, so a container with
  RDS reachable can overwrite a SUID binary on the host.  Apply the
  mitigation before running untrusted workloads on shared-kernel
  deployments (Docker, Kubernetes without microVM/gVisor isolation).
- **CI/CD runners:** self-hosted GitHub Actions, GitLab Runners, and
  Jenkins agents that execute untrusted code are directly in scope on
  affected kernels.
- **Default exposure is narrow:** RDS is rare.  Among common
  distributions only Arch Linux loads it readily; RHEL-family kernels do
  not build it at all.  The risk concentrates on Arch hosts and on any
  system where an administrator has loaded RDS deliberately.
- **Forensics:** exploitation modifies only the in-memory page cache;
  the on-disk binary is untouched.  Runtime detection (Falco, eBPF) or
  memory forensics is required — file-integrity tooling will miss it.

The in-memory corruption is transient — dropping the page cache clears
it, and a reboot achieves the same:

```bash
echo 1 > /proc/sys/vm/drop_caches
```

## Verification log

*Last verified 2026-05-20.*

### Upstream

- Both fix commits verified against the local `netdev/net.git` and
  `stable/linux.git` clones: `44b550d88b26` first appears in tag
  `v7.1-rc3`, `e17492979319` in `v7.1-rc4`.  Neither is present in any
  `linux-*.y` stable branch yet.
- Introducing commit `0cebaccef3ac` ("rds: zerocopy Tx support.")
  confirmed first released in v4.17 — every supported stable branch
  contains the vulnerable code.

### Distributions

- **Debian:** `CONFIG_RDS=m` confirmed for Debian 11 and 13 by direct
  kernel-config inspection; Debian 12 carries the same setting.  No
  DSA/DLA issued for PinTheft as of 2026-05-20.
- **Proxmox VE:** `CONFIG_RDS=m` confirmed for PVE 9; PVE 8 not yet
  inspected.
- **NixOS:** `CONFIG_RDS=m` confirmed for `nixos-unstable`; `nixos-25.11`
  shares the kernel config and is treated as vulnerable pending direct
  confirmation.
- **Rocky Linux:** `# CONFIG_RDS is not set` confirmed for Rocky 8 and 9
  (installed kernels) and Rocky 10 (the `r10` kernel config in
  git.rockylinux.org) — not affected.
- **Amazon Linux:** AL2023 and AL2 kernel configs not yet located —
  status unverified.
- **Arch Linux / Fedora:** module-availability behaviour per the V12
  disclosure and the oss-security thread; not independently re-verified.

## References

| Source | URL |
|---|---|
| [Public PoC — v12-security/pocs (pintheft)][upstream-repo] | <https://github.com/v12-security/pocs/tree/09e835b587bf71249775654061ae4c79e92cf430/pintheft> |
| [V12 security team][v12] | <https://v12.sh> |
| [oss-security — PinTheft Linux LPE (2026-05-19)][oss-sec] | <https://www.openwall.com/lists/oss-security/2026/05/19/6> |
| [oss-security — Fedora mitigation reply][oss-sec-fedora] | <https://seclists.org/oss-sec/2026/q2/609> |
| [CWE-415 — Double Free][cwe-415] | <https://cwe.mitre.org/data/definitions/415.html> |
| [Fix part 1 — netdev patch (Nan Li et al.)][fix-1-patch] | <https://lore.kernel.org/netdev/d2ea98a6313d5467bac00f7c9fef8c7acddb9258.1777550074.git.tonanli66@gmail.com/> |
| [Fix part 2 — netdev patch (Allison Henderson)][fix-2-patch] | <https://lore.kernel.org/netdev/20260505234336.2132721-1-achender@kernel.org/> |
| [Fix commit `44b550d88b26` (Linus tree)][fix-1] | <https://git.kernel.org/linus/44b550d88b267320459d518c0743a241ab2108fa> |
| [Fix commit `e17492979319` (Linus tree)][fix-2] | <https://git.kernel.org/linus/e174929793195e0cd6a4adb0cad731b39f9019b4> |
| [Introducing commit `0cebaccef3ac` (Linus tree)][rds-introduced] | <https://git.kernel.org/linus/0cebaccef3acbdfbc2d85880a2efb765d2f4e2e3> |
| [Rocky Linux `r10` kernel config][rocky-r10-config] | <https://git.rockylinux.org/staging/rpms/kernel/-/blob/r10/SOURCES/kernel-x86_64-rhel.config> |
| [stable kernel releases][kernel-releases] | <https://www.kernel.org/category/releases.html> |
{.references}

[upstream-repo]:    https://github.com/v12-security/pocs/tree/09e835b587bf71249775654061ae4c79e92cf430/pintheft
[v12]:              https://v12.sh
[oss-sec]:          https://www.openwall.com/lists/oss-security/2026/05/19/6
[oss-sec-fedora]:   https://seclists.org/oss-sec/2026/q2/609
[cwe-415]:          https://cwe.mitre.org/data/definitions/415.html
[fix-1]:            https://git.kernel.org/linus/44b550d88b267320459d518c0743a241ab2108fa
[fix-2]:            https://git.kernel.org/linus/e174929793195e0cd6a4adb0cad731b39f9019b4
[fix-1-patch]:      https://lore.kernel.org/netdev/d2ea98a6313d5467bac00f7c9fef8c7acddb9258.1777550074.git.tonanli66@gmail.com/
[fix-2-patch]:      https://lore.kernel.org/netdev/20260505234336.2132721-1-achender@kernel.org/
[rds-introduced]:   https://git.kernel.org/linus/0cebaccef3acbdfbc2d85880a2efb765d2f4e2e3
[rocky-r10-config]: https://git.rockylinux.org/staging/rpms/kernel/-/blob/r10/SOURCES/kernel-x86_64-rhel.config
[kernel-releases]:  https://www.kernel.org/category/releases.html
