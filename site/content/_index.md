---
title: "PinTheft — RDS zerocopy double-free LPE tracking"
description: "Linux kernel RDS zerocopy double-free → io_uring page-cache overwrite LPE — distro patch status tracker"
layout: "single"
date: 2026-05-20
lastmod: 2026-06-02
cover:
  image: "pintheft-tracker.png"
  alt: "PinTheft — RDS zerocopy double-free → io_uring page-cache overwrite LPE tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | [`CVE-2026-43494`][cve-mitre] |
| Alias | PinTheft |
| Component | `net/rds/message.c` — RDS zerocopy send path (`rds_message_zcopy_from_user()`, `rds_message_purge()`) |
| Type | Local Privilege Escalation (LPE) — RDS zerocopy double-free turned into an `io_uring` page-cache overwrite |
| CWE | [CWE-415][cwe-415] Double Free |
| CVSS | 7.8 HIGH — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Discoverer | Aaron Esau, [V12 security team][v12] |
| Public disclosure | 2026-05-19 on [oss-security][oss-sec] |
| Public PoC | [v12-security/pocs][upstream-repo] (`pintheft/poc.c`) |
| KEV listed | not yet |
| EPSS | not yet |

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
| Linus mainline | :white_check_mark: Present by 7.1-rc4 | 7.1-rc6 | `44b550d88b26` in 7.1-rc3, `e17492979319` in 7.1-rc4; 7.1 not yet released |
| 7.0.x  | :white_check_mark: Fixed | 7.0.11   | both fixes backported — fix part 1 (`44b550d88b26`, stable `0f5c185fc79a`) first in v7.0.7; fix part 2 (`e17492979319`, stable `290e833d1acb`) first in v7.0.10 |
| 6.19.x | :x: Vulnerable — EOL | 6.19.14 (EOL) | Non-LTS stable; EOL 2026-04-22 — neither fix backported before EOL; users should upgrade to 7.0 |
| 6.18.x | :white_check_mark: Fixed | 6.18.34  | LTS 2028-12 — both fixes backported; fix part 1 (`44b550d88b26`, stable `14ef6fd18db2`) first in v6.18.30; fix part 2 (`e17492979319`, stable `640e37f58f99`) first in v6.18.33 |
| 6.12.x | :white_check_mark: Fixed | 6.12.92  | LTS 2028-12 — both fixes backported; fix part 1 (`44b550d88b26`, stable `3abc8983b2ba`) first in v6.12.88; fix part 2 (`e17492979319`, stable `0bbbff00a15b`) first in v6.12.91 |
| 6.6.x  | :white_check_mark: Fixed | 6.6.142  | LTS 2026-12 — both fixes backported; fix part 1 (`44b550d88b26`, stable `21d70744e6d3`) first in v6.6.140; fix part 2 (`e17492979319`, stable `9115669faedc`) first in v6.6.141 |
| 6.1.x  | :white_check_mark: Fixed | 6.1.175  | LTS 2026-12 — both fixes backported; fix part 1 (`44b550d88b26`, stable `1e262db7675e`) first in v6.1.175; fix part 2 (`e17492979319`, stable `d84ce1786ce4`) first in v6.1.175 |
| 5.15.x | :white_check_mark: Fixed | 5.15.209 | LTS 2026-12 — both fixes backported; fix part 1 (`44b550d88b26`, stable `46662f7dc594`) first in v5.15.209; fix part 2 (`e17492979319`, stable `03014551938a`) first in v5.15.209 |
| 5.10.x | :white_check_mark: Fixed | 5.10.258 | LTS 2026-12 — both fixes backported; fix part 1 (`44b550d88b26`, stable `e9aefdc5c53f`) first in v5.10.258; fix part 2 (`e17492979319`, stable `c6e51512a784`) first in v5.10.258 |

RDS zero-copy Tx support landed in v4.17, so every branch above carries
the vulnerable code.  Both fixes have now backported to all actively
maintained stable branches: 7.0.y, 6.18.y, 6.12.y, 6.6.y, 6.1.y,
5.15.y, and 5.10.y (see Notes column), making all those branches fully
fixed as of their latest point releases.  The 6.19.y branch reached EOL
on 2026-04-22 (v6.19.14) before the fixes were backported — it was a
short-lived non-LTS stable between 6.18 LTS and 7.0 and is no longer
listed on kernel.org.

## Distribution status

A distribution is exploitable only if RDS is built (`=y` or `=m`) **and**
the attacker can reach it.  Where RDS ships as a module, the PoC relies
on the `SO_RDS_TRANSPORT=2` (`RDS_TRANS_TCP`) socket option autoloading
`rds_tcp`; distributions that block unprivileged module autoloading
raise the bar accordingly.

A distro that blocks that autoload by default — via a kernel patch or a
`modprobe.d` drop-in — is marked **mitigated, not fixed**
(:warning:): the double-free is still built and stays exploitable once
`rds` is loaded by other means (an administrator `modprobe`, or a
workload that uses RDS).  A mitigation reduces exposure; it is not a
fix, and it does not earn a :white_check_mark:.

### Debian

Debian ships the RDS subsystem as a module (`CONFIG_RDS=m`,
`CONFIG_RDS_TCP=m`) across all current suites.

| Release | RDS | Status |
|---|---|---|
| Debian 13 (trixie) | `CONFIG_RDS=m` | :white_check_mark: Fixed — linux 6.12.90-2 (trixie-security); [DSA-6305-1][dsa-6305] issued 2026-05-28 |
| Debian 12 (bookworm) | `CONFIG_RDS=m` | :warning: Mitigated, not fixed — kernel patch blocks unprivileged RDS autoload; double-free unpatched |
| Debian 11 (bullseye) | `CONFIG_RDS=m` | :warning: Mitigated, not fixed — kernel patch blocks unprivileged RDS autoload; double-free unpatched |

`CONFIG_RDS=m` on Debian 11 and 13 was confirmed by direct kernel-config
inspection; Debian 12 carries the same long-standing module setting.

Debian carries a long-standing kernel patch
([`rds-Disable-auto-loading-as-mitigation-against-local.patch`][debian-rds-patch],
Ben Hutchings, 2010) that comments out `MODULE_ALIAS_NETPROTO(PF_RDS)`
in `net/rds/af_rds.c`.  With no `net-pf-21` module alias, an
unprivileged `socket(AF_RDS, …)` cannot autoload `rds`, so the PoC's
`SO_RDS_TRANSPORT=2` autoload trigger is closed **by default** — and
more firmly than a `modprobe.d` drop-in, since it is compiled into the
kernel binary.  The patch is present in the kernel `series` of every
tracked suite (`debian/latest` for sid/forky, and the trixie, bookworm,
and bullseye security branches).

[DSA-6305-1][dsa-6305] (2026-05-28) brought a full kernel patch to
trixie with linux 6.12.90-2 (trixie-security pocket); both fix commits
are applied.  Bookworm and bullseye remain unpatched — the double-free
in `net/rds/message.c` is still built and is exploitable on those hosts
once `rds` is loaded by other means (an administrator `modprobe`, or a
workload that uses RDS).  The [Debian security tracker][debian-cve]
lists bookworm and bullseye as vulnerable.

### Proxmox Virtual Environment

Proxmox ships its own `proxmox-kernel` packages built on an
Ubuntu-derived kernel tree.

| Version | RDS | Status |
|---|---|---|
| PVE 9 | `CONFIG_RDS=m` | :white_check_mark: Fixed — [PSA-2026-00022-2][proxmox-advisories] issued 2026-05-29; proxmox-kernel-7.0.2-5-pve (7.0.x) and proxmox-kernel-6.17.13-10-pve (6.17.x) |
| PVE 8 | `CONFIG_RDS=m` | :white_check_mark: Fixed — [PSA-2026-00022-2][proxmox-advisories] issued 2026-05-29; proxmox-kernel-6.8.12-25-pve |

Proxmox acknowledged PinTheft in [PSA-2026-00022-1][proxmox-advisories]
(2026-05-19); [PSA-2026-00022-2][proxmox-advisories] (2026-05-29)
followed with patched kernel packages for PVE 8 and PVE 9.

`CONFIG_RDS=m` on PVE 9 was confirmed by kernel-config inspection, and
PVE 9 ships **no autoload block** — verified on a running host:

- `modinfo` on the `proxmox-kernel` `rds.ko` shows `alias: net-pf-21`
  intact, so the kernel does *not* carry Debian's autoload-disable
  patch.
- `modprobe -c` resolves `net-pf-21` straight to the `rds` module
  with no stock `modprobe.d` drop-in disabling it.

Proxmox takes its *kernel* from Ubuntu but its *userland* from Debian,
so it inherits neither parent's mitigation: Debian's lives in the
kernel source (and Proxmox builds its own kernel), while Ubuntu's
`net-pf-21` blacklist lives in the `kmod` package (and Proxmox ships
Debian's `kmod`).  A stock PVE 9 host therefore autoloads `rds` on
demand for an unprivileged user, exactly like Arch.  PVE 8 is the
same: the `rds.ko` in the `proxmox-kernel-6.8.12-9-pve` package
likewise carries `alias: net-pf-21`, and PVE 8 shares the
Debian-userland / Ubuntu-derived-kernel structure that leaves it without
a `modprobe.d` block.

### NixOS

NixOS builds RDS as a module (`CONFIG_RDS=m`), but an unprivileged
process cannot autoload it: NixOS enables the Ubuntu module blacklist by
default — `boot.modprobeConfig.useUbuntuModuleBlacklist` defaults to
`true` on both `nixos-unstable` and `nixos-25.11` — which installs
`/etc/modprobe.d/ubuntu.conf`.  That file carries Ubuntu's
`blacklist-rare-network.conf`, which includes:

```
# rds
alias net-pf-21 off
```

A `socket(AF_RDS, …)` from an unprivileged process makes the kernel
issue `request_module("net-pf-21")`; the alias resolves `net-pf-21` to
the non-existent module `off`, so `rds` does not autoload.  The PoC's
autoload-driven entry is blocked by default.

| Channel | RDS | Status |
|---|---|---|
| Unstable | `CONFIG_RDS=m` | :white_check_mark: Fixed — `linux_6_18` 6.18.33 (both fixes) pinned since 2026-05-23 |
| 25.11 | `CONFIG_RDS=m` | :white_check_mark: Fixed — `linux_6_12` 6.12.91 (both fixes) pinned since 2026-05-26 |

Both kernel bumps landed in nixpkgs on 2026-05-23; the `nixos-unstable`
channel picked them up the same day, while `nixos-25.11` advanced on
2026-05-26.
The Ubuntu module blacklist
(`boot.modprobeConfig.useUbuntuModuleBlacklist`, default `true`) continues
to ship on both channels as an additional layer of defence-in-depth.
The other modprobe.d files NixOS ships do not affect RDS: `debian.conf`
(Debian module aliases), `systemd.conf` (`bonding` / `dummy` / `ifb`
options), and `firmware.conf` (firmware search path).  `nixos.conf` is
empty unless `boot.blacklistedKernelModules` or `boot.extraModprobeConfig`
is set.

### Rocky Linux

| Release | Kernel series | RDS | Status |
|---|---|---|---|
| Rocky Linux 10 | 6.12.x | `# CONFIG_RDS is not set` | :white_check_mark: Not affected — RDS not built |
| Rocky Linux 9 | 5.14.x | `# CONFIG_RDS is not set` | :white_check_mark: Not affected — RDS not built |
| Rocky Linux 8 | 4.18.x | `# CONFIG_RDS is not set` | :white_check_mark: Not affected — RDS not built |

The RHEL family does not build the RDS subsystem — the kernel config
ships `# CONFIG_RDS is not set`, so the vulnerable code is absent
entirely and no mitigation is required.  All three releases were
confirmed against the Rocky kernel configs in
[git.rockylinux.org][rocky-kernel-config]: branch `r8`
(`SOURCES/kernel-x86_64.config`) and branches `r9` and `r10`
(`SOURCES/kernel-x86_64-rhel.config`).  The same is expected to hold for
RHEL, AlmaLinux, and other RHEL rebuilds, but verify per build if in
doubt.

### Amazon Linux

Amazon builds the RDS subsystem as a loadable module — `CONFIG_RDS=m`,
`CONFIG_RDS_TCP=m` — on every Amazon Linux kernel inspected, with
`CONFIG_IO_URING=y`.

#### Amazon Linux 2023

| Stream | Kernel series | Status |
|---|---|---|
| `kernel` (default) | 6.1.x  | :x: Vulnerable — `CONFIG_RDS=m`; apply the modprobe workaround |
| `kernel6.12` | 6.12.x | :x: Vulnerable — `CONFIG_RDS=m` (Amazon-wide config); apply the modprobe workaround |
| `kernel6.18` | 6.18.x | :x: Vulnerable — `CONFIG_RDS=m`; apply the modprobe workaround |

#### Amazon Linux 2

| Stream | Kernel series | Status |
|---|---|---|
| `kernel` (Core) | 4.14.x | :white_check_mark: Not affected — RDS is `=m`, but 4.14 predates the vulnerable code (see below) |
| `kernel` (5.4 / 5.10 extras) | 5.4.x / 5.10.x | :x: Vulnerable — `CONFIG_RDS=m` (Amazon-wide config); apply the modprobe workaround |
| `kernel` (5.15 extra) | 5.15.x | :x: Vulnerable — `CONFIG_RDS=m`; apply the modprobe workaround |

Confirmed by extracting the kernel build config from Amazon's published
binary kernel RPMs — AL2023 `kernel-6.1.170-213.321` and
`kernel6.18-6.18.25-57.109`, and AL2 `kernel-4.14.355-282.729` (Core)
and `kernel-5.15.204-143.231` (5.15 extra) — all carry `CONFIG_RDS=m`.
The AL2023 `kernel6.12` stream and the AL2 5.4 / 5.10 extras were not
extracted individually; they follow the same Amazon-wide `CONFIG_RDS=m`
policy.

Amazon Linux 2's default **Core** kernel is 4.14, which predates the RDS
zerocopy Tx support (`0cebaccef3ac`, first released in v4.17) and
`io_uring` (v5.1).  RDS is built, but neither PinTheft code path exists —
AL2 Core is not affected.  The AL2 5.x kernels installed via
`amazon-linux-extras` carry both and are exploitable.

### Arch Linux

Arch Linux's stock `linux` kernel ships `CONFIG_RDS=m` /
`CONFIG_RDS_TCP=m` and does **not** blacklist the module, so it
autoloads on demand.  Per V12, Arch is the one common distribution where
PinTheft works out of the box — it is the primary real-world target.

| Release | RDS | Status |
|---|---|---|
| Arch Linux (`linux`) | `CONFIG_RDS=m` | :white_check_mark: Fixed — `linux` 7.0.10.arch1-1 (both fixes) graduated from [testing] to stable (core) on 2026-05-24 |

### Fedora

Fedora builds RDS as a module (`CONFIG_RDS=m`) but ships it in the
separate `kernel-modules-extra` package, which is not installed on
Fedora Cloud Edition by default.  Fedora also ships a `modprobe.d`
drop-in that blacklists the RDS module.  Exploitation therefore requires
both installing `kernel-modules-extra` and overriding the blacklist —
two deliberate administrative actions.

| Release | RDS | Status |
|---|---|---|
| Fedora (current) | `CONFIG_RDS=m`, in `kernel-modules-extra` + blacklisted | :warning: Mitigated, not fixed — module in `kernel-modules-extra` + blacklisted; not reachable in a default install |

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

### NixOS

NixOS manages `/etc/modprobe.d` and `/etc/sysctl.d` declaratively — set
the NixOS options below rather than editing those files (which are
regenerated on every rebuild), then run `nixos-rebuild switch`.  These
are ordinary NixOS options: they belong in `configuration.nix`, or —
with a flake — in any module imported by the host's
`nixosConfigurations.<host>` entry.  The option syntax is identical
either way; only the file the lines live in differs.

Block the RDS modules — this text is appended to
`/etc/modprobe.d/nixos.conf`:

```nix
boot.extraModprobeConfig = ''
  install rds /bin/false
  install rds_tcp /bin/false
'';
```

Harden `io_uring` (defence-in-depth):

```nix
boot.kernel.sysctl."kernel.io_uring_disabled" = 2;
```

NixOS already blocks the unprivileged RDS *autoload* by default (see the
NixOS row under **Distribution status**); the `boot.extraModprobeConfig`
block above additionally defeats an explicit `modprobe rds`.  Neither
option unloads a module that is *already* loaded — reboot, or run
`rmmod rds_tcp rds`, to clear a live one.

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
- **Default exposure:** RDS is rarely *used*, but it is built as a
  loadable module (`CONFIG_RDS=m`) on more distributions than the
  upstream PoC suggests — Debian, Proxmox, NixOS, Arch, Fedora, and
  Amazon Linux all ship it.  RHEL-family kernels (Rocky / RHEL /
  AlmaLinux 8–10) are the exception and do not build it at all.  Real
  exposure then turns on whether an unprivileged user can get the module
  loaded: Arch loads it on demand, whereas Debian (a kernel patch) and
  Fedora and NixOS (a `modprobe.d` blacklist of the `net-pf-21` family)
  block the unprivileged autoload by default.
- **Forensics:** exploitation modifies only the in-memory page cache;
  the on-disk binary is untouched.  Runtime detection (Falco, eBPF) or
  memory forensics is required — file-integrity tooling will miss it.

The in-memory corruption is transient — dropping the page cache clears
it, and a reboot achieves the same:

```bash
echo 1 > /proc/sys/vm/drop_caches
```

## Verification log

*Last verified 2026-06-02.*

### Upstream

- CVE-2026-43494 assigned by the Linux kernel CNA on 2026-05-21,
  announced on [oss-security][oss-sec-cve]; keyed to fix commit
  `e17492979319`.  PUBLISHED state confirmed in the MITRE CVE record,
  NVD, and `vulns.git` (`cve/published/2026/CVE-2026-43494`, published
  2026-05-21); CVSS 3.1 score **7.8 HIGH**
  (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) added to the
  kernel CNA record on 2026-05-29.  The record cites only fix part 2
  (`e17492979319`); both fix commits are required for a complete fix.
- Both fix commits verified against the local `netdev/net.git` and
  `stable/linux.git` clones: `44b550d88b26` first appears in tag
  `v7.1-rc3`, `e17492979319` in `v7.1-rc4`.  Mainline advanced to
  v7.1-rc6 (2026-06-01); both fixes remain present.
- linux-6.19.y confirmed present in the stable clone with latest tag
  v6.19.14 (2026-04-22) — a short-lived non-LTS stable between 6.18 LTS
  and 7.0, now EOL and no longer listed on kernel.org.  Neither
  PinTheft fix was backported to this branch before EOL.
- Both fix commits now backported to all actively maintained stable
  branches.  Fix part 1 (`44b550d88b26`): stable hash `0f5c185fc79a`
  first in v7.0.7, `14ef6fd18db2` first in v6.18.30, `3abc8983b2ba`
  first in v6.12.88, `21d70744e6d3` first in v6.6.140,
  `1e262db7675e` first in v6.1.175, `46662f7dc594` first in v5.15.209,
  `e9aefdc5c53f` first in v5.10.258.  Fix part 2 (`e17492979319`):
  stable hash `290e833d1acb` first in v7.0.10, `640e37f58f99` first in
  v6.18.33, `0bbbff00a15b` first in v6.12.91, `9115669faedc` first in
  v6.6.141, `d84ce1786ce4` first in v6.1.175, `03014551938a` first in
  v5.15.209, `c6e51512a784` first in v5.10.258.  Current point releases:
  7.0.11, 6.18.34, 6.12.92, 6.6.142, 6.1.175, 5.15.209, 5.10.258 — all
  fully fixed.  The CVE-2026-43494 dyad in `vulns.git` has been updated
  to include the 6.1.y, 5.15.y, and 5.10.y branches (via
  `e17492979319` as keyed fix commit).
- Introducing commit `0cebaccef3ac` ("rds: zerocopy Tx support.")
  confirmed first released in v4.17 — every supported stable branch
  contains the vulnerable code.

### Distributions

- **Debian:** `CONFIG_RDS=m` confirmed for Debian 11 and 13 by direct
  kernel-config inspection; Debian 12 carries the same setting.  The
  RDS autoload-disable patch (`MODULE_ALIAS_NETPROTO(PF_RDS)` commented
  out in `net/rds/af_rds.c`) was confirmed present in the kernel patch
  `series` of the `debian/latest` (sid/forky), trixie, bookworm, and
  bullseye branches on Salsa.  [DSA-6305-1][dsa-6305] (2026-05-28)
  fixed trixie with linux 6.12.90-2 (trixie-security pocket); both fix
  patches confirmed via the Debian security tracker.  Bookworm
  (security: 6.1.174-1) and bullseye (security: 5.10.257-1) remain
  unpatched; the Debian security tracker lists them as vulnerable.
- **Proxmox VE:** `CONFIG_RDS=m` confirmed for PVE 9.  Verified on a
  running PVE 9 host (`proxmox-kernel` 6.17.x) that no autoload block is
  present: `modinfo` on `rds.ko` shows `alias: net-pf-21` intact (no
  Debian-style kernel patch), and `modprobe -c` resolves `net-pf-21` to
  `rds` with no stock `modprobe.d` drop-in — a stock PVE 9 host
  autoloads `rds` on demand.  PVE 8 confirmed the same way: `rds.ko`
  extracted from the `proxmox-kernel-6.8.12-9-pve` package (Proxmox
  `bookworm` repo) also carries `alias: net-pf-21`.  Proxmox issued
  [PSA-2026-00022-1][proxmox-advisories] on 2026-05-19 acknowledging
  PinTheft; [PSA-2026-00022-2][proxmox-advisories] (2026-05-29) listed
  the fixed packages: proxmox-kernel-7.0.2-5-pve and
  proxmox-kernel-6.17.13-10-pve for PVE 9, and
  proxmox-kernel-6.8.12-25-pve for PVE 8.
- **NixOS:** both channels now pin fixed kernel versions: `nixos-unstable`
  pins `linux_6_18` 6.18.33 (channel rev `64c08a7ca051`, 2026-05-23;
  both fixes confirmed in upstream 6.18.y branch) and `nixos-25.11` pins
  `linux_6_12` 6.12.91 (channel rev `25f538306313`, 2026-05-26; both
  fixes confirmed in upstream 6.12.y branch).  Kernel versions verified
  via local nixpkgs clone at the respective channel revisions
  (`pkgs/os-specific/linux/kernel/kernels-org.json`).
  `boot.modprobeConfig.useUbuntuModuleBlacklist` default confirmed `true`
  at both revisions in `nixos/modules/system/boot/modprobe.nix`.
- **Rocky Linux:** `# CONFIG_RDS is not set` confirmed for Rocky 8, 9,
  and 10 against the Rocky kernel configs in git.rockylinux.org
  (branches `r8` / `r9` / `r10`) — not affected.
- **Amazon Linux:** kernel build configs extracted from Amazon's
  published binary kernel RPMs (2026-05-20) — `CONFIG_RDS=m` on AL2023
  6.1 and 6.18 and on AL2 4.14 (Core) and 5.15 (extra).  AL2 Core 4.14
  predates the vulnerable code; the AL2023 streams and the AL2 5.x
  extras are vulnerable.  See the Amazon Linux table.
- **Arch Linux:** `linux` 7.0.10.arch1-1 (both fixes — `44b550d88b26`
  and `e17492979319`) graduated from [testing] to stable (core) on
  2026-05-24; confirmed via the Arch packages page (built 2026-05-23,
  last updated 2026-05-24 19:27 UTC).  Status updated to
  `:white_check_mark: Fixed`.  CVE-2026-43494 not yet listed in the
  Arch security tracker.
- **Fedora:** module-availability behaviour per the V12 disclosure and the
  oss-security thread; not independently re-verified.

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
| [Debian RDS autoload-disable patch (Salsa)][debian-rds-patch] | <https://salsa.debian.org/kernel-team/linux/-/blob/debian/6.12/trixie-security/debian/patches/debian/rds-Disable-auto-loading-as-mitigation-against-local.patch> |
| [Rocky Linux kernel dist-git (`r8` / `r9` / `r10`)][rocky-kernel-config] | <https://git.rockylinux.org/staging/rpms/kernel> |
| [stable kernel releases][kernel-releases] | <https://www.kernel.org/category/releases.html> |
| [Proxmox security advisories (PSA-2026-00022-1 — PinTheft)][proxmox-advisories] | <https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/> |
| [CVE-2026-43494 — MITRE CVE Record][cve-mitre] | <https://www.cve.org/CVERecord?id=CVE-2026-43494> |
| [CVE-2026-43494 — NVD record][cve-nvd] | <https://nvd.nist.gov/vuln/detail/CVE-2026-43494> |
| [CVE-2026-43494 — Debian security tracker][debian-cve] | <https://security-tracker.debian.org/tracker/CVE-2026-43494> |
| [DSA-6305-1 — linux security update (2026-05-28)][dsa-6305] | <https://www.debian.org/security/2026/dsa-6305> |
| [oss-security — CVE-2026-43494 assignment (2026-05-21)][oss-sec-cve] | <https://www.openwall.com/lists/oss-security/2026/05/21/2> |
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
[debian-rds-patch]: https://salsa.debian.org/kernel-team/linux/-/blob/debian/6.12/trixie-security/debian/patches/debian/rds-Disable-auto-loading-as-mitigation-against-local.patch
[rocky-kernel-config]: https://git.rockylinux.org/staging/rpms/kernel
[kernel-releases]:  https://www.kernel.org/category/releases.html
[proxmox-advisories]: https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/
[cve-mitre]:        https://www.cve.org/CVERecord?id=CVE-2026-43494
[cve-nvd]:          https://nvd.nist.gov/vuln/detail/CVE-2026-43494
[debian-cve]:       https://security-tracker.debian.org/tracker/CVE-2026-43494
[dsa-6305]:         https://www.debian.org/security/2026/dsa-6305
[oss-sec-cve]:      https://www.openwall.com/lists/oss-security/2026/05/21/2
