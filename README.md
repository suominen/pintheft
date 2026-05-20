# PinTheft — RDS zerocopy double-free LPE tracking site

Patch-status tracker for **PinTheft**, a Linux kernel local privilege
escalation: an RDS (Reliable Datagram Sockets) zero-copy double-free in
`net/rds/message.c`, turned into a page-cache overwrite of a SUID-root
binary via `io_uring` fixed buffers.  Discovered by
[Aaron Esau](https://v12.sh) of the V12 security team and
[disclosed on oss-security on 2026-05-19](https://www.openwall.com/lists/oss-security/2026/05/19/6).
Public PoC: <https://github.com/v12-security/pocs/tree/main/pintheft>.

No CVE has been assigned yet; the tracker uses the placeholder
`CVE-2026-XXXXX`.

The rendered site is published at **<https://kimmo.cloud/pintheft/>**.
Deployment plan and current setup state live in [`WEBSITE.md`](WEBSITE.md).

## Source of truth

The tracker is a single Hugo page: [`site/content/_index.md`](site/content/_index.md).
Edit that file; everything else is build infrastructure.

## Local development

Requires Hugo extended (≥ 0.146.0) and Go (for Hugo Modules to fetch the
PaperMod theme).

### With Nix (recommended)

```sh
nix develop          # shell with hugo + go + git
cd site
hugo server          # local preview at http://localhost:1313/pintheft/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the
dev shell auto-activates whenever you `cd` into the repo.

### Without Nix

Install Hugo extended ≥ 0.146.0 and Go ≥ 1.24 yourself, then:

```sh
cd site
hugo server          # http://localhost:1313/pintheft/
```

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:.www/sites/kimmo.cloud/htdocs/pintheft/
```

`make dist` runs `make build` first.

## Repo layout

```
.
├── flake.nix              # Nix dev environment (hugo + go + git)
├── .envrc                 # direnv hook → `use flake`
├── .gitignore
├── Makefile               # `make build`, `make dist`
├── LICENSE                # CC BY 4.0
├── README.md              # this file
├── CLAUDE.md              # project instructions for Claude Code
├── WEBSITE.md             # publication plan / decisions log
├── scripts/               # auto-update agent: prompt + driver
├── systemd/               # user-level timer + service units
└── site/                  # Hugo project
    ├── hugo.toml
    ├── content/
    │   └── _index.md      # the tracker (single page)
    ├── assets/css/extended/custom.css  # PaperMod CSS overrides
    ├── layouts/partials/  # PaperMod overrides (post_meta, extend_footer)
    ├── go.mod, go.sum     # Hugo Modules — pulls PaperMod theme
    └── …                  # standard Hugo skeleton
```

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
