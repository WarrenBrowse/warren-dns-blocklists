# Warren DNS content-blocking lists & resolver

This repository is the **public, auditable source of truth** for Warren VPN's
optional "DNS content blockers" feature. It contains the per-category blocklist
**sources**, the **generation pipeline** that turns them into resolver zones,
and the **resolver policy** (kresd) that applies them on a Warren exit.

Nothing here is required to use Warren. The feature is **off by default** and is
a tool you choose to point your own device's DNS at, the same way you might run
a Pi-hole. We publish it so that anyone can verify exactly **what** Warren can
block, **how** the lists are built, and that the resolver **logs nothing**.

## Why this repository exists (our "And then?" stance)

Warren refuses to censor what you can reach. A blocking capability is, by
nature, also a censorship capability, so the only honest way to offer optional
filtering is to make the whole thing impossible to weaponise in secret:

- **Opt-in, off by default.** With no category selected, the resolver blocks
  nothing and simply resolves your queries.
- **Uniform and public.** The lists are identical for every user and published
  here. There is **no per-user, per-account or per-domain customisation** that
  could be aimed at a specific person or site.
- **No targeting lever.** Because there is no per-user list, "block site X for
  user Y" is not something the infrastructure can express.
- **Transparency as a canary.** Any change to what gets blocked lands in this
  repository's git history in public view. A coerced addition could not be made
  quietly.
- **No logs.** The resolver does not record queries (see [No-log](#no-log)).

This mirrors [Mullvad's model](https://github.com/mullvad/dns-blocklists):
Warren VPN is a fork of the Mullvad VPN app, and this feature is inherited from
it. Where Mullvad runs the filtering on BIND, Warren runs it on Knot Resolver
(kresd); the user-facing behaviour and the safeguards above are the same.

## What gets blocked

Six independent categories, each built from public upstream feeds (see
[`rpz-sources.conf`](./rpz-sources.conf)):

| Category | What it targets | Primary upstreams |
|---|---|---|
| `ads` | Advertising | OISD, AdGuard DNS, HaGeZi |
| `trackers` | Tracking / telemetry | Firebog EasyPrivacy, HaGeZi native lists |
| `malware` | Malware / phishing C2 | URLhaus (abuse.ch), HaGeZi threat-intel |
| `adult` | Adult content | OISD NSFW |
| `gambling` | Gambling | HaGeZi gambling |
| `social` | Social media | [`social-seed.txt`](./social-seed.txt) (Warren-curated) |

`social` is a small, deliberately conservative apex-domain seed we maintain
ourselves (every other category just aggregates well-known public lists). It is
the one list we author, so it is fully visible here.

> Note: this repo ships the **source URLs and the curated social seed**, not the
> downloaded contents of the upstream lists. Each upstream remains under its own
> license; the resolver fetches them at refresh time on the exit (see below).

## How it works

The app encodes your selected categories as a bitmask in the **last octet of a
`100.64.0.x` resolver address** (CGNAT range, RFC 6598), then sets that as your
system DNS over the tunnel:

```
ads=1  trackers=2  malware=4  adult=8  gambling=16  social=32   (OR-combined)

example: "ads + malware" -> 1 | 4 = 5 -> system resolver 100.64.0.5
```

On the exit, kresd listens on every `100.64.0.1 .. 100.64.0.63`, decodes the
octet, and runs only the selected categories' matchers:

```
query to 100.64.0.5  ->  kresd: mask 5 -> {ads, malware}
   match in ads.rpz or malware.rpz  ->  NXDOMAIN ("this name does not exist")
   no match                         ->  resolve normally (recursive, QNAME-minimised)
```

Blocking is a truthful **NXDOMAIN**, not a redirect to a sinkhole the operator
controls. Non-blocked names are resolved by **kresd itself** (it recurses with
QNAME minimisation), so no third-party resolver ever sees your queries.

Files:

- [`rpz-sources.conf`](./rpz-sources.conf): the per-category upstream feeds.
- [`social-seed.txt`](./social-seed.txt): the Warren-curated social list.
- [`normalize-to-rpz.awk`](./normalize-to-rpz.awk): converts any source format
  (RPZ / hosts / domain / wildcard) to bare domains.
- [`warren-dns-refresh.sh`](./warren-dns-refresh.sh): fetch → normalize →
  dedupe → wrap one RPZ zone per category → atomic in-place reload. On the
  exits it runs at boot and then every 6 hours.
- [`kresd.conf`](./kresd.conf): the resolver: listeners, the destination-decode
  policy, the six shared RPZ matchers, and the no-log configuration.
- [`test-kresd-decode.lua`](./test-kresd-decode.lua): an executable LuaJIT test
  proving per-category decode (e.g. the ads address blocks an ad domain but not
  an adult domain, the vanilla gateway never filters).

## No-log

- kresd does **not** log queries. We pin `log_level('warning')` and load no
  query-logging module (no dnstap).
- kresd **recurses itself** with QNAME minimisation, so no upstream resolver
  sees your full query stream.
- On Warren exits the system journal is **RAM-only** (`Storage=volatile`),
  so nothing query-adjacent is ever written to disk.
- The refresh job only ever touches **public blocklist data**, never queries.

## Reproduce / audit

```bash
# Build the per-category domain sets locally, exactly as an exit would,
# without touching a live resolver:
WARREN_DNS_RPZ_DIR=./out ./warren-dns-refresh.sh
ls -l ./out            # ads.rpz, trackers.rpz, malware.rpz, adult.rpz, gambling.rpz, social.rpz

# Verify the resolver's per-category decode logic (no network, no root):
luajit test-kresd-decode.lua
```

## Relationship to Warren

Warren's daemon-side mapping of toggles to the `100.64.0.x` bitmask lives in the
app/daemon ([warren-app](https://github.com/WarrenBrowse/warren-app), a GPL-3.0
fork of Mullvad VPN) and is inherited unmodified from Mullvad. This repository
is the **canonical home** of the blocklist sources and resolver policy; the deployment infrastructure vendors an exact copy and is checked
against this repo to guarantee that what runs in production matches what is
published here.

## License

[GPL-3.0-or-later](./LICENSE), consistent with the Warren / Mullvad app lineage.
The configuration and scripts in this repository are Warren's; the upstream
blocklists referenced in `rpz-sources.conf` remain under their respective
licenses and are not redistributed here.
