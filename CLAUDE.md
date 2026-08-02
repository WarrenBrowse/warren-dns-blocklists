# warren-dns-blocklists: rules for Claude Code

Opt-in DNS content blockers and no-log resolver policy for Warren VPN.

> Shared Warren rules (single source of truth: WarrenBrowse/warren-workspace).
> They resolve when this repo is checked out inside the workspace (mani sync);
> cloned standalone, the imports just warn harmlessly.
@../shared/rules/00-conventions.md
@../shared/rules/10-tdd.md
@../shared/rules/20-errors-secrets.md
@../shared/rules/30-git-commits.md

## Repo-specific rules

- **No-log and uniformity are the law of this repo.** kresd never logs queries:
  `log_level('warning')` stays pinned in `kresd.conf` and no query-logging
  module (dnstap) is ever loaded. Lists are uniform and public; per-user,
  per-account or per-domain customisation is architecturally banned. The README
  carries the full stance; a change that weakens either point is wrong by
  definition.
- **Test entry.** Before changing `kresd.conf`, `normalize-to-rpz.awk` or
  `warren-dns-refresh.sh`, run `luajit test-kresd-decode.lua` (decode logic, no
  network, no root) and build the zones locally with
  `WARREN_DNS_RPZ_DIR=./out ./warren-dns-refresh.sh` (exactly what an exit runs;
  `./out` is throwaway, keep it out of commits).
- **Drift-lock with warren-core.** `rpz-sources.conf`, `social-seed.txt`,
  `normalize-to-rpz.awk`, `warren-dns-refresh.sh` and `kresd.conf` must stay
  byte-identical with `warren-core/infra/dns/` (see its `CANONICAL-SOURCE.md`;
  the `dns-integrity` CI job runs `verify-canonical-sync.sh`). The exits run
  that vendored copy at boot and then every 6 hours, so mirror every change of
  a drift-tracked file into warren-core in the same session or its CI goes red.
