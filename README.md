# fluxmoat-feeds

Threat-intelligence indicators from [abuse.ch ThreatFox][threatfox], republished
as a [FluxMoat][fluxmoat] **JSON manifest** blocklist and served from GitHub Pages.

**This is an unofficial third-party mirror. It is not operated, endorsed, or
supported by abuse.ch.** Problems with the mirror belong in this repository's
issues; problems with the underlying indicators belong with ThreatFox.

## The feed

| | |
|---|---|
| Manifest | <https://feeds.hominexis.com/threatfox/manifest.json> |
| Checksum | <https://feeds.hominexis.com/threatfox/manifest.sha256> |
| Format | FluxMoat "JSON manifest" |
| Rebuilt | every 6 hours (and on demand) |
| Upstream | `https://threatfox.abuse.ch/export/json/full/` |
| Licence | data CC0 1.0 (see [Attribution](#attribution)) |

In FluxMoat: **Blocklists → add source → format "JSON manifest (ThreatFox)"**,
paste the manifest URL. No abuse.ch Auth-Key is needed on the device — the key
is only used here, in CI, to fetch the upstream export.

`feeds.hominexis.com` is the address the app ships with, and the one to use.
It is a custom domain over the same GitHub Pages deployment, so the origin URL
`https://vrk176.github.io/fluxmoat-feeds/threatfox/manifest.json` serves the
identical file and works as a fallback if the domain is ever unreachable.

## What is in it, and what is not

ThreatFox publishes more kinds of indicator than a packet tunnel can act on.
The build keeps:

- **`domain`** IOCs, normalized the way FluxMoat normalizes them (lowercased,
  trailing dot removed, `*.` wildcard prefix stripped — the engine matches
  subdomains already).
- **`ip:port`** IOCs, reduced to the **IP address** with the port dropped.
  FluxMoat matches indicators per connection by address, so `1.2.3.4:443` and
  `1.2.3.4:8080` are one indicator, not two.

and drops:

- **`url` IOCs.** A URL IOC names one path on a host that is very often
  legitimate. The 2026-08 full export listed `cdn.jsdelivr.net`,
  `steamcommunity.com`, `t.me`, `sites.google.com` and
  `raw.githubusercontent.com` among its URL hosts — and FluxMoat blocks whole
  domains, not paths. Shipping those as domain blocks would be worse than
  shipping nothing.
- **File hashes** (`md5_hash`, `sha1_hash`, `sha256_hash`). Nothing on the wire
  to match them against.
- **Indicators first seen more than 183 days ago**, matching ThreatFox's own
  expiry policy.
- **Indicators below confidence level 50.**
- Anything on [`data/allowlist.txt`](data/allowlist.txt) — an exact-match list
  of shared apexes (`workers.dev`, `duckdns.org`, …). Exact match on purpose:
  `evil.workers.dev` stays blocked, only the bare apex is dropped.

Duplicates collapse; output is sorted (domains alphabetically, then IPs
numerically with v4 before v6), so an unchanged upstream produces a
byte-identical file and a run that changes nothing commits nothing.

Typical size as of 2026-08: **~63,000 indicators, ~4 MB** — comfortably inside
FluxMoat's own limits (`BlocklistParser.maxEntries` 200,000 and
`BlocklistUpdater.maxDownloadBytes` 10 MB). If the export ever grows past the
size budget, the oldest indicators are trimmed rather than letting the download
fail on device.

## Manifest format

```jsonc
{
  "manifest_version": 1,
  "feed": "fluxmoat-threatfox",
  "title": "FluxMoat ThreatFox mirror",
  "description": "…",
  "source": {
    "name": "ThreatFox",
    "operator": "abuse.ch",
    "url": "https://threatfox.abuse.ch/",
    "export": "https://threatfox.abuse.ch/export/json/full/",
    "license": "CC0-1.0"
  },
  "generated_at": "2026-08-31T08:33:11Z",
  "filters": {
    "max_age_days": 183,
    "min_confidence_level": 50,
    "ioc_types": ["domain", "ip:port"],
    "dropped_ioc_types": ["url", "md5_hash", "sha1_hash", "sha256_hash"]
  },
  "counts": { "total": 63313, "domain": 47653, "ip": 15660 },
  "oldest_first_seen_utc": "2026-03-01 12:00:00",
  "newest_first_seen_utc": "2026-08-31 07:45:00",
  "data_digest": "…sha256 over the indicators only…",
  "data": [
    {"ioc_value":"bad.example.com","ioc_type":"domain"},
    {"ioc_value":"93.184.216.34","ioc_type":"ip:port"}
  ]
}
```

Only `data` is load-bearing: FluxMoat reads the array and, per record,
`ioc_value` and `ioc_type`. Everything else is metadata for humans and for the
build's own safety checks, and the parser ignores it. `ioc_type` keeps
ThreatFox's `"ip:port"` spelling even though the port is stripped, because that
is the type name FluxMoat maps to an IP indicator.

One indicator per line, so the git history of the published branch is a clean
list of additions and removals.

`data_digest` covers the indicators only — not `generated_at` — so you can tell
"nothing changed upstream" apart from "new data".

## Verifying a download

```sh
curl -O https://feeds.hominexis.com/threatfox/manifest.json
curl -O https://feeds.hominexis.com/threatfox/manifest.sha256
shasum -a 256 -c manifest.sha256      # macOS/Linux
```

The `.sha256` file is `<digest>  manifest.json`, generated next to the manifest
in the same CI run.

## Build

```sh
# offline tests -- no network, no key
python3 -m unittest discover -s tests -v

# real run (needs an abuse.ch Auth-Key from https://auth.abuse.ch/)
ABUSECH_AUTH_KEY=... python3 scripts/build_manifest.py \
    --out out/threatfox/manifest.json \
    --previous published/threatfox/manifest.json \
    --allowlist data/allowlist.txt \
    --summary-file out/summary.json

# offline, from a saved copy of the export
python3 scripts/build_manifest.py --input-file full.zip --out out/manifest.json
```

Python 3 standard library only — nothing to install.

CI (`.github/workflows/build.yml`) runs on a 6-hourly cron, on pushes to `main`,
and on `workflow_dispatch`. It reads the repository secret **`ABUSECH_AUTH_KEY`**
and publishes to the `gh-pages` branch.

### Failing safe

The published manifest is only ever replaced by a build that passed every check.
Any of these aborts the run **before** the publish step, leaving the previous
good file exactly where it is:

- `ABUSECH_AUTH_KEY` missing or empty (checked before any network call, with a
  log line naming the secret);
- the upstream fetch failing, or abuse.ch rejecting the key;
- a payload that is not valid JSON (or a zip that will not open);
- an export containing no IOC records at all;
- fewer than 1,000 indicators surviving the filters;
- an indicator count below 50% of the currently published manifest;
- output over FluxMoat's entry or size limits.

There is no "publish an empty manifest" path. An empty manifest would silently
switch the protection off for everyone subscribed.

## Attribution

Indicator data comes from **[ThreatFox][threatfox]**, a project of
**[abuse.ch][abusech]**, and is released by them under
[CC0 1.0 Universal][cc0] — public domain dedication, redistribution permitted.
This mirror reshapes and filters that data; it adds no indicators of its own.

The scripts in this repository are MIT-licensed (see [LICENSE](LICENSE)). The
licence covers the code, not the indicator data, which stays CC0.

[threatfox]: https://threatfox.abuse.ch/
[abusech]: https://abuse.ch/
[cc0]: https://creativecommons.org/publicdomain/zero/1.0/
[fluxmoat]: https://github.com/vrk176/FluxMoat
