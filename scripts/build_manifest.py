#!/usr/bin/env python3
"""Turn an abuse.ch ThreatFox export into a FluxMoat JSON manifest blocklist.

ThreatFox ships a lot of things a packet tunnel cannot act on -- file
hashes, single URLs on otherwise-legitimate hosts, IOCs that expired
months ago. This script keeps only what FluxMoat's BlocklistParser can
actually match against a live flow (domains and IP addresses), normalizes
them the same way the app does, and writes a deterministic manifest so
that two runs over the same data produce byte-identical output.

Standard library only -- it has to run in CI with zero install steps.

Usage:
    ABUSECH_AUTH_KEY=... python3 scripts/build_manifest.py \
        --out public/threatfox/manifest.json \
        --previous public/threatfox/manifest.json \
        --summary-file summary.json

    # offline (tests, local bootstrap): skip the download entirely
    python3 scripts/build_manifest.py --input-file full.zip --out out.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile
from urllib.parse import urlsplit

# --- constants that mirror the app -----------------------------------------
# FluxMoat/Shared/Sources/SharedCore/Blocklist/BlocklistUpdater.swift:12
APP_MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
# FluxMoat/Shared/Sources/SharedCore/RuleEngine/BlocklistParser.swift:45
APP_MAX_ENTRIES = 200_000
# FluxMoat/Shared/Sources/SharedCore/RuleEngine/BlocklistParser.swift:47
MAX_DOMAIN_LENGTH = 253

DEFAULT_SOURCE_URL = "https://threatfox.abuse.ch/export/json/full/"
DEFAULT_MAX_AGE_DAYS = 183  # ~6 months, matches ThreatFox's own expiry policy
DEFAULT_MIN_CONFIDENCE = 50
DEFAULT_MIN_RATIO = 0.5  # a run yielding <50% of the previous entry count is a bug, not news
ABSOLUTE_MIN_ENTRIES = 1_000
MANIFEST_VERSION = 1
USER_AGENT = "fluxmoat-feeds/1.0 (+https://github.com/vrk176/fluxmoat-feeds)"

# BlocklistParser.swift:50-54 -- hosts-file boilerplate the app never accepts.
HOSTS_BOILERPLATE = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
}

# ThreatFox ioc_type values. The app maps ip:port -> IP and domain -> domain;
# url is host-extracted, hashes are dropped. We drop url ourselves (see
# map_record) so the two type names below are the whole output vocabulary.
TYPE_IP = "ip:port"
TYPE_DOMAIN = "domain"


class BuildError(Exception):
    """Anything that must stop the run before it can overwrite good data."""


# --- normalization (mirrors BlocklistParser.swift) --------------------------

def normalize_domain(raw):
    """Canonical blocklist domain, or None.

    Same rules as BlocklistParser.normalizedDomain (BlocklistParser.swift:287):
    lowercase, no trailing dot, wildcard prefix stripped (the engine is
    suffix-matching already), >=2 labels, ASCII letters/digits/-/_ only, no
    leading or trailing hyphen per label, not an all-numeric name.
    """
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower().rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    s = s.lstrip(".")
    if not s or len(s) > MAX_DOMAIN_LENGTH or s in HOSTS_BOILERPLATE:
        return None
    labels = s.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None
    all_numeric = True
    for label in labels:
        if len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return None
        for ch in label:
            if not (ch.isascii() and (ch.isalpha() or ch.isdigit() or ch in "-_")):
                return None
        if not label.isdigit():
            all_numeric = False
    if all_numeric:
        return None
    return s


def strip_port(value):
    """`1.2.3.4:443` -> `1.2.3.4`, `[2001:db8::1]:443` -> `2001:db8::1`.

    Mirrors BlocklistParser.strippingPort (BlocklistParser.swift:263).
    """
    if value.startswith("["):
        close = value.find("]")
        if close != -1:
            return value[1:close]
    colon = value.rfind(":")
    if colon != -1:
        return value[:colon]
    return value


def normalize_ip(raw):
    """Canonical IP string, or None. Tries the raw value first (a bare IPv6
    address is full of colons) and then the port-stripped form, exactly like
    BlocklistParser.mapIOC does (BlocklistParser.swift:240)."""
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value:
        return None
    for candidate in (value, strip_port(value)):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


# --- input handling --------------------------------------------------------

def flatten_records(root):
    """Flatten the three ThreatFox container shapes into a list of records.

    Same three shapes BlocklistParser.flattenIOCRecords accepts
    (BlocklistParser.swift:224), so a fixture that exercises the script also
    describes something the app can read.
    """
    if isinstance(root, list):
        return [r for r in root if isinstance(r, dict)]
    if not isinstance(root, dict):
        return []
    data = root.get("data")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    records = []
    for value in root.values():
        if isinstance(value, list):
            records.extend(r for r in value if isinstance(r, dict))
    return records


def decode_payload(blob):
    """ThreatFox serves /export/json/full/ as a zip and /recent/ as raw JSON.
    Accept either, and be loud when it is neither -- a truncated download must
    never look like an empty feed."""
    if blob[:2] == b"PK":
        try:
            archive = zipfile.ZipFile(io.BytesIO(blob))
            names = [n for n in archive.namelist() if n.lower().endswith(".json")]
            if not names:
                raise BuildError("zip archive contains no .json member")
            blob = archive.read(names[0])
        except zipfile.BadZipFile as exc:
            raise BuildError("payload looks like a zip but will not open: %s" % exc)
    try:
        return json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuildError("payload is not valid UTF-8 JSON: %s" % exc)


def fetch(url, auth_key, timeout=180):
    request = urllib.request.Request(url, headers={
        "Auth-Key": auth_key,
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/zip",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise BuildError("HTTP %s from %s" % (response.status, url))
            return response.read()
    except urllib.error.HTTPError as exc:
        hint = ""
        if exc.code in (401, 403):
            hint = " (abuse.ch rejected the Auth-Key -- check the ABUSECH_AUTH_KEY secret)"
        raise BuildError("HTTP %s from %s%s" % (exc.code, url, hint))
    except urllib.error.URLError as exc:
        raise BuildError("cannot reach %s: %s" % (url, exc.reason))


def load_allowlist(path):
    """Exact-match domain allowlist. Deliberately exact, not suffix: ThreatFox
    lists things like `evil.workers.dev`, and those must stay blocked -- it is
    only the shared apex (`workers.dev`) that would be a catastrophe."""
    if not path or not os.path.exists(path):
        return set()
    allowed = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                allowed.add(line)
    return allowed


# --- the actual filtering --------------------------------------------------

def parse_first_seen(value):
    if not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S UTC"):
        try:
            return dt.datetime.strptime(value.strip(), fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def map_record(record, cutoff, min_confidence, allowlist, stats):
    """One ThreatFox record -> (ioc_type, ioc_value, first_seen) or None.

    `url` IOCs are dropped on purpose. FluxMoat matches whole domains, and a
    URL IOC names one path on a host that is very often legitimate -- the
    August 2026 full export had cdn.jsdelivr.net, steamcommunity.com, t.me,
    sites.google.com and raw.githubusercontent.com among its url IOC hosts.
    Shipping those as domain blocks in a default subscription would break the
    internet for every user who enabled it.
    """
    ioc_type = record.get("ioc_type")
    ioc_value = record.get("ioc_value")
    if not isinstance(ioc_type, str) or not isinstance(ioc_value, str):
        stats["malformed"] += 1
        return None

    if ioc_type not in (TYPE_IP, TYPE_DOMAIN):
        stats["unsupported_type"] += 1
        return None

    first_seen = parse_first_seen(record.get("first_seen_utc"))
    if first_seen is None:
        stats["no_first_seen"] += 1
        return None
    if first_seen < cutoff:
        stats["expired"] += 1
        return None

    confidence = record.get("confidence_level")
    if isinstance(confidence, (int, float)) and confidence < min_confidence:
        stats["low_confidence"] += 1
        return None

    if ioc_type == TYPE_DOMAIN:
        domain = normalize_domain(ioc_value)
        if domain is None:
            stats["unparseable"] += 1
            return None
        if domain in allowlist:
            stats["allowlisted"] += 1
            return None
        return (TYPE_DOMAIN, domain, first_seen)

    ip = normalize_ip(ioc_value)
    if ip is None:
        stats["unparseable"] += 1
        return None
    return (TYPE_IP, ip, first_seen)


def build_entries(records, now, max_age_days, min_confidence, allowlist):
    """Filter, dedupe and sort. Output order is fully determined by the data,
    so an unchanged feed produces an unchanged file."""
    cutoff = now - dt.timedelta(days=max_age_days)
    stats = {
        "input_records": 0, "malformed": 0, "unsupported_type": 0,
        "no_first_seen": 0, "expired": 0, "low_confidence": 0,
        "unparseable": 0, "allowlisted": 0, "duplicate": 0,
    }
    # value -> newest first_seen, so a duplicate keeps the most recent sighting.
    domains = {}
    ips = {}
    for record in records:
        stats["input_records"] += 1
        mapped = map_record(record, cutoff, min_confidence, allowlist, stats)
        if mapped is None:
            continue
        ioc_type, value, first_seen = mapped
        bucket = domains if ioc_type == TYPE_DOMAIN else ips
        if value in bucket:
            stats["duplicate"] += 1
            if first_seen > bucket[value]:
                bucket[value] = first_seen
        else:
            bucket[value] = first_seen

    entries = [
        {"ioc_type": TYPE_DOMAIN, "ioc_value": value, "first_seen": first_seen}
        for value, first_seen in sorted(domains.items())
    ]
    # Sort IPs numerically (v4 before v6) rather than as strings, so
    # 9.0.0.1 does not land after 10.0.0.1.
    entries += [
        {"ioc_type": TYPE_IP, "ioc_value": value, "first_seen": first_seen}
        for value, first_seen in sorted(
            ips.items(), key=lambda kv: (ipaddress.ip_address(kv[0]).version,
                                         int(ipaddress.ip_address(kv[0]))))
    ]
    stats["domains"] = len(domains)
    stats["ips"] = len(ips)
    stats["total"] = len(entries)
    return entries, stats


def trim_to_budget(entries, max_bytes, headroom=0.85):
    """Drop the oldest indicators until the file comfortably fits the app's
    download ceiling.

    BlocklistUpdater aborts a download mid-stream past maxDownloadBytes, so a
    manifest that grows past it stops updating for every user at once. The
    2026-08 export lands around 4 MB against a 10 MB ceiling; this only ever
    fires if ThreatFox doubles. When it does, the freshest indicators are the
    ones worth keeping.
    """
    budget = int(max_bytes * headroom)
    dropped = 0
    while entries and rendered_size(entries) > budget:
        keep = max(1, int(len(entries) * 0.9))
        by_age = sorted(entries, key=lambda e: e["first_seen"], reverse=True)[:keep]
        kept = {(e["ioc_type"], e["ioc_value"]) for e in by_age}
        dropped += len(entries) - len(by_age)
        entries = [e for e in entries if (e["ioc_type"], e["ioc_value"]) in kept]
    return entries, dropped


def rendered_size(entries):
    """Bytes the `data` array will occupy, without building the whole file."""
    return sum(len(json.dumps(emitted(e), separators=(",", ":")).encode()) + 6
               for e in entries)


def emitted(entry):
    """What actually ships per indicator. Deliberately two fields: the app
    reads only these (BlocklistParser.swift:197), and a line that never
    changes once written keeps the git history to pure adds and removes."""
    return {"ioc_value": entry["ioc_value"], "ioc_type": entry["ioc_type"]}


def data_digest(entries):
    """Digest of the indicators only -- no timestamps. Lets the workflow tell
    'nothing changed' apart from 'new data', and skip a pointless commit."""
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(entry["ioc_type"].encode())
        digest.update(b"\x1f")
        digest.update(entry["ioc_value"].encode())
        digest.update(b"\x1e")
    return digest.hexdigest()


def render_manifest(entries, generated_at, source_url, max_age_days,
                    min_confidence):
    """Serialize to the shape BlocklistParser reads: a top-level `data` array
    of {ioc_value, ioc_type} records. Everything else in the object is
    metadata for humans -- flattenIOCRecords returns `data` and ignores its
    siblings (BlocklistParser.swift:228).

    Written by hand rather than json.dumps(indent=...) so each indicator is
    one line: a 3 MB file that only ever gains and loses whole lines is a
    readable diff, and gzip likes it too.
    """
    first_seen = [e["first_seen"] for e in entries if e.get("first_seen")]
    header = {
        "manifest_version": MANIFEST_VERSION,
        "feed": "fluxmoat-threatfox",
        "title": "FluxMoat ThreatFox mirror",
        "description": (
            "Domain and IP indicators from abuse.ch ThreatFox, filtered to what "
            "FluxMoat can match on a live network flow. Unofficial third-party "
            "mirror -- not operated by abuse.ch."
        ),
        "source": {
            "name": "ThreatFox",
            "operator": "abuse.ch",
            "url": "https://threatfox.abuse.ch/",
            "export": source_url,
            "license": "CC0-1.0",
        },
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "filters": {
            "max_age_days": max_age_days,
            "min_confidence_level": min_confidence,
            "ioc_types": [TYPE_DOMAIN, TYPE_IP],
            "dropped_ioc_types": ["url", "md5_hash", "sha1_hash", "sha256_hash"],
        },
        "counts": {
            "total": len(entries),
            "domain": sum(1 for e in entries if e["ioc_type"] == TYPE_DOMAIN),
            "ip": sum(1 for e in entries if e["ioc_type"] == TYPE_IP),
        },
        "oldest_first_seen_utc": (min(first_seen).strftime("%Y-%m-%d %H:%M:%S")
                                  if first_seen else None),
        "newest_first_seen_utc": (max(first_seen).strftime("%Y-%m-%d %H:%M:%S")
                                  if first_seen else None),
        "data_digest": data_digest(entries),
    }
    out = io.StringIO()
    out.write("{\n")
    for key, value in header.items():
        out.write('  %s: %s,\n' % (json.dumps(key), json.dumps(value, sort_keys=True)))
    out.write('  "data": [\n')
    for index, entry in enumerate(entries):
        line = json.dumps(emitted(entry), separators=(",", ":"))
        out.write("    %s%s\n" % (line, "" if index == len(entries) - 1 else ","))
    out.write("  ]\n}\n")
    return out.getvalue()


def previous_summary(path):
    """Entry count + digest of the manifest already published, so we can
    refuse to replace 60k good indicators with 12."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    data = manifest.get("data")
    if not isinstance(data, list):
        return None
    return {
        "total": len(data),
        "digest": manifest.get("data_digest"),
        "generated_at": manifest.get("generated_at"),
    }


def check_gates(entries, body, previous, min_ratio, max_entries, max_bytes,
                min_entries=ABSOLUTE_MIN_ENTRIES):
    """Every reason to abandon a run, in one place. Raising here means the
    previously published manifest stays exactly where it is."""
    total = len(entries)
    if total < min_entries:
        raise BuildError(
            "only %d indicators survived filtering (floor is %d) -- refusing to "
            "publish; the export or the filters are broken"
            % (total, min_entries))
    if total > max_entries:
        raise BuildError(
            "%d indicators exceeds the app's BlocklistParser.maxEntries (%d) -- "
            "the app would reject the whole list" % (total, max_entries))
    size = len(body.encode("utf-8"))
    if size > max_bytes:
        raise BuildError(
            "manifest is %d bytes, over the app's BlocklistUpdater."
            "maxDownloadBytes (%d) -- the download would be aborted mid-stream"
            % (size, max_bytes))
    if previous and previous["total"]:
        ratio = total / previous["total"]
        if ratio < min_ratio:
            raise BuildError(
                "indicator count collapsed from %d to %d (%.0f%% of the "
                "previous run, floor is %.0f%%) -- keeping the published "
                "manifest" % (previous["total"], total, ratio * 100, min_ratio * 100))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_SOURCE_URL,
                        help="ThreatFox export URL (default: %(default)s)")
    parser.add_argument("--input-file",
                        help="read the export from a local file instead of "
                             "downloading it (tests, offline bootstrap)")
    parser.add_argument("--out", required=True, help="manifest output path")
    parser.add_argument("--checksum-out",
                        help="sha256 sidecar path (default: <out dir>/manifest.sha256)")
    parser.add_argument("--previous",
                        help="path to the currently published manifest, used for "
                             "the count-collapse gate")
    parser.add_argument("--allowlist", default=None,
                        help="newline-separated domains to drop (exact match)")
    parser.add_argument("--summary-file",
                        help="write a JSON run summary here (for CI steps)")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--min-confidence", type=int, default=DEFAULT_MIN_CONFIDENCE)
    parser.add_argument("--min-ratio", type=float, default=DEFAULT_MIN_RATIO)
    parser.add_argument("--min-entries", type=int, default=ABSOLUTE_MIN_ENTRIES,
                        help="absolute floor below which the run fails "
                             "(default: %(default)s; lowered only by the tests)")
    parser.add_argument("--max-entries", type=int, default=APP_MAX_ENTRIES)
    parser.add_argument("--max-bytes", type=int, default=APP_MAX_DOWNLOAD_BYTES)
    parser.add_argument("--now", help="override the clock, RFC3339 (tests only)")
    args = parser.parse_args(argv)

    # The manifest always names the canonical upstream endpoint: --input-file
    # is just a local copy of that same export (tests, offline bootstrap), and
    # a file:// path in a published feed would be nonsense to a reader.
    source_url = args.url
    if args.input_file:
        with open(args.input_file, "rb") as handle:
            blob = handle.read()
    else:
        auth_key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
        if not auth_key:
            raise BuildError(
                "ABUSECH_AUTH_KEY is empty or unset. abuse.ch downloads need an "
                "Auth-Key from https://auth.abuse.ch/ -- add it as the repository "
                "secret ABUSECH_AUTH_KEY (Settings -> Secrets and variables -> "
                "Actions). Refusing to run: an unauthenticated fetch would either "
                "fail or return a stub, and either way must not overwrite the "
                "published manifest.")
        blob = fetch(args.url, auth_key)
        source_url = args.url

    if not blob:
        raise BuildError("empty response body from %s" % source_url)

    root = decode_payload(blob)
    records = flatten_records(root)
    if not records:
        raise BuildError(
            "no IOC records found in the export -- the upstream format changed, "
            "or the download was truncated")

    now = (dt.datetime.strptime(args.now, "%Y-%m-%dT%H:%M:%SZ")
           .replace(tzinfo=dt.timezone.utc) if args.now
           else dt.datetime.now(dt.timezone.utc).replace(microsecond=0))

    allowlist = load_allowlist(args.allowlist)
    entries, stats = build_entries(records, now, args.max_age_days,
                                   args.min_confidence, allowlist)
    entries, trimmed = trim_to_budget(entries, args.max_bytes)
    stats["trimmed_for_size"] = trimmed
    stats["total"] = len(entries)
    stats["domains"] = sum(1 for e in entries if e["ioc_type"] == TYPE_DOMAIN)
    stats["ips"] = sum(1 for e in entries if e["ioc_type"] == TYPE_IP)
    body = render_manifest(entries, now, source_url, args.max_age_days,
                           args.min_confidence)

    previous = previous_summary(args.previous)
    check_gates(entries, body, previous, args.min_ratio, args.max_entries,
                args.max_bytes, args.min_entries)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(body)

    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    checksum_path = args.checksum_out or os.path.join(out_dir, "manifest.sha256")
    with open(checksum_path, "w", encoding="utf-8") as handle:
        handle.write("%s  %s\n" % (digest, os.path.basename(args.out)))

    changed = not (previous and previous.get("digest") == data_digest(entries))
    summary = {
        "manifest": args.out,
        "bytes": len(body.encode("utf-8")),
        "sha256": digest,
        "changed": changed,
        "previous_total": previous["total"] if previous else None,
        "stats": stats,
    }
    if args.summary_file:
        with open(args.summary_file, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)

    print("indicators: %d (%d domain, %d ip) from %d records"
          % (stats["total"], stats["domains"], stats["ips"], stats["input_records"]))
    print("dropped: %d expired, %d unsupported type, %d low confidence, "
          "%d unparseable, %d duplicate, %d allowlisted, %d malformed, "
          "%d trimmed for size"
          % (stats["expired"], stats["unsupported_type"], stats["low_confidence"],
             stats["unparseable"], stats["duplicate"], stats["allowlisted"],
             stats["malformed"], stats["trimmed_for_size"]))
    print("manifest: %s (%d bytes, sha256 %s)" % (args.out, summary["bytes"], digest))
    print("changed since published manifest: %s" % ("yes" if changed else "no"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as error:
        print("build_manifest: %s" % error, file=sys.stderr)
        sys.exit(1)
