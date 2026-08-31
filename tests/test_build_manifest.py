#!/usr/bin/env python3
"""Offline tests for build_manifest.py. Standard library only.

    python3 -m unittest discover -s tests -v

Everything here runs against a checked-in fixture -- no network, no key.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import build_manifest as bm  # noqa: E402

FIXTURE = os.path.join(REPO, "tests", "fixtures", "threatfox_export_sample.json")
ALLOWLIST = os.path.join(REPO, "data", "allowlist.txt")
NOW = dt.datetime(2026, 8, 31, 12, 0, 0, tzinfo=dt.timezone.utc)


def build_fixture(**overrides):
    with open(FIXTURE, "rb") as handle:
        root = json.load(handle)
    kwargs = {
        "now": NOW,
        "max_age_days": bm.DEFAULT_MAX_AGE_DAYS,
        "min_confidence": bm.DEFAULT_MIN_CONFIDENCE,
        "allowlist": bm.load_allowlist(ALLOWLIST),
    }
    kwargs.update(overrides)
    return bm.build_entries(bm.flatten_records(root), **kwargs)


class NormalizationTests(unittest.TestCase):
    def test_domain_normalization_matches_app_rules(self):
        self.assertEqual(bm.normalize_domain("BAD.Example.COM."), "bad.example.com")
        self.assertEqual(bm.normalize_domain("*.wildcard.example"), "wildcard.example")
        self.assertEqual(bm.normalize_domain(" .lead.example "), "lead.example")
        self.assertEqual(bm.normalize_domain("under_score.example"), "under_score.example")

    def test_domain_rejects_what_the_app_rejects(self):
        for bad in ["", "localhost", "single", "a..b", "192.0.2.1",
                    "-lead.example", "trail-.example", "uniçode.example",
                    "not a domain", "a" * 64 + ".example",
                    ("x" * 60 + ".") * 5 + "example"]:
            self.assertIsNone(bm.normalize_domain(bad), bad)

    def test_ip_normalization_strips_ports_and_brackets(self):
        self.assertEqual(bm.normalize_ip("93.184.216.34:443"), "93.184.216.34")
        self.assertEqual(bm.normalize_ip("[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(bm.normalize_ip("2001:db8::1"), "2001:db8::1")
        self.assertEqual(bm.normalize_ip("2001:0db8:0000::0001"), "2001:db8::1")
        self.assertEqual(bm.normalize_ip("198.51.100.7"), "198.51.100.7")

    def test_ip_rejects_junk(self):
        for bad in ["", "example.com:443", "999.1.1.1:80", "not-an-ip"]:
            self.assertIsNone(bm.normalize_ip(bad), bad)


class FlattenTests(unittest.TestCase):
    """The three container shapes BlocklistParser.flattenIOCRecords accepts."""

    def test_dict_of_arrays(self):
        root = {"1": [{"ioc_value": "a.example", "ioc_type": "domain"}],
                "2": [{"ioc_value": "b.example", "ioc_type": "domain"}]}
        self.assertEqual(len(bm.flatten_records(root)), 2)

    def test_api_data_array_wins_over_siblings(self):
        root = {"query_status": "ok",
                "data": [{"ioc_value": "a.example", "ioc_type": "domain"}],
                "other": [{"ioc_value": "b.example", "ioc_type": "domain"}]}
        records = bm.flatten_records(root)
        self.assertEqual([r["ioc_value"] for r in records], ["a.example"])

    def test_plain_array(self):
        root = [{"ioc_value": "a.example", "ioc_type": "domain"}]
        self.assertEqual(len(bm.flatten_records(root)), 1)

    def test_junk_root(self):
        self.assertEqual(bm.flatten_records("nope"), [])
        self.assertEqual(bm.flatten_records({}), [])


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.entries, self.stats = build_fixture()

    def test_only_domains_and_ips_survive(self):
        self.assertEqual({e["ioc_type"] for e in self.entries}, {"domain", "ip:port"})

    def test_expected_indicator_set(self):
        domains = [e["ioc_value"] for e in self.entries if e["ioc_type"] == "domain"]
        ips = [e["ioc_value"] for e in self.entries if e["ioc_type"] == "ip:port"]
        self.assertEqual(domains,
                         ["bad.example.com", "evil-c2.workers.dev", "wildcard.example"])
        self.assertEqual(ips,
                         ["9.8.7.6", "10.0.0.1", "93.184.216.34", "2001:db8::1"])

    def test_url_and_hash_iocs_are_dropped(self):
        values = {e["ioc_value"] for e in self.entries}
        self.assertNotIn("cdn.jsdelivr.net", values)
        self.assertNotIn("198.51.100.9", values)
        self.assertEqual(self.stats["unsupported_type"], 4)  # 2 url + md5 + sha256

    def test_records_older_than_six_months_are_dropped(self):
        values = {e["ioc_value"] for e in self.entries}
        self.assertNotIn("stale.example", values)
        self.assertNotIn("203.0.113.77", values)
        self.assertEqual(self.stats["expired"], 2)

    def test_duplicates_collapse_and_keep_the_newest_sighting(self):
        self.assertEqual(self.stats["duplicate"], 2)
        ip = [e for e in self.entries if e["ioc_value"] == "93.184.216.34"]
        # seen at :443 on 08-20 and at :8443 on 08-29 -- one entry, newer date
        self.assertEqual(len(ip), 1)
        self.assertEqual(ip[0]["first_seen"],
                         dt.datetime(2026, 8, 29, 6, 0, tzinfo=dt.timezone.utc))

    def test_low_confidence_and_allowlist_and_malformed(self):
        values = {e["ioc_value"] for e in self.entries}
        self.assertNotIn("lowtrust.example", values)
        self.assertNotIn("workers.dev", values)
        self.assertIn("evil-c2.workers.dev", values)  # subdomain stays blocked
        self.assertNotIn("nodate.example", values)
        self.assertEqual(self.stats["low_confidence"], 1)
        self.assertEqual(self.stats["allowlisted"], 1)
        self.assertEqual(self.stats["malformed"], 1)
        self.assertEqual(self.stats["unparseable"], 2)  # junk string + localhost
        self.assertEqual(self.stats["no_first_seen"], 1)

    def test_counts_add_up(self):
        self.assertEqual(self.stats["input_records"], 21)
        self.assertEqual(self.stats["total"], 7)
        self.assertEqual(self.stats["domains"], 3)
        self.assertEqual(self.stats["ips"], 4)

    def test_age_window_is_configurable(self):
        _, stats = build_fixture(max_age_days=3650)
        self.assertEqual(stats["expired"], 0)

    def test_output_is_deterministic(self):
        again, _ = build_fixture()
        self.assertEqual(self.entries, again)


class ManifestShapeTests(unittest.TestCase):
    """The manifest has to be readable by BlocklistParser.parseJSON."""

    def setUp(self):
        self.entries, self.stats = build_fixture()
        self.body = bm.render_manifest(self.entries, NOW,
                                       "https://threatfox.abuse.ch/export/json/full/",
                                       bm.DEFAULT_MAX_AGE_DAYS,
                                       bm.DEFAULT_MIN_CONFIDENCE)
        self.manifest = json.loads(self.body)

    def test_data_array_of_ioc_records(self):
        self.assertIsInstance(self.manifest["data"], list)
        for record in self.manifest["data"]:
            # exactly the two keys BlocklistParser.parseJSON reads
            self.assertEqual(set(record), {"ioc_value", "ioc_type"})
            self.assertIn(record["ioc_type"], ("domain", "ip:port"))
            self.assertIsInstance(record["ioc_value"], str)
            self.assertTrue(record["ioc_value"])

    def test_metadata_present_and_counts_match(self):
        self.assertEqual(self.manifest["manifest_version"], 1)
        self.assertEqual(self.manifest["source"]["license"], "CC0-1.0")
        self.assertEqual(self.manifest["counts"]["total"], len(self.manifest["data"]))
        self.assertEqual(self.manifest["counts"]["domain"], 3)
        self.assertEqual(self.manifest["counts"]["ip"], 4)
        self.assertEqual(self.manifest["generated_at"], "2026-08-31T12:00:00Z")
        # 08-20 belongs to the 93.184.216.34 duplicate, which dedupe moved to 08-29
        self.assertEqual(self.manifest["oldest_first_seen_utc"], "2026-08-26 11:00:00")
        self.assertEqual(self.manifest["newest_first_seen_utc"], "2026-08-30 09:20:00")

    def test_one_indicator_per_line(self):
        lines = [ln for ln in self.body.splitlines() if ln.startswith('    {')]
        self.assertEqual(len(lines), len(self.manifest["data"]))

    def test_digest_ignores_timestamps(self):
        later = bm.render_manifest(self.entries, NOW + dt.timedelta(days=1),
                                   "https://threatfox.abuse.ch/export/json/full/",
                                   bm.DEFAULT_MAX_AGE_DAYS,
                                   bm.DEFAULT_MIN_CONFIDENCE)
        self.assertNotEqual(later, self.body)
        self.assertEqual(json.loads(later)["data_digest"],
                         self.manifest["data_digest"])


class PayloadTests(unittest.TestCase):
    def test_zip_payload_is_unwrapped(self):
        import io
        import zipfile
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("full.json", '{"1":[{"ioc_value":"a.example",'
                                          '"ioc_type":"domain"}]}')
        root = bm.decode_payload(buffer.getvalue())
        self.assertEqual(len(bm.flatten_records(root)), 1)

    def test_broken_json_raises(self):
        with self.assertRaises(bm.BuildError):
            bm.decode_payload(b"{not json")


class GateTests(unittest.TestCase):
    """Every gate must raise, because raising is what leaves the published
    manifest untouched."""

    def setUp(self):
        self.entries, self.stats = build_fixture()
        self.body = bm.render_manifest(self.entries, NOW, "x",
                                       bm.DEFAULT_MAX_AGE_DAYS, 50)

    def test_passes_when_healthy(self):
        bm.check_gates(self.entries, self.body, {"total": 7, "digest": None},
                       0.5, 200_000, 10 * 1024 * 1024, min_entries=1)

    def test_absolute_floor(self):
        with self.assertRaisesRegex(bm.BuildError, "floor"):
            bm.check_gates(self.entries, self.body, None, 0.5, 200_000,
                           10 * 1024 * 1024, min_entries=1_000)

    def test_count_collapse_blocks_publish(self):
        with self.assertRaisesRegex(bm.BuildError, "collapsed"):
            bm.check_gates(self.entries, self.body, {"total": 60_000}, 0.5,
                           200_000, 10 * 1024 * 1024, min_entries=1)

    def test_app_entry_cap(self):
        with self.assertRaisesRegex(bm.BuildError, "maxEntries"):
            bm.check_gates(self.entries, self.body, None, 0.5, 3,
                           10 * 1024 * 1024, min_entries=1)

    def test_app_size_cap(self):
        with self.assertRaisesRegex(bm.BuildError, "maxDownloadBytes"):
            bm.check_gates(self.entries, self.body, None, 0.5, 200_000, 10,
                           min_entries=1)


class TrimTests(unittest.TestCase):
    """The app aborts a download past maxDownloadBytes, so an oversized
    manifest would stop updating for everyone. Trim the oldest instead."""

    def make(self, count):
        return [{"ioc_type": "domain", "ioc_value": "n%06d.example" % i,
                 "first_seen": NOW - dt.timedelta(days=i)} for i in range(count)]

    def test_no_trim_when_it_fits(self):
        entries = self.make(100)
        kept, dropped = bm.trim_to_budget(entries, 10 * 1024 * 1024)
        self.assertEqual(dropped, 0)
        self.assertEqual(kept, entries)

    def test_trims_oldest_first_until_under_budget(self):
        entries = self.make(1_000)
        kept, dropped = bm.trim_to_budget(entries, 20_000)
        self.assertGreater(dropped, 0)
        self.assertEqual(len(kept) + dropped, 1_000)
        self.assertLessEqual(bm.rendered_size(kept), int(20_000 * 0.85))
        # the survivors are the newest ones, and original order is preserved
        self.assertEqual([e["ioc_value"] for e in kept],
                         ["n%06d.example" % i for i in range(len(kept))])

    def test_real_export_fits_with_headroom(self):
        """Guard rail for the 2026-08 sizing: ~63k indicators at ~4 MB against
        a 10 MB ceiling. If this ever needs relaxing, re-check the app cap."""
        entries = self.make(70_000)
        self.assertLess(bm.rendered_size(entries), bm.APP_MAX_DOWNLOAD_BYTES)


class CLITests(unittest.TestCase):
    SCRIPT = os.path.join(REPO, "scripts", "build_manifest.py")

    def run_cli(self, args, env=None):
        environment = dict(os.environ)
        environment.pop("ABUSECH_AUTH_KEY", None)
        environment.update(env or {})
        return subprocess.run([sys.executable, self.SCRIPT] + args,
                              capture_output=True, text=True, env=environment)

    def test_end_to_end_offline_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "manifest.json")
            summary = os.path.join(tmp, "summary.json")
            result = self.run_cli([
                "--input-file", FIXTURE, "--out", out, "--allowlist", ALLOWLIST,
                "--summary-file", summary, "--min-entries", "1",
                "--now", "2026-08-31T12:00:00Z",
            ])
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(out, encoding="utf-8") as handle:
                manifest = json.load(handle)
            self.assertEqual(manifest["counts"]["total"], 7)

            # sidecar checksum is over the manifest we actually wrote
            with open(os.path.join(tmp, "manifest.sha256"), encoding="utf-8") as handle:
                checksum = handle.read().split()
            import hashlib
            with open(out, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            self.assertEqual(checksum[0], digest)
            self.assertEqual(checksum[1], "manifest.json")

            with open(summary, encoding="utf-8") as handle:
                report = json.load(handle)
            self.assertTrue(report["changed"])
            self.assertEqual(report["stats"]["total"], 7)

    def test_rerun_reports_no_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "manifest.json")
            summary = os.path.join(tmp, "summary.json")
            args = ["--input-file", FIXTURE, "--out", out, "--allowlist", ALLOWLIST,
                    "--summary-file", summary, "--min-entries", "1",
                    "--now", "2026-08-31T12:00:00Z"]
            self.assertEqual(self.run_cli(args).returncode, 0)
            second = self.run_cli(args + ["--previous", out])
            self.assertEqual(second.returncode, 0, second.stderr)
            with open(summary, encoding="utf-8") as handle:
                self.assertFalse(json.load(handle)["changed"])

    def test_missing_auth_key_fails_loudly_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "manifest.json")
            result = self.run_cli(["--out", out])
            self.assertEqual(result.returncode, 1)
            self.assertIn("ABUSECH_AUTH_KEY", result.stderr)
            self.assertFalse(os.path.exists(out))

    def test_collapse_gate_leaves_the_published_manifest_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            published = os.path.join(tmp, "manifest.json")
            # a healthy published manifest with 60k indicators
            fat = [{"ioc_type": "domain", "ioc_value": "n%d.example" % i,
                    "first_seen": NOW} for i in range(60_000)]
            with open(published, "w", encoding="utf-8") as handle:
                handle.write(bm.render_manifest(fat, NOW, "x", 183, 50))
            with open(published, "rb") as handle:
                before = handle.read()
            result = self.run_cli([
                "--input-file", FIXTURE, "--out", published, "--previous", published,
                "--allowlist", ALLOWLIST, "--min-entries", "1",
                "--now", "2026-08-31T12:00:00Z",
            ])
            self.assertEqual(result.returncode, 1)
            self.assertIn("collapsed", result.stderr)
            with open(published, "rb") as handle:
                self.assertEqual(handle.read(), before)


if __name__ == "__main__":
    unittest.main()
