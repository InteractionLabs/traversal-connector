#!/usr/bin/env python3
import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("dependency_cooldown", Path(__file__).with_name("dependency_cooldown.py"))
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class CooldownEvidenceTest(unittest.TestCase):
    def test_public_uses_index_timestamp_not_proxy_commit_time(self):
        commit_time = "2020-01-01T00:00:00Z"
        observed_time = "2026-09-08T00:00:00Z"
        with mock.patch.object(POLICY, "fetch_json", return_value={"Time": commit_time}), mock.patch.object(
            POLICY,
            "fetch_json_lines",
            return_value=[{"Path": "example.com/mod", "Version": "v0.0.0-20200101000000-deadbeef", "Timestamp": observed_time}],
        ):
            observed = POLICY.public_first_observed("example.com/mod", "v0.0.0-20200101000000-deadbeef")
        self.assertEqual(observed, POLICY.parse_time(observed_time))

    def test_exact_reviewed_exception_matches_only_one_version(self):
        now = dt.datetime(2026, 9, 9, tzinfo=dt.timezone.utc)
        record = {"exceptions": [{
            "ecosystem": "go", "artifact": "example.com/mod", "version": "v1.2.3",
            "reason": "urgent security fix", "reference": "SEC-123", "approver": "security@example.com",
            "created_at": "2026-09-08T00:00:00Z", "expires_at": "2026-09-10T00:00:00Z"
        }]}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(POLICY.Path, "read_text", return_value=json.dumps(record)), mock.patch.object(POLICY.Path, "exists", return_value=True):
            self.assertTrue(POLICY.exact_exception("example.com/mod", "v1.2.3", now))
            self.assertFalse(POLICY.exact_exception("example.com/mod", "v1.2.4", now))

    def test_exception_cannot_outlive_known_normal_eligibility(self):
        now = dt.datetime(2026, 9, 9, tzinfo=dt.timezone.utc)
        record = {"exceptions": [{
            "ecosystem": "go", "artifact": "example.com/mod", "version": "v1.2.3",
            "reason": "urgent security fix", "reference": "SEC-123", "approver": "security@example.com",
            "created_at": "2026-09-08T00:00:00Z", "expires_at": "2026-09-12T00:00:00Z"
        }]}
        with mock.patch.object(POLICY.Path, "read_text", return_value=json.dumps(record)), mock.patch.object(POLICY.Path, "exists", return_value=True):
            with self.assertRaisesRegex(ValueError, "after normal eligibility"):
                POLICY.exact_exception("example.com/mod", "v1.2.3", now, dt.datetime(2026, 9, 10, tzinfo=dt.timezone.utc))

    def test_exception_cannot_authorize_missing_evidence(self):
        with mock.patch.object(
            POLICY,
            "modules_at",
            side_effect=[{}, {"example.com/mod": "v1.2.3"}],
        ), mock.patch.object(
            POLICY,
            "public_first_observed",
            side_effect=RuntimeError("registry outage"),
        ), mock.patch.object(
            POLICY,
            "exact_exception",
            side_effect=AssertionError("exception must not be consulted"),
        ):
            with self.assertRaisesRegex(SystemExit, "missing trustworthy"):
                POLICY.verify("base")


if __name__ == "__main__":
    unittest.main()
