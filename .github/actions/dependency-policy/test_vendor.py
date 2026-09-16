#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@b8e9d2380348409bbdffb5c5bf62402f668e13b6",
        )
        expected = {
            "action.yml": "a3617eea9a33cf8b55333bad9eb238bf112c071036d4e367291952f6d60bf4c0",
            "policy.py": "fe42cd2ba783126c3ffe284bbcb2b504ab754682a26283e1be744928aff5d180",
            "repository_invariants.py": "dd3c9ab496baf2b8f3ead07e37a115ed98a4fe7ab0f72ade3c0e1980a7f3a88c",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
