#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@823724812ee7dcd1482c4f43f086669dcb480c05",
        )
        expected = {
            "action.yml": "a3617eea9a33cf8b55333bad9eb238bf112c071036d4e367291952f6d60bf4c0",
            "policy.py": "d72ff3199b5475df8fabad5c1ac763cc3f284eba079b3cd53c6c794746712a68",
            "repository_invariants.py": "3cf8531929363228bc0c5d09c047fe95c41a6248527e4137be5b850419a620b4",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
