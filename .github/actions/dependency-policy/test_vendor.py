#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@0ea7fba775f67009a21178f01a807c73c305efca",
        )
        expected = {
            "action.yml": "a3617eea9a33cf8b55333bad9eb238bf112c071036d4e367291952f6d60bf4c0",
            "policy.py": "fae5beff977c7b5ba07a358fd33676074a6c5e2a1f33711d49d0f695c49201b7",
            "repository_invariants.py": "dd3c9ab496baf2b8f3ead07e37a115ed98a4fe7ab0f72ade3c0e1980a7f3a88c",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
