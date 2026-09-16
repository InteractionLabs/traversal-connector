#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@77b320bf486076813b1db60159b7785b03427ca8",
        )
        expected = {
            "action.yml": "a3617eea9a33cf8b55333bad9eb238bf112c071036d4e367291952f6d60bf4c0",
            "policy.py": "0157bac891a43d39afa7e653e70a99b896ae805b15cce89e2edddd155b46764d",
            "repository_invariants.py": "77e0eb2b64d7b82a39d056ce845218ba5962df743024fe8ce4edf9f17b62a442",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
