#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@1c731caec408c99828ff3415c6be3691d5b7f687",
        )
        expected = {
            "action.yml": "42a60790c45ba3c93c450cc6a8aa7a6ae67a59830edb7e9ec2f19d8cdcea3929",
            "policy.py": "fae5beff977c7b5ba07a358fd33676074a6c5e2a1f33711d49d0f695c49201b7",
            "repository_invariants.py": "264cca662f3d26d1a9c8453d6aea73e3c48bf04bb1af82b28131a37f947b665a",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
