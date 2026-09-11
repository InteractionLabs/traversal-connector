#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/actions/dependency-policy"


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@2fdbee2264343826b354f92d8e1787f8df65035c",
        )
        expected = {
            "dependency_policy.py": "7d4e99e286b69d5d3df3ffbe56a9da2b98f4df9edae66639cd008659f1f2b53d",
            "dependency_policy_invariants.py": "3ee3714e1df09a2112e22074068b20ce59e9c8a5056aca687ebc356fd2f5b68f",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
