#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@b643da6e4e60678e13f86124e74d2a08c7ae6e5a",
        )
        expected = {
            "action.yml": "deb89725a4b7ac2c7ade7dcfd83a64ba4f0be0d42fed04c78914444f2810904c",
            "policy.py": "03cd82ea1ff93530da41cc66bd87388a16251b375269d6af28ef8aa560395f39",
            "repository_invariants.py": "3cf8531929363228bc0c5d09c047fe95c41a6248527e4137be5b850419a620b4",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
