#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@afb468937d5bd0891c89cd9983d586092793120e",
        )
        expected = {
            "action.yml": "a68eaf2b98eb9c1ea2309e2cceeef395682641cbb6c5c95430ca17c24da7986f",
            "policy.py": "79764b106089a845939c59ff8a41bb6e33dce87fb0168b1b5fd006c23a8edc3d",
            "repository_invariants.py": "c13f1c9fde633ba17cddcbd890ef17ebec919dafa882f368e72efce69cf65a1a",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
