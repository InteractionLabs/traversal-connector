#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@8695dbcc829b8c848bfd5f14c511da867f22e99c",
        )
        expected = {
            "action.yml": "42a60790c45ba3c93c450cc6a8aa7a6ae67a59830edb7e9ec2f19d8cdcea3929",
            "policy.py": "79764b106089a845939c59ff8a41bb6e33dce87fb0168b1b5fd006c23a8edc3d",
            "repository_invariants.py": "b226f376bb05446ed579609e1e51543c30431e1006c034a0ff537446552a1c53",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
