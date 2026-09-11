#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/actions/dependency-cooldown"


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@7f488debf398a01e91fb55a456fb00778b766c39",
        )
        expected = {
            "dependency_cooldown.py": "83196441214a0c552fde057f389b9f052bb5f1b451fee3ae3edee2a2f2e66aa6",
            "dependency_policy_invariants.py": "5866d5d5de73c5eea156bd4e3ba19b9a0a3c640e9e10ddb6c857e3ff9f33c08e",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
