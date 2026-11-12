#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@f63af3ceb2728f1155836f22d0ccc111ce1595cd",
        )
        expected = {
            "action.yml": "b1b5fdaceb6adaef68b416a3434d5512971e6856239569661a5304efe2aaff15",
            "policy.py": "05c7877b14d507a7d8fa2b4decb1dd469f851a9fc8af34f0314fdccfc6c0c900",
            "resolve_base.py": "bd3da0f8356ba3cf531d9cb9132d42da6a5bd7f2b3da4e25dcf3cf99dfdde3f0",
            "repository_invariants.py": "57858bf11fd53159dc92ebada74cb5e233ab997f34b1c5d879ecbc8651c6d114",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
