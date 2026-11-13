#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@f542389b8107d1bc0b54f8b73cd36152d06d9a1e",
        )
        expected = {
            "action.yml": "13d077722e6309049802bde7b30e6df10ca8ccb4894e2d5e01d247ac23bb22dc",
            "policy.py": "babf9051e13b89667316889d216bfcb5ed0819ed8ba282a4c95c22d02bb63d30",
            "resolve_base.py": "d4e230f80888eedbe9ed9e665ac6e35c34038c5f5162defba712f45aec991967",
            "repository_invariants.py": "b00c007200a73a0aa5ce371157961bd1d05136e25b3c589659d2daa922d19267",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
