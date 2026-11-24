#!/usr/bin/env python3
import hashlib
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parent


class DependencyPolicyVendorTest(unittest.TestCase):
    def test_policy_matches_declared_infrastructure_source(self):
        self.assertEqual(
            (POLICY / "SOURCE").read_text().strip(),
            "InteractionLabs/infrastructure@b42e1f5671665df51536ba0e94811bea6c374f37",
        )
        expected = {
            "action.yml": "c0905bf8ed0bdc629f435ffc517f87e207a68f7d26c6aa7e911c2f343b96e967",
            "policy.py": "5a345658946fc7207548e41364fb95c531ddfe70423ab56b6bcb9bcf878d9e9d",
            "repository_invariants.py": "b00c007200a73a0aa5ce371157961bd1d05136e25b3c589659d2daa922d19267",
            "resolve_base.py": "3a4ba3d2977290ce9104517e918ef4a8e01489e230f29c2adf43b81cbf119da2",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((POLICY / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
