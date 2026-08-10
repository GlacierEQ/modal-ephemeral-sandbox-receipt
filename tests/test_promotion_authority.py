from __future__ import annotations
import hashlib, json, unittest
from pathlib import Path
from src.promotion_authority import (
    LOCAL_OPERATOR_SECRET, PromotionAuthority, verify_bound_grant,
)
ROOT = Path(__file__).resolve().parents[1]
class PromotionAuthTests(unittest.TestCase):
    def test_issue_verify(self):
        a = PromotionAuthority(b"test-secret", ttl_s=60)
        g = a.issue("GlacierEQ/x", "abc", "def", now=1000.0)
        ok, r = a.verify(g, now=1001.0)
        self.assertTrue(ok)
    def test_expired(self):
        a = PromotionAuthority(b"test-secret", ttl_s=10)
        g = a.issue("GlacierEQ/x", "abc", "def", now=1000.0)
        ok, r = a.verify(g, now=2000.0)
        self.assertFalse(ok)
        self.assertEqual(r, "GRANT_EXPIRED")
    def test_real_machine_grant_verifies_against_proof_receipt(self):
        grant_path = ROOT / "machine" / "promotion_authority.json"
        proof_path = ROOT / "machine" / "proof_receipt.json"
        if not grant_path.is_file() or not proof_path.is_file():
            self.skipTest("receipts not yet bound")
        grant = json.loads(grant_path.read_text())
        proof = json.loads(proof_path.read_text())
        file_digest = hashlib.sha256(proof_path.read_bytes()).hexdigest()
        self.assertEqual(grant["proof_receipt_digest"], file_digest)
        self.assertEqual(grant["source_sha"], proof["source_sha"])
        ok, reason = verify_bound_grant(grant, proof_path, secret=LOCAL_OPERATOR_SECRET)
        self.assertTrue(ok, reason)
if __name__ == "__main__":
    unittest.main()
