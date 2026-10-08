from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.promotion_authority import PromotionAuthority, verify_bound_grant

ROOT = Path(__file__).resolve().parents[1]


class PromotionProofCompatibilityTests(unittest.TestCase):
    def test_legacy_class_name_produces_non_authoritative_binding(self):
        verifier = PromotionAuthority()
        binding = verifier.issue("GlacierEQ/x", "abc", "def")
        self.assertFalse(binding.project_authority)
        ok, reason = verifier.verify(binding)
        self.assertTrue(ok, reason)

    def test_real_machine_record_is_evidence_only_and_bound_to_proof(self):
        record_path = ROOT / "machine" / "promotion_authority.json"
        proof_path = ROOT / "machine" / "proof_receipt.json"
        if not record_path.is_file() or not proof_path.is_file():
            self.skipTest("receipts not yet bound")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        file_digest = hashlib.sha256(proof_path.read_bytes()).hexdigest()
        self.assertEqual(record["status"], "EVIDENCE_BOUND_NON_AUTHORITATIVE")
        self.assertFalse(record["project_direction_authority"])
        self.assertFalse(record["repository_lifecycle_authority"])
        self.assertFalse(record["cross_repository_authority"])
        self.assertEqual(record["proof_receipt_digest"], file_digest)
        self.assertEqual(record["source_sha"], proof["source_sha"])
        ok, reason = verify_bound_grant(record, proof_path)
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
