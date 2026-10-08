"""Legacy promotion-proof compatibility API with no project authority.

Historical callers may still import PromotionAuthority and PromotionGrant.
Those names are retained only to avoid breaking leaf integrations. The current
objects bind exact-source proof metadata; they cannot authorize promotion, merge,
release, retirement, repository disposition, or cross-repository action.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProofBinding:
    repository: str
    source_sha: str
    proof_receipt_digest: str

    @property
    def project_authority(self) -> bool:
        return False

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ProofBinding":
        return cls(
            repository=str(payload["repository"]),
            source_sha=str(payload["source_sha"]),
            proof_receipt_digest=str(payload["proof_receipt_digest"]),
        )


class ProofBindingVerifier:
    """Verify structural proof bindings only; never project permission."""

    def __init__(self, secret: bytes | None = None, ttl_s: float | None = None):
        self.legacy_parameter_supplied = secret is not None or ttl_s is not None

    def issue(
        self,
        repository: str,
        source_sha: str,
        proof_receipt_digest: str,
        now: float | None = None,
    ) -> ProofBinding:
        del now
        return ProofBinding(repository, source_sha, proof_receipt_digest)

    def verify(
        self,
        binding: ProofBinding,
        now: float | None = None,
    ) -> tuple[bool, str | None]:
        del now
        if not binding.repository or not binding.source_sha or not binding.proof_receipt_digest:
            return False, "BINDING_INCOMPLETE"
        return True, None


PromotionGrant = ProofBinding
PromotionAuthority = ProofBindingVerifier


def verify_bound_grant(
    grant_dict: dict[str, Any],
    proof_receipt_path: str | bytes | Path,
    *,
    secret: bytes | None = None,
    now: float | None = None,
) -> tuple[bool, str | None]:
    """Verify exact-source proof binding on a non-authoritative compatibility record."""

    del secret, now
    path = Path(proof_receipt_path)
    if not path.is_file():
        return False, "PROOF_RECEIPT_MISSING"
    try:
        proof_bytes = path.read_bytes()
        proof = json.loads(proof_bytes.decode("utf-8"))
    except Exception:
        return False, "PROOF_RECEIPT_INVALID"

    if grant_dict.get("status") != "EVIDENCE_BOUND_NON_AUTHORITATIVE":
        return False, "LEGACY_AUTHORITY_RECORD_NOT_MIGRATED"
    for key in (
        "project_direction_authority",
        "repository_lifecycle_authority",
        "cross_repository_authority",
    ):
        if grant_dict.get(key) is not False:
            return False, "AUTHORITY_FLAG_MUST_BE_FALSE"

    digest = hashlib.sha256(proof_bytes).hexdigest()
    if grant_dict.get("proof_receipt_digest") != digest:
        return False, "PROOF_DIGEST_MISMATCH"
    if grant_dict.get("source_sha") != proof.get("source_sha"):
        return False, "SOURCE_SHA_MISMATCH"
    try:
        binding = ProofBinding.from_dict(grant_dict)
    except Exception:
        return False, "BINDING_MALFORMED"
    return ProofBindingVerifier().verify(binding)
