"""Promotion authority — short-lived HMAC grant for PROMOTED gate.

Independent reference. Not Helix; local operator authority for this leaf.

Auditors re-verify grants with LOCAL_OPERATOR_SECRET and
scripts/verify_promotion_grant.py against machine/promotion_authority.json
bound to machine/proof_receipt.json digest + source_sha.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass


# Reference local operator secret (NOT production). Documented for re-verification.
LOCAL_OPERATOR_SECRET = b"glaciereq-local-operator-promotion-authority-v1"


def _digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class PromotionGrant:
    repository: str
    source_sha: str
    proof_receipt_digest: str
    not_after: float
    mac: str

    def fingerprint(self) -> str:
        return _digest({
            "repository": self.repository,
            "source_sha": self.source_sha,
            "proof_receipt_digest": self.proof_receipt_digest,
            "not_after": self.not_after,
            "mac": self.mac,
        })

    @classmethod
    def from_dict(cls, d: dict) -> "PromotionGrant":
        return cls(
            repository=d["repository"],
            source_sha=d["source_sha"],
            proof_receipt_digest=d["proof_receipt_digest"],
            not_after=float(d["not_after"]),
            mac=d["mac"],
        )


class PromotionAuthority:
    def __init__(self, secret: bytes, ttl_s: float = 3600.0):
        if not secret:
            raise ValueError("secret required")
        if ttl_s <= 0:
            raise ValueError("ttl")
        self._secret = secret
        self._ttl = ttl_s

    def issue(self, repository: str, source_sha: str, proof_receipt_digest: str, now: float | None = None) -> PromotionGrant:
        t = time.time() if now is None else now
        na = t + self._ttl
        body = f"{repository}|{source_sha}|{proof_receipt_digest}|{na}"
        mac = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return PromotionGrant(repository, source_sha, proof_receipt_digest, na, mac)

    def verify(self, grant: PromotionGrant, now: float | None = None) -> tuple[bool, str | None]:
        t = time.time() if now is None else now
        if t > grant.not_after:
            return False, "GRANT_EXPIRED"
        body = f"{grant.repository}|{grant.source_sha}|{grant.proof_receipt_digest}|{grant.not_after}"
        mac = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, grant.mac):
            return False, "BAD_MAC"
        return True, None


def verify_bound_grant(
    grant_dict: dict,
    proof_receipt_path: str | bytes | "Path",
    *,
    secret: bytes = LOCAL_OPERATOR_SECRET,
    now: float | None = None,
) -> tuple[bool, str | None]:
    """Verify a machine/promotion_authority.json grant against a proof receipt file.

    Checks:
      1) proof_receipt_digest == sha256(proof file bytes)
      2) grant.source_sha == proof.source_sha
      3) HMAC verify with operator secret
    Fail-closed on any mismatch.
    """
    from pathlib import Path as _P
    path = _P(proof_receipt_path)
    if not path.is_file():
        return False, "PROOF_RECEIPT_MISSING"
    proof_bytes = path.read_bytes()
    file_digest = hashlib.sha256(proof_bytes).hexdigest()
    try:
        proof = json.loads(proof_bytes.decode())
    except Exception:
        return False, "PROOF_RECEIPT_INVALID_JSON"
    if grant_dict.get("proof_receipt_digest") != file_digest:
        return False, "PROOF_DIGEST_MISMATCH"
    if grant_dict.get("source_sha") != proof.get("source_sha"):
        return False, "SOURCE_SHA_MISMATCH"
    try:
        grant = PromotionGrant.from_dict(grant_dict)
    except Exception:
        return False, "GRANT_MALFORMED"
    auth = PromotionAuthority(secret, ttl_s=max(1.0, float(grant.not_after) - (now or time.time()) + 1.0))
    return auth.verify(grant, now=now)
