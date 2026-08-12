"""Ephemeral Sandbox Receipt.

Attests an untrusted sandbox run against an explicit input digest and resource
budget, then refuses success unless post-run filesystem/output integrity and
secret/capability revocation are complete. Receipts are independently
re-verifiable without rerunning the workload.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class EphemeralSandboxReceiptRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 1.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class EphemeralSandboxReceiptReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "reasons": list(self.reasons), "digest": self.digest, "metrics": self.metrics}


class SandboxError(ValueError):
    pass


class EphemeralSandboxReceipt:
    MIN_BUDGET = 0.0

    @staticmethod
    def _num(value: Any, label: str, *, minimum: float | None = None) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SandboxError(f"{label}_invalid")
        value = float(value)
        if not math.isfinite(value):
            raise SandboxError(f"{label}_not_finite")
        if minimum is not None and value < minimum:
            raise SandboxError(f"{label}_below_minimum")
        return value

    @staticmethod
    def _sha(value: Any, label: str) -> str:
        value = str(value or "").strip()
        if not SHA256_RE.fullmatch(value):
            raise SandboxError(f"{label}_invalid_sha256")
        return value

    @staticmethod
    def _id(value: Any, label: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise SandboxError(f"{label}_missing")
        return value

    @classmethod
    def _limits(cls, raw: Any) -> dict[str, float]:
        if not isinstance(raw, dict):
            raise SandboxError("resource_limits_missing")
        return {
            "cpu_seconds": cls._num(raw.get("cpu_seconds"), "limit_cpu_seconds", minimum=0),
            "memory_mb": cls._num(raw.get("memory_mb"), "limit_memory_mb", minimum=0),
            "network_bytes": cls._num(raw.get("network_bytes"), "limit_network_bytes", minimum=0),
            "wall_seconds": cls._num(raw.get("wall_seconds"), "limit_wall_seconds", minimum=0),
            "output_bytes": cls._num(raw.get("output_bytes"), "limit_output_bytes", minimum=0),
        }

    @classmethod
    def _observed(cls, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise SandboxError("observed_run_missing")
        destinations = raw.get("network_destinations", [])
        if not isinstance(destinations, list) or any(not str(v).strip() for v in destinations):
            raise SandboxError("network_destinations_invalid")
        revoked = raw.get("revoked_capabilities", [])
        if not isinstance(revoked, list) or any(not str(v).strip() for v in revoked):
            raise SandboxError("revoked_capabilities_invalid")
        return {
            "cpu_seconds": cls._num(raw.get("cpu_seconds"), "observed_cpu_seconds", minimum=0),
            "memory_mb": cls._num(raw.get("memory_mb"), "observed_memory_mb", minimum=0),
            "network_bytes": cls._num(raw.get("network_bytes"), "observed_network_bytes", minimum=0),
            "wall_seconds": cls._num(raw.get("wall_seconds"), "observed_wall_seconds", minimum=0),
            "output_bytes": cls._num(raw.get("output_bytes"), "observed_output_bytes", minimum=0),
            "exit_code": int(cls._num(raw.get("exit_code"), "exit_code")),
            "output_digest": cls._sha(raw.get("output_digest"), "output_digest"),
            "final_fs_digest": cls._sha(raw.get("final_fs_digest"), "final_fs_digest"),
            "network_destinations": sorted(set(str(v).strip() for v in destinations)),
            "revoked_capabilities": sorted(set(str(v).strip() for v in revoked)),
            "filesystem_destroyed": raw.get("filesystem_destroyed") is True,
        }

    @classmethod
    def _attest(cls, payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        run_id = cls._id(payload.get("run_id"), "run_id")
        input_digest = cls._sha(payload.get("input_digest"), "input_digest")
        limits = cls._limits(payload.get("resource_limits"))
        observed = cls._observed(payload.get("observed_run"))
        allowed_destinations_raw = payload.get("allowed_network_destinations", [])
        required_revocations_raw = payload.get("required_revocations", [])
        if not isinstance(allowed_destinations_raw, list) or not isinstance(required_revocations_raw, list):
            raise SandboxError("policy_lists_invalid")
        allowed_destinations = {str(v).strip() for v in allowed_destinations_raw if str(v).strip()}
        required_revocations = {str(v).strip() for v in required_revocations_raw if str(v).strip()}
        reasons: list[str] = []
        for field_name in ("cpu_seconds", "memory_mb", "network_bytes", "wall_seconds", "output_bytes"):
            if observed[field_name] > limits[field_name]:
                reasons.append(f"resource_budget_exceeded:{field_name}")
        unexpected_destinations = sorted(set(observed["network_destinations"]) - allowed_destinations)
        if unexpected_destinations:
            reasons.append("network_destination_outside_policy")
        missing_revocations = sorted(required_revocations - set(observed["revoked_capabilities"]))
        if missing_revocations:
            reasons.append("required_capability_not_revoked")
        if not observed["filesystem_destroyed"]:
            reasons.append("ephemeral_filesystem_not_destroyed")
        expected_exit_codes = payload.get("allowed_exit_codes", [0])
        if not isinstance(expected_exit_codes, list) or any(isinstance(v, bool) or not isinstance(v, int) for v in expected_exit_codes):
            raise SandboxError("allowed_exit_codes_invalid")
        if observed["exit_code"] not in expected_exit_codes:
            reasons.append("exit_code_outside_policy")
        receipt_body = {
            "schema": "glaciereq.ephemeral-sandbox-receipt.v1",
            "run_id": run_id,
            "input_digest": input_digest,
            "resource_limits": limits,
            "observed_run": observed,
            "allowed_network_destinations": sorted(allowed_destinations),
            "required_revocations": sorted(required_revocations),
            "unexpected_destinations": unexpected_destinations,
            "missing_revocations": missing_revocations,
            "integrity_ok": not reasons,
        }
        return {**receipt_body, "receipt_digest": _digest(receipt_body)}, reasons

    @classmethod
    def _verify(cls, payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        receipt = payload.get("receipt")
        if not isinstance(receipt, dict):
            raise SandboxError("receipt_missing")
        supplied_digest = str(receipt.get("receipt_digest", ""))
        if not SHA256_RE.fullmatch(supplied_digest):
            raise SandboxError("receipt_digest_invalid_sha256")
        body = {k: v for k, v in receipt.items() if k != "receipt_digest"}
        reasons: list[str] = []
        if _digest(body) != supplied_digest:
            reasons.append("receipt_digest_mismatch")
        if body.get("integrity_ok") is not True:
            reasons.append("receipt_records_integrity_failure")
        expected_input = payload.get("expected_input_digest")
        if expected_input is not None and str(expected_input) != body.get("input_digest"):
            reasons.append("input_digest_mismatch")
        return {"verified": not reasons, "run_id": body.get("run_id"), "receipt_digest": supplied_digest}, reasons

    def evaluate(self, req: EphemeralSandboxReceiptRequest) -> EphemeralSandboxReceiptReceipt:
        reasons: list[str] = []
        if not str(req.subject_id or "").strip():
            reasons.append("subject_id_missing")
        if isinstance(req.budget, bool) or not isinstance(req.budget, (int, float)) or not math.isfinite(float(req.budget)) or float(req.budget) <= self.MIN_BUDGET:
            reasons.append("budget_non_positive_or_invalid")
        payload = req.payload if isinstance(req.payload, dict) else {}
        if not isinstance(req.payload, dict):
            reasons.append("payload_not_object")
        result = None
        try:
            mode = str(payload.get("mode", "attest")).lower()
            if mode == "attest":
                receipt, mode_reasons = self._attest(payload)
                result = {"receipt": receipt}
            elif mode == "verify":
                result, mode_reasons = self._verify(payload)
            else:
                raise SandboxError("mode_invalid")
            reasons.extend(mode_reasons)
        except SandboxError as exc:
            reasons.append(str(exc))
        decision = Decision.REFUSE if reasons else Decision.ALLOW
        metrics = {"result": result}
        body = {"subject_id": req.subject_id, "decision": decision.value, "reasons": reasons, "metrics": metrics}
        return EphemeralSandboxReceiptReceipt(decision, tuple(reasons or ["sandbox_integrity_receipt_verified"]), _digest(body), metrics)


Mechanism = EphemeralSandboxReceipt
