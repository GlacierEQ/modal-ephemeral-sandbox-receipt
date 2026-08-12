"""Deterministic post-run receipts for ephemeral sandbox executions.

This module verifies declared execution facts and policy invariants. It does not
execute untrusted code and it does not claim provider attestation unless a
separate adapter supplies authenticated run evidence.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import posixpath
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class EphemeralSandboxReceiptRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 4.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class EphemeralSandboxReceiptReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "digest": self.digest,
            "metrics": self.metrics,
            "result": self.result,
        }


class EphemeralSandboxReceipt:
    """Normalize sandbox run facts and enforce a post-run integrity policy."""

    VALID_PAYLOAD_KEYS = frozenset({"now", "run", "policy", "expected_receipt_digest"})
    RUN_KEYS = frozenset(
        {
            "sandbox_id",
            "image_digest",
            "input_digest",
            "started_at",
            "ended_at",
            "exit_code",
            "usage",
            "network_destinations",
            "files",
            "stdout_digest",
            "stderr_digest",
            "isolation",
        }
    )
    POLICY_KEYS = frozenset(
        {
            "allowed_image_digests",
            "allowed_network_destinations",
            "max_usage",
            "require_zero_exit",
            "require_ephemeral_rootfs",
            "require_network_policy",
            "require_secret_scrub",
            "require_revoked",
        }
    )
    USAGE_KEYS = frozenset(
        {"wall_seconds", "cpu_seconds", "memory_mb_seconds", "network_egress_bytes", "output_bytes"}
    )
    ISOLATION_KEYS = frozenset(
        {"ephemeral_rootfs", "network_policy_enforced", "secrets_scrubbed", "revoked"}
    )
    FILE_KEYS = frozenset({"path", "sha256", "size", "change"})
    FILE_CHANGES = frozenset({"created", "modified", "deleted", "unchanged"})
    MAX_FILES = 4096
    MAX_NETWORK_DESTINATIONS = 512
    MAX_PATTERNS = 512
    MAX_TEXT = 4096
    MAX_INPUT_CHARS = 2_000_000
    BASE_WORK = 0.5
    ITEM_WORK = 0.005

    @classmethod
    def _text(cls, value: Any, label: str, *, lower: bool = False) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{label}_type_invalid")
        value = value.strip()
        if not value:
            raise ValueError(f"{label}_missing")
        if len(value) > cls.MAX_TEXT:
            raise ValueError(f"{label}_too_long")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError(f"{label}_control_character")
        return value.lower() if lower else value

    @staticmethod
    def _number(value: Any, label: str, *, minimum: float = 0.0) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{label}_invalid")
        value = float(value)
        if not math.isfinite(value) or value < minimum:
            raise ValueError(f"{label}_invalid")
        return value

    @staticmethod
    def _integer(value: Any, label: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{label}_invalid")
        return value

    @staticmethod
    def _boolean(value: Any, label: str) -> bool:
        if not isinstance(value, bool):
            raise ValueError(f"{label}_invalid")
        return value

    @staticmethod
    def _sha(value: Any, label: str, *, optional: bool = False) -> str | None:
        if value is None and optional:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{label}_type_invalid")
        value = value.lower()
        if not _SHA256.fullmatch(value):
            raise ValueError(f"{label}_invalid")
        return value

    @classmethod
    def _file_path(cls, value: Any, label: str) -> str:
        value = cls._text(value, label)
        if value.startswith("/") or "\\" in value:
            raise ValueError(f"{label}_invalid")
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError(f"{label}_invalid")
        normalized = posixpath.normpath(value)
        if normalized in {".", ".."} or normalized.startswith("../"):
            raise ValueError(f"{label}_escape")
        return normalized

    @classmethod
    def _network_target(cls, value: Any, label: str, *, pattern: bool) -> str:
        target = cls._text(value, label, lower=True)
        if "/" in target or "\\" in target or " " in target or target.count(":") != 1:
            raise ValueError(f"{label}_invalid")
        host, port = target.rsplit(":", 1)
        if not host or not port:
            raise ValueError(f"{label}_invalid")
        if pattern:
            if host.startswith("*."):
                suffix = host[2:]
                if not suffix or "*" in suffix:
                    raise ValueError(f"{label}_invalid")
            elif "*" in host:
                raise ValueError(f"{label}_invalid")
            if port != "*" and (not port.isdigit() or not 1 <= int(port) <= 65535):
                raise ValueError(f"{label}_port_invalid")
        else:
            if "*" in host or "*" in port:
                raise ValueError(f"{label}_wildcard_not_allowed")
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError(f"{label}_port_invalid")
        return f"{host}:{port}"

    @classmethod
    def _usage(cls, raw: Any, label: str) -> dict[str, float]:
        if not isinstance(raw, Mapping):
            raise ValueError(f"{label}_invalid")
        unknown = set(raw) - cls.USAGE_KEYS
        if unknown:
            raise ValueError(f"{label}_keys_unknown:" + ",".join(sorted(unknown)))
        result: dict[str, float] = {}
        for key in sorted(cls.USAGE_KEYS):
            result[key] = cls._number(raw.get(key, 0.0), f"{label}_{key}")
        return result

    @classmethod
    def _isolation(cls, raw: Any) -> dict[str, bool]:
        if not isinstance(raw, Mapping):
            raise ValueError("isolation_invalid")
        unknown = set(raw) - cls.ISOLATION_KEYS
        if unknown:
            raise ValueError("isolation_keys_unknown:" + ",".join(sorted(unknown)))
        return {
            key: cls._boolean(raw.get(key), f"isolation_{key}")
            for key in sorted(cls.ISOLATION_KEYS)
        }

    @classmethod
    def _file(cls, raw: Any, index: int) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise ValueError(f"file_{index}_not_object")
        unknown = set(raw) - cls.FILE_KEYS
        if unknown:
            raise ValueError(f"file_{index}_keys_unknown:" + ",".join(sorted(unknown)))
        change = cls._text(raw.get("change"), f"file_{index}_change", lower=True)
        if change not in cls.FILE_CHANGES:
            raise ValueError(f"file_{index}_change_invalid")
        path = cls._file_path(raw.get("path"), f"file_{index}_path")
        size = cls._integer(raw.get("size", 0), f"file_{index}_size")
        if size < 0:
            raise ValueError(f"file_{index}_size_invalid")
        sha = cls._sha(raw.get("sha256"), f"file_{index}_sha256", optional=change == "deleted")
        if change != "deleted" and sha is None:
            raise ValueError(f"file_{index}_sha256_missing")
        return {"path": path, "sha256": sha, "size": size, "change": change}

    @classmethod
    def _normalize_run(cls, raw: Any) -> tuple[dict[str, Any], int]:
        if not isinstance(raw, Mapping):
            raise ValueError("run_missing")
        unknown = set(raw) - cls.RUN_KEYS
        if unknown:
            raise ValueError("run_keys_unknown:" + ",".join(sorted(unknown)))
        started_at = cls._number(raw.get("started_at"), "run_started_at")
        ended_at = cls._number(raw.get("ended_at"), "run_ended_at")
        if ended_at < started_at:
            raise ValueError("run_time_order_invalid")
        network_raw = raw.get("network_destinations", [])
        if not isinstance(network_raw, list):
            raise ValueError("network_destinations_invalid")
        if len(network_raw) > cls.MAX_NETWORK_DESTINATIONS:
            raise ValueError("network_destinations_over_limit")
        network = sorted(
            {
                cls._network_target(value, f"network_destination_{index}", pattern=False)
                for index, value in enumerate(network_raw)
            }
        )
        files_raw = raw.get("files", [])
        if not isinstance(files_raw, list):
            raise ValueError("files_invalid")
        if len(files_raw) > cls.MAX_FILES:
            raise ValueError("files_over_limit")
        files = [cls._file(value, index) for index, value in enumerate(files_raw)]
        if len({item["path"] for item in files}) != len(files):
            raise ValueError("duplicate_file_path")
        files.sort(key=lambda item: item["path"])
        result = {
            "sandbox_id": cls._text(raw.get("sandbox_id"), "run_sandbox_id"),
            "image_digest": cls._sha(raw.get("image_digest"), "run_image_digest"),
            "input_digest": cls._sha(raw.get("input_digest"), "run_input_digest"),
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": ended_at - started_at,
            "exit_code": cls._integer(raw.get("exit_code"), "run_exit_code"),
            "usage": cls._usage(raw.get("usage"), "run_usage"),
            "network_destinations": network,
            "files": files,
            "stdout_digest": cls._sha(raw.get("stdout_digest"), "run_stdout_digest", optional=True),
            "stderr_digest": cls._sha(raw.get("stderr_digest"), "run_stderr_digest", optional=True),
            "isolation": cls._isolation(raw.get("isolation")),
        }
        return result, len(network) + len(files)

    @classmethod
    def _normalize_policy(cls, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise ValueError("policy_missing")
        unknown = set(raw) - cls.POLICY_KEYS
        if unknown:
            raise ValueError("policy_keys_unknown:" + ",".join(sorted(unknown)))
        images_raw = raw.get("allowed_image_digests", [])
        if not isinstance(images_raw, list) or not images_raw:
            raise ValueError("policy_allowed_image_digests_invalid")
        if len(images_raw) > cls.MAX_PATTERNS:
            raise ValueError("policy_allowed_image_digests_over_limit")
        images = sorted(
            {
                cls._sha(value, f"policy_allowed_image_digest_{index}")
                for index, value in enumerate(images_raw)
            }
        )
        network_raw = raw.get("allowed_network_destinations", [])
        if not isinstance(network_raw, list):
            raise ValueError("policy_allowed_network_destinations_invalid")
        if len(network_raw) > cls.MAX_PATTERNS:
            raise ValueError("policy_allowed_network_destinations_over_limit")
        network = sorted(
            {
                cls._network_target(value, f"policy_network_{index}", pattern=True)
                for index, value in enumerate(network_raw)
            }
        )
        return {
            "allowed_image_digests": images,
            "allowed_network_destinations": network,
            "max_usage": cls._usage(raw.get("max_usage", {}), "policy_max_usage"),
            "require_zero_exit": cls._boolean(raw.get("require_zero_exit", True), "policy_require_zero_exit"),
            "require_ephemeral_rootfs": cls._boolean(raw.get("require_ephemeral_rootfs", True), "policy_require_ephemeral_rootfs"),
            "require_network_policy": cls._boolean(raw.get("require_network_policy", True), "policy_require_network_policy"),
            "require_secret_scrub": cls._boolean(raw.get("require_secret_scrub", True), "policy_require_secret_scrub"),
            "require_revoked": cls._boolean(raw.get("require_revoked", True), "policy_require_revoked"),
        }

    @staticmethod
    def _network_matches(target: str, pattern: str) -> bool:
        host, port = target.rsplit(":", 1)
        pattern_host, pattern_port = pattern.rsplit(":", 1)
        if pattern_host.startswith("*."):
            suffix = pattern_host[2:]
            host_ok = host.endswith("." + suffix) and host != suffix
        else:
            host_ok = host == pattern_host
        return host_ok and (pattern_port == "*" or pattern_port == port)

    @classmethod
    def _violations(cls, run: Mapping[str, Any], policy: Mapping[str, Any]) -> list[dict[str, Any]]:
        violations: list[dict[str, Any]] = []
        if run["image_digest"] not in set(policy["allowed_image_digests"]):
            violations.append({"kind": "image_not_allowed", "value": run["image_digest"]})
        if policy["require_zero_exit"] and run["exit_code"] != 0:
            violations.append({"kind": "nonzero_exit", "value": run["exit_code"]})
        for key, maximum in policy["max_usage"].items():
            if run["usage"][key] > maximum:
                violations.append(
                    {
                        "kind": "usage_limit_exceeded",
                        "resource": key,
                        "value": run["usage"][key],
                        "maximum": maximum,
                    }
                )
        patterns = policy["allowed_network_destinations"]
        for target in run["network_destinations"]:
            if not any(cls._network_matches(target, pattern) for pattern in patterns):
                violations.append({"kind": "network_destination_not_allowed", "value": target})
        isolation = run["isolation"]
        required_flags = {
            "ephemeral_rootfs": policy["require_ephemeral_rootfs"],
            "network_policy_enforced": policy["require_network_policy"],
            "secrets_scrubbed": policy["require_secret_scrub"],
            "revoked": policy["require_revoked"],
        }
        for key, required in required_flags.items():
            if required and not isolation[key]:
                violations.append({"kind": "isolation_invariant_failed", "invariant": key})
        violations.sort(key=lambda item: json.dumps(item, sort_keys=True))
        return violations

    def evaluate(self, req: EphemeralSandboxReceiptRequest) -> EphemeralSandboxReceiptReceipt:
        if not isinstance(req, EphemeralSandboxReceiptRequest):
            raise TypeError("req must be EphemeralSandboxReceiptRequest")
        reasons: list[str] = []
        try:
            subject_id = self._text(req.subject_id, "subject_id")
        except ValueError as exc:
            subject_id = ""
            reasons.append(str(exc))
        try:
            budget = self._number(req.budget, "budget", minimum=0.001)
        except ValueError as exc:
            budget = 0.0
            reasons.append(str(exc))
        grant_reference: str | None = None
        if req.grant_id is not None:
            try:
                grant_reference = self._text(req.grant_id, "grant_id")
            except ValueError as exc:
                reasons.append(str(exc))
        if not isinstance(req.payload, Mapping):
            payload: Mapping[str, Any] = {}
            reasons.append("payload_not_object")
        else:
            payload = req.payload
            unknown = set(payload) - self.VALID_PAYLOAD_KEYS
            if unknown:
                reasons.append("payload_keys_unknown:" + ",".join(sorted(unknown)))

        now: float | None = None
        if payload.get("now") is not None:
            try:
                now = self._number(payload.get("now"), "now")
            except ValueError as exc:
                reasons.append(str(exc))
        if req.not_after is not None:
            try:
                not_after = self._number(req.not_after, "not_after")
                if now is None:
                    reasons.append("not_after_requires_now")
                elif now > not_after:
                    reasons.append("request_expired")
            except ValueError as exc:
                reasons.append(str(exc))

        result: dict[str, Any] = {}
        work_units = self.BASE_WORK
        try:
            run_raw = payload.get("run")
            policy_raw = payload.get("policy")
            preflight_files = len(run_raw.get("files", [])) if isinstance(run_raw, Mapping) and isinstance(run_raw.get("files", []), list) else 0
            preflight_network = len(run_raw.get("network_destinations", [])) if isinstance(run_raw, Mapping) and isinstance(run_raw.get("network_destinations", []), list) else 0
            work_units += (preflight_files + preflight_network) * self.ITEM_WORK
            if work_units > budget:
                reasons.append("work_budget_exceeded")
            else:
                run, item_count = self._normalize_run(run_raw)
                policy = self._normalize_policy(policy_raw)
                work_units = self.BASE_WORK + item_count * self.ITEM_WORK
                violations = self._violations(run, policy)
                if violations:
                    reasons.append("sandbox_policy_violation")
                manifest = {
                    "schema": "glaciereq.ephemeral-sandbox-receipt.v1",
                    "run": run,
                    "policy": policy,
                    "run_digest": _digest(run),
                    "policy_digest": _digest(policy),
                }
                receipt_digest = _digest(manifest)
                expected = payload.get("expected_receipt_digest")
                if expected is not None:
                    expected = self._sha(expected, "expected_receipt_digest")
                    if expected != receipt_digest:
                        reasons.append("expected_receipt_digest_mismatch")
                result = {
                    "grant_reference": grant_reference,
                    "manifest": manifest,
                    "receipt_digest": receipt_digest,
                    "violations": violations,
                    "policy_compliant": not violations,
                }
        except ValueError as exc:
            reasons.append(str(exc))

        decision = Decision.REFUSE if reasons else Decision.ALLOW
        if not reasons:
            reasons = ["sandbox_run_receipt_verified"]
        metrics = {
            "grant_reference": grant_reference,
            "work_units": work_units,
            "budget_units": budget,
            "violation_count": len(result.get("violations", [])),
            "file_count": len(result.get("manifest", {}).get("run", {}).get("files", [])),
            "network_destination_count": len(
                result.get("manifest", {}).get("run", {}).get("network_destinations", [])
            ),
        }
        digest = _digest(
            {
                "subject_id": subject_id,
                "decision": decision.value,
                "reasons": reasons,
                "result": result,
                "metrics": metrics,
            }
        )
        return EphemeralSandboxReceiptReceipt(
            decision=decision,
            reasons=tuple(reasons),
            digest=digest,
            metrics=metrics,
            result=result,
        )


Mechanism = EphemeralSandboxReceipt


def _read_input(path: str | None) -> str:
    limit = EphemeralSandboxReceipt.MAX_INPUT_CHARS
    if path:
        source = Path(path)
        if source.stat().st_size > limit * 4:
            raise ValueError("input_too_large")
        raw = source.read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input_too_large")
    return raw


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an ephemeral sandbox run receipt from JSON.")
    parser.add_argument("--input", "-i", help="request JSON file; defaults to stdin")
    args = parser.parse_args(argv)
    try:
        data = json.loads(_read_input(args.input))
        if not isinstance(data, Mapping):
            raise ValueError("request JSON must be an object")
        payload = data.get("payload", {})
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be an object")
        receipt = EphemeralSandboxReceipt().evaluate(
            EphemeralSandboxReceiptRequest(
                subject_id=data.get("subject_id", ""),
                payload=dict(payload),
                budget=data.get("budget", 4.0),
                grant_id=data.get("grant_id"),
                not_after=data.get("not_after"),
            )
        )
    except Exception as exc:
        print(
            json.dumps(
                {"decision": "REFUSE", "reasons": [f"cli_input_error:{type(exc).__name__}:{exc}"]},
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2
