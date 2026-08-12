#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ephemeral_sandbox_receipt import Decision, EphemeralSandboxReceipt, EphemeralSandboxReceiptRequest

IMAGE = "a" * 64


def _run() -> dict:
    return {
        "sandbox_id": "operate-sbx",
        "image_digest": IMAGE,
        "input_digest": "b" * 64,
        "started_at": 100.0,
        "ended_at": 102.0,
        "exit_code": 0,
        "usage": {
            "wall_seconds": 2.0,
            "cpu_seconds": 1.0,
            "memory_mb_seconds": 200.0,
            "network_egress_bytes": 512.0,
            "output_bytes": 1024.0,
        },
        "network_destinations": ["api.example.com:443"],
        "files": [{"path": "out/result.json", "sha256": "c" * 64, "size": 100, "change": "created"}],
        "stdout_digest": "d" * 64,
        "stderr_digest": None,
        "isolation": {
            "ephemeral_rootfs": True,
            "network_policy_enforced": True,
            "secrets_scrubbed": True,
            "revoked": True,
        },
    }


def _policy() -> dict:
    return {
        "allowed_image_digests": [IMAGE],
        "allowed_network_destinations": ["*.example.com:443"],
        "max_usage": {
            "wall_seconds": 5.0,
            "cpu_seconds": 4.0,
            "memory_mb_seconds": 512.0,
            "network_egress_bytes": 4096.0,
            "output_bytes": 4096.0,
        },
        "require_zero_exit": True,
        "require_ephemeral_rootfs": True,
        "require_network_policy": True,
        "require_secret_scrub": True,
        "require_revoked": True,
    }


def _evaluate(run: dict, policy: dict, expected: str | None = None):
    payload = {"now": 103.0, "run": run, "policy": policy}
    if expected is not None:
        payload["expected_receipt_digest"] = expected
    return EphemeralSandboxReceipt().evaluate(
        EphemeralSandboxReceiptRequest("operate", payload, budget=4.0)
    )


def main() -> int:
    baseline = _evaluate(_run(), _policy())
    if baseline.decision is not Decision.ALLOW:
        print(json.dumps(baseline.as_dict(), indent=2, sort_keys=True))
        return 2
    expected = baseline.result["receipt_digest"]
    rebound = _evaluate(_run(), _policy(), expected)

    network_escape_run = deepcopy(_run())
    network_escape_run["network_destinations"] = ["example.com:443"]
    network_escape = _evaluate(network_escape_run, _policy())

    tampered_run = deepcopy(_run())
    tampered_run["files"][0]["sha256"] = "e" * 64
    tampered = _evaluate(tampered_run, _policy(), expected)

    print(json.dumps({
        "baseline": baseline.as_dict(),
        "rebound": rebound.as_dict(),
        "network_escape": network_escape.as_dict(),
        "tampered": tampered.as_dict(),
    }, indent=2, sort_keys=True))

    if rebound.decision is not Decision.ALLOW:
        return 3
    if network_escape.decision is not Decision.REFUSE:
        return 4
    if tampered.decision is not Decision.REFUSE or "expected_receipt_digest_mismatch" not in tampered.reasons:
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
