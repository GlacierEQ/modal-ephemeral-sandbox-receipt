from __future__ import annotations

import hashlib

from ephemeral_sandbox_receipt import Decision, EphemeralSandboxReceipt, EphemeralSandboxReceiptRequest


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def payload(**obs_overrides):
    observed={"cpu_seconds":2.0,"memory_mb":256.0,"network_bytes":1024.0,"wall_seconds":3.0,"output_bytes":128.0,"exit_code":0,"output_digest":sha("output"),"final_fs_digest":sha("fs"),"network_destinations":["api.example.com"],"revoked_capabilities":["secret:token","network"],"filesystem_destroyed":True}
    observed.update(obs_overrides)
    return {"mode":"attest","run_id":"run-1","input_digest":sha("input"),"resource_limits":{"cpu_seconds":5.0,"memory_mb":512.0,"network_bytes":2048.0,"wall_seconds":10.0,"output_bytes":1024.0},"observed_run":observed,"allowed_network_destinations":["api.example.com"],"required_revocations":["secret:token","network"],"allowed_exit_codes":[0]}


def evaluate(p):
    return EphemeralSandboxReceipt().evaluate(EphemeralSandboxReceiptRequest("sandbox-a",p,1.0))


def test_clean_bounded_run_gets_integrity_receipt() -> None:
    r=evaluate(payload()); assert r.decision is Decision.ALLOW
    receipt=r.metrics["result"]["receipt"]
    assert receipt["integrity_ok"] is True
    assert len(receipt["receipt_digest"])==64


def test_cpu_budget_excess_refuses_success() -> None:
    r=evaluate(payload(cpu_seconds=8.0)); assert r.decision is Decision.REFUSE
    assert "resource_budget_exceeded:cpu_seconds" in r.reasons


def test_memory_budget_excess_refuses_success() -> None:
    r=evaluate(payload(memory_mb=1024.0)); assert r.decision is Decision.REFUSE
    assert "resource_budget_exceeded:memory_mb" in r.reasons


def test_unapproved_network_destination_is_visible_and_refused() -> None:
    r=evaluate(payload(network_destinations=["evil.example"])); assert r.decision is Decision.REFUSE
    assert "network_destination_outside_policy" in r.reasons


def test_required_revocation_must_be_complete() -> None:
    r=evaluate(payload(revoked_capabilities=["network"])); assert r.decision is Decision.REFUSE
    assert "required_capability_not_revoked" in r.reasons


def test_ephemeral_filesystem_must_be_destroyed() -> None:
    r=evaluate(payload(filesystem_destroyed=False)); assert r.decision is Decision.REFUSE
    assert "ephemeral_filesystem_not_destroyed" in r.reasons


def test_exit_code_policy_is_enforced() -> None:
    r=evaluate(payload(exit_code=137)); assert r.decision is Decision.REFUSE
    assert "exit_code_outside_policy" in r.reasons


def test_receipt_verification_detects_tampering() -> None:
    attested=evaluate(payload()); receipt=dict(attested.metrics["result"]["receipt"])
    receipt["observed_run"]=dict(receipt["observed_run"]); receipt["observed_run"]["cpu_seconds"]=0.1
    checked=evaluate({"mode":"verify","receipt":receipt,"expected_input_digest":sha("input")})
    assert checked.decision is Decision.REFUSE
    assert "receipt_digest_mismatch" in checked.reasons


def test_receipt_verification_binds_original_input() -> None:
    attested=evaluate(payload()); receipt=attested.metrics["result"]["receipt"]
    checked=evaluate({"mode":"verify","receipt":receipt,"expected_input_digest":sha("different")})
    assert checked.decision is Decision.REFUSE
    assert "input_digest_mismatch" in checked.reasons
