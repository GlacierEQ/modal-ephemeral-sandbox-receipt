# DEV_UP_INSTRUCTIONS — for implementing AIs / engineers

## Excellence group enrollment

- **Group:** Wave C
- **Wave id:** `WAVE-C-2026-08-10`
- **Enrolled:** 2026-08-10T1002Z
- **Phase:** SCAFFOLD_ENROLLED → implement mechanism → proof → promote (XOR gap)
- **DoD:** Bodybuilder gates in `excellence/framework/PIP_TO_BODYBUILDER_PIPELINE.md`

**Repository:** `GlacierEQ/modal-ephemeral-sandbox-receipt`  
**Company lens (independent):** Modal (`modal`)  
**Innovation:** Ephemeral Sandbox Receipt  
**Scaffold batch:** 2026-08-10T0924Z

## Mission

Implement a **real, testable** central mechanism that addresses the bottleneck below. Do **not** claim Modal affiliation, proprietary access, or production deployment.

### Bottleneck
Ephemeral sandboxes run untrusted code without a complete post-run integrity receipt.

### Brick wall
Silent success without receipts; affiliation or production claims without evidence.

### Mechanism to implement
Wrap sandbox runs with input digest, resource budget, and post-run integrity/revoke receipt.

## Hard rules (fail closed)

1. **No affiliation theater** — never state or imply Modal employment, endorsement, or proprietary systems access.
2. **No magic numbers / ANSWER=42** — all thresholds named constants with units in comments.
3. **No import-only operate** — `scripts/operate.py` must call real methods and assert behavioral outputs.
4. **No field-echo tests** — tests must change inputs and observe different outputs / refuse paths.
5. **Deterministic** — pure functions preferred; time/randomness injected.
6. **Receipts** — success and refuse paths return structured dicts with digests where useful.
7. **PROMOTED XOR gap** — do not mark PROMOTED while `machine/gap-receipt.json` exists.
8. Keep public surface free of secrets, private repos, and personal contact PII.

## Implementation checklist

### 1. Replace the stub mechanism
File: `src/ephemeral_sandbox_receipt.py`

- Expand `EphemeralSandboxReceipt` into a complete, self-contained implementation.
- Public API must stay stable enough that tests in `tests/test_ephemeral_sandbox_receipt.py` can be upgraded (not gutted).
- Include at least:
  - happy-path success with structured result
  - explicit **refuse** path (invalid input, budget exceeded, expired grant, etc.)
  - deterministic digest/fingerprint for auditability
- Prefer stdlib-only unless a dependency is essential (then pin in `requirements.txt`).

### 2. Make operate real
File: `scripts/operate.py`

- Import the mechanism, construct inputs, call methods, print JSON receipt.
- Exit non-zero on refuse/failure.
- Content-check that outputs are not empty / not mere class names.

### 3. Strengthen tests
Files: `tests/test_ephemeral_sandbox_receipt.py`, `tests/test_adversarial.py`

- Positive: ≥3 behavioral cases with distinct inputs → distinct outputs.
- Negative: malformed input, expired authority, over-budget, idempotency where relevant.
- Adversarial: attempt to smuggle affiliation claims or bypass refuse gates — must fail closed.

### 4. Freeze the target contract
File: `machine/target-contract.json`

- Update `target.purpose` and `target.central_bottleneck` only if the mechanism narrows (never broadens into marketing).
- When tests + operate pass: set `current.implemented/tested/operable` appropriately and bind proof receipt.

### 5. Excellence state
File: `machine/excellence-state.json`

- Leave `DISCOVERED` until real proof exists.
- On elevation: follow Helix promotion policy (AUTHORITY_BOUND + PROJECTION_TRUTH_CLOSED for PROMOTED).

### 6. README honesty
- Keep non-affiliation block.
- Document exact current boundary (what works / what does not).

## Suggested algorithm sketch

```text
input → validate schema → check authority/budget/freshness
      → compute decision (allow | refuse)
      → emit receipt {decision, reasons[], digest, metrics}
```

## Definition of done (for the filling AI)

- [ ] `python -m pytest -q` passes with **real** behavioral tests (not skip-all)
- [ ] `python scripts/operate.py` prints a JSON receipt with decision + digest
- [ ] Refuse path covered
- [ ] No company affiliation language outside the explicit non-affiliation disclaimer
- [ ] `DEV_UP_INSTRUCTIONS.md` can be marked COMPLETED with date + commit in a short receipt note at bottom

## Out of scope

- Cloud deploy, customer pilots, proprietary Modal APIs
- Multi-repo monorepos, secret material, personal data
- Claiming “production-ready” without operate + tests + proof receipt

---
*Scaffold only. Implementation is the next agent’s job.*
