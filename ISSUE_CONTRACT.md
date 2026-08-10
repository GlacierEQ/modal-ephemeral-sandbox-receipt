# Issue contract — Ephemeral Sandbox Receipt

## Problem
Ephemeral sandboxes run untrusted code without a complete post-run integrity receipt.

## Desired outcome
A bounded, open, testable implementation of **Ephemeral Sandbox Receipt** that demonstrates Wrap sandbox runs with input digest, resource budget, and post-run integrity/revoke receipt.

## Non-goals
- Modal affiliation or proprietary integration
- Portfolio-wide scale/performance claims
- UI marketing site

## Acceptance
1. Mechanism module implements allow + refuse with structured receipts
2. pytest behavioral suite green
3. operate.py cold-start produces JSON receipt
4. Non-affiliation disclaimer preserved
