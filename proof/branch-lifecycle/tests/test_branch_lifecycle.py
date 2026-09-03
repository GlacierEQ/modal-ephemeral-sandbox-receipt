from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "branch_lifecycle.py"
spec = importlib.util.spec_from_file_location("branch_lifecycle", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)

POLICY = {
    "version": "test",
    "stale_days": 30,
    "minimum_delete_confidence": 95,
    "protected_patterns": ["main", "release/*"],
    "family_prefixes": ["apex/", "feat/", "fix/"],
    "automatic_delete_states": ["MERGED_REDUNDANT", "REACHABLE_REDUNDANT"],
    "fail_closed_on_evidence_error": True,
}

def branch(name, *, ahead=None, protected=False, open_prs=None, merged_prs=None, errors=None, committed="2026-08-01T00:00:00Z"):
    return {
        "name": name,
        "sha": "a" * 40,
        "protected": protected,
        "head_committed_at": committed,
        "ahead_by": ahead,
        "behind_by": 0,
        "compare_status": "ahead" if ahead else "identical",
        "open_prs": open_prs or [],
        "merged_prs": merged_prs or [],
        "closed_unmerged_prs": [],
        "changed_files": [],
        "evidence_errors": errors or [],
    }

def inventory(branches):
    return {
        "schema": "glaciereq.branch-inventory.v1",
        "repository": "GlacierEQ/example",
        "default_branch": "main",
        "generated_at": "2026-09-02T12:00:00Z",
        "branches": branches,
    }

def by_name(plan):
    return {row["branch"]: row for row in plan["branches"]}

class BranchLifecycleTests(unittest.TestCase):
    def test_merged_pr_is_high_confidence_cleanup_even_if_branch_has_unique_tip(self):
        plan = module.build_plan(inventory([
            branch("feat/squash-merge", ahead=3, merged_prs=[{"number": 7, "head_sha": "a" * 40}]),
        ]), POLICY)
        row = by_name(plan)["feat/squash-merge"]
        self.assertEqual(row["state"], "MERGED_REDUNDANT")
        self.assertEqual(row["action"], "DELETE")
        self.assertEqual(row["cleanup_confidence"], 100)

    def test_historical_merge_does_not_delete_reused_branch(self):
        plan = module.build_plan(inventory([
            branch(
                "feat/reused-after-merge",
                ahead=2,
                merged_prs=[{"number": 7, "head_sha": "b" * 40}],
                committed="2026-09-02T00:00:00Z",
            ),
        ]), POLICY)
        row = by_name(plan)["feat/reused-after-merge"]
        self.assertEqual(row["state"], "DIVERGENT_PRESERVE")
        self.assertEqual(row["action"], "KEEP")
        self.assertEqual(row["evidence"]["merged_pr_count"], 1)
        self.assertEqual(row["evidence"]["merged_current_head_pr_count"], 0)

    def test_dynamic_assessment_marks_redundant_for_removal(self):
        plan = module.build_plan(inventory([branch("fix/redundant", ahead=0)]), POLICY)
        row = by_name(plan)["fix/redundant"]
        assessment = row["dynamic_assessment"]
        self.assertEqual(assessment["recommended_effect"], "REMOVE_REDUNDANT")
        self.assertEqual(assessment["value_signal"], "REDUNDANT")
        self.assertTrue(assessment["reassess_before_mutation"])
        self.assertFalse(assessment["static_label_authoritative"])

    def test_dynamic_assessment_marks_unique_work_for_harvest(self):
        plan = module.build_plan(inventory([
            branch("feat/valuable", ahead=3, committed="2026-09-02T00:00:00Z"),
        ]), POLICY)
        row = by_name(plan)["feat/valuable"]
        assessment = row["dynamic_assessment"]
        self.assertEqual(assessment["recommended_effect"], "PRESERVE_AND_HARVEST")
        self.assertEqual(assessment["value_signal"], "HIGH")
        self.assertFalse(assessment["reassess_before_mutation"])

    def test_plan_has_expiring_dynamic_assessment_window(self):
        plan = module.build_plan(inventory([branch("fix/redundant", ahead=0)]), POLICY)
        self.assertTrue(plan["dynamic_assessment_required"])
        self.assertEqual(plan["assessment_ttl_seconds"], 300)
        self.assertEqual(plan["assessment_valid_until"], "2026-09-02T12:05:00Z")

    def test_zero_ahead_is_redundant(self):
        plan = module.build_plan(inventory([branch("fix/already-contained", ahead=0)]), POLICY)
        row = by_name(plan)["fix/already-contained"]
        self.assertEqual(row["state"], "REACHABLE_REDUNDANT")
        self.assertEqual(row["action"], "DELETE")

    def test_open_pr_overrides_redundancy(self):
        plan = module.build_plan(inventory([
            branch("feat/live", ahead=0, open_prs=[{"number": 9}]),
        ]), POLICY)
        row = by_name(plan)["feat/live"]
        self.assertEqual(row["state"], "ACTIVE")
        self.assertEqual(row["action"], "KEEP")

    def test_evidence_error_fails_closed(self):
        plan = module.build_plan(inventory([
            branch("feat/uncertain", ahead=0, errors=["compare_failed"]),
        ]), POLICY)
        row = by_name(plan)["feat/uncertain"]
        self.assertEqual(row["state"], "UNKNOWN_BLOCKED")
        self.assertEqual(row["action"], "BLOCK")

    def test_old_divergent_branch_is_review_not_delete(self):
        plan = module.build_plan(inventory([
            branch("apex/job-restore-old-20260801", ahead=5),
        ]), POLICY)
        row = by_name(plan)["apex/job-restore-old-20260801"]
        self.assertEqual(row["state"], "STALE_REVIEW")
        self.assertEqual(row["action"], "REVIEW_CONSOLIDATE")

    def test_repository_policy_overrides_redundant_topology(self):
        repository_policy = {
            "schema": "glaciereq.branch-lifecycle-repository-policy.v1",
            "preservations": [
                {
                    "name": "feat/recovery-evidence",
                    "reason": "restored after failed cleanup transaction",
                }
            ],
        }
        merged_policy = module.merge_repository_policy(POLICY, repository_policy)
        plan = module.build_plan(
            inventory([branch("feat/recovery-evidence", ahead=0)]),
            merged_policy,
        )
        row = by_name(plan)["feat/recovery-evidence"]
        self.assertEqual(row["state"], "PROTECTED")
        self.assertEqual(row["action"], "KEEP")

    def test_protected_pattern_never_deletes(self):
        plan = module.build_plan(inventory([
            branch("release/2026.09", ahead=0),
        ]), POLICY)
        row = by_name(plan)["release/2026.09"]
        self.assertEqual(row["state"], "PROTECTED")
        self.assertEqual(row["action"], "KEEP")

    def test_family_groups_volatile_suffixes_but_does_not_auto_merge(self):
        plan = module.build_plan(inventory([
            branch("apex/job-restore-router-20260817", ahead=2, committed="2026-09-01T00:00:00Z"),
            branch("apex/job-restore-router-20260818", ahead=4, committed="2026-09-02T00:00:00Z"),
        ]), POLICY)
        self.assertEqual(len(plan["families"]), 1)
        family = plan["families"][0]
        self.assertTrue(family["consolidation_recommended"])
        self.assertEqual(len(family["divergent_members"]), 2)


    def test_admission_reuses_exact_live_workstream_binding(self):
        plan = module.build_plan(inventory([
            branch("feat/router-live", ahead=2, committed="2026-09-02T00:00:00Z"),
        ]), POLICY)
        request = {
            "schema": "glaciereq.branch-admission-request.v1",
            "requested_branch": "feat/router-next",
            "workstream_id": "router",
            "bindings": [{"workstream_id": "router", "branch": "feat/router-live"}],
        }
        decision = module.build_admission_decision(plan, request, POLICY)
        self.assertEqual(decision["action"], "REUSE_EXISTING")
        self.assertFalse(decision["allow_create"])
        self.assertEqual(decision["target_branch"], "feat/router-live")

    def test_admission_blocks_new_branch_for_duplicate_explicit_workstream(self):
        plan = module.build_plan(inventory([
            branch("feat/router-a", ahead=2, committed="2026-09-02T00:00:00Z"),
            branch("feat/router-b", ahead=3, committed="2026-09-02T01:00:00Z"),
        ]), POLICY)
        request = {
            "schema": "glaciereq.branch-admission-request.v1",
            "requested_branch": "feat/router-c",
            "workstream_id": "router",
            "bindings": [
                {"workstream_id": "router", "branch": "feat/router-a"},
                {"workstream_id": "router", "branch": "feat/router-b"},
            ],
        }
        decision = module.build_admission_decision(plan, request, POLICY)
        self.assertEqual(decision["action"], "REVIEW_CONSOLIDATE")
        self.assertFalse(decision["allow_create"])

    def test_admission_name_similarity_warns_but_does_not_fake_equivalence(self):
        plan = module.build_plan(inventory([
            branch("apex/job-restore-router-20260901", ahead=2, committed="2026-09-02T00:00:00Z"),
        ]), POLICY)
        request = {
            "schema": "glaciereq.branch-admission-request.v1",
            "requested_branch": "apex/job-restore-router-20260902",
            "workstream_id": "different-stream",
            "bindings": [],
        }
        decision = module.build_admission_decision(plan, request, POLICY)
        self.assertEqual(decision["action"], "CREATE_NEW_WITH_FAMILY_WARNING")
        self.assertTrue(decision["allow_create"])

    def test_admission_closed_continuation_can_start_new_lifecycle(self):
        plan = module.build_plan(inventory([
            branch("feat/router-old", ahead=0),
        ]), POLICY)
        request = {
            "schema": "glaciereq.branch-admission-request.v1",
            "requested_branch": "feat/router-v2",
            "workstream_id": "router-v2",
            "continuation_of": "feat/router-old",
            "bindings": [],
        }
        decision = module.build_admission_decision(plan, request, POLICY)
        self.assertEqual(decision["action"], "CREATE_NEW")
        self.assertTrue(decision["allow_create"])
        self.assertEqual(decision["target_branch"], "feat/router-v2")

    def test_admission_protected_continuation_fails_closed(self):
        plan = module.build_plan(inventory([
            branch("release/2026.09", ahead=0),
        ]), POLICY)
        request = {
            "schema": "glaciereq.branch-admission-request.v1",
            "requested_branch": "feat/release-followup",
            "workstream_id": "release-followup",
            "continuation_of": "release/2026.09",
            "bindings": [],
        }
        decision = module.build_admission_decision(plan, request, POLICY)
        self.assertEqual(decision["action"], "BLOCK")
        self.assertFalse(decision["allow_create"])

    def test_plan_is_deterministic(self):
        payload = inventory([
            branch("feat/a", ahead=0),
            branch("feat/b", ahead=2, committed="2026-09-02T00:00:00Z"),
        ])
        first = module.build_plan(payload, POLICY)
        second = module.build_plan(payload, POLICY)
        self.assertEqual(first, second)
        self.assertEqual(len(first["plan_sha256"]), 64)

if __name__ == "__main__":
    unittest.main()
