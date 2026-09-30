"""Auto-generated tests for Cloud AI Platform Engineering."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from modal_ephemeral_sandbox_receipt.core import CircuitState, SLOTarget, CircuitBreaker, CostBudget

def test_slo_met():
    slo = SLOTarget("availability", 0.999)
    assert slo.is_met(0.9995)
    assert not slo.is_met(0.99)

def test_circuit_breaker_closed():
    cb = CircuitBreaker(failure_threshold=3)
    assert cb.state == CircuitState.CLOSED
    assert cb.should_allow_request

def test_circuit_breaker_opens():
    cb = CircuitBreaker(failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert not cb.should_allow_request

def test_circuit_breaker_success_resets():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.0)
    cb.record_failure()
    cb.record_failure()
    cb.record_failure()
    # After timeout, goes half-open
    import time; time.sleep(0.01)
    assert cb.state == CircuitState.HALF_OPEN
    cb.record_success()
    assert cb.state == CircuitState.CLOSED

def test_cost_budget():
    budget = CostBudget(daily_budget_usd=100.0)
    assert budget.can_afford(50.0)
    assert budget.charge(50.0)
    assert abs(budget.remaining_usd - 50.0) < 0.01

def test_cost_budget_exceeded():
    budget = CostBudget(daily_budget_usd=10.0, spent_usd=9.5)
    assert not budget.can_afford(1.0)
    assert not budget.charge(1.0)

def test_cost_utilization():
    budget = CostBudget(daily_budget_usd=100.0, spent_usd=75.0)
    assert abs(budget.utilization_pct - 75.0) < 0.01

