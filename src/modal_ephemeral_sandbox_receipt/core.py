"""Cloud AI Platform Engineering — Core Module"""

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

class CircuitState(Enum):
    CLOSED = auto()     # Normal operation
    OPEN = auto()       # Failing, reject requests
    HALF_OPEN = auto()  # Testing recovery

@dataclass
class SLOTarget:
    """Service Level Objective target."""
    metric_name: str
    target_value: float
    window_seconds: int = 300

    def is_met(self, current_value: float) -> bool:
        return current_value >= self.target_value


class CircuitBreaker:
    """Circuit breaker with configurable thresholds."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._success_count = 0

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN and self._last_failure_time:
            if time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
        return self._state

    def record_success(self) -> None:
        self._success_count += 1
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
            self._failure_count = 0

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN

    @property
    def should_allow_request(self) -> bool:
        return self.state != CircuitState.OPEN


@dataclass
class CostBudget:
    """Cost-aware resource allocation."""
    daily_budget_usd: float
    spent_usd: float = 0.0

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.daily_budget_usd - self.spent_usd)

    @property
    def utilization_pct(self) -> float:
        if self.daily_budget_usd <= 0:
            return 100.0
        return (self.spent_usd / self.daily_budget_usd) * 100.0

    def can_afford(self, cost_usd: float) -> bool:
        return self.remaining_usd >= cost_usd

    def charge(self, cost_usd: float) -> bool:
        if not self.can_afford(cost_usd):
            return False
        self.spent_usd += cost_usd
        return True

