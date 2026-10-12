"""IP reputation and temporary block policy helpers."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional
from .native_runtime import function as native_function


REASON_WEIGHTS = {
    "scanner": 20,
    "scan": 20,
    "sqli": 40,
    "sql injection": 40,
    "xss": 30,
    "bruteforce": 25,
    "brute force": 25,
    "flood": 25,
    "rate limit": 20,
    "honeypot": 30,
    "uuid": 25,
    "header": 15,
    "geo": 20,
    "keyword": 20,
}

DEFAULT_REASON_WEIGHT = 10
BLOCK_THRESHOLD = 60
LONG_BLOCK_THRESHOLD = 80
FIRST_BLOCK_SECONDS = 15 * 60
SECOND_BLOCK_SECONDS = 60 * 60
REPEATED_BLOCK_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class ReputationDecision:
    score: int
    offenses: int
    reasons: List[str]
    should_block: bool
    duration: Optional[int]
    expires_at: Optional[float]


def normalize_reason(reason: Optional[str]) -> str:
    value = str(reason or "unknown").strip()
    return value or "unknown"


def reason_weight(reason: Optional[str]) -> int:
    normalized = normalize_reason(reason).lower()
    for token, weight in REASON_WEIGHTS.items():
        if token in normalized:
            return weight
    return DEFAULT_REASON_WEIGHT


def _unique_reasons(values: Iterable[str]) -> List[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        reason = normalize_reason(value)
        key = reason.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(reason)
    return result


def progressive_duration(score: int, offenses: int) -> Optional[int]:
    if score < BLOCK_THRESHOLD:
        return None
    if score >= LONG_BLOCK_THRESHOLD or offenses >= 3:
        return REPEATED_BLOCK_SECONDS
    if offenses == 2:
        return SECOND_BLOCK_SECONDS
    return FIRST_BLOCK_SECONDS


def evaluate_reputation(
    *,
    existing: Optional[Mapping[str, Any]],
    reason: Optional[str],
    now: Optional[float] = None,
) -> ReputationDecision:
    current_time = time.time() if now is None else float(now)
    existing = existing or {}
    previous_score = int(existing.get("score", 0) or 0)
    previous_offenses = int(existing.get("offenses", 0) or 0)
    previous_reasons = existing.get("reasons") or existing.get("reason") or []
    if isinstance(previous_reasons, str):
        previous_reasons = [previous_reasons]
    native = native_function('policy_reputation')
    if native is not None:
        score, offenses, reasons, blocked, duration = native(
            previous_score, previous_offenses,
            [normalize_reason(item) for item in previous_reasons], normalize_reason(reason))
        return ReputationDecision(score, offenses, reasons, blocked, duration,
                                  current_time + duration if duration else None)
    reasons = _unique_reasons([*previous_reasons, normalize_reason(reason)])
    offenses = previous_offenses + 1
    score = min(100, previous_score + reason_weight(reason))
    should_block = score >= BLOCK_THRESHOLD
    duration = progressive_duration(score, offenses)
    expires_at = current_time + duration if duration else None
    return ReputationDecision(
        score=score,
        offenses=offenses,
        reasons=reasons,
        should_block=should_block,
        duration=duration,
        expires_at=expires_at,
    )


def format_block_reason(decision: ReputationDecision) -> str:
    joined = ", ".join(decision.reasons)
    return f"{joined}; score={decision.score}; offenses={decision.offenses}"
