"""Shared geo-block decision policy."""

from dataclasses import dataclass
from typing import Iterable, Set
from .native_runtime import function as native_function


@dataclass(frozen=True)
class GeoDecision:
    should_block: bool
    country: str
    reason: str


def normalize_country_list(value) -> Set[str]:
    if not value:
        return set()
    if isinstance(value, str):
        values = [value]
    else:
        values = list(value)
    normalized: Set[str] = set()
    for item in values:
        if item:
            normalized.add(str(item).strip().upper())
    return normalized


def evaluate_geo_policy(
    *,
    country: str,
    allow_countries: Iterable[str],
    block_countries: Iterable[str],
    dynamic_blocked: Iterable[str],
) -> GeoDecision:
    normalized_country = (country or "").strip().upper()
    if not normalized_country:
        return GeoDecision(False, "", "")

    allow = normalize_country_list(allow_countries)
    block = normalize_country_list(block_countries)
    dynamic = normalize_country_list(dynamic_blocked)
    native = native_function('policy_geo')
    if native is not None:
        return GeoDecision(*native(normalized_country, allow, block, dynamic))

    if allow:
        blocked = normalized_country not in allow
    else:
        blocked = normalized_country in block or normalized_country in dynamic

    reason = f"Geo blocked: {normalized_country}" if blocked else ""
    return GeoDecision(blocked, normalized_country, reason)

