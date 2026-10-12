"""Cached route-level middleware execution plans."""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from itertools import count
from threading import RLock
from typing import Any, Callable, Iterable, Mapping

from .exemptions import normalize_middleware_name, normalize_path
from .native_runtime import function as native_function


MIDDLEWARE_NAMES = (
    "geo_block",
    "ip_keyword_block",
    "rate_limit",
    "ai_anomaly",
    "honeypot",
    "uuid_tamper",
    "header_validation",
    "logging",
)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return ("mapping", tuple(sorted((str(key), _freeze(item)) for key, item in value.items())))
    if isinstance(value, list):
        return ("list", tuple(_freeze(item) for item in value))
    if isinstance(value, tuple):
        return ("tuple", tuple(_freeze(item) for item in value))
    if isinstance(value, (set, frozenset)):
        return ("set", tuple(sorted((_freeze(item) for item in value), key=repr)))
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value


def _thaw(value: Any) -> Any:
    if not isinstance(value, tuple) or len(value) != 2:
        return value
    kind, items = value
    if kind == "mapping":
        return {key: _thaw(item) for key, item in items}
    if kind == "list":
        return [_thaw(item) for item in items]
    if kind == "tuple":
        return tuple(_thaw(item) for item in items)
    if kind == "set":
        return {_thaw(item) for item in items}
    return value


@dataclass(frozen=True)
class RouteExecutionPlan:
    enabled_middlewares: frozenset[str]
    rate_limit_overrides: tuple[Any, ...] = ()

    def should_apply(self, middleware_name: Any) -> bool:
        return normalize_middleware_name(middleware_name) in self.enabled_middlewares

    def get_rate_limit_overrides(self) -> dict[str, Any]:
        overrides = _thaw(self.rate_limit_overrides)
        return overrides if isinstance(overrides, dict) else {}


@dataclass(frozen=True)
class CompiledRoutePolicy:
    token: int
    prefix_rules: tuple[tuple[str, Mapping[str, Any]], ...]
    native_rules: tuple = ()

    def match(self, path: str) -> Mapping[str, Any] | None:
        normalized_path = normalize_path(path, trailing_slash=False)
        for prefix, rule in self.prefix_rules:
            if normalized_path == prefix.rstrip("/") or normalized_path.startswith(prefix):
                return rule
        return None


class RoutePolicyCache:
    """Compile each path-rule configuration once per explicit version."""

    def __init__(self, maxsize: int = 128):
        if maxsize < 1:
            raise ValueError("maxsize must be positive")
        self.maxsize = maxsize
        self._policies: OrderedDict[Any, tuple[Any, CompiledRoutePolicy]] = OrderedDict()
        self._tokens = count(1)
        self._lock = RLock()

    def get_or_compile(self, rules: Iterable[dict] | None, version: Any = None) -> CompiledRoutePolicy:
        source = rules
        if not rules:
            source = None
            key = ("empty", _freeze(version))
        else:
            key = (id(rules), _freeze(version))

        with self._lock:
            cached = self._policies.get(key)
            if cached is not None and cached[0] is source:
                self._policies.move_to_end(key)
                return cached[1]

            rules_tuple = tuple(rules or ())
            policy = _compile_route_policy(rules_tuple, next(self._tokens))
            self._policies[key] = (source, policy)
            self._policies.move_to_end(key)
            while len(self._policies) > self.maxsize:
                self._policies.popitem(last=False)
            return policy

    def clear(self) -> None:
        with self._lock:
            self._policies.clear()


def _compile_route_policy(rules: tuple[dict, ...], token: int) -> CompiledRoutePolicy:
    prefix_rules = []
    for position, rule in enumerate(rules):
        if not isinstance(rule, Mapping) or not rule.get("PREFIX"):
            continue
        prefix = normalize_path(rule["PREFIX"], trailing_slash=True)
        prefix_rules.append((prefix, deepcopy(dict(rule)), position))
    prefix_rules.sort(key=lambda item: (-len(item[0]), item[2]))
    native_rules = []
    for prefix, rule, _position in prefix_rules:
        disabled = rule.get('DISABLE', rule.get('disable', []))
        if not isinstance(disabled, (list, tuple, set, frozenset)):
            disabled = []
        native_rules.append((prefix, frozenset(normalize_middleware_name(value)
                                               for value in disabled if value)))
    return CompiledRoutePolicy(
        token=token,
        prefix_rules=tuple((prefix, rule) for prefix, rule, _position in prefix_rules),
        native_rules=tuple(native_rules),
    )


class RoutePlanCache:
    """Small thread-safe LRU used by all framework adapters."""

    def __init__(self, maxsize: int = 1024):
        if maxsize < 1:
            raise ValueError("maxsize must be positive")
        self.maxsize = maxsize
        self._plans: OrderedDict[Any, RouteExecutionPlan] = OrderedDict()
        self._lock = RLock()

    def get_or_create(self, key: Any, factory: Callable[[], RouteExecutionPlan]) -> RouteExecutionPlan:
        with self._lock:
            cached = self._plans.get(key)
            if cached is not None:
                self._plans.move_to_end(key)
                return cached

        plan = factory()
        with self._lock:
            cached = self._plans.get(key)
            if cached is not None:
                self._plans.move_to_end(key)
                return cached
            self._plans[key] = plan
            self._plans.move_to_end(key)
            while len(self._plans) > self.maxsize:
                self._plans.popitem(last=False)
            return plan

    def clear(self) -> None:
        with self._lock:
            self._plans.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._plans)


_route_plan_cache = RoutePlanCache()
_route_policy_cache = RoutePolicyCache()


def get_route_execution_plan(
    path: str,
    rules: Iterable[dict] | None,
    *,
    fully_exempt: bool = False,
    exempt_middlewares: Iterable[str] | None = None,
    required_middlewares: Iterable[str] | None = None,
    policy_version: Any = None,
) -> RouteExecutionPlan:
    policy = _route_policy_cache.get_or_compile(rules, policy_version)
    exempt = frozenset(normalize_middleware_name(item) for item in (exempt_middlewares or ()) if item)
    required = frozenset(normalize_middleware_name(item) for item in (required_middlewares or ()) if item)
    key = (
        normalize_path(path, trailing_slash=False),
        policy.token,
        bool(fully_exempt),
        tuple(sorted(exempt)),
        tuple(sorted(required)),
    )
    return _route_plan_cache.get_or_create(
        key,
        lambda: _build_route_execution_plan(
            path,
            policy,
            fully_exempt=fully_exempt,
            exempt_middlewares=exempt,
            required_middlewares=required,
        ),
    )


def _build_route_execution_plan(
    path: str,
    policy: CompiledRoutePolicy,
    *,
    fully_exempt: bool,
    exempt_middlewares: frozenset[str],
    required_middlewares: frozenset[str],
) -> RouteExecutionPlan:
    native = native_function('policy_route_plan')
    if native is not None and len(policy.native_rules) == len(policy.prefix_rules):
        index, enabled = native(normalize_path(path, trailing_slash=False), list(policy.native_rules),
                                list(MIDDLEWARE_NAMES), bool(fully_exempt),
                                set(exempt_middlewares), set(required_middlewares))
        rule = policy.prefix_rules[index][1] if index is not None else {}
        overrides = rule.get('RATE_LIMIT', rule.get('rate_limit', {}))
        return RouteExecutionPlan(frozenset(enabled),
                                  _freeze(overrides if isinstance(overrides, Mapping) else {}))
    rule = policy.match(path)
    disabled_values = []
    rate_limit_overrides: Mapping[str, Any] = {}
    if isinstance(rule, Mapping):
        disabled_values = rule.get("DISABLE", rule.get("disable", []))
        if not isinstance(disabled_values, (list, tuple, set, frozenset)):
            disabled_values = []
        overrides = rule.get("RATE_LIMIT", rule.get("rate_limit", {}))
        if isinstance(overrides, Mapping):
            rate_limit_overrides = overrides

    disabled = frozenset(normalize_middleware_name(item) for item in disabled_values if item)
    enabled = set()
    for middleware_name in MIDDLEWARE_NAMES:
        if middleware_name in required_middlewares:
            enabled.add(middleware_name)
        elif middleware_name in disabled or fully_exempt or middleware_name in exempt_middlewares:
            continue
        else:
            enabled.add(middleware_name)

    return RouteExecutionPlan(
        enabled_middlewares=frozenset(enabled),
        rate_limit_overrides=_freeze(rate_limit_overrides),
    )


def clear_route_plan_cache() -> None:
    _route_plan_cache.clear()
    _route_policy_cache.clear()
