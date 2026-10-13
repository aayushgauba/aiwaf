"""Opt-in compiled request stage; unsupported inputs use the established path."""
from . import sql_injection, ip_keyword
from .native_runtime import function
from .storage_ops import now_iso
import time

_DEFAULT_INSPECT = sql_injection.SQLInjectionPolicy.inspect
_DEFAULT_ENFORCE = sql_injection.SQLInjectionPolicy.enforce
_DEFAULT_RULES = sql_injection.RULES
_DEFAULT_KEYWORD = ip_keyword.evaluate_keyword_policy
_DEFAULT_KEYWORD_RULES = (ip_keyword.PROBE_PATH_PATTERNS, ip_keyword.INHERENTLY_MALICIOUS_PATTERNS, ip_keyword.VERY_STRONG_ATTACK_PATTERNS)


def prepare_request_engine(owner, *, enabled, policy, path, query_context, query_keys,
        exists, learning, top_n, file, counts, static, legitimate, exempt, prefixes, malicious, sql_prechecked=False):
    factory = function('NativeRequestEngine') if enabled else None
    if (factory is None or policy.mode not in {'block', 'off'} or top_n < 0
            or type(policy) is not sql_injection.SQLInjectionPolicy
            or getattr(policy.inspect, '__func__', None) is not _DEFAULT_INSPECT
            or getattr(policy.enforce, '__func__', None) is not _DEFAULT_ENFORCE
            or sql_injection.RULES is not _DEFAULT_RULES
            or ip_keyword.evaluate_keyword_policy is not _DEFAULT_KEYWORD
            or any(current is not original for current, original in zip(
                (ip_keyword.PROBE_PATH_PATTERNS, ip_keyword.INHERENTLY_MALICIOUS_PATTERNS, ip_keyword.VERY_STRONG_ATTACK_PATTERNS), _DEFAULT_KEYWORD_RULES))
            or not isinstance(path, str) or not path.isascii()):
        return None
    sets = tuple(frozenset(values) for values in (static, legitimate, exempt, malicious))
    prefixes = tuple(prefixes)
    if any(not isinstance(value, str) or not value.isascii() for values in (*sets, prefixes) for value in values):
        return None
    signature = (factory, policy.mode, policy.max_bytes, bool(learning), int(top_n), str(file), bool(counts), *sets, prefixes, bool(sql_prechecked))
    cached = getattr(owner, '_native_request_engine_profile', None)
    if cached is None or cached[0] != signature:
        engine = factory(policy.mode == 'block' and not sql_prechecked, policy.max_bytes, bool(learning), int(top_n), str(file), bool(counts),
            sets[0], sets[1], sets[2], list(prefixes), sets[3])
        owner._native_request_engine_profile = (signature, engine)
    else:
        engine = cached[1]
    decision = []

    def evaluate(query, body):
        if function('NativeRequestEngine') is not factory:
            return policy.inspect(query, body)
        query = query.encode('utf-8') if isinstance(query, str) else query
        raw = engine.evaluate(query or b'', body, path, query_context, set(query_keys), bool(exists), now_iso(), time.time())
        if raw is None:
            return policy.inspect(query, body)
        rule, status, reason, learned, segments = raw
        if rule:
            return sql_injection.Finding(rule, status)
        decision.append(ip_keyword.KeywordDecision(reason, learned, segments))
        return None

    return evaluate, decision
