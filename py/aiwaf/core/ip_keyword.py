"""Shared IP/keyword decision engine."""

from dataclasses import dataclass
import re
from typing import Callable, Iterable, List, Optional, Sequence, Set
from .native_runtime import function as native_function


INHERENTLY_MALICIOUS_PATTERNS = (
    "hack",
    "exploit",
    "attack",
    "malicious",
    "evil",
    "backdoor",
    "inject",
    "xss",
)

VERY_STRONG_ATTACK_PATTERNS = (
    "union+select",
    "drop+table",
    "<script",
    "javascript:",
    "onload=",
    "onerror=",
    "${",
    "{{",
    "eval(",
)

PROBE_PATH_PATTERNS = (
    r"(^|/)\.(env|git|htaccess|htpasswd)(/|$)",
    r"\.(php|asp|aspx|jsp|cgi|bak|sql)(/|$)",
    r"xmlrpc\.php",
)


@dataclass(frozen=True)
class KeywordDecision:
    block_reason: Optional[str]
    learned_keywords: List[str]
    segments: List[str]


def extract_path_segments(path: str) -> List[str]:
    value = (path or "").lower().lstrip("/")
    return [seg for seg in re.split(r"\W+", value) if len(seg) > 3]


def evaluate_keyword_policy(
    *,
    path: str,
    query_keys: Sequence[str],
    path_exists: bool,
    keyword_learning_enabled: bool,
    static_keywords: Iterable[str],
    dynamic_keywords: Iterable[str],
    legitimate_keywords: Set[str],
    exempt_keywords: Set[str],
    safe_prefixes: Iterable[str],
    malicious_keywords: Set[str],
    is_malicious_context: Callable[[str], bool],
) -> KeywordDecision:
    native = native_function('policy_keyword')
    if native is not None and (path or '').isascii():
        static_keywords, dynamic_keywords = set(static_keywords), set(dynamic_keywords)
        # Framework-specific context callbacks remain in the adapter. Evaluate each
        # distinct candidate once, then pass its result with the policy snapshot.
        # Learning historically evaluates path segments first. Preserve that order
        # for adapters whose context callback keeps per-request state.
        candidates = dict.fromkeys(extract_path_segments(path) + sorted(static_keywords | dynamic_keywords))
        contexts = {candidate for candidate in candidates if is_malicious_context(candidate)}
        return KeywordDecision(*native(path or '', set(query_keys), bool(path_exists),
            bool(keyword_learning_enabled), static_keywords, dynamic_keywords,
            legitimate_keywords, exempt_keywords, list(safe_prefixes), malicious_keywords, contexts))
    raw_path = (path or "").lower()
    normalized_path = raw_path.lstrip("/")
    segments = extract_path_segments(raw_path)
    learned_keywords: List[str] = []

    if keyword_learning_enabled and not path_exists:
        for seg in segments:
            if (
                seg not in legitimate_keywords
                and seg not in exempt_keywords
                and is_malicious_context(seg)
            ):
                learned_keywords.append(seg)

    if not path_exists:
        for pattern in PROBE_PATH_PATTERNS:
            if re.search(pattern, raw_path):
                return KeywordDecision(
                    block_reason="Keyword block: Inherently suspicious: probe path",
                    learned_keywords=learned_keywords,
                    segments=segments,
                )

    all_kw = set(static_keywords) | set(dynamic_keywords)
    suspicious_kw = set()
    for kw in all_kw:
        if kw in exempt_keywords:
            continue
        if kw in legitimate_keywords and path_exists and not is_malicious_context(kw):
            continue
        if any(normalized_path.startswith(prefix) for prefix in safe_prefixes if prefix):
            continue
        suspicious_kw.add(kw)

    for seg in segments:
        is_suspicious = False
        block_reason = ""
        if seg in suspicious_kw:
            is_suspicious = True
            block_reason = f"Learned keyword: {seg}"
        elif (
            not path_exists
            and seg not in legitimate_keywords
            and (
                is_malicious_context(seg)
                or any(pattern in seg for pattern in INHERENTLY_MALICIOUS_PATTERNS)
            )
        ):
            is_suspicious = True
            block_reason = f"Inherently suspicious: {seg}"

        if not is_suspicious:
            continue

        if path_exists:
            very_strong = [
                sum(
                    [
                        "../" in raw_path,
                        "..\\" in raw_path,
                        any(param in query_keys for param in ["cmd", "exec", "system"]),
                        raw_path.count("%") > 5,
                        len([s for s in segments if s in malicious_keywords]) > 2,
                    ]
                )
                >= 2,
                any(pattern in raw_path for pattern in VERY_STRONG_ATTACK_PATTERNS),
            ]
            if not any(very_strong):
                continue

        if is_malicious_context(seg) or not path_exists:
            return KeywordDecision(
                block_reason=f"Keyword block: {block_reason}",
                learned_keywords=learned_keywords,
                segments=segments,
            )

    return KeywordDecision(block_reason=None, learned_keywords=learned_keywords, segments=segments)
