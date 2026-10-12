"""Shared honeypot policy helpers."""

from dataclasses import dataclass
from typing import Optional
from .native_runtime import function as native_function


ACTION_ALLOW = "allow"
ACTION_BLOCK = "block"
ACTION_PAGE_EXPIRED = "page_expired"


@dataclass(frozen=True)
class HoneypotDecision:
    action: str
    reason: Optional[str] = None
    status_code: Optional[int] = None
    message: Optional[str] = None


LOGIN_PATH_PREFIXES = (
    "/admin/login/",
    "/login/",
    "/accounts/login/",
    "/auth/login/",
    "/signin/",
)

OBVIOUS_POST_ONLY_SUFFIXES = (
    "/create/",
    "/submit/",
    "/upload/",
    "/delete/",
    "/process/",
)
DEFAULT_HONEYPOT_TTL_SECONDS = 300


def honeypot_get_key(ip: str) -> str:
    return f"honeypot_get:{ip}"


def store_honeypot_get_timestamp(setter, ip: str, now: float, ttl_seconds: int = DEFAULT_HONEYPOT_TTL_SECONDS) -> None:
    """
    Persist GET timestamp using adapter-provided setter(key, value, ttl_seconds).
    """
    setter(honeypot_get_key(ip), now, ttl_seconds)


def load_honeypot_get_timestamp(getter, ip: str):
    """
    Load previously persisted GET timestamp using adapter-provided getter(key).
    """
    return getter(honeypot_get_key(ip))


def clear_honeypot_get_timestamp(deleter, ip: str) -> None:
    """
    Clear persisted GET timestamp using adapter-provided deleter(key).
    """
    deleter(honeypot_get_key(ip))


def is_login_path(path: str) -> bool:
    path_l = (path or "").lower()
    return any(path_l.startswith(prefix) for prefix in LOGIN_PATH_PREFIXES)


def effective_min_form_time(path: str, base_min_form_time: float) -> float:
    if is_login_path(path):
        return 0.1
    return float(base_min_form_time)


def should_block_get_to_post_only_endpoint(path: str, accepts_get: bool) -> bool:
    if accepts_get:
        return False
    path_l = (path or "").lower()
    return any(path_l.endswith(suffix) for suffix in OBVIOUS_POST_ONLY_SUFFIXES)


def evaluate_form_timing(
    *,
    now: float,
    get_time: Optional[float],
    path: str,
    min_form_time: float,
    max_page_time: float,
) -> HoneypotDecision:
    native = native_function('policy_form')
    if native is not None:
        return HoneypotDecision(*native(float(now), None if get_time is None else float(get_time),
                                        path or '', float(min_form_time), float(max_page_time)))
    if get_time is None:
        return HoneypotDecision(action=ACTION_ALLOW)

    time_diff = now - float(get_time)
    if time_diff > float(max_page_time):
        return HoneypotDecision(
            action=ACTION_PAGE_EXPIRED,
            status_code=409,
            message="Page has expired. Please reload and try again.",
        )

    threshold = effective_min_form_time(path, min_form_time)
    if time_diff < threshold:
        return HoneypotDecision(
            action=ACTION_BLOCK,
            reason=f"Form submitted too quickly ({time_diff:.2f}s)",
            status_code=403,
        )

    return HoneypotDecision(action=ACTION_ALLOW)


def is_authenticated_session_context(user=None, session=None) -> bool:
    """
    Best-effort authenticated-session detection shared across adapters.
    """
    if user is not None:
        is_authenticated = getattr(user, "is_authenticated", False)
        if callable(is_authenticated):
            try:
                is_authenticated = is_authenticated()
            except Exception:
                is_authenticated = False
        if bool(is_authenticated):
            return True

    if session is not None:
        try:
            session_key = getattr(session, "session_key", None)
            auth_user_id = session.get("_auth_user_id") if hasattr(session, "get") else None
            if session_key and auth_user_id:
                return True
        except Exception:
            pass

    return False
