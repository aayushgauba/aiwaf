import logging
from django.conf import settings

_APPLIED = False


def apply_legacy_settings() -> None:
    global _APPLIED
    if _APPLIED:
        return
    _APPLIED = True

    legacy = getattr(settings, "AIWAF_SETTINGS", None)
    if not isinstance(legacy, dict):
        return

    logger = logging.getLogger("aiwaf.settings")

    def set_if_missing(name, value):
        if not hasattr(settings, name):
            setattr(settings, name, value)
            return True
        return False

    # Storage mode compatibility
    storage_type = legacy.get("STORAGE_TYPE")
    if storage_type:
        set_if_missing("AIWAF_STORAGE_MODE", storage_type)

    # Training mode compatibility
    training_mode = legacy.get("TRAINING_MODE")
    if training_mode is False:
        set_if_missing("AIWAF_DISABLE_AI", True)

    # Rate limiting compatibility
    rate = legacy.get("RATE_LIMITING")
    if isinstance(rate, dict):
        rpm = rate.get("REQUESTS_PER_MINUTE")
        if rpm is not None:
            set_if_missing("AIWAF_RATE_WINDOW", 60)
            set_if_missing("AIWAF_RATE_MAX", rpm)
        burst = rate.get("BURST_THRESHOLD")
        if burst is not None:
            set_if_missing("AIWAF_RATE_FLOOD", burst)

    # Exemptions compatibility
    exemptions = legacy.get("EXEMPTIONS")
    if isinstance(exemptions, dict):
        paths = exemptions.get("PATHS")
        if paths:
            set_if_missing("AIWAF_EXEMPT_PATHS", list(paths))
        ips = exemptions.get("IPS")
        if ips:
            set_if_missing("AIWAF_EXEMPT_IPS", list(ips))

    # Keyword detection compatibility
    keyword = legacy.get("KEYWORD_DETECTION")
    if isinstance(keyword, dict):
        enabled = keyword.get("ENABLED")
        if enabled is not None:
            set_if_missing("AIWAF_ENABLE_KEYWORD_LEARNING", bool(enabled))

        sensitivity = keyword.get("SENSITIVITY_LEVEL")
        sensitivity_map = {"low": 5, "medium": 10, "high": 20}
        if isinstance(sensitivity, str):
            mapped = sensitivity_map.get(sensitivity.lower())
            if mapped is not None:
                set_if_missing("AIWAF_DYNAMIC_TOP_N", mapped)

        patterns = keyword.get("CUSTOM_PATTERNS")
        if patterns:
            existing = list(getattr(settings, "AIWAF_MALICIOUS_KEYWORDS", []))
            merged = []
            for token in existing + list(patterns):
                if token not in merged:
                    merged.append(token)
            setattr(settings, "AIWAF_MALICIOUS_KEYWORDS", merged)

    # IP blocking compatibility
    ip_blocking = legacy.get("IP_BLOCKING")
    if isinstance(ip_blocking, dict):
        enabled = ip_blocking.get("ENABLED")
        if enabled is not None:
            set_if_missing("AIWAF_ENABLE_IP_BLOCKING", bool(enabled))
        whitelist = ip_blocking.get("WHITELIST")
        if whitelist:
            set_if_missing("AIWAF_EXEMPT_IPS", list(whitelist))

    # Logging compatibility (best-effort)
    logging_cfg = legacy.get("LOGGING")
    if isinstance(logging_cfg, dict):
        enabled = logging_cfg.get("ENABLED")
        if enabled is not None:
            set_if_missing("AIWAF_MIDDLEWARE_LOGGING", bool(enabled))
        level = logging_cfg.get("LEVEL")
        if level is not None:
            set_if_missing("AIWAF_LOG_LEVEL", level)
        log_format = logging_cfg.get("FORMAT")
        if log_format is not None:
            set_if_missing("AIWAF_LOG_FORMAT", log_format)

    if logger.isEnabledFor(logging.INFO):
        logger.info("Applied AIWAF_SETTINGS compatibility mapping.")
