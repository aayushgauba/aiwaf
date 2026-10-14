"""
Shared blocklist policy helpers.
"""

from __future__ import annotations


def should_block_ip(enable_blocking: bool, is_exempt_func, ip: str) -> bool:
    if not enable_blocking:
        return False
    if is_exempt_func and is_exempt_func(ip):
        return False
    return True


def should_unblock_ip(enable_blocking: bool, is_exempt_func, ip: str) -> bool:
    if not enable_blocking:
        return False
    if is_exempt_func and is_exempt_func(ip):
        return False
    return True
