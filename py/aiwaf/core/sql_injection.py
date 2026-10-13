"""Bounded SQL signatures and body buffering that preserves downstream reads."""
from collections import deque
from dataclasses import dataclass
import io
import json
import logging
import os
import re
from urllib.parse import unquote_plus
from .native_runtime import function as native_function

LOGGER = logging.getLogger("aiwaf.payload")
RULES = tuple((name, re.compile(pattern, re.I)) for name, pattern in (
    ("sql_union_select", r"\bunion\s+(?:all\s+)?select\b"),
    ("sql_boolean_tautology", r"['\"`]\s*(?:or|and)\s+(?:true\b|\d+\s*=\s*\d+|['\"][^'\"\r\n]{0,80}['\"]\s*=\s*['\"])"),
    ("sql_quote_comment", r"['\"`]\s*(?:--|#)"),
    ("sql_stacked_statement", r";\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b"),
))


@dataclass(frozen=True)
class Finding:
    rule: str
    status: int = 403


class SQLInjectionPolicy:
    def __init__(self, mode=None, max_bytes=None):
        self.mode = str(mode if mode is not None else os.getenv("AIWAF_SQL_INJECTION_MODE", "block")).lower()
        if self.mode not in ("block", "monitor", "off"):
            raise ValueError("Invalid AIWAF_SQL_INJECTION_MODE")
        value = max_bytes if max_bytes is not None else os.getenv("AIWAF_PAYLOAD_MAX_BYTES", "65536")
        if isinstance(value, bool) or str(value) != str(int(value)) or not 1 <= int(value) <= 1048576:
            raise ValueError("AIWAF_PAYLOAD_MAX_BYTES must be 1..1048576")
        self.max_bytes = int(value)

    def inspect(self, query=None, body=None):
        if self.mode == "off":
            return None
        stack, seen, size, nodes = [(query, 0), (body, 0)], set(), 0, 0
        batch_native = native_function('policy_sql_signatures')
        single_native = native_function('policy_sql_signature') if batch_native is not None else None
        immediate_checks = 0
        pending = []

        def flush():
            if not pending:
                return None
            rule = batch_native(pending)
            pending.clear()
            return Finding(rule) if rule else None

        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > 4096 or depth > 16:
                return flush() or Finding("payload_inspection_limit", 413)
            if value is None:
                continue
            if isinstance(value, bytes):
                if size + len(value) > self.max_bytes:
                    return flush() or Finding("payload_inspection_limit", 413)
                if b'\x00' in value or value.startswith((b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff')):
                    try:
                        parsed = json.loads(value)
                    except (ValueError, UnicodeError, RecursionError):
                        pass
                    else:
                        size += len(value)
                        stack.append((parsed, depth + 1))
                        continue
                stack.append((value.decode("utf-8", errors="replace"), depth + 1))
            elif isinstance(value, (dict, list, tuple)):
                if id(value) in seen:
                    return flush() or Finding("payload_inspection_limit", 413)
                seen.add(id(value))
                values = (item for pair in value.items() for item in pair) if isinstance(value, dict) else iter(value)
                for item in values:
                    stack.append((item, depth + 1))
                    if len(stack) > 4096:
                        return flush() or Finding("payload_inspection_limit", 413)
            elif isinstance(value, str):
                size += len(value.encode("utf-8", errors="replace"))
                if size > self.max_bytes:
                    return flush() or Finding("payload_inspection_limit", 413)
                for _ in range(2):
                    value = unquote_plus(value)
                if value.lstrip().startswith(("{", "[")):
                    try:
                        stack.append((json.loads(value), depth + 1))
                    except (ValueError, RecursionError):
                        pass
                if batch_native is not None and value.isascii():
                    # Reject attacks near the start immediately rather than
                    # preparing a complete batch before checking them.
                    if immediate_checks < 8:
                        immediate_checks += 1
                        rule = single_native(value) if single_native is not None else batch_native([value])
                        if rule:
                            return Finding(rule)
                        continue
                    pending.append(value)
                    if len(pending) >= 128:
                        finding = flush()
                        if finding:
                            return finding
                    continue
                # Earlier ASCII findings retain precedence over Unicode checks.
                finding = flush()
                if finding:
                    return finding
                native = native_function('policy_sql_signature')
                if native is not None and value.isascii():
                    rule = native(value)
                    if rule:
                        return Finding(rule)
                    continue
                value = re.sub(r"/\*[\s\S]*?\*/", " ", value)
                for name, pattern in RULES:
                    if pattern.search(value):
                        return Finding(name)
        return flush()

    def enforce(self, finding):
        if finding and self.mode == "monitor":
            LOGGER.warning("aiwaf.payload rule=%s mode=monitor", finding.rule)
            return None
        return finding


def inspectable_content_type(content_type):
    media = (content_type or "").split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json") or media == "application/x-www-form-urlencoded"


class _PrefixStream(io.RawIOBase):
    def __init__(self, prefix, stream):
        super().__init__()
        self.prefix, self.stream = io.BytesIO(prefix), stream

    def readable(self):
        return True

    def readinto(self, target):
        data = self.prefix.read(len(target))
        if not data:
            data = self.stream.read(len(target))
        target[:len(data)] = data
        return len(data)


def inspect_wsgi_request(request, policy, *, django=False, evaluator=None):
    """Read at most budget+1 bytes and prepend them for the application's parser."""
    if policy.mode == "off":
        if evaluator is not None:
            query = request.META.get("QUERY_STRING", "") if django else request.query_string
            return evaluator(query, None)
        return None
    if django:
        query = request.META.get("QUERY_STRING", "")
        content_type = request.META.get("CONTENT_TYPE", "")
        cached = getattr(request, "_body", None)
    else:
        query, content_type = request.query_string, request.content_type
        cached = getattr(request, "_cached_data", None)
    body = None
    if inspectable_content_type(content_type):
        if cached is not None:
            body = cached
        elif django:
            body = request.read(policy.max_bytes + 1)
            request._stream = io.BufferedReader(_PrefixStream(body, request._stream))
            request._read_started = False
        else:
            stream = request.stream
            body = stream.read(policy.max_bytes + 1)
            request.stream = io.BufferedReader(_PrefixStream(body, stream))
    return policy.enforce((evaluator or policy.inspect)(query, body))


async def inspect_asgi_request(request, policy, *, evaluator=None):
    """Replay exact ASGI messages, including an over-budget monitor-mode prefix."""
    if policy.mode == "off":
        if evaluator is not None:
            return evaluator(request.scope.get("query_string", b""), None)
        return None
    body = None
    if inspectable_content_type(request.headers.get("content-type")):
        if hasattr(request, "_body"):
            body = request._body
        else:
            original_receive, messages, chunks, size = request.receive, deque(), [], 0
            buffered, exhausted = 0, False
            while True:
                message = await original_receive()
                messages.append(message)
                if message["type"] != "http.request":
                    break
                chunk = message.get("body", b"")
                size += len(chunk)
                prefix = chunk[:max(0, policy.max_bytes + 1 - buffered)]
                chunks.append(prefix)
                buffered += len(prefix)
                if size > policy.max_bytes or not message.get("more_body", False):
                    break
                if len(messages) >= 4096:
                    exhausted = True
                    break

            async def replay():
                return messages.popleft() if messages else await original_receive()

            request._receive = replay
            body = b"".join(chunks)
            if exhausted:
                return policy.enforce(Finding("payload_inspection_limit", 413))
    query = request.scope.get("query_string", b"")
    return policy.enforce((evaluator or policy.inspect)(query, body))
