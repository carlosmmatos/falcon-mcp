"""Bound oversized MCP tool results without changing handlers or happy-path shapes.

Fitting results are returned unchanged. Oversized list/search pages keep a prefix of
complete records and an ``overflow`` footer; a single value that cannot fit is stored
and read back through ``falcon_continue_result``. The budget is the Unicode character
count of the unstructured text FastMCP would put in ``CallToolResult.content``.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from functools import partial
from typing import Any

import anyio
import pydantic_core
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import unwrap_field_default

logger = get_logger(__name__)

CONTINUE_TOOL = "falcon_continue_result"
DEFAULT_MAX_CHARS = 25_000
MIN_MAX_CHARS = 256
CLI_MIN_MAX_CHARS = 2_000
MAX_MAX_CHARS = 1_000_000
DEFAULT_TTL_SECONDS = 300
DEFAULT_STORE_BYTES = 64 * 1024 * 1024
_MAX_STORE_ENTRIES = 128
_MAX_OVERFLOW_IDS = 40
_ENVELOPE_KEEP = frozenset(
    {
        "pagination",
        "filter_used",
        "query_used",
        "error",
        "required_scopes",
        "hint",
        "job",
    }
)

_ID_KEYS = (
    "composite_id",
    "detection_id",
    "device_id",
    "incident_id",
    "case_id",
    "session_id",
    "job_id",
    "indicator_id",
    "uuid",
    "aid",
    "cid",
    "id",
    "_id",
)

_CONTINUE_HINT = (
    "Unread rows remain from this Falcon page. Call falcon_continue_result with "
    "this handle and overflow.offset before following pagination.next. Do not "
    "replay mutations to recover data."
)
_TEXT_HINT = (
    "This value does not fit as one JSON object. Concatenate overflow.text from "
    "falcon_continue_result calls, advancing char_offset, then increment offset "
    "when record_complete is true."
)
_NO_HANDLE_HINT = (
    "No snapshot is available (stateless HTTP, storage full, or expired). Use "
    "overflow.ids with a get-by-id tool, or narrow the query. Do not automatically "
    "repeat mutations."
)


def coerce_max_chars(value: Any, *, cli: bool = False) -> int:
    """Coerce a budget to the allowed range; invalid input becomes the default."""
    try:
        budget = int(unwrap_field_default(value))
    except (TypeError, ValueError):
        return DEFAULT_MAX_CHARS
    minimum = CLI_MIN_MAX_CHARS if cli else MIN_MAX_CHARS
    return max(minimum, min(budget, MAX_MAX_CHARS))


def mcp_text(value: Any) -> str:
    """Reproduce the unstructured text FastMCP writes for ``structured_output=False``."""
    if isinstance(value, CallToolResult):
        return "".join(
            block.text
            for block in value.content
            if isinstance(block, TextContent) and block.text
        )
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "".join(mcp_text(item) for item in value)
    return pydantic_core.to_json(value, fallback=str, indent=2).decode()


def mcp_size(value: Any) -> int:
    """Unicode character count of the MCP text payload."""
    return len(mcp_text(value))


def record_id(record: Any) -> Any | None:
    """Best identifier from a record, or None."""
    if not isinstance(record, dict):
        return None
    for key in _ID_KEYS:
        value = record.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            return value
    for key, value in record.items():
        if key.endswith("_id") and value is not None and not isinstance(value, (dict, list)):
            return value
    return None


def record_ids(records: list[Any], limit: int = _MAX_OVERFLOW_IDS) -> list[Any]:
    """Collect identifiers from records, preserving order and skipping blanks."""
    ids: list[Any] = []
    for record in records:
        found = record_id(record)
        if found is not None:
            ids.append(found)
        if len(ids) >= limit:
            break
    return ids


def as_rows(value: Any) -> tuple[list[Any] | None, dict[str, Any]]:
    """Split a list or search envelope into rows plus the remaining envelope."""
    if isinstance(value, list):
        return value, {}
    if isinstance(value, dict) and isinstance(value.get("results"), list):
        extra = {key: item for key, item in value.items() if key != "results"}
        return value["results"], extra
    return None, {}


class OverflowStore:
    """Session-isolated, capacity-limited snapshots of overflowed tool results."""

    def __init__(
        self,
        max_bytes: int = DEFAULT_STORE_BYTES,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.max_bytes = max_bytes
        self.ttl_seconds = ttl_seconds
        self._entries: dict[str, tuple[object, str, float]] = {}
        self._used = 0
        self._lock = threading.Lock()

    def _purge_locked(self, now: float) -> None:
        expired = [handle for handle, item in self._entries.items() if item[2] <= now]
        for handle in expired:
            _owner, payload, _expires = self._entries.pop(handle)
            self._used -= len(payload.encode("utf-8"))

    def put(self, owner: object | None, data: Any) -> str | None:
        """Store ``data`` for ``owner``. Returns None when storage is unavailable."""
        if owner is None:
            return None
        try:
            payload = json.dumps(data, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return None
        count = len(payload.encode("utf-8"))
        with self._lock:
            self._purge_locked(time.monotonic())
            if count + self._used > self.max_bytes or len(self._entries) >= _MAX_STORE_ENTRIES:
                return None
            handle = secrets.token_urlsafe(18)
            self._entries[handle] = (owner, payload, time.monotonic() + self.ttl_seconds)
            self._used += count
            return handle

    def get(self, owner: object | None, handle: str) -> Any:
        """Return the stored value or raise ValueError if it is not readable."""
        with self._lock:
            self._purge_locked(time.monotonic())
            entry = self._entries.get(handle)
            if entry is None or entry[0] is not owner:
                raise ValueError(
                    "Result unavailable: expired, different session, or different worker. "
                    "Do not automatically repeat mutations."
                )
            return json.loads(entry[1])


def bound_result(
    value: Any,
    budget: int,
    store: OverflowStore,
    owner: object | None,
    *,
    offset: int = 0,
    char_offset: int = 0,
    handle: str | None = None,
) -> Any:
    """Return ``value`` unchanged when it fits; otherwise a sliced overflow document."""
    if offset < 0 or char_offset < 0:
        return {"error": "offset and char_offset must be nonnegative"}

    rows, envelope = as_rows(value)
    if rows is None:
        if offset == 0 and char_offset == 0 and mcp_size(value) <= budget:
            return value
        return _bound_value_text(value, budget, store, owner, char_offset, handle)

    if offset == 0 and char_offset == 0 and mcp_size(value) <= budget:
        return value
    if offset > len(rows):
        return {"error": "offset exceeds saved result"}

    remaining = rows[offset:]
    snapshot = handle or store.put(owner, value)
    if char_offset:
        if not remaining:
            return {"error": "char_offset was set but no record remains at offset"}
        return _bound_record_text(
            remaining[0],
            envelope,
            budget,
            snapshot,
            record_offset=offset,
            char_offset=char_offset,
            leftover=len(remaining) - 1,
            ids=record_ids(remaining[1:]),
        )

    included: list[Any] = []
    for index, row in enumerate(remaining):
        trial = _envelope(
            envelope,
            included + [row],
            _footer(
                remaining=len(remaining) - (index + 1),
                offset=offset + index + 1,
                ids=record_ids(remaining[index + 1 :]),
                handle=snapshot,
                unit="records",
            ),
        )
        if mcp_size(trial) <= budget:
            included.append(row)
            continue
        if not included:
            return _bound_record_text(
                row,
                envelope,
                budget,
                snapshot,
                record_offset=offset,
                char_offset=0,
                leftover=len(remaining) - 1,
                ids=record_ids(remaining[1:]),
            )
        break

    next_offset = offset + len(included)
    leftover_rows = rows[next_offset:]
    footer = _footer(
        remaining=len(leftover_rows),
        offset=next_offset,
        ids=record_ids(leftover_rows),
        handle=snapshot,
        unit="records",
    )
    return _fit(_envelope(envelope, included, footer), budget)


def _footer(
    *,
    remaining: int,
    offset: int,
    ids: list[Any],
    handle: str | None,
    unit: str,
    **extra: Any,
) -> dict[str, Any]:
    hint = _CONTINUE_HINT if handle else _NO_HANDLE_HINT
    if unit == "characters":
        hint = _TEXT_HINT if handle else _NO_HANDLE_HINT
    footer: dict[str, Any] = {
        "remaining": remaining,
        "offset": offset,
        "ids": ids,
        "handle": handle,
        "unit": unit,
        "hint": hint,
    }
    footer.update(extra)
    return footer


def _envelope(
    extra: dict[str, Any],
    included: list[Any],
    footer: dict[str, Any],
) -> dict[str, Any]:
    body = {key: extra[key] for key in _ENVELOPE_KEEP if key in extra}
    pagination = body.get("pagination")
    if isinstance(pagination, dict):
        pagination = dict(pagination)
        if footer.get("remaining"):
            footer = dict(footer)
            # Cursor tokens (Spotlight `after`) can exceed the budget on their own.
            # Keep them in the snapshot; restore pagination.next when remaining is 0.
            if pagination.get("next") is not None:
                footer["upstream_cursor"] = True
            pagination["next"] = None
        body["pagination"] = pagination
    body["results"] = included
    body["overflow"] = footer
    return body


def _fit(body: dict[str, Any], budget: int) -> dict[str, Any]:
    """Drop overflow ids/hints until the stamped document fits, then give up cleanly."""
    if mcp_size(body) <= budget:
        return body
    footer = dict(body.get("overflow") or {})
    ids = list(footer.get("ids") or [])
    while ids and mcp_size(body) > budget:
        ids = ids[: max(0, len(ids) // 2)] if len(ids) > 8 else ids[:-1]
        footer["ids"] = ids
        body["overflow"] = footer
    if mcp_size(body) <= budget:
        return body
    footer.pop("hint", None)
    body["overflow"] = footer
    if mcp_size(body) <= budget:
        return body
    minimal = {
        "results": body.get("results") or [],
        "overflow": {
            "remaining": footer.get("remaining"),
            "offset": footer.get("offset"),
            "handle": footer.get("handle"),
            "unit": footer.get("unit", "records"),
        },
    }
    if mcp_size(minimal) <= budget:
        return minimal
    return {
        "overflow": {
            "remaining": footer.get("remaining"),
            "offset": footer.get("offset"),
            "handle": footer.get("handle"),
        }
    }


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))


def _bound_record_text(
    row: Any,
    envelope: dict[str, Any],
    budget: int,
    handle: str | None,
    *,
    record_offset: int,
    char_offset: int,
    leftover: int,
    ids: list[Any] | None = None,
) -> dict[str, Any]:
    text = _compact_json(row)
    return _slice_text(
        text,
        budget,
        handle,
        char_offset=char_offset,
        record_offset=record_offset,
        leftover=leftover,
        envelope=envelope,
        ids=ids or record_ids([row]),
    )


def _bound_value_text(
    value: Any,
    budget: int,
    store: OverflowStore,
    owner: object | None,
    char_offset: int,
    handle: str | None,
) -> Any:
    snapshot = handle or store.put(owner, value)
    text = _compact_json(value) if not isinstance(value, str) else value
    if char_offset == 0 and not snapshot:
        stub = {
            "overflow": _footer(
                remaining=1,
                offset=0,
                ids=record_ids([value]) if isinstance(value, dict) else [],
                handle=None,
                unit="characters",
            )
        }
        if isinstance(value, dict) and "error" in value:
            stub["error"] = value["error"]
        return _fit(stub, budget)
    return _slice_text(
        text,
        budget,
        snapshot,
        char_offset=char_offset,
        record_offset=0,
        leftover=0,
        envelope={},
        ids=record_ids([value]) if isinstance(value, dict) else [],
    )


def _slice_text(
    text: str,
    budget: int,
    handle: str | None,
    *,
    char_offset: int,
    record_offset: int,
    leftover: int,
    envelope: dict[str, Any],
    ids: list[Any] | None = None,
) -> dict[str, Any]:
    if char_offset > len(text):
        return {"error": "char_offset exceeds saved value"}

    def build(length: int) -> dict[str, Any]:
        end = char_offset + length
        complete = end >= len(text)
        footer = _footer(
            remaining=leftover + (0 if complete else 1),
            offset=record_offset + (1 if complete else 0),
            ids=ids or [],
            handle=handle,
            unit="characters",
            char_offset=char_offset,
            next_char_offset=None if complete else end,
            record_complete=complete,
            total_characters=len(text),
            text=text[char_offset:end],
        )
        if envelope:
            return _envelope(envelope, [], footer)
        return {"overflow": footer}

    low, high = 0, len(text) - char_offset
    best = 0
    while low <= high:
        mid = (low + high) // 2
        if mcp_size(build(mid)) <= budget:
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    return _fit(build(best), budget)


class BoundedFastMCP(FastMCP):
    """Apply the overflow bound once, after normal or dynamic tool execution."""

    def __init__(
        self,
        *args: Any,
        response_max_chars: int | None = None,
        **kwargs: Any,
    ) -> None:
        raw = (
            response_max_chars
            if response_max_chars is not None
            else os.environ.get("FALCON_MCP_RESPONSE_MAX_CHARS", DEFAULT_MAX_CHARS)
        )
        self.response_max_chars = coerce_max_chars(raw)
        ttl = _coerce_int(
            os.environ.get("FALCON_MCP_OVERFLOW_TTL_SECONDS", DEFAULT_TTL_SECONDS),
            DEFAULT_TTL_SECONDS,
            1,
            3600,
        )
        capacity = _coerce_int(
            os.environ.get("FALCON_MCP_OVERFLOW_STORE_BYTES", DEFAULT_STORE_BYTES),
            DEFAULT_STORE_BYTES,
            1024,
            1024 * 1024 * 1024,
        )
        self.overflow_store = OverflowStore(max_bytes=capacity, ttl_seconds=ttl)
        super().__init__(*args, **kwargs)

    def register_overflow_tool(self) -> None:
        """Register the always-on continue tool. Safe to call once after other tools."""
        self.add_tool(
            self.continue_result,
            name=CONTINUE_TOOL,
            structured_output=False,
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )

    def owner(self) -> object | None:
        """Session object used as the snapshot ACL, or None when none exists."""
        if getattr(self.settings, "stateless_http", False):
            return None
        try:
            return self.get_context().session
        except (ValueError, LookupError):
            return None

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        context = self.get_context()
        raw = await self._tool_manager.call_tool(
            name, arguments, context=context, convert_result=False
        )
        tool = self._tool_manager.get_tool(name)
        if tool is None:
            return raw
        if name == CONTINUE_TOOL:
            return tool.fn_metadata.convert_result(raw)
        bounded = await anyio.to_thread.run_sync(
            partial(
                bound_result,
                raw,
                self.response_max_chars,
                self.overflow_store,
                self.owner(),
            )
        )
        return tool.fn_metadata.convert_result(bounded)

    def continue_result(
        self,
        handle: str = Field(
            description=(
                "Handle from overflow.handle. Reads the saved Falcon page in this "
                "MCP session without calling Falcon again."
            )
        ),
        offset: int = Field(
            default=0,
            ge=0,
            description="Record index into the saved page. Use overflow.offset from the last response.",
        ),
        char_offset: int = Field(
            default=0,
            ge=0,
            description=(
                "Unicode offset into a single record that does not fit as JSON. "
                "Use overflow.next_char_offset; leave 0 when packing records."
            ),
        ),
    ) -> Any:
        """Read the next slice of a saved oversized result.

        Use the handle and offset from the previous overflow object. When
        ``unit`` is ``characters``, also pass ``char_offset``. Finish the saved
        page before following the original tool's pagination.next.
        """
        try:
            saved = self.overflow_store.get(self.owner(), handle)
        except ValueError as exc:
            return {"error": str(exc)}
        return bound_result(
            saved,
            self.response_max_chars,
            self.overflow_store,
            self.owner(),
            offset=offset,
            char_offset=char_offset,
            handle=handle,
        )


def _coerce_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))
