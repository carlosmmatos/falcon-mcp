"""Bounded MCP results and session-isolated, temporary result navigation.

The budget is UTF-8 bytes of CallToolResult.model_dump_json(exclude_none=True,
by_alias=True), including escaped text and metadata, excluding the JSON-RPC shell.
"""

import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from functools import partial
from typing import Any, Literal

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field


class ResponseOptions(BaseModel):
    """Presentation controls; never sent to Falcon."""

    model_config = ConfigDict(extra="forbid")
    detail_level: Literal["summary", "compact", "full"] = Field(
        default="full",
        description="full preserves all fields but remains bounded; summary/compact project recognized entities.",
    )
    fields: list[str] | None = Field(
        default=None,
        max_length=64,
        description="Exact top-level entity fields, overriding detail_level; identifiers always retained.",
    )
    max_bytes: int | None = Field(
        default=None, ge=2048, description="Lower the server byte budget."
    )


def encode(value: Any) -> str:
    """Serialize JSON without whitespace, preserving Unicode."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def result(value: Any, is_error: bool = False) -> CallToolResult:
    """Use one JSON text block, with no duplicate structured content."""
    return CallToolResult(content=[TextContent(type="text", text=encode(value))], isError=is_error)


def size(value: CallToolResult) -> int:
    """Measure the actual SDK result serialization, not Python repr or tokens."""
    return len(value.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))


IDENTIFIERS = {
    "id",
    "ids",
    "aid",
    "cid",
    "device_id",
    "composite_id",
    "detection_id",
    "incident_id",
}
SUMMARY = IDENTIFIERS | {"hostname", "severity", "status", "name", "platform_name"}
COMPACT = SUMMARY | {
    "created_timestamp",
    "updated_timestamp",
    "first_seen",
    "last_seen",
    "timestamp",
    "tactic",
    "technique",
    "tactic_id",
    "technique_id",
    "behaviors",
    "description",
}


def project(value: Any, options: ResponseOptions) -> tuple[Any, int]:
    """Project entity rows only; retain envelopes, aggregates and unknown schemas."""
    omitted = 0

    def row(item: Any) -> Any:
        nonlocal omitted
        if not isinstance(item, dict) or "error" in item:
            return item
        known = (
            ("device_id" in item and "hostname" in item)
            or "composite_id" in item
            or "detection_id" in item
        )
        if options.fields is not None:
            keep = set(options.fields) | IDENTIFIERS
        elif known and options.detail_level != "full":
            keep = SUMMARY if options.detail_level == "summary" else COMPACT
        else:
            return item
        omitted += len(set(item) - keep)
        return {k: v for k, v in item.items() if k in keep}

    if isinstance(value, list):
        return [row(item) for item in value], omitted
    if isinstance(value, dict) and isinstance(value.get("results"), list):
        rows = [row(item) for item in value["results"]]
        return {**value, "results": rows}, omitted
    return row(value), omitted


@dataclass
class Snapshot:
    owner: object
    data: str
    expires: float
    timer: threading.Timer


class ResultStore:
    """Hard admission limits, no live eviction, and active expiration cleanup."""

    def __init__(self, max_bytes: int = 64 * 1024 * 1024, ttl: int = 300) -> None:
        self.max_bytes = max_bytes
        self.ttl = ttl
        self.entries: dict[str, Snapshot] = {}
        self.used = 0
        self.lock = threading.RLock()

    def remove(self, handle: str) -> None:
        with self.lock:
            entry = self.entries.pop(handle, None)
            if entry:
                self.used -= len(entry.data.encode("utf-8"))
                entry.timer.cancel()

    def put(self, owner: object, data: Any) -> str | None:
        serialized = encode(data)
        count = len(serialized.encode("utf-8"))
        with self.lock:
            if count + self.used > self.max_bytes or len(self.entries) >= 128:
                return None
            handle = secrets.token_urlsafe(24)
            timer = threading.Timer(self.ttl, self.remove, args=(handle,))
            timer.daemon = True
            self.entries[handle] = Snapshot(owner, serialized, time.monotonic() + self.ttl, timer)
            self.used += count
            timer.start()
            return handle

    def get(self, owner: object, handle: str) -> Any:
        with self.lock:
            entry = self.entries.get(handle)
            if entry is None or entry.owner is not owner or entry.expires <= time.monotonic():
                raise ValueError(
                    "Result unavailable: expired, different session, or different worker. Do not automatically repeat mutations."
                )
            return json.loads(entry.data)


class BoundedFastMCP(FastMCP):
    """Apply presentation exactly once, after normal or dynamic execution."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.response_budget = int(os.getenv("FALCON_MCP_RESPONSE_MAX_BYTES", "25000"))
        if not 2048 <= self.response_budget <= 1_000_000:
            raise ValueError("FALCON_MCP_RESPONSE_MAX_BYTES must be 2048..1000000")
        ttl = int(os.getenv("FALCON_MCP_RESULT_TTL_SECONDS", "300"))
        capacity = int(os.getenv("FALCON_MCP_RESULT_STORE_BYTES", str(64 * 1024 * 1024)))
        if not 1 <= ttl <= 3600 or not 1024 <= capacity <= 1024 * 1024 * 1024:
            raise ValueError(
                "Result TTL must be 1..3600 seconds and store capacity 1024..1073741824 bytes"
            )
        self.results = ResultStore(max_bytes=capacity, ttl=ttl)
        super().__init__(*args, **kwargs)

    def register_result_tool(self) -> None:
        self.add_tool(
            self.read_result,
            name="falcon_read_result",
            structured_output=False,
            annotations=ToolAnnotations(
                readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
            ),
        )

    async def list_tools(self) -> list[Tool]:
        tools = await super().list_tools()
        for tool in tools:
            if tool.name != "falcon_read_result":
                tool.inputSchema = {
                    **tool.inputSchema,
                    "properties": {
                        **tool.inputSchema.get("properties", {}),
                        "response_options": ResponseOptions.model_json_schema(),
                    },
                }
                tool.description = (tool.description or "") + (
                    " Responses are byte-bounded. response_options selects full (default), compact, "
                    "summary, fields, or max_bytes. If response_control is returned, use "
                    "falcon_read_result to inspect the saved result before upstream pagination."
                )
            # This boundary returns JSON text, including for fallback envelopes.
            tool.outputSchema = None
        return tools

    def owner(self) -> object | None:
        if self.settings.stateless_http:
            return None
        try:
            return self.get_context().session
        except (ValueError, LookupError):
            return None

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        options = ResponseOptions()
        try:
            arguments = dict(arguments)
            options = ResponseOptions.model_validate(arguments.pop("response_options", {}))
            raw = await self._tool_manager.call_tool(
                name, arguments, context=self.get_context(), convert_result=False
            )
            if isinstance(raw, CallToolResult):
                if size(raw) <= min(
                    options.max_bytes or self.response_budget, self.response_budget
                ):
                    return raw
                is_error = raw.isError
                raw = raw.model_dump(mode="json", by_alias=True, exclude_none=True)
            else:
                is_error = False
            return await anyio.to_thread.run_sync(
                partial(self.present, raw, options, self.owner(), is_error=is_error)
            )
        except Exception as exc:
            return await anyio.to_thread.run_sync(
                partial(self.present, {"error": str(exc)}, options, self.owner(), is_error=True)
            )

    def present(
        self, raw: Any, options: ResponseOptions, owner: object | None, is_error: bool = False
    ) -> CallToolResult:
        budget = min(options.max_bytes or self.response_budget, self.response_budget)
        projected, omitted = project(raw, options)
        output = result(projected, is_error)
        if not omitted and size(output) <= budget:
            return output
        handle = self.results.put(owner, raw) if owner is not None else None
        control: dict[str, Any] = {
            "detail_level": options.detail_level,
            "projected_fields": omitted,
            "budget_bytes": budget,
            "result_handle": handle,
            "expires_in_seconds": self.results.ttl if handle else None,
            "upstream_pagination": "Unchanged in saved result. Finish reading this snapshot before using the endpoint's next page parameter.",
            "retrieval": "Call falcon_read_result(result_handle, path=[], start=0). Use path to inspect children; mode=json_text reads large scalar/serialized values in bounded segments.",
        }
        if not handle:
            control["recovery_error"] = (
                "Snapshot unavailable (storage full or no persistent MCP session). "
                "Reduce endpoint limit, narrow filters/IDs, or aggregate NG-SIEM queries. "
                "Do not repeat mutations automatically; verify their outcome first."
            )
        candidate = result(
            {"data": projected, "response_control": {**control, "records_withheld": False}},
            is_error,
        )
        if size(candidate) <= budget:
            return candidate
        # No partial upstream page is published, so its cursor cannot skip hidden rows.
        control["result_withheld"] = True
        # Unknown dictionaries/scalars are not necessarily entity records.
        control["records_withheld"] = None
        control["saved_result_complete"] = bool(handle)
        control["root_type"] = type(raw).__name__
        control["root_count"] = len(raw) if isinstance(raw, (dict, list)) else None
        control["error_present"] = is_error or (
            (isinstance(raw, dict) and "error" in raw)
            or (
                isinstance(raw, dict)
                and isinstance(raw.get("results"), list)
                and any(isinstance(row, dict) and "error" in row for row in raw["results"])
            )
            or (
                isinstance(raw, list)
                and any(isinstance(row, dict) and "error" in row for row in raw)
            )
        )
        if isinstance(raw, dict) and isinstance(raw.get("results"), list):
            control["withheld_record_count"] = len(raw["results"])
            control["records_withheld"] = bool(raw["results"])
        elif isinstance(raw, list):
            control["withheld_record_count"] = len(raw)
            control["records_withheld"] = bool(raw)
        pagination = raw.get("pagination") if isinstance(raw, dict) else None
        if isinstance(pagination, dict) and pagination.get("next") is not None:
            control["upstream_cursor_withheld"] = True
        # Preserve useful investigation metadata inline when it fits. Large values
        # remain navigable in the snapshot rather than being cut mid-field.
        preview: dict[str, Any] = {}
        if isinstance(raw, dict):
            for key in (
                "error",
                "pagination",
                "job",
                "filter_used",
                "query_used",
                "required_scopes",
            ):
                if key in raw:
                    metadata_value = raw[key]
                    if key == "pagination" and control.get("upstream_cursor_withheld"):
                        metadata_value = {**metadata_value, "next": None}
                    candidate = result(
                        {"metadata": {**preview, key: metadata_value}, "response_control": control},
                        is_error,
                    )
                    if size(candidate) <= budget:
                        preview[key] = metadata_value
        # Metadata pagination is informational, never a server continuation.
        output = result({"metadata": preview, "response_control": control}, is_error)
        assert size(output) <= budget
        return output

    async def read_result(
        self,
        result_handle: str,
        path: list[str | int] | None = None,
        start: int = 0,
        mode: Literal["value", "json_text"] = "value",
    ) -> CallToolResult:
        """Read a saved result in this MCP session, without a Falcon API call.

        path selects nested fields or array indexes. Integer segments on objects
        select their insertion-order value, allowing navigation even with huge keys.
        value returns whole values when small, otherwise bounded child entries.
        Follow next_start at the SAME path until null; descend using each entry's index.
        json_text returns slices of serialized JSON (start counts Unicode code points);
        concatenate text segments to reconstruct the exact selected value. Each response
        itself is valid JSON. Stored upstream totals/cursors are unchanged: finish the
        snapshot before advancing upstream, using the original endpoint's parameter.
        Handles expire after the advertised expires_in_seconds (default 300) and
        require the same session and worker.
        """
        return await anyio.to_thread.run_sync(
            partial(self._read_result, self.owner(), result_handle, path, start, mode)
        )

    def _read_result(
        self,
        owner: object | None,
        result_handle: str,
        path: list[str | int] | None,
        start: int,
        mode: Literal["value", "json_text"],
    ) -> CallToolResult:
        """Navigate and serialize off the event loop, using the captured session owner."""
        try:
            if start < 0:
                raise ValueError("start must be nonnegative")
            value = self.results.get(owner, result_handle)
            for segment in path or []:
                if isinstance(value, dict) and isinstance(segment, int):
                    if segment < 0:
                        raise ValueError("negative path index")
                    value = list(value.values())[segment]
                else:
                    if isinstance(segment, int) and segment < 0:
                        raise ValueError("negative path index")
                    value = value[segment]
            if mode == "value" and start == 0:
                whole = result({"value": value, "next_start": None})
                if size(whole) <= self.response_budget:
                    return whole
            if mode == "json_text" or not isinstance(value, (list, dict)):
                text = encode(value)
                if start > len(text):
                    raise ValueError("start exceeds serialized value length")
                low, high = 0, min(len(text) - start, self.response_budget)
                while low < high:
                    mid = (low + high + 1) // 2
                    candidate = result(
                        {
                            "mode": "json_text",
                            "text": text[start : start + mid],
                            "next_start": start + mid if start + mid < len(text) else None,
                            "total_characters": len(text),
                        }
                    )
                    if size(candidate) <= self.response_budget:
                        low = mid
                    else:
                        high = mid - 1
                return result(
                    {
                        "mode": "json_text",
                        "text": text[start : start + low],
                        "next_start": start + low if start + low < len(text) else None,
                        "total_characters": len(text),
                    }
                )
            children = list(value.items()) if isinstance(value, dict) else list(enumerate(value))
            if start > len(children):
                raise ValueError("start exceeds child count")
            entries: list[dict[str, Any]] = []
            for index in range(start, len(children)):
                key, child = children[index]
                item = {"index": index, "key": key, "value": child}
                candidate = result(
                    {
                        "entries": entries + [item],
                        "next_start": index + 1 if index + 1 < len(children) else None,
                        "total_children": len(children),
                    }
                )
                if size(candidate) > self.response_budget:
                    if entries:
                        break
                    item = {
                        "index": index,
                        "deferred": True,
                        "type": type(child).__name__,
                        "hint": "Append index to path to read this child. Read parent with mode=json_text for complete keys.",
                    }
                    # Keys can themselves exceed the budget; numeric paths remain usable.
                    if len(encode(key).encode("utf-8")) < 256:
                        item["key"] = key
                entries.append(item)
            end = start + len(entries)
            return result(
                {
                    "entries": entries,
                    "next_start": end if end < len(children) else None,
                    "total_children": len(children),
                }
            )
        except (ValueError, KeyError, IndexError, TypeError):
            return result(
                {
                    "error": "Result/path unavailable, expired, belongs to another session/worker, or start is invalid. Check path and start. Do not automatically repeat mutations."
                },
                True,
            )
