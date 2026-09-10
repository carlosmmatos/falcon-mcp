"""Bound and project Falcon tool responses for MCP clients.

Falcon APIs can return more data than an MCP client can place in a model
context window. This module is the single shaping boundary used by every
module tool (normal registration and dynamic ``falcon_execute_tool``).

The budget measures **Unicode characters of the pretty-printed JSON text**
that FastMCP writes into ``CallToolResult.content`` (``pydantic_core.to_json``
with ``indent=2``). That is not a token count and is not the JSON-RPC frame
size. See ``docs/usage/response-handling.md``.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

import pydantic_core
from pydantic import Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import unwrap_field_default

logger = get_logger(__name__)

DEFAULT_CHAR_BUDGET = 25_000
ABSOLUTE_MIN_CHAR_BUDGET = 256
CLI_MIN_CHAR_BUDGET = 2_000
MAX_CHAR_BUDGET = 1_000_000
DEFAULT_DETAIL_LEVEL = "compact"
DETAIL_LEVELS = ("summary", "compact", "full")
DetailLevel = Literal["summary", "compact", "full"]

# Slack so inserting the final ``used`` / ``utf8_bytes`` figures cannot push a
# packed payload back over the caller-visible budget.
_BUDGET_SLACK = 96
_MAX_OMITTED_IDS = 50
_MAX_STRING_SUMMARY = 240
_MAX_STRING_COMPACT = 800
_NESTED_LIMIT_SUMMARY = 240
_NESTED_LIMIT_COMPACT = 1_500
_PREVIEW_CHARS = 200

IDENTITY_KEYS = frozenset(
    {
        "id",
        "_id",
        "composite_id",
        "device_id",
        "detection_id",
        "alert_id",
        "session_id",
        "uuid",
        "cid",
        "aid",
        "resource_id",
        "host_id",
        "rule_id",
        "group_id",
        "policy_id",
        "case_id",
        "agent_id",
        "sha256",
        "md5",
        "job_id",
        "indicator_id",
        "notification_id",
        "hostname",
        "name",
        "serial_number",
    }
)

TRIAGE_KEYS = frozenset(
    {
        "status",
        "severity",
        "severity_name",
        "state",
        "type",
        "product",
        "platform_name",
        "os_version",
        "confidence",
        "verdict",
        "tactic",
        "technique",
        "timestamp",
        "created_timestamp",
        "updated_timestamp",
        "last_seen",
        "first_seen",
        "external_ip",
        "local_ip",
        "mac_address",
        "agent_version",
        "assigned_to",
        "status_name",
        "max_severity",
        "max_confidence",
        "show_in_ui",
        "pattern_id",
        "scenario",
        "objective",
        "filename",
        "filepath",
        "description",
        "comment",
    }
)

BULKY_KEYS = frozenset(
    {
        "behaviors",
        "processes",
        "process",
        "files",
        "network_accesses",
        "dns_requests",
        "documents_accessed",
        "registry_keys",
        "script_content",
        "raw",
        "raw_event",
        "payload",
        "full_payload",
        "command_history",
        "stdout",
        "stderr",
        "output",
        "pattern_disposition_details",
        "device_policies",
        "related_alerts",
        "related_detections",
        "ioc_context",
        "screenshot",
        "memory_dump",
        "events",
        "logs",
    }
)

GUIDE_KEYS = frozenset({"fql_guide", "cql_guide"})

DETAIL_LEVEL_DESCRIPTION = (
    "Fields returned per record: 'summary' (identifiers and triage fields such as "
    "status, severity, hostname, timestamps), 'compact' (default; key operational "
    "fields, with bulky nested blobs replaced by an explicit omission marker), or "
    "'full' (every API field). full does not disable the response character budget. "
    "When records or fields are omitted, response.omitted_records lists ids and "
    "how to retrieve them — do not advance pagination.next/offset past withheld rows."
)

INCLUDE_FIELDS_DESCRIPTION = (
    "Optional field names to keep in addition to identifiers. Restricts the payload "
    "further than detail_level. Use to recover specific omitted fields without "
    "requesting full records."
)


@dataclass(frozen=True)
class ResponsePolicy:
    """Process-wide defaults applied at the MCP tool boundary."""

    char_budget: int = DEFAULT_CHAR_BUDGET
    default_detail_level: str = DEFAULT_DETAIL_LEVEL


_policy = ResponsePolicy()


def get_response_policy() -> ResponsePolicy:
    """Return the process-wide response policy."""
    return _policy


def configure_response_policy(policy: ResponsePolicy) -> None:
    """Replace the process-wide response policy (tests and server startup)."""
    global _policy
    _policy = ResponsePolicy(
        char_budget=_coerce_char_budget(policy.char_budget),
        default_detail_level=_coerce_detail_level(policy.default_detail_level),
    )


def policy_from_sources(
    char_budget: int | None = None,
    default_detail_level: str | None = None,
) -> ResponsePolicy:
    """Build a policy from explicit values, falling back to environment, then defaults.

    Precedence: explicit argument > ``FALCON_MCP_*`` environment variable > default.
    """
    if char_budget is None:
        raw_budget = os.environ.get("FALCON_MCP_RESPONSE_CHAR_BUDGET")
        char_budget = int(raw_budget) if raw_budget else DEFAULT_CHAR_BUDGET
    if default_detail_level is None:
        default_detail_level = os.environ.get(
            "FALCON_MCP_DEFAULT_DETAIL_LEVEL", DEFAULT_DETAIL_LEVEL
        )
    return ResponsePolicy(
        char_budget=_coerce_char_budget(char_budget),
        default_detail_level=_coerce_detail_level(default_detail_level),
    )


def serialize_mcp_text(value: Any) -> str:
    """Serialize a tool result the way FastMCP builds unstructured TextContent."""
    if isinstance(value, str):
        return value
    return pydantic_core.to_json(value, fallback=str, indent=2).decode()


def mcp_text_size(value: Any) -> int:
    """Unicode character count of the MCP text payload."""
    return len(serialize_mcp_text(value))


def extract_record_ids(record: Any) -> dict[str, Any]:
    """Return identifier-like fields from a record, preserving their values."""
    if not isinstance(record, dict):
        return {}
    ids: dict[str, Any] = {}
    for key, value in record.items():
        if key in IDENTITY_KEYS or (key.endswith("_id") and not key.startswith("_")):
            if value is not None and not isinstance(value, (dict, list)):
                ids[key] = value
    return ids


def project_entity(
    value: Any,
    detail_level: str,
    include_fields: list[str] | None,
    *,
    depth: int = 0,
) -> Any:
    """Deterministically project an entity according to ``detail_level`` / fields."""
    level = _coerce_detail_level(detail_level)
    if isinstance(value, list):
        return [
            project_entity(item, level, include_fields, depth=depth + 1) for item in value
        ]
    if not isinstance(value, dict):
        if isinstance(value, str):
            return _bound_string(value, level)
        return value

    if include_fields is not None and depth == 0:
        allowed_fields = set(include_fields) | set(extract_record_ids(value))
        filtered = {key: val for key, val in value.items() if key in allowed_fields}
        return {
            key: project_entity(val, level, None, depth=depth + 1)
            for key, val in filtered.items()
        }

    if level == "full":
        return value

    if level == "summary":
        summary_keys: frozenset[str] = IDENTITY_KEYS | TRIAGE_KEYS
        projected: dict[str, Any] = {}
        for key, val in value.items():
            if key in summary_keys or (key.endswith("_id") and not key.startswith("_")):
                projected[key] = _summary_value(val)
        return projected

    projected = {}
    for key, val in value.items():
        if key in BULKY_KEYS:
            projected[key] = _omission_marker(val, reason="detail_level")
        else:
            projected[key] = _compact_value(val)
    return projected


def shape_tool_result(
    result: Any,
    *,
    tool_name: str,
    detail_level: str | None = None,
    include_fields: list[str] | None = None,
    char_budget: int | None = None,
) -> Any:
    """Project and pack a tool result so the MCP text payload stays within budget.

    Already-shaped results are returned unchanged so dynamic execute cannot
    transform the same payload twice.
    """
    if _is_shaped(result):
        return result

    policy = get_response_policy()
    level = _coerce_detail_level(
        detail_level if detail_level is not None else policy.default_detail_level
    )
    fields = _normalize_include_fields(include_fields)
    budget = _coerce_char_budget(
        char_budget if char_budget is not None else policy.char_budget
    )

    if isinstance(result, str):
        return _shape_string(result, tool_name=tool_name, level=level, budget=budget)

    if isinstance(result, dict) and "error" in result:
        return _shape_error(result, tool_name=tool_name, level=level, budget=budget)

    if isinstance(result, list):
        projected = [project_entity(item, level, fields) for item in result]
        return _pack_records(
            projected,
            extra={},
            original_records=result,
            tool_name=tool_name,
            level=level,
            include_fields=fields,
            budget=budget,
        )

    if isinstance(result, dict) and "results" in result:
        records = result.get("results")
        extra = {key: value for key, value in result.items() if key != "results"}
        if isinstance(records, list):
            projected = [project_entity(item, level, fields) for item in records]
            return _pack_records(
                projected,
                extra=extra,
                original_records=records,
                tool_name=tool_name,
                level=level,
                include_fields=fields,
                budget=budget,
            )
        extra["results"] = project_entity(records, level, fields)
        return _finalize_payload(extra, tool_name=tool_name, level=level, fields=fields, budget=budget)

    if isinstance(result, dict):
        projected = project_entity(result, level, fields)
        packed = dict(projected) if isinstance(projected, dict) else {"value": projected}
        return _finalize_payload(
            packed,
            tool_name=tool_name,
            level=level,
            fields=fields,
            budget=budget,
        )

    return result


def with_response_controls(method: Callable[..., Any], tool_name: str) -> Callable[..., Any]:
    """Wrap a tool handler to add ``detail_level`` / ``include_fields`` and shape output.

    The wrapper does **not** set ``__wrapped__``, so FastMCP's ``inspect.signature``
    sees the injected parameters instead of following through to the original.
    """
    original_signature = inspect.signature(method)
    extra_parameters: list[inspect.Parameter] = []
    if "detail_level" not in original_signature.parameters:
        extra_parameters.append(
            inspect.Parameter(
                "detail_level",
                inspect.Parameter.KEYWORD_ONLY,
                default=Field(
                    default=get_response_policy().default_detail_level,
                    description=DETAIL_LEVEL_DESCRIPTION,
                ),
                annotation=DetailLevel,
            )
        )
    if "include_fields" not in original_signature.parameters:
        extra_parameters.append(
            inspect.Parameter(
                "include_fields",
                inspect.Parameter.KEYWORD_ONLY,
                default=Field(
                    default=None,
                    description=INCLUDE_FIELDS_DESCRIPTION,
                ),
                annotation=list[str] | None,
            )
        )

    parameters = list(original_signature.parameters.values())
    var_keyword: list[inspect.Parameter] = []
    if parameters and parameters[-1].kind == inspect.Parameter.VAR_KEYWORD:
        var_keyword = [parameters.pop()]
    new_signature = original_signature.replace(parameters=parameters + extra_parameters + var_keyword)

    def _pop_controls(kwargs: dict[str, Any]) -> tuple[str, list[str] | None]:
        policy = get_response_policy()
        detail_level = unwrap_field_default(
            kwargs.pop("detail_level", policy.default_detail_level)
        )
        include_fields = unwrap_field_default(kwargs.pop("include_fields", None))
        if not isinstance(detail_level, str):
            detail_level = policy.default_detail_level
        if include_fields is not None and not isinstance(include_fields, list):
            include_fields = None
        return detail_level, include_fields

    if inspect.iscoroutinefunction(method):

        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            detail_level, include_fields = _pop_controls(kwargs)
            result = await method(*args, **kwargs)
            return shape_tool_result(
                result,
                tool_name=tool_name,
                detail_level=detail_level,
                include_fields=include_fields,
            )

        wrapper: Callable[..., Any] = async_wrapper
    else:

        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            detail_level, include_fields = _pop_controls(kwargs)
            result = method(*args, **kwargs)
            return shape_tool_result(
                result,
                tool_name=tool_name,
                detail_level=detail_level,
                include_fields=include_fields,
            )

        wrapper = sync_wrapper

    wrapper.__name__ = getattr(method, "__name__", "tool")
    wrapper.__doc__ = getattr(method, "__doc__", None)
    wrapper.__module__ = getattr(method, "__module__", wrapper.__module__)
    wrapper.__qualname__ = getattr(method, "__qualname__", wrapper.__name__)
    annotations = dict(getattr(method, "__annotations__", {}))
    annotations["detail_level"] = DetailLevel
    annotations["include_fields"] = list[str] | None
    wrapper.__annotations__ = annotations
    wrapper.__signature__ = new_signature  # type: ignore[attr-defined]
    return wrapper


def details_tool_for(tool_name: str) -> str:
    """Best-effort get-by-id tool for retrieving omitted records."""
    if tool_name == "falcon_search_ngsiem":
        return "falcon_search_ngsiem"
    if "get_" in tool_name:
        return tool_name
    if tool_name.startswith("falcon_search_"):
        stem = tool_name[len("falcon_search_") :]
        if stem.endswith("ies"):
            singular = stem[:-3] + "y"
        elif stem.endswith("ses"):
            singular = stem[:-2]
        elif stem.endswith("s"):
            singular = stem[:-1]
        else:
            singular = stem
        return f"falcon_get_{singular}_details"
    return tool_name


def _coerce_detail_level(value: Any) -> str:
    text = unwrap_field_default(value)
    if text in DETAIL_LEVELS:
        return str(text)
    return DEFAULT_DETAIL_LEVEL


def _coerce_char_budget(value: Any) -> int:
    try:
        budget = int(value)
    except (TypeError, ValueError):
        return DEFAULT_CHAR_BUDGET
    if budget < ABSOLUTE_MIN_CHAR_BUDGET:
        return ABSOLUTE_MIN_CHAR_BUDGET
    if budget > MAX_CHAR_BUDGET:
        return MAX_CHAR_BUDGET
    return budget


def _normalize_include_fields(value: Any) -> list[str] | None:
    value = unwrap_field_default(value)
    if not isinstance(value, list):
        return None
    fields = [item for item in value if isinstance(item, str) and item]
    return fields or None


def _is_shaped(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    meta = value.get("response")
    if not isinstance(meta, dict):
        return False
    budget = meta.get("budget")
    return isinstance(budget, dict) and "used" in budget and "limit" in budget


def _is_marker(value: Any) -> bool:
    return isinstance(value, dict) and value.get("_omitted") is True


def _compact_json_size(value: Any) -> int:
    try:
        return len(pydantic_core.to_json(value, fallback=str))
    except Exception:
        return len(str(value))


def _omission_marker(value: Any, *, reason: str) -> dict[str, Any]:
    if _is_marker(value):
        existing = dict(value)
        existing["reason"] = reason
        return existing
    marker: dict[str, Any] = {"_omitted": True, "reason": reason}
    if isinstance(value, str):
        marker["kind"] = "string"
        marker["approx_chars"] = len(value)
        marker["preview"] = value[:_PREVIEW_CHARS]
    elif isinstance(value, list):
        marker["kind"] = "array"
        marker["length"] = len(value)
        marker["approx_chars"] = _compact_json_size(value)
    elif isinstance(value, dict):
        marker["kind"] = "object"
        marker["keys"] = list(value.keys())[:20]
        marker["approx_chars"] = _compact_json_size(value)
    else:
        marker["kind"] = type(value).__name__
        marker["approx_chars"] = _compact_json_size(value)
    return marker


def _bound_string(value: str, level: str) -> Any:
    limit = {
        "summary": _MAX_STRING_SUMMARY,
        "compact": _MAX_STRING_COMPACT,
        "full": None,
    }[level]
    if limit is not None and len(value) > limit:
        return _omission_marker(value, reason="detail_level")
    return value


def _summary_value(value: Any) -> Any:
    if isinstance(value, str):
        return _bound_string(value, "summary")
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        if _compact_json_size(value) > _NESTED_LIMIT_SUMMARY:
            return _omission_marker(value, reason="detail_level")
        return {
            key: _summary_value(val)
            for key, val in value.items()
            if key in IDENTITY_KEYS or key in TRIAGE_KEYS or key.endswith("_id")
        }
    if isinstance(value, list):
        if _compact_json_size(value) > _NESTED_LIMIT_SUMMARY:
            return _omission_marker(value, reason="detail_level")
        return [_summary_value(item) for item in value[:5]]
    return value


def _compact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _bound_string(value, "compact")
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        if _compact_json_size(value) > _NESTED_LIMIT_COMPACT:
            return _omission_marker(value, reason="detail_level")
        return {key: _compact_value(val) for key, val in value.items()}
    if isinstance(value, list):
        if _compact_json_size(value) > _NESTED_LIMIT_COMPACT:
            return _omission_marker(value, reason="detail_level")
        return [_compact_value(item) for item in value]
    return value


def _guide_resource(tool_name: str, key: str) -> str:
    if key == "cql_guide":
        return "falcon://ngsiem/search/cql-guide"
    if tool_name.startswith("falcon_search_"):
        module = tool_name[len("falcon_search_") :]
        return f"falcon://{module}/search/fql-guide"
    if tool_name.startswith("falcon_"):
        rest = tool_name[len("falcon_") :]
        module = rest.split("_", 1)[0]
        return f"falcon://{module}/search/fql-guide"
    return "falcon://guides"


def _omit_guides(payload: dict[str, Any], tool_name: str) -> dict[str, Any]:
    updated = dict(payload)
    for key in GUIDE_KEYS:
        value = updated.get(key)
        if isinstance(value, str) and value:
            updated[key] = {
                "_omitted": True,
                "reason": "response_budget",
                "kind": "guide",
                "resource": _guide_resource(tool_name, key),
                "hint": f"Read {_guide_resource(tool_name, key)} for the full guide.",
            }
    return updated


def _trim_error_details(payload: dict[str, Any]) -> dict[str, Any]:
    details = payload.get("details")
    if details is None:
        return payload
    updated = dict(payload)
    marker = _omission_marker(details, reason="response_budget")
    if isinstance(details, dict) and "status_code" in details:
        marker["status_code"] = details["status_code"]
    updated["details"] = marker
    return updated


def _record_ids_of(record: Any) -> dict[str, Any]:
    if isinstance(record, dict):
        if _is_marker(record):
            return {key: val for key, val in record.items() if key in IDENTITY_KEYS}
        return extract_record_ids(record)
    return {}


def _omitted_id_list(records: list[Any]) -> list[Any]:
    ids: list[Any] = []
    for record in records:
        extracted = _record_ids_of(record)
        record_id = (
            extracted.get("composite_id")
            or extracted.get("device_id")
            or extracted.get("id")
            or extracted.get("uuid")
            or extracted.get("job_id")
            or next(iter(extracted.values()), None)
        )
        if record_id is not None:
            ids.append(record_id)
    return ids[:_MAX_OMITTED_IDS]


def _stub_record(record: Any) -> dict[str, Any]:
    stub = dict(_record_ids_of(record))
    stub["_omitted"] = True
    stub["reason"] = "record_exceeds_budget"
    stub["hint"] = (
        "This record exceeded the response budget even after field projection. "
        "Retrieve it individually with include_fields, detail_level=summary, or a "
        "higher FALCON_MCP_RESPONSE_CHAR_BUDGET."
    )
    return stub


def _largest_nested_key(record: dict[str, Any]) -> str | None:
    best_key: str | None = None
    best_size = -1
    protected = set(extract_record_ids(record))
    for key, value in record.items():
        if key in protected or key.startswith("_") or _is_marker(value):
            continue
        if not isinstance(value, (dict, list, str)):
            continue
        size = len(value) if isinstance(value, str) else _compact_json_size(value)
        if size > best_size:
            best_size = size
            best_key = key
    return best_key


def _shrink_record(record: Any) -> Any:
    if not isinstance(record, dict):
        return _stub_record({"id": str(record)})
    current = dict(record)
    for _ in range(24):
        victim = _largest_nested_key(current)
        if victim is None:
            break
        current[victim] = _omission_marker(current[victim], reason="response_budget")
    return current


def _pack_records(
    records: list[Any],
    *,
    extra: dict[str, Any],
    original_records: list[Any],
    tool_name: str,
    level: str,
    include_fields: list[str] | None,
    budget: int,
) -> dict[str, Any]:
    target = max(ABSOLUTE_MIN_CHAR_BUDGET, budget - _BUDGET_SLACK)
    included: list[Any] = []
    omitted: list[Any] = []

    def assemble(inc: list[Any], om: list[Any]) -> dict[str, Any]:
        return _build_envelope(
            inc,
            om,
            extra=extra,
            tool_name=tool_name,
            level=level,
            include_fields=include_fields,
            budget=budget,
        )

    for index, record in enumerate(records):
        trial = assemble(included + [record], original_records[index + 1 :])
        if mcp_text_size(trial) <= target:
            included.append(record)
            continue
        shrunk = _shrink_record(record)
        trial_shrunk = assemble(included + [shrunk], original_records[index + 1 :])
        if mcp_text_size(trial_shrunk) <= target:
            included.append(shrunk)
            omitted = original_records[index + 1 :]
            break
        stub = _stub_record(original_records[index] if index < len(original_records) else record)
        trial_stub = assemble(included + [stub], original_records[index + 1 :])
        if mcp_text_size(trial_stub) <= target:
            included.append(stub)
            omitted = original_records[index + 1 :]
            break
        omitted = original_records[index:]
        break
    else:
        omitted = []

    payload = assemble(included, omitted)
    if mcp_text_size(payload) > budget and included:
        omitted = original_records[len(included) - 1 :] if original_records else omitted
        included = included[:-1]
        payload = assemble(included, omitted)
        logger.debug(
            "Dropped the last included record for %s to stay within the character budget",
            tool_name,
        )
    if omitted:
        logger.debug(
            "Omitted %d record(s) from %s to stay within the character budget",
            len(omitted),
            tool_name,
        )
    return payload


def _build_envelope(
    included: list[Any],
    omitted: list[Any],
    *,
    extra: dict[str, Any],
    tool_name: str,
    level: str,
    include_fields: list[str] | None,
    budget: int,
) -> dict[str, Any]:
    body = dict(extra)
    body["results"] = included
    pagination = body.get("pagination")
    upstream_next: Any = None
    page_complete = not omitted
    if isinstance(pagination, dict):
        pagination = dict(pagination)
        upstream_next = pagination.get("next")
        if not page_complete:
            pagination["next"] = None
        body["pagination"] = pagination

    omitted_ids = _omitted_id_list(omitted)
    hints = _hints(
        tool_name=tool_name,
        omitted_count=len(omitted),
        page_complete=page_complete,
        upstream_next=upstream_next if not page_complete else None,
        pagination=body.get("pagination") if isinstance(body.get("pagination"), dict) else None,
    )
    body["response"] = {
        "detail_level": level,
        "include_fields": include_fields,
        "field_projection": {
            "applied": level != "full" or include_fields is not None,
            "reason": (
                "include_fields"
                if include_fields is not None
                else ("detail_level" if level != "full" else None)
            ),
        },
        "page_complete": page_complete,
        "omitted_records": {
            "count": len(omitted),
            "ids": omitted_ids,
            "ids_truncated": len(omitted) > len(omitted_ids),
            "reason": "response_budget" if omitted else None,
        },
        "hints": hints,
        "budget": {
            "unit": "unicode_characters",
            "limit": budget,
            "used": 0,
            "utf8_bytes": 0,
        },
    }
    if not page_complete:
        body["response"]["upstream_next"] = upstream_next

    if mcp_text_size(body) > budget:
        body = _omit_guides(body, tool_name)
    if mcp_text_size(body) > budget:
        body = _trim_error_details(body)
    return _stamp_budget(body, budget)


def _finalize_payload(
    payload: dict[str, Any],
    *,
    tool_name: str,
    level: str,
    fields: list[str] | None,
    budget: int,
) -> dict[str, Any]:
    target = max(ABSOLUTE_MIN_CHAR_BUDGET, budget - _BUDGET_SLACK)
    body = dict(payload)
    current = body
    if mcp_text_size(current) > target:
        current = _omit_guides(current, tool_name)
    if mcp_text_size(current) > target:
        current = _trim_error_details(current)
    if mcp_text_size(current) > target:
        current = _shrink_record(current) if isinstance(current, dict) else current
        if not isinstance(current, dict):
            current = {"value": current}

    omitted_count = 0
    hints: list[str] = []
    if mcp_text_size(current) > target:
        # Last resort: identity stub of the whole object.
        stub = _stub_record(payload)
        current = stub
        omitted_count = 1
        hints = _hints(
            tool_name=tool_name,
            omitted_count=1,
            page_complete=False,
            upstream_next=None,
            pagination=None,
        )

    current["response"] = {
        "detail_level": level,
        "include_fields": fields,
        "field_projection": {
            "applied": level != "full" or fields is not None,
            "reason": (
                "include_fields" if fields is not None else ("detail_level" if level != "full" else None)
            ),
        },
        "page_complete": omitted_count == 0,
        "omitted_records": {
            "count": omitted_count,
            "ids": _omitted_id_list([payload]) if omitted_count else [],
            "ids_truncated": False,
            "reason": "response_budget" if omitted_count else None,
        },
        "hints": hints,
        "budget": {
            "unit": "unicode_characters",
            "limit": budget,
            "used": 0,
            "utf8_bytes": 0,
        },
    }
    return _stamp_budget(current, budget)


def _shape_error(
    error: dict[str, Any],
    *,
    tool_name: str,
    level: str,
    budget: int,
) -> dict[str, Any]:
    body = dict(error)
    target = max(ABSOLUTE_MIN_CHAR_BUDGET, budget - _BUDGET_SLACK)
    if mcp_text_size(body) > target:
        body = _omit_guides(body, tool_name)
    if mcp_text_size(body) > target:
        body = _trim_error_details(body)
    body["response"] = {
        "detail_level": level,
        "include_fields": None,
        "field_projection": {"applied": False, "reason": None},
        "page_complete": True,
        "omitted_records": {"count": 0, "ids": [], "ids_truncated": False, "reason": None},
        "hints": (
            ["Error details were reduced to stay within the response character budget."]
            if body.get("details") != error.get("details")
            else []
        ),
        "budget": {
            "unit": "unicode_characters",
            "limit": budget,
            "used": 0,
            "utf8_bytes": 0,
        },
    }
    return _stamp_budget(body, budget)


def _shape_string(text: str, *, tool_name: str, level: str, budget: int) -> Any:
    if len(text) <= budget - _BUDGET_SLACK:
        return text
    keep = max(0, budget - 400)
    payload = {
        "text": text[:keep],
        "response": {
            "detail_level": level,
            "include_fields": None,
            "field_projection": {"applied": False, "reason": None},
            "page_complete": False,
            "omitted_records": {
                "count": 1,
                "ids": [],
                "ids_truncated": False,
                "reason": "response_budget",
            },
            "hints": [
                f"{tool_name} returned a string larger than the response character "
                "budget; the text field is a prefix. Request a higher budget or a "
                "narrower query."
            ],
            "budget": {
                "unit": "unicode_characters",
                "limit": budget,
                "used": 0,
                "utf8_bytes": 0,
            },
            "original_characters": len(text),
        },
    }
    return _stamp_budget(payload, budget)


def _hints(
    *,
    tool_name: str,
    omitted_count: int,
    page_complete: bool,
    upstream_next: Any,
    pagination: dict[str, Any] | None,
) -> list[str]:
    if omitted_count <= 0:
        return []
    get_tool = details_tool_for(tool_name)
    hints = [
        (
            f"Omitted {omitted_count} record(s) from this upstream page to stay "
            "within the response character budget (Unicode characters of the "
            "pretty-printed JSON text FastMCP puts in the tool result; not a token "
            "guarantee)."
        )
    ]
    if get_tool == "falcon_search_ngsiem":
        hints.append(
            "NG-SIEM has no get-by-id tool: retrieve omitted events with a tighter "
            "CQL query (head/tail, include_fields, or detail_level=summary)."
        )
    else:
        hints.append(
            f"Retrieve omitted records with {get_tool} using the omitted ids."
        )
    hints.append(
        "Do not advance pagination.next or offset until omitted ids are retrieved; "
        "they still belong to this upstream page."
    )
    if upstream_next:
        hints.append(
            f"After retrieving omitted ids, continue upstream pagination with next={upstream_next!r}."
        )
    elif isinstance(pagination, dict):
        offset = pagination.get("offset")
        limit = pagination.get("limit")
        if isinstance(offset, int) and isinstance(limit, int):
            hints.append(
                "After retrieving omitted ids, the next upstream page starts at "
                f"offset={offset + limit}."
            )
    hints.append(
        "Use detail_level=summary or include_fields to fit more records; "
        "detail_level=full still respects the budget."
    )
    return hints


def _stamp_budget(payload: dict[str, Any], budget: int) -> dict[str, Any]:
    meta = payload.setdefault("response", {})
    budget_meta = meta.setdefault("budget", {})
    for _ in range(4):
        text = serialize_mcp_text(payload)
        budget_meta["unit"] = "unicode_characters"
        budget_meta["limit"] = budget
        budget_meta["used"] = len(text)
        budget_meta["utf8_bytes"] = len(text.encode("utf-8"))
        meta["budget"] = budget_meta
        payload["response"] = meta
        again = serialize_mcp_text(payload)
        if len(again) == budget_meta["used"]:
            break
        budget_meta["used"] = len(again)
        budget_meta["utf8_bytes"] = len(again.encode("utf-8"))
    if mcp_text_size(payload) > budget:
        payload = _omit_guides(payload, "falcon")
        payload = _trim_error_details(payload)
        text = serialize_mcp_text(payload)
        payload["response"]["budget"]["used"] = len(text)
        payload["response"]["budget"]["utf8_bytes"] = len(text.encode("utf-8"))
    return payload


def validate_cli_char_budget(value: str) -> int:
    """argparse type for ``--response-char-budget``."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(
            f"response character budget must be an integer, got {value!r}"
        ) from exc
    if parsed < CLI_MIN_CHAR_BUDGET:
        raise ValueError(
            f"response character budget must be >= {CLI_MIN_CHAR_BUDGET}, got {parsed}"
        )
    if parsed > MAX_CHAR_BUDGET:
        raise ValueError(
            f"response character budget must be <= {MAX_CHAR_BUDGET}, got {parsed}"
        )
    return parsed


def validate_cli_detail_level(value: str) -> str:
    """argparse type for ``--default-detail-level``."""
    if value not in DETAIL_LEVELS:
        raise ValueError(
            f"default detail level must be one of {', '.join(DETAIL_LEVELS)}, got {value!r}"
        )
    return value


