"""How to recover leftover overflow.ids when a snapshot handle is gone.

The MCP boundary does not invent get-by-id tools. Combined search endpoints
stay the happy path; this map only describes the fallback after continue.
"""

from __future__ import annotations

from typing import Any

# Search tools that have a real get-by-id sibling for the same entity.
_GET_BY_ID: dict[str, tuple[str, str]] = {
    "falcon_search_hosts": ("falcon_get_host_details", "ids"),
    "falcon_search_detections": ("falcon_get_detection_details", "ids"),
    "falcon_search_cases": ("falcon_get_cases", "ids"),
    "falcon_search_rtr_sessions": ("falcon_get_rtr_session_details", "ids"),
    "falcon_search_zta_assessments": ("falcon_get_zta_assessments", "ids"),
    "falcon_search_cloud_groups": ("falcon_get_cloud_groups", "ids"),
    "falcon_search_guardian_agents": ("falcon_get_guardian_agent", "agent_id"),
    "falcon_search_workflow_executions": (
        "falcon_get_workflow_execution_results",
        "ids",
    ),
}

# Combined-only searches whose FQL id field is not `id`.
_SEARCH_ID_FIELD: dict[str, str] = {
    "falcon_search_correlation_rules": "rule_id",
}

# Results are not addressable by leftover entity ids.
_NARROW_ONLY = frozenset(
    {
        "falcon_search_ngsiem",
        "falcon_search_sensor_usage",
    }
)

_GET_IDS_PARAM = {
    "falcon_get_guardian_agent": "agent_id",
}


def fql_id_filter(field: str, ids: list[Any]) -> str:
    """Build a tight FQL id clause for leftover overflow.ids."""
    quoted = [f"'{item}'" for item in ids]
    if len(quoted) == 1:
        return f"{field}:{quoted[0]}"
    return f"{field}:[{','.join(quoted)}]"


def recovery_plan(tool_name: str | None, ids: list[Any]) -> dict[str, Any]:
    """Structured fallback for leftover ids when ``overflow.handle`` is unusable."""
    if tool_name in _NARROW_ONLY:
        return {"method": "narrow_query"}

    if tool_name in _GET_BY_ID:
        dest, param = _GET_BY_ID[tool_name]
        return {"method": "get_by_id", "tool": dest, "ids_param": param}

    if tool_name and tool_name.startswith("falcon_get_"):
        return {
            "method": "get_by_id",
            "tool": tool_name,
            "ids_param": _GET_IDS_PARAM.get(tool_name, "ids"),
        }

    if tool_name and (
        tool_name.startswith("falcon_search_") or tool_name.startswith("falcon_list_")
    ):
        field = _SEARCH_ID_FIELD.get(tool_name, "id")
        plan: dict[str, Any] = {
            "method": "search_ids",
            "tool": tool_name,
            "filter_field": field,
        }
        if ids:
            plan["filter"] = fql_id_filter(field, ids)
            plan["limit"] = len(ids)
        return plan

    if ids and tool_name:
        field = "id"
        return {
            "method": "search_ids",
            "tool": tool_name,
            "filter_field": field,
            "filter": fql_id_filter(field, ids),
            "limit": len(ids),
        }
    if ids:
        return {"method": "search_ids"}
    return {"method": "narrow_query"}
