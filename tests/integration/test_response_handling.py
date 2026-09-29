"""Live MCP-path tests for response detail levels and the character budget.

These go through FastMCP ``tools/call`` against the real Falcon API, which is
the path clients see. Direct module-method integration tests bypass the
shaping wrapper.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from falcon_mcp.common.response import (
    ResponsePolicy,
    configure_response_policy,
    get_response_policy,
    mcp_text_size,
)
from falcon_mcp.server import FalconMCPServer
from tests.integration.utils.base_integration_test import BaseIntegrationTest


def _payload(result: Any) -> dict[str, Any]:
    assert result.content, "tool returned no content"
    text = result.content[0].text
    parsed = json.loads(text)
    assert isinstance(parsed, dict), f"expected JSON object, got {type(parsed)}"
    return parsed


async def _call(server: FalconMCPServer, name: str, arguments: dict[str, Any]) -> Any:
    async with create_connected_server_and_client_session(server.server) as session:
        return await session.call_tool(name, arguments)


@pytest.fixture(scope="module")
def live_server(falcon_client):
    """Real MCP server covering detections and hosts. falcon_client proves auth."""
    _ = falcon_client
    previous = get_response_policy()
    server = FalconMCPServer(
        enabled_modules={"detections", "hosts"},
        response_char_budget=25_000,
        default_detail_level="compact",
    )
    try:
        yield server
    finally:
        configure_response_policy(previous)


@pytest.mark.integration
class TestResponseHandlingLive(BaseIntegrationTest):
    """Live shaping behavior on the MCP result path."""

    def test_search_detections_compact_is_bounded_json(self, live_server):
        result = asyncio.run(
            _call(
                live_server,
                "falcon_search_detections",
                {"limit": 5, "detail_level": "compact"},
            )
        )
        assert not result.isError
        payload = _payload(result)
        self.assert_no_error(payload, context="live compact search")
        assert "response" in payload
        assert payload["response"]["detail_level"] == "compact"
        assert payload["response"]["budget"]["limit"] == 25_000
        assert payload["response"]["budget"]["used"] == len(result.content[0].text)
        assert payload["response"]["budget"]["used"] <= 25_000
        assert result.structuredContent is None
        records = payload.get("results") or []
        if records:
            first = records[0]
            assert "composite_id" in first
            # Compact must not silently keep bulky blobs as raw strings/lists.
            behaviors = first.get("behaviors")
            if isinstance(behaviors, dict):
                assert behaviors.get("_omitted") is True

    def test_summary_keeps_ids_and_drops_blobs_vs_full(self, live_server):
        compact = asyncio.run(
            _call(
                live_server,
                "falcon_search_detections",
                {"limit": 3, "detail_level": "compact"},
            )
        )
        summary = asyncio.run(
            _call(
                live_server,
                "falcon_search_detections",
                {"limit": 3, "detail_level": "summary"},
            )
        )
        full = asyncio.run(
            _call(
                live_server,
                "falcon_search_detections",
                {"limit": 3, "detail_level": "full"},
            )
        )
        for label, result in (("compact", compact), ("summary", summary), ("full", full)):
            assert not result.isError, label
            payload = _payload(result)
            self.assert_no_error(payload, context=label)
            assert len(result.content[0].text) <= 25_000, label

        summary_payload = _payload(summary)
        full_payload = _payload(full)
        records_s = summary_payload.get("results") or []
        records_f = full_payload.get("results") or []
        if not records_s or not records_f:
            pytest.skip("tenant returned no detections to compare field sets")
        summary_keys = set(records_s[0])
        full_keys = set(records_f[0])
        assert "composite_id" in summary_keys
        assert len(summary_keys) <= len(full_keys)
        assert "behaviors" not in summary_keys
        assert "script_content" not in summary_keys

    def test_small_budget_omits_records_without_advancing_cursor(self, live_server):
        previous = get_response_policy()
        configure_response_policy(
            ResponsePolicy(char_budget=4_000, default_detail_level="compact")
        )
        try:
            result = asyncio.run(
                _call(
                    live_server,
                    "falcon_search_detections",
                    {"limit": 10, "detail_level": "full"},
                )
            )
        finally:
            configure_response_policy(previous)

        assert not result.isError
        text = result.content[0].text
        assert len(text) <= 4_000
        payload = json.loads(text)
        self.assert_no_error(payload, context="live small-budget search")
        meta = payload["response"]
        if meta["omitted_records"]["count"] == 0:
            pytest.skip("page fit inside 4000 characters; nothing to omit")
        assert meta["page_complete"] is False
        assert payload["pagination"]["next"] is None
        assert meta["omitted_records"]["ids"]
        hint = " ".join(meta.get("hints") or [])
        assert "Do not advance" in hint
        assert "falcon_get_detection_details" in hint

    def test_get_details_recovers_omitted_id(self, live_server):
        previous = get_response_policy()
        configure_response_policy(
            ResponsePolicy(char_budget=4_000, default_detail_level="compact")
        )
        try:
            search = asyncio.run(
                _call(
                    live_server,
                    "falcon_search_detections",
                    {"limit": 10, "detail_level": "full"},
                )
            )
        finally:
            configure_response_policy(previous)

        payload = _payload(search)
        self.assert_no_error(payload, context="search before recover")
        omitted_ids = payload["response"]["omitted_records"]["ids"]
        if not omitted_ids:
            pytest.skip("no omitted ids to recover on this tenant page")
        target = omitted_ids[0]
        details = asyncio.run(
            _call(
                live_server,
                "falcon_get_detection_details",
                {"ids": [target], "detail_level": "summary"},
            )
        )
        assert not details.isError
        recovered = _payload(details)
        self.assert_no_error(recovered, context="get_detection_details recover")
        recovered_ids = [
            row.get("composite_id")
            for row in recovered.get("results") or []
            if isinstance(row, dict)
        ]
        assert target in recovered_ids
        assert len(details.content[0].text) <= 25_000

    def test_search_hosts_envelope_and_budget(self, live_server):
        result = asyncio.run(
            _call(
                live_server,
                "falcon_search_hosts",
                {"limit": 5, "detail_level": "summary"},
            )
        )
        assert not result.isError
        payload = _payload(result)
        self.assert_no_error(payload, context="live host search")
        assert "results" in payload
        assert "pagination" in payload
        assert "response" in payload
        assert len(result.content[0].text) <= 25_000
        if payload["results"]:
            host = payload["results"][0]
            assert "device_id" in host or "hostname" in host or "id" in host

    def test_dynamic_execute_is_shaped_once(self, falcon_client):
        _ = falcon_client
        previous = get_response_policy()
        server = FalconMCPServer(
            enabled_modules={"detections"},
            dynamic=True,
            response_char_budget=4_000,
            default_detail_level="full",
        )
        try:
            result = asyncio.run(
                _call(
                    server,
                    "falcon_execute_tool",
                    {
                        "tool_name": "falcon_search_detections",
                        "parameters": {"limit": 8, "detail_level": "full"},
                    },
                )
            )
        finally:
            configure_response_policy(previous)

        assert not result.isError
        payload = _payload(result)
        self.assert_no_error(payload, context="dynamic execute search")
        assert "response" in payload
        assert payload["response"]["budget"]["used"] == len(result.content[0].text)
        assert len(result.content[0].text) <= 4_000
        # Inner tool already shaped; execute must not wrap a second response object.
        inner = payload.get("result")
        assert not (
            isinstance(inner, dict) and isinstance(inner.get("response"), dict)
        )
        assert mcp_text_size(payload) <= 4_000
