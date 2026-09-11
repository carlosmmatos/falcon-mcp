"""Live MCP tests for overflow slicing against the Falcon API."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from falcon_mcp.common.overflow import mcp_size
from falcon_mcp.server import FalconMCPServer


def _payload(result: Any) -> Any:
    blocks = [block.text for block in result.content if getattr(block, "text", None)]
    if not blocks:
        return None
    if len(blocks) == 1:
        try:
            return json.loads(blocks[0])
        except json.JSONDecodeError:
            return blocks[0]
    parsed = []
    for block in blocks:
        try:
            parsed.append(json.loads(block))
        except json.JSONDecodeError:
            parsed.append(block)
    return parsed


async def _drain(session: Any, first: dict[str, Any]) -> tuple[list[Any], list[str]]:
    """Follow overflow handles. Returns packed records and any reconstructed JSON texts."""
    rows = list(first.get("results") or [])
    texts: list[str] = []
    overflow = first.get("overflow") or {}
    handle = overflow.get("handle")
    offset = overflow.get("offset", 0)
    char_offset = overflow.get("next_char_offset") or overflow.get("char_offset")
    chunk = overflow.get("text")
    if chunk:
        texts.append(chunk)
        char_offset = overflow.get("next_char_offset")
    for _ in range(64):
        if not handle:
            break
        if not overflow.get("remaining") and char_offset is None:
            break
        arguments: dict[str, Any] = {"handle": handle, "offset": offset}
        if char_offset:
            arguments["char_offset"] = char_offset
        nxt = _payload(await session.call_tool("falcon_continue_result", arguments))
        assert isinstance(nxt, dict)
        assert "error" not in nxt, nxt
        rows.extend(nxt.get("results") or [])
        overflow = nxt.get("overflow") or {}
        if overflow.get("text"):
            texts.append(overflow["text"])
        handle = overflow.get("handle")
        offset = overflow.get("offset", offset)
        char_offset = overflow.get("next_char_offset")
    return rows, texts


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_search_detections_overflow_and_continue(falcon_client):
    del falcon_client
    # A live detection is ~3k pretty-printed chars; 8k fits a prefix and still overflows.
    server = FalconMCPServer(
        enabled_modules={"detections"},
        response_max_chars=8_000,
        read_only=True,
    )
    async with create_connected_server_and_client_session(server.server) as session:
        first = _payload(
            await session.call_tool("falcon_search_detections", {"limit": 10})
        )
        assert isinstance(first, dict)
        if first.get("error"):
            pytest.skip(f"detections search failed: {first['error']}")
        if not (first.get("results") or first.get("overflow")):
            pytest.skip("tenant has no detections")

        assert mcp_size(first) <= 8_000
        if "overflow" not in first:
            pytest.skip("page already fit the 8k budget")
        assert first["pagination"]["next"] is None
        assert first["overflow"]["handle"]
        recovered, texts = await _drain(session, first)
        assert recovered or texts
        if recovered:
            assert recovered[0].get("composite_id") or recovered[0].get("id")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_search_hosts_overflow_and_continue(falcon_client):
    del falcon_client
    # A live host is ~12k pretty-printed chars; 16k keeps one row and overflows the page.
    server = FalconMCPServer(
        enabled_modules={"hosts"},
        response_max_chars=16_000,
        read_only=True,
    )
    async with create_connected_server_and_client_session(server.server) as session:
        first = _payload(await session.call_tool("falcon_search_hosts", {"limit": 5}))
        assert isinstance(first, dict)
        if first.get("error"):
            pytest.skip(f"hosts search failed: {first['error']}")
        if not (first.get("results") or first.get("overflow")):
            pytest.skip("tenant has no hosts")
        assert mcp_size(first) <= 16_000
        if "overflow" not in first:
            pytest.skip("page already fit the 16k budget")
        recovered, texts = await _drain(session, first)
        assert recovered or texts
        if recovered:
            assert recovered[0].get("device_id") or recovered[0].get("id")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_get_details_recovers_omitted_id(falcon_client):
    del falcon_client
    server = FalconMCPServer(
        enabled_modules={"detections"},
        response_max_chars=8_000,
        read_only=True,
    )
    async with create_connected_server_and_client_session(server.server) as session:
        search = _payload(
            await session.call_tool("falcon_search_detections", {"limit": 10})
        )
        assert isinstance(search, dict)
        omitted = (search.get("overflow") or {}).get("ids") or []
        included = search.get("results") or []
        target = omitted[0] if omitted else None
        if target is None and included:
            target = included[0].get("composite_id")
        if not target:
            pytest.skip("no detection id available")

        server.server.response_max_chars = 25_000
        details = _payload(
            await session.call_tool("falcon_get_detection_details", {"ids": [target]})
        )
        records = details if isinstance(details, list) else []
        if isinstance(details, dict):
            if details.get("error"):
                pytest.skip(f"get_detection_details failed: {details['error']}")
            records = details.get("results") or ([details] if details.get("composite_id") else [])
        assert records
        assert any(
            row.get("composite_id") == target or row.get("id") == target
            for row in records
            if isinstance(row, dict)
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_dynamic_execute_is_bounded(falcon_client):
    del falcon_client
    server = FalconMCPServer(
        enabled_modules={"detections"},
        response_max_chars=8_000,
        read_only=True,
        dynamic=True,
    )
    async with create_connected_server_and_client_session(server.server) as session:
        first = _payload(
            await session.call_tool(
                "falcon_execute_tool",
                {
                    "tool_name": "falcon_search_detections",
                    "parameters": {"limit": 10},
                },
            )
        )
        assert isinstance(first, dict)
        if first.get("error"):
            pytest.skip(f"dynamic execute failed: {first['error']}")
        if not (first.get("results") or first.get("overflow")):
            pytest.skip("tenant has no detections")
        assert mcp_size(first) <= 8_000
        if "overflow" in first:
            recovered, texts = await _drain(session, first)
            assert recovered or texts


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_spotlight_cursor_is_not_advanced(falcon_client):
    del falcon_client
    server = FalconMCPServer(
        enabled_modules={"spotlight"},
        response_max_chars=8_000,
        read_only=True,
    )
    async with create_connected_server_and_client_session(server.server) as session:
        first = _payload(
            await session.call_tool(
                "falcon_search_vulnerabilities",
                {"filter": "status:'open'", "limit": 10},
            )
        )
        assert isinstance(first, dict)
        if first.get("error"):
            pytest.skip(f"spotlight search failed: {first['error']}")
        if not (first.get("results") or first.get("overflow")):
            pytest.skip("tenant has no open vulnerabilities")
        assert mcp_size(first) <= 8_000
        if "overflow" not in first:
            pytest.skip("spotlight page already fit the 8k budget")
        pagination = first.get("pagination")
        if isinstance(pagination, dict):
            assert pagination.get("next") is None
        recovered, texts = await _drain(session, first)
        assert recovered or texts


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_single_record_character_slices(falcon_client):
    del falcon_client
    server = FalconMCPServer(
        enabled_modules={"detections"},
        response_max_chars=2_048,
        read_only=True,
    )
    async with create_connected_server_and_client_session(server.server) as session:
        first = _payload(
            await session.call_tool("falcon_search_detections", {"limit": 3})
        )
        assert isinstance(first, dict)
        if first.get("error"):
            pytest.skip(f"detections search failed: {first['error']}")
        overflow = first.get("overflow") or {}
        if overflow.get("unit") != "characters" or not overflow.get("text"):
            pytest.skip("page did not enter character-slice mode")
        chunks = [overflow["text"]]
        handle = overflow.get("handle")
        offset = overflow.get("offset", 0)
        char_offset = overflow.get("next_char_offset")
        while handle and char_offset is not None:
            nxt = _payload(
                await session.call_tool(
                    "falcon_continue_result",
                    {
                        "handle": handle,
                        "offset": offset,
                        "char_offset": char_offset,
                    },
                )
            )
            assert isinstance(nxt, dict)
            piece = (nxt.get("overflow") or {}).get("text")
            assert piece
            chunks.append(piece)
            overflow = nxt["overflow"]
            handle = overflow.get("handle")
            offset = overflow.get("offset", offset)
            char_offset = overflow.get("next_char_offset")
            if overflow.get("record_complete"):
                break
        parsed = json.loads("".join(chunks))
        assert parsed.get("composite_id") or parsed.get("id")
