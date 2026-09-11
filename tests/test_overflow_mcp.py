"""MCP-path tests for the overflow boundary."""

import json
from typing import Any
from unittest.mock import MagicMock, patch

from mcp.shared.memory import create_connected_server_and_client_session

from falcon_mcp.server import FalconMCPServer


def _text(result: Any) -> Any:
    blocks = [block.text for block in result.content if getattr(block, "text", None)]
    if len(blocks) == 1:
        try:
            return json.loads(blocks[0])
        except json.JSONDecodeError:
            return blocks[0]
    return [json.loads(block) for block in blocks]


def _fat(i: int, blob: int = 500) -> dict[str, Any]:
    return {"composite_id": f"det:{i}", "severity": 30, "blob": "z" * blob}


def _install_handlers(server: FalconMCPServer) -> None:
    async def fake_search(**_kwargs: Any) -> dict[str, Any]:
        return {
            "results": [_fat(i) for i in range(12)],
            "pagination": {"total": 12, "next": "cursor-next", "offset": 0, "limit": 12},
        }

    async def fake_details(**_kwargs: Any) -> list[dict[str, Any]]:
        return [_fat(0, 80)]

    server.server._tool_manager._tools["falcon_search_detections"].fn = fake_search
    server.server._tool_manager._tools["falcon_get_detection_details"].fn = fake_details


class TestOverflowMcpPath:
    def setup_method(self) -> None:
        self._patcher = patch("falcon_mcp.server.FalconClient")
        mock_client_cls = self._patcher.start()
        mock_client = MagicMock()
        mock_client.authenticate.return_value = True
        mock_client.is_authenticated.return_value = True
        mock_client_cls.return_value = mock_client
        self.server = FalconMCPServer(
            enabled_modules={"detections"},
            response_max_chars=2_000,
        )
        _install_handlers(self.server)

    def teardown_method(self) -> None:
        self._patcher.stop()

    async def test_search_overflow_and_continue_without_advancing_cursor(self):
        async with create_connected_server_and_client_session(
            self.server.server
        ) as session:
            first = _text(
                await session.call_tool("falcon_search_detections", {"limit": 12})
            )
            assert "overflow" in first
            assert first["pagination"]["next"] is None
            assert first["overflow"]["upstream_cursor"] is True
            assert first["overflow"]["handle"]

            continued = _text(
                await session.call_tool(
                    "falcon_continue_result",
                    {
                        "handle": first["overflow"]["handle"],
                        "offset": first["overflow"]["offset"],
                    },
                )
            )
            assert continued["results"]
            assert (
                continued["results"][0]["composite_id"]
                != first["results"][0]["composite_id"]
            )

    async def test_small_get_by_id_stays_a_bare_list(self):
        self.server.server.response_max_chars = 25_000
        async with create_connected_server_and_client_session(
            self.server.server
        ) as session:
            payload = _text(
                await session.call_tool(
                    "falcon_get_detection_details",
                    {"ids": ["det:0"]},
                )
            )
        # FastMCP emits one text block per list item, so a single record is a
        # JSON object rather than a one-element array.
        record = payload[0] if isinstance(payload, list) else payload
        assert isinstance(record, dict)
        assert "overflow" not in record
        assert record["composite_id"] == "det:0"

    async def test_continue_is_not_in_enabled_inventory(self):
        async with create_connected_server_and_client_session(
            self.server.server
        ) as session:
            inventory = _text(await session.call_tool("falcon_list_enabled_tools", {}))
        assert "falcon_continue_result" not in inventory["tools"]

    async def test_foreign_session_cannot_read_handle(self):
        async with create_connected_server_and_client_session(
            self.server.server
        ) as session:
            first = _text(
                await session.call_tool("falcon_search_detections", {"limit": 12})
            )
            handle = first["overflow"]["handle"]

        async with create_connected_server_and_client_session(
            self.server.server
        ) as other:
            denied = _text(
                await other.call_tool(
                    "falcon_continue_result",
                    {"handle": handle, "offset": 0},
                )
            )
        assert "error" in denied
