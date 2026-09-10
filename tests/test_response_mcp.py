"""MCP-path tests for response shaping (normal tools and falcon_execute_tool)."""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from mcp.shared.memory import create_connected_server_and_client_session

from falcon_mcp.common.response import (
    ResponsePolicy,
    configure_response_policy,
    get_response_policy,
    mcp_text_size,
    serialize_mcp_text,
)
from falcon_mcp.dynamic import DynamicMode
from falcon_mcp.modules.detections import DetectionsModule
from falcon_mcp.server import FalconMCPServer


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _fat_alert(i: int, blob_chars: int = 1200) -> dict[str, Any]:
    blob = ("B" * blob_chars) + f"-{i}"
    return {
        "composite_id": f"cid-{i}",
        "severity": 80,
        "severity_name": "High",
        "status": "new",
        "hostname": f"workstation-{i}",
        "created_timestamp": "2026-03-01T00:00:00Z",
        "tactic": "Execution",
        "technique": "PowerShell",
        "device_id": f"aid-{i}",
        "behaviors": [{"cmdline": blob}],
        "script_content": blob,
    }


class _ResponsePolicyTestCase(unittest.TestCase):
    def setUp(self):
        self._previous = get_response_policy()
        configure_response_policy(
            ResponsePolicy(char_budget=4000, default_detail_level="compact")
        )

    def tearDown(self):
        configure_response_policy(self._previous)


class TestToolSchemaExposesControls(_ResponsePolicyTestCase):
    @patch("falcon_mcp.server.FalconClient")
    def test_search_tool_declares_detail_level_and_include_fields(self, mock_client_cls):
        mock_client_cls.return_value.authenticate.return_value = True
        server = FalconMCPServer(
            enabled_modules={"detections"},
            response_char_budget=4000,
            default_detail_level="compact",
        )
        tool = server.server._tool_manager._tools["falcon_search_detections"]
        properties = tool.parameters["properties"]
        self.assertIn("detail_level", properties)
        self.assertIn("include_fields", properties)
        detail = properties["detail_level"]
        self.assertEqual(set(detail.get("enum") or []), {"summary", "compact", "full"})
        self.assertIn("compact", detail.get("description", "").lower())
        self.assertIn("full", detail.get("description", "").lower())
        self.assertNotIn("raw", detail.get("description", "").lower())


class TestNormalModeMcpPath(_ResponsePolicyTestCase, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        patcher = patch("falcon_mcp.server.FalconClient")
        self.mock_client_cls = patcher.start()
        self.addCleanup(patcher.stop)
        mock_client = MagicMock()
        mock_client.authenticate.return_value = True
        mock_client.is_authenticated.return_value = True
        self.mock_client = mock_client
        self.mock_client_cls.return_value = mock_client
        self.mcp_server = FalconMCPServer(
            enabled_modules={"detections"},
            response_char_budget=4000,
            default_detail_level="compact",
        )

    def _stub_search(self, alerts: list[dict[str, Any]], *, total: int, next_cursor: str | None) -> None:
        ids = [a["composite_id"] for a in alerts]
        query = {
            "status_code": 200,
            "body": {
                "resources": ids,
                "meta": {
                    "pagination": {
                        "offset": 0,
                        "limit": len(alerts),
                        "total": total,
                        "after": next_cursor,
                    }
                },
            },
        }
        details = {"status_code": 200, "body": {"resources": alerts}}
        self.mock_client.command.side_effect = [query, details]

    async def test_tools_call_returns_bounded_json_text(self):
        alerts = [_fat_alert(i, blob_chars=1500) for i in range(6)]
        self._stub_search(alerts, total=60, next_cursor="page-2")

        async with create_connected_server_and_client_session(
            self.mcp_server.server
        ) as session:
            result = await session.call_tool(
                "falcon_search_detections",
                {"limit": 6, "detail_level": "full"},
            )

        self.assertFalse(result.isError)
        self.assertEqual(len(result.content), 1)
        text = result.content[0].text
        self.assertLessEqual(len(text), 4000)
        payload = json.loads(text)
        self.assertLessEqual(mcp_text_size(payload), 4000)
        self.assertEqual(payload["pagination"]["total"], 60)
        self.assertFalse(payload["response"]["page_complete"])
        self.assertIsNone(payload["pagination"]["next"])
        self.assertEqual(payload["response"]["upstream_next"], "page-2")
        self.assertGreater(payload["response"]["omitted_records"]["count"], 0)
        # No structuredContent duplication with structured_output=False.
        self.assertIsNone(getattr(result, "structuredContent", None))

    async def test_summary_then_get_details_recovers_omitted_record(self):
        alerts = [_fat_alert(i, blob_chars=1800) for i in range(4)]
        self._stub_search(alerts, total=4, next_cursor=None)

        async with create_connected_server_and_client_session(
            self.mcp_server.server
        ) as session:
            search = await session.call_tool(
                "falcon_search_detections",
                {"limit": 4, "detail_level": "full"},
            )
            search_payload = json.loads(search.content[0].text)
            omitted_ids = search_payload["response"]["omitted_records"]["ids"]
            self.assertTrue(omitted_ids)
            recovered_id = omitted_ids[0]
            match = next(a for a in alerts if a["composite_id"] == recovered_id)
            self.mock_client.command.side_effect = [
                {"status_code": 200, "body": {"resources": [match]}},
            ]
            details = await session.call_tool(
                "falcon_get_detection_details",
                {"ids": [recovered_id], "detail_level": "summary"},
            )

        details_payload = json.loads(details.content[0].text)
        returned_ids = [r["composite_id"] for r in details_payload["results"]]
        self.assertIn(recovered_id, returned_ids)
        self.assertEqual(details_payload["results"][0]["composite_id"], recovered_id)

    async def test_unicode_round_trip_on_the_wire(self):
        alert = _fat_alert(0, blob_chars=20)
        alert["hostname"] = "实验室-🔥"
        self._stub_search([alert], total=1, next_cursor=None)

        async with create_connected_server_and_client_session(
            self.mcp_server.server
        ) as session:
            result = await session.call_tool(
                "falcon_search_detections",
                {"limit": 1, "detail_level": "summary"},
            )

        payload = json.loads(result.content[0].text)
        self.assertEqual(payload["results"][0]["hostname"], "实验室-🔥")
        self.assertEqual(
            len(result.content[0].text),
            len(serialize_mcp_text(payload)),
        )


class TestDynamicExecutePath(_ResponsePolicyTestCase):
    def test_execute_applies_shaping_once(self):
        mock_client = MagicMock()
        alerts = [_fat_alert(i, blob_chars=1500) for i in range(5)]
        mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": [a["composite_id"] for a in alerts],
                    "meta": {
                        "pagination": {
                            "offset": 0,
                            "limit": 5,
                            "total": 50,
                            "after": "dyn-next",
                        }
                    },
                },
            },
            {"status_code": 200, "body": {"resources": alerts}},
        ]
        dynamic = DynamicMode({"detections": DetectionsModule(mock_client)}, MagicMock())
        result = _run(
            dynamic._execute_tool(
                tool_name="falcon_search_detections",
                parameters={"limit": 5, "detail_level": "full"},
            )
        )
        self.assertIsInstance(result, dict)
        self.assertIn("response", result)
        self.assertLessEqual(mcp_text_size(result), 4000)
        self.assertFalse(result["response"]["page_complete"])
        self.assertIsNone(result["pagination"]["next"])
        # Second pass is a no-op (execute must not reshape the inner result).
        from falcon_mcp.common.response import shape_tool_result

        again = shape_tool_result(
            result, tool_name="falcon_search_detections", detail_level="full"
        )
        self.assertEqual(again, result)

    def test_execute_error_path_stays_bounded(self):
        mock_client = MagicMock()
        mock_client.command.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}], "blob": "Z" * 9000},
        }
        dynamic = DynamicMode({"detections": DetectionsModule(mock_client)}, MagicMock())
        result = _run(
            dynamic._execute_tool(
                tool_name="falcon_get_detection_details",
                parameters={"ids": ["cid-1"], "detail_level": "full"},
            )
        )
        self.assertIn("error", result)
        self.assertLessEqual(mcp_text_size(result), 4000)


if __name__ == "__main__":
    unittest.main()
