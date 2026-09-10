"""Tests for Falcon tool response shaping (detail levels and character budget).

These tests exercise the helpers directly. MCP-path coverage lives in
tests/test_response_mcp.py.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from typing import Any
from unittest.mock import patch

import pydantic_core

from falcon_mcp.common.response import (
    DEFAULT_CHAR_BUDGET,
    ResponsePolicy,
    configure_response_policy,
    extract_record_ids,
    get_response_policy,
    mcp_text_size,
    project_entity,
    serialize_mcp_text,
    shape_tool_result,
)


def _fat_detection(i: int, blob_chars: int = 800) -> dict[str, Any]:
    """Synthetic detection-like record with bulky nested fields."""
    blob = ("X" * blob_chars) + f"-{i}"
    return {
        "composite_id": f"det-{i}",
        "severity": 90 + (i % 10),
        "severity_name": "Critical",
        "status": "new",
        "hostname": f"host-{i}.example.com",
        "created_timestamp": "2026-01-15T12:00:00Z",
        "tactic": "Execution",
        "technique": "PowerShell",
        "device_id": f"aid-{i}",
        "behaviors": [
            {
                "filename": "powershell.exe",
                "cmdline": blob,
                "tactic": "Execution",
            }
        ],
        "process": {
            "command_line": blob,
            "sha256": "abc123",
        },
        "script_content": blob,
        "extra_unused": f"noise-{i}",
    }


def _search_envelope(records: list[dict[str, Any]], **pagination: Any) -> dict[str, Any]:
    pag = {
        "total": pagination.get("total", len(records)),
        "offset": pagination.get("offset", 0),
        "limit": pagination.get("limit", len(records)),
        "next": pagination.get("next"),
    }
    return {"results": records, "pagination": pag, "filter_used": "severity_name:'Critical'"}


class TestSerializeMcpText(unittest.TestCase):
    """Budget measurement must match FastMCP's unstructured text conversion."""

    def test_matches_fastmcp_pretty_json(self):
        payload = {"results": [{"id": "a", "name": "n"}], "pagination": {"total": 1}}
        expected = pydantic_core.to_json(payload, fallback=str, indent=2).decode()
        self.assertEqual(serialize_mcp_text(payload), expected)
        self.assertEqual(mcp_text_size(payload), len(expected))

    def test_unicode_counts_characters_not_utf8_bytes(self):
        payload = {"id": "det-1", "hostname": "主机-🔥"}
        text = serialize_mcp_text(payload)
        self.assertEqual(mcp_text_size(payload), len(text))
        self.assertGreater(len(text.encode("utf-8")), len(text))
        # JSON stays valid and does not escape the emoji out of the string value.
        parsed = json.loads(text)
        self.assertEqual(parsed["hostname"], "主机-🔥")

    def test_escaping_quotes_does_not_cut_fields(self):
        payload = {"id": "a", "name": 'he said "hello"\\world'}
        parsed = json.loads(serialize_mcp_text(payload))
        self.assertEqual(parsed["name"], 'he said "hello"\\world')


class TestProjectEntity(unittest.TestCase):
    def test_summary_keeps_identity_and_triage_drops_blobs(self):
        record = _fat_detection(1)
        projected = project_entity(record, "summary", None)
        self.assertEqual(projected["composite_id"], "det-1")
        self.assertEqual(projected["severity"], 91)
        self.assertEqual(projected["hostname"], "host-1.example.com")
        self.assertNotIn("behaviors", projected)
        self.assertNotIn("script_content", projected)
        self.assertNotIn("process", projected)

    def test_compact_replaces_bulky_nested_with_explicit_marker(self):
        record = _fat_detection(2, blob_chars=4000)
        projected = project_entity(record, "compact", None)
        self.assertEqual(projected["composite_id"], "det-2")
        self.assertIn("created_timestamp", projected)
        self.assertIn("tactic", projected)
        behaviors = projected["behaviors"]
        self.assertIsInstance(behaviors, dict)
        self.assertTrue(behaviors.get("_omitted"))
        self.assertEqual(behaviors.get("reason"), "detail_level")
        self.assertIn("approx_chars", behaviors)

    def test_full_keeps_all_fields(self):
        record = _fat_detection(3, blob_chars=50)
        projected = project_entity(record, "full", None)
        self.assertEqual(projected["script_content"], record["script_content"])
        self.assertEqual(projected["behaviors"], record["behaviors"])
        self.assertEqual(projected["extra_unused"], "noise-3")

    def test_include_fields_restricts_to_identity_plus_named_fields(self):
        record = _fat_detection(4, blob_chars=50)
        projected = project_entity(record, "full", ["status", "tactic"])
        self.assertEqual(projected["composite_id"], "det-4")
        self.assertEqual(projected["status"], "new")
        self.assertEqual(projected["tactic"], "Execution")
        self.assertNotIn("script_content", projected)
        self.assertNotIn("severity", projected)

    def test_unknown_schema_preserves_ids_and_bounds_nested(self):
        record = {
            "uuid": "abc-99",
            "weird_nested": {"blob": "Y" * 5000, "k": 1},
            "ok": "yes",
        }
        projected = project_entity(record, "compact", None)
        self.assertEqual(projected["uuid"], "abc-99")
        self.assertEqual(projected["ok"], "yes")
        nested = projected["weird_nested"]
        self.assertTrue(nested.get("_omitted") or isinstance(nested, dict))

    def test_extract_record_ids(self):
        ids = extract_record_ids(_fat_detection(5))
        self.assertEqual(ids["composite_id"], "det-5")
        self.assertEqual(ids["device_id"], "aid-5")
        self.assertEqual(ids["hostname"], "host-5.example.com")


class TestShapeToolResultBudget(unittest.TestCase):
    def setUp(self):
        self._previous = get_response_policy()
        configure_response_policy(ResponsePolicy(char_budget=3500, default_detail_level="compact"))

    def tearDown(self):
        configure_response_policy(self._previous)

    def test_empty_results_stay_empty_and_under_budget(self):
        envelope = _search_envelope([], total=0, offset=0, limit=10, next=None)
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_detections", detail_level="compact"
        )
        self.assertEqual(shaped["results"], [])
        self.assertEqual(shaped["pagination"]["total"], 0)
        self.assertIsNone(shaped["pagination"]["next"])
        self.assertLessEqual(mcp_text_size(shaped), 3500)
        self.assertIn("response", shaped)

    def test_omits_whole_records_not_mid_json(self):
        records = [_fat_detection(i, blob_chars=200) for i in range(8)]
        envelope = _search_envelope(records, total=80, offset=0, limit=8, next="cursor-next")
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_detections", detail_level="full"
        )
        json.loads(serialize_mcp_text(shaped))  # must be valid JSON
        self.assertLessEqual(mcp_text_size(shaped), 3500)
        included = shaped["results"]
        omitted = shaped["response"]["omitted_records"]
        self.assertGreater(len(included), 0)
        self.assertGreater(omitted["count"], 0)
        self.assertEqual(len(included) + omitted["count"], 8)
        included_ids = {r["composite_id"] for r in included}
        self.assertTrue(set(omitted["ids"]).isdisjoint(included_ids))
        # Prefix of the page is kept; omitted are the tail (no silent gaps).
        self.assertEqual(
            [r["composite_id"] for r in included] + omitted["ids"],
            [f"det-{i}" for i in range(8)][: len(included) + len(omitted["ids"])],
        )

    def test_does_not_advance_cursor_when_page_is_incomplete(self):
        records = [_fat_detection(i, blob_chars=400) for i in range(5)]
        envelope = _search_envelope(
            records, total=500, offset=0, limit=5, next="after-this-page"
        )
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_detections", detail_level="full"
        )
        self.assertFalse(shaped["response"]["page_complete"])
        self.assertIsNone(shaped["pagination"]["next"])
        self.assertEqual(shaped["response"]["upstream_next"], "after-this-page")
        self.assertEqual(shaped["pagination"]["total"], 500)
        self.assertEqual(shaped["pagination"]["offset"], 0)
        hint = " ".join(shaped["response"]["hints"])
        self.assertIn("falcon_get_detection_details", hint)
        self.assertIn("Do not advance", hint)

    def test_offset_pagination_without_cursor_still_holds_the_page(self):
        records = [_fat_detection(i, blob_chars=400) for i in range(4)]
        envelope = _search_envelope(records, total=40, offset=10, limit=4, next=None)
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_hosts", detail_level="full"
        )
        self.assertFalse(shaped["response"]["page_complete"])
        self.assertEqual(shaped["pagination"]["offset"], 10)
        self.assertIsNone(shaped["pagination"]["next"])
        hint = " ".join(shaped["response"]["hints"])
        self.assertIn("offset", hint)
        self.assertIn("falcon_get_host_details", hint)

    def test_complete_page_keeps_upstream_next(self):
        records = [{"composite_id": f"det-{i}", "severity": 1} for i in range(3)]
        envelope = _search_envelope(records, total=30, offset=0, limit=3, next="cursor-2")
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_detections", detail_level="summary"
        )
        self.assertTrue(shaped["response"]["page_complete"])
        self.assertEqual(shaped["pagination"]["next"], "cursor-2")
        self.assertIsNone(shaped["response"].get("upstream_next"))
        self.assertEqual(shaped["response"]["omitted_records"]["count"], 0)

    def test_single_record_larger_than_budget_returns_bounded_stub(self):
        record = _fat_detection(0, blob_chars=20_000)
        shaped = shape_tool_result(
            [record],
            tool_name="falcon_get_detection_details",
            detail_level="full",
        )
        self.assertLessEqual(mcp_text_size(shaped), 3500)
        self.assertEqual(len(shaped["results"]), 1)
        stub = shaped["results"][0]
        self.assertEqual(stub["composite_id"], "det-0")
        self.assertTrue(stub.get("_omitted") or "script_content" not in stub or isinstance(stub.get("script_content"), dict))
        json.loads(serialize_mcp_text(shaped))

    def test_oversized_nested_field_is_explicit(self):
        record = {
            "id": "one",
            "status": "new",
            "script_content": "Z" * 8000,
        }
        shaped = shape_tool_result(
            [record],
            tool_name="falcon_get_detection_details",
            detail_level="compact",
        )
        field = shaped["results"][0]["script_content"]
        self.assertIsInstance(field, dict)
        self.assertTrue(field["_omitted"])
        self.assertIn(field["reason"], {"detail_level", "response_budget", "oversized_field"})

    def test_full_does_not_disable_budget(self):
        records = [_fat_detection(i, blob_chars=1500) for i in range(6)]
        envelope = _search_envelope(records, total=6, offset=0, limit=6, next=None)
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_detections", detail_level="full"
        )
        self.assertEqual(shaped["response"]["detail_level"], "full")
        self.assertLessEqual(mcp_text_size(shaped), 3500)
        self.assertGreater(shaped["response"]["omitted_records"]["count"], 0)

    def test_error_details_are_trimmed_not_silently_dropped(self):
        error = {
            "error": "API request failed",
            "details": {"status_code": 500, "body": {"blob": "E" * 8000}},
            "required_scopes": ["Alerts:read"],
        }
        shaped = shape_tool_result(
            error, tool_name="falcon_search_detections", detail_level="full"
        )
        self.assertEqual(shaped["error"], "API request failed")
        self.assertEqual(shaped["required_scopes"], ["Alerts:read"])
        self.assertLessEqual(mcp_text_size(shaped), 3500)
        details = shaped["details"]
        if isinstance(details, dict) and details.get("_omitted"):
            self.assertEqual(details["reason"], "response_budget")
        else:
            self.assertEqual(details.get("status_code"), 500)

    def test_diagnostic_guide_is_replaced_with_pointer(self):
        envelope = {
            "results": [{"error": "bad filter"}],
            "filter_used": "nope",
            "fql_guide": "G" * 5000,
            "hint": "Filter error occurred.",
        }
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_detections", detail_level="compact"
        )
        self.assertLessEqual(mcp_text_size(shaped), 3500)
        guide = shaped["fql_guide"]
        self.assertNotEqual(guide, "G" * 5000)
        self.assertTrue(
            isinstance(guide, dict) and guide.get("_omitted"),
            msg=guide,
        )
        self.assertIn("falcon://", str(guide))

    def test_does_not_reshape_twice(self):
        records = [{"composite_id": "det-1", "severity": 1}]
        envelope = _search_envelope(records, total=1, offset=0, limit=1, next=None)
        first = shape_tool_result(
            envelope, tool_name="falcon_search_detections", detail_level="summary"
        )
        second = shape_tool_result(
            first, tool_name="falcon_search_detections", detail_level="full"
        )
        self.assertEqual(second, first)

    def test_bare_list_becomes_envelope_so_omissions_are_explicit(self):
        records = [_fat_detection(i, blob_chars=400) for i in range(5)]
        shaped = shape_tool_result(
            records,
            tool_name="falcon_get_detection_details",
            detail_level="full",
        )
        self.assertIsInstance(shaped, dict)
        self.assertIn("results", shaped)
        self.assertIn("response", shaped)
        if shaped["response"]["omitted_records"]["count"]:
            self.assertIn("ids", shaped["response"]["omitted_records"])

    def test_ngsiem_job_metadata_preserved_when_events_omitted(self):
        events = [{"id": f"evt-{i}", "raw": "Q" * 800} for i in range(6)]
        envelope = {
            "results": events,
            "query_used": "#event_simpleName=ProcessRollup2 | head(6)",
            "job": {
                "job_id": "job-1",
                "event_count": 6,
                "processed_events": 1000,
                "parsed_query": "#event_simpleName=ProcessRollup2 | head(6)",
            },
        }
        shaped = shape_tool_result(
            envelope, tool_name="falcon_search_ngsiem", detail_level="full"
        )
        self.assertEqual(shaped["job"]["event_count"], 6)
        self.assertEqual(shaped["job"]["processed_events"], 1000)
        self.assertEqual(shaped["query_used"], envelope["query_used"])
        self.assertLessEqual(mcp_text_size(shaped), 3500)

    def test_budget_metadata_reports_characters_and_utf8_bytes(self):
        shaped = shape_tool_result(
            _search_envelope([{"id": "a", "hostname": "主机"}]),
            tool_name="falcon_search_hosts",
            detail_level="summary",
        )
        budget = shaped["response"]["budget"]
        self.assertEqual(budget["unit"], "unicode_characters")
        self.assertEqual(budget["limit"], 3500)
        self.assertEqual(budget["used"], mcp_text_size(shaped))
        self.assertEqual(budget["utf8_bytes"], len(serialize_mcp_text(shaped).encode("utf-8")))
        self.assertNotIn("estimated_tokens", budget)

    def test_default_budget_constant_is_25000(self):
        self.assertEqual(DEFAULT_CHAR_BUDGET, 25000)


class TestSizeReductionFixture(unittest.TestCase):
    """Representative before/after sizes for the design write-up."""

    def test_compact_plus_budget_shrinks_hydrated_search_page(self):
        records = [_fat_detection(i, blob_chars=2500) for i in range(10)]
        envelope = _search_envelope(records, total=150, offset=0, limit=10, next="n2")
        before = mcp_text_size(envelope)
        configure_response_policy(
            ResponsePolicy(char_budget=DEFAULT_CHAR_BUDGET, default_detail_level="compact")
        )
        try:
            shaped = shape_tool_result(
                envelope, tool_name="falcon_search_detections", detail_level="compact"
            )
        finally:
            configure_response_policy(ResponsePolicy())
        after = mcp_text_size(shaped)
        self.assertLess(after, before)
        self.assertLessEqual(after, DEFAULT_CHAR_BUDGET)
        # Keep this as a regression signal: compact should cut the fat blobs.
        self.assertLess(after / before, 0.5, f"before={before} after={after}")


class TestResponseCli(unittest.TestCase):
    def setUp(self):
        self._saved = {
            key: os.environ.pop(key, None)
            for key in (
                "FALCON_MCP_RESPONSE_CHAR_BUDGET",
                "FALCON_MCP_DEFAULT_DETAIL_LEVEL",
            )
        }

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_parse_args_defaults(self):
        from falcon_mcp.server import parse_args

        with patch.object(sys, "argv", ["falcon-mcp"]):
            args = parse_args()
        self.assertEqual(args.response_char_budget, DEFAULT_CHAR_BUDGET)
        self.assertEqual(args.default_detail_level, "compact")

    def test_parse_args_cli_overrides_env(self):
        from falcon_mcp.server import parse_args

        os.environ["FALCON_MCP_RESPONSE_CHAR_BUDGET"] = "30000"
        os.environ["FALCON_MCP_DEFAULT_DETAIL_LEVEL"] = "summary"
        with patch.object(
            sys,
            "argv",
            [
                "falcon-mcp",
                "--response-char-budget",
                "40000",
                "--default-detail-level",
                "full",
            ],
        ):
            args = parse_args()
        self.assertEqual(args.response_char_budget, 40000)
        self.assertEqual(args.default_detail_level, "full")

    def test_main_forwards_response_flags(self):
        from falcon_mcp.server import main

        with patch.object(
            sys,
            "argv",
            [
                "falcon-mcp",
                "--response-char-budget",
                "32000",
                "--default-detail-level",
                "summary",
            ],
        ):
            with patch("falcon_mcp.server.FalconMCPServer") as mock_server:
                main()
        kwargs = mock_server.call_args.kwargs
        self.assertEqual(kwargs["response_char_budget"], 32000)
        self.assertEqual(kwargs["default_detail_level"], "summary")


if __name__ == "__main__":
    unittest.main()
