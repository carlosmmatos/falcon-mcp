"""Exercise the actual MCP client/server path, including snapshot recovery."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult, TextContent

from falcon_mcp.common.responses import (
    BoundedFastMCP,
    ResponseOptions,
    ResultStore,
    project,
    result,
    size,
)
from falcon_mcp.dynamic import DynamicMode
from falcon_mcp.modules.base import BaseModule


def payload(response):
    assert response.structuredContent is None
    return json.loads(response.content[0].text)


class FixtureModule(BaseModule):
    def __init__(self, value):
        super().__init__(Mock())
        self.value = value
        self.calls = 0

    def register_tools(self, server):
        self._add_tool(server, self.search, "fixture")

    def search(self, offset: int = 0, after: str | None = None):
        self.calls += 1
        return self.value


async def recover(client, handle, path=None, budget=25000):
    pieces = []
    start = 0
    while True:
        response = await client.call_tool(
            "falcon_read_result",
            {
                "result_handle": handle,
                "path": path or [],
                "start": start,
                "mode": "json_text",
            },
        )
        assert size(response) <= budget
        data = payload(response)
        pieces.append(data["text"])
        if data["next_start"] is None:
            break
        assert data["next_start"] > start
        start = data["next_start"]
    return json.loads("".join(pieces))


@pytest.mark.parametrize("dynamic", [False, True])
@pytest.mark.parametrize(
    "pagination",
    [
        {"total": 700, "offset": 100, "limit": 150, "next": None},
        {"total": None, "limit": 150, "next": "opaque-after-cursor"},
    ],
)
async def test_mcp_page_recovery_without_gaps(dynamic, pagination):
    original = {
        "results": [
            {"composite_id": str(i), "severity": 80, "evidence": 'é\\"😀' * 150} for i in range(150)
        ],
        "pagination": pagination,
        "filter_used": "severity:80",
    }
    server = BoundedFastMCP("test")
    module = FixtureModule(original)
    if dynamic:
        DynamicMode({"fixture": module}, server).register()
    else:
        module.register_tools(server)
    server.register_result_tool()
    async with create_connected_server_and_client_session(server) as client:
        tools = await client.list_tools()
        name = "falcon_execute_tool" if dynamic else "falcon_fixture"
        schema = next(t.inputSchema for t in tools.tools if t.name == name)
        assert "response_options" in schema["properties"]
        args = {"tool_name": "falcon_fixture", "parameters": {}} if dynamic else {}
        response = await client.call_tool(name, args)
        assert size(response) <= 25000
        control = payload(response)["response_control"]
        assert control["records_withheld"]
        if pagination["next"]:
            assert control["upstream_cursor_withheld"]
            assert payload(response)["metadata"]["pagination"]["next"] is None
        restored = await recover(client, control["result_handle"])
        assert restored == original
        assert module.calls == 1
        page = payload(
            await client.call_tool(
                "falcon_read_result",
                {
                    "result_handle": control["result_handle"],
                    "path": ["results"],
                },
            )
        )
        assert page["next_start"] is not None
        # Every index is either present or explicitly deferred, with no gaps.
        indexes = [entry["index"] for entry in page["entries"]]
        while page["next_start"] is not None:
            page = payload(
                await client.call_tool(
                    "falcon_read_result",
                    {
                        "result_handle": control["result_handle"],
                        "path": ["results"],
                        "start": page["next_start"],
                    },
                )
            )
            indexes.extend(entry["index"] for entry in page["entries"])
        assert indexes == list(range(150))


@pytest.mark.parametrize(
    "original",
    [
        {
            "results": [{"id": "huge", "nested": {"log": '😀\n"\\' * 15000}}],
            "job": {"processed_events": 200, "status": "done"},
        },
        {"error": "diagnostic" * 10000, "details": {"status_code": 403}},
        {"unknown": {"x" * 30000: "value"}},
        [{"name": "aggregate", "buckets": [{"count": i} for i in range(10000)]}],
    ],
)
async def test_unknown_nested_diagnostics_and_huge_keys(original):
    server = BoundedFastMCP("test")
    FixtureModule(original).register_tools(server)
    server.register_result_tool()
    async with create_connected_server_and_client_session(server) as client:
        response = await client.call_tool("falcon_fixture", {})
        assert size(response) <= 25000
        handle = payload(response)["response_control"]["result_handle"]
        assert await recover(client, handle) == original
        async with create_connected_server_and_client_session(server) as other:
            denied = await other.call_tool("falcon_read_result", {"result_handle": handle})
            assert denied.isError


async def test_projection_full_and_invalid_options():
    original = {
        "results": [
            {"device_id": "a", "hostname": "host", "severity": 9, "secret_field": "evidence"}
        ],
        "pagination": {"total": 1, "next": None},
    }
    server = BoundedFastMCP("test")
    module = FixtureModule(original)
    module.register_tools(server)
    server.register_result_tool()
    async with create_connected_server_and_client_session(server) as client:
        response = await client.call_tool(
            "falcon_fixture", {"response_options": {"detail_level": "summary"}}
        )
        data = payload(response)
        assert "secret_field" not in data["data"]["results"][0]
        assert data["response_control"]["projected_fields"] == 1
        assert not data["response_control"]["records_withheld"]
        assert await recover(client, data["response_control"]["result_handle"]) == original
        assert payload(await client.call_tool("falcon_fixture", {})) == original
        invalid = await client.call_tool(
            "falcon_fixture", {"response_options": {"detail_level": "raw"}}
        )
        assert invalid.isError
        assert module.calls == 2


def test_projection_unknown_and_field_selection():
    raw = [{"id": "a", "arbitrary": 5, "other": 6}]
    assert project(raw, ResponseOptions(detail_level="summary")) == (raw, 0)
    assert project(raw, ResponseOptions(fields=["arbitrary"])) == ([{"id": "a", "arbitrary": 5}], 1)


def test_storage_admission_expiry_and_isolation():
    store = ResultStore(max_bytes=20)
    owner = object()
    handle = store.put(owner, {"id": "a"})
    assert store.get(owner, handle) == {"id": "a"}
    with pytest.raises(ValueError):
        store.get(object(), handle)
    assert store.put(owner, "x" * 30) is None
    store.entries[handle].expires = 0
    with pytest.raises(ValueError):
        store.get(owner, handle)
    store.remove(handle)
    assert store.used == 0


@pytest.mark.parametrize(
    "raw",
    [
        [],
        {"results": [], "pagination": {"total": 0, "next": None}},
        {"error": "denied", "details": {"status_code": 403}},
    ],
)
def test_small_results_preserve_semantics(raw):
    server = BoundedFastMCP("test")
    assert payload(server.present(raw, ResponseOptions(), object())) == raw


def test_minimum_budget_storage_failure_and_serialization(monkeypatch):
    monkeypatch.setenv("FALCON_MCP_RESPONSE_MAX_BYTES", "2048")
    server = BoundedFastMCP("test")
    server.results.max_bytes = 1
    output = server.present({"error": '😀"\\' * 3000}, ResponseOptions(), object(), True)
    assert size(output) <= 2048
    assert output.isError
    assert payload(output)["response_control"]["recovery_error"]
    assert size(result("😀")) > len(result("😀").model_dump_json(exclude_none=True))


def test_concurrent_storage_limit_and_active_cleanup():
    store = ResultStore(max_bytes=100, ttl=1)
    owner = object()
    with ThreadPoolExecutor(max_workers=8) as pool:
        handles = list(pool.map(lambda _: store.put(owner, "x" * 18), range(30)))
    assert sum(handle is not None for handle in handles) == 5
    assert store.used == 100
    deadline = time.monotonic() + 3
    while store.used and time.monotonic() < deadline:
        time.sleep(0.02)
    assert store.used == 0
    assert not store.entries


async def test_deferred_nested_values_and_exception_are_bounded(monkeypatch):
    monkeypatch.setenv("FALCON_MCP_RESPONSE_MAX_BYTES", "2048")
    server = BoundedFastMCP("test")
    original = {"results": [{"id": "large", "log": 'é"\\😀' * 10000}]}
    FixtureModule(original).register_tools(server)
    server.register_result_tool()

    async def fail():
        raise ValueError("large diagnostic " * 5000)

    server.add_tool(fail, name="fail", structured_output=False)
    async with create_connected_server_and_client_session(server) as client:
        response = await client.call_tool("falcon_fixture", {})
        handle = payload(response)["response_control"]["result_handle"]
        page = payload(
            await client.call_tool(
                "falcon_read_result", {"result_handle": handle, "path": ["results"]}
            )
        )
        assert page["entries"][0]["deferred"]
        assert page["next_start"] is None
        assert (
            await recover(client, handle, ["results", 0, "log"], budget=2048)
            == original["results"][0]["log"]
        )
        error = await client.call_tool("fail", {})
        assert error.isError
        assert size(error) <= 2048
        assert payload(error)["response_control"]["error_present"]


@pytest.mark.parametrize("last_length", [1898, 1899])
async def test_final_retrieval_page_budgets_null_continuation(monkeypatch, last_length):
    monkeypatch.setenv("FALCON_MCP_RESPONSE_MAX_BYTES", "2048")
    server = BoundedFastMCP("test")
    original = ["a" * 3000, "b" * last_length]
    FixtureModule(original).register_tools(server)
    server.register_result_tool()
    async with create_connected_server_and_client_session(server) as client:
        response = await client.call_tool("falcon_fixture", {})
        handle = payload(response)["response_control"]["result_handle"]
        response = await client.call_tool(
            "falcon_read_result", {"result_handle": handle, "start": 1}
        )
        assert size(response) <= 2048
        page = payload(response)
        assert "response_control" not in page
        assert page["next_start"] is None
        assert page["total_children"] == 2
        assert len(page["entries"]) == 1
        entry = page["entries"][0]
        assert entry["index"] == 1
        if last_length == 1898:
            assert entry["value"] == original[1]
            assert size(response) == 2048
        else:
            assert entry["deferred"]
        assert await recover(client, handle, [1], budget=2048) == original[1]


async def test_stateless_explicitly_declines_unusable_handle():
    server = BoundedFastMCP("test", stateless_http=True)
    FixtureModule({"results": ["x" * 40000]}).register_tools(server)
    async with create_connected_server_and_client_session(server) as client:
        response = await client.call_tool("falcon_fixture", {})
        control = payload(response)["response_control"]
        assert control["result_handle"] is None
        assert "recovery_error" in control
        assert not server.results.entries


async def test_explicit_mcp_result_counts_both_copies_and_preserves_error():
    server = BoundedFastMCP("test")
    raw = CallToolResult(
        content=[TextContent(type="text", text="x" * 15000)],
        structuredContent={"value": "x" * 15000},
        isError=True,
    )

    async def duplicate():
        return raw

    server.add_tool(duplicate, name="duplicate", structured_output=False)
    server.register_result_tool()
    async with create_connected_server_and_client_session(server) as client:
        response = await client.call_tool("duplicate", {})
        assert size(raw) > 25000
        assert size(response) <= 25000
        assert response.isError
        handle = payload(response)["response_control"]["result_handle"]
        assert await recover(client, handle) == raw.model_dump(
            mode="json", by_alias=True, exclude_none=True
        )
