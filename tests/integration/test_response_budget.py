"""Read-only live checks through an initialized MCP session; never print Falcon data."""

from datetime import datetime, timedelta, timezone
from functools import wraps
from hashlib import sha256
from inspect import iscoroutinefunction

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from falcon_mcp.common.responses import BoundedFastMCP, encode, size
from falcon_mcp.dynamic import DynamicMode
from falcon_mcp.modules.detections import DetectionsModule
from falcon_mcp.modules.hosts import HostsModule
from falcon_mcp.modules.ngsiem import NGSIEMModule
from falcon_mcp.modules.spotlight import SpotlightModule
from tests.common.test_responses import payload, recover


@pytest.mark.integration
@pytest.mark.parametrize("dynamic", [False, True])
@pytest.mark.parametrize(
    "module_class,tool,parameters",
    [
        (HostsModule, "falcon_search_hosts", {"limit": 10}),
        (DetectionsModule, "falcon_search_detections", {"limit": 5}),
        (SpotlightModule, "falcon_search_vulnerabilities", {"limit": 5, "filter": "status:'open'"}),
        (NGSIEMModule, "falcon_search_ngsiem", {"query_string": "* | head(3)"}),
    ],
)
async def test_live_response_budget(
    falcon_client, monkeypatch, dynamic, module_class, tool, parameters
):
    monkeypatch.setenv("FALCON_MCP_RESPONSE_MAX_BYTES", "2048")
    server = BoundedFastMCP("live-budget-validation")
    module = module_class(falcon_client)
    captured = []
    original = getattr(module, tool.removeprefix("falcon_"))
    if iscoroutinefunction(original):

        @wraps(original)
        async def observe(*args, **kwargs):
            value = await original(*args, **kwargs)
            captured.append(value)
            return value

    else:

        @wraps(original)
        def observe(*args, **kwargs):
            value = original(*args, **kwargs)
            captured.append(value)
            return value

    setattr(module, tool.removeprefix("falcon_"), observe)
    if dynamic:
        DynamicMode({"live": module}, server).register()
    else:
        module.register_tools(server)
    server.register_result_tool()
    parameters = dict(parameters)
    if module_class is NGSIEMModule:
        parameters["start"] = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    async with create_connected_server_and_client_session(server) as client:
        response = await client.call_tool(
            "falcon_execute_tool" if dynamic else tool,
            {"tool_name": tool, "parameters": parameters} if dynamic else parameters,
        )
        assert size(response) <= 2048
        data = payload(response)
        if "response_control" in data:
            handle = data["response_control"]["result_handle"]
            assert handle is not None
            data = await recover(client, handle, budget=2048)
        assert len(captured) == 1, "Snapshot retrieval must not call Falcon again"
        # Compare hashes so a failing assertion cannot print sensitive records.
        assert (
            sha256(encode(data).encode()).hexdigest()
            == sha256(encode(captured[0]).encode()).hexdigest()
        )
        # Fail on unavailable permissions/endpoints, without printing sensitive data.
        assert isinstance(data, dict), "Expected search envelope"
        assert "error" not in data, "Falcon returned an API error"
        rows = data.get("results", [])
        assert not any(
            isinstance(row, dict) and "error" in row for row in rows
        ), "Falcon returned a wrapped API error"
        assert "pagination" in data or "job" in data
        print(
            f"{tool} dynamic={dynamic}: {size(response)} bytes; {len(rows)} records; recovery verified"
        )
        if module_class is HostsModule and rows:
            details_args = {"ids": [rows[0]["device_id"]]}
            details = await client.call_tool(
                "falcon_execute_tool" if dynamic else "falcon_get_host_details",
                (
                    {"tool_name": "falcon_get_host_details", "parameters": details_args}
                    if dynamic
                    else details_args
                ),
            )
            assert size(details) <= 2048
            details_data = payload(details)
            if isinstance(details_data, dict) and "response_control" in details_data:
                details_data = await recover(
                    client, details_data["response_control"]["result_handle"], budget=2048
                )
            assert isinstance(details_data, list) and len(details_data) == 1
            assert details_data[0]["device_id"] == rows[0]["device_id"]
        next_parameters = None
        if module_class is HostsModule and rows:
            next_parameters = {**parameters, "offset": parameters["limit"]}
        elif module_class is SpotlightModule and data.get("pagination", {}).get("next"):
            next_parameters = {**parameters, "after": data["pagination"]["next"]}
        if next_parameters:
            next_response = await client.call_tool(
                "falcon_execute_tool" if dynamic else tool,
                {"tool_name": tool, "parameters": next_parameters} if dynamic else next_parameters,
            )
            assert size(next_response) <= 2048
            next_data = payload(next_response)
            if "response_control" in next_data:
                next_data = await recover(
                    client, next_data["response_control"]["result_handle"], budget=2048
                )
            assert "pagination" in next_data
            assert len(captured) == 2
            assert (
                sha256(encode(next_data).encode()).hexdigest()
                == sha256(encode(captured[1]).encode()).hexdigest()
            )
            print(f"{tool} dynamic={dynamic}: endpoint continuation validated")


@pytest.mark.integration
@pytest.mark.parametrize("dynamic", [False, True])
async def test_live_aggregate_budget(falcon_client, monkeypatch, dynamic):
    monkeypatch.setenv("FALCON_MCP_RESPONSE_MAX_BYTES", "2048")
    server = BoundedFastMCP("live-aggregate")
    module = DetectionsModule(falcon_client)
    if dynamic:
        DynamicMode({"detections": module}, server).register()
    else:
        module.register_tools(server)
    server.register_result_tool()
    async with create_connected_server_and_client_session(server) as client:
        parameters = {"field": "severity_name", "type": "terms"}
        response = await client.call_tool(
            "falcon_execute_tool" if dynamic else "falcon_aggregate_detections",
            (
                {"tool_name": "falcon_aggregate_detections", "parameters": parameters}
                if dynamic
                else parameters
            ),
        )
        assert size(response) <= 2048
        data = payload(response)
        if isinstance(data, dict) and "response_control" in data:
            data = await recover(client, data["response_control"]["result_handle"], budget=2048)
        assert isinstance(data, list), "Expected aggregate buckets"
        assert not any(isinstance(row, dict) and "error" in row for row in data)
        print(f"aggregate dynamic={dynamic}: {size(response)} bytes")
