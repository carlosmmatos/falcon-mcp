"""Print synthetic SDK before/after sizes; never uses credentials or tenant data."""

from mcp.server.fastmcp.utilities.func_metadata import _convert_to_content
from mcp.types import CallToolResult

from falcon_mcp.common.responses import BoundedFastMCP, ResponseOptions, size


def main() -> None:
    fixtures = {
        "150 detections": {
            "results": [
                {"composite_id": str(i), "severity": 80, "evidence": 'é\\"😀' * 150}
                for i in range(150)
            ],
            "pagination": {"total": 700, "offset": 100, "limit": 150, "next": None},
        },
        "large record": {
            "results": [{"id": "huge", "nested": {"log": '😀\n"\\' * 15000}}],
            "job": {"processed_events": 200, "status": "done"},
        },
        "diagnostic": {"error": "diagnostic" * 10000, "details": {"status_code": 403}},
        "aggregate": [{"name": "aggregate", "buckets": [{"count": i} for i in range(10000)]}],
    }
    server = BoundedFastMCP("measure")
    print("fixture | prior bytes | full initial bytes | summary initial bytes")
    for name, data in fixtures.items():
        before = size(CallToolResult(content=list(_convert_to_content(data))))
        after = size(server.present(data, ResponseOptions(), object()))
        summary = size(server.present(data, ResponseOptions(detail_level="summary"), object()))
        print(f"{name} | {before} | {after} | {summary}")


if __name__ == "__main__":
    main()
