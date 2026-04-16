---
title: Integration Testing
description: Running integration tests with real CrowdStrike API calls.
---

Integration tests make real API calls to validate that modules work correctly against the live Falcon platform. They catch issues that mocked unit tests cannot detect.

## What Integration Tests Validate

- **FalconPy operation names** — typos pass in mocks but fail against real API
- **HTTP method mismatches** — POST body vs GET query parameters
- **Two-step search patterns** — ensuring full details are returned, not just IDs
- **API response schema changes** — real API may return different structures than mocked data
- **Authentication and scope issues** — only detectable with real credentials

## Configuration

:::note
Requires valid CrowdStrike API credentials:
:::

Copy the example file for development:

```bash
cp .env.dev.example .env
```

Then configure the variables:

```bash frame="none"
# Required
FALCON_CLIENT_ID=your-client-id
FALCON_CLIENT_SECRET=your-client-secret

# Optional (defaults to US-1)
FALCON_BASE_URL=https://api.crowdstrike.com
```

## Running Integration Tests

Run all integration tests:

```bash
uv run pytest --run-integration tests/integration/
```

Run for a specific module:

```bash
uv run pytest --run-integration tests/integration/test_detections.py
```

Run a specific test:

```bash
uv run pytest --run-integration tests/integration/test_scheduled_reports.py::TestScheduledReportsIntegration::test_search_scheduled_reports_returns_details
```

With verbose output (-s is required to see print statements):

```bash
uv run pytest --run-integration -v -s tests/integration/
```

## Test Structure

All integration tests inherit from `BaseIntegrationTest`:

```python
import pytest
from falcon_mcp.modules.my_module import MyModule
from tests.integration.utils.base_integration_test import BaseIntegrationTest


@pytest.mark.integration
class TestMyModuleIntegration(BaseIntegrationTest):

    @pytest.fixture(autouse=True)
    def setup_module(self, falcon_client):
        self.module = MyModule(falcon_client)

    def test_search_returns_details(self):
        result = self.call_method(self.module.search_entities, limit=5)
        self.assert_no_error(result)
        self.assert_valid_list_response(result)
        if len(result) > 0:
            self.assert_search_returns_details(result, expected_fields=["id", "name"])
```

:::note
Use `call_method()` to properly resolve Pydantic `Field()` defaults. Calling module methods directly may fail.
:::

## Available Assertions

| Method | Description |
|--------|-------------|
| `assert_no_error(result)` | Verify result is not an API error |
| `assert_valid_list_response(result, min_length)` | Verify result is a list |
| `assert_search_returns_details(result, expected_fields)` | Verify full entity objects are returned |
| `assert_result_has_id(result, id_field)` | Verify each result has an ID field |
| `skip_with_warning(reason)` | Skip test with visible warning in CI output |

## Best Practices

- Keep `limit` parameters small (3–5) to minimize API calls
- Prefer read-only operations; avoid tests that create data unless necessary
- Use `skip_with_warning()` when test data may not exist in the environment
- Document skip conditions in docstrings

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Tests not running | Add `--run-integration` flag |
| Authentication failures | Verify `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, and `FALCON_BASE_URL` |
| Empty results | Your tenant may lack the required data; check filter parameters |
| 403 errors | API client missing required scopes — see [Credentials](/falcon-mcp/getting-started/credentials/) |
