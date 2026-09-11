<!-- meta:title Response Overflow -->
<!-- meta:description How oversized Falcon tool results stay inside a client context window. -->
<!-- meta:section usage -->
<!-- meta:link-base /falcon-mcp/ -->

Falcon APIs can return more data than an MCP client can place in a model context window.
This server does **not** invent per-tool detail levels or rewrite handlers. Every tool
result — including `falcon_execute_tool` — passes one boundary after the handler returns.

- If the unstructured text FastMCP would emit fits the budget, the result is unchanged.
- If a list or search page is too large, the response keeps a prefix of **complete
  records** and an `overflow` object. `pagination.next` is set to `null` so a client
  cannot skip unread rows on this Falcon page.
- If a single value still cannot fit, `overflow.unit` is `characters` and
  `falcon_continue_result` returns JSON text slices.

The budget counts **Unicode characters of result text**, default **25,000**. It is not
a token count and does not include the JSON-RPC frame.

## Reading the rest of a page

```json
{
  "results": ["…prefix…"],
  "pagination": {"total": 80, "next": null},
  "overflow": {
    "remaining": 62,
    "offset": 18,
    "ids": ["…"],
    "handle": "…",
    "unit": "records",
    "upstream_cursor": true,
    "hint": "…"
  }
}
```

1. Call `falcon_continue_result` with `overflow.handle` and `overflow.offset`.
2. Repeat until `overflow.remaining` is `0` (or `handle` is null).
3. Only then follow the original tool's next-page parameter. Cursor tokens stay
   in the saved page (`overflow.upstream_cursor`) and are restored on
   `pagination.next` once the saved page is finished.

`falcon_continue_result` does not call Falcon. Handles are bound to the MCP session,
expire after five minutes by default, and are not issued on
`FALCON_MCP_STATELESS_HTTP=true`. When there is no handle, use `overflow.ids` with a
get-by-id tool or narrow the query. Do not replay mutations to recover data.

## Configuration

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--response-max-chars` | `FALCON_MCP_RESPONSE_MAX_CHARS` | `25000` |
| — | `FALCON_MCP_OVERFLOW_TTL_SECONDS` | `300` |
| — | `FALCON_MCP_OVERFLOW_STORE_BYTES` | `67108864` |

```bash
falcon-mcp --response-max-chars 40000
```
