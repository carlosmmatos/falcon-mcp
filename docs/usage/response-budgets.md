<!-- meta:title Response Budgets -->
<!-- meta:description Bounded tool responses, detail selection, and safe result retrieval. -->
<!-- meta:section usage -->
<!-- meta:link-base /falcon-mcp/ -->

## Response contract

All MCP tool calls, including dynamic execution and diagnostic tools, pass through
one response boundary. The default budget is **25,000 UTF-8 bytes of the serialized
MCP `CallToolResult`**. Specifically, the measurement is
`len(result.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))`.
It includes JSON escaping, text block wrappers, warnings, metadata, `isError`, and
any structured content a handler supplies. The JSON-RPC request ID/envelope,
HTTP/SSE framing, tool definitions, resources, and client-added text are outside
this budget. This is neither a character count nor a token count. Unicode and
escaping make these measures different; token estimates depend on the tokenizer.
No fixed budget guarantees that a client's remaining context can accommodate it.

Results use a single JSON text block, without duplicating the data in
`structuredContent`. Small results retain their JSON value. Oversized results
return `response_control` and available investigation `metadata`, with an opaque
`result_handle` for the original result. No partial upstream page is returned.
`result_withheld` identifies withholding of the complete result. `records_withheld`
is a boolean for recognized row lists and null for other shapes; `withheld_record_count`
counts rows in this page when the result has a recognized list shape. It is not
the total number of upstream matches. `metadata.pagination` is informational.
Its next cursor is replaced with null and `upstream_cursor_withheld=true` when
a cursor exists; this means deferred, not exhausted. The original cursor is
only in the saved result:
**finish the saved page before requesting the next upstream page**.

Metadata that cannot fit remains in the saved result. `error_present` identifies
error dictionaries even when the diagnostic itself is too large to include.
Existing Falcon error dictionaries and HTTP status details remain intact in the
snapshot. Tool execution/validation exceptions use MCP `isError=true`.

## Choosing details

Pass `response_options` alongside a normal tool's parameters:

```json
{
  "name": "falcon_search_hosts",
  "arguments": {
    "limit": 10,
    "response_options": {"detail_level": "summary", "max_bytes": 8000}
  }
}
```

In dynamic mode, these options belong **outside** `parameters`:

```json
{
  "name": "falcon_execute_tool",
  "arguments": {
    "tool_name": "falcon_search_hosts",
    "parameters": {"limit": 10},
    "response_options": {"fields": ["hostname", "platform_name", "last_seen"]}
  }
}
```

`full` is the default: it preserves every field of the module's result, subject
to the budget. It does not mean the untouched Falcon HTTP response; existing
module normalization still applies. Full fidelity is available through the
snapshot when the result cannot fit. `full` never disables the budget.

`summary` and `compact` are deterministic projections for recognized hosts
(`device_id` plus `hostname`) and detections (`composite_id` or `detection_id`).
Summary retains identifiers and available `hostname`, `severity`, `status`,
`name`, and `platform_name`. Compact additionally retains timestamps,
first/last-seen fields, tactic/technique fields, behaviors, and description.
Retained nested values are not shortened; they still must fit the budget.
Other schemas, including aggregate buckets and NG-SIEM events, retain all fields
unless the caller explicitly selects `fields`. This avoids guessing what an
unfamiliar entity's important evidence is.

`fields` selects exact top-level entity keys, overrides the detail level, and
always retains available identifiers: `id`, `ids`, `aid`, `cid`, `device_id`,
`composite_id`, `detection_id`, `incident_id`. It applies to list rows, `results`
rows, or a single entity. Search envelopes, pagination, job metadata, and error
dictionaries are preserved. It is not an FQL filter or nested path expression.
Use result navigation for nested fields. Projection returns `data` plus
`response_control.projected_fields` (the number of excluded top-level keys across
rows), even if it fits; original fields remain retrievable from the snapshot.
Field omission and record withholding are separate signals.

## Reading saved results

`falcon_read_result` is always exposed in both modes, including when tool filters
are active. It cannot invoke Falcon APIs or bypass the tool policy. Start with:

```json
{"result_handle": "HANDLE", "path": ["results"], "start": 0}
```

If the selected value fits, the response is `{"value": ..., "next_start": null}`.
Otherwise it returns bounded `entries`, `total_children`, and `next_start`.
Repeat at the **same path** with that `next_start` until it is null. Each entry
has an `index` and either a full `value` or an explicit `deferred` marker.
Deferred entries are not missing: append the entry's index to the path to inspect
them. For example, `path: ["results", 0, "hostname"]` retrieves one field.
Integer path segments also select object values in insertion order, so even an
object with a huge key remains navigable. A short key is included for convenience.

For a huge string, key, scalar, or a complete serialized subtree:

```json
{
  "result_handle": "HANDLE",
  "path": ["results", 0, "command_line"],
  "mode": "json_text",
  "start": 0
}
```

The response contains `text`, `total_characters`, and `next_start`. Here `start`
counts Unicode code points in the selected value's serialized JSON. Each outer
response is valid JSON; its `text` is explicitly a segment, not an independently
parseable document. Concatenating segments recovers the exact selected JSON
value. Models may inspect one segment at a time; no file access or external
payload processor is needed. Retrieval does not re-run the original API call.

Server navigation offsets are independent of upstream pagination. The original
`pagination.total`, `offset`, `limit`, and `next` remain unchanged in the saved
page. After inspecting all required records, use the endpoint's documented
parameter: for example, hosts accept `offset`, whereas Spotlight uses `after`
with `pagination.next`. Shield and cloud endpoints have their own cursor
parameters; inspect their tool descriptions. Do not substitute a server
`next_start` for an upstream cursor. NG-SIEM exposes a `job` block rather than
ordinary API pagination: inspect its completion/scanned-event metadata, and
use CQL filters, `head`, or aggregation to request a different query result.

## Configuration and deployment

| Setting | Default | Allowed range |
| --------- | --------- | --------------- |
| `FALCON_MCP_RESPONSE_MAX_BYTES` | 25000 | 2048–1000000 |
| `FALCON_MCP_RESULT_TTL_SECONDS` | 300 | 1–3600 |
| `FALCON_MCP_RESULT_STORE_BYTES` | 67108864 | 1024–1073741824 |

These environment settings are read once when the MCP server is constructed.
The usual `.env` loading applies; existing process environment takes precedence.
There are no corresponding CLI flags. Per-call `max_bytes` can lower the server
budget to at least 2048, never raise it. Invalid options fail before execution.
Each retrieval call uses the server budget. Detail defaults are `full` and no
field selection; explicit fields take precedence over the selected level.

Snapshots are memory-only, bound by object identity to the originating MCP
session and to one server instance, with cryptographically random handles. A
handle alone cannot grant another session access. HTTP authentication still
applies to all retrieval requests. No files, public paths, resource URLs, or
cross-tenant cache are created. Falcon credentials/member CID remain fixed per
server as before. Independent sessions using the same API key cannot read one
another's snapshots.

The store admits at most 128 live snapshots and the configured sum of serialized
UTF-8 payload bytes. It does not evict unexpired results to admit new ones. Locks
protect concurrent admission/read/removal. Daemon timers actively delete entries
at expiry even when no new requests arrive; reads also check expiry. Expiry is
absolute, not extended on access. Process exit clears all snapshots. The byte
limit is a retained serialized-data limit, **not a process RSS limit**: Python
strings, parsed retrieval values, and upstream response processing use additional
memory. This change does not stream Falcon HTTP downloads or bound their memory.

Use stdio or stateful HTTP, with session affinity to the same worker. No shared
database is introduced. Worker restarts, session termination/reconnection, or
expiry invalidate retrieval. Multi-worker deployments must route an MCP session
to its owning worker; a different worker returns an unavailable error, never
another session's data. `FALCON_MCP_STATELESS_HTTP=true` explicitly declines to
issue snapshot handles, since the next request has a different session. To use
lossless oversized-result navigation, migrate to stateful HTTP or stdio.

If storage is full, a result exceeds total storage capacity, or a persistent
session is unavailable, the bounded response explicitly reports `recovery_error`
and a null handle. It does not claim data was saved. Reduce endpoint pages,
narrow IDs/filters, aggregate queries, or increase storage before a subsequent
read. Re-fetching is not a stable snapshot. A mutation may already have completed:
**never automatically replay it**; verify its outcome using the relevant read
tool. Within these finite storage/session limits, saved results preserve all
records, fields, totals, diagnostics, and cursors without API re-fetching.

## Compatibility

Small result JSON values and upstream pagination/error semantics remain intact.
List returns now occupy one JSON text block instead of SDK-generated text blocks
per item. Parsers that relied on block count must parse the JSON value. Clients
must recognize `response_control`, and projected results' `data` wrapper. Dynamic
mode exposes four tools rather than three. Existing tool parameter schemas are
extended only at `tools/list`; the dynamic catalog's underlying API parameters
remain unchanged. Results advertise no structured output schema because the
boundary emits JSON text and can return a control envelope. Existing Falcon
registrations already used `structured_output=False`.

No endpoint default page sizes, hydration calls, sorting, FQL, or CQL semantics
change. There is no LLM summarization dependency. For design alternatives and
measurements, see [the investigation](../development/response-budget-design.md).
