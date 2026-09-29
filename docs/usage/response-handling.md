<!-- meta:title Response Handling -->
<!-- meta:description Detail levels and the character budget that keep Falcon tool results inside MCP client context. -->
<!-- meta:section usage -->
<!-- meta:link-base /falcon-mcp/ -->

Falcon APIs can return more data than an MCP client can place in a model context window. Every
Falcon module tool is shaped once at the MCP boundary — the same path in normal mode and through
`falcon_execute_tool` — so clients that cannot write payloads to disk still receive a bounded,
machine-readable JSON object.

This is not MCP resource-link support and does not store results on disk. Continuation is
stateless: omitted records are identified in the response so the client can fetch them with the
matching get-by-id tool (or a tighter query).

## What the budget measures

The budget counts **Unicode characters of the pretty-printed JSON text** that FastMCP puts in
`CallToolResult.content` (`pydantic_core.to_json` with `indent=2`). That is the string most
clients inject into the model.

It is **not**:

- A token count. Tokenization is model- and client-specific; a common English/JSON heuristic is
  roughly four characters per token, but that is not a guarantee.
- UTF-8 byte length of that text (non-ASCII is larger on the wire). The `response.budget` object
  reports both `used` (characters) and `utf8_bytes`.
- The JSON-RPC frame size. Wrapping the text in a `tools/call` result adds protocol overhead.
- Remaining context in the client. Other tools, history, and system prompts consume the same
  window.

This server currently registers tools with `structured_output=False`, so results are **not**
duplicated into `structuredContent`. Enabling structured output later would roughly double the
payload for the same Python object; the budget is applied to the Python result *before* that
serialization.

Default: **25,000 characters**. Configurable; `full` does **not** disable it.

## Detail levels

Every Falcon module tool accepts:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `detail_level` | `compact` | `summary`, `compact`, or `full` |
| `include_fields` | unset | Extra field names to keep, plus identifiers |

- **`summary`** — identifiers and triage fields (status, severity, hostname, timestamps, and
  similar) when present. Unknown entity types still keep identifier-like keys.
- **`compact`** — key operational fields. Bulky nested blobs (`behaviors`, `script_content`,
  `process`, raw payloads) are replaced with an explicit omission marker
  (`_omitted: true`, `reason: detail_level`) rather than dropped silently.
- **`full`** — every field the Falcon API returned on that record. Nested values are not stripped
  for brevity. The character budget still applies: oversized pages omit trailing records; a single
  oversized record has nested fields replaced with markers or is reduced to an identifier stub.

`include_fields` further restricts the payload to identifiers plus the named fields, then the
chosen `detail_level` still bounds those values.

The issue that proposed this work used the name `raw` for the third level; this server calls it
`full`.

## Omissions are explicit

Search tools keep their existing envelope (`results`, `pagination`, optional `filter_used`). Get-by-id
tools that previously returned a bare list are wrapped as `{ "results": [...], "response": {...} }`
so omitted rows can be described without cutting JSON mid-field.

`response` always includes:

- `detail_level`, `include_fields`, `field_projection` (field-level reduction, distinct from
  omitted **records**)
- `page_complete`
- `omitted_records` (`count`, `ids`, `reason`)
- `budget` (`unit`, `limit`, `used`, `utf8_bytes`)
- `hints` when something was withheld

**Field projection** (compact/summary/`include_fields`) is not the same as **omitted records**
(budget packed a prefix of the upstream page). Upstream **pagination** (`pagination.total`,
`offset`, `limit`) stays truthful. `pagination.next` is the next **upstream** page only when
`page_complete` is true.

If this upstream page did not all fit:

- `pagination.next` is set to `null` so a client that follows `next` cannot skip withheld rows
- `response.upstream_next` holds the cursor that would have been returned
- `response.omitted_records.ids` lists withheld identifiers that still fit; `ids_truncated` is
  true when the id list itself was shortened to stay under the budget
- hints name a **registered** get-by-id tool when one exists (for example
  `falcon_get_detection_details`, `falcon_get_cases`). Search tools without a companion are not
  given an invented name; the hint says to tighten the query instead.

The budget is measured **after** the `response` envelope is attached. String results, error
objects, and omitted-id metadata are packed the same way as search rows. At very small budgets
(library minimum 256) the envelope may drop hints, id lists, and optional fields so the JSON
still serializes under `limit`.

Empty pages, errors, and NG-SIEM `job` metadata are preserved. A bare empty list (typical of
get-by-id tools) is wrapped as `{results: [], pagination: {total: 0, next: null}, hint, response}`.
Oversized `fql_guide` / `cql_guide` strings are replaced with a pointer to the **registered**
`falcon://…` guide for that tool, or with a `falcon_list_enabled_tools` hint when the tool has no
guide. Error `details` dumps are reduced the same way, keeping `error`, status, and required scopes.

## Retrieving omitted data

1. For withheld rows, call the get-by-id tool named in `response.hints` with
   `response.omitted_records.ids` (optionally `detail_level=summary` or `include_fields`).
2. After those ids are consumed, continue **upstream** pagination with `response.upstream_next`
   or the next offset (`pagination.offset + pagination.limit`).
3. For omitted **fields** on an included row, call the get-by-id tool with `detail_level=full`
   and/or `include_fields` for that id.
4. NG-SIEM has no get-by-id tool: tighten the CQL (`head`/`tail`), raise the budget, or use
   `summary` / `include_fields`.

Do not invent a new offset that skips the omitted tail of the current page.

## Configuration

Precedence: **CLI flag > environment variable > default**.

| Flag | Environment variable | Default | Notes |
| --- | --- | --- | --- |
| `--response-char-budget` | `FALCON_MCP_RESPONSE_CHAR_BUDGET` | `25000` | CLI minimum 2000, maximum 1_000_000. Library construction accepts down to 256 for tests. |
| `--default-detail-level` | `FALCON_MCP_DEFAULT_DETAIL_LEVEL` | `compact` | `summary`, `compact`, or `full`. |

```bash
falcon-mcp --response-char-budget 40000 --default-detail-level compact
```

```bash
# .env
FALCON_MCP_RESPONSE_CHAR_BUDGET=40000
FALCON_MCP_DEFAULT_DETAIL_LEVEL=compact
```

Changing the default detail level to `full` restores previous field completeness for records that
fit, but the budget still omits trailing records on oversized pages. That is a compatibility
change: clients that assumed a bare list from get-by-id tools now receive `{results, response}`,
and search envelopes gain a `response` object.

## What this server does not do

- **No result handles or server-side caches.** Stateless HTTP and multi-worker deployments would
  otherwise need shared storage, expiry, and authorization isolation for sensitive Falcon data.
- **No MCP resource links or file export** as the baseline. Those require client support the
  problem statement cannot assume.
- **No LLM summarization.** Projection is deterministic.
- **No second pass in dynamic mode.** `falcon_execute_tool` runs the already-wrapped inner tool
  and returns that object; it does not shape again.

Smaller `limit` values and FQL/CQL filters still reduce **upstream** API usage; the budget runs
after Falcon has already returned the page.
