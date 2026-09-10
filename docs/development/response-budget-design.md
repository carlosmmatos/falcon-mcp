<!-- meta:title Response Budget Design -->
<!-- meta:description Investigation and tradeoffs behind bounded Falcon tool results. -->
<!-- meta:section development -->
<!-- meta:link-base /falcon-mcp/ -->

## Investigation

[Issue 230](https://github.com/CrowdStrike/falcon-mcp/issues/230) proposes three
detail levels and a 25,000-character limit, dropping whole items when necessary.
Its comments API was empty when checked on 2026-09-10. The available timeline
linked [issue 570](https://github.com/CrowdStrike/falcon-mcp/issues/570), which
describes a sandbox report exceeding 600 KB and a much smaller domain-specific
overview. Its discussion acknowledges planned sandbox work; there was no linked
implementation PR in issue 230's timeline. The large-report example demonstrates
why reducing page sizes alone cannot solve the problem. This implementation calls
the complete detail level `full`, retains it as the compatibility default, and
uses serialized bytes instead of characters.

Repository guidance (`CLAUDE.md` and `.github/CONTRIBUTING.md`) requires pagination
envelopes, order preservation after hydration, uv-based checks, and generated
documentation freshness. The installed SDK inspected was **mcp 1.29.0**; the
project allows `>=1.28.1,<2.0.0`. The actual response flow is:

1. FalconPy returns HTTP status, body resources, metadata, and errors.
2. `BaseModule` helpers normalize resources/errors and capture endpoint pagination.
3. Searches may hydrate queried IDs, reorder details, and return `results` with
   pagination. ID-based detail tools often return a list. Aggregations return
   endpoint-shaped buckets; NG-SIEM returns events plus query/job metadata.
4. Normal registration offloads synchronous handlers. Dynamic catalog registration
   uses a scratch FastMCP, and `falcon_execute_tool` calls the selected `Tool.run`
   without output conversion. Both reach the actual server's response boundary
   once, after complete module execution.
5. The new boundary emits `CallToolResult` directly. SDK low-level handling accepts
   that type without converting it again; transport serialization follows.

Projection, snapshot serialization, and navigation run in the existing AnyIO worker
pool so large local transformations do not block the event loop.

The previous Falcon registrations explicitly disabled structured output, so
their results did **not** duplicate text and structured data. SDK
`FuncMetadata.convert_result` can emit both when structured output is enabled;
lists also become multiple text blocks in the unstructured converter. The new
boundary accounts for the final result object and normally emits one JSON text
block. Raw `CallToolResult` values are measured too; oversized ones are saved in
their complete serialized model shape.

Endpoint pagination is not interchangeable. `_extract_pagination` handles nested
`meta.pagination.next`, nested `after`, and top-level cloud `meta.next`.
`_build_pagination_envelope` preserves unknown totals as null. Hosts expose
offsets; Spotlight forwards an `after` token. FQL failures include diagnostic
guides; empty 200s remain successful envelopes. NG-SIEM lacks ordinary pagination
and carries job status, scan statistics, and query metadata instead. Applying
record truncation in the API helper would miss these response shapes and guides.

## Protocol versus clients

The [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
supports text, structured content, resource links, and optional output schemas.
Structured output should also have a text representation for compatibility;
advertised output schemas must match structured results. The specification's
tool-list pagination does not provide automatic pagination of arbitrary tool
result data. It defines no universal model-context budget or automatic file
spill mechanism. These are reasons to implement bounded ordinary tool calls.

[MCP resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)
are application-controlled, and clients determine how to present/include them.
A resource link is a protocol capability, not a guarantee that a client can
retrieve or process its contents outside model context. The
[official Python SDK documentation](https://github.com/modelcontextprotocol/python-sdk#structured-output)
describes structured result conversion and direct `CallToolResult` support.
Local installed SDK code, not assumptions about a particular client's behavior,
determined the enforcement point.

## Alternatives compared

| Approach | Context and preservation | Compatibility/deployment | Complexity and latency/API cost |
| ---------- | -------------------------- | -------------------------- | --------------------------------- |
| Smaller pages | Reduces typical volume; one row can still overflow. All records accessible if paging is stable. | Ordinary clients; changing defaults changes page counts. | Low per endpoint, more API calls for exhaustive reads. |
| Upstream filters and aggregates | Often greatest reduction before hydration; aggregate answers intentionally omit entity evidence. | Ordinary clients; endpoint-specific syntax/scopes. | Low shared infrastructure, needs domain knowledge; usually fewer bytes/API calls. |
| Avoid hydration | IDs are small but lose immediate investigation detail. | Ordinary clients; changes established full-detail search behavior. | Endpoint-specific changes and extra follow-up detail calls. |
| Deterministic levels/fields | Strong reduction for known entities; original evidence must remain retrievable. | Ordinary clients; optional inputs and explicit projection wrapper. | Moderate, no model cost; mappings need maintenance. Does not reduce API work here. |
| Budget without storage | Reliable cap only if fallback can withhold fields/rows. Exact recovery by re-fetch is not guaranteed. | Stateless deployment is easy; replay can drift or duplicate mutations. | Low infrastructure; repeated reads cost latency/API calls. |
| Budget plus snapshots | Reliable per-call cap and exact recovery within TTL/capacity/session limits, including one huge record. | Ordinary tool clients; requires session affinity and in-memory state. | Moderate; local navigation calls add round trips but no Falcon calls. |
| Resource links | Small initial result; subsequent resource read can itself be huge. | Depends on client resource support and inclusion behavior. | Additional resource/auth lifecycle; does not replace bounded retrieval. |
| Optional export | Preserves bulk data and reduces initial context. | Needs client download/file handling; local paths do not imply shared storage. | Files/object storage add permissions, cleanup, and deployment work. |

The selected combination is upstream controls already available, opt-in deterministic
projection, a shared byte budget, and bounded snapshot navigation. State is justified
because cursors can advance past withheld rows, repeated reads can drift, writes
cannot safely be replayed, and large nested fields have no universal Falcon field
pagination. Storing only oversized/projected results limits retention. Resource
links, file export, broad page-size changes, and hydration rewrites are deferred.
They do not strengthen the baseline contract enough to justify their scope here.

Twenty-five thousand bytes is an operational starting point, deliberately
configurable. It is stricter than the issue's character proposal for non-ASCII
data and includes the nested escaping that payload-only limits miss. The default
`full` avoids introducing implicit domain-specific evidence loss. Summary/compact
recognize hosts/detections conservatively; unknown schemas retain fields. A
future entity profile should be supported by representative fixtures, not guessed
from a generic field list.

## Validation and representative sizes

Measurements use synthetic data and the installed SDK's prior content conversion,
then measure complete serialized `CallToolResult` objects. No tenant data is
written to this report.

| Fixture | Prior bytes | Bounded full initial bytes | Summary initial bytes |
| --------- | ------------: | ---------------------------: | ----------------------: |
| 150 detections with escaped Unicode evidence | 330082 | 810 | 7016 |
| One large nested Unicode record | 225252 | 789 | 792 |
| Large diagnostic | 100128 | 706 | 709 |
| 10000 aggregate buckets | 378999 | 735 | 738 |

These approximately 99.3–99.8% initial reductions for `full` defer data to
retrieval; they are not compression of the total information. Summary retains
150 projected detection rows, with about 97.9% initial reduction. Retrieval
responses individually remain within budget. Control metadata changes can
slightly change these counts; the reproducible measurement script is
`scripts/measure_response_budgets.py`.

Synthetic tests initialize real SDK client/server sessions and exercise normal
and dynamic dispatch, offset/cursor envelopes, exact reconstruction, nested field
navigation, huge keys, diagnostics, Unicode/escaping, empty results, projections,
invalid options, storage exhaustion/expiry/concurrency, and session isolation.
Live read-only tests use provided credentials and a 2048-byte budget for hosts,
detections, Spotlight, and NG-SIEM in both modes. Existing HTTP MCP compliance
tests cover actual HTTP framing. Live testing does not mutate tenant state or
claim coverage of every Falcon endpoint/schema.

Validation on 2026-09-10: the full suite passed 1802 tests and 281 subtests
(434 integration tests skipped in that default run). Ten explicit live tests
passed, including host ID retrieval, host offset and Spotlight cursor continuation,
exact snapshot comparison, and detection aggregates in both modes. Ruff/import
checks, repository-wide mypy, changed-document Markdown lint, and generated module
documentation freshness checks passed. Existing deprecation warnings remain.

The final-page regression tests exercise the actual MCP path at exactly 2048
bytes and one byte over. Retrieval budgets include the final `null` continuation;
an oversized child is explicitly deferred and remains recoverable by its path.

See [configuration and limitations](../usage/response-budgets.md) for storage,
session affinity, stateless migration, exception behavior, and client migrations.
