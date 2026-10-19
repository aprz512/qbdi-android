# qtrace-ui design

[Analyzer overview](../README.md) · [Project documentation](../../docs/README.md)

The analyzer keeps decoding, indexing, analysis, application services, and desktop presentation in separate layers:

```text
QTRB / Flight / session report
  -> qtrace-provider
  -> qtrace-store
  -> qtrace-analysis
  -> qtrace-service
  -> Tauri / React
```

Captured values remain captured, derived, unknown, or damaged. Missing events and overwritten ranges stay explicit.
See the [operator guide](usage.md#truth-and-storage-model) for provenance and source-storage rules.

## Long operations

Open jobs report source verification, cache validation, indexing, cache publication,
cache reopening, analysis preparation, and workspace publication. The outer count
tracks artifacts. Stage counters report accounted input bytes, events, and rows;
repeated validation passes count separately, and counters reset at each stage.
They do not estimate a percentage or remaining time. Updates are bounded and
coalesced; analysis preparation also reports row work when no input bytes change.
The Cancel button shows `Cancelling…` until the job reaches a terminal state and
allows another attempt if cancellation submission fails.

Cache validation uses at most two workers per artifact, sharing the existing
allocation, input, and cancellation budgets. Event keys and metadata decode
independently; the second worker then checks all section checksums alongside
catalog validation. Source identity, file stamps, corruption rebuilding, and
transactional publication remain enforced. Closing a workspace or cancelling
the service also cancels active register replay and call tree construction;
cancelled builds never populate their shared analysis caches.

## Call tree page memory

The call tree cache retains at most 8,192 nodes and 4 MiB of accounted weight.
Weight includes string lengths and allowances for objects; it is not a browser
heap limit. Each sibling page contains at most 100 nodes. Paging replaces that
parent's window and releases unreachable descendants. Least recently used
branches are evicted under pressure and remain available through expansion or
Load calls. An ancestor path that alone exceeds the budget is rejected without
replacing the current view. DOM virtualization also remains enabled.

## Timeline page requests

The main timeline uses one page repository per workspace, projection, and frontend
generation. Scrolling, next/previous pages, event jumps, and history reveal share
in-flight page requests. Only the latest navigation can publish its result;
aborted consumers cannot replace the visible timeline. Switching projections or
closing the workspace releases cached pages and rejects late responses.

Pages contain at most 2,000 rows. The LRU cache retains at most 128 pages and
32 MiB of accounted weight (four pages in E2E mode). Cursor positions are retained
with their cached pages; evicted pages can be located and fetched again. Weight
uses string lengths and object allowances, without serializing each page. This
is an accounting bound, not a browser heap limit. An already dispatched IPC call
cannot be cancelled; its response may populate the bounded cache while the same
projection remains open. Search results keep their independent page navigation.

## Service resource boundaries

Each artifact supports at most 4,294,967,295 events in the current numeric row
protocol. Opening an artifact above that limit returns
`workspace.event_limit_exceeded` before analysis preparation or workspace
publication. Counts and locations never silently saturate. Existing allocation
and event-work budgets still apply below that protocol ceiling.

Timeline responses contain at most 2,000 rows; call-tree pages contain at most
100 siblings and require the same tree identity for continuation. Filters accept
at most 256 terms across all fields, 4 KiB per text value and 64 KiB of aggregate
text. Memory directions accept all four existing variants. Symbol resolution accepts at
most 2,000 addresses. Identifiers and tree identities are capped at 256 bytes,
timeline cursors at 8 KiB, comments at 64 KiB, local names at 4 KiB and highlights
at 256 bytes. The request deserializers reject excess arrays and strings before
building their full typed values; service entry points repeat the checks for
non-IPC callers.

DTO responses are limited to 16 MiB of serialized JSON, including escaping.
The counter writes no encoded copy. Oversized open metadata is rejected before
workspace publication. This response bound complements the existing work,
deadline and cumulative allocation budgets; it is not a JavaScript heap limit.
Annotation SQLite work uses the same interactive deadline, VM-work budget and
workspace cancellation token.

At most eight open/projection jobs run concurrently. The registry retains at
most 512 jobs and evicts only terminal entries. Multi-artifact preparation runs
at most two artifacts concurrently with the same cumulative source and cache
budgets. Results keep report order, individual format failures remain isolated,
and every worker joins before an open error returns. Source keys that already
have strict order use an implicit row mapping in memory; nonmonotonic sources
retain an explicit sorted mapping. The cache schema and encoded row bytes stay
compatible with existing readers.

Measurements, compatibility checks and the command audit are recorded in the
[2026-10-19 store and boundary report](../../docs/benchmarks/qtrace-store-boundaries-2026-10-19.md).

## Design history

The original [analyzer design](../../docs/superpowers/specs/2026-08-30-qtrace-ui-design.md)
and [implementation plan](../../docs/superpowers/plans/2026-08-30-qtrace-ui-offline-analyzer.md)
preserve the original decisions. Current workflows and diagnostics are in the
[development guide](development.md).
