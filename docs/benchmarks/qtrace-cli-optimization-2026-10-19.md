# qtrace CLI ownership, fault matrix, and evidence retention

Date: 2026-10-19. Scope: CLI-01, CLI-02, OPS-01. The starting working tree is
based on `72548df`; unrelated UI changes remain in the shared tree. This work
does not alter the public CLI, resource bounds, native protocol, or recovery
classification.

## Artifact ownership before extraction

```text
bound device identity
  remote listing / strict status / selected names
    bounded streaming into a held output-directory descriptor
      private .qtrace-stage-*/artifacts (collector owns cleanup)
        validation and derived files (only validated paths enter result)
          durable metadata and report fragment
            renameat2(RENAME_NOREPLACE) transfers stage to session directory
              parent/session fsync
                success: canonical report inode belongs to collector token
                durability error: committed partial, report refresh required
                  refresh succeeds: token names new canonical report inode
                  refresh fails: retain canonical report and recovery diagnostic
                    session diagnostic fails: parent sibling diagnostic
                    all diagnostics fail: raise, retain private recovery evidence
```

The output handle owns its descriptor and verifies the visible parent identity.
The stage owns a duplicate parent descriptor and a stage descriptor until cleanup.
Before rename, failures remove the private stage. After rename, errors never claim
an uncommitted result. Output replacement quarantines the held committed directory
and any fallback sibling as private recovery evidence. It never recursively deletes
an unverified replacement. Tokens retain parent/session descriptors and the exact
canonical report inode. A concurrent report replacement creates a separate error
report instead of overwriting the replacement. Every transferred descriptor gets a
cleanup attempt even when another close fails.

## Extraction boundary and proof

The internal owners now follow the existing transaction boundaries:

| Module | Owns | Does not own |
| --- | --- | --- |
| `qtrace._artifact_remote` | Bound device reads, listing rules, bounded pulled snapshots and SHA-256 | Session publication or trace interpretation |
| `qtrace._artifact_validation` | Strict status, trace/sidecar validation, derived members and provenance records | Output directory lifetime or commit |
| `qtrace._artifact_publication` | Held output/stage descriptors, no-replace directory commit, durability and recovery quarantine | Canonical report inode refresh |
| `qtrace._artifact_reports` | Bounded metadata writes, conditional report replacement, recovery diagnostics and merge tokens | Remote reads or trace conversion |
| `qtrace._artifact_common` | Existing result/selection values, basename rules and exhaustive cleanup | Transport or transaction state |
| `qtrace.artifacts` | Existing selection and lifecycle orchestration; public imports remain available | Decoder internals or directory operations |

The validator accepts a source-size callback for provenance. It cannot publish a
directory or take ownership of the remote client. `ArtifactProcessor._publish`
retains its existing signature and fault injection seam. Private test injection
targets for rename, report exchange, and decoder lookup follow their new owner.
The CLI arguments, result fields, selection ordering, bounds, and artifact
recovery rules remain unchanged by extraction.

Baseline: `python3 -m unittest scripts.tests.test_qtrace_artifacts
scripts.tests.test_qtrace_process scripts.tests.test_bounded_process -q` passed
122 tests in 12.873 seconds before edits. Final commands, the cross-entry fault
matrix, and retention policy follow.

The original 82 artifact tests pass after extraction. Their observable-state proof
includes these cases:

| Visible state | Representative existing proof |
| --- | --- |
| Remote read fails; no final directory or partial member returned | `test_bound_client_streams_chunks_and_removes_partial_on_transport_failure`, `test_transport_timeout_leaves_no_final_session_directory` |
| Source changes or short read; no apparent success | `test_collector_rejects_a_short_stream_against_the_bounded_remote_size` |
| Active/incomplete native evidence remains partial | `test_current_writer_is_retained_as_bounded_incomplete_evidence`, `test_all_keeps_only_sealed_uuid_roots_and_marks_active_partial` |
| Invalid root and its sidecars disappear; valid sibling survives | `test_corrupt_root_removes_sidecars_but_preserves_valid_sibling` |
| Existing destination survives no-replace commit | `test_existing_destination_is_never_overwritten` |
| Committed session with uncertain durability is partial | `test_post_rename_fsync_failure_returns_committed_partial` |
| Report refresh returns the applied inode, not a concurrent replacement | `test_refresh_returns_applied_inode_not_a_late_replacement` |
| Concurrent canonical report survives and no merge token is issued | `test_refresh_concurrent_report_does_not_issue_merge_token`, `test_collector_token_never_overwrites_a_concurrent_report_inode` |
| Failed refresh retains canonical report and a bounded diagnostic | `test_manual_refresh_failure_persists_error_report_with_recovery_name` |
| Session diagnostic fails; parent sibling is persisted without replacement | `test_refresh_persist_failure_writes_parent_sibling_without_following_collision` |
| All diagnostic persistence fails; operation raises | `test_refresh_persist_failures_raise_instead_of_returning_result` |
| Output replacement retains private committed recovery | `test_final_output_swap_reports_private_committed_recovery`, `test_parent_fallback_reclaim_retains_a_concurrently_replaced_sibling` |
| Interrupt and cleanup failures retain primary error and attempt all closes | `test_report_refresh_preserves_committed_report_and_propagates_interrupt`, `test_collector_publication_keeps_body_error_while_closing_every_fd` |

## Shared process fault matrix

`scripts/tests/test_qtrace_process_fault_matrix.py` runs one corpus through six
real command entries: `capture_bounded`, `BoundedRunner.capture`,
`BoundedRunner.stream`, `AdbDevice.shell`, `FridaInjector.install`'s force-stop
command, and acceptance `SubprocessRunner.run`. The ADB executable is a temporary
Python fixture. The processes, supervisor, namespace, output pipes, cancellation,
and reaping are real; no device is contacted by this matrix.

Each entry runs all six faults, for 36 cells:

| Fault | Trigger and required evidence |
| --- | --- |
| Timeout | Target exceeds explicit 0.6-second command deadline; correct timeout boundary and exact target identities cease running |
| Cancellation | SIGUSR1 raises `KeyboardInterrupt` after process identity receipts; cancellation survives and targets cease running |
| ADB disconnect | Fake ADB exits 1 after partial stdout and `error: device offline`; operation cannot return success and descendants cease running |
| PID reuse | Disable wrapper pidfd path and inject changed starttime before cancellation; raw `kill` is never called and cleanup reports the identity mismatch |
| Output limit | Target writes beyond entry's explicit stdout limit; size-limit error, bounded stream file and complete target teardown |
| Orphan process | Root exits 0 while a setsid double-fork daemon closes capture pipes and survives; no success is returned and daemon ceases running |

An AF_UNIX receipt server uses peer credentials and `/proc/<host-pid>/stat`
starttime to identify the root and orphan. Cleanup checks those exact identities,
not PID existence alone. The PID-reuse test intentionally refuses production
teardown; a test-owned pidfd opened before fault injection performs the final
cleanup. Existing namespace, child/wrapper fallback, stalled supervisor, late
fork, output, and descriptor identity tests remain unchanged. Production process
bounds and containment were not weakened. The shared helper already owns these
invariants; this work introduces no additional process abstraction.

Frida startup has an additional process-ownership boundary. A suspended Android
PID cannot safely be cleaned with an unqualified ADB `kill`. The previous path
did exactly that. Cleanup now invokes the fixed script's argument-free
`qtraceAbort` RPC inside the original process. The agent calls `_exit(137)` in its
own process and host accepts cleanup only after that same Frida session reports
`process-terminated`. RPC requests never accept a target PID. Successful resume
still prevents cleanup from terminating the application; ordinary timed tracing
continues to use native stop.

The worker reserves part of the existing setup budget for that RPC. A blocked RPC
cannot extend setup indefinitely; parent kills/reaps its own worker. Attach/load
failure, transport loss, cancellation before a receipt, and stuck worker paths
retain `inject.cleanup_incomplete: spawned PID ...` in the primary bounded error.
The marker precedes long primary messages so the existing 512-byte error limit
cannot discard it. These paths can leave the original suspended process alive;
they never guess its identity or kill a reused PID. Later package-scoped retry
starts with the existing force-stop operation. New diagnostics do not claim that
an unconfirmed process was terminated.

Additional injector tests cover blocked attach/resume/unload/detach calls, parent
cancellation after PID ownership transfer, the 1 MiB request limit, original
session termination receipts, disconnected-session/PID-reuse safety, and long
primary errors. Three new safety regressions fail against `HEAD`'s original
injector in a temporary package overlay and pass with the change. The Node agent
contract proves that only the argument-free cleanup RPC is exported and that it
resolves `_exit`, takes an integer exit code, and ignores an attempted PID input.

Actual Frida 17.24.2 also spawned a local suspended Python process and loaded the
complete repository agent. `exports_sync.qtrace_abort()` returned its original PID
322662; the original session reported `process-terminated` 47.122 ms after attach
started. A pidfd opened before invocation provided test cleanup. This validates
the real Python RPC mapping, agent NativeFunction, and session receipt. It is not
an Android timing measurement or proof of device detach delivery under transport
loss. Source, command, and result are retained in the companion JSON. A first
probe used the old Python 3.11 venv and found no `os.pidfd_open`; its target exited
and absence was checked. The successful probe used system Python 3.12 and the
same venv's ABI3 Frida bindings.

The same full agent also ran on a suspended fixed demo process on the actual
Pixel 6 (`1C111FDF600G6S`). The cleanup RPC returned the original PID 19313 and
that original session reported `process-terminated`. The bounded probe completed
in 501.869 ms; this single functional check is not a latency gate. No native
tracer request was posted. The JSON result is retained at
`artifacts/complete-optimization-2026-10-19/cli/frida-pixel-cleanup.json`.
Disconnected-session and PID-reuse safety continue to use controlled fault
injection; no Android PID recycling was forced.

## Read-only inventory and manual retention

Run from the repository root:

```sh
python3 scripts/qtrace_evidence.py
```

The command reads metadata and bounded success manifests. It creates no directory,
writes no marker, follows no symlink, and deletes nothing. Each run reports logical
bytes, allocated bytes, file/directory count, identity, inventory SHA-256, status,
and retention reason. Missing roots remain absent. The digest covers the root
inode plus member paths, modes, identities, sizes, mtime and ctime; it does not
re-hash multi-gigabyte trace content.

The actual read-only inventory found 2 successful directories with 1,463,012,030
logical bytes and 24 failed directories with 3,607,605,629 logical bytes. The full
directory inventory is in the companion JSON. This work removed no existing
evidence and did not alter those directories.

Manual retention policy:

1. Keep every failed, incomplete, unknown, and quarantined run until its incident
   is resolved and a human has reviewed the raw evidence. The tool never deletes
   anything under `qtrace-acceptance-failures`.
2. Keep successful runs referenced by a report, review, release gate, or benchmark.
   Keep raw samples and the source, device, corpus, binary, and configuration
   identities needed to reproduce their claims.
3. Keep a representative complete successful run for each currently supported
   device/build combination. Dates or matching byte counts alone do not prove a
   duplicate. Select obsolete whole runs only after reviewing their manifests
   and links from reports.
4. Move long-term evidence to an operator-managed archive when needed, then verify
   content hashes and archive readability before selecting the local successful
   run for deletion. No automatic age or size threshold removes evidence.

Preview one explicitly selected successful run using its current inventory digest:

```sh
python3 scripts/qtrace_evidence.py --delete-success UUID --inventory-sha256 SHA256
```

After review, explicitly apply that exact selection:

```sh
python3 scripts/qtrace_evidence.py --delete-success UUID --inventory-sha256 SHA256 --apply
```

Cleanup only selects the success root. It requires a strict successful gate
manifest and all eight expected regular scenario reports. A failure diagnostic,
unknown name, symlink/special member, or changed digest protects the run. Cleanup
atomically quarantines the chosen tree, compares the inventory again, and removes
only the same directory inode. Concurrent replacements remain as private evidence.
Tests use temporary workspaces for preview, deletion, stale metadata, root links,
failure protection, malformed opt-in flags, and quarantine replacement. They never
clean real acceptance output.

## Final validation

```sh
python3 -m unittest scripts.tests.test_qtrace_artifacts scripts.tests.test_qtrace_process scripts.tests.test_qtrace_process_fault_matrix scripts.tests.test_qtrace_injector scripts.tests.test_qtrace_device scripts.tests.test_qtrace_evidence scripts.tests.test_bounded_process scripts.tests.test_qtrace_contracts scripts.tests.test_qtrace_session scripts.tests.test_qtrace_cli -q
```

The final working tree passed 369 tests in 37.283 seconds, exit 0. All 36 real
command fault cells passed. The log is retained at
`artifacts/complete-optimization-2026-10-19/cli/python-focused-final.log`.
`git diff --check` passed for changed CLI source and tests. The companion
[JSON record](qtrace-cli-optimization-2026-10-19.json) includes source hashes,
the original-source regression result, the actual Frida probe, the full read-only
inventory, and exact validation commands. These checks prove the stated host
ownership and recovery boundaries, not Android throughput or UI behavior.
