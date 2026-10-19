# qtrace-ui

Offline Linux desktop analyzer for QTRB 1.0–1.2 and Flight v2 captures, built with Tauri and React.
Open a qtrace session report to retain package, device, target, and configuration context.
Single-file open works with reduced context and reports missing capabilities.

The analyzer never attaches to a device or target process. Capture instructions are in the
[project usage guide](../docs/usage.md).

## Quick start

Install Rust stable, Node 22, and the [Tauri Linux build dependencies](docs/development.md#build-and-test).
From the repository root:

```bash
cd qtrace-ui/src-web
npm ci
npm run tauri -- dev
```

Use `npm run dev` for the web shell. Testing and desktop packaging commands are in the
[development guide](docs/development.md#build-and-test).

## Documentation

| Task | Guide |
| --- | --- |
| Open captures, navigate, inspect provenance, manage caches and annotations | [Usage](docs/usage.md) |
| Understand analysis layers, paging, cancellation, and resource limits | [Design](docs/design.md) |
| Build, test, verify captured sessions, reproduce diagnostics and performance gates | [Development and validation](docs/development.md) |

The [project documentation index](../docs/README.md) links format specifications, design history,
and retained benchmark evidence.

## Scope

Captured values remain labeled captured, derived, unknown, or damaged. Source artifacts stay immutable;
gaps and overwritten ranges remain explicit. See [truth and storage rules](docs/usage.md#truth-and-storage-model).

V1 excludes live capture, device control, trace editing, source-level debugging, collaborative sync,
Windows/macOS packaging, and automatic symbol downloads.
