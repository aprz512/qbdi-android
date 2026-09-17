#!/usr/bin/env python3
"""Fail when checked-in qtrace-ui fixtures or TypeScript DTOs drift."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "qtrace-ui"


def compare_trees(expected: Path, actual: Path) -> list[str]:
    expected_files = {path.relative_to(expected) for path in expected.rglob("*") if path.is_file()}
    actual_files = {path.relative_to(actual) for path in actual.rglob("*") if path.is_file()}
    diagnostics = [f"missing generated fixture: {path}" for path in sorted(expected_files - actual_files)]
    diagnostics += [f"unexpected generated fixture: {path}" for path in sorted(actual_files - expected_files)]
    for path in sorted(expected_files & actual_files):
        if expected.joinpath(path).read_bytes() != actual.joinpath(path).read_bytes():
            diagnostics.append(f"generated fixture drift: {path}")
    return diagnostics


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="qtrace-generated-") as directory:
        generated = Path(directory) / "fixtures"
        spec = importlib.util.spec_from_file_location("qtrace_fixture_export", UI / "tools/export_contract_fixtures.py")
        if spec is None or spec.loader is None:
            print("cannot load fixture exporter", file=sys.stderr)
            return 2
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        module.FIXTURE_ROOT = generated
        if module.main(["--write"]) != 0:
            print("fixture regeneration failed", file=sys.stderr)
            return 2
        diagnostics = compare_trees(UI / "fixtures", generated)

    bindings = subprocess.run(
        ["cargo", "run", "-q", "-p", "qtrace-service", "--bin", "export_bindings"],
        cwd=UI, capture_output=True, check=False,
    )
    if bindings.returncode != 0:
        diagnostics.append("TypeScript binding exporter failed")
    elif bindings.stdout != (UI / "src-web/src/api/generated.ts").read_bytes():
        diagnostics.append("generated binding drift: src-web/src/api/generated.ts")
    for diagnostic in diagnostics[:50]:
        print(diagnostic[:512], file=sys.stderr)
    if len(diagnostics) > 50:
        print(f"... {len(diagnostics) - 50} more generated differences", file=sys.stderr)
    return 1 if diagnostics else 0


if __name__ == "__main__":
    raise SystemExit(main())
