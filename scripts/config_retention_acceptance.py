#!/usr/bin/env python3
"""Opt-in device check for invalid JSON preserving an accepted generation."""

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPAWN_TRACE = ROOT / "scripts/spawn_trace.js"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", default="com.aprz.qbdiandroid")
    parser.add_argument("--timeout", type=int, default=10)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        import frida
    except ImportError as error:
        raise SystemExit("Frida Python package is required") from error

    source = SPAWN_TRACE.read_text(encoding="utf-8")
    wrapper = """
rpc.exports = {
  runretentionacceptance() {
    return runConfigurationRetentionAcceptance();
  }
};
"""
    device = frida.get_usb_device(timeout=args.timeout)
    pid = None
    session = None
    script = None
    resumed = False
    try:
        pid = device.spawn([args.package])
        session = device.attach(pid)
        script = session.create_script(
            "globalThis.__QTRACE_TEST__ = true;\n" + source + "\n" + wrapper
        )
        script.load()
        result = script.exports_sync.runretentionacceptance()
        print(json.dumps(result, sort_keys=True))
        device.resume(pid)
        resumed = True
        return 0
    finally:
        if script is not None:
            script.unload()
        if session is not None:
            session.detach()
        if pid is not None and not resumed:
            device.kill(pid)


if __name__ == "__main__":
    raise SystemExit(main())
