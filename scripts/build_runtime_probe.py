"""Build standalone arm64 native runtime acceptance targets and supervisor."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "out/runtime-probe")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    compiler = args.ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang++"
    source = ROOT / "tracer/src/test/device"
    common = [str(compiler), "-std=c++20", "-O1", "-g", "-static-libstdc++", "-Wl,-z,max-page-size=16384"]
    subprocess.run([*common, "-shared", "-fPIC", "-fvisibility=hidden", str(source / "runtime_probe_target.cpp"),
                    "-o", str(args.output / "libruntime_probe.so")], check=True)
    subprocess.run([*common, "-fPIE", "-pie", "-I", str(ROOT / "tracer/src/main/cpp"),
                    str(source / "runtime_probe_launcher.cpp"), "-ldl", "-o", str(args.output / "runtime_probe")], check=True)
    subprocess.run([*common, "-fPIE", "-pie", "-I", str(ROOT / "tracer/src/main/cpp"),
                    str(source / "snapshot_native_probe.cpp"), "-ldl", "-o", str(args.output / "snapshot_native_probe")], check=True)
    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream,"sha256").hexdigest()
    identity = {"compiler":str(compiler),"abi":"arm64-v8a","api":28,
                "sources":{name:digest(source/name) for name in ("runtime_probe.h","runtime_probe_target.cpp","runtime_probe_launcher.cpp","snapshot_native_probe.cpp")},
                "artifacts":{name:digest(args.output/name) for name in ("runtime_probe","libruntime_probe.so","snapshot_native_probe")}}
    (args.output / "build-identity.json").write_text(json.dumps(identity,indent=2)+"\n")


if __name__ == "__main__":
    main()
