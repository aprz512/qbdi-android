"""Build the independent arm64 ART/JNI probe, without building an APK."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, default=os.environ.get("ANDROID_HOME"), required=not os.environ.get("ANDROID_HOME"))
    parser.add_argument("--build-tools", default="36.0.0")
    parser.add_argument("--output", type=Path, default=ROOT / "out/jni-abi-probe")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = ROOT / "tracer/src/test/device"
    with tempfile.TemporaryDirectory(prefix=".classes-", dir=args.output) as directory:
        classes = Path(directory)
        subprocess.run(["javac", "--release", "8", "-d", str(classes), str(source / "JniAbiProbe.java")], check=True)
        subprocess.run([str(args.sdk / "build-tools" / args.build_tools / "d8"), "--min-api", "28",
                        "--output", str(args.output), *map(str, sorted(classes.rglob("*.class")))], check=True)
    compiler = args.ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang++"
    subprocess.run([str(compiler), "-std=c++20", "-O1", "-g", "-shared", "-fPIC",
                    "-static-libstdc++", "-fvisibility=hidden", "-Wl,-z,max-page-size=16384",
                    "-I", str(ROOT / "tracer/src/main/cpp"), str(source / "jni_abi_probe.cpp"),
                    "-ldl", "-o", str(args.output / "libjni_abi_probe.so")], check=True)
    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    identity = {"schema_version": 1, "abi": "arm64-v8a", "api": 28,
                "compiler": str(compiler.resolve()), "build_tools": args.build_tools,
                "sources": {name: digest(source / name) for name in ("JniAbiProbe.java", "jni_abi_probe.cpp")},
                "artifacts": {name: digest(args.output / name) for name in ("libjni_abi_probe.so", "classes.dex")}}
    (args.output / "build-identity.json").write_text(json.dumps(identity, indent=2) + "\n")


if __name__ == "__main__":
    main()
