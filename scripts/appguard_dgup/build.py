"""Build the opt-in AppGuard analysis tracer without changing default user rules."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, default=os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT"), required=not (os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")))
    parser.add_argument("--cmake", type=Path)
    args = parser.parse_args()
    ndk = args.ndk.resolve()
    cmake = args.cmake or shutil.which("cmake")
    if not cmake:
        candidates = sorted((ndk.parents[1] / "cmake").glob("*/bin/cmake"))
        if candidates: cmake = candidates[-1]
    if not cmake: parser.error("CMake unavailable; pass --cmake")
    cmake = Path(cmake).resolve()
    ninja = shutil.which("ninja") or str(cmake.with_name("ninja"))
    output = ROOT / "out/appguard-dgup"
    build = ROOT / "out/appguard-dgup-build"
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(cmake), "-S", str(ROOT / "tracer/src/main/cpp"), "-B", str(build),
        "-G", "Ninja", "-DCMAKE_MAKE_PROGRAM=" + ninja,
        "-DCMAKE_TOOLCHAIN_FILE=" + str(ndk / "build/cmake/android.toolchain.cmake"),
        "-DANDROID_ABI=arm64-v8a", "-DANDROID_PLATFORM=android-28", "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=" + str(output),
        "-DQTRACE_SHADOWHOOK_LONG_JUMP_FALLBACK=ON",
        "-DQTRACE_USER_RULES_SAMPLE_SHA256=4aeafdbe1ea691c8c6f7ea675cb817688a1f4875a258b97e1f342aaebd9094d0",
        "-DQTRACE_USER_RULES_SOURCE=" + str(ROOT / "scripts/appguard_dgup/rules.cpp")], check=True)
    subprocess.run([str(cmake), "--build", str(build), "--target", "qbdi_tracer", "shadowhook_nothing", "-j", "4"], check=True)
    clang = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang++"
    subprocess.run([str(clang), "-shared", "-fPIC", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
        "-fno-exceptions", "-fno-rtti", "-nostdlib++", "-Wl,-z,max-page-size=16384", "-Wl,-z,nodelete",
        str(ROOT / "scripts/appguard_dgup/guard.cpp"), "-ldl", "-llog",
        "-o", str(output / "libappguard_dgup.so")], check=True)
    print(output)


if __name__ == "__main__":
    main()
