"""Build the shared Android native API helper with the local SDK."""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile


def build_native_helper(adb_path: str) -> Path:
    """Cache only compiled source; no APK, service, or alternate control runner."""
    adb = shutil.which(adb_path)
    if not adb:
        raise RuntimeError("ADB executable unavailable for Android SDK discovery")
    sdk = Path(os.environ.get("ANDROID_SDK_ROOT") or Path(adb).resolve().parent.parent)
    version = lambda path: tuple(int(n) for n in re.findall(r"\d+", path.parent.name))
    platforms = list(sdk.glob("platforms/*/android.jar"))
    compilers = list(sdk.glob("build-tools/*/lib/d8.jar"))
    if not platforms or not compilers or not shutil.which("javac") or not shutil.which("java"):
        raise RuntimeError("Android native helper requires local JDK and Android SDK build-tools")
    android_jar = max(platforms, key=version)
    d8_jar = max(compilers, key=lambda path: version(path.parent))
    source = Path(__file__).with_name("native") / "AndroidNativeBridge.java"
    identity = sha256(source.read_bytes() + str(android_jar).encode() + str(d8_jar).encode()).hexdigest()
    cache = Path(__file__).resolve().parents[5] / "runs/tool-cache/android-native"
    cache.mkdir(parents=True, exist_ok=True)
    artifact = cache / (identity + ".zip")
    if artifact.is_file():
        with zipfile.ZipFile(artifact) as archive:
            if "classes.dex" not in archive.namelist() or archive.testzip():
                raise RuntimeError("Cached Android native helper is corrupt")
        return artifact
    with tempfile.TemporaryDirectory(prefix="compile-", dir=cache) as folder:
        work = Path(folder)
        classes = work / "classes"
        classes.mkdir()
        commands = (
            ("javac", "-encoding", "UTF-8", "--release", "8", "-classpath", str(android_jar),
             "-d", str(classes), str(source)),
            ("java", "-cp", str(d8_jar), "com.android.tools.r8.D8", "--lib", str(android_jar),
             "--min-api", "26", "--output", str(work / "snapshot.zip"),
             str(classes / "org/testbed/mobile/AndroidNativeBridge.class")),
        )
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=45, check=False)
            if result.returncode:
                raise RuntimeError("Android native helper compilation failed: " + result.stderr[-2000:])
        (work / "snapshot.zip").replace(artifact)
    return artifact
