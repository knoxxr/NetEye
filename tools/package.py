"""Build the NetEye installers for Windows, Linux, macOS, and Android.

    python tools/package.py windows     dist/NetEye-<ver>.msi and dist/NetEye-Setup-<ver>.exe
    python tools/package.py linux       dist/neteye_<ver>_amd64.deb and dist/neteye-<ver>-linux-x86_64.tar.gz
    python tools/package.py macos       dist/NetEye-<ver>-macos-universal.pkg and dist/neteye-<ver>-macos-universal.tar.gz
    python tools/package.py android     dist/NetEye-<ver>-android-arm64.apk
    python tools/package.py all

Windows needs: Rust (msvc), Go, WiX 5 (`dotnet tool install -g wix`) with the extensions
WixToolset.Util.wixext and WixToolset.BootstrapperApplications.wixext.
Linux needs:   Rust with target x86_64-unknown-linux-gnu, Go (optional: cargo-zigbuild + ziglang for glibc 2.17).
macOS needs:   macOS host, Rust targets aarch64-apple-darwin + x86_64-apple-darwin, Go, Xcode CLI tools (lipo, pkgbuild).
Android needs: Rust target aarch64-linux-android, Go, Android SDK + NDK, JDK 17+, Gradle.
All targets embed data/vulndb.json and data/ip2asn-v4.tsv.gz (tools/vulndb_build.py, tools/ipasn_build.py)
so the installed sensor works offline from the first start.
"""
import argparse
import hashlib
import io
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
CACHE = DIST / "cache"
PKG = ROOT / "packaging"
BANGDB = "github.com/knoxxr/bangdb"
BANGDB_VERSION = "v0.7.73"

# Pinned downloads (checked by hash).
WINSW_URL = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
WINSW_SHA256 = "05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da"
NPCAP_URL = "https://npcap.com/dist/npcap-1.90.exe"
NPCAP_SHA512 = ("DBF9492DC0FE821BDF64AEE0F82096A80E16B15A7C68D352B0C3F452C0C2B10F"
                "7C49ADB7E6BB9173DFCB4627177EE0B6988C2BC838F8CE5FF4AB9AB245AC7263")


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), file=sys.stderr)
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def version() -> str:
    text = (ROOT / "sensor" / "Cargo.toml").read_text(encoding="utf-8")
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


def download(url: str, dest: Path, sha256: str | None = None, sha512: str | None = None) -> Path:
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_suffix(dest.suffix + ".part")
        req = urllib.request.Request(url, headers={"User-Agent": "NetEye-packager"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r, open(part, "wb") as f:
                shutil.copyfileobj(r, f)
            part.replace(dest)
        except Exception:
            part.unlink(missing_ok=True)
            raise
    data = dest.read_bytes()
    if sha256 and hashlib.sha256(data).hexdigest().lower() != sha256.lower():
        dest.unlink()
        raise SystemExit(f"{dest.name}: SHA-256 mismatch")
    if sha512 and hashlib.sha512(data).hexdigest().lower() != sha512.lower():
        dest.unlink()
        raise SystemExit(f"{dest.name}: SHA-512 mismatch")
    return dest


def data_files() -> dict[str, Path]:
    files = {}
    for name in ("vulndb.json", "ip2asn-v4.tsv.gz"):
        p = ROOT / "data" / name
        if not p.exists():
            raise SystemExit(f"data/{name} is missing: build it first (tools/vulndb_build.py, tools/ipasn_build.py)")
        files[name] = p
    return files


def text_file(src: Path, dest: Path, crlf: bool = False, bom: bool = False):
    text = src.read_text(encoding="utf-8").replace("\r\n", "\n")
    if crlf:
        text = text.replace("\n", "\r\n")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes((b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8"))


def bangdb(goos: str, goarch: str = "amd64") -> Path:
    """Build the BangDB server for a target OS/arch (CGO off, so cross-compiling just works)."""
    out_dir = CACHE / f"{goos}-{goarch}-{BANGDB_VERSION}"
    exe = out_dir / ("bangdb.exe" if goos == "windows" else "bangdb")
    if exe.exists():
        return exe
    gopath = Path(tempfile.mkdtemp(prefix="neteye-gopath-"))
    env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0", "GOPATH": str(gopath),
           "GOFLAGS": "-modcacherw"}
    env.pop("GOBIN", None)
    plain = BANGDB_VERSION.lstrip("v")
    try:
        run(["go", "install", "-trimpath", "-ldflags", f"-s -w -X {BANGDB}.Version={plain}",
             f"{BANGDB}/cmd/bangdb@{BANGDB_VERSION}"], env=env)
        built = next(p for p in (gopath / "bin").rglob(exe.name))
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, exe)
    finally:
        shutil.rmtree(gopath, ignore_errors=True)
    return exe


# ------------------------------------------------------------------ Windows
def windows():
    ver = version()
    run(["cargo", "build", "--release"], cwd=ROOT / "sensor")
    stage = DIST / "windows" / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    (stage / "data").mkdir(parents=True)
    shutil.copy2(ROOT / "sensor" / "target" / "release" / "neteye.exe", stage)
    shutil.copy2(bangdb("windows", "amd64"), stage / "bangdb.exe")
    winsw = download(WINSW_URL, CACHE / "WinSW-x64-2.12.0.exe", sha256=WINSW_SHA256)
    shutil.copy2(winsw, stage / "neteye-service.exe")
    text_file(PKG / "windows" / "neteye-service.xml", stage / "neteye-service.xml", crlf=True)
    text_file(PKG / "windows" / "neteye.conf", stage / "neteye.conf", crlf=True)
    text_file(PKG / "windows" / "update-intel.ps1", stage / "update-intel.ps1", crlf=True, bom=True)
    text_file(PKG / "THIRD-PARTY.txt", stage / "THIRD-PARTY.txt", crlf=True)
    shutil.copytree(ROOT / "frontend", stage / "frontend")
    for name, path in data_files().items():
        shutil.copy2(path, stage / "data" / name)

    msi = DIST / f"NetEye-{ver}.msi"
    run(["wix", "build", "-arch", "x64", "-ext", "WixToolset.Util.wixext",
         "-d", f"Version={ver}", "-d", f"Stage={stage}", PKG / "windows" / "Package.wxs", "-o", msi])

    npcap = download(NPCAP_URL, CACHE / NPCAP_URL.rsplit("/", 1)[1], sha512=NPCAP_SHA512)
    setup = DIST / f"NetEye-Setup-{ver}.exe"
    run(["wix", "build", "-arch", "x64", "-ext", "WixToolset.Util.wixext",
         "-ext", "WixToolset.BootstrapperApplications.wixext",
         "-d", f"Version={ver}", "-d", f"MsiPath={msi}", "-d", f"NpcapUrl={NPCAP_URL}",
         "-d", f"NpcapHash={NPCAP_SHA512}", "-d", f"NpcapSize={npcap.stat().st_size}",
         PKG / "windows" / "Bundle.wxs", "-o", setup])
    for p in (msi, setup):
        print(f"{p}  {p.stat().st_size / 1e6:.1f} MB")


# ------------------------------------------------------------------ Tar/Deb helpers
def tar_add(tar: tarfile.TarFile, name: str, data: bytes, mode: int):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), mode, int(time.time())
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    tar.addfile(info, io.BytesIO(data))


def tar_dir(tar: tarfile.TarFile, name: str):
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, int(time.time())
    info.uname = info.gname = "root"
    tar.addfile(info)


def lf(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


# ------------------------------------------------------------------ Linux
def linux_files(neteye: Path, bangdb_bin: Path) -> list[tuple[str, bytes, int]]:
    """(relative path in the payload, content, mode)."""
    out = [("neteye", neteye.read_bytes(), 0o755), ("bangdb", bangdb_bin.read_bytes(), 0o755)]
    for name in ("update-intel.sh", "uninstall.sh", "setup-common.sh"):
        out.append((name, lf(PKG / "linux" / name), 0o755 if name != "setup-common.sh" else 0o644))
    out.append(("neteye.service", lf(PKG / "linux" / "neteye.service"), 0o644))
    out.append(("neteye.conf", lf(PKG / "linux" / "neteye.conf"), 0o644))
    out.append(("README.md", lf(ROOT / "README.md"), 0o644))
    out.append(("THIRD-PARTY.txt", lf(PKG / "THIRD-PARTY.txt"), 0o644))
    for f in sorted((ROOT / "frontend").rglob("*")):
        if f.is_file():
            out.append((f"frontend/{f.relative_to(ROOT / 'frontend').as_posix()}", lf(f), 0o644))
    for name, path in data_files().items():
        out.append((f"data/{name}", path.read_bytes(), 0o644))
    return out


def ar_member(name: str, data: bytes) -> bytes:
    header = f"{name:<16}{int(time.time()):<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
    return header + data + (b"\n" if len(data) % 2 else b"")


def build_deb(ver: str, files: list[tuple[str, bytes, int]], out: Path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        dirs = set()
        def add(path: str, content: bytes, mode: int):
            parts = path.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                d = "./" + "/".join(parts[:i])
                if d not in dirs:
                    dirs.add(d)
                    tar_dir(tar, d)
            tar_add(tar, "./" + path, content, mode)
        size = 0
        for rel, content, mode in files:
            if rel in ("uninstall.sh", "neteye.service", "neteye.conf", "setup-common.sh") or rel.startswith("data/"):
                continue
            add(f"opt/neteye/{rel}", content, mode)
            size += len(content)
        for rel, content, mode in files:
            if rel == "neteye.service":
                add("lib/systemd/system/neteye.service", content, 0o644)
            elif rel in ("neteye.conf", "setup-common.sh"):
                add(f"usr/share/neteye/{rel}", content, 0o644)
            elif rel.startswith("data/"):
                add(f"usr/share/neteye/{rel}", content, 0o644)
            else:
                continue
            size += len(content)
    control = (
        "Package: neteye\n"
        f"Version: {ver}\n"
        "Architecture: amd64\n"
        "Maintainer: NetEye Maintainers <neteye@localhost>\n"
        "Section: net\n"
        "Priority: optional\n"
        "Depends: libpcap0.8t64 | libpcap0.8, passwd\n"
        "Recommends: curl\n"
        f"Installed-Size: {size // 1024}\n"
        "Description: NetEye passive OT/ICS network monitoring sensor\n"
        " Passive asset discovery, protocol analysis, baseline and anomaly detection for industrial\n"
        " networks (S7, Modbus, EtherNet/IP, DNP3, IEC 104 ...), with a web dashboard.\n"
    ).encode()
    ctl = io.BytesIO()
    with tarfile.open(fileobj=ctl, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        tar_add(tar, "./control", control, 0o644)
        for script in ("postinst", "prerm", "postrm"):
            tar_add(tar, f"./{script}", lf(PKG / "linux" / "deb" / script), 0o755)
    blob = b"!<arch>\n" + ar_member("debian-binary", b"2.0\n") + ar_member("control.tar.gz", ctl.getvalue()) \
        + ar_member("data.tar.gz", data.getvalue())
    out.write_bytes(blob)


def build_tarball(ver: str, files: list[tuple[str, bytes, int]], out: Path):
    top = f"neteye-{ver}-linux-x86_64"
    with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        tar_dir(tar, top)
        tar_add(tar, f"{top}/install.sh", lf(PKG / "linux" / "install.sh"), 0o755)
        tar_dir(tar, f"{top}/payload")
        dirs = set()
        for rel, content, mode in files:
            parts = rel.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                d = f"{top}/payload/" + "/".join(parts[:i])
                if d not in dirs:
                    dirs.add(d)
                    tar_dir(tar, d)
            tar_add(tar, f"{top}/payload/{rel}", content, mode)


def linux():
    ver = version()
    target = "x86_64-unknown-linux-gnu"
    run(["rustup", "target", "add", target])
    env = dict(os.environ)
    zig_bin = shutil.which("zig")
    if not zig_bin:
        try:  # zig from the `ziglang` pip package, when zig itself is not on PATH
            import ziglang
            zig = Path(ziglang.__file__).parent / ("zig.exe" if os.name == "nt" else "zig")
            if zig.exists():
                zig_bin = str(zig)
                env.setdefault("CARGO_ZIGBUILD_ZIG_PATH", zig_bin)
        except ImportError:
            pass

    if shutil.which("cargo-zigbuild") and zig_bin:
        # glibc 2.17 baseline: runs on RHEL/CentOS 7+, Ubuntu 14.04+, Debian 8+.
        run(["cargo", "zigbuild", "--release", "--target", f"{target}.2.17"], cwd=ROOT / "sensor", env=env)
    elif sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64"):
        print("note: cargo-zigbuild/zig not found; building natively against host glibc", file=sys.stderr)
        run(["cargo", "build", "--release", "--target", target], cwd=ROOT / "sensor", env=env)
    else:
        raise SystemExit("Linux cross-build requires cargo-zigbuild and zig (pip install ziglang)")

    neteye = ROOT / "sensor" / "target" / target / "release" / "neteye"
    files = linux_files(neteye, bangdb("linux", "amd64"))
    deb = DIST / f"neteye_{ver}_amd64.deb"
    tgz = DIST / f"neteye-{ver}-linux-x86_64.tar.gz"
    build_deb(ver, files, deb)
    build_tarball(ver, files, tgz)
    for p in (deb, tgz):
        print(f"{p}  {p.stat().st_size / 1e6:.1f} MB")


# ------------------------------------------------------------------ macOS
def macos():
    if sys.platform != "darwin":
        raise SystemExit("macOS installer (.pkg) must be built on a macOS host (or GitHub Actions macos-latest)")
    ver = version()
    targets = ("aarch64-apple-darwin", "x86_64-apple-darwin")
    for t in targets:
        run(["rustup", "target", "add", t])
        run(["cargo", "build", "--release", "--target", t], cwd=ROOT / "sensor")

    stage = DIST / "macos"
    shutil.rmtree(stage, ignore_errors=True)
    root_dir = stage / "root"
    app_dir = root_dir / "Library" / "NetEye"
    defaults_dir = app_dir / "defaults"
    daemons_dir = root_dir / "Library" / "LaunchDaemons"
    scripts_dir = stage / "scripts"
    for d in (app_dir, defaults_dir, daemons_dir, scripts_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Combine Apple Silicon (arm64) + Intel (x86_64) into universal binaries.
    universal_neteye = app_dir / "neteye"
    run(["lipo", "-create",
         ROOT / "sensor" / "target" / targets[0] / "release" / "neteye",
         ROOT / "sensor" / "target" / targets[1] / "release" / "neteye",
         "-output", universal_neteye])
    universal_neteye.chmod(0o755)

    universal_bangdb = app_dir / "bangdb"
    run(["lipo", "-create",
         bangdb("darwin", "arm64"),
         bangdb("darwin", "amd64"),
         "-output", universal_bangdb])
    universal_bangdb.chmod(0o755)

    for name in ("update-intel.sh", "uninstall.sh"):
        dest = app_dir / name
        dest.write_bytes(lf(PKG / "macos" / name))
        dest.chmod(0o755)
    (app_dir / "README.md").write_bytes(lf(ROOT / "README.md"))
    (app_dir / "THIRD-PARTY.txt").write_bytes(lf(PKG / "THIRD-PARTY.txt"))
    shutil.copytree(ROOT / "frontend", app_dir / "frontend")

    (defaults_dir / "neteye.conf").write_bytes(lf(PKG / "macos" / "neteye.conf"))
    for name, path in data_files().items():
        shutil.copy2(path, defaults_dir / name)

    (daemons_dir / "com.neteye.sensor.plist").write_bytes(lf(PKG / "macos" / "com.neteye.sensor.plist"))

    for script in ("preinstall", "postinstall"):
        dest = scripts_dir / script
        dest.write_bytes(lf(PKG / "macos" / "scripts" / script))
        dest.chmod(0o755)

    pkg = DIST / f"NetEye-{ver}-macos-universal.pkg"
    run(["pkgbuild",
         "--root", root_dir,
         "--scripts", scripts_dir,
         "--identifier", "com.neteye.sensor",
         "--version", ver,
         "--install-location", "/",
         pkg])

    # Also build a portable tarball with install.sh.
    tgz = DIST / f"neteye-{ver}-macos-universal.tar.gz"
    top = f"neteye-{ver}-macos-universal"
    with tarfile.open(tgz, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        tar_dir(tar, top)
        tar_add(tar, f"{top}/install.sh", lf(PKG / "macos" / "install.sh"), 0o755)
        tar_dir(tar, f"{top}/scripts")
        for script in ("preinstall", "postinstall"):
            tar_add(tar, f"{top}/scripts/{script}", lf(PKG / "macos" / "scripts" / script), 0o755)
        tar_dir(tar, f"{top}/payload")
        tar_add(tar, f"{top}/payload/neteye", universal_neteye.read_bytes(), 0o755)
        tar_add(tar, f"{top}/payload/bangdb", universal_bangdb.read_bytes(), 0o755)
        for name in ("update-intel.sh", "uninstall.sh"):
            tar_add(tar, f"{top}/payload/{name}", lf(PKG / "macos" / name), 0o755)
        tar_add(tar, f"{top}/payload/com.neteye.sensor.plist", lf(PKG / "macos" / "com.neteye.sensor.plist"), 0o644)
        tar_add(tar, f"{top}/payload/neteye.conf", lf(PKG / "macos" / "neteye.conf"), 0o644)
        tar_add(tar, f"{top}/payload/README.md", lf(ROOT / "README.md"), 0o644)
        tar_add(tar, f"{top}/payload/THIRD-PARTY.txt", lf(PKG / "THIRD-PARTY.txt"), 0o644)
        tar_dir(tar, f"{top}/payload/frontend")
        for f in sorted((ROOT / "frontend").rglob("*")):
            if f.is_file():
                rel = f.relative_to(ROOT / "frontend").as_posix()
                tar_add(tar, f"{top}/payload/frontend/{rel}", lf(f), 0o644)
        tar_dir(tar, f"{top}/payload/data")
        for name, path in data_files().items():
            tar_add(tar, f"{top}/payload/data/{name}", path.read_bytes(), 0o644)

    for p in (pkg, tgz):
        print(f"{p}  {p.stat().st_size / 1e6:.1f} MB")


# ------------------------------------------------------------------ Android
def find_android_sdk() -> Path:
    for env_key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(env_key)
        if val and Path(val).is_dir():
            return Path(val)
    for cand in (Path("/opt/android-sdk"), Path.home() / "Android" / "Sdk", Path.home() / "Library" / "Android" / "sdk"):
        if cand.is_dir():
            return cand
    raise SystemExit("Android SDK not found (set ANDROID_HOME or ANDROID_SDK_ROOT)")


def find_android_ndk(sdk: Path) -> Path:
    for env_key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"):
        val = os.environ.get(env_key)
        if val and Path(val).is_dir():
            return Path(val)
    ndk_root = sdk / "ndk"
    if ndk_root.is_dir():
        versions = sorted([p for p in ndk_root.iterdir() if p.is_dir()])
        if versions:
            return versions[-1]
    raise SystemExit(f"Android NDK not found under {ndk_root} (install via sdkmanager 'ndk;28.2.13676358')")


def android():
    ver = version()
    sdk = find_android_sdk()
    ndk = find_android_ndk(sdk)
    host_tag = {
        "linux": "linux-x86_64",
        "darwin": "darwin-x86_64",
        "win32": "windows-x86_64",
    }.get(sys.platform, "linux-x86_64")
    llvm_bin = ndk / "toolchains" / "llvm" / "prebuilt" / host_tag / "bin"
    ext = ".cmd" if sys.platform == "win32" else ""
    linker = llvm_bin / f"aarch64-linux-android26-clang{ext}"
    ar = llvm_bin / ("llvm-ar.exe" if sys.platform == "win32" else "llvm-ar")
    if not linker.exists():
        raise SystemExit(f"NDK linker not found: {linker}")

    target = "aarch64-linux-android"
    run(["rustup", "target", "add", target])
    env = {
        **os.environ,
        "ANDROID_HOME": str(sdk),
        "ANDROID_SDK_ROOT": str(sdk),
        "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER": str(linker),
        "CC_aarch64_linux_android": str(linker),
        "AR_aarch64_linux_android": str(ar),
    }
    run(["cargo", "build", "--release", "--target", target], cwd=ROOT / "sensor", env=env)
    neteye_bin = ROOT / "sensor" / "target" / target / "release" / "neteye"
    # Static pure-Go ARM64 Linux ELF runs directly on Android ARM64 kernels without glibc.
    bangdb_bin = bangdb("linux", "arm64")

    android_dir = PKG / "android"
    main_dir = android_dir / "app" / "src" / "main"
    jni_dir = main_dir / "jniLibs" / "arm64-v8a"
    assets_dir = main_dir / "assets"
    shutil.rmtree(jni_dir, ignore_errors=True)
    shutil.rmtree(assets_dir, ignore_errors=True)
    jni_dir.mkdir(parents=True, exist_ok=True)
    (assets_dir / "data").mkdir(parents=True, exist_ok=True)

    shutil.copy2(neteye_bin, jni_dir / "libneteye.so")
    shutil.copy2(bangdb_bin, jni_dir / "libbangdb.so")
    strip_tool = llvm_bin / ("llvm-strip.exe" if sys.platform == "win32" else "llvm-strip")
    if strip_tool.exists():
        run([strip_tool, "--strip-debug", jni_dir / "libneteye.so"])
    (jni_dir / "libneteye.so").chmod(0o755)
    (jni_dir / "libbangdb.so").chmod(0o755)

    shutil.copytree(ROOT / "frontend", assets_dir / "frontend")
    for name, path in data_files().items():
        # Suffix .gz files with .bin so aapt2 preserves them intact instead of decompressing and renaming.
        dest_name = f"{name}.bin" if name.endswith(".gz") else name
        shutil.copy2(path, assets_dir / "data" / dest_name)

    gradle = shutil.which("gradle")
    if not gradle:
        raise SystemExit("gradle not found on PATH")
    run([gradle, "--no-daemon", f"-PneteyeVersion={ver}", "assembleRelease"], cwd=android_dir, env=env)

    out_dir = android_dir / "app" / "build" / "outputs" / "apk" / "release"
    built_apk = next((p for p in sorted(out_dir.glob("*.apk"))), None)
    if not built_apk:
        raise SystemExit(f"APK output not found under {out_dir}")
    apk = DIST / f"NetEye-{ver}-android-arm64.apk"
    shutil.copy2(built_apk, apk)
    print(f"{apk}  {apk.stat().st_size / 1e6:.1f} MB")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", choices=["windows", "linux", "macos", "android", "all"])
    args = parser.parse_args()
    DIST.mkdir(exist_ok=True)
    if args.target in ("linux", "all"):
        linux()
    if args.target in ("windows", "all"):
        windows()
    if args.target in ("macos", "all"):
        macos()
    if args.target in ("android", "all"):
        android()


if __name__ == "__main__":
    main()
