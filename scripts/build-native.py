"""从锁定的官方源码构建 OHCRYPTO 静态库；不依赖 HomoXterm 或固定构建机。"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import urllib.request
import uuid

from native_inputs import read_inputs, sha256, source_inventory, validate_source_cache


ROOT = Path(__file__).resolve().parents[1]


def within(path: Path, parent: Path) -> Path:
    """所有写入和移动目标都必须位于本次原生输入对应的生成目录中。"""
    resolved = path.resolve()
    if resolved == parent.resolve() or not resolved.is_relative_to(parent.resolve()):
        raise ValueError("Native output path escapes the allowed generated directory")
    return resolved


def extract_source(archive: Path, destination: Path, prefix: str) -> None:
    """仅提取普通文件和目录，逐项拒绝越界路径、链接及特殊文件。"""
    with tarfile.open(archive, "r:xz") as source:
        for member in source:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name or path.parts[0] != prefix:
                raise ValueError("Unsafe path in upstream archive")
            relative = Path(*path.parts[1:])
            if not relative.parts:
                if not member.isdir():
                    raise ValueError("Invalid upstream archive root")
                continue
            target = within(destination / relative, destination)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as content, target.open("xb") as output:
                    shutil.copyfileobj(content, output)
                target.chmod(member.mode & 0o777)
            else:
                raise ValueError("Links and special upstream archive entries are not allowed")


def build(args: argparse.Namespace) -> None:
    """核对输入后交叉编译；不同源码身份使用独立缓存，不删除已有构建。"""
    native = args.native_root.resolve(strict=True)
    project = native.parent
    build_root = within(args.build_root or project / "build/native", project / "build")
    install = within(args.install_root or native / "prebuilt/arm64-v8a", native / "prebuilt")
    lock, patches, backend, fingerprint = read_inputs(native)
    dependency = lock["libssh2"]
    if dependency["ohosBuild"]["abi"] != "arm64-v8a" or dependency["ohosBuild"]["api"] != 26:
        raise ValueError("This release requires arm64-v8a and API 26")
    version = dependency["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid upstream version")
    sdk_value = os.environ.get("DEVECO_CLI_CLT_PATH")
    if not sdk_value:
        raise ValueError("DEVECO_CLI_CLT_PATH must identify the HarmonyOS Command Line Tools root")
    sdk = Path(sdk_value).resolve(strict=True)
    native_sdk = sdk / "sdk/default/openharmony/native"
    suffix = ".exe" if os.name == "nt" else ""
    cmake = native_sdk / f"build-tools/cmake/bin/cmake{suffix}"
    ninja = native_sdk / f"build-tools/cmake/bin/ninja{suffix}"
    toolchain = sdk / "sdk/default/hms/native/build/cmake/hmos.toolchain.cmake"
    compiler = native_sdk / f"llvm/bin/clang{suffix}"
    sdk_version = sdk / "version.txt"
    for tool in [cmake, ninja, toolchain, compiler, sdk_version]:
        if not tool.is_file():
            raise ValueError("Required tool is missing in the configured SDK")
    patch_tool = shutil.which("patch")
    if not patch_tool:
        raise ValueError("GNU patch is required on PATH")

    downloads = build_root / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / f"libssh2-{version}.tar.xz"
    if not archive.exists() or sha256(archive) != dependency["archive"]["sha256"]:
        url = dependency["archive"]["url"]
        if url != f"https://libssh2.org/download/libssh2-{version}.tar.xz":
            raise ValueError("Unexpected upstream download URL")
        temporary = downloads / f"{archive.name}.{uuid.uuid4().hex}.download"
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("xb") as output:
            if not response.geturl().startswith("https://"):
                raise ValueError("Upstream download redirected away from HTTPS")
            shutil.copyfileobj(response, output)
        if sha256(temporary) != dependency["archive"]["sha256"]:
            raise ValueError("Upstream archive checksum mismatch")
        temporary.replace(archive)

    inputs = build_root / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    # 新清单版本使用独立命名空间，旧标记不会被当成完整性证据。
    source = inputs / ("v2-" + fingerprint)
    marker = source / ".libssh2-oh-inputs.json"
    if source.exists():
        validate_source_cache(source, fingerprint)
    else:
        stage = within(inputs / f"stage-{uuid.uuid4().hex}", inputs)
        stage.mkdir()
        extract_source(archive, stage, f"libssh2-{version}")
        for name in backend:
            shutil.copyfile(native / "libssh2/ohcrypto" / name, stage / "src" / name)
        for patch in patches:
            subprocess.run([patch_tool, "--directory", str(stage), "--strip=1", "--forward"],
                           input=(native / "libssh2/patches" / patch["file"]).read_bytes(), check=True)
        inventory = source_inventory(stage)
        (stage / marker.name).write_text(json.dumps({
            "schemaVersion": 2, "fingerprint": fingerprint, "files": inventory
        }, indent=2) + "\n", encoding="utf-8")
        within(stage, inputs).rename(within(source, inputs))

    inventory = validate_source_cache(source, fingerprint)
    # SDK 变化不能复用缓存中的旧编译器；只将摘要写入公开来源清单。
    toolchain_fingerprint = hashlib.sha256(json.dumps({
        "sdkRoot": str(sdk), "sdkVersion": sha256(sdk_version),
        "compiler": sha256(compiler), "toolchain": sha256(toolchain)
    }, sort_keys=True).encode()).hexdigest()
    target = build_root / "cmake" / ("v2-" + fingerprint + "-" + toolchain_fingerprint[:16])
    subprocess.run([str(cmake), "-S", str(source), "-B", str(target), "-G", "Ninja",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}", f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
                    f"-DOHOS_SDK_NATIVE={native_sdk}", f"-DHMOS_SDK_NATIVE={sdk / 'sdk/default/hms/native'}",
                    "-DCMAKE_SYSTEM_NAME=OHOS", "-DOHOS_ARCH=arm64-v8a",
                    "-DCMAKE_OHOS_ARCH_ABI=arm64-v8a", "-DOHOS_PLATFORM_LEVEL=26",
                    "-DCMAKE_BUILD_TYPE=RelWithDebInfo", f"-DCMAKE_INSTALL_PREFIX={install}",
                    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON", "-DBUILD_SHARED_LIBS=OFF",
                    "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTING=OFF", "-DENABLE_ZLIB_COMPRESSION=OFF",
                    "-DENABLE_DEBUG_LOGGING=OFF", "-DCRYPTO_BACKEND=OHCRYPTO"], check=True)
    subprocess.run([str(cmake), "--build", str(target), "--parallel"], check=True)
    subprocess.run([str(cmake), "--install", str(target)], check=True)
    result = install / "lib/libssh2.a"
    if result.read_bytes()[:8] != b"!<arch>\n":
        raise ValueError("Native build did not produce a static archive")
    evidence = {"schemaVersion": 2, "fingerprint": fingerprint, "archiveSha256": sha256(result),
                "toolchainFingerprint": toolchain_fingerprint,
                "sourceTreeSha256": hashlib.sha256(
                    json.dumps(inventory, sort_keys=True).encode()).hexdigest(),
                "backendSources": backend, "headers": {
                    name: sha256(install / "include" / name)
                    for name in ["libssh2.h", "libssh2_publickey.h", "libssh2_sftp.h"]}}
    (install / "build-manifest.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"LIBSSH2_OH_NATIVE_BUILD_PASS sha256={evidence['archiveSha256']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-root", type=Path, default=ROOT / "native")
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--install-root", type=Path)
    build(parser.parse_args())
