"""校验原生构建输入，只将公开接口与 libssh2 静态库暂存到独立 HAR 工程。"""

import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import argparse
import hashlib
import tarfile
import re

from native_inputs import read_inputs, sha256


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "library"


def prepare(native: Path) -> None:
    """锁文件必须完整覆盖补丁队列，避免把来源不明的依赖装入 HAR。"""
    lock, locked, sources, fingerprint = read_inputs(ROOT / "native")
    native = native.resolve(strict=True)
    archive = native / "lib/libssh2.a"
    if archive.read_bytes()[:8] != b"!<arch>\n":
        raise ValueError("Invalid libssh2 static archive")
    headers = ["libssh2.h", "libssh2_publickey.h", "libssh2_sftp.h"]
    for name in headers:
        if not (native / "include" / name).is_file():
            raise ValueError(f"Missing public header: {name}")
    # 发布输入必须来自当前构建脚本；缺少清单时拒绝装配。
    evidence_path = native / "build-manifest.json"
    if not evidence_path.is_file() or evidence_path.is_symlink():
        raise ValueError("build-manifest.json is required; rebuild native inputs first")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if (evidence.get("schemaVersion") != 2 or evidence.get("fingerprint") != fingerprint or
            evidence.get("archiveSha256") != sha256(archive) or evidence.get("backendSources") != sources or
            not re.fullmatch(r"[0-9a-f]{64}", evidence.get("sourceTreeSha256", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", evidence.get("toolchainFingerprint", ""))):
        raise ValueError("Native build evidence differs from current source inputs")
    if any(evidence.get("headers", {}).get(name) != sha256(native / "include" / name) for name in headers):
        raise ValueError("Native build evidence differs from public headers")

    include = MODULE / "include"
    libraries = MODULE / "libs/arm64-v8a"
    licenses = MODULE / "licenses"
    for directory in [include, libraries, licenses]:
        directory.mkdir(parents=True, exist_ok=True)
    for name in headers:
        shutil.copyfile(native / "include" / name, include / name)
    shutil.copyfile(archive, libraries / "libssh2.a")
    # Hvigor 自动收集根 LICENSE；将两份许可及归属声明合并，避免遗漏未收集的目录。
    apache = (ROOT / "LICENSE").read_text(encoding="utf-8")
    bsd = (ROOT / "native/licenses/libssh2-COPYING").read_text(encoding="utf-8")
    notice = (MODULE / "NOTICE").read_text(encoding="utf-8")
    (MODULE / "LICENSE").write_text(
        notice + "\n\n=== Apache-2.0 ===\n\n" + apache + "\n\n=== libssh2 BSD-3-Clause ===\n\n" + bsd,
        encoding="utf-8")
    shutil.copyfile(ROOT / "native/licenses/libssh2-COPYING", licenses / "libssh2-COPYING")

    # SDK 路径仅从环境变量读取；剥离 DWARF，保留静态链接需要的符号与重定位。
    import os
    sdk = os.environ.get("DEVECO_CLI_CLT_PATH")
    if not sdk:
        raise ValueError("DEVECO_CLI_CLT_PATH is required")
    suffix = ".exe" if os.name == "nt" else ""
    strip = Path(sdk) / f"sdk/default/openharmony/native/llvm/bin/llvm-strip{suffix}"
    subprocess.run([str(strip), "--strip-debug", str(libraries / "libssh2.a")], check=True)

    manifest = {
        "name": "libssh2-oh", "version": "0.1.1",
        "repository": "https://github.com/DreamistW/libssh2-oh.git",
        "inputFingerprint": fingerprint,
        "sourceTreeSha256": evidence["sourceTreeSha256"],
        "toolchainFingerprint": evidence["toolchainFingerprint"],
        "upstream": lock["libssh2"]["archive"], "upstreamVersion": lock["libssh2"]["version"],
        "platform": {"os": "HarmonyOS", "api": 26, "abi": "arm64-v8a", "deviceType": "2in1"},
        "cryptoBackend": "OHCRYPTO", "systemLibraries": ["libohcrypto.so", "libhilog_ndk.z.so"],
        "patches": [{"file": patch["file"], "sha256": patch["sha256"]} for patch in locked],
        "backendSources": sources, "inputArchiveSha256": sha256(archive),
        "archiveSha256": sha256(libraries / "libssh2.a"),
        "headers": {name: sha256(include / name) for name in headers},
    }
    (include / "libssh2-oh-manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"PREPARE_PASS patches={len(locked)} headers={len(headers)} abi=arm64-v8a")


def audit_har(path: Path) -> None:
    """只读取归档成员；拒绝路径穿越、额外运行库和本机私有配置。"""
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or name.parts[0] != "package":
                raise ValueError(f"Unexpected archive path: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError("Archive links are not allowed")
        files = {member.name: archive.extractfile(member).read()
                 for member in members if member.isfile()}
    required = ["oh-package.json5", "README.md", "CHANGELOG.md", "LICENSE",
                "Index.ets", "include/libssh2.h", "include/libssh2_publickey.h",
                "include/libssh2_sftp.h", "include/libssh2-oh.cmake",
                "include/libssh2-oh-manifest.json", "libs/arm64-v8a/libssh2.a",
                "src/main/module.json"]
    allowed = {"package/" + name for name in required} | {
        "package/BuildProfile.ets", "package/NOTICE", "package/build-profile.json5",
        "package/hvigorfile.ts", "package/licenses/libssh2-COPYING"
    }
    if set(files) - allowed:
        raise ValueError("Unexpected files in the produced HAR")
    for name in required:
        if not files.get("package/" + name):
            raise ValueError(f"Missing or empty HAR file: {name}")
    package = json.loads(files["package/oh-package.json5"])
    if package["name"] != "libssh2-oh" or package["version"] != "0.1.1":
        raise ValueError("Incorrect package identity")
    if package.get("repository") != "https://github.com/DreamistW/libssh2-oh.git":
        raise ValueError("Incorrect public source repository")
    if "ohpm install libssh2-oh" not in files["package/README.md"].decode():
        raise ValueError("README is missing the installation command")
    if package["version"] not in files["package/CHANGELOG.md"].decode():
        raise ValueError("CHANGELOG is missing the package version")
    license_text = files["package/LICENSE"].decode()
    if "Apache-2.0" not in license_text or "BSD-3-Clause" not in license_text or "Sara Golemon" not in license_text:
        raise ValueError("Missing original notices or third-party license")
    manifest = json.loads(files["package/include/libssh2-oh-manifest.json"])
    native = files["package/libs/arm64-v8a/libssh2.a"]
    if hashlib.sha256(native).hexdigest() != manifest["archiveSha256"]:
        raise ValueError("Native archive hash mismatch")
    for name, expected in manifest["headers"].items():
        if hashlib.sha256(files["package/include/" + name]).hexdigest() != expected:
            raise ValueError(f"Public header hash mismatch: {name}")
    for name, data in files.items():
        if name.endswith((".so", ".exe", ".p12", ".p7b", ".cer", ".keystore")):
            raise ValueError(f"Forbidden distributed file: {name}")
        # 协议解析器本身含 PEM 标签；只将完整的私钥数据块判为秘密。
        if re.search(rb"/home/" rb"[u]ser/|[A-Za-z]:[\\/]Users[\\/]|publish_id\s*=", data) or re.search(
                rb"-----BEGIN (?:RSA |OPENSSH |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n"
                rb"[A-Za-z0-9+/=\r\n]{32,}-----END", data):
            raise ValueError(f"Private path or credential material found in: {name}")
    print(f"HAR_AUDIT_PASS files={len(files)} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-install", type=Path, default=ROOT / "native/prebuilt/arm64-v8a")
    parser.add_argument("--verify-har", type=Path, help="Verify the produced package before accepting the build")
    args = parser.parse_args()
    audit_har(args.verify_har) if args.verify_har else prepare(args.native_install)
