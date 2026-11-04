"""共享原生输入校验，保证源码构建和 HAR 打包使用同一补丁及后端版本。"""

import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    """以流方式计算文件哈希，不记录开发机路径。"""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read_inputs(native_root: Path) -> tuple[dict, list[dict], dict[str, str], str]:
    """拒绝漏锁、重复、越界或内容不符的补丁，返回内容寻址的构建身份。"""
    lock = json.loads((native_root / "dependencies.lock.json").read_text(encoding="utf-8"))
    dependency = lock["libssh2"]
    patches = native_root / "libssh2/patches"
    series = [line.strip() for line in (patches / "series").read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.lstrip().startswith("#")]
    locked = dependency["securityPatches"] + dependency["projectPatches"]
    if series != [patch["file"] for patch in locked] or len(series) != len(set(series)):
        raise ValueError("Patch series differs from the complete dependency lock")
    for patch in locked:
        name = patch["file"]
        if Path(name).name != name or "/" in name or "\\" in name:
            raise ValueError("Invalid patch name")
        if sha256(patches / name) != patch["sha256"]:
            raise ValueError(f"Patch checksum mismatch: {name}")
    backend = {name: sha256(native_root / "libssh2/ohcrypto" / name)
               for name in ["ohcrypto.c", "ohcrypto.h"]}
    identity = {"archive": dependency["archive"], "patches": locked,
                "backend": backend, "build": dependency["ohosBuild"]}
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return lock, locked, backend, fingerprint


def source_inventory(source: Path) -> dict[str, str]:
    """记录实际补丁后源码；拒绝链接，清单自身不参与递归摘要。"""
    result = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("Links are not allowed in native source caches")
        if path.is_file() and path != source / ".libssh2-oh-inputs.json":
            result[path.relative_to(source).as_posix()] = sha256(path)
    return result


def validate_source_cache(source: Path, fingerprint: str) -> dict[str, str]:
    """输入身份与已展开源码必须同时匹配，修改或增加缓存文件都会失败。"""
    if source.is_symlink() or source.resolve() != source.absolute():
        raise ValueError("Native source cache must not be a directory link")
    marker = source / ".libssh2-oh-inputs.json"
    if not marker.is_file() or marker.is_symlink():
        raise ValueError("Refusing an unrecognized native source cache")
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    actual = source_inventory(source)
    if (manifest.get("schemaVersion") != 2 or manifest.get("fingerprint") != fingerprint or
            not actual or manifest.get("files") != actual):
        raise ValueError("Native source cache content differs from its integrity manifest")
    return actual
