"""哈希与文件摘要工具（流式，不整文件读入内存）。"""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1024 * 1024


def hash_bytes(data: bytes) -> dict[str, object]:
    """返回 sha256/sha1/md5/size。"""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
    }


def hash_file(path: str | Path) -> dict[str, object]:
    """流式计算文件哈希。"""
    p = Path(path)
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    size = 0
    with p.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "size": size,
    }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    return str(hash_file(path)["sha256"])
