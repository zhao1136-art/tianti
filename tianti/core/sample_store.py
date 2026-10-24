"""样本库：混淆存储 + 元信息，禁止直接执行。

说明：标准库没有 AES，这里用 SHA256 派生密钥流做 XOR 混淆（只防误执行/误扫描，
不宣称加密强度），文件后缀改为 .obj，并建议外层用 ACL 禁止执行（M1 补）。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .errors import SampleError
from .hashing import hash_bytes
from .model import Sample, SampleType, guess_type


def _keystream(sha256: str) -> bytes:
    return hashlib.sha256((sha256 + "tianti-store").encode("utf-8")).digest()


def _xor(data: bytes, sha256: str) -> bytes:
    key = _keystream(sha256)
    if not key:
        return data
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


class SampleStore:
    OBJ_SUFFIX = ".obj"
    META_SUFFIX = ".json"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"

    def _bucket(self, sha256: str) -> Path:
        return self.objects / sha256[:2]

    def _obj_path(self, sha256: str) -> Path:
        return self._bucket(sha256) / f"{sha256}{self.OBJ_SUFFIX}"

    def _meta_path(self, sha256: str) -> Path:
        return self._bucket(sha256) / f"{sha256}{self.META_SUFFIX}"

    def has(self, sha256: str) -> bool:
        return self._obj_path(sha256).exists()

    def put_bytes(
        self,
        data: bytes,
        name: str,
        *,
        sample_type: SampleType | None = None,
        origin: str = "api",
    ) -> Sample:
        info = hash_bytes(data)
        sha256 = str(info["sha256"])
        sample = Sample(
            name=name,
            sha256=sha256,
            size=len(data),
            type=sample_type or guess_type(name, data[:65536]),
            sha1=str(info["sha1"]),
            md5=str(info["md5"]),
            origin=origin,
        )
        self._obj_path(sha256).parent.mkdir(parents=True, exist_ok=True)
        if not self._obj_path(sha256).exists():
            self._obj_path(sha256).write_bytes(_xor(data, sha256))
        self._meta_path(sha256).write_text(
            json.dumps(sample.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return sample

    def put_file(self, path: str | Path, *, origin: str = "file") -> Sample:
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as exc:
            raise SampleError(f"读取样本失败: {p}: {exc}", path=str(p)) from exc
        return self.put_bytes(data, p.name, origin=origin)

    def read(self, sha256: str) -> bytes:
        path = self._obj_path(sha256)
        if not path.exists():
            raise SampleError(f"样本不存在: {sha256}", sha256=sha256)
        return _xor(path.read_bytes(), sha256)

    def meta(self, sha256: str) -> dict:
        path = self._meta_path(sha256)
        if not path.exists():
            raise SampleError(f"样本元信息不存在: {sha256}", sha256=sha256)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise SampleError(f"样本元信息损坏: {sha256}", sha256=sha256) from exc

    def sample(self, sha256: str) -> Sample:
        return Sample.from_dict(self.meta(sha256))
