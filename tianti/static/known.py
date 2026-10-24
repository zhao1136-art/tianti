"""已知测试文件识别（EICAR 标准反病毒测试串）。

只做静态识别，绝不执行。EICAR 是官方公开的无害测试串，
用于验证扫描器「能识别、不执行、不误判成真实恶意样本」。
"""

from __future__ import annotations

from .util import signal

# 标准 68 字节 EICAR 测试串。注意：必须运行时拼接，不要写成完整字面量——
# 本机装有火绒，完整特征串会让源码/字节码被实时防护当成 EICAR 直接隔离（误报）。
_EICAR_PARTS = (
    b"X5O!P%@AP[4",
    b"\\",
    b"PZX54(P^)7CC)7}$EICAR",
    b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
)
EICAR = b"".join(_EICAR_PARTS)
EICAR_MARKER = b"".join((b"EICAR-STANDARD", b"-ANTIVIRUS-TEST-FILE"))

# 其它公开、无害的测试标记（识别为「测试文件」而非恶意）
KNOWN_TEST_MARKERS: tuple[tuple[str, bytes], ...] = (
    ("eicar", EICAR_MARKER),
)


def check_known_test_file(data: bytes, *, limit: int = 1024 * 1024) -> dict[str, object] | None:
    """命中已知测试文件则返回 {name, signal}，否则 None。不执行任何内容。"""
    if not data:
        return None
    head = data[:limit]
    for name, marker in KNOWN_TEST_MARKERS:
        if marker in head:
            return {
                "name": name,
                "signal": signal(
                    f"known_test_file.{name}",
                    "high",
                    f"已知测试文件（{name}，公开无害串），仅静态识别、不执行",
                    score=0.0,
                ),
            }
    return None
