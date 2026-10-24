"""DLL 动态执行单元测试：_build_command 的 rundll32 / regsvr32 / fail-closed 分支。

使用真实系统 DLL（C:\\Windows\\System32\\version.dll）构造样本，只做命令构造与导出解析，
不执行任何样本。合成最小 PE 用于覆盖“无函数名导出回退 regsvr32”等分支。
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tianti.core.errors import SandboxUnavailable
from tianti.core.model import Sample
from tianti.sandbox import containment

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
VERSION_DLL = SYSTEM32 / "version.dll"


def _minimal_pe(*, dll: bool) -> bytes:
    """构造最小合法 PE（无节区、无导出表），用于测试回退/直启分支。"""
    e_lfanew = 0x40
    size_optional = 0xE0
    data = bytearray(e_lfanew + 4 + 20 + size_optional)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    data[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    coff = e_lfanew + 4
    data[coff : coff + 2] = (0x14C).to_bytes(2, "little")  # i386
    data[coff + 2 : coff + 4] = (0).to_bytes(2, "little")  # NumberOfSections
    data[coff + 16 : coff + 18] = size_optional.to_bytes(2, "little")
    characteristics = 0x0002 | 0x0020 | (0x2000 if dll else 0)
    data[coff + 18 : coff + 20] = characteristics.to_bytes(2, "little")
    optional = coff + 20
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")  # PE32
    # NumberOfRvaAndSizes（optional+92）= 0，导出目录为空
    return bytes(data)


class DllBuildCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="tianti_dll_unit_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _copy_version_dll(self) -> Path:
        if not VERSION_DLL.is_file():
            self.skipTest("系统缺少 version.dll")
        target = self.tmp / "version.dll"
        shutil.copy2(VERSION_DLL, target)
        return target

    def test_version_dll_named_exports(self) -> None:
        target = self._copy_version_dll()
        exports, source = containment._named_dll_exports(target)
        self.assertGreaterEqual(len(exports), 1, "version.dll 应有名字导出")
        self.assertTrue(all(isinstance(name, str) and name for name in exports))
        self.assertTrue("static.pe" in source or "内置" in source, f"解析来源异常: {source}")

    def test_build_command_uses_rundll32_with_comma_export(self) -> None:
        target = self._copy_version_dll()
        sample = Sample.from_path(target)
        spec = containment._build_command(sample, target)
        self.assertIn("rundll32.exe", spec.program.lower())
        self.assertIn(str(target), spec.command_line)
        loader = spec.dll_loader or {}
        self.assertEqual(loader.get("launcher"), "rundll32")
        export = loader.get("export")
        self.assertIsInstance(export, str)
        self.assertTrue(export)
        self.assertIn("," + export, spec.command_line)
        self.assertIn("防火墙", str(loader.get("note", "")))

    def test_dll_detected_by_characteristic_without_suffix(self) -> None:
        target = self._copy_version_dll()
        renamed = self.tmp / "sample.bin"
        renamed.write_bytes(target.read_bytes())
        self.assertTrue(containment._pe_is_dll(renamed))
        sample = Sample.from_path(renamed)
        spec = containment._build_command(sample, renamed)
        self.assertIn("rundll32.exe", spec.program.lower())

    def test_no_named_exports_falls_back_to_regsvr32(self) -> None:
        path = self.tmp / "minimal.dll"
        path.write_bytes(_minimal_pe(dll=True))
        sample = Sample.from_path(path)
        spec = containment._build_command(sample, path)
        self.assertIn("regsvr32.exe", spec.program.lower())
        self.assertIn("/s", spec.command_line)
        loader = spec.dll_loader or {}
        self.assertEqual(loader.get("launcher"), "regsvr32")
        self.assertIsNone(loader.get("export"))

    def test_non_dll_pe_launches_directly(self) -> None:
        path = self.tmp / "minimal.exe"
        path.write_bytes(_minimal_pe(dll=False))
        sample = Sample.from_path(path)
        spec = containment._build_command(sample, path)
        self.assertEqual(spec.program, str(path))
        self.assertIsNone(spec.dll_loader)

    def test_both_launchers_missing_is_fail_closed(self) -> None:
        target = self._copy_version_dll()
        sample = Sample.from_path(target)
        with mock.patch.object(containment, "_system32_tool", return_value=None):
            with self.assertRaises(SandboxUnavailable) as ctx:
                containment._build_command(sample, target)
        self.assertIn("DLL", str(ctx.exception))

    def test_minimal_parser_matches_static_exports(self) -> None:
        target = self._copy_version_dll()
        data = target.read_bytes()
        is_dll, exports = containment._minimal_pe_exports(data)
        self.assertTrue(is_dll)
        static_exports, _ = containment._named_dll_exports(target)
        self.assertEqual(exports, static_exports)

    def test_minimal_parser_tolerates_garbage(self) -> None:
        for blob in (b"", b"MZ", b"not a pe at all", _minimal_pe(dll=True)[:60]):
            with self.subTest(size=len(blob)):
                is_dll, exports = containment._minimal_pe_exports(blob)
                self.assertIsInstance(is_dll, bool)
                self.assertEqual(exports, [])


if __name__ == "__main__":
    unittest.main()
