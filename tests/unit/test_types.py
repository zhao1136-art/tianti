"""更多文件类型识别与 .dat 等数据文件静态扫描测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tianti.api import pipeline
from tianti.core.model import SampleType, guess_type
from tianti.static import analyze_bytes


def _pe32_head() -> bytes:
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"PE\x00\x00"
    data[0x44:0x46] = (0x14C).to_bytes(2, "little")
    return bytes(data)


class TypeDetectionTests(unittest.TestCase):
    def test_dat_with_pe_magic_is_pe(self) -> None:
        self.assertEqual(guess_type("payload.dat", _pe32_head()), SampleType.PE32)

    def test_dat_without_magic_is_data(self) -> None:
        self.assertEqual(guess_type("cache.dat", b"\x00\x01\x02random-bytes" * 10), SampleType.DATA)

    def test_pdf(self) -> None:
        self.assertEqual(guess_type("manual.pdf", b"%PDF-1.7\n..."), SampleType.DOCUMENT_PDF)

    def test_iso_image(self) -> None:
        head = bytearray(0x9000)
        head[0x8001:0x8006] = b"CD001"
        self.assertEqual(guess_type("disc.iso", bytes(head)), SampleType.DISK_IMAGE)

    def test_lnk(self) -> None:
        head = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 64
        self.assertEqual(guess_type("shortcut.lnk", head), SampleType.SHORTCUT)

    def test_eml(self) -> None:
        self.assertEqual(guess_type("mail.eml", b"From: a@b\r\nSubject: hi\r\n\r\nbody"), SampleType.EMAIL)

    def test_python(self) -> None:
        self.assertEqual(guess_type("tool.py", b"print('hi')\n"), SampleType.SCRIPT_PYTHON)

    def test_java_class(self) -> None:
        self.assertEqual(guess_type("Main.class", b"\xca\xfe\xba\xbe" + b"\x00" * 64), SampleType.CODE_JAVA)

    def test_msi(self) -> None:
        cfb = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 128
        self.assertEqual(guess_type("setup.msi", cfb), SampleType.PACKAGE_MSI)

    def test_cab(self) -> None:
        self.assertEqual(guess_type("driver.cab", b"MSCF" + b"\x00" * 64), SampleType.ARCHIVE_CAB)

    def test_gzip_and_tar(self) -> None:
        self.assertEqual(guess_type("a.gz", b"\x1f\x8b" + b"\x00" * 32), SampleType.ARCHIVE_GZIP)
        head = bytearray(512)
        head[257:262] = b"ustar"
        self.assertEqual(guess_type("a.tar", bytes(head)), SampleType.ARCHIVE_TAR)

    def test_elf(self) -> None:
        self.assertEqual(guess_type("linux.bin", b"\x7fELF" + b"\x00" * 64), SampleType.ELF)


class DataFileAnalysisTests(unittest.TestCase):
    def test_dat_with_embedded_pe_signal(self) -> None:
        payload = b"\x00" * 1024 + _pe32_head()
        report = analyze_bytes(payload, "cache.dat")
        self.assertEqual(report.type, SampleType.DATA.value)
        ids = {item["id"] for item in report.signals}
        self.assertIn("data.embedded_pe", ids)

    def test_dat_with_script_marker(self) -> None:
        payload = b"config\x00" + b"powershell -enc AAAA" + b"\x00" * 32
        report = analyze_bytes(payload, "config.dat")
        ids = {item["id"] for item in report.signals}
        self.assertIn("data.script_marker", ids)

    def test_empty_data_file(self) -> None:
        report = analyze_bytes(b"", "empty.dat")
        ids = {item["id"] for item in report.signals}
        self.assertIn("sample.empty", ids)

    def test_scan_path_dat_is_static_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.dat"
            path.write_bytes(b"\x00" * 512 + _pe32_head())
            result = pipeline.scan_path(path)
        self.assertEqual(result.extra.get("input"), "static-only")
        self.assertEqual(result.events, [])
        ids = {item["id"] for item in (result.static.get("signals") or [])}
        self.assertIn("data.embedded_pe", ids)
