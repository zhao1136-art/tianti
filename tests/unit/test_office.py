"""Office 宏提取测试：OOXML/OLE、CFB 最小解析、fallback、畸形输入与静态集成。"""

from __future__ import annotations

import io
import json
import struct
import unittest
import zipfile

from tianti.static import analyze_bytes, analyze_office, office as office_mod, parse_cfb

CFB_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")


def build_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _cfb_entry(name: str, object_type: int, child: int = 0xFFFFFFFF) -> bytes:
    raw = name.encode("utf-16-le")
    entry = bytearray(128)
    entry[0 : len(raw)] = raw
    struct.pack_into("<H", entry, 64, len(raw) + 2)
    entry[66] = object_type
    entry[67] = 1
    struct.pack_into("<III", entry, 68, 0xFFFFFFFF, 0xFFFFFFFF, child)
    struct.pack_into("<I", entry, 116, 0xFFFFFFFE)
    return bytes(entry)


def build_cfb(stream_names: list[str]) -> bytes:
    """构造最小合法 CFB：1 个 FAT 扇区 + 1 个目录扇区（最多 3 个流）。"""
    assert len(stream_names) <= 3, "测试用 CFB 仅支持 1 个目录扇区（4 项）"
    sector = 512
    header = bytearray(512)
    header[0:8] = CFB_MAGIC
    struct.pack_into("<HHH", header, 24, 0x3E, 3, 0xFFFE)
    struct.pack_into("<HH", header, 30, 9, 6)
    struct.pack_into("<III", header, 40, 0, 1, 1)  # num dir sectors / num FAT / first dir sector
    struct.pack_into("<I", header, 56, 4096)  # mini stream cutoff
    struct.pack_into("<II", header, 60, 0xFFFFFFFE, 0)  # first mini FAT / count
    struct.pack_into("<II", header, 68, 0xFFFFFFFE, 0)  # first DIFAT / count
    struct.pack_into("<I", header, 76, 0)  # DIFAT[0] -> FAT sector 0
    for index in range(1, 109):
        struct.pack_into("<I", header, 76 + 4 * index, 0xFFFFFFFF)

    fat = bytearray(sector)
    fat_values = [0xFFFFFFFD, 0xFFFFFFFE] + [0xFFFFFFFF] * (sector // 4 - 2)
    for index, value in enumerate(fat_values):
        struct.pack_into("<I", fat, 4 * index, value)

    directory = bytearray(sector)
    entries = [_cfb_entry("Root Entry", 5, child=1)]
    for name in stream_names:
        entries.append(_cfb_entry(name, 2))
    for index, entry in enumerate(entries[:4]):
        directory[index * 128 : (index + 1) * 128] = entry
    return bytes(header) + bytes(fat) + bytes(directory)


def macro_stub() -> bytes:
    """无害占位宏字节：只含宏关键字，不含可执行代码。"""
    parts = [
        b"VBA",
        b"\x00" * 16,
        b"Auto" + b"Open",
        b"\x00" * 4,
        b"WScript" + b".Shell",
        b"URLDownload" + b"ToFile",
        b"ADODB" + b".Stream",
    ]
    return b"".join(parts)


class CFBParserTests(unittest.TestCase):
    def test_enumerate_streams(self):
        info = parse_cfb(build_cfb(["VBA", "dir", "_VBA_PROJECT"]))
        self.assertTrue(info.valid)
        self.assertEqual(info.major_version, 3)
        self.assertEqual(info.sector_size, 512)
        self.assertIn("VBA", info.streams)
        self.assertIn("_VBA_PROJECT", info.streams)

    def test_malformed_cfb(self):
        for data in (b"", CFB_MAGIC, CFB_MAGIC + b"\x00" * 20, b"MZ" + b"\x00" * 600):
            info = parse_cfb(data)
            self.assertIsInstance(info.valid, bool)
            self.assertFalse(info.valid)
            self.assertTrue(info.error)


class OOXMLTests(unittest.TestCase):
    def test_docx_with_macro(self):
        stub = macro_stub()
        data = build_zip({"word/document.xml": b"<xml/>", "word/vbaProject.bin": stub})
        result = analyze_office(data, "invoice.docm")
        self.assertEqual(result["container"], "ooxml")
        self.assertEqual(result["kind"], "word")
        self.assertTrue(result["has_macros"])
        self.assertEqual(result["vba_project_size"], len(stub))
        self.assertIn("Auto" + "Open", result["autoexec"])
        self.assertIn("WScript" + ".Shell", result["suspicious_api"])
        self.assertIn("URLDownload" + "ToFile", result["suspicious_api"])
        ids = [item["id"] for item in result["signals"]]
        self.assertIn("office.macro_present", ids)
        self.assertIn("office.macro_autoexec", ids)
        self.assertIn("office.macro_suspicious_api", ids)

    def test_docx_without_macro(self):
        data = build_zip({"word/document.xml": b"<xml/>", "[Content_Types].xml": b"<Types/>"})
        result = analyze_office(data, "plain.docx")
        self.assertEqual(result["container"], "ooxml")
        self.assertFalse(result["has_macros"])
        self.assertEqual(result["vba_project_size"], 0)
        self.assertEqual(result["signals"], [])
        self.assertFalse(any(item["id"].startswith("office.") for item in result["signals"]))

    def test_utf16_keywords(self):
        stub = b"VBA" + (b"Workbook_" + b"Open").decode("ascii").encode("utf-16-le")
        data = build_zip({"xl/vbaProject.bin": stub})
        result = analyze_office(data, "book.xlsm")
        self.assertEqual(result["kind"], "excel")
        self.assertTrue(result["has_macros"])
        self.assertIn("Workbook_" + "Open", result["autoexec"])

    def test_malformed_zip(self):
        result = analyze_office(b"PK\x03\x04" + b"\x00" * 20, "bad.docx")
        self.assertEqual(result["container"], "ooxml")
        self.assertFalse(result["has_macros"])
        self.assertTrue(result["notes"])
        json.dumps(result, ensure_ascii=False)


class OLETests(unittest.TestCase):
    def test_valid_ole_with_vba_streams(self):
        data = build_cfb(["VBA", "dir", "_VBA_PROJECT"])
        result = analyze_office(data, "legacy.doc")
        self.assertEqual(result["container"], "ole")
        self.assertTrue(result["has_macros"])
        self.assertIn("VBA", result["streams"])
        self.assertTrue(result["macro_streams"])
        self.assertFalse(result["heuristic"])
        ids = [item["id"] for item in result["signals"]]
        self.assertIn("office.macro_present", ids)
        self.assertNotIn("office.ole_heuristic", ids)

    def test_ole_without_macro_streams(self):
        data = build_cfb(["WordDocument", "1Table", "Data"])
        result = analyze_office(data, "plain.doc")
        self.assertEqual(result["container"], "ole")
        self.assertFalse(result["has_macros"])
        self.assertTrue(result["heuristic"])
        ids = [item["id"] for item in result["signals"]]
        self.assertIn("office.ole_heuristic", ids)
        self.assertNotIn("office.macro_present", ids)

    def test_ole_raw_fallback(self):
        data = CFB_MAGIC + b"\x00" * 100 + b"VBA" + (b"Auto" + b"Open") + (b"Workbook_" + b"Open")
        result = analyze_office(data, "legacy.xls")
        self.assertEqual(result["container"], "ole")
        self.assertTrue(result["has_macros"])
        self.assertTrue(result["heuristic"])
        self.assertIn("Auto" + "Open", result["autoexec"])
        self.assertIn("Workbook_" + "Open", result["autoexec"])
        ids = [item["id"] for item in result["signals"]]
        self.assertIn("office.macro_present", ids)
        self.assertIn("office.macro_autoexec", ids)
        self.assertIn("office.ole_heuristic", ids)

    def test_unknown_container(self):
        result = analyze_office(b"not an office file", "x.doc")
        self.assertEqual(result["container"], "unknown")
        self.assertFalse(result["has_macros"])
        self.assertTrue(result["notes"])


class StaticIntegrationTests(unittest.TestCase):
    def test_docm_through_base(self):
        data = build_zip({"word/document.xml": b"<xml/>", "word/vbaProject.bin": macro_stub()})
        report = analyze_bytes(data, "payload.docm")
        self.assertIsNotNone(report.office)
        self.assertTrue(report.office["has_macros"])
        self.assertIn("office.macro_present", report.signal_ids)
        self.assertIn("office.macro_autoexec", report.signal_ids)
        self.assertNotIn("archive.macro_container", report.signal_ids)
        self.assertIsNotNone(report.archive)
        payload = report.to_dict()
        json.dumps(payload, ensure_ascii=False)
        self.assertEqual(payload["office"]["container"], "ooxml")

    def test_plain_docx_through_base(self):
        data = build_zip({"word/document.xml": b"<xml/>"})
        report = analyze_bytes(data, "plain.docx")
        self.assertFalse(report.office["has_macros"])
        self.assertFalse(any(item["id"].startswith("office.") for item in report.signals))

    def test_legacy_doc_through_base(self):
        data = build_cfb(["VBA", "dir", "_VBA_PROJECT"])
        report = analyze_bytes(data, "legacy.doc")
        self.assertEqual(report.office["container"], "ole")
        self.assertIn("office.macro_present", report.signal_ids)
        json.dumps(report.to_dict(), ensure_ascii=False)

    def test_malformed_office_does_not_crash(self):
        for data, name in (
            (b"PK\x03\x04broken", "bad.docm"),
            (CFB_MAGIC + b"\x00" * 20, "bad.doc"),
            (b"", "empty.docx"),
            (b"garbage" * 20, "unknown.office"),
        ):
            report = analyze_bytes(data, name)
            payload = report.to_dict()
            json.dumps(payload, ensure_ascii=False)
            self.assertIn("office", payload)

    def test_module_exports(self):
        self.assertTrue(callable(office_mod.analyze_office))
        self.assertTrue(callable(parse_cfb))


if __name__ == "__main__":
    unittest.main()
