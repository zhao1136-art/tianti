"""压缩包一层展开 + 逐条目静态分析 + GUI/HTML 展示测试。"""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tianti.api import pipeline
from tianti.gui import format as fmt
from tianti.report import ScanResult, jsonr, render_html


def minimal_pe64() -> bytes:
    head = bytearray(0x200)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    head[0x40:0x44] = b"PE\x00\x00"
    head[0x44:0x46] = (0x8664).to_bytes(2, "little")
    return bytes(head)


def build_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def make_nested_zip(path: Path) -> bytes:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("inner.exe", minimal_pe64())
    return path.read_bytes()


class ZipExpandTests(unittest.TestCase):
    def _scan(self, entries: dict[str, bytes]) -> tuple[ScanResult, dict]:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            nested = make_nested_zip(root / "nested.zip")
            payload = dict(entries)
            payload["nested.zip"] = nested
            path = build_zip(root / "sample.zip", payload)
            result = pipeline.scan_path(path)
        archive = dict((result.extra or {}).get("archive") or {})
        return result, archive

    def test_entries_are_analyzed_and_aggregated(self) -> None:
        result, archive = self._scan(
            {
                "readme.txt": b"hello yutian analysis",
                "demo.exe": minimal_pe64(),
            }
        )
        self.assertEqual(result.sample.get("type"), "archive/zip")
        self.assertEqual(result.sample_name, "sample.zip")
        self.assertEqual(result.events, [], "压缩包条目只做静态分析，不应产生行为事件")
        self.assertEqual(result.extra.get("input"), "static-only")
        self.assertTrue(archive.get("expanded"))
        self.assertEqual(archive.get("count"), 3)
        self.assertEqual(archive.get("discovered"), 3)
        names = {entry["name"] for entry in archive["entries"]}
        self.assertEqual(names, {"readme.txt", "demo.exe", "nested.zip"})
        nested = [entry for entry in archive["entries"] if entry["name"] == "nested.zip"]
        self.assertTrue(nested and nested[0]["nested"] is True)
        for entry in archive["entries"]:
            self.assertIn(entry["verdict"], ("clean", "suspicious", "malicious"))
            self.assertIsInstance(entry["score"], (int, float))
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertIn("signals", entry)

        rank = {"clean": 0, "suspicious": 1, "malicious": 2}
        expected = max(archive["entries"], key=lambda item: (rank.get(item["verdict"], 0), item["score"]))
        # 顶层归档静态信号（嵌入可执行、嵌套包等）可能比任何条目更严重：聚合取更严重者
        self.assertGreaterEqual(rank.get(result.verdict_name, 0), rank.get(expected["verdict"], 0))
        self.assertGreaterEqual(float(result.verdict.score), float(expected["score"]) - 1e-9)
        joined = " ".join(result.notes)
        self.assertIn("压缩包内共 3 个文件", joined)
        self.assertIn("最严重条目", joined)
        self.assertIn("嵌套压缩包", joined)

        payload = result.to_dict()
        self.assertEqual(payload["schema"], "tianti.result/1")
        restored = ScanResult.from_dict(payload)
        self.assertEqual(restored.to_dict(), payload)
        self.assertEqual(jsonr.loads(jsonr.dumps(result)).to_dict()["schema"], "tianti.result/1")
        json.dumps(payload, ensure_ascii=False)

    def test_path_traversal_is_skipped_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            path = build_zip(
                root / "evil.zip",
                {"../evil.txt": b"escape", "C:/windows/evil.txt": b"drive", "safe.txt": b"ok"},
            )
            result = pipeline.scan_path(path)
        archive = dict(result.extra["archive"])
        skipped_names = {item["name"] for item in archive["skipped"]}
        self.assertIn("../evil.txt", skipped_names)
        self.assertIn("C:/windows/evil.txt", skipped_names)
        self.assertTrue(any("穿越" in item["reason"] for item in archive["skipped"]))
        self.assertEqual([entry["name"] for entry in archive["entries"]], ["safe.txt"])

    def test_entry_limit_truncates(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            path = build_zip(root / "many.zip", {f"f{i}.txt": b"x" for i in range(4)})
            with mock.patch.object(pipeline, "MAX_ARCHIVE_ENTRIES", 2):
                result = pipeline.scan_path(path)
        archive = dict(result.extra["archive"])
        self.assertTrue(archive["truncated"])
        self.assertLessEqual(archive["count"], 2)
        self.assertIn("截断", " ".join(result.notes))

    def test_total_size_limit_truncates(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            path = build_zip(root / "big.zip", {"a.txt": b"a" * 40, "b.txt": b"b" * 40})
            with mock.patch.object(pipeline, "MAX_ARCHIVE_TOTAL_BYTES", 50):
                result = pipeline.scan_path(path)
        archive = dict(result.extra["archive"])
        self.assertTrue(archive["truncated"])
        self.assertLessEqual(archive["count"], 1)
        self.assertIn("上限", " ".join(result.notes))

    def test_single_file_limit_skips(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            path = build_zip(root / "single.zip", {"large.txt": b"a" * 100})
            with mock.patch.object(pipeline, "MAX_ARCHIVE_FILE_BYTES", 10):
                result = pipeline.scan_path(path)
        archive = dict(result.extra["archive"])
        self.assertEqual(archive["count"], 0)
        self.assertTrue(any("单文件超过上限" in item["reason"] for item in archive["skipped"]))

    def test_rar_is_not_expanded(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "fake.rar"
            path.write_bytes(b"Rar!\x1a\x07\x00fake")
            result = pipeline.scan_path(path)
        archive = dict(result.extra["archive"])
        self.assertFalse(archive["expanded"])
        self.assertEqual(archive["format"], "archive/rar")
        self.assertEqual(archive["entries"], [])
        self.assertTrue(any("无解压能力" in note for note in result.notes))

    def test_expand_can_be_disabled(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = build_zip(Path(tmp) / "sample.zip", {"readme.txt": b"hello"})
            result = pipeline.scan_path(path, expand_archives=False)
        archive = dict(result.extra["archive"])
        self.assertFalse(archive["expanded"])
        self.assertEqual(archive["entries"], [])
        self.assertEqual(result.events, [])
        self.assertTrue(any("--no-archive-expand" in note for note in result.notes))

    def test_html_report_contains_archive_section(self) -> None:
        result, _ = self._scan({"readme.txt": b"hello", "demo.exe": minimal_pe64()})
        html = render_html(result)
        self.assertIn("压缩包内容", html)
        self.assertIn("readme.txt", html)
        self.assertIn("demo.exe", html)
        self.assertNotIn("<script", html)


class ArchiveFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            path = build_zip(
                root / "sample.zip",
                {"readme.txt": b"hello", "demo.exe": minimal_pe64(), "data.bin": b"1234"},
            )
            cls.result = pipeline.scan_path(path)

    def test_archive_rows(self) -> None:
        rows = fmt.archive_rows(self.result)
        self.assertEqual(len(rows), 3)
        self.assertEqual({row["name"] for row in rows}, {"readme.txt", "demo.exe", "data.bin"})
        self.assertTrue(all(row["verdict_label"] for row in rows))

    def test_summary_text_has_archive_table(self) -> None:
        text = fmt.summary_text(self.result)
        self.assertIn("【压缩包内容】", text)
        self.assertIn("readme.txt", text)
        self.assertIn("已静态分析 3 个", text)

    def test_summary_text_truncates_entries(self) -> None:
        extra = dict(self.result.extra or {})
        archive = dict(extra.get("archive") or {})
        archive["entries"] = [
            {"name": f"item{i}.txt", "size": i, "type": "text", "verdict": "clean", "score": 0.0}
            for i in range(60)
        ]
        extra["archive"] = archive
        result = ScanResult.from_dict({**self.result.to_dict(), "extra": extra})
        text = fmt.summary_text(result)
        self.assertIn("仅显示前 50 条", text)

    def test_zip_entry_count_helper(self) -> None:
        try:
            from tianti.gui.app import _zip_entry_count
        except ImportError:
            self.skipTest("tkinter 不可用")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            path = build_zip(root / "count.zip", {"a.txt": b"a", "b.txt": b"b"})
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("dir/", b"")
            self.assertEqual(_zip_entry_count(path), 2)
            self.assertEqual(_zip_entry_count(root / "missing.zip"), 0)


if __name__ == "__main__":
    unittest.main()


class OfficeContainerRoutingTests(unittest.TestCase):
    def test_office_container_is_not_expanded_as_archive(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "demo.docm"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("word/vbaProject.bin", b"VBA" + b"\x00" * 64)
            result = pipeline.scan_path(path)
        self.assertIsNone((result.extra or {}).get("archive"), "Office 容器不应走普通 zip 展开")
        office = result.static.get("office") or {}
        self.assertEqual(office.get("container"), "ooxml")
        self.assertTrue(office.get("has_macros"))
        self.assertIn("office.macro_present", [item["id"] for item in (result.static.get("signals") or [])])
        self.assertIn(result.verdict_name, ("suspicious", "malicious"))


class MalformedZipTests(unittest.TestCase):
    """损坏/改名/截断的 .zip 不能抛异常，要回退原始数据静态分析。"""

    def _scan_bytes(self, name: str, payload: bytes):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / name
            path.write_bytes(payload)
            return pipeline.scan_path(path)

    def test_garbage_zip_falls_back(self) -> None:
        result = self._scan_bytes("garbage.zip", b"not a zip file at all")
        archive = dict((result.extra or {}).get("archive") or {})
        self.assertTrue(archive.get("malformed"))
        self.assertFalse(archive.get("expanded"))
        self.assertEqual(result.extra.get("input"), "static-only")
        ids = {item["id"] for item in (result.static.get("signals") or [])}
        self.assertIn("archive.malformed", ids)
        self.assertTrue(any("不是有效 ZIP" in note for note in result.notes))

    def test_truncated_zip_falls_back(self) -> None:
        import io

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "hello" * 100)
        payload = buffer.getvalue()
        result = self._scan_bytes("truncated.zip", payload[: len(payload) // 2])
        archive = dict((result.extra or {}).get("archive") or {})
        self.assertTrue(archive.get("malformed"))
        self.assertEqual(result.events, [])

    def test_empty_zip_falls_back(self) -> None:
        result = self._scan_bytes("empty.zip", b"")
        archive = dict((result.extra or {}).get("archive") or {})
        self.assertTrue(archive.get("malformed"))
        self.assertTrue(any("样本为空" in note or "不是有效 ZIP" in note for note in result.notes))

    def test_embedded_pe_in_fake_zip_detected(self) -> None:
        payload = b"\x00" * 1024 + minimal_pe64()
        result = self._scan_bytes("fake.zip", payload)
        ids = {item["id"] for item in (result.static.get("signals") or [])}
        self.assertIn("data.embedded_pe", ids)
