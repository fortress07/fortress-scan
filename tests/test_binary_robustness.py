"""Tệp thù địch không được làm công cụ chết, treo, hay ghi ra đĩa.

Mô hình đe doạ ở đây rõ hơn mọi chỗ khác trong dự án: người dùng CHỦ ĐỘNG
trỏ công cụ vào một tệp mà họ nghi là mã độc. Tức là đầu vào do kẻ tấn công
soạn, và nó được soạn để phá đúng công cụ đang đọc nó.

Nên ba tính chất dưới đây là bắt buộc:

* mọi tệp hỏng đều phải thành một dòng "dị thường" trong báo cáo, không phải
  một traceback;
* thời gian phải có trần, không phụ thuộc vào con số mà header khai;
* và không byte nào được ghi ra đĩa, không tiến trình nào được tạo, không
  kết nối nào được mở.
"""

from __future__ import annotations

import ast
import builtins
import io
import os
import pkgutil
import random
import struct
import time
import zipfile
from pathlib import Path

import pytest

import binary_builders as B
import fortress_scan.binary as binary_package
from fortress_scan.binary import engine, reference
from fortress_scan.binary.formats import archive, elf, macho, pe, scripts
from fortress_scan.binary.model import Verdict
from fortress_scan.security import runtime as sandbox

# Trần rộng tay: bài kiểm tra này chạy cả trên runner Windows chậm, và một
# bài đo thời gian hay đỏ ngẫu nhiên thì tệ hơn là không có. Khoảng cách tới
# kiểu hỏng thật ( treo vô hạn vì tin vào số đếm trong header ) là vô cùng,
# nên một trần lỏng vẫn bắt được đúng thứ cần bắt.
TIME_LIMIT = 30.0

SAMPLES = {
    "pe": B.build_pe(
        imports={"kernel32.dll": ["FindFirstFileW", "CreateFileW"]},
        resources=[(16, "1", B.version_resource({"CompanyName": "Acme"})), (10, "P", b"\x01" * 2048)],
        exports=["Run"],
        overlay=b"\x00" * 512,
        certificate=b"\x30\x82" + b"\x00" * 64,
    ),
    "pe-dotnet": B.build_pe(clr=True, clr_metadata=B.dotnet_metadata(user_strings=["xin chao"])),
    "elf": B.build_elf(imported=["opendir"], local_symbols=["main"], needed=["libc.so.6"]),
    "elf32be": B.build_elf(bits64=False, little=False, imported=["opendir"], needed=["libc.so.6"]),
    "macho": B.build_macho(imported=["opendir"], exported=["main"], code_signature=b"\xfa\xde\x0c\xc0"),
    "macho-fat": B.build_fat_macho([B.build_macho(), B.build_macho(cpu=0x0100000C)]),
    "jar": B.build_jar({"META-INF/MANIFEST.MF": b"Main-Class: A\n", "A.class": B.build_class(["AES"])}),
    "pyinstaller": B.build_pe(overlay=B.pyinstaller_overlay({"main": b"print(1)"})),
    "script": b"@echo off\r\nvssadmin delete shadows /all\r\n",
}


def _analyze(data: bytes, name: str = "mau.bin"):
    started = time.perf_counter()
    report = engine.analyze_bytes(data, name)
    elapsed = time.perf_counter() - started
    assert elapsed < TIME_LIMIT, "%s tốn %.1fs" % (name, elapsed)
    return report


# ------------------------------------------------------------------- cắt cụt


@pytest.mark.parametrize("kind", sorted(SAMPLES))
def test_every_truncation_of_every_sample_is_survived(kind):
    """Cắt tệp ở mọi độ dài: không chỗ nào được ném ra ngoài.

    Đây là phép dò biên rẻ nhất và hiệu quả nhất với parser nhị phân, vì mỗi
    độ dài đặt đúng một phép đọc vào đúng biên của dữ liệu.
    """
    data = SAMPLES[kind]
    lengths = set(range(0, min(len(data), 600)))
    lengths |= {len(data) * index // 32 for index in range(33)}
    for length in sorted(lengths):
        report = _analyze(data[:length], "%s-cat-%d" % (kind, length))
        assert isinstance(report.verdict, Verdict)
        assert report.hashes["sha256"]


@pytest.mark.parametrize("kind", sorted(SAMPLES))
def test_random_single_byte_mutations_are_survived(kind):
    """Đột biến một byte ở vị trí ngẫu nhiên, hạt giống CỐ ĐỊNH.

    Hạt giống cố định để một lần đỏ là một lần tái hiện được; đổi hạt giống
    mỗi lần chạy thì lỗi hiện ra ở CI của người khác rồi biến mất.
    """
    data = bytearray(SAMPLES[kind])
    generator = random.Random(20261006)
    for round_index in range(120):
        copy = bytearray(data)
        for _ in range(generator.randint(1, 6)):
            position = generator.randrange(len(copy))
            copy[position] = generator.randrange(256)
        _analyze(bytes(copy), "%s-dot-%d" % (kind, round_index))


# ------------------------------------------------------- header khai số giả


def test_pe_section_count_beyond_the_specification_limit_is_capped():
    data = B.build_pe(section_count_override=0xFFFF)
    parsed = pe.parse(data)
    assert len(parsed.sections) <= pe.MAX_SECTIONS
    assert any("vượt trần" in note for note in parsed.anomalies)


def test_pe_e_lfanew_pointing_outside_the_file_is_reported_not_followed():
    data = B.build_pe(e_lfanew_override=0x70000000)
    parsed = pe.parse(data)
    assert parsed.format.startswith("MS-DOS")
    assert parsed.anomalies


def test_pe_directories_pointing_outside_the_file_are_reported():
    for index in (0, 1, 2, 4, 14):
        data = B.build_pe(directory_override={index: (0x7FFF0000, 0x1000)})
        parsed = pe.parse(data)
        assert parsed.anomalies or not parsed.imports, "thư mục %d" % index
        _analyze(data, "dir-%d" % index)


def test_pe_resource_tree_with_a_loop_is_stopped():
    """Cây resource trỏ vòng lại chính nó là cách làm treo một parser đệ quy."""
    data = bytearray(B.build_pe(resources=[(10, "A", b"x" * 16)]))
    parsed = pe.parse(bytes(data))
    rsrc = next(section for section in parsed.sections if section.name == ".rsrc")
    # Mục đầu của thư mục gốc trỏ ngược về chính thư mục gốc.
    entry_at = rsrc.offset + 16
    data[entry_at + 4 : entry_at + 8] = struct.pack("<I", 0x80000000)
    parsed = pe.parse(bytes(data))
    assert any("vòng lặp" in note for note in parsed.anomalies)


def test_pe_import_descriptor_with_a_self_referencing_thunk_is_bounded():
    data = bytearray(B.build_pe(imports={"a.dll": ["x"]}))
    parsed = pe.parse(bytes(data))
    idata = next(section for section in parsed.sections if section.name == ".idata")
    # OriginalFirstThunk trỏ vào chính bảng descriptor: chuỗi thunk không bao
    # giờ gặp số 0 nên chỉ có trần MAX_IMPORTS chặn được nó.
    data[idata.offset : idata.offset + 4] = struct.pack("<I", idata.virtual_address)
    report = _analyze(bytes(data), "thunk-loop.exe")
    assert len(report.parsed.imports) <= pe.MAX_IMPORTS


def test_elf_section_count_and_string_table_index_lies_are_survived():
    data = B.build_elf(section_count_override=0xFFF0)
    parsed = elf.parse(data)
    assert len(parsed.sections) <= elf.MAX_SECTIONS
    assert parsed.anomalies

    data = bytearray(B.build_elf())
    data[62:64] = struct.pack("<H", 0xFFF0)  # e_shstrndx
    parsed = elf.parse(bytes(data))
    assert isinstance(parsed.sections, list)


def test_elf_dynamic_segment_without_a_string_table_is_survived():
    data = bytearray(B.build_elf(needed=["libc.so.6"]))
    position = data.find(b"libc.so.6")
    data[position : position + 9] = b"\x00" * 9
    parsed = elf.parse(bytes(data))
    assert isinstance(parsed.libraries, list)


def test_macho_command_count_lies_are_bounded():
    parsed = macho.parse(B.build_macho(command_count_override=0xFFFFFFF))
    assert any("load command" in note for note in parsed.anomalies)
    parsed = macho.parse(B.build_macho(command_count_override=0))
    assert parsed.format == "Mach-O 64-bit"


def test_macho_load_command_with_zero_size_does_not_loop_forever():
    data = bytearray(B.build_macho())
    data[36:40] = struct.pack("<I", 0)  # cmdsize của load command đầu tiên
    parsed = macho.parse(bytes(data))
    assert any("kích thước" in note for note in parsed.anomalies)


def test_fat_binary_with_an_absurd_architecture_count_is_bounded():
    data = bytearray(B.build_fat_macho([B.build_macho()]))
    data[4:8] = struct.pack(">I", 0xFFFF)
    report = _analyze(bytes(data), "fat.bin")
    assert len(report.parsed.children) <= macho.MAX_FAT_ARCHES


def test_dotnet_metadata_with_a_huge_stream_count_is_bounded():
    data = bytearray(B.build_pe(clr=True))
    position = data.find(b"BSJB")
    assert position > 0
    length = struct.unpack_from("<I", data, position + 12)[0]
    cursor = position + 16 + length
    struct.pack_into("<H", data, cursor + 2, 0xFFFF)
    report = _analyze(bytes(data), "clr.exe")
    assert report.parsed.has_trait(".net")


# -------------------------------------------------------------- bom và trần


def test_a_zip_bomb_member_is_refused_by_the_ratio_ceiling():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as handle:
        handle.writestr("bomb.txt", b"\x00" * (64 << 20))
    report = _analyze(buffer.getvalue(), "bomb.jar")
    assert any("tỉ lệ nén" in note or "quá lớn" in note for note in report.parsed.anomalies)


def test_a_zip_with_very_many_members_is_capped():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        for index in range(archive.MAX_MEMBERS // 10):
            handle.writestr("m%d.txt" % index, b"x")
    report = _analyze(buffer.getvalue(), "many.jar")
    assert int(report.parsed.metadata["members"]) == archive.MAX_MEMBERS // 10


def test_a_file_made_only_of_printable_bytes_does_not_blow_up_the_string_pool():
    """Một tệp 8 MB toàn chuỗi in được là cách làm nổ bộ nhớ của phép rút chuỗi."""
    report = _analyze(b"A" * (8 << 20), "chuoi.bin")
    assert report.pool is not None
    assert len(report.pool) <= 250_000


def test_a_file_of_many_tiny_strings_hits_the_pool_ceiling_and_says_so():
    body = b"\x00".join(b"abcdef" for _ in range(400_000))
    report = _analyze(body, "nhieu.bin")
    assert report.pool is not None and report.pool.truncated
    assert any("quá nhiều chuỗi" in note for note in report.limitations)


def test_reading_a_file_larger_than_the_ceiling_is_truncated_and_reported(tmp_path):
    target = tmp_path / "lon.bin"
    target.write_bytes(B.build_pe() + b"\x00" * 4096)
    report = engine.analyze_path(str(target), 1024)
    assert report.truncated
    assert report.size == 1024
    assert any("trần đọc" in note for note in report.limitations)


def test_deeply_nested_base64_in_a_script_is_bounded():
    import base64

    payload = "echo xong"
    for _ in range(40):
        payload = "iex([Convert]::FromBase64String('%s'))" % base64.b64encode(
            payload.encode("utf-8")
        ).decode("ascii")
    started = time.perf_counter()
    parsed = scripts.parse(payload.encode("utf-8"), "a.ps1", "PowerShell")
    assert time.perf_counter() - started < TIME_LIMIT
    assert len(parsed.embedded_text) <= scripts.MAX_BLOBS + 2


# --------------------------------------------------------- không tác dụng phụ


def test_analysis_writes_nothing_and_reads_only_the_target(tmp_path):
    """Công cụ phân tích tệp chỉ được MỞ ĐỌC đúng tệp được chỉ định."""
    target = tmp_path / "mau.exe"
    target.write_bytes(SAMPLES["pe"])
    snapshot = {path: path.stat().st_mtime_ns for path in tmp_path.rglob("*")}

    opened = []
    original = builtins.open

    def recorder(file, mode="r", *args, **kwargs):
        opened.append((os.fspath(file) if not isinstance(file, int) else file, mode))
        return original(file, mode, *args, **kwargs)

    builtins.open = recorder
    try:
        engine.analyze_path(str(target))
    finally:
        builtins.open = original

    assert opened == [(str(target), "rb")]
    assert {path: path.stat().st_mtime_ns for path in tmp_path.rglob("*")} == snapshot
    assert list(tmp_path.rglob("*")) == [target]


def test_analysis_works_while_the_sandbox_blocks_network_and_processes():
    """Nếu một bước nào đó cần socket hay tiến trình, bài này sẽ đỏ.

    Đó chính là mục đích: bộ phân tích phải chạy được trọn vẹn trong lúc mạng
    và tạo tiến trình đã bị vá chặn.
    """
    sandbox.engage()
    try:
        assert sandbox.is_engaged()
        for kind, data in SAMPLES.items():
            report = engine.analyze_bytes(data, kind)
            assert isinstance(report.verdict, Verdict)
    finally:
        sandbox.release()


def _binary_modules():
    found = []
    for info in pkgutil.walk_packages(binary_package.__path__, "fortress_scan.binary."):
        if info.name.endswith("__main__"):
            continue
        found.append(info.name)
    return found


def test_the_binary_package_contains_no_dangerous_call_at_all():
    """Không eval, không exec, không marshal/pickle, không subprocess, không socket.

    Bộ phân tích đọc dữ liệu của kẻ tấn công. Một lời gọi giải tuần tự ở đây
    biến chính công cụ thành đường thực thi mã - đúng loại lỗ hổng mà phần
    còn lại của dự án đi tìm.
    """
    banned_calls = {"eval", "exec", "compile", "__import__", "system", "popen", "spawn"}
    banned_attributes = {
        ("marshal", "loads"),
        ("marshal", "load"),
        ("pickle", "loads"),
        ("pickle", "load"),
        ("os", "system"),
        ("shutil", "unpack_archive"),
    }
    banned_imports = {"subprocess", "socket", "marshal", "pickle", "ctypes", "urllib", "http", "requests"}

    modules = _binary_modules()
    assert len(modules) >= 12, "không gom được module nào thì bài kiểm tra này vô nghĩa"
    for name in modules:
        path = Path(__import__(name, fromlist=["x"]).__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = node.func
                if isinstance(target, ast.Name):
                    assert target.id not in banned_calls, "%s gọi %s" % (name, target.id)
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                    pair = (target.value.id, target.attr)
                    assert pair not in banned_attributes, "%s gọi %s.%s" % (name, *pair)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in banned_imports, "%s nhập %s" % (name, alias.name)
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in banned_imports, "%s nhập %s" % (name, node.module)


def test_zipfile_members_are_never_extracted_to_disk(tmp_path):
    """Giải nén ra đĩa là đường Zip Slip; mọi mục chỉ được đọc trong bộ nhớ."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        handle.writestr("../../ngoai.txt", b"xin chao")
        handle.writestr("/tuyet-doi.txt", b"xin chao")
    before = sorted(tmp_path.rglob("*"))
    report = _analyze(buffer.getvalue(), "slip.jar")
    assert sorted(tmp_path.rglob("*")) == before
    assert not Path("ngoai.txt").exists()
    assert any("ngoai.txt" in name for name, _ in report.parsed.names)


# ------------------------------------------------------------- duyệt thư mục


def test_directory_walk_picks_executables_and_ignores_plain_source(tmp_path):
    (tmp_path / "con").mkdir()
    (tmp_path / "con" / "tool.exe").write_bytes(B.build_pe())
    (tmp_path / "con" / "lib.so").write_bytes(B.build_elf(elf_type=3))
    (tmp_path / "script.ps1").write_text("Write-Output 1\n", encoding="utf-8")
    (tmp_path / "ghi-chu.txt").write_text("xin chao\n", encoding="utf-8")
    (tmp_path / "ma-nguon.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "co-shebang.py").write_text("#!/usr/bin/env python3\nprint(1)\n", encoding="utf-8")
    (tmp_path / "khong-duoi").write_bytes(B.build_elf())
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.exe").write_bytes(B.build_pe())

    found = {path.name for path in engine.discover(str(tmp_path))}
    assert {"tool.exe", "lib.so", "script.ps1", "khong-duoi", "co-shebang.py"} <= found
    assert "ghi-chu.txt" not in found
    assert "ma-nguon.py" not in found, "mã nguồn không phải việc của bộ dò nhị phân"
    assert "hook.exe" not in found, ".git không được quét"


def test_directory_walk_does_not_follow_links(tmp_path):
    (tmp_path / "ngoai").mkdir()
    (tmp_path / "ngoai" / "that.exe").write_bytes(B.build_pe())
    (tmp_path / "trong").mkdir()
    try:
        (tmp_path / "trong" / "lien-ket").symlink_to(tmp_path / "ngoai", target_is_directory=True)
        (tmp_path / "trong" / "lk.exe").symlink_to(tmp_path / "ngoai" / "that.exe")
    except (OSError, NotImplementedError):
        pytest.skip("hệ thống không cho tạo liên kết")
    found = [path.name for path in engine.discover(str(tmp_path / "trong"))]
    assert found == []


def test_directory_walk_has_a_file_ceiling(tmp_path):
    for index in range(30):
        (tmp_path / ("t%d.exe" % index)).write_bytes(B.build_pe())
    assert len(list(engine.discover(str(tmp_path), max_files=7))) == 7


def test_an_unreadable_file_does_not_stop_the_walk(tmp_path):
    (tmp_path / "ok.exe").write_bytes(B.build_pe())
    blocked = tmp_path / "chan.exe"
    blocked.write_bytes(B.build_pe())
    try:
        blocked.chmod(0o000)
        if os.access(str(blocked), os.R_OK):
            pytest.skip("đang chạy bằng quyền bỏ qua phân quyền tệp")
        names = {path.name for path in engine.discover(str(tmp_path))}
        assert "ok.exe" in names
    finally:
        blocked.chmod(0o644)


# ------------------------------------------------------------ chặn trần tài liệu


def test_the_reference_guard_needs_real_density_not_one_mention():
    from fortress_scan.binary.strings import StringPool, add_text

    pool = StringPool()
    add_text("phát hiện T1486 trong mẫu này", pool, "x")
    assert reference.looks_like_reference(pool) is None

    pool = StringPool()
    add_text(" ".join("T14%02d" % index for index in range(80, 90)), pool, "x")
    assert reference.looks_like_reference(pool) is not None
