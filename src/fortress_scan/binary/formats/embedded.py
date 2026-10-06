"""Nhận diện thứ được nhúng trong một tệp thực thi: PyInstaller, Go build info.

Với PyInstaller, các script chính được lưu dạng code object đã marshal và nén
zlib. Ở đây chỉ GIẢI NÉN có trần rồi rút chuỗi in được; tuyệt đối không gọi
marshal.loads, vì marshal không an toàn với dữ liệu không tin cậy.
"""

from __future__ import annotations

import zlib
from typing import Optional

from ..model import Parsed
from ..reader import ByteView, Truncated

PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
MAX_TOC_ENTRIES = 10_000
MAX_SCRIPT_BYTES = 8 << 20
MAX_SCRIPTS = 64

GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def pyinstaller(data: bytes, parsed: Parsed) -> None:
    search_from = max(0, len(data) - (1 << 16))
    position = data.rfind(PYINSTALLER_MAGIC, search_from)
    if position < 0:
        return
    view = ByteView(data, little=False)
    try:
        package_length = view.u32(position + 8)
        toc_offset = view.u32(position + 12)
        toc_length = view.u32(position + 16)
        python_version = view.u32(position + 20)
    except Truncated:
        parsed.anomalies.append("cookie PyInstaller bị cắt cụt")
        return
    parsed.traits.append("pyinstaller")
    parsed.packers.append("PyInstaller")
    if python_version < 1000:
        major, minor = divmod(python_version, 100 if python_version >= 100 else 10)
        parsed.metadata["pyinstaller_python"] = "%d.%d" % (major, minor)
    # Cookie mới dài 88 byte ( thêm tên libpython ), cookie cũ 24 byte.
    cookie_size = 88 if b"python" in data[position + 24 : position + 88].lower() else 24
    package_start = position + cookie_size - package_length
    if package_start < 0:
        parsed.anomalies.append("cookie PyInstaller khai độ dài gói không hợp lệ")
        return
    cursor = package_start + toc_offset
    end = cursor + toc_length
    scripts = 0
    entries = 0
    while cursor < end and entries < MAX_TOC_ENTRIES:
        entries += 1
        try:
            entry_size = view.u32(cursor)
            entry_pos = view.u32(cursor + 4)
            compressed_size = view.u32(cursor + 8)
            flag = view.u8(cursor + 16)
            kind = chr(view.u8(cursor + 17))
            name = view.bytes_at(cursor + 18, max(0, entry_size - 18)).split(b"\x00", 1)[0]
        except Truncated:
            parsed.anomalies.append("mục lục PyInstaller bị cắt cụt")
            return
        if entry_size < 18:
            parsed.anomalies.append("mục lục PyInstaller có mục hỏng")
            return
        label = name.decode("utf-8", errors="replace")
        parsed.names.append((label, "mục lục PyInstaller ( loại %s )" % kind))
        if kind == "s" and scripts < MAX_SCRIPTS:
            body = data[package_start + entry_pos : package_start + entry_pos + compressed_size]
            content = _inflate(body) if flag else body
            if content:
                scripts += 1
                parsed.embedded.append(("PyInstaller script %s" % label, content))
        cursor += entry_size


def _inflate(body: bytes) -> Optional[bytes]:
    try:
        engine = zlib.decompressobj()
        content = engine.decompress(body, MAX_SCRIPT_BYTES)
        return content
    except zlib.error:
        return None


def _varint(data: bytes, offset: int):
    value = 0
    shift = 0
    for index in range(10):
        if offset + index >= len(data):
            raise Truncated("varint bị cắt cụt")
        byte = data[offset + index]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset + index + 1
        shift += 7
    raise Truncated("varint quá dài")


def go_buildinfo(data: bytes, parsed: Parsed) -> None:
    """Đọc phiên bản Go và danh sách module ( Go 1.18+ lưu dạng chuỗi nội tuyến )."""
    position = data.find(GO_BUILDINFO_MAGIC)
    if position < 0:
        return
    if "go" not in parsed.traits:
        parsed.traits.append("go")
    flags = data[position + 15] if position + 15 < len(data) else 0
    if not flags & 0x2:
        return  # dạng con trỏ của Go cũ; cần ánh xạ địa chỉ, bỏ qua
    try:
        size, cursor = _varint(data, position + 32)
        version = data[cursor : cursor + min(size, 64)].decode("utf-8", errors="replace")
        cursor += size
        size, cursor = _varint(data, cursor)
        modinfo = data[cursor : cursor + min(size, 1 << 20)].decode("utf-8", errors="replace")
    except Truncated:
        parsed.anomalies.append("Go build info bị cắt cụt")
        return
    parsed.metadata["go_version"] = version
    deps = []
    for line in modinfo.splitlines():
        fields = line.split("\t")
        if len(fields) >= 2 and fields[0] in ("path", "mod", "dep"):
            if fields[0] == "path":
                parsed.metadata["go_main_package"] = fields[1][:200]
            elif fields[0] == "dep":
                deps.append(fields[1])
            parsed.names.append((fields[1], "Go module"))
    if deps:
        parsed.metadata["go_dependencies"] = str(len(deps))
