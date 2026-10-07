"""Đọc metadata .NET ( ECMA-335 phần II.24 ) đủ để lấy định danh và chuỗi.

Không dựng lại bảng metadata đầy đủ: heap #Strings đã chứa tên mọi kiểu,
phương thức, namespace mà assembly tham chiếu ( RijndaelManaged,
CreateEncryptor, GetFiles ... ), còn heap #US chứa chuỗi literal của chương
trình, nơi ghi chú tống tiền của ransomware viết bằng C# thường nằm.
"""

from __future__ import annotations

from typing import Dict

from ..model import Parsed
from ..reader import ByteView, Truncated

MAX_STREAMS = 16
MAX_IDENTIFIERS = 60_000
MAX_USER_STRINGS = 60_000

# Dấu vết các obfuscator .NET phổ biến, theo attribute / tên kiểu mà chính
# các công cụ đó chèn vào ( tài liệu công khai của de4dot và vendor ).
OBFUSCATOR_MARKERS: Dict[str, str] = {
    "ConfusedByAttribute": "ConfuserEx",
    "ConfuserEx": "ConfuserEx",
    "DotfuscatorAttribute": "Dotfuscator",
    "SmartAssembly.Attributes": "SmartAssembly",
    "PoweredByAttribute": "SmartAssembly",
    "BabelObfuscatorAttribute": "Babel",
    "BabelAttribute": "Babel",
    "ObfuscatedByGoliath": "Goliath",
    "CryptoObfuscator": "Crypto Obfuscator",
    "Xenocode.Client.Attributes": "Xenocode",
    "YanoAttribute": "Yano",
    "NETSpider.Attribute": "NETSpider",
    "EMyPID_8234_": "Agile.NET",
    "__BeaEngine": ".NET Reactor",
}


def parse_metadata(data: bytes, offset: int, size: int, parsed: Parsed) -> None:
    view = ByteView(data)
    if not view.has(offset, 16) or view.u32(offset) != 0x424A5342:  # "BSJB"
        parsed.anomalies.append("metadata .NET thiếu chữ ký BSJB")
        return
    length = view.u32(offset + 12)
    if length > 255:
        parsed.anomalies.append("chuỗi phiên bản runtime .NET dài bất thường")
        return
    parsed.metadata["dotnet_runtime"] = view.fixed_str(offset + 16, length)
    cursor = offset + 16 + length
    stream_count = min(view.u16(cursor + 2), MAX_STREAMS)
    cursor += 4
    streams: Dict[str, tuple] = {}
    for _ in range(stream_count):
        stream_offset = view.u32(cursor)
        stream_size = view.u32(cursor + 4)
        name_end = data.find(b"\x00", cursor + 8, cursor + 8 + 32)
        if name_end < 0:
            break
        name = data[cursor + 8 : name_end].decode("latin-1")
        streams[name] = (offset + stream_offset, stream_size)
        cursor = (name_end + 4) & ~3  # tên đệm tới bội số 4
    if "#Strings" in streams:
        start, length = streams["#Strings"]
        _identifiers(data, start, length, parsed)
    if "#US" in streams:
        start, length = streams["#US"]
        _user_strings(data, start, length, parsed)
    parsed.metadata["dotnet_streams"] = ", ".join(sorted(streams))


def _identifiers(data: bytes, start: int, length: int, parsed: Parsed) -> None:
    heap = data[start : start + length]
    unreadable = 0
    total = 0
    for raw in heap.split(b"\x00"):
        if not raw:
            continue
        total += 1
        if total > MAX_IDENTIFIERS:
            parsed.anomalies.append("heap #Strings quá lớn, đã cắt")
            break
        try:
            name = raw.decode("utf-8")
        except UnicodeDecodeError:
            unreadable += 1
            continue
        if not name.isprintable() or not name.isascii():
            unreadable += 1
        parsed.names.append((name, ".net #Strings"))
        for marker, tool in OBFUSCATOR_MARKERS.items():
            if marker in name and tool not in parsed.packers:
                parsed.packers.append(tool)
    if total >= 40 and unreadable / total > 0.3:
        parsed.traits.append("obfuscated-names")


def _user_strings(data: bytes, start: int, length: int, parsed: Parsed) -> None:
    view = ByteView(data)
    cursor = start + 1  # byte đầu của heap #US luôn là 0
    end = min(start + length, len(data))
    found = []
    while cursor < end and len(found) < MAX_USER_STRINGS:
        try:
            first = view.u8(cursor)
            if first & 0x80 == 0:
                size, header = first, 1
            elif first & 0xC0 == 0x80:
                size, header = ((first & 0x3F) << 8) | view.u8(cursor + 1), 2
            elif first & 0xE0 == 0xC0:
                size = ((first & 0x1F) << 24) | (view.u8(cursor + 1) << 16)
                size |= (view.u8(cursor + 2) << 8) | view.u8(cursor + 3)
                header = 4
            else:
                break
        except Truncated:
            break
        body = data[cursor + header : cursor + header + max(size - 1, 0)]
        if body:
            found.append(body.decode("utf-16-le", errors="replace"))
        cursor += header + size
        if size == 0:
            continue
    if found:
        parsed.embedded_text.append((".net #US", "\n".join(found)))
