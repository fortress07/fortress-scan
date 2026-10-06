"""Đọc cấu trúc nhị phân có kiểm biên.

Mọi parser trong gói này đọc tệp KHÔNG TIN CẬY. Một header khai số mục giả,
một offset trỏ ra ngoài tệp hay một vòng lặp con trỏ đều phải chết thành một
dòng "dị thường" trong báo cáo, không được thành IndexError hay treo máy.
"""

from __future__ import annotations

import struct
from typing import Optional


class Truncated(ValueError):
    """Đọc vượt quá cuối dữ liệu."""


class ByteView:
    __slots__ = ("data", "little")

    def __init__(self, data: bytes, little: bool = True) -> None:
        self.data = data
        self.little = little

    def __len__(self) -> int:
        return len(self.data)

    def has(self, offset: int, size: int) -> bool:
        return 0 <= offset and size >= 0 and offset + size <= len(self.data)

    def bytes_at(self, offset: int, size: int) -> bytes:
        if not self.has(offset, size):
            raise Truncated("đọc %d byte tại 0x%x vượt cuối tệp" % (size, offset))
        return self.data[offset : offset + size]

    def _unpack(self, fmt: str, offset: int, size: int) -> int:
        prefix = "<" if self.little else ">"
        return struct.unpack_from(prefix + fmt, self.bytes_at(offset, size))[0]

    def u8(self, offset: int) -> int:
        return self._unpack("B", offset, 1)

    def u16(self, offset: int) -> int:
        return self._unpack("H", offset, 2)

    def u32(self, offset: int) -> int:
        return self._unpack("I", offset, 4)

    def u64(self, offset: int) -> int:
        return self._unpack("Q", offset, 8)

    def cstr(self, offset: int, limit: int = 512) -> str:
        """Chuỗi kết thúc bằng NUL, cắt ở `limit` byte, giải mã thay thế."""
        if not 0 <= offset < len(self.data):
            raise Truncated("chuỗi tại 0x%x nằm ngoài tệp" % offset)
        end = self.data.find(b"\x00", offset, offset + limit)
        if end < 0:
            end = min(len(self.data), offset + limit)
        return self.data[offset:end].decode("utf-8", errors="replace")

    def fixed_str(self, offset: int, size: int) -> str:
        raw = self.bytes_at(offset, size).split(b"\x00", 1)[0]
        return raw.decode("latin-1")


def safe_slice(data: bytes, offset: int, size: int) -> Optional[bytes]:
    if offset < 0 or size < 0 or offset >= len(data):
        return None
    return data[offset : offset + size]
