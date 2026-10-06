"""Rút chuỗi in được ( ASCII và UTF-16LE ) kèm offset trong tệp.

Các chuỗi được nối vào một "bể" văn bản duy nhất theo thứ tự offset, để mỗi
detector chạy regex một lần trên cả bể rồi tra ngược offset bằng bisect, thay
vì lặp regex trên hàng trăm nghìn chuỗi lẻ.
"""

from __future__ import annotations

import bisect
import re
from typing import Iterator, List, Optional, Tuple

MIN_LENGTH = 5
MAX_STRING_CHARS = 4096
MAX_STRINGS = 250_000

_ASCII = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_LENGTH)
_UTF16 = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_LENGTH)


class StringPool:
    """Bể chuỗi: `text` là các chuỗi nối bằng '\\n', `starts[i]` là vị trí của
    chuỗi thứ i trong `text`, `offsets[i]` và `labels[i]` cho biết nó từ đâu ra."""

    def __init__(self) -> None:
        self._parts: List[str] = []
        self.starts: List[int] = []
        self.offsets: List[int] = []
        self.labels: List[str] = []
        self._length = 0
        self._text: Optional[str] = None
        self._lower: Optional[str] = None
        self.truncated = False

    def add(self, value: str, offset: int, label: str) -> None:
        if len(self.starts) >= MAX_STRINGS:
            self.truncated = True
            return
        value = value[:MAX_STRING_CHARS]
        self.starts.append(self._length)
        self.offsets.append(offset)
        self.labels.append(label)
        self._parts.append(value)
        self._length += len(value) + 1
        self._text = None
        self._lower = None

    def __len__(self) -> int:
        return len(self.starts)

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = "\n".join(self._parts)
        return self._text

    @property
    def lower(self) -> str:
        if self._lower is None:
            self._lower = self.text.lower()
        return self._lower

    def string_at(self, index: int) -> str:
        return self._parts[index]

    def index_of(self, position: int) -> int:
        return max(0, bisect.bisect_right(self.starts, position) - 1)

    def locate(self, position: int) -> Tuple[int, str]:
        """(offset trong tệp, nhãn) của chuỗi chứa vị trí `position` trong text."""
        index = self.index_of(position)
        if not self.starts:
            return 0, ""
        delta = position - self.starts[index]
        offset = self.offsets[index]
        label = self.labels[index]
        if offset >= 0 and label.endswith("utf16"):
            delta *= 2
        return (offset + delta if offset >= 0 else offset), label

    def iter_strings(self) -> Iterator[Tuple[str, int, str]]:
        for value, offset, label in zip(self._parts, self.offsets, self.labels):
            yield value, offset, label


def extract(data: bytes, pool: StringPool, base_label: str = "", base_offset: int = 0) -> None:
    """Đổ chuỗi ASCII và UTF-16LE của `data` vào `pool`, theo thứ tự offset."""
    found: List[Tuple[int, str, str]] = []
    suffix = (base_label + ":") if base_label else ""
    for match in _ASCII.finditer(data):
        found.append((match.start(), match.group().decode("ascii"), suffix + "ascii"))
        if len(found) > MAX_STRINGS:
            break
    for match in _UTF16.finditer(data):
        found.append(
            (match.start(), match.group().decode("utf-16-le", errors="replace"), suffix + "utf16")
        )
        if len(found) > 2 * MAX_STRINGS:
            break
    found.sort(key=lambda item: item[0])
    for offset, value, label in found:
        pool.add(value, (base_offset + offset) if base_offset >= 0 else -1, label)


def add_text(text: str, pool: StringPool, label: str) -> None:
    """Thêm văn bản ( script, chuỗi đã giải mã ) vào bể theo từng dòng, offset là số dòng âm."""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if len(stripped) >= 3:
            pool.add(stripped, -number, label)
