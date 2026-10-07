"""Khôi phục chuỗi bị che bằng XOR một byte.

Vì sao cần, và đây là con số đo được chứ không phải cảm tính: lấy đúng một
tệp mang đủ dấu hiệu rồi XOR riêng vùng chuỗi của nó bằng một byte duy nhất,
kết luận tụt từ "rõ rệt" ( 100 điểm ) xuống "cần lưu ý" ( 20 ). XOR kèm bảng
import rút gọn thì tụt hẳn về "sạch". Chín dấu hiệu nội dung chết cùng lúc vì
một phép toán tầm thường nhất trong nghề, nên không vá chỗ này thì mọi con số
bắt được chỉ đúng với tệp để chuỗi lộ thiên.

Cách làm, và vì sao KHÔNG phải thử 255 lần: XOR với một hằng số giữ nguyên
hiệu XOR của hai byte liền nhau, vì (a^k) ^ (b^k) = a^b. Nên tính delta của
dữ liệu đúng một lần rồi tìm delta của vài mỏ neo trong đó; trúng ở vị trí p
thì khoá chính là data[p] ^ anchor[0]. Một lượt quét thay cho 255 lượt, và
lượt đó chạy ở tốc độ C nhờ số nguyên lớn của Python.

Mỏ neo là tên lệnh và tên API của hệ điều hành, KHÔNG phải chuỗi đặc trưng
của một họ mã độc. Chữ ký theo họ chết ngay khi tác giả đổi một ký tự, còn
tên lệnh thì không đổi được: nó là thứ Windows quy định, không phải thứ kẻ
tấn công đặt ra.

Giới hạn, nói trước: phép này chỉ bắt khoá MỘT byte. Khoá lặp nhiều byte,
phép cộng, RC4 hay AES đều không rơi vào đây, và báo cáo không được hiểu
"không tìm thấy khoá" thành "tệp không che gì".
"""

from __future__ import annotations

from typing import List, Tuple

# Trần tổng số byte được soi. Một tệp 256 MB không được phép kéo cả lượt quét
# đi theo chỉ vì phép này.
MAX_SCAN = 32 << 20
CHUNK = 4 << 20
# Chồng lấn giữa hai khúc, phải lớn hơn mỏ neo dài nhất kẻo bỏ sót chỗ nằm vắt
# qua ranh giới khúc.
OVERLAP = 64
MAX_KEYS = 4
# Tệp nhỏ hơn mức này thì giải NGUYÊN tệp, vì bảng chuỗi bị che có thể nằm rải
# ở nhiều chỗ cách xa nhau. Phần đắt này chỉ chạy khi đã tìm ra khoá, mà tìm ra
# khoá thì tệp vốn đã rất đáng ngờ rồi - đúng chỗ nên tiêu thêm công.
FULL_DECODE_LIMIT = 8 << 20
# Tệp lớn hơn thì chỉ giải một cửa sổ quanh chỗ trúng, để có trần.
WINDOW = 128 << 10

_PLAIN = (
    b"vssadmin delete",
    b"shadowcopy delete",
    b"wbadmin delete",
    b"bcdedit /set",
    b"wevtutil.exe cl",
    b"CryptEncrypt",
    b"CryptGenKey",
    b"CryptImportKey",
    b"FindFirstFileW",
    b"GetLogicalDriveStrings",
    b"CurrentVersion\\Run",
)
# API Windows hay ở dạng rộng, nên vài mỏ neo có thêm bản UTF-16LE.
_WIDE = (b"vssadmin delete", b"CryptEncrypt", b"FindFirstFileW")

ANCHORS = _PLAIN + tuple(item.decode("ascii").encode("utf-16-le") for item in _WIDE)

# Mỏ neo ngắn thì dễ trúng ngẫu nhiên. Mười byte cho tám byte delta, tức xác
# suất trúng nhầm cỡ 2^-64 mỗi vị trí: trên cả bộ tệp vẫn là không bao giờ.
MIN_ANCHOR = 10


def _delta(data: bytes) -> bytes:
    """[d0^d1, d1^d2, ...] - bất biến với mọi phép XOR một byte."""
    if len(data) < 2:
        return b""
    value = int.from_bytes(data, "big")
    width = len(data) - 1
    return ((value >> 8) ^ (value & ((1 << (8 * width)) - 1))).to_bytes(width, "big")


_DELTAS = tuple((anchor, _delta(anchor)) for anchor in ANCHORS if len(anchor) >= MIN_ANCHOR)


def find_keys(data: bytes) -> List[Tuple[int, int, bytes]]:
    """[(khoá, vị trí mỏ neo trong tệp, mỏ neo)] cho mỗi khoá tìm được."""
    found: List[Tuple[int, int, bytes]] = []
    seen = set()
    limit = min(len(data), MAX_SCAN)
    for start in range(0, limit, CHUNK):
        chunk = data[start:min(start + CHUNK + OVERLAP, limit)]
        if len(chunk) < MIN_ANCHOR:
            break
        delta = _delta(chunk)
        for anchor, anchor_delta in _DELTAS:
            position = delta.find(anchor_delta)
            if position < 0:
                continue
            key = chunk[position] ^ anchor[0]
            # Khoá 0 là chuỗi lộ thiên, phần rút chuỗi thường đã lấy rồi.
            if key == 0 or key in seen:
                continue
            seen.add(key)
            found.append((key, start + position, anchor))
            if len(seen) >= MAX_KEYS:
                return found
    return found


def recover(data: bytes) -> List[Tuple[int, int, bytes, bytes]]:
    """[(khoá, offset đầu cửa sổ, dữ liệu đã giải, mỏ neo đã trúng)]."""
    out: List[Tuple[int, int, bytes, bytes]] = []
    for key, position, anchor in find_keys(data):
        table = bytes(index ^ key for index in range(256))
        if len(data) <= FULL_DECODE_LIMIT:
            start, end = 0, len(data)
        else:
            start = max(0, position - WINDOW // 2)
            end = min(len(data), position + WINDOW // 2)
        out.append((key, start, data[start:end].translate(table), anchor))
    return out
