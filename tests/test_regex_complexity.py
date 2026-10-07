"""Mọi regex trong src/ phải tuyến tính trên đầu vào thù địch.

Công cụ này đọc tệp của người lạ. Một regex bậc hai trong đó không phải là
chuyện hiệu năng: nó là một lỗ hổng từ chối dịch vụ mà kẻ tấn công kích hoạt
bằng cách nhờ nạn nhân quét đúng repo của mình. Hai lỗ hổng như vậy đã tồn
tại thật và được vá ở 0.1.0:

* `redact()` -- mẫu bắt mật khẩu trong URL viết `[a-z][a-z0-9+.\\-]*://`, và
  lớp ký tự đó nuốt được cả chữ lẫn số lẫn dấu chấm trong khi `:` thì không.
  Trên một dòng dài không có `://`, bộ máy quét tới cuối rồi lùi từng ký tự
  để dò dấu hai chấm, làm lại ở MỌI vị trí bắt đầu. Đo được 3,0 giây cho
  32 KB, và tăng 16 lần kích thước thì tốn gấp 276 lần thời gian. Một tệp
  JavaScript đã minify nằm trên một dòng là đủ để treo lượt quét hàng giờ.
* `manifest` -- mẫu `\\bcurl\\b[^;&\\n]{0,400}...[^\\n]{0,200}[;&]{1,2}` thử lại
  400 x 200 tổ hợp độ dài ở mỗi vị trí. Đo được 23 giây cho 200 KB.

Bài kiểm tra ở đây không đọc mẫu regex mà ĐO nó. Cách đó bắt được cả những
hình dạng mà mắt người bỏ sót, và nó tự động áp dụng cho mọi regex viết thêm
sau này -- không ai phải nhớ bổ sung gì.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time
from typing import Any, Dict, List, Tuple

import pytest

import fortress_scan

# Phép khẳng định CHÍNH là một trần tuyệt đối trên một đầu vào lớn, không
# phải một tỉ lệ giữa hai phép đo.
#
# Lý do rất thực tế: các mẫu trong src/ chạy khoảng 10-25 nanô giây mỗi ký tự,
# nên ở cỡ nhỏ một lần đo chỉ tốn vài chục micro giây. Chia hai con số cỡ đó
# cho nhau là khuếch đại nhiễu lịch trình của hệ điều hành chứ không đo được
# gì -- và một bài kiểm tra đo thời gian mà đỏ ngẫu nhiên còn tệ hơn là không
# có, vì cả đội sẽ học cách chạy lại cho tới khi nó xanh, kể cả khi nó đúng.
#
# Ở cỡ 256 nghìn ký tự thì khoảng cách giữa hai lớp độ phức tạp rộng tới ba
# bậc: mẫu tuyến tính tốn vài mili giây, còn lỗi bậc hai đã vá ( 3,0 giây cho
# 32 KB ) sẽ tốn khoảng ba phút. Không có nhiễu nào bắc qua được khoảng đó.
MAX_SECONDS = 1.0

# Lấy thời gian NHỎ NHẤT của vài lần chạy. Nhiễu chỉ làm phép đo chậm đi chứ
# không bao giờ làm nó nhanh lên, nên giá trị nhỏ nhất là ước lượng sạch nhất
# của chi phí thật.
REPEATS = 3

SMALL = 2_000
LARGE = 256_000
_SIZE_RATIO = LARGE / SMALL

# Ngưỡng tỉ lệ SUY RA từ cỡ đầu vào chứ không gõ tay. Tuyến tính thì tỉ lệ
# xấp xỉ 128, bậc hai thì xấp xỉ 16.384, nên hệ số 4 nằm gọn giữa hai lớp.
#
# Gõ tay một lần rồi đổi cỡ đầu vào là cách bài kiểm tra này tự làm mình đỏ:
# đúng chuyện đó đã xảy ra khi LARGE tăng từ 32 nghìn lên 256 nghìn mà ngưỡng
# vẫn nằm dưới mức tuyến tính.
MAX_SCALE = _SIZE_RATIO * 4

# Dưới mức này thì phép chia hai số đo chỉ khuếch đại nhiễu lịch trình.
NOISE_FLOOR = 1e-3

# Những hình dạng hay làm vỡ một quantifier tham lam: chuỗi lặp gồm đúng
# những ký tự mà các lớp trong mẫu có thể nuốt, nhưng thiếu hẳn ký tự kết
# thúc mà mẫu đang đi tìm.
SHAPES: Dict[str, str] = {
    "chu": "a",
    "chu-cham": "a.",
    "chu-gach": "a-",
    "chu-gach-duoi": "a_",
    "khoang-trang": " ",
    "tab": "\t",
    "chu-hai-cham": "a:",
    "chu-cheo": "a/",
    "so": "0",
    "so-chu": "0a",
    "mo-heredoc": "<<",
    "mo-noi-suy": "${",
    "mo-lenh": "$(",
    "chu-thich": "# ",
    "nhay-kep": '"',
    "tron": "aA0_.-: /",
    "tai-ve": "curl -o ",
    "jwt-cut": "eyJA.",
}


def _grow(unit: str, size: int) -> str:
    return unit * (size // len(unit) + 1)


def _probe(pattern: "re.Pattern[Any]", unit: str, size: int):
    """Đầu vào thử, cùng kiểu với mẫu.

    Các parser nhị phân dò thẳng trên bytes ( rút chuỗi, shebang ), nên mẫu của
    chúng là mẫu bytes. Chúng đọc tệp của người lạ y như các mẫu str, nên phải
    nằm trong cùng lưới an toàn này chứ không được lặng lẽ miễn trừ.
    """
    text = _grow(unit, size)
    if isinstance(pattern.pattern, bytes):
        return text.encode("utf-8", errors="replace")
    return text


def _every_pattern() -> List[Tuple[str, "re.Pattern[str]"]]:
    """Mọi regex đã biên dịch mà src/ giữ ở cấp module.

    Gom cả những mẫu nằm trong tuple và dict ( bảng theo ngôn ngữ, danh sách
    mẫu redaction ), vì đó chính là chỗ chúng hay nằm.
    """
    found: List[Tuple[str, "re.Pattern[str]"]] = []
    seen = set()
    for info in pkgutil.walk_packages(fortress_scan.__path__, "fortress_scan."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            for label, pattern in _patterns_in(name, value):
                key = (info.name, label, pattern.pattern)
                if key in seen:
                    continue
                seen.add(key)
                found.append(("%s.%s" % (info.name, label), pattern))
    return found


def _patterns_in(name: str, value: object):
    if isinstance(value, re.Pattern):
        return [(name, value)]
    if isinstance(value, (tuple, list)):
        return [
            ("%s[%d]" % (name, index), item)
            for index, item in enumerate(value)
            if isinstance(item, re.Pattern)
        ]
    if isinstance(value, dict):
        return [
            ("%s[%s]" % (name, key), item)
            for key, item in value.items()
            if isinstance(item, re.Pattern)
        ]
    return []


ALL_PATTERNS = _every_pattern()


def test_the_sweep_covers_byte_patterns_too():
    """Mẫu bytes của các parser nhị phân phải nằm trong lưới, không bị bỏ qua."""
    assert any(isinstance(pattern.pattern, bytes) for _, pattern in ALL_PATTERNS)


def test_the_sweep_actually_finds_patterns():
    """Lưới an toàn cho chính bài kiểm tra.

    Nếu cách gom mẫu hỏng ( đổi tên module, đổi cách khai báo ) thì vòng lặp
    dưới chạy trên tập rỗng và luôn xanh -- một bài kiểm tra không kiểm tra
    gì cả thì tệ hơn là không có.
    """
    assert len(ALL_PATTERNS) >= 30


def _fastest(pattern: "re.Pattern[Any]", text) -> float:
    best = float("inf")
    for _ in range(REPEATS):
        started = time.perf_counter()
        pattern.search(text)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("label,pattern", ALL_PATTERNS, ids=[item[0] for item in ALL_PATTERNS])
def test_pattern_stays_linear(label: str, pattern: "re.Pattern[str]"):
    for shape, unit in SHAPES.items():
        small_seconds = _fastest(pattern, _probe(pattern, unit, SMALL))
        large_seconds = _fastest(pattern, _probe(pattern, unit, LARGE))

        assert large_seconds < MAX_SECONDS, (
            "%s tốn %.2fs cho %d ký tự dạng %r" % (label, large_seconds, LARGE, shape)
        )
        if small_seconds < NOISE_FLOOR:
            continue
        scale = large_seconds / small_seconds
        assert scale < MAX_SCALE, (
            "%s tăng %.0f lần khi đầu vào tăng %.0f lần trên dạng %r, "
            "dấu hiệu quay lui bậc hai" % (label, scale, _SIZE_RATIO, shape)
        )
