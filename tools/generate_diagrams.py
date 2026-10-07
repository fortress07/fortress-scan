"""Sinh bộ hình minh hoạ cho README, mỗi hình hai bản sáng và tối.

Vì sao phải SINH ra chứ không vẽ tay: mọi con số trên hình đều lấy thẳng từ
`core.registry`, nên thêm hay bớt một rule là hình tự lệch theo mã chứ không âm
thầm nói sai. `tests/test_diagrams.py` chạy lại script này rồi so từng byte với
tệp đã commit, nên hình không thể cũ hơn mã.

Số đo hiệu năng thì không suy ra được từ mã, nên chúng nằm trong `MEASUREMENTS`
kèm cả trung vị và số lần lặp. Đo lại thì sửa ở đúng một chỗ.

HAI LUẬT VẼ, và cả hai đều có lý do:

* **Không vẽ nền.** SVG để trong suốt rồi thả thẳng lên nền của GitHub. Vẽ một
  ô nền trắng thì ở chế độ tối nó thành một tấm thẻ chói mắt dán giữa trang.
* **Panel tô bằng chính màu nhấn ở độ mờ thấp**, viền cùng màu đậm hơn một
  chút, kèm một vạch dọc bên trái. Cách này đọc được trên cả nền sáng lẫn nền
  tối mà không cần một màu xám riêng cho từng chế độ.

Chạy:  python tools/generate_diagrams.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fortress_scan.core.registry import all_rules  # noqa: E402

OUT = ROOT / "docs" / "img"

FONT = "Segoe UI, system-ui, -apple-system, sans-serif"
MONO = "Cascadia Code, SF Mono, Consolas, monospace"

# Bề rộng chung. Phần nội dung README của GitHub rộng khoảng ngần này, nên vẽ
# đúng cỡ thì chữ không bị thu nhỏ rồi nhoè.
W = 900
PAD = 24


# --------------------------------------------------------------------------
# Bảng màu. Hai bản đối xứng nhau để cùng một hình đọc được ở cả hai chế độ.
# Không có khoá "bg": hình không bao giờ tự vẽ nền cho mình.
# --------------------------------------------------------------------------

THEMES: Dict[str, Dict[str, str]] = {
    "light": {
        "text": "#1c2233",
        "muted": "#525d75",
        "grid": "#c9cfdd",
        "red": "#b0201a",
        "orange": "#9a5200",
        "yellow": "#8a6100",
        "green": "#0c7268",
        "blue": "#3730c9",
        "purple": "#7233a8",
        "pink": "#b81d63",
    },
    "dark": {
        "text": "#e9eef8",
        "muted": "#a3aec6",
        "grid": "#2b3546",
        "red": "#ff8585",
        "orange": "#ffc255",
        "yellow": "#ffd479",
        "green": "#4cd8c2",
        "blue": "#93a2ff",
        "purple": "#d3a4ff",
        "pink": "#ff8ac0",
    },
}

# Độ mờ dùng chung cho lối vẽ panel.
FILL_TINT = "0.11"
STROKE_TINT = "0.50"
BAR_TINT = "0.95"
TRACK_TINT = "0.20"


# --------------------------------------------------------------------------
# Số đo. Máy đo: Windows 11, CPython 3.13. Mỗi phép lặp 7 lần, lấy trung vị,
# chạy trên đúng hai commit trước và sau khi vá với cùng một bộ fixture.
# --------------------------------------------------------------------------

MEASUREMENTS = {
    "ignore_realistic_us": {
        "label": "So khớp .gitignore thật",
        "unit": "micro-giây mỗi entry",
        "before": 1299.30,
        "after": 34.93,
        "note": "bộ mẫu Python + Node của GitHub, 74 dòng",
    },
    "attack_scan_s": {
        "label": "Quét cây dựng riêng để đốt CPU",
        "unit": "giây",
        "before": 26.14,
        "after": 6.16,
        "note": ".gitignore 15 KB hợp lệ, 60 tệp sâu 14 cấp",
    },
    "ignore_peak_mb": {
        "label": "Đỉnh bộ nhớ, .gitignore 126 MB",
        "unit": "MB",
        "before": 378.24,
        "after": 0.04,
        "note": "tệp gồm TOÀN dòng chú thích, không sinh quy tắc nào",
    },
    "selfscan_s": {
        "label": "Quét chính src/ ( đối chứng )",
        "unit": "giây",
        "before": 3.14,
        "after": 3.38,
        "note": "khoảng đo chồng nhau, tức là không đổi",
    },
}

REPS = 7


# --------------------------------------------------------------------------
# Tiện ích dựng SVG. Chỉ dùng thuộc tính trình bày, không dùng khối <style>,
# vì bộ lọc SVG của GitHub không hứa giữ lại khối đó.
# --------------------------------------------------------------------------


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&apos;")
    )


def num(value) -> str:
    """Số gọn và ỔN ĐỊNH giữa các lần chạy, để phép so từng byte còn có nghĩa."""
    text = "%.1f" % float(value)
    return text[:-2] if text.endswith(".0") else text


class Canvas:
    def __init__(self, height: int, theme: str, width: int = W) -> None:
        self.width = width
        self.height = height
        self.theme = theme
        self.c = THEMES[theme]
        self.parts: List[str] = []

    def rect(self, x, y, w, h, fill, rx=0, stroke=None, sw=1, opacity=None):
        extra = ""
        if stroke:
            extra += " stroke='%s' stroke-width='%s'" % (stroke, num(sw))
        if opacity is not None:
            extra += " opacity='%s'" % opacity
        self.parts.append(
            "<rect x='%s' y='%s' width='%s' height='%s' rx='%s' fill='%s'%s/>"
            % (num(x), num(y), num(w), num(h), rx, fill, extra)
        )

    def panel(self, x, y, w, h, accent, rx=10, bar=True):
        """Tấm nền tô bằng chính màu nhấn, đọc được trên cả hai chế độ màu."""
        self.rect(x, y, w, h, accent, rx=rx, opacity=FILL_TINT)
        self.rect(x, y, w, h, "none", rx=rx, stroke=accent, sw=1.4,
                  opacity=STROKE_TINT)
        if bar:
            self.rect(x, y, 4, h, accent, rx=2, opacity=BAR_TINT)

    def track(self, x, y, w, h, accent):
        """Rãnh nền của một thanh đo."""
        self.rect(x, y, w, h, accent, rx=h / 2, opacity=TRACK_TINT)

    def text(self, x, y, s, size=11, fill=None, weight="400", anchor="start",
             font=None, opacity=None):
        extra = " opacity='%s'" % opacity if opacity is not None else ""
        self.parts.append(
            "<text x='%s' y='%s' font-family='%s' font-size='%s' fill='%s' "
            "text-anchor='%s' font-weight='%s'%s>%s</text>"
            % (num(x), num(y), font or FONT, num(size), fill or self.c["text"],
               anchor, weight, extra, esc(s))
        )

    def line(self, x1, y1, x2, y2, stroke, sw=1.4, marker=False, opacity=None):
        extra = " marker-end='url(#a%s)'" % self.theme if marker else ""
        if opacity is not None:
            extra += " opacity='%s'" % opacity
        self.parts.append(
            "<line x1='%s' y1='%s' x2='%s' y2='%s' stroke='%s' stroke-width='%s'"
            " stroke-linecap='round'%s/>"
            % (num(x1), num(y1), num(x2), num(y2), stroke, num(sw), extra)
        )

    def path(self, d, stroke, sw=1.4, marker=False, opacity=None):
        extra = " marker-end='url(#a%s)'" % self.theme if marker else ""
        if opacity is not None:
            extra += " opacity='%s'" % opacity
        self.parts.append(
            "<path d='%s' fill='none' stroke='%s' stroke-width='%s'"
            " stroke-linecap='round' stroke-linejoin='round'%s/>"
            % (d, stroke, num(sw), extra)
        )

    def circle(self, cx, cy, r, fill, opacity=None):
        extra = " opacity='%s'" % opacity if opacity is not None else ""
        self.parts.append(
            "<circle cx='%s' cy='%s' r='%s' fill='%s'%s/>"
            % (num(cx), num(cy), num(r), fill, extra)
        )

    def chip(self, x, y, label, accent, size=10, height=19):
        """Nhãn tròn, tô nhạt cùng màu nhấn chứ không tô đặc."""
        width = int(len(label) * size * 0.60) + 18
        self.rect(x, y, width, height, accent, rx=height / 2, opacity="0.16")
        self.rect(x, y, width, height, "none", rx=height / 2, stroke=accent,
                  sw=1, opacity="0.45")
        self.text(x + width / 2, y + height * 0.72, label, size=size,
                  fill=accent, weight="700", anchor="middle")
        return width

    def title(self, title: str, subtitle: str = "") -> None:
        self.text(PAD, 30, title, size=14.5, weight="700")
        if subtitle:
            self.text(PAD, 52, subtitle, size=11.5, fill=self.c["muted"])

    def footer(self, note: str) -> None:
        self.text(PAD, self.height - 14, note, size=10.5, fill=self.c["muted"])

    def render(self) -> str:
        head = (
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 %d %d' "
            "width='%d' height='%d' role='img'>"
            % (self.width, self.height, self.width, self.height)
        )
        defs = (
            "<defs><marker id='a%s' viewBox='0 0 10 10' refX='9' refY='5' "
            "markerWidth='6' markerHeight='6' orient='auto-start-reverse'>"
            "<path d='M 0 0 L 10 5 L 0 10 z' fill='%s' opacity='0.75'/>"
            "</marker></defs>" % (self.theme, self.c["muted"])
        )
        # Không có rect nền: hình trong suốt, thả thẳng lên nền của GitHub.
        return head + defs + "\n" + "\n".join(self.parts) + "\n</svg>\n"


# --------------------------------------------------------------------------
# 1. Mô hình phân tích: nguồn, lan truyền, khử độc, sink
# --------------------------------------------------------------------------


def diagram_taint_flow(theme: str) -> str:
    cv = Canvas(486, theme)
    c = cv.c
    cv.title(
        "Cách công cụ hiểu mã: truy vết đường đi của dữ liệu",
        "Không dò từ khoá. Chỉ báo khi dữ liệu bẩn TỚI ĐƯỢC sink mà chưa bị vô hiệu hoá.",
    )

    stages = [
        ("1", "NGUỒN", "chỗ dữ liệu người\nngoài đi vào", c["blue"],
         "request.args\n$_GET · req.query"),
        ("2", "LAN TRUYỀN", "vết bẩn chảy theo\nphép gán và phép nối", c["purple"],
         "gán · nối chuỗi\nf-string · list/dict"),
        ("3", "KHỬ ĐỘC", "hàng rào duy nhất\nxoá được vết bẩn", c["green"],
         "shlex.quote\ntham số hoá · allowlist"),
        ("4", "SINK", "API nguy hiểm,\nnơi dữ liệu phát nổ", c["red"],
         "os.system · execute\neval · from_string"),
    ]

    box_w, box_h, gap = 192, 156, 26
    y0 = 84
    for index, (idx, name, desc, color, examples) in enumerate(stages):
        x = PAD + index * (box_w + gap)
        cv.panel(x, y0, box_w, box_h, color)
        cv.text(x + 18, y0 + 26, idx, size=11, fill=c["muted"], weight="700")
        cv.text(x + 34, y0 + 26, name, size=13, fill=color, weight="700")
        for line_index, line in enumerate(desc.split("\n")):
            cv.text(x + 18, y0 + 50 + line_index * 15, line, size=10.5,
                    fill=c["muted"])
        cv.rect(x + 14, y0 + 92, box_w - 28, 46, color, rx=7, opacity="0.10")
        for line_index, line in enumerate(examples.split("\n")):
            cv.text(x + 24, y0 + 112 + line_index * 15, line, size=9.5,
                    fill=c["text"], font=MONO, opacity="0.90")
        if index < len(stages) - 1:
            ax = x + box_w + 6
            cv.line(ax, y0 + box_h / 2, ax + gap - 14, y0 + box_h / 2,
                    c["muted"], marker=True, opacity="0.70")

    # Hai lối ra, đặt ngay dưới đúng chặng quyết định ra chúng.
    x3 = PAD + 2 * (box_w + gap)
    x4 = PAD + 3 * (box_w + gap)
    out_y, out_h = y0 + box_h + 30, 50

    cv.line(x3 + box_w / 2, y0 + box_h, x3 + box_w / 2, out_y - 4, c["green"],
            marker=True, opacity="0.80")
    cv.panel(x3, out_y, box_w, out_h, c["green"], bar=False)
    cv.text(x3 + 16, out_y + 21, "Đã khử độc", size=12, fill=c["green"],
            weight="700")
    cv.text(x3 + 16, out_y + 38, "im lặng, không báo gì", size=10,
            fill=c["muted"])

    cv.line(x4 + box_w / 2, y0 + box_h, x4 + box_w / 2, out_y - 4, c["red"],
            marker=True, opacity="0.80")
    cv.panel(x4, out_y, box_w, out_h, c["red"], bar=False)
    cv.text(x4 + 16, out_y + 21, "Thành PHÁT HIỆN", size=12, fill=c["red"],
            weight="700")
    cv.text(x4 + 16, out_y + 38, "kèm cả đường đi để tự kiểm", size=10,
            fill=c["muted"])

    # Ví dụ thật, để đối chiếu mô hình với một đoạn mã cụ thể.
    ex_y = out_y + out_h + 26
    cv.rect(PAD, ex_y, W - PAD * 2, 82, c["grid"], rx=10, opacity="0.22")
    cv.text(PAD + 18, ex_y + 22, "Đường đi mà báo cáo in ra", size=11,
            weight="700")
    rows = [
        ("dòng 40", "tham số truy vấn HTTP đi vào từ đây", c["blue"]),
        ("dòng 40", "chảy vào biến name", c["purple"]),
        ("dòng 42", "chạy tới cursor.execute()", c["red"]),
    ]
    for index, (where, what, color) in enumerate(rows):
        ry = ex_y + 42 + index * 15
        cv.circle(PAD + 24, ry - 4, 3.5, color, opacity="0.90")
        cv.text(PAD + 36, ry, where, size=9.5, fill=c["muted"], font=MONO)
        cv.text(PAD + 96, ry, what, size=9.5, fill=c["text"], font=MONO,
                opacity="0.90")

    cv.footer("Rẽ nhánh thì hai nhánh được gộp lại: nhiễm ở một nhánh là đủ để cảnh báo.")
    return cv.render()


# --------------------------------------------------------------------------
# 2. Sáu bước của một lượt quét
# --------------------------------------------------------------------------


def diagram_pipeline(theme: str) -> str:
    cv = Canvas(386, theme)
    c = cv.c
    cv.title(
        "Sáu bước xảy ra khi anh em gõ lệnh quét",
        "Bước 1 là lý do anh em trỏ được công cụ vào mã lạ mà không cần dựng sandbox riêng.",
    )

    steps = [
        ("1", "Khoá tiến trình", c["red"],
         "vá đè socket, subprocess, os.system",
         "dù có lỗi cũng không chạy được mã"),
        ("2", "Tìm tệp", c["orange"],
         "bỏ thư mục loại trừ, tệp nhị phân",
         "không đi theo liên kết ra ngoài"),
        ("3", "Đọc và giải mã", c["yellow"],
         "giải mã đúng khai báo # coding:",
         "để thấy đúng thứ CPython sẽ chạy"),
        ("4", "Phân tích", c["green"],
         "truy vết đường đi của dữ liệu",
         "AST cho Python, lexer cho phần còn lại"),
        ("5", "Lọc", c["blue"],
         "chỉ thị ignore, ngưỡng, baseline",
         "thứ gì làm hẹp phạm vi đều bị nói ra"),
        ("6", "Báo cáo", c["purple"],
         "console, JSON, SARIF, Markdown",
         "kèm mã thoát cho cổng CI"),
    ]

    card_w, card_h = 272, 108
    gap_x, gap_y = 18, 30
    y0 = 80
    for index, (idx, name, color, what, why) in enumerate(steps):
        col, row = index % 3, index // 3
        x = PAD + col * (card_w + gap_x)
        y = y0 + row * (card_h + gap_y)
        cv.panel(x, y, card_w, card_h, color)
        cv.text(x + 18, y + 26, idx, size=11, fill=c["muted"], weight="700")
        cv.text(x + 34, y + 26, name, size=13, fill=color, weight="700")
        cv.text(x + 18, y + 52, what, size=10.5, fill=c["text"], opacity="0.92")
        cv.text(x + 18, y + 74, why, size=10, fill=c["muted"])
        if col < 2:
            ax = x + card_w + 4
            cv.line(ax, y + card_h / 2, ax + gap_x - 10, y + card_h / 2,
                    c["muted"], marker=True, opacity="0.70")

    # Nối cuối hàng một xuống đầu hàng hai.
    mid_y = y0 + card_h + gap_y / 2
    end_x = PAD + 2 * (card_w + gap_x) + card_w / 2
    start_x = PAD + card_w / 2
    cv.path("M %s %s L %s %s L %s %s L %s %s"
            % (num(end_x), num(y0 + card_h), num(end_x), num(mid_y),
               num(start_x), num(mid_y), num(start_x), num(y0 + card_h + gap_y - 5)),
            c["muted"], marker=True, opacity="0.70")

    cv.footer("Mỗi tệp có ngân sách node/token riêng, nên một tệp dựng riêng để làm "
              "treo công cụ sẽ bị cắt chứ không kéo cả lượt quét đi theo.")
    return cv.render()


# --------------------------------------------------------------------------
# 3. Số đo trước và sau khi vá
# --------------------------------------------------------------------------


def _fmt(value: float) -> str:
    if value >= 100:
        return "%.0f" % value
    if value >= 10:
        return ("%.1f" % value).replace(".", ",")
    return ("%.2f" % value).replace(".", ",")


def diagram_benchmarks(theme: str) -> str:
    cv = Canvas(452, theme)
    c = cv.c
    cv.title(
        "Bốn phép đo trước và sau khi vá",
        "Mỗi phép lặp %d lần, lấy trung vị. Máy đo: Windows 11, CPython 3.13." % REPS,
    )

    keys = ["ignore_realistic_us", "attack_scan_s", "ignore_peak_mb", "selfscan_s"]
    row_h = 86
    y0 = 76
    bar_x, bar_max = 330, 300

    for index, key in enumerate(keys):
        item = MEASUREMENTS[key]
        y = y0 + index * row_h
        before, after = item["before"], item["after"]
        improved = after < before * 0.9
        accent = c["green"] if improved else c["muted"]

        cv.panel(PAD, y, W - PAD * 2, row_h - 12, accent, bar=False)
        cv.text(PAD + 18, y + 24, item["label"], size=12, weight="700")
        cv.text(PAD + 18, y + 42, item["note"], size=10, fill=c["muted"])
        cv.text(PAD + 18, y + 60, item["unit"], size=10, fill=c["muted"],
                opacity="0.80")

        # Thanh vẽ theo căn bậc hai để chênh lệch hàng nghìn lần vẫn nhìn được,
        # còn con số thật thì luôn in nguyên bên cạnh.
        span = max(before, after) or 1.0
        w_before = max(5, (before / span) ** 0.5 * bar_max)
        w_after = max(5, (after / span) ** 0.5 * bar_max)

        cv.text(bar_x - 10, y + 30, "trước", size=9.5, fill=c["muted"], anchor="end")
        cv.track(bar_x, y + 20, bar_max, 13, c["grid"])
        cv.rect(bar_x, y + 20, w_before, 13, c["red"], rx=6.5, opacity="0.85")
        cv.text(bar_x + bar_max + 12, y + 30, _fmt(before), size=11,
                fill=c["red"], weight="700")

        cv.text(bar_x - 10, y + 56, "sau", size=9.5, fill=c["muted"], anchor="end")
        cv.track(bar_x, y + 46, bar_max, 13, c["grid"])
        cv.rect(bar_x, y + 46, w_after, 13, accent, rx=6.5, opacity="0.85")
        cv.text(bar_x + bar_max + 12, y + 56, _fmt(after), size=11,
                fill=accent, weight="700")

        if improved:
            ratio = before / after if after else 0
            label = "nhanh hơn %s lần" % _fmt(ratio)
            if key == "ignore_peak_mb":
                label = "không còn đọc tệp"
            cv.chip(742, y + 28, label, c["green"])
        else:
            cv.chip(742, y + 28, "không đổi", c["muted"])

    cv.footer("Khoảng đo của phép đối chứng chồng lên nhau, nên phần vá không làm "
              "chậm đường chạy bình thường.")
    return cv.render()


# --------------------------------------------------------------------------
# 4. Bộ rule: mức độ nghiêm trọng và họ lỗ hổng
# --------------------------------------------------------------------------


def _severity_counts() -> List[Tuple[str, int]]:
    counts = Counter(rule.severity.label for rule in all_rules())
    order = ["critical", "high", "medium", "low", "info"]
    return [(name, counts[name]) for name in order if counts.get(name)]


def _family_counts() -> List[Tuple[str, int]]:
    counts = Counter(rule.category.value for rule in all_rules())
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def diagram_rules(theme: str) -> str:
    cv = Canvas(432, theme)
    c = cv.c
    total = len(list(all_rules()))
    cv.title(
        "%d rule, nhìn theo hai chiều" % total,
        "Số lấy thẳng từ core.registry, nên hình không lệch khỏi mã được.",
    )

    sev_colors = {
        "critical": c["red"], "high": c["orange"], "medium": c["yellow"],
        "low": c["blue"], "info": c["muted"],
    }

    col_w = 414
    left_x, right_x = PAD, PAD + col_w + 14
    panel_y, panel_h = 76, 322

    cv.panel(left_x, panel_y, col_w, panel_h, c["grid"], bar=False)
    cv.text(left_x + 20, panel_y + 26, "Theo mức độ nghiêm trọng", size=12,
            weight="700")
    severities = _severity_counts()
    top = max(count for _, count in severities)
    bar_w = 250
    for index, (name, count) in enumerate(severities):
        y = panel_y + 52 + index * 66
        color = sev_colors[name]
        cv.text(left_x + 20, y + 14, name, size=12, fill=color, weight="700")
        cv.text(left_x + 130, y + 14, "%d rule" % count, size=10.5, fill=c["muted"])
        cv.track(left_x + 20, y + 24, bar_w, 12, c["grid"])
        cv.rect(left_x + 20, y + 24, max(8, bar_w * count / top), 12, color,
                rx=6, opacity="0.85")
        cv.text(left_x + 20 + bar_w + 12, y + 34,
                "%d%%" % round(100.0 * count / total), size=10, fill=c["muted"])

    cv.panel(right_x, panel_y, col_w, panel_h, c["grid"], bar=False)
    cv.text(right_x + 20, panel_y + 26, "Theo họ lỗ hổng", size=12, weight="700")
    families = _family_counts()
    shown = families[:8]
    rest = sum(count for _, count in families[8:])
    if rest:
        shown = shown + [("còn lại (%d họ)" % len(families[8:]), rest)]
    fam_top = max(count for _, count in shown)
    # Không đưa màu lưới vào bảng màu: nó nhạt đúng bằng rãnh nền, nên hàng
    # nào rơi vào nó thì cả thanh lẫn con số biến mất khỏi hình.
    palette = [c["red"], c["orange"], c["yellow"], c["green"], c["blue"],
               c["purple"], c["pink"], c["text"]]
    fam_bar = 150
    for index, (name, count) in enumerate(shown):
        y = panel_y + 48 + index * 30
        # Hàng gộp "còn lại" cố ý dùng màu chữ mờ: nó là phần dư, không phải
        # một họ lỗ hổng để so ngang với các hàng trên.
        is_rest = rest and index == len(shown) - 1
        color = c["muted"] if is_rest else palette[index % len(palette)]
        cv.text(right_x + 20, y + 12, name, size=10.5, fill=c["text"],
                opacity="0.92")
        cv.track(right_x + 200, y + 2, fam_bar, 12, c["grid"])
        cv.rect(right_x + 200, y + 2, max(7, fam_bar * count / fam_top), 12,
                color, rx=6, opacity="0.85")
        cv.text(right_x + 200 + fam_bar + 12, y + 12, str(count), size=10.5,
                fill=color, weight="700")

    cv.footer("Mỗi rule đều có mẫu mã nguồn thật làm nó bắn, và với đa số là một mẫu "
              "an toàn tương ứng để chắc nó không kêu bừa.")
    return cv.render()


# --------------------------------------------------------------------------
# 5. Đối chiếu OWASP Top 10:2025
# --------------------------------------------------------------------------


def diagram_owasp(theme: str) -> str:
    counts = Counter(rule.owasp[0] for rule in all_rules())
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    # Mỗi mục một hàng 58px; thêm mục mới ( A06 cho lỗi bộ nhớ ) thì hình tự cao lên.
    cv = Canvas(76 + 58 * len(rows) + 26, theme)
    c = cv.c
    total = len(list(all_rules()))
    cv.title(
        "Đối chiếu OWASP Top 10:2025",
        "%d rule trải trên %d mục của bản 2025, mỗi rule giữ kèm nhãn 2021." % (total, len(rows)),
    )

    colors = {"A01": c["purple"], "A02": c["blue"], "A03": c["green"],
              "A05": c["red"], "A06": c["pink"], "A08": c["orange"]}
    legacy = {"A01": "A01:2021 · A10:2021 (SSRF)", "A02": "A05:2021",
              "A03": "A08:2021", "A05": "A03:2021", "A06": "A04:2021",
              "A08": "A08:2021"}

    top = max(count for _, count in rows)
    bar_x, bar_w = 470, 250
    for index, (tag, count) in enumerate(rows):
        y = 76 + index * 58
        code = tag.split(":")[0]
        name = tag.split("-", 1)[1]
        color = colors.get(code, c["muted"])
        cv.panel(PAD, y, W - PAD * 2, 48, color)
        cv.chip(PAD + 18, y + 14, code, color)
        cv.text(PAD + 76, y + 22, name, size=12, weight="700")
        cv.text(PAD + 76, y + 38, "nhãn 2021 đi kèm: " + legacy.get(code, ""),
                size=10, fill=c["muted"])
        cv.track(bar_x, y + 18, bar_w, 12, c["grid"])
        cv.rect(bar_x, y + 18, max(8, bar_w * count / top), 12, color, rx=6,
                opacity="0.85")
        cv.text(bar_x + bar_w + 12, y + 28, "%d rule" % count, size=11,
                fill=color, weight="700")

    cv.footer("Nhãn 2021 vẫn giữ nguyên đi kèm, vì mã rule và khoá JSON của bản 0.1.0 "
              "là giao diện ổn định nên chỉ được THÊM vào.")
    return cv.render()


# --------------------------------------------------------------------------
# 6. Độ phủ theo ngôn ngữ
# --------------------------------------------------------------------------

LANGUAGE_COVERAGE: Sequence[Tuple[str, str, int, str]] = (
    ("Python", "AST + luồng dữ liệu, xuyên file", 27, "full"),
    ("C / C++ / Objective-C", "6 luật bộ nhớ + lệnh, SQL, path, dlopen", 5, "native"),
    # Số họ rule của Java, Kotlin, Groovy, Scala, Go, C#, Swift, Dart, Elixir đếm từ
    # tests/test_language_family_coverage.py: mỗi họ có một mẫu bắt được thật.
    ("Java", "Servlet, Spring, Android", 14, "token"),
    ("Kotlin", "Spring, Ktor, Android", 14, "token"),
    ("Groovy / Jenkinsfile", "Grails, pipeline Jenkins", 14, "token"),
    ("C#", "ASP.NET Core, ADO.NET", 12, "token"),
    ("Swift", "Vapor, Hummingbird, iOS", 11, "token"),
    ("Elixir", "Phoenix, LiveView, Ecto", 11, "token"),
    ("JavaScript / TypeScript", "Express, Node", 9, "token"),
    ("Scala", "Play, Akka HTTP, Slick", 9, "token"),
    ("Go", "net/http, gin, echo", 8, "token"),
    ("PHP", "$_GET / $_POST / $_COOKIE", 8, "token"),
    ("Lua", "OpenResty ngx.*", 7, "token"),
    ("Dart", "shelf, Dart Frog, Flutter", 7, "token"),
    ("Rust", "actix, axum", 6, "token"),
    ("PowerShell", "script build, script CI", 6, "token"),
    ("Perl", "CGI $q->param", 5, "token"),
    ("Workflow GitHub Actions", ".github/workflows/*.yml", 4, "token"),
    ("Ruby", "Rails params", 4, "token"),
    ("Shell", "bash, sh", 2, "token"),
    ("package.json", "script vòng đời", 2, "token"),
)


def diagram_languages(theme: str) -> str:
    cv = Canvas(126 + len(LANGUAGE_COVERAGE) * 30, theme)
    c = cv.c
    cv.title(
        "Độ phủ trên %d ngôn ngữ và định dạng" % len(LANGUAGE_COVERAGE),
        "Python có parser AST nên sâu hơn hẳn; phần còn lại phân tích theo token.",
    )

    cv.chip(PAD, 64, "AST + luồng dữ liệu, theo được taint xuyên file", c["green"])
    cv.chip(PAD + 320, 64, "Lexer theo token, dừng ở ranh giới một hàm", c["blue"])
    cv.chip(PAD + 606, 64, "Cây lệnh C, luồng giải phóng theo nhánh", c["orange"])

    top = max(count for _, _, count, _ in LANGUAGE_COVERAGE)
    bar_x, bar_w = 420, 300
    for index, (name, detail, count, kind) in enumerate(LANGUAGE_COVERAGE):
        y = 100 + index * 30
        color = {"full": c["green"], "native": c["orange"]}.get(kind, c["blue"])
        if index % 2 == 0:
            cv.rect(PAD, y - 4, W - PAD * 2, 27, c["grid"], rx=7, opacity="0.16")
        cv.circle(PAD + 14, y + 9, 4, color, opacity="0.90")
        cv.text(PAD + 28, y + 13, name, size=11, weight="700")
        cv.text(PAD + 210, y + 13, detail, size=10, fill=c["muted"])
        cv.track(bar_x, y + 3, bar_w, 12, c["grid"])
        cv.rect(bar_x, y + 3, max(7, bar_w * count / top), 12, color, rx=6,
                opacity="0.85")
        suffix = " / %d rule" % len(list(all_rules())) if kind == "full" else " họ rule"
        cv.text(bar_x + bar_w + 12, y + 13, "%d%s" % (count, suffix), size=10.5,
                fill=color, weight="700")

    cv.footer("Con số của các ngôn ngữ quét theo token đếm theo HỌ rule bắt được, "
              "không phải theo số rule đăng ký.")
    return cv.render()


# --------------------------------------------------------------------------
# 7. Hai bộ phân tích đặt cạnh nhau
# --------------------------------------------------------------------------


def diagram_analyzers(theme: str) -> str:
    cv = Canvas(376, theme)
    c = cv.c
    cv.title(
        "Hai bộ phân tích, hai mức độ sâu",
        "Giá trị 'độ tin cậy' trong báo cáo phản ánh đúng khoảng chênh này.",
    )

    columns = [
        ("Python", c["green"], "AST đầy đủ", [
            ("Cách đọc mã", "dựng cây cú pháp đầy đủ"),
            ("Theo dữ liệu qua", "if, vòng lặp, try, và hàm khác"),
            ("Ranh giới tệp", "vượt qua được, có chỉ mục dự án"),
            ("Phủ được", "27 / %d rule" % len(list(all_rules()))),
            ("Hàm bọc tự viết", "tự học được, kể cả khác tệp"),
        ]),
        ("%d ngôn ngữ còn lại" % sum(kind == "token" for *_, kind in LANGUAGE_COVERAGE),
         c["blue"], "Lexer theo token", [
            ("Cách đọc mã", "tách token, lexer riêng từng ngôn ngữ"),
            ("Theo dữ liệu qua", "trong phạm vi một hàm"),
            ("Ranh giới tệp", "dừng lại ở đó"),
            ("Phủ được", "dạng nguồn → biến → sink"),
            ("Hàm bọc tự viết", "chỉ khi nằm cùng hàm"),
        ]),
    ]

    col_w, col_h = 414, 268
    for index, (name, color, badge, rows) in enumerate(columns):
        x = PAD + index * (col_w + 14)
        cv.panel(x, 72, col_w, col_h, color)
        cv.text(x + 20, 100, name, size=14, fill=color, weight="700")
        cv.chip(x + col_w - 148, 88, badge, color)
        for row_index, (key, value) in enumerate(rows):
            y = 130 + row_index * 42
            cv.text(x + 20, y, key, size=9.5, fill=c["muted"])
            cv.text(x + 20, y + 17, value, size=11.5, fill=c["text"],
                    opacity="0.92")
            if row_index < len(rows) - 1:
                cv.line(x + 20, y + 28, x + col_w - 20, y + 28, c["grid"],
                        sw=1, opacity="0.55")

    cv.footer("Không phải cứ nhiều ngôn ngữ là phủ đều: chỗ nào nông hơn thì báo cáo "
              "nói ra bằng độ tin cậy thấp hơn.")
    return cv.render()


# --------------------------------------------------------------------------

DIAGRAMS = {
    "taint-flow": diagram_taint_flow,
    "pipeline": diagram_pipeline,
    "benchmarks": diagram_benchmarks,
    "rules": diagram_rules,
    "owasp-2025": diagram_owasp,
    "languages": diagram_languages,
    "analyzers": diagram_analyzers,
}


def build() -> Dict[str, str]:
    """Toàn bộ tệp sẽ được ghi, dạng {tên tệp: nội dung}."""
    result: Dict[str, str] = {}
    for name, fn in sorted(DIAGRAMS.items()):
        for theme in ("light", "dark"):
            result["%s-%s.svg" % (name, theme)] = fn(theme)
    return result


def preview(files: Dict[str, str]) -> str:
    """Trang xem thử, và là chỗ DUY NHẤT có nền.

    Hình để trong suốt cho hợp với GitHub, nên muốn xem chúng đúng như người
    đọc sẽ thấy thì phải tự đặt lên hai nền thật. Trang này không đi vào README.
    """
    blocks = []
    for label, background, text_color, theme in (
        ("NỀN SÁNG", "#ffffff", "#1c2233", "light"),
        ("NỀN TỐI", "#0d1117", "#e9eef8", "dark"),
    ):
        parts = [
            "<div style='background:%s;padding:24px'>" % background,
            "<p style='font:600 13px system-ui;color:%s'>%s</p>" % (text_color, label),
        ]
        for name in sorted(files):
            if not name.endswith("-%s.svg" % theme):
                continue
            parts.append(
                "<h3 style='font:600 12px system-ui;color:%s;margin-top:22px'>%s</h3>"
                % (text_color, name)
            )
            parts.append(files[name])
        parts.append("</div>")
        blocks.append("".join(parts))
    return "".join(blocks)


def main(argv: Sequence[str] = ()) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    files = build()
    for name, content in sorted(files.items()):
        (OUT / name).write_text(content, encoding="utf-8", newline="\n")
    # Thông báo giữ nguyên ASCII: console mặc định của Windows chạy bảng mã
    # cp1258, và một dấu tiếng Việt ở đây là đủ để script chết ngay dòng cuối.
    print("generated %d SVG files -> %s" % (len(files), OUT.relative_to(ROOT).as_posix()))

    if "--preview" in argv:
        # Trang xem thử KHÔNG commit: nó chỉ để mở bằng trình duyệt mà soi hình
        # trên hai nền thật trước khi đẩy lên.
        target = ROOT / "diagram-preview.html"
        target.write_text(preview(files), encoding="utf-8", newline="\n")
        print("preview page -> %s" % target.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
