"""Nhận webshell và cửa hậu đã được CẮM, bằng cách tính điểm trên cả tệp.

Vì sao không bắn theo dòng như các rule injection: bản thân một dòng
``eval($_POST['c'])`` không cho biết nó là lỗi của người viết hay là cửa hậu
của người lạ. Thứ phân biệt được nằm ở phần còn lại của tệp -- tệp dài bao
nhiêu, có khung dự án không, nằm ở thư mục nào, có lớp giải mã không, có cổng
mật khẩu không. Nên đơn vị kết luận ở đây là TỆP.

Mô hình trụ, mỗi trụ là một loại bằng chứng độc lập:

* ĐẦU VÀO -- tệp đọc dữ liệu request;
* SINK -- tệp có nơi thực thi;
* LÀM RỐI -- tệp giải mã chính nó trước khi chạy, hoặc gọi hàm qua tên ghép;
* DẤU CHE -- tắt báo lỗi, nằm trong thư mục tải lên, hoặc tên ngụy trang;
* CỔNG MẬT KHẨU -- so với một hằng băm cứng ngay cạnh sink.

ĐẦU VÀO cộng SINK một mình thì mô-đun này IM LẶNG: đó là injection, và
FSB-EXEC-001 cùng họ của nó đã bắt. Chỉ khi có thêm ít nhất một trụ nói về
cách tệp được cắm vào thì mới có kết luận "đã bị xâm nhập".
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import PurePath
from typing import List, Optional, Sequence, Tuple

from ...core.budget import Budget
from ...core.context import classify
from ...core.model import Confidence, PathContext, Severity, StepKind, TraceStep
from ..base import AnalysisUnit, FindingBuilder
from . import indicators, scrub

# Một webshell thật dài vài dòng tới vài trăm dòng. Quá mức này thì tệp là mã
# của dự án, và kết luận "có người cắm tệp này vào" không còn đứng được: phần
# dò injection theo dòng mới là thứ đúng việc.
MAX_WEBSHELL_LINES = 400

# Ngưỡng "tệp nhỏ": đủ nhỏ để toàn bộ nội dung là cửa hậu chứ không phải một
# mô-đun có cửa hậu lẫn trong đó.
SMALL_FILE_LINES = 60

# Dòng dài hơn mức này là mã đã nén hoặc payload dán vào, không phải mã người
# viết tay. Dùng để nhận gói một dòng, và để KHÔNG kết luận trên bundle.
PACKED_LINE_LENGTH = 2_000

# Chặn trên cho bản hạ chữ thường. Webshell nhỏ; một tệp lớn hơn mức này
# không phải webshell, và hạ chữ thường trọn tệp chỉ tốn công vô ích.
MAX_SCAN_BYTES = 512 * 1024


@dataclass(frozen=True)
class _Hit:
    marker: str
    line: int
    column: int


def _line_starts(source: str) -> Tuple[int, ...]:
    starts = [0]
    index = source.find("\n")
    while index != -1:
        starts.append(index + 1)
        index = source.find("\n", index + 1)
    return tuple(starts)


def _position(starts: Sequence[int], offset: int) -> Tuple[int, int]:
    line = bisect_right(starts, offset)
    return line, offset - starts[line - 1]


def _first(lowered: str, starts: Sequence[int], markers: Sequence[str]) -> Optional[_Hit]:
    """Dấu hiệu xuất hiện SỚM NHẤT trong tệp, không phải dấu hiệu đầu bảng.

    Lấy theo thứ tự bảng thì vị trí báo ra phụ thuộc vào cách sắp bảng chứ
    không phụ thuộc vào tệp, và người đọc mở đúng dòng đó lên sẽ thấy một chỗ
    không liên quan gì tới cái đứng trước nó.
    """
    best: Optional[_Hit] = None
    best_offset = -1
    for marker in markers:
        offset = lowered.find(marker)
        if offset == -1:
            continue
        if best is None or offset < best_offset:
            line, column = _position(starts, offset)
            best = _Hit(marker=marker, line=line, column=column)
            best_offset = offset
    return best


def _decoy_name(name: str) -> Optional[str]:
    """``anh.jpg.php`` -- phần mở rộng cuối quyết định bộ xử lý, phần đầu để lừa mắt."""
    suffixes = PurePath(name.lower()).suffixes
    if len(suffixes) < 2:
        return None
    if suffixes[-2] in indicators.DECOY_SUFFIXES:
        return name
    return None


class _Pillars:
    """Bằng chứng tìm được trên một tệp, chưa kết luận gì.

    `code` là bản đã xóa chuỗi và chú thích, `raw` là văn bản gốc. Hai bản có
    ĐÚNG cùng độ dài nên vị trí tìm được trên bản nào cũng trỏ về đúng một chỗ
    trong tệp gốc. Bảng nào soi bản nào, xem `indicators.py`.
    """

    def __init__(
        self, unit: AnalysisUnit, code: str, raw: str, starts: Sequence[int]
    ) -> None:
        language = unit.language
        self.input = _first(code, starts, indicators.INPUT_MARKERS.get(language, ())) or _first(
            raw, starts, indicators.INPUT_LITERAL_MARKERS
        )
        # Sink dò trên MÃ và chỉ trên mã. Đây là phép kiểm giữ cho cả mô hình
        # đứng được: mọi kết luận bên dưới đều đòi có sink, nên một tệp chỉ
        # NHẮC TỚI `eval(` trong một chuỗi -- bộ quy tắc WAF, luật YARA,
        # chính `indicators.py` bên cạnh -- không thể ra phát hiện nào.
        self.sink = _first(code, starts, indicators.SINK_MARKERS.get(language, ()))
        self.decoder = _first(code, starts, indicators.DECODER_MARKERS)
        self.indirection = _first(
            code, starts, indicators.INDIRECTION_MARKERS.get(language, ())
        )
        self.concealment = _first(
            code, starts, indicators.CONCEALMENT_MARKERS
        ) or _first(raw, starts, indicators.CONCEALMENT_LITERAL_MARKERS)
        self.auth_gate = _first(code, starts, indicators.AUTH_GATE_MARKERS)
        # Khung dự án chỉ dùng để HẠ mức, nên dò trên văn bản thô là hướng an
        # toàn: giấy phép và chú thích bản quyền nằm trong chú thích.
        self.scaffolding = _first(raw, starts, indicators.SCAFFOLDING_MARKERS)

        self.upload_directory = indicators.upload_directory_of(unit.relative_path)
        self.decoy = _decoy_name(PurePath(unit.relative_path).name)
        self.line_count = len(unit.lines)
        self.small = self.line_count <= SMALL_FILE_LINES
        self.packed = any(len(line) > PACKED_LINE_LENGTH for line in unit.lines)

    @property
    def obfuscated(self) -> bool:
        return self.decoder is not None or self.indirection is not None

    @property
    def planted(self) -> bool:
        """Có dấu hiệu tệp được CẮM vào cây mã, không phải được viết trong đó."""
        return (
            self.concealment is not None
            or self.upload_directory is not None
            or self.decoy is not None
        )


def _evidence(pillars: _Pillars) -> List[str]:
    reasons: List[str] = []
    if pillars.input is not None:
        reasons.append(
            "đọc dữ liệu request qua %r ở dòng %d" % (pillars.input.marker, pillars.input.line)
        )
    if pillars.sink is not None:
        reasons.append(
            "thực thi qua %r ở dòng %d" % (pillars.sink.marker, pillars.sink.line)
        )
    if pillars.decoder is not None:
        reasons.append(
            "giải mã chính nội dung mình sắp chạy bằng %r ở dòng %d"
            % (pillars.decoder.marker, pillars.decoder.line)
        )
    if pillars.indirection is not None:
        reasons.append(
            "gọi hàm qua tên ghép lúc chạy ( %r, dòng %d ) nên không có từ khoá để dò"
            % (pillars.indirection.marker, pillars.indirection.line)
        )
    if pillars.concealment is not None:
        reasons.append(
            "tắt hoặc nới cơ chế giám sát bằng %r ở dòng %d"
            % (pillars.concealment.marker, pillars.concealment.line)
        )
    if pillars.upload_directory is not None:
        reasons.append(
            "nằm trong %s, là thư mục máy chủ web ghi được chứ không phải nơi chứa mã dự án"
            % pillars.upload_directory
        )
    if pillars.decoy is not None:
        reasons.append(
            "tên %r có phần mở rộng ngụy trang: máy chủ chọn bộ xử lý theo phần cuối, "
            "người kiểm duyệt nhìn phần đầu" % pillars.decoy
        )
    if pillars.auth_gate is not None:
        reasons.append(
            "so dữ liệu vào với một hằng băm cứng trong tệp ( %r, dòng %d )"
            % (pillars.auth_gate.marker, pillars.auth_gate.line)
        )
    reasons.append(
        "cả tệp chỉ có %d dòng%s"
        % (
            pillars.line_count,
            "" if pillars.scaffolding is None else " nhưng có khung dự án quanh nó",
        )
    )
    return reasons


def _trace(builder: FindingBuilder, pillars: _Pillars) -> Tuple[TraceStep, ...]:
    steps: List[TraceStep] = []
    if pillars.input is not None:
        steps.append(
            builder.step(
                StepKind.SOURCE,
                pillars.input.line,
                pillars.input.column,
                "dữ liệu request đi vào từ đây",
            )
        )
    if pillars.decoder is not None:
        steps.append(
            builder.step(
                StepKind.PROPAGATION,
                pillars.decoder.line,
                pillars.decoder.column,
                "được giải mã ở đây",
            )
        )
    if pillars.auth_gate is not None:
        steps.append(
            builder.step(
                StepKind.SANITIZER,
                pillars.auth_gate.line,
                pillars.auth_gate.column,
                "cổng mật khẩu của chính cửa hậu",
            )
        )
    if pillars.sink is not None:
        steps.append(
            builder.step(
                StepKind.SINK,
                pillars.sink.line,
                pillars.sink.column,
                "chạy tới nơi thực thi",
            )
        )
    return tuple(steps)


def scan(unit: AnalysisUnit, builder: FindingBuilder, budget: Budget) -> None:
    if unit.language not in indicators.WEBSHELL_LANGUAGES:
        return
    if len(unit.lines) > MAX_WEBSHELL_LINES:
        return
    # Mã đi mượn và mã sinh tự động KHÔNG được kết luận là bị cắm. Ở đó phép
    # hạ một nấc của calibration là chưa đủ: câu "có người cắm tệp này vào"
    # sai hẳn về bản chất chứ không chỉ kém chắc, và trong một ca ứng cứu nó
    # đẩy người ta đi truy một vụ xâm nhập không có thật.
    if classify(unit.relative_path) in (PathContext.VENDORED, PathContext.GENERATED):
        return
    source = unit.source
    if len(source) > MAX_SCAN_BYTES:
        return

    budget.spend(len(unit.lines) or 1)
    raw = source.lower()
    code = scrub.scrub(source, unit.language).lower()
    starts = _line_starts(source)
    pillars = _Pillars(unit, code, raw, starts)

    if pillars.sink is None:
        return

    evidence = _evidence(pillars)
    trace = _trace(builder, pillars)
    anchor = pillars.sink

    if pillars.input is not None and pillars.obfuscated:
        builder.add(
            rule_id="FSB-IR-001",
            line=anchor.line,
            column=anchor.column,
            symbol=anchor.marker,
            message=(
                "tệp này nhận lệnh từ request, tự giải mã nội dung rồi thực thi; đó là "
                "hình dạng của một webshell đã được cắm, không phải một lỗi lập trình"
            ),
            confidence=Confidence.HIGH if pillars.small else Confidence.MEDIUM,
            trace=trace,
            evidence=evidence,
            tags=("ir", "webshell", "compromise"),
        )
        return

    if pillars.input is not None and pillars.planted and (pillars.small or pillars.packed):
        strong = pillars.upload_directory is not None or pillars.decoy is not None
        builder.add(
            rule_id="FSB-IR-001",
            line=anchor.line,
            column=anchor.column,
            symbol=anchor.marker,
            message=(
                "tệp nhỏ, không có khung dự án quanh nó, nhận lệnh từ request và thực "
                "thi ngay; vị trí cùng cách viết nói rằng nó được cắm vào chứ không "
                "được viết trong dự án"
            ),
            confidence=Confidence.HIGH if strong else Confidence.MEDIUM,
            trace=trace,
            evidence=evidence,
            tags=("ir", "webshell", "compromise"),
        )
        return

    if (
        pillars.input is not None
        and pillars.auth_gate is not None
        and pillars.small
        and pillars.scaffolding is None
    ):
        builder.add(
            rule_id="FSB-IR-003",
            line=anchor.line,
            column=anchor.column,
            symbol=anchor.marker,
            message=(
                "một cổng mật khẩu cứng đứng ngay trước nơi thực thi trong một tệp nhỏ "
                "không có khung dự án; đó là cách một cửa hậu tự giữ riêng cho người cắm nó"
            ),
            confidence=Confidence.MEDIUM,
            trace=trace,
            evidence=evidence,
            tags=("ir", "backdoor", "compromise"),
        )
        return

    if pillars.input is None and pillars.obfuscated and (pillars.small or pillars.packed):
        decoder = pillars.decoder or pillars.indirection
        builder.add(
            rule_id="FSB-IR-002",
            line=anchor.line,
            column=anchor.column,
            symbol=anchor.marker,
            message=(
                "nội dung bị làm rối được giải mã rồi thực thi ngay trong tệp này, "
                "không qua đầu vào nào; đó là hình dạng của một dropper, tầng chạy "
                "trước khi payload thật được ghi xuống"
            ),
            severity=Severity.HIGH if decoder is not None else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            trace=trace,
            evidence=evidence,
            tags=("ir", "dropper", "compromise"),
        )
