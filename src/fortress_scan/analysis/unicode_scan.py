from __future__ import annotations

import re
from typing import List, Set

from ..core.budget import Budget
from ..core.model import Finding, StepKind
from ..security.text import (
    AMBIGUOUS_LINE_BREAKS,
    BIDI_CONTROLS,
    INVISIBLE_CHARS,
    code_point_name,
    find_code_points,
    find_control_points,
    script_of,
)
from .base import Analyzer, AnalysisUnit, FindingBuilder

_IDENTIFIER = re.compile(r"[^\W\d]\w{1,80}", re.UNICODE)
_MAX_IDENTIFIER_REPORTS = 20
_ESCAPE_LETTERS = frozenset("abefnrtuvxUN")
_MAX_CONTROL_REPORTS = 20
# Budget.spend() chỉ soi đồng hồ mỗi 2048 lần gọi, tức là nó ngầm giả định mỗi
# lần gọi đều rẻ. Ở các vòng lặp này mỗi lần lại kèm một lần dựng snippet, nên
# một tệp nhồi hàng nghìn ký tự như vậy chạy quá xa mốc file_timeout_seconds
# trước khi chạm lần kiểm tra kế tiếp. Chặn số lượng báo cáo để giới hạn đó có
# hiệu lực thật; hai chục vị trí đầu đã quá đủ để kết luận tệp có vấn đề.
_MAX_CODE_POINT_REPORTS = 50
_CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK", "ARMENIAN"})


def _control_message(char: str) -> str:
    name = code_point_name(char)
    if char in AMBIGUOUS_LINE_BREAKS:
        return (
            "%s (U+%04X) được str.splitlines() và nhiều trình soạn thảo coi là xuống "
            "dòng, còn trình biên dịch thì không, nên dòng người review nhìn thấy có "
            "thể lệch khỏi dòng thực sự chạy" % (name, ord(char))
        )
    if char == "\x1b":
        return (
            "%s (U+%04X) mở đầu chuỗi điều khiển terminal, đủ để viết đè nội dung hiển "
            "thị trên console" % (name, ord(char))
        )
    return (
        "%s (U+%04X) là ký tự điều khiển vô hình, không có lý do chính đáng để nằm "
        "trong mã nguồn" % (name, ord(char))
    )


class UnicodeAnalyzer(Analyzer):
    name = "unicode-integrity"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        builder = FindingBuilder(unit)
        source = unit.source

        # Chạy trước và không phụ thuộc isascii(): \x0b, \x0c, \x1b và \x1c-\x1e
        # đều là ASCII, nên nhánh thoát sớm bên dưới từng bỏ sót toàn bộ chúng.
        self._check_controls(source, builder, budget)

        if source.isascii():
            return builder.findings

        for line, column, char in find_code_points(source, BIDI_CONTROLS)[
            :_MAX_CODE_POINT_REPORTS
        ]:
            budget.spend()
            builder.add(
                rule_id="FSB-UNI-001",
                line=line,
                column=column,
                symbol=code_point_name(char),
                message=(
                    "%s (U+%04X) đảo thứ tự hiển thị của dòng này mà không đổi cách trình "
                    "biên dịch đọc nó" % (code_point_name(char), ord(char))
                ),
                trace=(
                    builder.step(
                        StepKind.SINK, line, column, "ký tự điều khiển hai chiều"
                    ),
                ),
            )

        for line, column, char in find_code_points(source, INVISIBLE_CHARS)[
            :_MAX_CODE_POINT_REPORTS
        ]:
            budget.spend()
            builder.add(
                rule_id="FSB-UNI-002",
                line=line,
                column=column,
                symbol=code_point_name(char),
                message="%s (U+%04X) vô hình trong trình soạn thảo nhưng vẫn có ý nghĩa với trình biên dịch"
                % (code_point_name(char), ord(char)),
                trace=(
                    builder.step(StepKind.SINK, line, column, "ký tự vô hình"),
                ),
            )

        self._check_identifiers(unit, builder, budget)
        return builder.findings

    def _check_controls(
        self, source: str, builder: FindingBuilder, budget: Budget
    ) -> None:
        for line, column, char in find_control_points(source, _MAX_CONTROL_REPORTS):
            budget.spend()
            builder.add(
                rule_id="FSB-UNI-004",
                line=line,
                column=column,
                symbol=code_point_name(char),
                message=_control_message(char),
                trace=(
                    builder.step(StepKind.SINK, line, column, "ký tự điều khiển"),
                ),
            )

    def _check_identifiers(
        self, unit: AnalysisUnit, builder: FindingBuilder, budget: Budget
    ) -> None:
        reported: Set[str] = set()
        for index, text in enumerate(unit.lines, start=1):
            if text.isascii():
                continue
            budget.spend()
            for match in _IDENTIFIER.finditer(text):
                token = match.group(0)
                if match.start() > 0 and text[match.start() - 1] == "\\" and token[0] in _ESCAPE_LETTERS:
                    # `"\nПривет"`: chữ `n` thuộc dãy thoát, không thuộc từ tiếng Nga.
                    token = token[1:]
                if token.isascii() or token in reported:
                    continue
                scripts = {script_of(char) for char in token if char.isalpha()}
                scripts &= _CONFUSABLE_SCRIPTS
                if len(scripts) < 2:
                    continue
                reported.add(token)
                builder.add(
                    rule_id="FSB-UNI-003",
                    line=index,
                    column=match.start(),
                    symbol=token,
                    message="token %r trộn lẫn bảng chữ %s, các bảng này có những chữ trông giống hệt nhau"
                    % (token, " và ".join(sorted(scripts))),
                    trace=(
                        builder.step(
                            StepKind.SINK, index, match.start(), "token trộn nhiều hệ chữ"
                        ),
                    ),
                )
                if len(reported) >= _MAX_IDENTIFIER_REPORTS:
                    return
