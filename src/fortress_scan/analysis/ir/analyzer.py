"""Bộ phân tích truy vết xâm nhập: chạy cho MỌI tệp, như bộ dò unicode.

Không gắn vào một ngôn ngữ nào vì câu hỏi của nó không thuộc một ngôn ngữ nào.
Một ca xâm nhập để lại dấu ở hai chỗ cùng lúc -- một tệp .php trong thư mục
tải lên và một dòng trong cron.d -- nên bộ dò phải nhìn được cả hai trong cùng
một lượt quét, chứ không phải chờ người dùng bật đúng chế độ.
"""

from __future__ import annotations

from typing import List

from ...core.budget import Budget
from ...core.model import Finding
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from . import persistence, webshell


class IRAnalyzer(Analyzer):
    name = "ir-compromise"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        builder = FindingBuilder(unit)
        # Thứ tự có ý nghĩa với ngân sách chứ không với kết quả: phép nhận
        # hiện vật chỉ cắt chuỗi đường dẫn nên gần như miễn phí, còn bộ dò
        # webshell hạ chữ thường cả tệp. Chạy cái rẻ trước thì một tệp hiện
        # vật lớn không tiêu ngân sách vào phép dò không áp dụng cho nó.
        persistence.scan(unit, builder, budget)
        webshell.scan(unit, builder, budget)
        return builder.findings
