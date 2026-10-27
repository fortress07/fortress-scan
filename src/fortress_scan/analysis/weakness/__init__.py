"""Điểm yếu không cần nguồn dữ liệu bẩn: mật mã, TLS, secret viết cứng.

Bộ phân tích taint trả lời "dữ liệu từ ngoài có tới được chỗ nguy hiểm không".
Ở đây câu hỏi khác: CHÍNH lời gọi đã sai -- thuật toán bị phá, khoá nằm trong
mã, cờ xác minh chứng chỉ bị tắt. Python được đọc trên AST; các ngôn ngữ còn
lại đọc trên chuỗi token của bộ lexer chung, nên chuỗi và chú thích không bao
giờ bị nhầm thành mã.
"""

from __future__ import annotations

from typing import List

from ...core.budget import Budget, BudgetExceeded
from ...core.model import Finding
from ...languages import MANIFEST, PYTHON, WORKFLOW
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from .python import scan_python
from .tokens import scan_tokens


class WeaknessAnalyzer(Analyzer):
    name = "weakness"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        if unit.language in (MANIFEST, WORKFLOW):
            return []
        builder = FindingBuilder(unit)
        try:
            if unit.language == PYTHON:
                scan_python(unit, budget, builder)
            else:
                scan_tokens(unit, budget, builder)
        except BudgetExceeded:
            pass
        return builder.findings


__all__ = ["WeaknessAnalyzer"]
