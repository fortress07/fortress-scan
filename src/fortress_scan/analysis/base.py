from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..core.budget import Budget
from ..core.config import Config
from ..core.model import Confidence, Finding, Severity, StepKind, TraceStep
from ..core.registry import get_rule
from ..security.redaction import PLACEHOLDER, redact
from ..security.text import make_snippet, normalize_newlines, split_lines


_MASK = "\x1f"


@dataclass(frozen=True)
class AnalysisUnit:
    relative_path: str
    language: str
    source: str
    config: Config
    degraded_encoding: bool = False
    lines: Tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        """Chuẩn hoá source về LF và suy ra lines từ chính nó.

        lines không nhận từ ngoài vào (init=False): mọi bộ phân tích đều đếm
        dòng theo "\\n" -- ast.parse, Tokenizer._line, find_code_points -- nên
        nếu để caller tự cắt dòng thì chỉ cần một chỗ dùng str.splitlines() là
        mảng dòng lệch khỏi số dòng rule engine báo, và snippet đính kèm
        finding sẽ trỏ sang đoạn mã khác. Buộc suy ra ở đây khiến trạng thái
        lệch đó không diễn đạt được nữa.
        """
        normalized = normalize_newlines(self.source)
        object.__setattr__(self, "source", normalized)
        object.__setattr__(self, "lines", split_lines(normalized))


class FindingBuilder:
    def __init__(self, unit: AnalysisUnit) -> None:
        self._unit = unit
        self._findings: Dict[Tuple[str, int, int, str], Finding] = {}
        # Vùng ( cột đầu, cột cuối ) trên từng dòng phải che trước khi đưa vào
        # snippet: giá trị của một secret mà bộ phân tích đã biết chính xác vị
        # trí. redact() chỉ đoán theo mẫu, nên không đủ cho
        # `ADMIN_PASSWORD_LINK = "..."` hay một khoá truyền thẳng vào hàm.
        self._masks: Dict[int, List[Tuple[int, int]]] = {}

    def mask(self, line: int, start: int, end: int) -> None:
        if end > start >= 0:
            self._masks.setdefault(line, []).append((start, end))

    def snippet_for(self, line: int) -> str:
        if 1 <= line <= len(self._unit.lines):
            text = self._unit.lines[line - 1]
            masks = self._masks.get(line)
            if not masks:
                return make_snippet(redact(text))
            # Che bằng một ký tự canh trước, rồi mới redact(): chèn thẳng
            # "[redacted]" thì mẫu `password = ...` của redact() lại ăn tiếp
            # vào chính chuỗi che đó.
            for start, end in sorted(masks, reverse=True):
                text = text[:start] + _MASK + text[end:]
            return make_snippet(redact(text).replace(_MASK, PLACEHOLDER))
        return ""

    def step(
        self,
        kind: StepKind,
        line: int,
        column: int,
        label: str,
        code: str = "",
        path: str = "",
    ) -> TraceStep:
        return TraceStep(
            kind=kind,
            line=line,
            column=column,
            label=make_snippet(label, 160),
            code=make_snippet(redact(code), 160) if code else self.snippet_for(line),
            path=path,
        )

    def add(
        self,
        rule_id: str,
        line: int,
        column: int,
        symbol: str,
        message: str,
        end_line: Optional[int] = None,
        end_column: Optional[int] = None,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        trace: Sequence[TraceStep] = (),
        tags: Sequence[str] = (),
        evidence: Sequence[str] = (),
    ) -> None:
        if not self._unit.config.rule_enabled(rule_id):
            return
        rule = get_rule(rule_id)
        resolved_severity = severity or rule.severity
        resolved_confidence = confidence or rule.confidence
        if resolved_severity < self._unit.config.min_severity:
            return
        if resolved_confidence < self._unit.config.min_confidence:
            return

        safe_line = max(1, line)
        key = (rule_id, safe_line, max(0, column), symbol)
        finding = Finding(
            rule_id=rule.id,
            title=rule.title,
            message=make_snippet(message, 400),
            severity=resolved_severity,
            confidence=resolved_confidence,
            category=rule.category,
            path=self._unit.relative_path,
            line=safe_line,
            column=max(0, column),
            end_line=max(safe_line, end_line or safe_line),
            end_column=max(0, end_column if end_column is not None else column),
            language=self._unit.language,
            snippet=self.snippet_for(safe_line),
            symbol=make_snippet(symbol, 120),
            cwe=rule.cwe,
            owasp=rule.owasp,
            remediation=rule.remediation,
            references=rule.references,
            trace=tuple(trace),
            tags=tuple(tags),
            evidence=tuple(evidence),
        )
        existing = self._findings.get(key)
        if existing is None or finding.sort_key < existing.sort_key:
            self._findings[key] = finding

    @property
    def findings(self) -> List[Finding]:
        best: Dict[Tuple[int, int, str], Finding] = {}
        for finding in self._findings.values():
            key = (finding.line, finding.column, finding.category.value)
            current = best.get(key)
            if current is None or finding.sort_key < current.sort_key:
                best[key] = finding
        return sorted(best.values(), key=lambda item: item.sort_key)


class Analyzer:
    name = "analyzer"
    languages: Tuple[str, ...] = ()

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        raise NotImplementedError
