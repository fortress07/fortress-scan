"""Dựng chỉ mục xuyên file: tách sự thật từng tệp rồi tính summary tới điểm bất động.

Thứ tự:

1. Tách hàm / lớp / import / export của mọi tệp JS, TS, Java, Go.
2. Đọc tệp không phải mã ( template, mapper, cấu hình, tsconfig, go.mod ).
3. Nối liên kết toàn dự án ( lớp hiện thực, handler của route, mapper SQL ).
4. Tính summary từng hàm, lặp lại tới khi không summary nào đổi nữa hoặc
   chạm số vòng tối đa. Mỗi vòng dùng summary mới nhất ngay khi có ( kiểu
   Gauss-Seidel ), nên chuỗi gọi dài vẫn hội tụ sau vài vòng.
5. Một lượt dò riêng cho những tệp đẩy job vào hàng đợi: biết hàng đợi nào
   nhận dữ liệu bẩn thì nơi xử lý job ở tệp khác mới có nguồn để báo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...languages import GO, JAVA
from ..base import AnalysisUnit
from ..generic.analyzer import GenericAnalyzer
from ..generic.lexer import Token, tokenize
from ..generic.profiles import spec_for
from . import extract_go, extract_java, extract_js
from .context import apply_queue_events
from .model import FileFacts
from .project import JS_FAMILY, SUPPORTED, XProject

MAX_ROUNDS = 5
# Giữ token trong RAM giữa các vòng tới mức này; quá thì đọc và tách lại.
_TOKEN_CACHE_LIMIT = 4_000_000
# Một tệp nhiều hàm hơn mức này chỉ được tính summary ở vòng một.
#
# Mã người viết tay không tới mức đó: tệp lớn nhất của juice-shop có 32 hàm,
# của OWASP BenchmarkJava có 35. Vượt hàng trăm là thư viện đi kèm hoặc bundle
# sinh ra ( jquery.js 400, bootstrap.bundle.js 322 ), và lặp 5 vòng trên chúng
# chiếm gần hết thời gian quét mà không đổi lấy phát hiện nào: lỗi của ứng
# dụng nằm ở mã của ứng dụng, không nằm trong chuỗi gọi nội bộ của jQuery.
# Lượt báo cáo vẫn đọc tệp đó như mọi tệp khác, và lời gọi từ ngoài vào nó vẫn
# thấy summary vòng một; chỉ chuỗi gọi nhiều chặng ĐI XUYÊN QUA nó là không
# được nối.
_MAX_FIXPOINT_FUNCTIONS = 150

_ANALYZER = GenericAnalyzer()


@dataclass
class SourceFile:
    relative: str
    language: str
    read: Callable[[], Optional[str]]


@dataclass
class BuildReport:
    rounds: int = 0
    converged: bool = True
    failed: List[str] = field(default_factory=list)
    # Tệp chỉ được tính summary ở vòng một vì quá nhiều hàm.
    shallow: List[str] = field(default_factory=list)


def extract_facts(relative: str, language: str, tokens: List[Token]) -> FileFacts:
    if language in JS_FAMILY:
        return extract_js.extract(relative, language, tokens)
    if language == JAVA:
        return extract_java.extract(relative, language, tokens)
    if language == GO:
        return extract_go.extract(relative, language, tokens)
    return FileFacts(path=relative, language=language)


def build(
    files: Sequence[SourceFile],
    artifact_texts: Sequence[Tuple[str, Callable[[], Optional[str]]]],
    config,
) -> Tuple[XProject, BuildReport]:
    project = XProject()
    report = BuildReport()
    cache: Dict[str, List[Token]] = {}
    cached_tokens = 0
    sources: Dict[str, SourceFile] = {}

    def tokens_of(item: SourceFile) -> Optional[List[Token]]:
        nonlocal cached_tokens
        cached = cache.get(item.relative)
        if cached is not None:
            return cached
        text = item.read()
        if text is None:
            return None
        spec = spec_for(item.language)
        if spec is None:
            return None
        budget = Budget(config.token_budget, config.file_timeout_seconds)
        try:
            unit = AnalysisUnit(relative_path=item.relative, language=item.language, source=text, config=config)
            tokens = tokenize(unit.source, spec.lexer, budget)
        except BudgetExceeded:
            report.failed.append(item.relative)
            return None
        if cached_tokens + len(tokens) <= _TOKEN_CACHE_LIMIT:
            cache[item.relative] = tokens
            cached_tokens += len(tokens)
        return tokens

    for item in files:
        if item.language not in SUPPORTED:
            continue
        tokens = tokens_of(item)
        if tokens is None:
            continue
        try:
            facts = extract_facts(item.relative, item.language, tokens)
        except (RecursionError, IndexError, ValueError):
            report.failed.append(item.relative)
            continue
        project.add_file(facts)
        sources[item.relative] = item

    for relative, read in artifact_texts:
        text = read()
        if text is not None:
            try:
                project.add_artifact(relative, text)
            except (RecursionError, ValueError):
                continue

    project.finalize()

    concrete: Dict[str, List] = {}
    for path, facts in project.facts.items():
        functions = [f for f in facts.functions if f.name and not f.abstract]
        if functions:
            concrete[path] = functions
    order = sorted(concrete)
    report.shallow = sorted(
        path for path, functions in concrete.items() if len(functions) > _MAX_FIXPOINT_FUNCTIONS
    )
    shallow = frozenset(report.shallow)
    for round_number in range(1, MAX_ROUNDS + 1):
        changed = False
        for path in order:
            if round_number > 1 and path in shallow:
                continue
            item = sources[path]
            tokens = tokens_of(item)
            if tokens is None:
                continue
            unit = AnalysisUnit(relative_path=path, language=item.language, source="", config=config)
            try:
                declared = _declared(unit, tokens, Budget(config.token_budget, config.file_timeout_seconds))
            except BudgetExceeded:
                continue
            for function in concrete[path]:
                budget = Budget(config.token_budget, config.file_timeout_seconds)
                summary = _ANALYZER.summarize(unit, tokens, function, project, budget, declared)
                if project.set_summary(function, summary):
                    changed = True
        report.rounds = round_number
        if not changed:
            break
    else:
        report.converged = False
    project.stats.rounds = report.rounds
    project.stats.summarized = len(project.summaries)
    project.stats.with_effects = sum(1 for summary in project.summaries.values() if not summary.empty)

    # Hàng đợi: nơi đẩy job bẩn ở tệp này làm nguồn cho nơi xử lý ở tệp khác.
    for path, facts in sorted(project.facts.items()):
        if not facts.queue_producers:
            continue
        item = sources.get(path)
        if item is None:
            continue
        text = item.read()
        if text is None:
            continue
        unit = AnalysisUnit(relative_path=path, language=item.language, source=text, config=config)
        budget = Budget(config.token_budget, config.file_timeout_seconds)
        events = _ANALYZER.probe(unit, budget, project)
        apply_queue_events(project, path, events)
    return project, report


def _declared(unit: AnalysisUnit, tokens: Sequence[Token], budget: Budget):
    spec = spec_for(unit.language)
    if spec is None:
        return set()
    from ..generic.analyzer import _Analysis

    analysis = _Analysis(unit, spec, budget)
    analysis._collect_declarations(tokens)
    return analysis.declared
