from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Sequence, Set, Tuple, TypeVar

from ..analysis.base import AnalysisUnit
from ..analysis.generic.analyzer import GenericAnalyzer
from ..analysis.manifest import ManifestAnalyzer
from ..analysis.python.analyzer import PythonAnalyzer, UnparsableSource
from ..analysis.python.project import MAX_INDEX_FUNCTIONS, ProjectIndex
from ..analysis.unicode_scan import UnicodeAnalyzer
from ..analysis.workflow import WorkflowAnalyzer
from ..analysis.native.memory import NativeMemoryAnalyzer
from ..languages import C, CPP, MANIFEST, OBJC, PYTHON, WORKFLOW
from ..security import paths as safe_paths
from . import baseline as baseline_module
from . import calibration as calibration_module
from . import diffscope
from . import suppression as suppression_module
from .budget import Budget, BudgetExceeded
from .config import Config
from .discovery import Discovery, DiscoveredFile, FileChangedDuringScan, read_source
from .model import Finding, ScanError, ScanNotice, ScanResult, ScanStats

_PYTHON_ANALYZER = PythonAnalyzer()
_GENERIC_ANALYZER = GenericAnalyzer()
_UNICODE_ANALYZER = UnicodeAnalyzer()
_MANIFEST_ANALYZER = ManifestAnalyzer()
_WORKFLOW_ANALYZER = WorkflowAnalyzer()
_NATIVE_MEMORY_ANALYZER = NativeMemoryAnalyzer()

# Bộ phân tích chạy THÊM sau bộ chính của ngôn ngữ, mỗi bộ một hạn mức riêng.
# Mã native vừa có injection ( system(), SQL ) do bộ token chung lo, vừa có
# lỗi bộ nhớ là thứ chỉ bộ đọc cấu trúc C mới thấy.
_EXTRA_ANALYZERS = {
    C: (_NATIVE_MEMORY_ANALYZER,),
    CPP: (_NATIVE_MEMORY_ANALYZER,),
    OBJC: (_NATIVE_MEMORY_ANALYZER,),
}

_MAX_FINDINGS = 20_000

# Phân tích xuyên file giữ hai vòng thu thập trong RAM nên phải có chặn trên
# riêng; vượt mức thì tắt hẳn và nói rõ thay vì im lặng quét nông.
_MAX_CROSS_FILE_FILES = 2000

_T = TypeVar("_T")


def scan(
    target: str,
    config: Optional[Config] = None,
    baseline_fingerprints: Optional[Set[str]] = None,
    notices: Optional[Sequence[ScanNotice]] = None,
) -> ScanResult:
    settings = config or Config()
    root = safe_paths.resolve_root(target)
    started = time.monotonic()

    coverage_notices: List[ScanNotice] = list(notices or ())

    discovery = Discovery(root, settings)
    discovered = list(discovery.walk())

    stats = ScanStats(files_discovered=len(discovered))
    errors: List[ScanError] = list(discovery.errors)
    findings: List[Finding] = []
    suppressed = 0

    outcomes, phase_notices = _run(discovered, settings)
    coverage_notices.extend(phase_notices)
    for outcome in outcomes:
        if outcome.error is not None:
            errors.append(outcome.error)
        if outcome.analyzed:
            stats.files_analyzed += 1
            stats.bytes_analyzed += outcome.size
            stats.languages[outcome.language] = stats.languages.get(outcome.language, 0) + 1
        suppressed += outcome.suppressed
        findings.extend(outcome.findings)

    stats.files_skipped = discovery.skipped + (len(discovered) - stats.files_analyzed)
    stats.directories_excluded = discovery.excluded_directories_hit

    # Bỏ qua liên kết là hành vi mặc định và đúng, nhưng nó vẫn là một mảng mã
    # chưa từng được soi. Nói ra, đừng để người đọc tự đoán từ một con số.
    # Cùng loại với cảnh báo của .fortress-scan.json: quy tắc do người viết cây
    # thư mục đặt, và nó gỡ mã khỏi lượt quét.
    if discovery.ignored_files or discovery.ignored_directories:
        coverage_notices.append(
            ScanNotice(
                kind="ignore-files-applied",
                summary=(
                    "tệp bỏ qua trong cây được quét (.gitignore / .fortress-scanignore) "
                    "đã gỡ %d tệp mã nguồn và %d thư mục khỏi lượt quét"
                    % (discovery.ignored_files, discovery.ignored_directories)
                ),
                details=(
                    "chạy lại với --no-vcs-ignore --no-ignore-files nếu không tin cây này",
                ),
            )
        )

    # Cạn hạn mức so khớp nghĩa là từ một điểm nào đó trở đi, quy tắc ignore
    # ngừng có hiệu lực. Không giấu gì cả là hướng an toàn, nhưng nó làm phạm
    # vi quét khác hẳn thứ người viết repo mô tả, nên phải nói ra.
    if discovery.ignore_budget_exhausted:
        coverage_notices.append(
            ScanNotice(
                kind="ignore-budget-exhausted",
                summary=(
                    "quy tắc bỏ qua trong cây được quét tốn quá nhiều công so khớp "
                    "nên đã bị ngừng áp dụng giữa chừng; từ đó trở đi không tệp nào "
                    "bị ẩn khỏi lượt quét"
                ),
                details=(
                    "một .gitignore hay .fortress-scanignore dựng riêng để làm chậm "
                    "lượt quét sẽ chạm vào đây; chạy lại với --no-vcs-ignore "
                    "--no-ignore-files nếu không tin cây này",
                ),
            )
        )

    if discovery.skipped_links:
        coverage_notices.append(
            ScanNotice(
                kind="links-skipped",
                summary=(
                    "đã bỏ qua %d liên kết; mã nằm sau chúng chưa được phân tích"
                    % discovery.skipped_links
                ),
                details=("bật --follow-symlinks để đi theo liên kết nằm trong thư mục quét",),
            )
        )

    findings.sort(key=lambda item: item.sort_key)
    if len(findings) > _MAX_FINDINGS:
        errors.append(
            ScanError(
                path=".",
                reason="finding-limit-reached",
                detail="đã cắt bớt còn %d phát hiện" % _MAX_FINDINGS,
            )
        )
        findings = findings[:_MAX_FINDINGS]

    baselined = 0
    if baseline_fingerprints:
        findings, baselined = baseline_module.apply(findings, baseline_fingerprints)

    out_of_diff = 0
    if settings.changed_lines is not None:
        findings, out_of_diff, diff_notices = _apply_diff_scope(findings, settings.changed_lines)
        coverage_notices.extend(diff_notices)

    stats.duration_seconds = time.monotonic() - started
    return ScanResult(
        root=str(root),
        findings=findings,
        errors=errors,
        notices=coverage_notices,
        stats=stats,
        suppressed=suppressed,
        baselined=baselined,
        out_of_diff=out_of_diff,
    )


def _apply_diff_scope(
    findings: Sequence[Finding], changed: diffscope.ChangedLines
) -> Tuple[List[Finding], int, List[ScanNotice]]:
    """Giữ lại phát hiện có ít nhất một bước chạm vào dòng đã thay đổi.

    Lọc ở đây chứ không lọc lúc duyệt cây là có chủ ý: một tệp KHÔNG đổi vẫn
    phải được phân tích, vì sink cũ của nó có thể vừa được một tệp mới đổi gọi
    tới. Bỏ qua tệp ngay từ đầu thì đúng loại lỗ hổng mà pull request thật hay
    tạo ra -- nối một handler mới vào một helper cũ -- không bao giờ bị bắt.
    """
    kept: List[Finding] = []
    dropped = 0
    for finding in findings:
        if diffscope.touches_change(finding, changed):
            kept.append(finding)
        else:
            dropped += 1
    notices: List[ScanNotice] = []
    if dropped or changed.truncated:
        details = [
            "bỏ --diff để xem toàn bộ phát hiện của cây mã",
        ]
        if changed.truncated:
            details.append(
                "patch vượt hạn mức nên phần cuối của nó không được đọc; "
                "một số dòng vừa đổi có thể đang bị coi là không đổi"
            )
        notices.append(
            ScanNotice(
                kind="diff-scope-applied",
                summary=(
                    "chỉ báo phát hiện chạm vào %d dòng đã thay đổi trong %d tệp; "
                    "%d phát hiện khác đã có sẵn trong cây mã bị giữ lại ngoài báo cáo"
                    % (changed.line_count, len(changed.paths), dropped)
                ),
                details=tuple(details),
            )
        )
    return kept, dropped, notices


def scan_source(
    source: str,
    language: str,
    relative_path: str = "<memory>",
    config: Optional[Config] = None,
) -> List[Finding]:
    settings = config or Config()
    unit = AnalysisUnit(
        relative_path=relative_path,
        language=language,
        source=source,
        config=settings,
    )
    findings, _ = _analyze_unit(unit, settings)
    if settings.honor_inline_suppressions:
        index = suppression_module.SuppressionIndex.from_lines(unit.lines, unit.language)
        findings, _ = suppression_module.partition(findings, index)
    findings = calibration_module.apply(findings, settings)
    return sorted(findings, key=lambda item: item.sort_key)


class _Outcome:
    __slots__ = ("findings", "error", "analyzed", "size", "language", "suppressed")

    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self.error: Optional[ScanError] = None
        self.analyzed = False
        self.size = 0
        self.language = ""
        self.suppressed = 0


def _run(
    discovered: Sequence[DiscoveredFile], config: Config
) -> Tuple[List[_Outcome], List[ScanNotice]]:
    """Phân tích mọi tệp, dựng trước chỉ mục xuyên file cho phần Python.

    Pha thu thập chạy hai vòng: vòng một tính summary từng tệp độc lập, vòng
    hai tính lại với chỉ mục vòng một trong tay để hàm trung gian ghi nhận
    được cả sink nằm ở tệp thứ ba. Sau đó mọi tệp mới vào pha báo cáo.
    """
    notices: List[ScanNotice] = []
    python_files = [item for item in discovered if item.language == PYTHON]
    project: Optional[ProjectIndex] = None
    if python_files and config.cross_file_analysis:
        if len(python_files) > _MAX_CROSS_FILE_FILES:
            notices.append(
                ScanNotice(
                    kind="cross-file-analysis-skipped",
                    summary=(
                        "dự án có %d tệp Python nên vượt chặn trên %d; lượt quét "
                        "này không theo dõi dữ liệu xuyên file"
                        % (len(python_files), _MAX_CROSS_FILE_FILES)
                    ),
                    details=(
                        "chạy lại với --jobs thấp hơn hoặc tách quét từng thư mục "
                        "con nếu cần đường đi xuyên file",
                    ),
                )
            )
        else:
            project = _build_project(python_files, config)
            if project.full:
                notices.append(
                    ScanNotice(
                        kind="cross-file-analysis-reduced",
                        summary=(
                            "dự án có nhiều hơn %d hàm nên chỉ mục xuyên file bị "
                            "cắt bớt; một phần đường đi xuyên file có thể thiếu"
                            % MAX_INDEX_FUNCTIONS
                        ),
                        details=("giới hạn bảo vệ bộ nhớ của chính lượt quét",),
                    )
                )
    outcomes = _map_files(
        discovered, config, lambda item: _analyze_file(item, config, project)
    )
    return outcomes, notices


def _build_project(files: Sequence[DiscoveredFile], config: Config) -> ProjectIndex:
    first = ProjectIndex()
    _collect_into(first, files, config, None)
    second = ProjectIndex()
    _collect_into(second, files, config, first)
    return second


def _collect_into(
    index: ProjectIndex,
    files: Sequence[DiscoveredFile],
    config: Config,
    project: Optional[ProjectIndex],
) -> None:
    collected = _map_files(files, config, lambda item: _collect_one(item, config, project))
    for item in collected:
        if item is not None:
            index.register(*item)


def _collect_one(
    discovered: DiscoveredFile,
    config: Config,
    project: Optional[ProjectIndex],
):
    try:
        source, _ = read_source(discovered.path, discovered.language, discovered.identity)
    except (FileChangedDuringScan, OSError, MemoryError):
        return None
    budget = Budget(config.node_budget, config.file_timeout_seconds)
    collected = _PYTHON_ANALYZER.collect_module(
        source, discovered.relative, budget, project
    )
    if collected is None:
        return None
    functions, summaries = collected
    return discovered.relative, functions, summaries


def _map_files(
    discovered: Sequence[DiscoveredFile], config: Config, worker: Callable[[DiscoveredFile], _T]
) -> List[_T]:
    if config.jobs <= 1 or len(discovered) < 4:
        return [worker(item) for item in discovered]
    workers = min(config.jobs, 32, len(discovered))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(worker, discovered))


def _analyze_file(
    discovered: DiscoveredFile, config: Config, project: Optional[ProjectIndex] = None
) -> _Outcome:
    outcome = _Outcome()
    outcome.language = discovered.language
    outcome.size = discovered.size
    try:
        source, degraded = read_source(
            discovered.path, discovered.language, discovered.identity
        )
    except FileChangedDuringScan:
        outcome.error = ScanError(
            path=discovered.relative,
            reason="file-changed-during-scan",
            detail="tệp bị thay thế sau khi được liệt kê nên không được phân tích",
        )
        return outcome
    except OSError as exc:
        outcome.error = ScanError(
            path=discovered.relative, reason="unreadable-file", detail=exc.strerror or ""
        )
        return outcome
    except MemoryError:
        outcome.error = ScanError(
            path=discovered.relative, reason="file-too-large", detail="không đủ bộ nhớ"
        )
        return outcome

    unit = AnalysisUnit(
        relative_path=discovered.relative,
        language=discovered.language,
        source=source,
        config=config,
        degraded_encoding=degraded,
    )
    try:
        findings, failure = _analyze_unit(unit, config, project)
    except RecursionError:
        outcome.error = ScanError(
            path=discovered.relative, reason="nesting-too-deep", detail="chạm giới hạn đệ quy"
        )
        return outcome

    if failure is not None:
        outcome.error = ScanError(
            path=discovered.relative, reason=failure[0], detail=failure[1][:200]
        )

    outcome.analyzed = True
    if config.honor_inline_suppressions:
        index = suppression_module.SuppressionIndex.from_lines(unit.lines, unit.language)
        if index.overflowed and outcome.error is None:
            outcome.error = ScanError(
                path=discovered.relative,
                reason="suppression-scan-too-complex",
                detail=(
                    "vượt hạn mức dò chú thích nên mọi chỉ thị fortress-scan: ignore "
                    "trong tệp này bị bỏ; không phát hiện nào bị ẩn"
                ),
            )
        findings, outcome.suppressed = suppression_module.partition(findings, index)
    # Hiệu chỉnh chạy SAU khi ẩn theo chú thích: một phát hiện đã bị người viết
    # mã tắt đi thì không cần ai cân lại độ tin cậy cho nó nữa, và tính bằng
    # chứng cho thứ sẽ bị vứt chỉ tốn công.
    outcome.findings = calibration_module.apply(findings, config)
    return outcome


def _analyze_unit(
    unit: AnalysisUnit, config: Config, project: Optional[ProjectIndex] = None
) -> Tuple[List[Finding], Optional[Tuple[str, str]]]:
    findings: List[Finding] = []
    failure: Optional[Tuple[str, str]] = None

    unicode_budget = Budget(config.node_budget, config.file_timeout_seconds)
    try:
        findings.extend(_UNICODE_ANALYZER.analyze(unit, unicode_budget))
    except BudgetExceeded:
        pass

    if unit.language == PYTHON:
        budget = Budget(config.node_budget, config.file_timeout_seconds)
        analyzer = _PYTHON_ANALYZER
    elif unit.language == MANIFEST:
        budget = Budget(config.node_budget, config.file_timeout_seconds)
        analyzer = _MANIFEST_ANALYZER
    elif unit.language == WORKFLOW:
        budget = Budget(config.node_budget, config.file_timeout_seconds)
        analyzer = _WORKFLOW_ANALYZER
    else:
        budget = Budget(config.token_budget, config.file_timeout_seconds)
        analyzer = _GENERIC_ANALYZER

    try:
        if unit.language == PYTHON:
            findings.extend(analyzer.analyze(unit, budget, project))
        else:
            findings.extend(analyzer.analyze(unit, budget))
    except UnparsableSource as exc:
        failure = ("parse-error", str(exc))
    except BudgetExceeded as exc:
        failure = ("budget-exceeded", str(exc))

    extra_exhausted = False
    for extra in _EXTRA_ANALYZERS.get(unit.language, ()):
        # Bộ đọc cấu trúc C đi qua mỗi token vài lần ( thu thập hằng, tách hàm,
        # dựng cây, rồi các lượt luật ), nên hạn mức tính theo kích thước tệp:
        # vẫn tuyến tính, vẫn chặn được tệp cố tình phình to.
        extra_budget = Budget(
            max(config.token_budget, 4 * len(unit.source)), config.file_timeout_seconds
        )
        try:
            findings.extend(extra.analyze(unit, extra_budget))
        except BudgetExceeded:
            extra_exhausted = True
        extra_exhausted = extra_exhausted or extra_budget.exhausted

    if failure is None and (budget.exhausted or unicode_budget.exhausted or extra_exhausted):
        failure = (
            "budget-exceeded",
            "tệp quá lớn hoặc quá phức tạp, phân tích chưa hoàn tất nên kết quả có thể thiếu",
        )

    return findings, failure
