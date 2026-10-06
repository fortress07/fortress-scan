from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...core.config import Config
from ...core.model import Category, Confidence, Finding, StepKind
from ...languages import PYTHON
from ...security.text import neutralize
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from . import specs
from .imports import ImportResolver, attribute_parts, dotted_name, module_names, package_of
from .taint import (
    CONSTANT,
    MAX_ENTRIES,
    UNKNOWN,
    CallableRef,
    Environment,
    Taint,
    Value,
    combine,
    copy_environment,
    environments_equal,
    limit_callables,
    literal,
    merge_environments,
    merge_taint,
    merge_values,
    ordered_callables,
    union_callables,
)

if TYPE_CHECKING:  # tránh vòng import: project.py nhập FunctionInfo từ đây
    from .project import ProjectIndex

SUMMARY_MODE = "summary"
REPORT_MODE = "report"

_MAX_SUMMARY_ROUNDS = 4
# Chuỗi kế thừa / thuộc tính lồng nhau đi sâu tới đâu thì dừng.
_MAX_CLASS_DEPTH = 8
_MAX_LOOP_ITERATIONS = 2
_MAX_BLOCK_DEPTH = 48
_SELF_NAMES = frozenset({"self", "cls", "mcs"})

# Lớp cơ sở của module enum. `StrEnum` chỉ có từ 3.11 nhưng tên thì vẫn xuất
# hiện trong mã nhắm bản mới, và bảng này chỉ so tên nên không cần bản nào.
_ENUM_BASES = frozenset({"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag", "ReprEnum"})

_EVERY_CATEGORY: FrozenSet[Category] = frozenset(Category)


class UnparsableSource(Exception):
    pass


@dataclass(frozen=True)
class SinkHit:
    parameter: str
    rule_id: str
    category: Category
    line: int
    column: int
    symbol: str
    description: str
    # Tệp mà `line`/`column` thuộc về; rỗng nghĩa là cùng tệp với hàm đã ghi
    # lại sink này. Thiếu trường này thì dòng của một sink ở tệp khác bị chép
    # vào summary rồi báo theo hệ tọa độ của tệp GỌI: đối chiếu stdlib từng ra
    # một phát hiện ở logging/config.py dòng 1339 trong khi tệp đó chỉ có 1066
    # dòng - một vị trí không tồn tại.
    origin_path: str = ""


@dataclass(frozen=True)
class ReturnEffect:
    cleared: FrozenSet[Category] = frozenset()
    sanitized: bool = False

    def merged(self, other: "ReturnEffect") -> "ReturnEffect":
        return ReturnEffect(
            cleared=self.cleared & other.cleared,
            sanitized=self.sanitized and other.sanitized,
        )


@dataclass
class Summary:
    returns: Dict[str, ReturnEffect] = field(default_factory=dict)
    sinks: FrozenSet[SinkHit] = frozenset()
    # Hàm factory: lớp của đối tượng được trả về ( `return ItemService()` ).
    instance: str = ""


@dataclass
class ClassInfo:
    """Lớp khai báo trong tệp: lớp cha và kiểu đoán được của từng thuộc tính."""

    qualname: str
    key: str
    bases: Tuple[str, ...] = ()
    # thuộc tính -> tên lớp ( đã phân giải theo import của tệp ) của giá trị
    # được gán: `self.repo = repo or ItemRepository()` -> ("app.db.ItemRepository",)
    attributes: Dict[str, Tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class ClassRecord:
    """Lớp như chỉ mục dự án thấy nó: mọi tên đã quy về tên đầy đủ."""

    qualname: str
    bases: Tuple[str, ...]
    attributes: Tuple[Tuple[str, Tuple[str, ...]], ...]
    # Phương thức khai báo ngay trong lớp, kể cả phương thức vô hại: lớp con
    # ghi đè `run` bằng bản an toàn thì không được lấy `run` của lớp cha.
    methods: FrozenSet[str]


@dataclass
class CollectedModule:
    """Kết quả pha thu thập của một tệp, đủ để đăng ký và để biết khi nào phải tính lại."""

    functions: Dict[str, "FunctionInfo"]
    summaries: Dict[str, "Summary"]
    classes: Tuple[ClassRecord, ...]
    aliases: Dict[str, str]
    # Mọi câu đã hỏi chỉ mục dự án cùng câu trả lời nhận được. Phân tích là
    # tất định theo mã nguồn và các câu trả lời này, nên vòng sau chỉ cần
    # tính lại tệp nào có ít nhất một câu trả lời đổi khác.
    answers: Dict[Tuple[str, ...], object]


@dataclass
class FunctionInfo:
    node: ast.AST
    qualname: str
    simple_name: str
    parameters: Tuple[str, ...]
    handler_sources: Dict[str, specs.SourceSpec] = field(default_factory=dict)
    # Tham số mà framework đã ép kiểu trước khi hàm chạy ( bộ chuyển kiểu
    # trong route, chú thích kiểu của FastAPI ). Khác "chưa biết gì": ở đây
    # ta biết giá trị KHÔNG mang nổi ký tự phá cú pháp.
    typed_parameters: FrozenSet[str] = frozenset()
    # Hàm của tệp khác mang sẵn summary và nguồn gốc của nó; hàm cục bộ thì
    # hai trường này trống và summary được tra ở module.summaries như trước.
    summary: Optional["Summary"] = None
    origin_path: str = ""


def _parse_filename(relative_path: str) -> str:
    r"""Tên tệp đưa cho ast.parse, đã trung hoà ký tự điều khiển.

    Tên này KHÔNG chỉ nằm trong thông báo lỗi mà ta tự bắt: CPython in nó
    thẳng ra stderr khi mã được quét sinh ra một SyntaxWarning ( ví dụ
    `x = "\d"` ), và đường đó không đi qua _stderr() nên không ai trung hoà
    hộ. Tên tệp thì do người viết cây thư mục đặt.

    Hệ quả là một tệp đặt tên kèm chuỗi thoát ANSI ghi đè được nội dung
    terminal của người chạy, còn U+202E ( RIGHT-TO-LEFT OVERRIDE, hợp lệ trong
    tên tệp trên cả Windows lẫn Linux ) đảo ngược đoạn tên hiển thị. Đúng thứ
    mà họ rule FSB-UNI của chính công cụ này tồn tại để bắt, nên nó không được
    phép đi ra từ chính công cụ.
    """
    return neutralize(relative_path)


class PythonAnalyzer(Analyzer):
    name = "python-taint"
    languages = (PYTHON,)

    def analyze(
        self,
        unit: AnalysisUnit,
        budget: Budget,
        project: Optional["ProjectIndex"] = None,
    ) -> List[Finding]:
        try:
            tree = ast.parse(unit.source, filename=_parse_filename(unit.relative_path))
        except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
            raise UnparsableSource(str(exc)) from exc
        module = ModuleAnalysis(unit, budget, project)
        return module.run(tree)

    def collect_module(
        self,
        source: str,
        relative_path: str,
        budget: Budget,
        project: Optional["ProjectIndex"] = None,
    ) -> Optional[CollectedModule]:
        """Chỉ chạy pha thu thập: hàm, lớp và summary, không báo cáo gì.

        Trả về None nếu mã không parse được -- pha báo cáo sẽ tự ghi lỗi
        parse cho tệp này, pha thu thập không cần nói lại.
        """
        try:
            tree = ast.parse(source, filename=_parse_filename(relative_path))
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return None
        unit = AnalysisUnit(
            relative_path=relative_path,
            language=PYTHON,
            source=source,
            config=Config(),
        )
        module = ModuleAnalysis(unit, budget, project)
        module.collect(tree)
        # Bỏ nút AST: kết quả của mọi tệp được giữ qua nhiều vòng, cây cú pháp
        # của cả dự án thì không cần nằm trong bộ nhớ cùng lúc.
        functions = {
            qualname: FunctionInfo(
                node=None,
                qualname=qualname,
                simple_name=info.simple_name,
                parameters=info.parameters,
            )
            for qualname, info in module.functions.items()
        }
        return CollectedModule(
            functions=functions,
            summaries=dict(module.summaries),
            classes=module.class_records(),
            aliases=module.imports.aliases(),
            answers=module.answers,
        )


class ModuleAnalysis:
    def __init__(
        self,
        unit: AnalysisUnit,
        budget: Budget,
        project: Optional["ProjectIndex"] = None,
    ) -> None:
        self.unit = unit
        self.budget = budget
        self.builder = FindingBuilder(unit)
        self.project = project
        names = module_names(unit.relative_path)
        # Tên module dài nhất, làm tiền tố cho tên đầy đủ của lớp trong tệp.
        self.module_name = names[0] if names else ""
        self.imports = ImportResolver(package_of(unit.relative_path))
        self.classes: Dict[str, ClassInfo] = {}
        self._classes_by_key: Dict[str, ClassInfo] = {}
        self.functions: Dict[str, FunctionInfo] = {}
        self.functions_by_name: Dict[str, List[FunctionInfo]] = {}
        self.summaries: Dict[str, Summary] = {}
        # Lớp enum do chính tệp này khai báo. `Mau(gia_tri)` ném ValueError khi
        # gia_tri không phải một thành viên, nên giá trị đi ra khỏi đó luôn là
        # một trong những hằng đã viết sẵn trong thân lớp -- đúng định nghĩa
        # của một phép kiểm danh sách cho phép, chỉ là viết bằng cú pháp khác.
        self.enum_classes: Set[str] = set()
        self._name_values: Dict[str, Value] = {}
        self._attribute_refs: Dict[str, FrozenSet[CallableRef]] = {}
        self.answers: Dict[Tuple[str, ...], object] = {}

    def name_value(self, qualname: str) -> Value:
        """Bare names repeat constantly; hand out one shared immutable value."""
        value = self._name_values.get(qualname)
        if value is None:
            value = Value(callables=frozenset({CallableRef(qualname=qualname)}))
            self._name_values[qualname] = value
        return value

    def attribute_refs(self, dotted: str, attribute: str) -> FrozenSet[CallableRef]:
        # ``dotted`` always ends with ``.<attribute>``, so it alone is a key —
        # this runs on every attribute load, no tuple allocation to spare.
        cached = self._attribute_refs.get(dotted)
        if cached is None:
            receiver = dotted[: len(dotted) - len(attribute) - 1]
            cached = frozenset(
                {
                    CallableRef(
                        qualname=self.imports.resolve(dotted),
                        attribute=attribute,
                        receiver=receiver or None,
                    )
                }
            )
            self._attribute_refs[dotted] = cached
        return cached

    def run(self, tree: ast.Module) -> List[Finding]:
        globals_env = self.collect(tree)
        try:
            self._report(tree, globals_env)
        except BudgetExceeded:
            pass
        except RecursionError:
            pass
        return self.builder.findings

    def collect(self, tree: ast.Module) -> Environment:
        """Pha thu thập: imports, hàm, biến toàn cục và summary từng hàm.

        Engine gọi riêng pha này cho mọi tệp Python để dựng chỉ mục xuyên
        file, rồi gọi pha báo cáo với chỉ mục đó trong tay.
        """
        self.imports.collect(tree)
        self._collect_functions(tree)
        globals_env: Environment = {}
        try:
            globals_env = self._collect_globals(tree)
            self._compute_summaries(globals_env)
        except BudgetExceeded:
            pass
        except RecursionError:
            pass
        return globals_env

    def _describe_function(self, node: ast.AST, qualname: str) -> FunctionInfo:
        """Mọi thứ biết được về một hàm ngay tại chỗ nó được định nghĩa."""
        # CHỈ handler của framework mới được hưởng phép ép kiểu. Chú thích kiểu
        # trong Python không được ép lúc chạy, nên `def f(x: int)` của một hàm
        # thường chỉ là lời hứa của tác giả -- tin nó là tự tạo ra điểm mù. Với
        # route handler thì khác: Flask trả 404 và FastAPI trả 422 TRƯỚC khi
        # thân hàm chạy, nên ở đó phép ép kiểu là thật.
        typed: FrozenSet[str] = frozenset()
        if _is_route_handler(node, self.imports):
            typed = _framework_typed_parameters(node, self.imports)
        return FunctionInfo(
            node=node,
            qualname=qualname,
            simple_name=node.name,
            parameters=_parameter_names(node.args),
            handler_sources=_handler_sources(node, self.imports),
            typed_parameters=typed,
        )

    def _collect_functions(self, tree: ast.Module) -> None:
        stack: List[Tuple[ast.AST, str]] = [(tree, "")]
        while stack:
            node, prefix = stack.pop()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = "%s.%s" % (prefix, child.name) if prefix else child.name
                    info = self._describe_function(child, qualname)
                    self.functions[qualname] = info
                    self.functions_by_name.setdefault(child.name, []).append(info)
                    self.summaries[qualname] = Summary()
                    stack.append((child, qualname))
                elif isinstance(child, ast.ClassDef):
                    qualname = "%s.%s" % (prefix, child.name) if prefix else child.name
                    if self._is_enum_class(child):
                        self.enum_classes.add(qualname)
                        self.enum_classes.add(child.name)
                    key = "%s.%s" % (self.module_name, qualname) if self.module_name else qualname
                    bases = tuple(
                        name for name in (self.imports.qualname_of(base) for base in child.bases) if name
                    )
                    info = ClassInfo(
                        qualname=qualname,
                        key=key,
                        bases=bases,
                        attributes=_attribute_types(child, self.imports),
                    )
                    self.classes[qualname] = info
                    self._classes_by_key[key] = info
                    stack.append((child, qualname))

    def _is_enum_class(self, node: ast.ClassDef) -> bool:
        """Lớp này có kế thừa một lớp cơ sở của module enum không.

        Chỉ nhìn lớp cơ sở VIẾT TRỰC TIẾP, không lần theo chuỗi kế thừa nhiều
        tầng: một lớp trung gian ở tệp khác thì tại đây không đọc được, và
        đoán bừa ở chỗ này là tự tay tắt một phát hiện thật.
        """
        for base in node.bases:
            resolved = self.imports.qualname_of(base) or ""
            tail = resolved.rsplit(".", 1)[-1]
            if tail in _ENUM_BASES and (resolved == tail or resolved.startswith("enum.")):
                return True
        return False

    def _collect_globals(self, tree: ast.Module) -> Environment:
        evaluator = Evaluator(self, None, SUMMARY_MODE, {})
        return evaluator.execute_module(tree)

    def _compute_summaries(self, globals_env: Environment) -> None:
        for _ in range(_MAX_SUMMARY_ROUNDS):
            changed = False
            for qualname, info in self.functions.items():
                evaluator = Evaluator(self, info, SUMMARY_MODE, globals_env)
                evaluator.execute_function(synthetic=True)
                summary = Summary(
                    returns=dict(evaluator.returned_parameters),
                    sinks=frozenset(evaluator.recorded_sinks),
                    instance=evaluator.returned_instance,
                )
                if summary != self.summaries.get(qualname):
                    self.summaries[qualname] = summary
                    changed = True
            if not changed:
                return

    def _report(self, tree: ast.Module, globals_env: Environment) -> None:
        evaluator = Evaluator(self, None, REPORT_MODE, {})
        evaluator.execute_module(tree)
        for info in self.functions.values():
            worker = Evaluator(self, info, REPORT_MODE, globals_env)
            worker.execute_function(synthetic=False)

    # ------------------------------------------------------------ classes
    def _ask(self, query: Tuple[str, ...]):
        """Hỏi chỉ mục dự án và ghi lại câu trả lời ( xem CollectedModule.answers )."""
        if self.project is None:
            return None
        answer = self.project.ask(query)
        self.answers[query] = answer
        return answer

    def class_key(self, dotted: Optional[str]) -> str:
        """Tên đầy đủ của lớp mà `dotted` ( đã qua import ) trỏ tới, hoặc ""."""
        if not dotted:
            return ""
        local = self.classes.get(dotted)
        if local is not None:
            return local.key
        return self._ask(("class", dotted)) or ""

    def find_method(self, key: str, name: str, depth: int = 0) -> Optional[FunctionInfo]:
        """Phương thức `name` của lớp `key`, tìm cả lên các lớp cha."""
        if depth > _MAX_CLASS_DEPTH:
            return None
        local = self._classes_by_key.get(key)
        if local is None:
            return self._ask(("method", key, name))
        info = self.functions.get("%s.%s" % (local.qualname, name))
        if info is not None:
            return info
        for base in local.bases:
            base_key = self.class_key(base)
            if base_key and base_key != key:
                found = self.find_method(base_key, name, depth + 1)
                if found is not None:
                    return found
        return None

    def attribute_type(self, key: str, attribute: str, depth: int = 0) -> str:
        """Lớp của `obj.attribute` khi `obj` thuộc lớp `key`, hoặc ""."""
        if depth > _MAX_CLASS_DEPTH:
            return ""
        local = self._classes_by_key.get(key)
        if local is None:
            return self._ask(("attribute", key, attribute)) or ""
        for candidate in local.attributes.get(attribute, ()):
            found = self.class_key(candidate) or self.instance_of(candidate)
            if found:
                return found
        for base in local.bases:
            base_key = self.class_key(base)
            if base_key and base_key != key:
                found = self.attribute_type(base_key, attribute, depth + 1)
                if found:
                    return found
        return ""

    def instance_of(self, dotted: str) -> str:
        """Lớp của đối tượng mà hàm factory `dotted` trả về, hoặc ""."""
        function = self.lookup_function(dotted)
        if function is None:
            return ""
        summary = function.summary or self.summaries.get(function.qualname)
        return summary.instance if summary is not None else ""

    def class_records(self) -> Tuple[ClassRecord, ...]:
        """Lớp của tệp cho chỉ mục dự án, tên lớp cha / kiểu thuộc tính đã quy về tên đầy đủ."""
        prefix = self.module_name + "." if self.module_name else ""

        def canonical(name: str) -> str:
            local = self.classes.get(name)
            if local is not None:
                return local.key
            if name in self.functions:
                return prefix + name
            return name

        methods: Dict[str, Set[str]] = {}
        for qualname in self.functions:
            owner, _, simple = qualname.rpartition(".")
            if owner in self.classes:
                methods.setdefault(owner, set()).add(simple)
        return tuple(
            ClassRecord(
                qualname=qualname,
                bases=tuple(canonical(base) for base in info.bases),
                attributes=tuple(
                    (attribute, tuple(canonical(item) for item in items))
                    for attribute, items in sorted(info.attributes.items())
                ),
                methods=frozenset(methods.get(qualname, ())),
            )
            for qualname, info in sorted(self.classes.items())
        )

    def lookup_function(
        self, qualname: Optional[str], *, bare_name_call: bool = False
    ) -> Optional[FunctionInfo]:
        if not qualname:
            return None
        info = self.functions.get(qualname)
        if info is not None:
            return info
        simple = qualname.rsplit(".", 1)[-1]
        candidates = self.functions_by_name.get(simple)
        if candidates and len(candidates) == 1:
            return candidates[0]
        # Khớp tên trần qua chỉ mục dự án chỉ dành cho lời gọi `ten_ham(...)`
        # không qua attribute: `cp.read(...)` là lời gọi phương thức trên một
        # đối tượng vô danh, bắt nó về `def read(...)` của module khác là gán
        # nhầm nguồn gốc - và cái giá là cắt oan cả chuỗi taint thật.
        return self._ask(("function", qualname, "simple" if bare_name_call else ""))


class Evaluator:
    def __init__(
        self,
        module: ModuleAnalysis,
        function: Optional[FunctionInfo],
        mode: str,
        globals_env: Environment,
    ) -> None:
        self.module = module
        self.function = function
        self.mode = mode
        self.globals_env = globals_env
        self.returned_parameters: Dict[str, ReturnEffect] = {}
        self.recorded_sinks: Set[SinkHit] = set()
        self.returned_instance = ""
        self._depth = 0

    @property
    def builder(self) -> FindingBuilder:
        return self.module.builder

    @property
    def imports(self) -> ImportResolver:
        return self.module.imports

    def execute_module(self, tree: ast.Module) -> Environment:
        env: Environment = {}
        self._execute_block(tree.body, env)
        return env

    def execute_function(self, synthetic: bool) -> None:
        info = self.function
        if info is None:
            return
        node = info.node
        env: Environment = copy_environment(self.globals_env)
        owner = self.module.classes.get(info.qualname.rpartition(".")[0])
        if owner is not None and info.parameters and info.parameters[0] in _SELF_NAMES:
            # `self` chỉ mang kiểu của lớp, để `self.repo.find(x)` và
            # `self._where(x)` tìm được phương thức ở tệp khác. Nó KHÔNG được
            # coi là tham số bẩn: bẩn cả đối tượng thì mọi thuộc tính hằng của
            # nó cũng bẩn theo, và `Service(request.args["id"]).cleanup()` sẽ
            # báo nhầm lệnh xóa thư mục tạm viết cứng trong lớp.
            env[info.parameters[0]] = Value(instance=owner.key)
        for name in info.parameters:
            if name in _SELF_NAMES:
                continue
            if synthetic:
                env[name] = Value(
                    taint=Taint(
                        labels=frozenset({"parameter %s" % name}),
                        confidence=Confidence.HIGH,
                        parameters=frozenset({name}),
                        trace=(),
                    )
                )
            else:
                source = info.handler_sources.get(name)
                if source is None:
                    # Tham số đã được framework ép kiểu không chỉ là "không
                    # phải nguồn bẩn" -- nó là giá trị ĐÃ BIẾT là vô hại. Để
                    # nó ở UNKNOWN thì rule "nhận giá trị không phải hằng"
                    # vẫn kêu, và kêu vào đúng cách viết chặt nhất.
                    env[name] = (
                        Value(constant=False, sanitized=True)
                        if name in info.typed_parameters
                        else UNKNOWN
                    )
                    continue
                step = self.builder.step(
                    StepKind.SOURCE,
                    getattr(node, "lineno", 1),
                    getattr(node, "col_offset", 0),
                    "%s đi vào qua tham số %s" % (source.label, name),
                )
                env[name] = Value(
                    taint=Taint(
                        labels=frozenset({source.label}),
                        confidence=source.confidence,
                        trace=(step,),
                        low_signal=source.low_signal,
                    )
                )
        self._execute_block(getattr(node, "body", []), env)

    def _execute_block(self, statements: Sequence[ast.stmt], env: Environment) -> Environment:
        if self._depth > _MAX_BLOCK_DEPTH:
            return env
        self._depth += 1
        try:
            for statement in statements:
                self.module.budget.spend()
                env = self._execute(statement, env)
        finally:
            self._depth -= 1
        return env

    def _execute(self, node: ast.stmt, env: Environment) -> Environment:
        if isinstance(node, ast.Assign):
            value = self._eval(node.value, env)
            for target in node.targets:
                self._bind(target, value, env)
            return env
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._bind(node.target, self._eval(node.value, env), env)
            return env
        if isinstance(node, ast.AugAssign):
            addition = self._eval(node.value, env)
            existing = self._eval(node.target, env)
            self._bind(node.target, merge_values(existing, addition), env)
            return env
        if isinstance(node, ast.Expr):
            self._eval(node.value, env)
            return env
        if isinstance(node, ast.Return):
            if node.value is not None:
                returned = self._eval(node.value, env)
                self._record_return(returned)
                if returned.instance and not self.returned_instance:
                    self.returned_instance = returned.instance
            return env
        if isinstance(node, ast.If):
            return self._execute_if(node, env)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            return self._execute_loop_for(node, env)
        if isinstance(node, ast.While):
            return self._execute_loop_while(node, env)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self._eval(item.context_expr, env)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, value, env)
            return self._execute_block(node.body, env)
        if isinstance(node, ast.Try):
            return self._execute_try(node, env)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in getattr(node, "decorator_list", []):
                self._eval(decorator, env)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Giá trị mặc định chạy NGAY tại chỗ định nghĩa, trong scope
                # đang đứng -- không phải lúc gọi hàm. Bỏ qua chúng thì
                # `def f(cb=eval(request.args.get("v"))): ...` không sinh ra
                # phát hiện nào, dù dòng đó nổ ngay khi module được import.
                for _, default in _lambda_parameters(node.args):
                    if default is not None:
                        self._eval(default, env)
                return env
            # Thân class cũng chạy lúc định nghĩa, nên `class C: x = eval(...)`
            # là một sink thật. Chạy trên BẢN SAO môi trường rồi bỏ đi: những
            # tên gán trong thân class thành thuộc tính của class chứ không rơi
            # vào scope bao ngoài, nên globals_env phải giữ nguyên. Method bên
            # trong vẫn được phân tích riêng qua self.functions như trước.
            self._execute_block(node.body, copy_environment(env))
            return env
        if isinstance(node, ast.Raise):
            for child in (node.exc, node.cause):
                if child is not None:
                    self._eval(child, env)
            return env
        if isinstance(node, ast.Assert):
            self._eval(node.test, env)
            if node.msg is not None:
                self._eval(node.msg, env)
            # `assert ten in CHO_PHEP` nói đúng điều mà `if ten not in CHO_PHEP:
            # raise` nói, và là cách viết rất phổ biến trong mã nội bộ.
            #
            # `python -O` gỡ bỏ assert nên phép kiểm biến mất trong bản chạy
            # tối ưu. Đó là khuyết điểm về cách viết, không phải một đường
            # injection đã dựng được, nên nó không đi vào phát hiện này.
            positive, _ = _guarded_names(node.test)
            _apply_guards(env, positive)
            return env
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
            return env
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.Pass)):
            return env
        if isinstance(node, (ast.Break, ast.Continue)):
            return env
        match_node = getattr(ast, "Match", None)
        if match_node is not None and isinstance(node, match_node):
            return self._execute_match(node, env)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._eval(child, env)
        return env

    def _execute_if(self, node: ast.If, env: Environment) -> Environment:
        self._eval(node.test, env)
        positive, negative = _guarded_names(node.test)
        true_env = copy_environment(env)
        false_env = copy_environment(env)
        _apply_guards(true_env, positive)
        _apply_guards(false_env, negative)
        true_env = self._execute_block(node.body, true_env)
        false_env = self._execute_block(node.orelse, false_env)
        if _terminates(node.body):
            return false_env
        if node.orelse and _terminates(node.orelse):
            return true_env
        return merge_environments(true_env, false_env)

    def _execute_loop_for(self, node: ast.stmt, env: Environment) -> Environment:
        iterable = self._eval(node.iter, env)
        element = Value(taint=iterable.taint, constant=iterable.constant)
        self._bind(node.target, element, env)
        current = env
        for _ in range(_MAX_LOOP_ITERATIONS):
            candidate = self._execute_block(node.body, copy_environment(current))
            merged = merge_environments(current, candidate)
            if environments_equal(merged, current):
                current = merged
                break
            current = merged
        current = self._execute_block(node.orelse, current)
        return current

    def _execute_loop_while(self, node: ast.While, env: Environment) -> Environment:
        self._eval(node.test, env)
        current = env
        for _ in range(_MAX_LOOP_ITERATIONS):
            candidate = self._execute_block(node.body, copy_environment(current))
            merged = merge_environments(current, candidate)
            if environments_equal(merged, current):
                current = merged
                break
            current = merged
        return self._execute_block(node.orelse, current)

    def _execute_try(self, node: ast.Try, env: Environment) -> Environment:
        body_env = self._execute_block(node.body, copy_environment(env))
        merged = body_env
        for handler in node.handlers:
            handler_env = copy_environment(env)
            if handler.name:
                handler_env[handler.name] = UNKNOWN
            merged = merge_environments(merged, self._execute_block(handler.body, handler_env))
        merged = self._execute_block(node.orelse, merged)
        return self._execute_block(node.finalbody, merged)

    def _execute_match(self, node: ast.stmt, env: Environment) -> Environment:
        subject = self._eval(node.subject, env)
        merged: Optional[Environment] = None
        for case in node.cases:
            case_env = copy_environment(env)
            for name in _match_capture_names(case.pattern):
                case_env[name] = Value(taint=subject.taint, constant=subject.constant)
            if case.guard is not None:
                self._eval(case.guard, case_env)
            case_env = self._execute_block(case.body, case_env)
            merged = case_env if merged is None else merge_environments(merged, case_env)
        return merged if merged is not None else env

    def _bind(self, target: ast.expr, value: Value, env: Environment) -> None:
        if isinstance(target, ast.Name):
            if value.taint is not None:
                step = self.builder.step(
                    StepKind.PROPAGATION,
                    target.lineno,
                    target.col_offset,
                    "chảy vào biến %s" % target.id,
                )
                value = value.with_step(step)
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            elements = value.elements
            for index, item in enumerate(target.elts):
                if isinstance(item, ast.Starred):
                    self._bind(item.value, value, env)
                elif index < len(elements):
                    self._bind(item, elements[index], env)
                else:
                    self._bind(item, Value(taint=value.taint, constant=value.constant), env)
            return
        if isinstance(target, ast.Attribute):
            dotted = dotted_name(target)
            if dotted:
                env[dotted] = value
            return
        if isinstance(target, ast.Subscript):
            base = target.value
            if isinstance(base, ast.Name):
                existing = env.get(base.id, UNKNOWN)
                env[base.id] = merge_values(existing, value)
            self._check_header_store(target, value, env)
            return
        if isinstance(target, ast.Starred):
            self._bind(target.value, value, env)

    def _check_header_store(
        self, target: ast.Subscript, value: Value, env: Environment
    ) -> None:
        """Gán ``resp.headers[k] = v`` là sink ghi header HTTP của phản hồi.

        Chỉ khớp khi container là một thuộc tính tên ``headers``: ghi subscript
        vào dict thường quá phổ biến để từ đó suy ra đây là header. Vị trí
        ``response['X'] = v`` của Django không có chữ ``headers`` nên không
        bắt được -- nói rõ trong README thay vì đoán mò.
        """
        base = target.value
        if not isinstance(base, ast.Attribute) or base.attr != "headers":
            return
        key = (
            self._eval(target.slice, env)
            if not isinstance(target.slice, ast.Slice)
            else UNKNOWN
        )
        for candidate in (key, value):
            self._flag(
                rule_id="FSB-HDR-001",
                dynamic_rule=None,
                node=target,
                category=Category.HTTP_HEADER,
                symbol="headers[...] = ...",
                description="ghi header HTTP của phản hồi",
                value=candidate,
            )

    def _eval(self, node: Optional[ast.expr], env: Environment) -> Value:
        if node is None:
            return CONSTANT
        self.module.budget.spend()

        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return literal(node.value)
            if isinstance(node.value, bytes):
                return literal(node.value.decode("utf-8", errors="replace"))
            return CONSTANT
        if isinstance(node, ast.Name):
            return self._eval_name(node, env)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(node, env)
        if isinstance(node, ast.Call):
            return self._eval_call(node, env)
        if isinstance(node, ast.JoinedStr):
            parts = [self._eval(value, env) for value in node.values]
            return combine(*parts) if parts else CONSTANT
        if isinstance(node, ast.FormattedValue):
            value = self._eval(node.value, env)
            return Value(taint=value.taint, constant=value.constant, text_parts=value.text_parts)
        if isinstance(node, ast.BinOp):
            left = self._eval(node.left, env)
            right = self._eval(node.right, env)
            return combine(left, right)
        if isinstance(node, ast.BoolOp):
            values = [self._eval(item, env) for item in node.values]
            if not values:
                return CONSTANT
            combined = combine(*values)
            # `repo or ItemRepository()`: giá trị ra là một trong các vế.
            instance = next((item.instance for item in values if item.instance), "")
            return replace(combined, instance=instance) if instance else combined
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, env)
        if isinstance(node, ast.Compare):
            self._eval(node.left, env)
            for comparator in node.comparators:
                self._eval(comparator, env)
            return CONSTANT
        if isinstance(node, ast.IfExp):
            self._eval(node.test, env)
            return merge_values(self._eval(node.body, env), self._eval(node.orelse, env))
        if isinstance(node, ast.Subscript):
            return self._eval_subscript(node, env)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            elements = tuple(self._eval(item, env) for item in node.elts)
            aggregate = combine(*elements) if elements else CONSTANT
            return Value(
                taint=aggregate.taint,
                constant=aggregate.constant,
                text_parts=aggregate.text_parts,
                elements=elements,
                is_sequence=True,
                sanitized=aggregate.sanitized,
                callables=union_callables(elements),
            )
        if isinstance(node, ast.Dict):
            return self._eval_dict(node, env)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._eval_comprehension(node, env, (node.elt,))
        if isinstance(node, ast.DictComp):
            return self._eval_comprehension(node, env, (node.key, node.value))
        if isinstance(node, ast.Starred):
            return self._eval(node.value, env)
        if isinstance(node, ast.Await):
            return self._eval(node.value, env)
        if isinstance(node, ast.NamedExpr):
            value = self._eval(node.value, env)
            self._bind(node.target, value, env)
            return value
        if isinstance(node, ast.Lambda):
            return self._eval_lambda(node, env)
        if isinstance(node, ast.Slice):
            for part in (node.lower, node.upper, node.step):
                self._eval(part, env)
            return CONSTANT
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._eval(child, env)
        return UNKNOWN

    def _eval_name(self, node: ast.Name, env: Environment) -> Value:
        if node.id in env:
            return env[node.id]
        resolved = self.imports.resolve(node.id)
        source = specs.SOURCE_ATTRIBUTES.get(resolved)
        if source is not None and self._source_enabled(source):
            return self._tainted(node, source)
        if node.id.isupper() and len(node.id) > 1:
            return CONSTANT
        return self.module.name_value(resolved)

    def _eval_attribute(self, node: ast.Attribute, env: Environment) -> Value:
        dotted = dotted_name(node)
        if dotted is not None:
            if dotted in env:
                return env[dotted]
            resolved = self.imports.resolve(dotted)
            source = specs.SOURCE_ATTRIBUTES.get(resolved)
            if source is not None and self._source_enabled(source):
                return self._tainted(node, source)
            request_source = self._request_member_source(resolved, node.attr)
            if request_source is not None:
                return self._tainted(node, request_source)
        base = self._eval(node.value, env)
        callables: FrozenSet[CallableRef] = frozenset()
        if dotted is not None:
            callables = self.module.attribute_refs(dotted, node.attr)
        return Value(
            taint=base.taint,
            constant=base.constant,
            text_parts=base.text_parts,
            sanitized=base.sanitized,
            callables=callables,
            instance=self.module.attribute_type(base.instance, node.attr) if base.instance else "",
        )

    def _eval_subscript(self, node: ast.Subscript, env: Environment) -> Value:
        base = self._eval(node.value, env)
        self._eval(node.slice, env)
        return Value(
            taint=base.taint,
            constant=base.constant,
            text_parts=base.text_parts,
            sanitized=base.sanitized,
            callables=_indexed_callables(base, node.slice),
        )

    def _eval_dict(self, node: ast.Dict, env: Environment) -> Value:
        values: List[Value] = []
        entries: List[Tuple[str, FrozenSet[CallableRef]]] = []
        for key, item in zip(node.keys, node.values):
            key_value = self._eval(key, env) if key is not None else CONSTANT
            item_value = self._eval(item, env)
            values.append(key_value)
            values.append(item_value)
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                entries.append((key.value, item_value.callables))
                if key.value in specs.NOSQL_OPERATOR_KEYS and item_value.taint is not None:
                    self._flag(
                        rule_id="FSB-NOSQL-001",
                        dynamic_rule=None,
                        node=key,
                        category=Category.NOSQL,
                        symbol=key.value,
                        description="toán tử NoSQL %s" % key.value,
                        value=item_value,
                    )
        aggregate = combine(*values) if values else CONSTANT
        return Value(
            taint=aggregate.taint,
            constant=aggregate.constant,
            sanitized=aggregate.sanitized,
            callables=union_callables(values),
            # A partial key map would read as "key absent" and hide a sink, so
            # an oversized literal keeps only the union.
            entries=tuple(entries) if len(entries) <= MAX_ENTRIES else (),
        )

    def _eval_comprehension(
        self, node: ast.expr, env: Environment, outputs: Sequence[ast.expr]
    ) -> Value:
        scope = copy_environment(env)
        for generator in node.generators:
            iterable = self._eval(generator.iter, scope)
            self._bind(
                generator.target, Value(taint=iterable.taint, constant=iterable.constant), scope
            )
            for condition in generator.ifs:
                self._eval(condition, scope)
                positive, _ = _guarded_names(condition)
                _apply_guards(scope, positive)
        parts = [self._eval(output, scope) for output in outputs]
        aggregate = combine(*parts) if parts else CONSTANT
        return Value(
            taint=aggregate.taint,
            constant=aggregate.constant,
            text_parts=aggregate.text_parts,
            is_sequence=True,
            sanitized=aggregate.sanitized,
        )

    def _eval_lambda(self, node: ast.Lambda, env: Environment) -> Value:
        """Đi vào thân lambda, rồi trả về UNKNOWN cho chính giá trị lambda.

        Trả UNKNOWN mà KHÔNG đọc thân là một điểm mù trọn vẹn, không phải một
        phép xấp xỉ: `handler = lambda: eval(request.args.get("x"))` không sinh
        ra phát hiện nào, trong khi đúng dòng đó viết bằng `def` lại là CRITICAL.
        Lambda là node biểu thức duy nhất vứt cả cây con của mình -- Slice còn
        đọc các phần của nó, và nhánh mặc định ở cuối _eval vẫn duyệt con.
        Ai muốn giấu một sink chỉ cần đổi `def` thành `lambda`.

        Thân lambda được đọc trong một bản sao môi trường, đúng cách
        _eval_comprehension làm: tham số của lambda che tên trùng ở ngoài (giá
        trị lúc gọi là thứ ta không biết), còn tên tự do vẫn thấy được giá trị
        đang có ở chỗ định nghĩa. Giá trị mặc định thì tính ngay tại đây, vì
        Python cũng tính chúng ở đúng thời điểm này.
        """
        scope = copy_environment(env)
        for name, default in _lambda_parameters(node.args):
            scope[name] = self._eval(default, env) if default is not None else UNKNOWN
        self._eval(node.body, scope)
        return UNKNOWN

    def _eval_call(self, node: ast.Call, env: Environment) -> Value:
        qualname = self.imports.qualname_of(node.func)
        argument_values = [self._eval(argument, env) for argument in node.args]
        keyword_values = {
            keyword.arg: self._eval(keyword.value, env)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        for keyword in node.keywords:
            if keyword.arg is None:
                self._eval(keyword.value, env)

        receiver = UNKNOWN
        callee = UNKNOWN
        dotted: Optional[str] = None
        if isinstance(node.func, ast.Attribute):
            receiver = self._eval(node.func.value, env)
            dotted = dotted_name(node.func)
            if dotted is not None:
                callee = env.get(dotted, UNKNOWN)
        elif isinstance(node.func, ast.Name):
            callee = env.get(node.func.id, UNKNOWN)
        elif isinstance(node.func, (ast.Call, ast.Subscript, ast.IfExp, ast.Lambda)):
            # ast.Lambda có mặt ở đây vì dạng gọi-ngay `(lambda: sink())()`:
            # callee vẫn là UNKNOWN như trước, nhưng _eval_lambda mới là chỗ đọc
            # thân lambda. Không đi qua đây thì thân đó lại thành điểm mù, đúng
            # cái vừa bịt -- chỉ khác chỗ đặt dấu ngoặc.
            callee = self._eval(node.func, env)

        targets = _call_targets(node, qualname, callee, dotted)
        effective = targets[0].qualname if targets else None

        self._check_sink(node, targets, argument_values, keyword_values, env)

        if effective is not None:
            # Only these three tables turn a finding off, and they are keyed by
            # the name an API is imported under, so each entry holds only while
            # that name still reaches the import. Sinks and sources keep
            # matching on the bare name: a shadow missed there costs an extra
            # finding, one missed here deletes a real one.
            suppresses = (
                effective in specs.TRUSTED_PRODUCERS
                or effective in specs.SANITIZERS
                or effective in specs.WEAK_SANITIZERS
            )
            if suppresses and self._suppression_applies(targets[0], node, callee, dotted, env):
                if effective in specs.TRUSTED_PRODUCERS:
                    return Value(constant=False, sanitized=True)
                cleared = specs.SANITIZERS.get(effective)
                if cleared is not None:
                    return self._sanitized(argument_values, keyword_values, cleared)
                weakened = specs.WEAK_SANITIZERS.get(effective)
                if weakened is not None:
                    aggregate = combine(*argument_values) if argument_values else UNKNOWN
                    if aggregate.taint is None:
                        return Value(constant=False, sanitized=True)
                    return Value(
                        taint=aggregate.taint.weakened_for(weakened),
                        constant=False,
                        sanitized=True,
                    )
            # `Lenh(gia_tri)` trên một lớp enum: hoặc gia_tri khớp đúng một
            # thành viên, hoặc lời gọi ném ValueError. Không có nhánh thứ ba,
            # nên giá trị đi ra khỏi đây luôn là hằng viết sẵn trong thân lớp.
            if effective in self.module.enum_classes and not self._rebound(effective, env):
                return self._sanitized(argument_values, keyword_values, _EVERY_CATEGORY)
            source = specs.SOURCE_CALLS.get(effective)
            if source is not None and self._source_enabled(source):
                return self._tainted(node, source)

        if isinstance(node.func, ast.Attribute):
            method_source = specs.REQUEST_METHODS.get(node.func.attr)
            if method_source is not None and self._is_request_receiver(node.func.value):
                return self._tainted(node, method_source)
            handler_source = specs.HANDLER_METHODS.get(node.func.attr)
            if handler_source is not None and _is_self_reference(node.func.value):
                return self._tainted(node, handler_source)
            socket_source = specs.SOCKET_READ_METHODS.get(node.func.attr)
            if socket_source is not None:
                return self._tainted(node, socket_source)

        current = getattr(self.function, "node", None)
        if isinstance(node.func, ast.Attribute) and receiver.instance:
            method = self.module.find_method(receiver.instance, node.func.attr)
            if method is not None and method.node is not current:
                return self._apply_summary(method, node, argument_values, keyword_values, receiver)

        local = self.module.lookup_function(
            effective, bare_name_call=isinstance(node.func, ast.Name)
        )
        if local is not None and local.node is not current:
            return self._apply_summary(local, node, argument_values, keyword_values)

        if effective is not None and effective in specs.PROPAGATING_CALLS:
            return combine(*argument_values) if argument_values else UNKNOWN

        if isinstance(node.func, ast.Attribute) and node.func.attr in specs.PROPAGATING_METHODS:
            # `bang.get(khoa)` trả về GIÁ TRỊ trong bảng, không trả về khoá.
            # Gộp cả khoá vào kết quả nghĩa là mọi phép tra bảng ánh xạ bằng
            # dữ liệu người dùng đều bị coi là chảy tiếp -- mà tra bảng ánh
            # xạ lại đúng là cách khử độc được khuyên dùng nhiều nhất. Phép
            # tra bằng ngoặc vuông đã tính đúng từ trước ( _eval_subscript
            # bỏ qua vết nhiễm của chỉ số ); chỗ này chỉ là cùng một sự việc
            # viết bằng lời gọi phương thức.
            carried = argument_values
            if node.func.attr in specs.KEYED_LOOKUP_METHODS and argument_values:
                carried = argument_values[1:]
            parts = [receiver] + list(carried)
            aggregate = combine(*parts)
            return Value(
                taint=aggregate.taint,
                constant=aggregate.constant,
                text_parts=aggregate.text_parts,
                sanitized=aggregate.sanitized,
            )

        inputs = argument_values + list(keyword_values.values())
        if isinstance(node.func, ast.Attribute):
            inputs.append(receiver)
        aggregate_taint: Optional[Taint] = None
        sanitized = False
        for item in inputs:
            aggregate_taint = merge_taint(aggregate_taint, item.taint)
            sanitized = sanitized or item.sanitized
        # Naming a callable must not disturb the data the call carries, so the
        # reflected name rides along on the value the fallthrough already built.
        produced = (
            _reflected_callables(node, self.imports) if effective == "getattr" else frozenset()
        )
        if effective == "super" and not node.args and not self._rebound("super", env):
            # `super().save(x)`: tìm phương thức từ lớp cha của lớp đang đứng.
            instance = self._parent_class()
        else:
            # Chỉ hỏi tên viết kiểu CapWords ( PEP 8 cho lớp ): hỏi chỉ mục cho
            # mọi lời gọi `os.path.join(...)` chỉ tốn thời gian. Hàm factory
            # viết thường vẫn trả về kiểu qua summary.instance ở _apply_summary.
            instance = (
                self.module.class_key(effective)
                if effective and effective.rpartition(".")[2][:1].isupper()
                else ""
            )
            if instance:
                # `ReportService(request.form["dir"])`: __init__ có sink thì báo ở đây.
                initializer = self.module.find_method(instance, "__init__")
                if initializer is not None and initializer.node is not current:
                    self._apply_summary(initializer, node, argument_values, keyword_values)
        if aggregate_taint is None:
            return Value(constant=False, sanitized=sanitized, callables=produced, instance=instance)
        return Value(
            taint=aggregate_taint.downgraded(),
            constant=False,
            sanitized=sanitized,
            callables=produced,
            instance=instance,
        )

    def _parent_class(self) -> str:
        """Lớp cha đầu tiên phân giải được của lớp chứa hàm đang xét, hoặc ""."""
        if self.function is None:
            return ""
        owner = self.module.classes.get(self.function.qualname.rpartition(".")[0])
        if owner is None:
            return ""
        for base in owner.bases:
            key = self.module.class_key(base)
            if key and key != owner.key:
                return key
        return ""

    def _rebound(self, path: str, env: Environment) -> bool:
        """Whether anything in scope has taken this dotted name over.

        ``import`` never writes to ``env`` while assignments, parameters, loop
        targets and ``except`` names do, so a binding on the path -- or on any
        receiver it hangs off -- means the name no longer reaches the module it
        was imported from. A ``def`` or a class method of the same name shadows
        it as well, which is what the sink side already assumes.
        """
        if path in env or path in self.module.functions:
            return True
        parts = path.split(".")
        return any(".".join(parts[:index]) in env for index in range(1, len(parts)))

    def _suppression_applies(
        self,
        target: CallableRef,
        node: ast.Call,
        callee: Value,
        dotted: Optional[str],
        env: Environment,
    ) -> bool:
        """Whether a suppression entry still describes what this call runs."""
        if callee.callables:
            # Matched through a tracked value, so the name here is only an
            # alias and rebinding it is how the alias was made. What still has
            # to hold is that the API it was taken from was not itself shadowed
            # before the alias was read.
            return target.receiver is None or not self._rebound(target.receiver, env)
        if isinstance(node.func, ast.Name):
            return not self._rebound(node.func.id, env)
        return dotted is None or not self._rebound(dotted, env)

    def _sanitized(
        self,
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
        cleared: FrozenSet[Category],
    ) -> Value:
        aggregate = combine(*argument_values) if argument_values else CONSTANT
        if aggregate.taint is None:
            return Value(
                constant=aggregate.constant, text_parts=aggregate.text_parts, sanitized=True
            )
        remaining = aggregate.taint.cleared_for(cleared)
        return Value(
            taint=remaining,
            constant=aggregate.constant,
            text_parts=aggregate.text_parts,
            sanitized=True,
        )

    def _apply_summary(
        self,
        callee: FunctionInfo,
        node: ast.Call,
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
        receiver: Optional[Value] = None,
    ) -> Value:
        if callee.summary is not None:
            summary = callee.summary
        else:
            summary = self.module.summaries.get(callee.qualname, Summary())
        bindings = _bind_arguments(callee.parameters, argument_values, keyword_values)
        if receiver is not None and callee.parameters and callee.parameters[0] in _SELF_NAMES:
            bindings[callee.parameters[0]] = receiver
        result_taint: Optional[Taint] = None
        sanitized = False
        for parameter, value in bindings.items():
            if value.taint is None:
                continue
            for hit in summary.sinks:
                if hit.parameter != parameter:
                    continue
                self._emit_summary_hit(hit, node, value, callee)
            effect = summary.returns.get(parameter)
            if effect is None:
                continue
            sanitized = sanitized or effect.sanitized or bool(effect.cleared)
            result_taint = merge_taint(result_taint, value.taint.cleared_for(effect.cleared))
        if result_taint is None:
            return Value(constant=False, sanitized=sanitized, instance=summary.instance)
        step = self.builder.step(
            StepKind.CALL,
            node.lineno,
            node.col_offset,
            "giá trị trả về từ %s()" % callee.simple_name,
        )
        return Value(
            taint=result_taint.with_step(step),
            constant=False,
            sanitized=sanitized,
            instance=summary.instance,
        )

    def _record_return(self, value: Value) -> None:
        taint = value.taint
        if taint is None or not taint.parameters:
            return
        effect = ReturnEffect(cleared=taint.cleared, sanitized=value.sanitized)
        for parameter in taint.parameters:
            existing = self.returned_parameters.get(parameter)
            self.returned_parameters[parameter] = (
                effect if existing is None else existing.merged(effect)
            )

    def _emit_summary_hit(
        self, hit: SinkHit, node: ast.Call, value: Value, callee: FunctionInfo
    ) -> None:
        taint = value.taint
        if taint is None or not taint.active_for(hit.category):
            return
        call_step = self.builder.step(
            StepKind.CALL,
            node.lineno,
            node.col_offset,
            "được truyền vào %s() ở tham số %s" % (callee.simple_name, hit.parameter),
        )
        if self.mode == SUMMARY_MODE:
            for parameter in taint.parameters:
                self.recorded_sinks.add(
                    SinkHit(
                        parameter=parameter,
                        rule_id=hit.rule_id,
                        category=hit.category,
                        line=hit.line,
                        column=hit.column,
                        symbol=hit.symbol,
                        description=hit.description,
                        # Sink giữ nguyên tệp gốc của nó khi đi vào summary
                        # của hàm đang xét, để tệp gọi ở lượt sau không báo
                        # dòng ấy như dòng của chính mình.
                        origin_path=hit.origin_path or callee.origin_path,
                    )
                )
            return
        if taint.parameters:
            return
        # hit.line/hit.column thuộc về hit.origin_path khi trường đó có giá
        # trị, nên nó được ưu tiên hơn tệp của hàm trung gian đang được gọi.
        origin_path = hit.origin_path or callee.origin_path
        if origin_path:
            # Sink nằm ở tệp khác: vị trí phát hiện là lời gọi ( cùng tệp với
            # đường đi đã biết ), còn bước sink trong đường đi chỉ rõ tệp và
            # dòng thật của nó để anh em nhảy thẳng tới chỗ cần sửa.
            sink_step = self.builder.step(
                StepKind.SINK,
                hit.line,
                hit.column,
                "chạy tới %s" % hit.description,
                path=origin_path,
            )
            self.builder.add(
                rule_id=hit.rule_id,
                line=node.lineno,
                column=node.col_offset,
                symbol=hit.symbol,
                message="%s đi qua %s() trong %s rồi vào %s"
                % (taint.describe(), callee.simple_name, origin_path, hit.description),
                confidence=_confidence_for(taint),
                trace=tuple(taint.trace) + (call_step, sink_step),
                tags=("interprocedural", "cross-file"),
            )
            return
        sink_step = self.builder.step(
            StepKind.SINK, hit.line, hit.column, "chạy tới %s" % hit.description
        )
        self.builder.add(
            rule_id=hit.rule_id,
            line=hit.line,
            column=hit.column,
            symbol=hit.symbol,
            message="%s đi qua %s() rồi vào %s"
            % (taint.describe(), callee.simple_name, hit.description),
            confidence=_confidence_for(taint),
            trace=tuple(taint.trace) + (call_step, sink_step),
            tags=("interprocedural",),
        )

    def _check_sink(
        self,
        node: ast.Call,
        targets: Sequence[CallableRef],
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
        env: Environment,
    ) -> None:
        for target in targets:
            self._check_sink_target(node, target, argument_values, keyword_values, env)

    def _check_sink_target(
        self,
        node: ast.Call,
        target: CallableRef,
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
        env: Environment,
    ) -> None:
        if target.qualname in self.module.functions:
            return
        spec = specs.SINKS.get(target.qualname)
        if spec is None and target.attribute is not None:
            candidate = specs.METHOD_SINKS.get(target.attribute)
            if candidate is not None and self._method_sink_applies(
                candidate, target, argument_values
            ):
                spec = candidate
        if spec is None:
            return

        condition = spec.condition
        if condition == specs.YAML_LOAD and self._yaml_is_safe(node, keyword_values, env):
            return
        if condition == specs.NUMPY_LOAD and not _keyword_is_true(node, "allow_pickle"):
            return
        if condition == specs.TORCH_LOAD and not _keyword_is_false(node, "weights_only"):
            return
        if condition == specs.XML_PARSER:
            self._check_xml_parser(node)
            return

        if condition in (specs.SHELL_KWARG, specs.ARGV):
            shell_enabled = _keyword_is_true(node, "shell")
            if condition == specs.ARGV or not shell_enabled:
                self._check_program_argument(node, spec, argument_values)
                return

        positions = spec.positions or (0,)
        for index in positions:
            if index < len(argument_values):
                self._evaluate_sink_argument(
                    node, spec, argument_values[index], node.args[index]
                )
        for keyword in spec.keywords:
            if keyword in keyword_values:
                self._evaluate_sink_argument(node, spec, keyword_values[keyword], node)

    def _evaluate_sink_argument(
        self, node: ast.Call, spec: specs.SinkSpec, value: Value, argument_node: ast.AST
    ) -> None:
        if spec.condition == specs.SQL_TEXT and value.constant:
            return
        self._flag(
            rule_id=spec.tainted_rule,
            dynamic_rule=spec.dynamic_rule if spec.condition != specs.TAINT_ONLY else None,
            node=node,
            category=spec.category,
            symbol=spec.qualname,
            description=spec.description,
            value=value,
        )

    def _check_program_argument(
        self, node: ast.Call, spec: specs.SinkSpec, argument_values: Sequence[Value]
    ) -> None:
        if not argument_values:
            return
        target = argument_values[0]
        if target.is_sequence:
            if not target.elements:
                return
            wrapped = _shell_wrapper_element(target.elements)
            if wrapped is not None:
                self._flag(
                    rule_id="FSB-CMD-001",
                    dynamic_rule="FSB-CMD-003",
                    node=node,
                    category=Category.COMMAND,
                    symbol=spec.qualname,
                    description="một lệnh shell truyền qua cờ thông dịch",
                    value=wrapped,
                )
                return
            target = target.elements[0]
        self._flag(
            rule_id="FSB-CMD-002",
            dynamic_rule=None,
            node=node,
            category=Category.COMMAND,
            symbol=spec.qualname,
            description="chương trình được chạy trong %s" % spec.description,
            value=target,
        )

    def _flag(
        self,
        rule_id: str,
        dynamic_rule: Optional[str],
        node: ast.AST,
        category: Category,
        symbol: str,
        description: str,
        value: Value,
    ) -> None:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0)
        taint = value.taint
        if taint is not None and taint.active_for(category):
            if self.mode == SUMMARY_MODE:
                for parameter in taint.parameters:
                    self.recorded_sinks.add(
                        SinkHit(
                            parameter=parameter,
                            rule_id=rule_id,
                            category=category,
                            line=line,
                            column=column,
                            symbol=symbol,
                            description=description,
                        )
                    )
                return
            if taint.parameters:
                return
            step = self.builder.step(
                StepKind.SINK, line, column, "chạy tới %s" % description
            )
            confidence = _confidence_for(taint)
            if taint.weak_for(category):
                confidence = Confidence(max(int(Confidence.LOW), int(confidence) - 10))
            self.builder.add(
                rule_id=rule_id,
                line=line,
                column=column,
                symbol=symbol,
                message="%s chạy tới %s mà chưa được vô hiệu hóa" % (taint.describe(), description),
                end_line=getattr(node, "end_lineno", None),
                end_column=getattr(node, "end_col_offset", None),
                confidence=confidence,
                trace=tuple(taint.trace) + (step,),
            )
            return
        if self.mode != REPORT_MODE or dynamic_rule is None:
            return
        if value.constant or value.sanitized:
            return
        self.builder.add(
            rule_id=dynamic_rule,
            line=line,
            column=column,
            symbol=symbol,
            message="%s nhận một giá trị không phải hằng" % description,
            end_line=getattr(node, "end_lineno", None),
            end_column=getattr(node, "end_col_offset", None),
            trace=(self.builder.step(StepKind.SINK, line, column, description),),
        )

    def _method_sink_applies(
        self, spec: specs.SinkSpec, target: CallableRef, argument_values: Sequence[Value]
    ) -> bool:
        if spec.category is not Category.SQL:
            return True
        if _receiver_matches(target.receiver, specs.SQL_METHOD_RECEIVER_HINTS):
            return True
        for value in argument_values[:1]:
            if specs.looks_like_sql(value.text, self.module.budget.spend):
                return True
        return False

    def _yaml_is_safe(
        self, node: ast.Call, keyword_values: Dict[str, Value], env: Environment
    ) -> bool:
        loader_node: Optional[ast.AST] = None
        for keyword in node.keywords:
            if keyword.arg == "Loader":
                loader_node = keyword.value
        if loader_node is None and len(node.args) > 1:
            loader_node = node.args[1]
        if loader_node is None:
            return False
        dotted = dotted_name(loader_node)
        if dotted is None:
            return False
        # The loader is recognised by name alone, so a rebound name would let
        # an unsafe loader wear a safe one's spelling and take the sink away.
        if self._rebound(dotted, env):
            return False
        return dotted.rsplit(".", 1)[-1] in specs.SAFE_YAML_LOADERS

    def _check_xml_parser(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            expected = specs.XML_UNSAFE_KEYWORDS.get(keyword.arg or "")
            if expected is None:
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is expected:
                self.builder.add(
                    rule_id="FSB-XML-001",
                    line=node.lineno,
                    column=node.col_offset,
                    symbol="XMLParser",
                    message="parser XML được cấu hình %s=%r" % (keyword.arg, expected),
                )
                return

    def _request_member_source(
        self, resolved: str, attribute: str
    ) -> Optional[specs.SourceSpec]:
        source = specs.REQUEST_MEMBERS.get(attribute)
        if source is None:
            return None
        prefix = resolved.rsplit(".", 1)[0] if "." in resolved else ""
        if not prefix:
            return None
        tail = prefix.rsplit(".", 1)[-1].lower()
        if prefix in specs.REQUEST_RECEIVER_NAMES or tail in ("request", "req"):
            return source
        return None

    def _is_request_receiver(self, node: ast.AST) -> bool:
        parts = attribute_parts(node)
        if not parts:
            return False
        return parts[-1].lower() in ("request", "req", "handler")

    def _source_enabled(self, source: specs.SourceSpec) -> bool:
        if source.low_signal and not self.module.unit.config.include_low_signal_sources:
            return False
        return True

    def _tainted(self, node: ast.AST, source: specs.SourceSpec) -> Value:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0)
        step = self.builder.step(
            StepKind.SOURCE, line, column, "%s đi vào từ đây" % source.label
        )
        return Value(
            taint=Taint(
                labels=frozenset({source.label}),
                confidence=source.confidence,
                trace=(step,),
                low_signal=source.low_signal,
            ),
            constant=False,
        )


def _confidence_for(taint: Taint) -> Confidence:
    return taint.confidence


def _parameter_names(arguments: ast.arguments) -> Tuple[str, ...]:
    names: List[str] = []
    for argument in getattr(arguments, "posonlyargs", []) or []:
        names.append(argument.arg)
    for argument in arguments.args:
        names.append(argument.arg)
    if arguments.vararg is not None:
        names.append(arguments.vararg.arg)
    for argument in arguments.kwonlyargs:
        names.append(argument.arg)
    if arguments.kwarg is not None:
        names.append(arguments.kwarg.arg)
    return tuple(names)


def _lambda_parameters(
    arguments: ast.arguments,
) -> Tuple[Tuple[str, Optional[ast.expr]], ...]:
    """Từng tham số kèm biểu thức mặc định của nó, hoặc None nếu không có.

    `defaults` xếp thẳng hàng với phần ĐUÔI của posonlyargs + args, còn
    `kw_defaults` xếp một-đối-một với kwonlyargs và mang None ở chỗ khuyết.
    `*args`/`**kwargs` không bao giờ có mặc định.
    """
    positional = list(getattr(arguments, "posonlyargs", []) or []) + list(arguments.args)
    defaults: List[Optional[ast.expr]] = [None] * (
        len(positional) - len(arguments.defaults)
    ) + list(arguments.defaults)

    pairs: List[Tuple[str, Optional[ast.expr]]] = [
        (argument.arg, default) for argument, default in zip(positional, defaults)
    ]
    if arguments.vararg is not None:
        pairs.append((arguments.vararg.arg, None))
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
        pairs.append((argument.arg, default))
    if arguments.kwarg is not None:
        pairs.append((arguments.kwarg.arg, None))
    return tuple(pairs)


def _bind_arguments(
    parameters: Sequence[str],
    argument_values: Sequence[Value],
    keyword_values: Dict[str, Value],
) -> Dict[str, Value]:
    positional = [name for name in parameters if name not in _SELF_NAMES]
    bindings: Dict[str, Value] = {}
    for index, value in enumerate(argument_values):
        if index < len(positional):
            bindings[positional[index]] = value
    for name, value in keyword_values.items():
        if name in parameters:
            bindings[name] = value
    return bindings


def _handler_sources(node: ast.AST, imports: ImportResolver) -> Dict[str, specs.SourceSpec]:
    sources: Dict[str, specs.SourceSpec] = {}
    arguments = node.args
    defaults = list(arguments.defaults) + list(arguments.kw_defaults or [])
    named = list(getattr(arguments, "posonlyargs", []) or []) + list(arguments.args)
    named += list(arguments.kwonlyargs)

    for default in defaults:
        if not isinstance(default, ast.Call):
            continue
        qualname = imports.qualname_of(default.func)
        source = specs.SOURCE_CALLS.get(qualname or "")
        if source is None:
            continue
        offset = len(arguments.args) - len(arguments.defaults)
        for index, default_node in enumerate(arguments.defaults):
            if default_node is default and 0 <= offset + index < len(arguments.args):
                sources[arguments.args[offset + index].arg] = source
        for index, default_node in enumerate(arguments.kw_defaults or []):
            if default_node is default and index < len(arguments.kwonlyargs):
                sources[arguments.kwonlyargs[index].arg] = source

    if _is_route_handler(node, imports):
        request_source = specs.SourceSpec("tham số của request HTTP", Confidence.HIGH)
        typed = _framework_typed_parameters(node, imports)
        for argument in named:
            if argument.arg in _SELF_NAMES:
                continue
            # Tham số mà chính framework đã ép kiểu thì không còn là chuỗi tự
            # do nữa. `@app.route('/x/<int:so>')` khiến Flask trả 404 trước
            # khi handler chạy nếu phần đó không phải số, và `def h(so: int)`
            # trong FastAPI cũng vậy. Một số nguyên không mang nổi dấu chấm
            # phẩy hay dấu nháy, nên coi nó là dữ liệu tấn công được là báo
            # nhầm đúng vào cách viết được khuyến nghị nhất.
            if argument.arg in typed:
                continue
            sources.setdefault(argument.arg, request_source)
    elif node.name in specs.HANDLER_FUNCTION_NAMES:
        event_source = specs.SourceSpec("dữ liệu sự kiện", Confidence.MEDIUM)
        for argument in named:
            if argument.arg in specs.HANDLER_PARAMETER_NAMES:
                sources.setdefault(argument.arg, event_source)
    return sources


# Bộ chuyển kiểu trong đường dẫn route, và tên kiểu trong chú thích tham số,
# mà kết quả KHÔNG THỂ mang ký tự phá cú pháp của bất kỳ nhóm sink nào.
# `str`, `string`, `path` và `any` cố tình vắng mặt: chúng vẫn là chuỗi tự do.
# Framework đọc chú thích kiểu của tham số handler rồi ÉP KIỂU trước khi gọi,
# và trả về lỗi 4xx nếu ép không được. Flask, Bottle, Django và Pyramid không
# nằm ở đây: chúng giao tham số đường dẫn vào dưới dạng chuỗi bất kể chú thích
# viết gì.
_ANNOTATION_ENFORCING_FRAMEWORKS: FrozenSet[str] = frozenset(
    {"fastapi", "litestar", "starlite", "blacksheep", "ninja"}
)

_SAFE_ROUTE_CONVERTERS: FrozenSet[str] = frozenset({"int", "float", "uuid"})
_SAFE_PARAMETER_TYPES: FrozenSet[str] = frozenset(
    {"int", "float", "bool", "complex", "UUID", "Decimal", "date", "datetime", "time"}
)

# `[^)]{0,80}` chứ không phải `.{0,80}?`: dấu chấm khớp cả `)`, nên bản lười
# phải nong ra từng bước để dò dấu đóng, và ở mỗi vị trí mở lại làm lại từ
# đầu. Lớp phủ định không có gì để quay lui -- nó dừng ngay tại dấu đóng.
_ROUTE_PARAMETER = re.compile(r"<([a-zA-Z_]\w*)(?:\([^)]{0,80}\))?:([a-zA-Z_]\w*)>")


def _framework_typed_parameters(node: ast.AST, imports: ImportResolver) -> FrozenSet[str]:
    """Tham số mà framework bảo đảm kiểu trước khi handler chạy.

    Hai nguồn bảo đảm, và cả hai đều đọc được ngay tại chỗ định nghĩa hàm:
    bộ chuyển kiểu viết trong chuỗi route ( Flask, Bottle ), và chú thích kiểu
    trên chính tham số ( FastAPI, Litestar ). Không suy diễn gì thêm: một chú
    thích `str` hay `Any` vẫn để tham số ở nguyên trạng thái không tin cậy.
    """
    return _route_converted_parameters(node) | _annotated_scalar_parameters(node, imports)


def _route_converted_parameters(node: ast.AST) -> FrozenSet[str]:
    """Tham số được ép kiểu ngay trong chuỗi route: `/x/<int:so>`."""
    typed: Set[str] = set()
    for decorator in getattr(node, "decorator_list", []):
        if not isinstance(decorator, ast.Call):
            continue
        for argument in decorator.args[:2]:
            if not isinstance(argument, ast.Constant) or not isinstance(argument.value, str):
                continue
            for converter, name in _ROUTE_PARAMETER.findall(argument.value[:2000]):
                if converter.lower() in _SAFE_ROUTE_CONVERTERS:
                    typed.add(name)
    return frozenset(typed)


def _annotated_scalar_parameters(node: ast.AST, imports: ImportResolver) -> FrozenSet[str]:
    """Tham số mang chú thích kiểu vô hại, ở framework THẬT SỰ ép kiểu đó.

    Python không ép kiểu theo chú thích lúc chạy, nên `def h(so: int)` chỉ là
    lời hứa của tác giả. FastAPI và các framework cùng họ biến lời hứa đó
    thành sự thật: chúng đọc chú thích, ép kiểu, và trả 422 trước khi thân hàm
    chạy. Flask thì không. Với Flask, `@app.route('/x/<so>')` luôn giao vào
    một chuỗi, chú thích `so: int` không đổi được điều đó.

    Không phân biệt hai chuyện này là bỏ sót thật:

        @app.route('/x/<so>')
        def h(so: int):
            os.system('ping ' + str(so))   # vẫn thủng, mà bộ dò lại im

    Ép kiểu viết ngay trong đường dẫn route (`<int:so>`) thì Flask có thi hành,
    nên nó được xét riêng ở _route_converted_parameters và không cần điều kiện
    này.
    """
    if not imports.imports_any(_ANNOTATION_ENFORCING_FRAMEWORKS):
        return frozenset()
    arguments = node.args
    every = (
        list(getattr(arguments, "posonlyargs", []) or [])
        + list(arguments.args)
        + list(arguments.kwonlyargs)
    )
    typed: Set[str] = set()
    for argument in every:
        if argument.annotation is None:
            continue
        resolved = imports.qualname_of(argument.annotation) or ""
        if resolved.rsplit(".", 1)[-1] in _SAFE_PARAMETER_TYPES:
            typed.add(argument.arg)
    return frozenset(typed)


def _is_route_handler(node: ast.AST, imports: ImportResolver) -> bool:
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not isinstance(target, ast.Attribute):
            continue
        if target.attr not in specs.ROUTE_DECORATOR_ATTRIBUTES:
            continue
        parts = attribute_parts(target)
        if len(parts) < 2:
            continue
        receiver = parts[-2].lower()
        if receiver in specs.ROUTE_DECORATOR_RECEIVERS:
            return True
        resolved = imports.resolve(".".join(parts))
        if resolved.startswith(("flask", "fastapi", "starlette", "sanic", "quart", "bottle")):
            return True
    return False


def _keyword_is_true(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name:
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False


def _keyword_is_false(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name:
            return not (isinstance(keyword.value, ast.Constant) and keyword.value.value is True)
    return True


def _receiver_matches(receiver: Optional[str], hints: FrozenSet[str]) -> bool:
    if not receiver:
        return False
    for part in receiver.split("."):
        lowered = part.lower()
        for hint in hints:
            if hint in lowered:
                return True
    return False


def _call_targets(
    node: ast.Call,
    qualname: Optional[str],
    callee: Value,
    dotted: Optional[str],
) -> Tuple[CallableRef, ...]:
    """Which callables this call may reach.

    A value that carries a tracked callable wins over the syntactic name: it
    means the name at the call site is a local alias rather than the API being
    called. Where nothing is tracked this reproduces the plain syntactic match.
    """
    if callee.callables:
        return ordered_callables(callee)
    if not isinstance(node.func, (ast.Name, ast.Attribute)) or qualname is None:
        return ()
    if isinstance(node.func, ast.Attribute):
        # ``dotted`` is the unresolved form and ends with ``.<attr>``; slicing it
        # avoids walking the receiver chain a second time.
        attribute = node.func.attr
        receiver = dotted[: len(dotted) - len(attribute) - 1] if dotted else None
        return (
            CallableRef(qualname=qualname, attribute=attribute, receiver=receiver or None),
        )
    return (CallableRef(qualname=qualname),)


def _indexed_callables(base: Value, index: ast.expr) -> FrozenSet[CallableRef]:
    """Callables reachable through ``container[index]``.

    A constant index picks the exact element, so an unrelated entry in a
    dispatch table is not blamed. Anything else falls back to every callable the
    container holds, because the index cannot be pinned down.
    """
    if isinstance(index, ast.Constant):
        key = index.value
        if isinstance(key, int) and not isinstance(key, bool) and base.elements:
            if -len(base.elements) <= key < len(base.elements):
                return base.elements[key].callables
            return frozenset()
        if isinstance(key, str) and base.entries:
            matched: FrozenSet[CallableRef] = frozenset()
            for name, refs in base.entries:
                if name == key:
                    matched = matched | refs
            return limit_callables(matched)
    return base.callables


def _reflected_callables(node: ast.Call, imports: ImportResolver) -> FrozenSet[CallableRef]:
    """``getattr(obj, "name")`` names a callable just as ``obj.name`` does."""
    if len(node.args) < 2:
        return frozenset()
    attribute = node.args[1]
    if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
        return frozenset()
    receiver = dotted_name(node.args[0])
    if receiver is None:
        return frozenset()
    return frozenset(
        {
            CallableRef(
                qualname=imports.resolve("%s.%s" % (receiver, attribute.value)),
                attribute=attribute.value,
                receiver=receiver,
            )
        }
    )


_EXIT_CALLS = frozenset(
    {
        "abort",
        "sys.exit",
        "os._exit",
        "os.abort",
        "exit",
        "quit",
        "posix_spawn",
        "flask.abort",
    }
)


def _terminates(statements: Sequence[ast.stmt]) -> bool:
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.If):
        return _terminates(last.body) and _terminates(last.orelse)
    if isinstance(last, ast.With):
        return _terminates(last.body)
    # flask.abort() và sys.exit() là lối thoát chuẩn của mẫu
    # "kiểm tra rồi dừng": không tính chúng là kết thúc luồng thì guard
    # `if not hop_le: abort(400)` không bao giờ vô hiệu được taint.
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        callee = last.value.func
        name = (
            callee.id
            if isinstance(callee, ast.Name)
            else (dotted_name(callee) if isinstance(callee, ast.Attribute) else None)
        )
        if name is not None and name in _EXIT_CALLS:
            return True
    return False


def _apply_guards(env: Environment, names: FrozenSet[str]) -> None:
    for name in names:
        value = env.get(name)
        if value is None or value.taint is None:
            continue
        env[name] = Value(
            taint=value.taint.fully_cleared(),
            constant=value.constant,
            text_parts=value.text_parts,
            sanitized=True,
        )


def _guarded_names(test: ast.expr) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        positive, negative = _guarded_names(test.operand)
        return negative, positive
    if isinstance(test, ast.BoolOp):
        collected = [_guarded_names(value) for value in test.values]
        if isinstance(test.op, ast.And):
            positive: FrozenSet[str] = frozenset()
            for item, _ in collected:
                positive = positive | item
            return positive, frozenset()
        shared: Optional[FrozenSet[str]] = None
        for item, _ in collected:
            shared = item if shared is None else (shared & item)
        return frozenset(), shared or frozenset()
    if isinstance(test, ast.Compare):
        return _guarded_names_compare(test)
    if isinstance(test, ast.Call):
        return _guarded_names_call(test)
    return frozenset(), frozenset()


def _guarded_names_compare(test: ast.Compare) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    if len(test.ops) != 1 or len(test.comparators) != 1:
        return frozenset(), frozenset()
    name = _simple_name(test.left)
    if name is None:
        return frozenset(), frozenset()
    operator = test.ops[0]
    comparator = test.comparators[0]
    if isinstance(operator, ast.In) and _is_allowlist(comparator):
        return frozenset({name}), frozenset()
    if isinstance(operator, ast.NotIn) and _is_allowlist(comparator):
        return frozenset(), frozenset({name})
    if isinstance(operator, ast.Eq) and isinstance(comparator, ast.Constant):
        return frozenset({name}), frozenset()
    if isinstance(operator, ast.NotEq) and isinstance(comparator, ast.Constant):
        return frozenset(), frozenset({name})
    return frozenset(), frozenset()


def _guarded_names_call(test: ast.Call) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    function = test.func
    if isinstance(function, ast.Attribute):
        if function.attr in specs.SCALAR_GUARD_METHODS:
            name = _simple_name(function.value)
            if name is not None:
                return frozenset({name}), frozenset()
        if function.attr in ("fullmatch", "match"):
            name = _argument_name(test, 1)
            if name is not None and _is_anchored_pattern(test, function.attr):
                return frozenset({name}), frozenset()
    if isinstance(function, ast.Name):
        if function.id in ("isinstance", "issubclass"):
            name = _argument_name(test, 0)
            if name is not None:
                return frozenset({name}), frozenset()
        if function.id == "fullmatch":
            name = _argument_name(test, 1)
            if name is not None:
                return frozenset({name}), frozenset()
    return frozenset(), frozenset()


def _is_anchored_pattern(test: ast.Call, attribute: str) -> bool:
    if attribute == "fullmatch":
        return True
    if not test.args:
        return False
    pattern = test.args[0]
    if isinstance(pattern, ast.Constant) and isinstance(pattern.value, str):
        return pattern.value.startswith("^") and pattern.value.endswith("$")
    return False


def _argument_name(test: ast.Call, index: int) -> Optional[str]:
    if index < len(test.args):
        return _simple_name(test.args[index])
    return None


_SHELL_BINARIES = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "cmd", "cmd.exe", "powershell", "pwsh", "busybox"}
)
_SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command"})


def _shell_wrapper_element(elements: Sequence[Value]) -> Optional[Value]:
    if len(elements) < 3:
        return None
    program = _sole_text(elements[0])
    if program is None:
        return None
    if program.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() not in _SHELL_BINARIES:
        return None
    for index in range(1, len(elements) - 1):
        flag = _sole_text(elements[index])
        if flag is not None and flag in _SHELL_FLAGS:
            return elements[index + 1]
    return None


def _sole_text(value: Value) -> Optional[str]:
    if value.constant and len(value.text_parts) == 1:
        return value.text_parts[0]
    return None


def _is_self_reference(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in _SELF_NAMES


def _simple_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted_name(node)
    return None


def _is_allowlist(node: ast.AST) -> bool:
    if isinstance(node, (ast.Set, ast.List, ast.Tuple, ast.Dict)):
        return True
    if isinstance(node, ast.Name):
        return node.id.isupper() or node.id.startswith(("ALLOWED", "VALID", "PERMITTED"))
    if isinstance(node, ast.Attribute):
        return node.attr.isupper()
    return False


def _match_capture_names(pattern: ast.AST) -> List[str]:
    names: List[str] = []
    for node in ast.walk(pattern):
        capture = getattr(ast, "MatchAs", None)
        star = getattr(ast, "MatchStar", None)
        if capture is not None and isinstance(node, capture) and node.name:
            names.append(node.name)
        elif star is not None and isinstance(node, star) and node.name:
            names.append(node.name)
    return names


def _attribute_types(node: ast.ClassDef, imports: ImportResolver) -> Dict[str, Tuple[str, ...]]:
    """Kiểu đoán được của thuộc tính lớp, đọc từ phép gán trong thân lớp và phương thức.

        class ItemService:
            repo: ItemRepository                       # chú thích ở thân lớp
            def __init__(self, repo=None, cache: Cache = None):
                self.repo = repo or ItemRepository()   # lời gọi khởi tạo
                self.cache = cache                     # chú thích của tham số
    """
    found: Dict[str, List[str]] = {}

    def add(attribute: str, name: Optional[str]) -> None:
        if not name:
            return
        bucket = found.setdefault(attribute, [])
        if name not in bucket and len(bucket) < 4:
            bucket.append(name)

    def add_value(attribute: str, value: Optional[ast.expr], annotations: Dict[str, str]) -> None:
        for call in _constructed_calls(value, 0):
            add(attribute, imports.qualname_of(call.func))
        if isinstance(value, ast.Name) and value.id in annotations:
            add(attribute, annotations[value.id])

    for statement in node.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    add_value(target.id, statement.value, {})
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            add(statement.target.id, imports.qualname_of(statement.annotation))
            add_value(statement.target.id, statement.value, {})
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = list(getattr(statement.args, "posonlyargs", []) or []) + list(statement.args.args)
            if not arguments or arguments[0].arg not in _SELF_NAMES:
                continue
            receiver = arguments[0].arg
            annotations = {
                argument.arg: name
                for argument in arguments[1:] + list(statement.args.kwonlyargs)
                if argument.annotation is not None
                for name in (imports.qualname_of(argument.annotation),)
                if name
            }
            for inner in _nested_statements(statement.body, 0):
                targets: List[ast.expr] = []
                value: Optional[ast.expr] = None
                if isinstance(inner, ast.Assign):
                    targets, value = list(inner.targets), inner.value
                elif isinstance(inner, ast.AnnAssign):
                    targets, value = [inner.target], inner.value
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == receiver
                    ):
                        if isinstance(inner, ast.AnnAssign):
                            add(target.attr, imports.qualname_of(inner.annotation))
                        add_value(target.attr, value, annotations)
    return {attribute: tuple(names) for attribute, names in found.items()}


_COMPOUND_FIELDS = ("body", "orelse", "finalbody", "handlers", "cases")


def _nested_statements(statements: Sequence[ast.stmt], depth: int):
    """Mọi câu lệnh trong khối, kể cả trong if/for/with/try, không đi vào biểu thức.

    Rẻ hơn ast.walk nhiều lần trên phương thức dài: chỉ phép gán mới mang
    kiểu của thuộc tính, nên không cần thăm từng nút con của biểu thức.
    """
    if depth > _MAX_BLOCK_DEPTH:
        return
    for statement in statements:
        yield statement
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        for name in _COMPOUND_FIELDS:
            inner = getattr(statement, name, None)
            if not inner:
                continue
            for item in inner:
                if isinstance(item, ast.stmt):
                    yield from _nested_statements([item], depth + 1)
                else:
                    # except-handler và match-case bọc thân của chúng.
                    yield from _nested_statements(getattr(item, "body", []), depth + 1)


def _constructed_calls(value: Optional[ast.expr], depth: int) -> List[ast.Call]:
    """Lời gọi có thể tạo ra giá trị: `A()`, `x or A()`, `A() if c else B()`, `await A()`."""
    if value is None or depth > 4:
        return []
    if isinstance(value, ast.Call) and isinstance(value.func, (ast.Name, ast.Attribute)):
        return [value]
    if isinstance(value, ast.BoolOp):
        return [call for item in value.values for call in _constructed_calls(item, depth + 1)]
    if isinstance(value, ast.IfExp):
        return _constructed_calls(value.body, depth + 1) + _constructed_calls(value.orelse, depth + 1)
    if isinstance(value, ast.Await):
        return _constructed_calls(value.value, depth + 1)
    return []
