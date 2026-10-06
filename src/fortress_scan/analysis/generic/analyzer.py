from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Callable, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...core.model import Category, Confidence, Finding, StepKind
from ...core.registry import get_rule
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from ..python.specs import looks_like_sql
from ..xfile.context import PROBE, SUMMARY, FileContext
from ..xfile.model import Callee, FunctionDef, SinkHit, SourceReturn, Summary
from ..xfile.stream import TokenIndex
from .lexer import IDENT, NEWLINE, OP, STRING, Token, tokenize
from .profiles import GenericSink, LanguageSpec, spec_for

if TYPE_CHECKING:
    from ..xfile.project import XProject

_MAX_STATEMENTS = 20000
_MAX_STATEMENT_TOKENS = 600
_CONTINUATION_OPERATORS = frozenset(
    {"+", "-", "*", "/", ",", "=", "(", "[", "{", "&&", "||", ".", "?", ":", "|", "\\", "+="}
)
_STATEMENT_BREAKS = frozenset({";", "{", "}"})
_SHELL_QUIET_COMMANDS = frozenset({"echo", "printf", "return", "local", "export", "declare"})
_EVERY_CATEGORY: FrozenSet[Category] = frozenset(Category)

# Từ khoá khai báo hàm của các ngôn ngữ ở đây. Dùng để nhận ra tệp được quét tự
# định nghĩa một cái tên trùng với bộ khử độc trong bảng.
_FUNCTION_KEYWORDS = frozenset({"function", "func", "def", "sub", "fn"})

# `const escapeHtml = require("escape-html")` là nạp thư viện thật, không phải
# chiếm tên. Trong JavaScript thì require/import mới là phép nhập, còn dấu `=`
# chỉ là cú pháp -- nên phải nhìn vế phải mới phân biệt được hai chuyện.
_IMPORT_CALLS = frozenset({"require", "import", "await"})


@dataclass(frozen=True)
class TaintMark:
    label: str
    line: int
    confidence: Confidence = Confidence.MEDIUM
    # Những nhóm đã thật sự được khử trên đường đi tới đây. Đi kèm giá trị chứ
    # không quyết định ngay tại chỗ gặp bộ khử độc, vì lúc gán thì chưa biết
    # giá trị này rồi sẽ chảy vào sink thuộc nhóm nào:
    #     $safe = htmlspecialchars($_GET['d']);   // khử MARKUP
    #     system("ls " . $safe);                  // sink COMMAND -> vẫn thủng
    cleared: FrozenSet[Category] = frozenset()
    # Chỉ có khi đang tính summary của một hàm: vết nhiễm này đến từ tham số
    # thứ mấy. Vết nhiễm của nguồn thật thì để trống.
    params: FrozenSet[int] = frozenset()

    def active_for(self, category: Category) -> bool:
        return category not in self.cleared


class GenericAnalyzer(Analyzer):
    name = "generic-dataflow"

    def analyze(
        self, unit: AnalysisUnit, budget: Budget, project: Optional["XProject"] = None
    ) -> List[Finding]:
        spec = spec_for(unit.language)
        if spec is None:
            return []
        try:
            tokens = tokenize(unit.source, spec.lexer, budget)
            context = None
            if project is not None and unit.relative_path in project.facts:
                context = FileContext(project, unit.relative_path, tokens)
            return _Analysis(unit, spec, budget, context).run(tokens)
        except BudgetExceeded:
            return []

    def probe(
        self, unit: AnalysisUnit, budget: Budget, project: "XProject"
    ) -> List[Tuple[str, str, int]]:
        """Chạy một lượt báo cáo chỉ để nhặt sự kiện xuyên file, bỏ phát hiện."""
        spec = spec_for(unit.language)
        if spec is None or unit.relative_path not in project.facts:
            return []
        try:
            tokens = tokenize(unit.source, spec.lexer, budget)
            context = FileContext(project, unit.relative_path, tokens, mode=PROBE)
            _Analysis(unit, spec, budget, context).run(tokens)
            return context.queue_events
        except BudgetExceeded:
            return []

    def summarize(
        self,
        unit: AnalysisUnit,
        tokens: Sequence[Token],
        function: FunctionDef,
        project: "XProject",
        budget: Budget,
        declared: Optional[Set[str]] = None,
    ) -> Summary:
        """Summary của một hàm: tham số nào tới sink nào, tham số nào ra return."""
        spec = spec_for(unit.language)
        if spec is None:
            return Summary()
        context = FileContext(project, unit.relative_path, tokens, mode=SUMMARY, function=function)
        analysis = _Analysis(unit, spec, budget, context)
        if declared is not None:
            analysis.declared = set(declared)
        else:
            analysis._collect_declarations(tokens)
        for position, (name, label) in enumerate(zip(function.params, function.param_sources)):
            if not name:
                continue
            if label:
                analysis.tainted[name] = TaintMark(label, function.line, Confidence.HIGH)
            else:
                analysis.tainted[name] = TaintMark(
                    "tham số %s" % name, function.line, Confidence.HIGH, params=frozenset({position})
                )
        body = list(tokens[function.body_start : function.body_end])
        try:
            if function.expression_body:
                analysis._record_return(body)
                analysis._analyze_statement(body)
            else:
                analysis._seed_annotations(body)
                for statement in _split_statements(body)[:_MAX_STATEMENTS]:
                    budget.spend()
                    if statement:
                        analysis._analyze_statement(statement)
        except BudgetExceeded:
            context.incomplete = True
        return context.summary()


class _Analysis:
    def __init__(
        self,
        unit: AnalysisUnit,
        spec: LanguageSpec,
        budget: Budget,
        context: Optional[FileContext] = None,
    ) -> None:
        self.unit = unit
        self.spec = spec
        self.budget = budget
        self.builder = FindingBuilder(unit)
        self.tainted: Dict[str, TaintMark] = {}
        self.sanitized: Set[str] = set()
        self.declared: Set[str] = set()
        self.context = context
        # Biến đang giữ một câu SQL ( dựng từ chuỗi hằng hay hằng số ở tệp
        # khác ), và biến chỉ gồm giá trị hằng. Chỉ dùng khi có ngữ cảnh dự án:
        # đó là lúc hằng số ở tệp khác được nhìn thấy.
        self.sql_vars: Set[str] = set()
        self.literal_vars: Set[str] = set()
        # Spring MVC: thuộc tính model bẩn đang chờ biết view nào được trả về.
        self.pending_model: Dict[str, List[Tuple[str, TaintMark, Token]]] = {}
        # Nguồn thật cuối cùng mà _taint_of nhìn thấy cạnh vết của tham số.
        self._last_source: Optional[TaintMark] = None
        self._index: Optional[TokenIndex] = None

    def _in_conditional(self, token: Token) -> bool:
        index = self.context.index if self.context is not None else self._index
        if index is None:
            return False
        return index.conditional(token)

    def run(self, tokens: Sequence[Token]) -> List[Finding]:
        if self.context is None:
            self._index = TokenIndex(tokens)
        self._collect_declarations(tokens)
        self._seed_annotations(tokens)
        if self.context is not None:
            for name, (label, line) in self.context.project.seeded_parameters(
                self.unit.relative_path
            ).items():
                self.tainted.setdefault(name, TaintMark(label, line, Confidence.HIGH))
        statements = _split_statements(tokens)
        for statement in statements[:_MAX_STATEMENTS]:
            self.budget.spend()
            if not statement:
                continue
            self._analyze_statement(statement)
        return self.builder.findings

    def _collect_declarations(self, tokens: Sequence[Token]) -> None:
        """Tên khử độc mà chính tệp này định nghĩa lại.

        Chỉ quan tâm những tên có trong bảng khử độc -- số còn lại không đổi
        được kết quả, nên không cần dựng bảng ký hiệu đầy đủ cho tám ngôn ngữ.
        Bắt hai dạng: khai báo hàm (`function escapeHtml`, `func`, `def`...) và
        gán vào chính cái tên đó (`escapeHtml = s => s`), vì cả hai đều đủ để
        cướp lấy quyền miễn trừ của bảng.

        Hai thứ KHÔNG phải là chiếm tên, và tính nhầm chúng thì bộ khử độc thật
        mất tác dụng -- tức là báo bừa đúng vào cách viết đúng nhất:

            const escapeHtml = require("escape-html");  // nạp thư viện THẬT
            utils.escapeHtml = fn;                      // gán vào thuộc tính

        Đây cũng là ranh giới mà dccc9b8 đã vạch cho phía Python: `import`
        không ghi vào môi trường, còn phép gán thì có.
        """
        limit = len(tokens)
        for index, token in enumerate(tokens):
            if token.kind != IDENT or token.in_string:
                continue
            if token.text not in self.spec.sanitizers:
                continue
            previous = tokens[index - 1] if index else None
            if previous is not None and previous.kind == OP:
                if previous.text in self.spec.chain_separators:
                    # `utils.escapeHtml` -- thuộc tính, không phải tên trần.
                    continue
            if (
                previous is not None
                and previous.kind == IDENT
                and previous.text in _FUNCTION_KEYWORDS
            ):
                self.declared.add(token.text)
                continue
            following = tokens[index + 1] if index + 1 < limit else None
            if (
                following is not None
                and following.kind == OP
                and following.text in self.spec.assignment_operators
            ):
                initializer = tokens[index + 2] if index + 2 < limit else None
                if (
                    initializer is not None
                    and initializer.kind == IDENT
                    and initializer.text in _IMPORT_CALLS
                ):
                    continue
                self.declared.add(token.text)

    def _seed_annotations(self, tokens: Sequence[Token]) -> None:
        if not self.spec.annotation_sources:
            return
        index = 0
        limit = len(tokens)
        while index < limit - 2:
            token = tokens[index]
            if token.kind == OP and token.text == "@":
                label = self.spec.annotation_sources.get(tokens[index + 1].text)
                if label is not None:
                    name = _next_declared_name(tokens, index + 2)
                    if name is not None:
                        self.tainted[name] = TaintMark(label, token.line, Confidence.HIGH)
            index += 1

    def _analyze_statement(self, statement: Sequence[Token]) -> None:
        if len(statement) > _MAX_STATEMENT_TOKENS:
            statement = statement[:_MAX_STATEMENT_TOKENS]
        if self.spec.language == "shell":
            self._analyze_shell_statement(statement)
            return
        if self.context is not None:
            self._track_callbacks(statement)
            if statement[0].kind == IDENT and statement[0].text == "return":
                self._record_return(statement[1:])
                self._model_view(statement)
        self._analyze_assignment(statement)
        self._analyze_calls(statement)
        self._analyze_backticks(statement)

    def _analyze_assignment(self, statement: Sequence[Token]) -> None:
        position = _assignment_position(statement, self.spec)
        if position is None:
            return
        left = statement[:position]
        right = statement[position + 1 :]
        if not right:
            return
        target = _assignment_target(left, self.spec)
        mark = self._taint_of(right)
        extra_targets = _destructured_targets(left, self.spec)
        if extra_targets:
            # `const { id, name: n } = req.query` / `rows, err := db.Query(q)`:
            # mỗi tên bên trái nhận trọn vết nhiễm của vế phải.
            for name in extra_targets:
                if mark is not None:
                    self.tainted[name] = mark
                    self.sanitized.discard(name)
                elif not self._in_conditional(statement[0]):
                    self.tainted.pop(name, None)
            if target is None or target in extra_targets:
                return
        if self.context is not None and target is not None:
            self._track_value_kind(target, right)

        if target is not None:
            member = target.rsplit(".", 1)[-1]
            sink = self.spec.assignment_sinks.get(member)
            if sink is not None:
                self._report_expression(
                    rule_id=sink[0],
                    dynamic_rule=None,
                    description=sink[2],
                    symbol=member,
                    tokens=right,
                    mark=mark,
                )
            previous = self.tainted.get(target)
            # Gán lại trong thân `if`/`for`/`switch`: nhánh không đi vào khối
            # vẫn mang giá trị cũ ra ngoài, nên phép gán ở đây chỉ được THÊM
            # vết nhiễm chứ không được xóa nó.
            #     term := r.FormValue("t")
            #     if level == "high" { term = html.EscapeString(term) }
            #     w.Write([]byte(term))        // vẫn thủng ở mức thấp
            conditional = previous is not None and self._in_conditional(statement[0])
            if mark is not None:
                if conditional and previous is not None:
                    mark = _merge_marks(previous, mark)
                self.tainted[target] = mark
                self.sanitized.discard(target)
                simple = target.rsplit(".", 1)[-1]
                if simple != target:
                    self.tainted.setdefault(simple, mark)
            elif not conditional:
                self.tainted.pop(target, None)
                if self._is_neutralized(right):
                    self.sanitized.add(target)
                else:
                    self.sanitized.discard(target)

    def _analyze_calls(self, statement: Sequence[Token]) -> None:
        index = 0
        limit = len(statement)
        while index < limit:
            self.budget.spend()
            chain, next_index = _read_chain(statement, index, self.spec)
            if chain is None:
                index += 1
                continue
            opens_call = (
                next_index < limit
                and statement[next_index].kind == OP
                and statement[next_index].text == "("
            )
            # Token cuối của chuỗi gọi ( `exec` trong `child_process.exec` ):
            # dùng làm điểm cuối của vùng báo lỗi để SARIF tô đúng lời gọi.
            chain_end = statement[next_index - 1] if next_index > index else statement[index]
            if opens_call:
                arguments, _ = _read_arguments(statement, next_index)
                if not (
                    self.spec.language in _JS_LANGUAGES
                    and chain in _PROCESS_METHODS
                    and index > 0
                    and statement[index - 1].kind == OP
                    and statement[index - 1].text in (".", "?.")
                ):
                    # `V[g].exec(h)`: chuỗi đọc được chỉ là `exec`, nhưng nó là
                    # phương thức của một biểu thức chứ không phải hàm trần.
                    self._check_call(chain, statement[index], arguments, chain_end)
                if self.context is not None:
                    self._project_call(chain, statement[index], arguments, statement, next_index)
            elif (
                self.context is not None
                and next_index < limit
                and statement[next_index].kind == OP
                and statement[next_index].text == "["
            ):
                self._dispatch_call(chain, statement, index, next_index)
            elif chain in self.spec.bare_call_names:
                self._check_call(
                    chain, statement[index], [list(statement[next_index:])], chain_end
                )
            index = max(next_index, index + 1)

    def _check_call(
        self,
        chain: str,
        anchor: Token,
        arguments: Sequence[Sequence[Token]],
        anchor_end: Optional[Token] = None,
    ) -> None:
        sink = _match_sink(chain, self.spec)
        if sink is None:
            return
        if self.spec.language in _JS_LANGUAGES and not self._is_process_receiver(chain):
            return
        if sink.require_sql:
            selected = _select_sql_argument(arguments, sink, chain, self.budget.spend)
            if not selected and self.context is not None:
                selected = self._select_sql_with_project(arguments, sink, anchor)
            if not selected and self._summarizing and arguments:
                self._record_conditional_sql(sink, chain, arguments, anchor)
        elif sink.program_position:
            wrapped = _shell_wrapper_argument(arguments)
            if wrapped is not None:
                self._report_expression(
                    rule_id="FSB-CMD-001",
                    dynamic_rule="FSB-CMD-003",
                    description="một lệnh shell truyền qua cờ thông dịch",
                    symbol=chain,
                    tokens=wrapped,
                    mark=self._taint_of(wrapped),
                    anchor=anchor,
                    anchor_end=anchor_end,
                    confidence=Confidence.HIGH,
                )
                return
            selected = arguments[0] if arguments else ()
        else:
            position = min(sink.argument_index, max(0, len(arguments) - 1))
            selected = arguments[position] if arguments else ()
        if not selected:
            return
        mark = self._taint_of(selected)
        self._report_expression(
            rule_id=sink.tainted_rule,
            dynamic_rule=sink.dynamic_rule,
            description=sink.description,
            symbol=chain,
            tokens=selected,
            mark=mark,
            anchor=anchor,
            anchor_end=anchor_end,
            confidence=sink.confidence,
        )

    def _analyze_backticks(self, statement: Sequence[Token]) -> None:
        if not self.spec.backtick_command:
            return
        for index, token in enumerate(statement):
            if token.kind != STRING or token.quote != "`":
                continue
            embedded = _following_interpolations(statement, index)
            if not embedded:
                continue
            mark = self._taint_of(embedded)
            self._report_expression(
                rule_id="FSB-CMD-001",
                dynamic_rule="FSB-CMD-003",
                description="một lệnh shell trong dấu backtick",
                symbol="`",
                tokens=embedded,
                mark=mark,
                anchor=token,
            )

    def _analyze_shell_statement(self, statement: Sequence[Token]) -> None:
        position = _assignment_position(statement, self.spec)
        if position == 1 and statement[0].kind == IDENT:
            mark = self._taint_of(statement[position + 1 :])
            name = statement[0].text
            if mark is not None:
                self.tainted["$" + name] = mark
            else:
                self.tainted.pop("$" + name, None)
            return
        command = statement[0]
        if command.kind != IDENT:
            return
        if command.text == "read":
            for token in statement[1:]:
                if token.kind == IDENT and not token.text.startswith("-"):
                    self.tainted["$" + token.text] = TaintMark("luồng nhập chuẩn", token.line)
            return
        if command.text in ("eval", "source", "."):
            arguments = statement[1:]
            mark = self._taint_of(arguments)
            sink = _match_sink(command.text, self.spec)
            if sink is not None:
                self._report_expression(
                    rule_id=sink.tainted_rule,
                    dynamic_rule=sink.dynamic_rule,
                    description=sink.description,
                    symbol=command.text,
                    tokens=arguments,
                    mark=mark,
                    anchor=command,
                )
            return
        if command.text in _SHELL_QUIET_COMMANDS:
            return
        for token in statement[1:]:
            if token.kind != IDENT or token.in_string or not token.text.startswith("$"):
                continue
            mark = self.tainted.get(token.text) or self._source_mark(token.text, token.line)
            if mark is None:
                continue
            self.builder.add(
                rule_id="FSB-CMD-004",
                line=token.line,
                column=token.column,
                symbol=token.text,
                message="%s được khai triển không có nháy kép trong câu lệnh; hãy viết \"%s\""
                % (mark.label, token.text),
                end_line=token.line,
                end_column=token.column + len(token.text),
                trace=(
                    self.builder.step(StepKind.SOURCE, mark.line, 0, mark.label),
                    self.builder.step(
                        StepKind.SINK, token.line, token.column, "khai triển không có nháy kép"
                    ),
                ),
            )

    # ------------------------------------------------------------------
    # Phân tích xuyên file: chỉ chạy khi có ngữ cảnh dự án.
    # ------------------------------------------------------------------
    @property
    def _summarizing(self) -> bool:
        return self.context is not None and self.context.summarizing

    def _project_call(
        self,
        chain: str,
        anchor: Token,
        arguments: Sequence[Sequence[Token]],
        statement: Sequence[Token],
        open_index: int,
    ) -> None:
        context = self.context
        if context is None:
            return
        full = context.full_arguments(anchor, chain)
        if full is not None:
            arguments = full
        head, _, method = chain.rpartition(".")
        if method == "add" and head and arguments and not context.summarizing:
            queue_name = context.is_queue(head)
            if queue_name is not None:
                payload = arguments[1] if len(arguments) >= 2 else arguments[0]
                mark = self._taint_of(payload)
                if mark is not None and not mark.params:
                    context.record_queue(queue_name, mark.label, anchor.line)
        if method == "render" and head and arguments and not context.summarizing:
            self._check_render(arguments, anchor)
        if method in ("addAttribute", "addObject") and len(arguments) >= 2:
            key = _sole_string(arguments[0])
            mark = self._taint_of(arguments[1])
            function = context.function_at(anchor)
            if key and mark is not None and function is not None:
                self.pending_model.setdefault(function.key, []).append((key, mark, anchor))
        if method in _MUTATORS and head and head.split(".")[0] not in _NOT_CONTAINERS:
            for argument in arguments:
                mark = self._taint_of(argument)
                if mark is not None:
                    self.tainted[head] = mark
                    self.sanitized.discard(head)
                    break
        for callee in context.resolve(chain, anchor, len(arguments)):
            self._apply_callee(callee, anchor, arguments)

    def _is_process_receiver(self, chain: str) -> bool:
        """`re.exec(s)` là RegExp, không phải child_process.

        Trong JavaScript `exec` là tên phương thức của MỌI biểu thức chính quy,
        nên một tệp jQuery đã minify đủ để sinh hàng chục phát hiện "lệnh
        shell" giả. Chỉ coi `x.exec(...)` là tạo tiến trình khi `x` thật sự là
        module child_process ( theo import, hoặc theo tên quen dùng ).
        """
        head, _, method = chain.rpartition(".")
        if not head or method not in _PROCESS_METHODS:
            return True
        receiver = head.rsplit(".", 1)[-1]
        if receiver in _PROCESS_RECEIVERS:
            return True
        if self.context is not None and self.context.facts is not None:
            binding = self.context.facts.imports.get(head.split(".", 1)[0])
            if binding is not None and binding.spec in _PROCESS_MODULES:
                return True
        return False

    def _record_conditional_sql(
        self, sink: GenericSink, chain: str, arguments: Sequence[Sequence[Token]], anchor: Token
    ) -> None:
        context = self.context
        if context is None:
            return
        position = min(sink.argument_index, len(arguments) - 1)
        mark = self._taint_of(arguments[position])
        if mark is None or not mark.params:
            return
        for parameter in mark.params:
            context.sink_hits.add(
                SinkHit(
                    param=parameter,
                    rule_id=sink.tainted_rule,
                    category=sink.category,
                    line=anchor.line,
                    column=anchor.column,
                    symbol=chain,
                    description=sink.description,
                    path=self.unit.relative_path,
                    requires_sql=True,
                )
            )

    def _looks_like_sql_argument(self, argument: Sequence[Token], anchor: Token) -> bool:
        return bool(self._select_sql_with_project([argument], _ANY_SQL_SINK, anchor)) or bool(
            _select_sql_argument([argument], _ANY_SQL_SINK, "", self.budget.spend)
        )

    def _dispatch_call(self, chain: str, statement: Sequence[Token], index: int, bracket: int) -> None:
        """`handlers[req.query.type](req.query.arg)`: mọi hàm trong bảng đều có thể chạy."""
        context = self.context
        if context is None:
            return
        closing = _group_end(statement, bracket)
        if closing is None or closing >= len(statement):
            return
        opener = statement[closing]
        if opener.kind != OP or opener.text != "(":
            return
        callees = context.dispatch(chain)
        if not callees:
            return
        arguments, _ = _read_arguments(statement, closing)
        for callee in callees:
            self._apply_callee(callee, statement[index], arguments)

    def _apply_callee(self, callee: Callee, anchor: Token, arguments: Sequence[Sequence[Token]]) -> None:
        context = self.context
        if context is None:
            return
        function = callee.function
        for hit in callee.summary.sinks:
            argument = _argument_for(function, hit.param, arguments)
            if not argument:
                continue
            mark = self._taint_of(argument)
            if mark is None or not mark.active_for(hit.category):
                continue
            via = (function.display,) + hit.via
            proven = not hit.requires_sql or self._looks_like_sql_argument(argument, anchor)
            if context.summarizing:
                for parameter in mark.params:
                    context.sink_hits.add(
                        replace(hit, param=parameter, via=via, requires_sql=not proven)
                    )
                continue
            if mark.params or not proven:
                continue
            self._emit_hit(hit, via, mark, anchor, callee)

    def _emit_hit(
        self, hit: SinkHit, via: Tuple[str, ...], mark: TaintMark, anchor: Token, callee: Callee
    ) -> None:
        function = callee.function
        same_file = hit.path == self.unit.relative_path
        parameter = (
            function.params[hit.param]
            if 0 <= hit.param < len(function.params) and function.params[hit.param]
            else "#%d" % (hit.param + 1)
        )
        call_step = self.builder.step(
            StepKind.CALL,
            anchor.line,
            anchor.column,
            "được truyền vào %s() ở tham số %s" % (function.display, parameter),
        )
        sink_step = self.builder.step(
            StepKind.SINK,
            hit.line,
            hit.column,
            "chạy tới %s" % hit.description,
            code="" if same_file else hit.symbol,
            path="" if same_file else hit.path,
        )
        route = " -> ".join("%s()" % name for name in via)
        crosses = (not same_file) or function.path != self.unit.relative_path
        confidence = min(mark.confidence, Confidence.HIGH)
        if callee.how == "dispatch":
            confidence = min(confidence, Confidence.MEDIUM)
        tags = ("interprocedural", "cross-file") if crosses else ("interprocedural",)
        if same_file:
            line, column = hit.line, hit.column
            message = "%s đi qua %s rồi vào %s" % (mark.label, route, hit.description)
        else:
            line, column = anchor.line, anchor.column
            message = "%s đi qua %s rồi vào %s trong %s" % (
                mark.label,
                route,
                hit.description,
                hit.path,
            )
        self.builder.add(
            rule_id=hit.rule_id,
            line=line,
            column=column,
            symbol=hit.symbol,
            message=message,
            confidence=confidence,
            trace=(
                self.builder.step(StepKind.SOURCE, mark.line, 0, "%s đi vào từ đây" % mark.label),
                call_step,
                sink_step,
            ),
            tags=tags,
        )

    def _call_result(
        self, chain: str, token: Token, tokens: Sequence[Token], open_index: int
    ) -> Optional[Tuple[Optional[TaintMark], int]]:
        """Vết nhiễm của giá trị trả về khi lời gọi trỏ về một hàm đã có summary.

        None nghĩa là "không biết hàm này": để bộ phân tích dùng quy tắc cũ
        ( đối số bẩn thì kết quả bẩn ). Biết hàm thì summary quyết định, kể cả
        khi nó nói kết quả sạch -- đó là lúc bộ khử độc viết ở tệp khác được
        công nhận.
        """
        context = self.context
        if context is None:
            return None
        arguments, after = _read_arguments(tokens, open_index)
        callees = context.resolve(chain, token, len(arguments))
        if not callees or any(not callee.summary.complete for callee in callees):
            return None
        result: Optional[TaintMark] = None
        for callee in callees:
            summary = callee.summary
            if summary.source is not None:
                result = _merge_marks(
                    result,
                    TaintMark(
                        "%s ( trả về từ %s() )" % (summary.source.label, callee.function.display),
                        token.line,
                        Confidence.HIGH,
                    ),
                )
            for parameter, cleared in summary.returns.items():
                argument = _argument_for(callee.function, parameter, arguments)
                if not argument:
                    continue
                mark = self._taint_of(argument)
                if mark is None:
                    continue
                result = _merge_marks(result, replace(mark, cleared=mark.cleared | cleared))
        return result, after

    def _record_return(self, tokens: Sequence[Token]) -> None:
        context = self.context
        if context is None or not context.summarizing or not tokens:
            return
        mark = self._taint_of(tokens)
        source = self._last_source
        if mark is None:
            return
        for parameter in mark.params:
            previous = context.returns.get(parameter)
            context.returns[parameter] = mark.cleared if previous is None else (previous & mark.cleared)
        if source is not None and context.source_return is None:
            context.source_return = SourceReturn(source.label, source.line, self.unit.relative_path)

    def _track_value_kind(self, target: str, right: Sequence[Token]) -> None:
        chains = self._chains(right)
        constants: List[str] = []
        constant_only = not any(token.interpolated for token in right)
        sql_flag = False
        for chain in chains:
            if chain in self.literal_vars:
                if chain in self.sql_vars:
                    sql_flag = True
                continue
            if chain in self.sql_vars:
                sql_flag = True
            value = self._constant(chain, right[0])
            if value is None:
                constant_only = False
            else:
                constants.append(value)
        text = " ".join([token.text for token in right if token.kind == STRING] + constants)
        if sql_flag or (text and looks_like_sql(text, self.budget.spend)):
            self.sql_vars.add(target)
        else:
            self.sql_vars.discard(target)
        if constant_only:
            self.literal_vars.add(target)
        else:
            self.literal_vars.discard(target)

    def _constant(self, chain: str, token: Optional[Token]) -> Optional[str]:
        if self.context is None:
            return None
        found = self.context.constant(chain, token)
        return found[0] if found is not None else None

    def _select_sql_with_project(
        self, arguments: Sequence[Sequence[Token]], sink: GenericSink, anchor: Token
    ) -> Sequence[Token]:
        for argument in arguments:
            pieces = [token.text for token in argument if token.kind == STRING]
            for chain in self._chains(argument):
                if chain in self.sql_vars:
                    return argument
                value = self._constant(chain, anchor)
                if value is not None:
                    pieces.append(value)
            for index, token in enumerate(argument):
                # `config.get("queries.findUser")` của node-config.
                if token.kind != IDENT or token.text != "get" or index < 2:
                    continue
                owner = argument[index - 2]
                if owner.kind != IDENT or owner.text not in _CONFIG_OBJECTS:
                    continue
                if index + 2 < len(argument) and argument[index + 2].kind == STRING:
                    value_found = self.context.config_value(argument[index + 2].text) if self.context else None
                    if value_found is not None:
                        pieces.append(value_found[0])
            text = " ".join(pieces)
            if text and looks_like_sql(text, self.budget.spend):
                return argument
        return ()

    def _is_constant_expression(self, tokens: Sequence[Token]) -> bool:
        if any(token.interpolated for token in tokens):
            return False
        chains = self._chains(tokens)
        if not chains:
            return False
        for chain in chains:
            if chain in self.literal_vars:
                continue
            if self._constant(chain, tokens[0]) is None:
                return False
        return True

    def _check_render(self, arguments: Sequence[Sequence[Token]], anchor: Token) -> None:
        context = self.context
        if context is None:
            return
        view = _sole_string(arguments[0])
        if not view:
            return
        templates = context.project.templates_for(view)
        if not templates:
            return
        mapping: Dict[str, Sequence[Token]] = {}
        wildcard: Optional[TaintMark] = None
        if len(arguments) >= 2:
            data = [token for token in arguments[1] if token.kind != NEWLINE]
            if data and data[0].kind == OP and data[0].text == "{" and data[-1].text == "}":
                for piece in _split_top_level(data[1:-1]):
                    if not piece:
                        continue
                    if piece[0].kind == OP and piece[0].text == "...":
                        spread = self._taint_of(piece[1:])
                        wildcard = wildcard or spread
                        continue
                    if len(piece) >= 3 and piece[1].kind == OP and piece[1].text == ":":
                        mapping[piece[0].text] = piece[2:]
                    elif piece[0].kind == IDENT:
                        mapping[piece[0].text] = piece[:1]
            else:
                wildcard = self._taint_of(data)
        for template in templates:
            for output in template.outputs:
                tokens = mapping.get(output.root)
                mark = self._taint_of(tokens) if tokens else wildcard
                if mark is None or mark.params or not mark.active_for(Category.MARKUP):
                    continue
                self._report_template(mark, anchor, template.path, output)

    def _model_view(self, statement: Sequence[Token]) -> None:
        context = self.context
        if context is None or context.summarizing or len(statement) < 2:
            return
        view = _sole_string(statement[1:])
        if not view:
            return
        function = context.function_at(statement[0])
        if function is None:
            return
        pending = self.pending_model.pop(function.key, [])
        if not pending:
            return
        templates = context.project.templates_for(view)
        for template in templates:
            for output in template.outputs:
                for key, mark, anchor in pending:
                    if key == output.root and not mark.params and mark.active_for(Category.MARKUP):
                        self._report_template(mark, anchor, template.path, output)

    def _report_template(self, mark: TaintMark, anchor: Token, template_path: str, output) -> None:
        self.builder.add(
            rule_id="FSB-XSS-001",
            line=anchor.line,
            column=anchor.column,
            symbol=output.root,
            message="%s được template %s in ra không escape ( %s )"
            % (mark.label, template_path, output.syntax),
            confidence=min(mark.confidence, Confidence.HIGH),
            trace=(
                self.builder.step(StepKind.SOURCE, mark.line, 0, "%s đi vào từ đây" % mark.label),
                self.builder.step(StepKind.CALL, anchor.line, anchor.column, "được đưa vào template"),
                self.builder.step(
                    StepKind.SINK,
                    output.line,
                    output.column,
                    "in ra không escape bằng %s" % output.syntax,
                    code=output.syntax,
                    path=template_path,
                ),
            ),
            tags=("cross-file", "template"),
        )

    def _track_callbacks(self, statement: Sequence[Token]) -> None:
        """Tham số của callback nhận phần tử từ một tập hợp bẩn.

            ids.forEach(id => db.query("... " + id))
            for _, v := range r.URL.Query()["x"] { exec.Command(v) }
        """
        limit = len(statement)
        for index, token in enumerate(statement):
            if token.kind != IDENT or token.in_string:
                continue
            if token.text == "range" and self.spec.language == "go":
                mark = self._taint_of(statement[index + 1 :])
                if mark is None:
                    continue
                for back in range(index - 1, -1, -1):
                    candidate = statement[back]
                    if candidate.kind == OP and candidate.text in (":=", "="):
                        names = [t for t in statement[:back] if t.kind == IDENT and t.text not in ("for", "_")]
                        if names:
                            self.tainted[names[-1].text] = mark
                        break
                continue
            if token.text not in _ITERATORS or index < 2:
                continue
            separator = statement[index - 1]
            if separator.kind != OP or separator.text not in self.spec.chain_separators + ("?.",):
                continue
            if index + 1 >= limit or statement[index + 1].text != "(":
                continue
            receiver_end = index - 2
            receiver_start = receiver_end
            while (
                receiver_start - 2 >= 0
                and statement[receiver_start - 1].kind == OP
                and statement[receiver_start - 1].text in self.spec.chain_separators
                and statement[receiver_start - 2].kind == IDENT
            ):
                receiver_start -= 2
            receiver = _read_chain(statement, receiver_start, self.spec)[0]
            if receiver is None:
                continue
            mark = self._mark_for(receiver, token.line)
            if mark is None:
                continue
            names = _callback_parameters(statement, index + 2)
            if not names:
                continue
            position = 1 if token.text == "reduce" and len(names) > 1 else 0
            self.tainted[names[position]] = mark

    def _report_expression(
        self,
        rule_id: str,
        dynamic_rule: Optional[str],
        description: str,
        symbol: str,
        tokens: Sequence[Token],
        mark: Optional[TaintMark],
        anchor: Optional[Token] = None,
        confidence: Confidence = Confidence.MEDIUM,
        anchor_end: Optional[Token] = None,
    ) -> None:
        target = anchor or (tokens[0] if tokens else None)
        if target is None:
            return
        end_line, end_column = _region_end(target, anchor_end)
        # Bộ khử độc đã chạy trên đường đi chỉ có giá trị cho ĐÚNG nhóm của nó.
        # htmlspecialchars() rồi đem vào system() thì vết nhiễm vẫn còn sống,
        # nên chỗ này hỏi lại theo nhóm của chính rule sắp báo.
        #
        # Khử đúng nhóm thì im hẳn, không rơi xuống rule "giá trị không phải
        # hằng" bên dưới: đã có người khử đúng chỗ rồi thì nhắc nữa là báo bừa.
        # Đây chính là điều kiện _is_neutralized() ở nhánh dưới vẫn luôn kiểm,
        # chỉ là nói được chính xác theo từng nhóm.
        if mark is not None and not mark.active_for(_category_of(rule_id)):
            return
        if self.context is not None and self.context.summarizing:
            if mark is not None and mark.params:
                for parameter in mark.params:
                    self.context.sink_hits.add(
                        SinkHit(
                            param=parameter,
                            rule_id=rule_id,
                            category=_category_of(rule_id),
                            line=target.line,
                            column=target.column,
                            symbol=symbol,
                            description=description,
                            path=self.unit.relative_path,
                        )
                    )
            return
        if mark is not None and mark.params:
            return
        if mark is not None:
            self.builder.add(
                rule_id=rule_id,
                line=target.line,
                column=target.column,
                symbol=symbol,
                message="%s chạy tới %s mà chưa được vô hiệu hóa" % (mark.label, description),
                end_line=end_line,
                end_column=end_column,
                confidence=min(confidence, mark.confidence),
                trace=(
                    self.builder.step(StepKind.SOURCE, mark.line, 0, "%s đi vào từ đây" % mark.label),
                    self.builder.step(
                        StepKind.SINK, target.line, target.column, "chạy tới %s" % description
                    ),
                ),
            )
            return
        if dynamic_rule is None or _is_literal(tokens) or self._is_neutralized(tokens):
            return
        if self.context is not None and self._is_constant_expression(tokens):
            return
        self.builder.add(
            rule_id=dynamic_rule,
            line=target.line,
            column=target.column,
            symbol=symbol,
            message="%s nhận một giá trị không phải hằng" % description,
            end_line=end_line,
            end_column=end_column,
            trace=(
                self.builder.step(StepKind.SINK, target.line, target.column, description),
            ),
        )

    def _taint_of(self, tokens: Sequence[Token]) -> Optional[TaintMark]:
        """Vết nhiễm còn sống trong biểu thức này, kèm những nhóm đã được khử.

        Một nhóm chỉ coi là an toàn khi MỌI vết nhiễm trong biểu thức đều đã
        được khử cho nhóm đó -- nên phần `cleared` trả về là phần giao. Chỉ cần
        một toán hạng chưa được khử là cả biểu thức vẫn thủng ở nhóm ấy.
        """
        hits: List[Tuple[int, TaintMark]] = []
        index = 0
        limit = len(tokens)
        while index < limit:
            chain, next_index = _read_chain(tokens, index, self.spec)
            if chain is None:
                index += 1
                continue
            if (
                self.context is not None
                and next_index < limit
                and tokens[next_index].kind == OP
                and tokens[next_index].text == "("
                and not tokens[next_index].in_string
            ):
                resolved = self._call_result(chain, tokens[index], tokens, next_index)
                if resolved is not None:
                    returned, after = resolved
                    if returned is not None:
                        hits.append((index, returned))
                    index = max(after, index + 1)
                    continue
            mark = self._mark_for(chain, tokens[index].line)
            if mark is not None:
                hits.append((index, mark))
            index = max(next_index, index + 1)
        if not hits:
            return None

        protected = _sanitizer_ranges(tokens, self.spec, self.declared)
        surviving: Optional[TaintMark] = None
        cleared: Optional[FrozenSet[Category]] = None
        params: FrozenSet[int] = frozenset()
        real_source: Optional[TaintMark] = None
        for position, mark in hits:
            here = mark.cleared
            for start, end, categories in protected:
                if start <= position < end:
                    here = here | categories
            cleared = here if cleared is None else (cleared & here)
            if here != _EVERY_CATEGORY:
                if surviving is None:
                    surviving = mark
                params = params | mark.params
                if real_source is None and not mark.params:
                    real_source = mark
        self._last_source = None
        if surviving is None or cleared is None or cleared == _EVERY_CATEGORY:
            return None
        self._last_source = real_source
        return replace(surviving, cleared=cleared, params=params)

    def _mark_for(self, chain: str, line: int) -> Optional[TaintMark]:
        """Vết nhiễm của một chuỗi truy cập, kể cả khi nó đi qua thuộc tính.

        `args` bẩn thì `args.host` cũng bẩn: đọc một trường ra khỏi giá trị bẩn
        không rửa sạch nó. Trước đây chỉ tên ĐẦY ĐỦ mới được tra, nên đúng cách
        viết phổ biến nhất của mọi framework -- gom tham số vào một biến rồi
        lấy từng trường -- rơi thẳng qua lưới:

            local args = ngx.req.get_uri_args()
            os.execute("ping " .. args.host)      -- không thấy vết nhiễm nào

        Phép tra theo tiền tố này đã có sẵn cho bảng nguồn ( vì `req.query.x`
        phải khớp `req.query` ), chỗ thiếu chỉ là bảng biến bẩn.
        """
        if self._summarizing and "." in chain:
            # `req.query.id` với `req` là tham số: nguồn thật thắng vết tham số,
            # vì caller thường truyền `req` -- thứ tự nó không mang vết nhiễm.
            source = self._source_mark(chain, line)
            if source is not None:
                return source
        mark = self.tainted.get(chain)
        if mark is not None:
            return mark
        # Một trường được gán lại bằng giá trị đã khử độc thì nó sạch, kể cả
        # khi cái gốc chứa nó vẫn bẩn: `args.host = tonumber(args.host)` phải
        # thắng phép tra theo tiền tố, nếu không thì cách sửa đúng cũng bị báo.
        if chain in self.sanitized:
            return None
        prefix = chain
        while "." in prefix:
            prefix = prefix.rsplit(".", 1)[0]
            mark = self.tainted.get(prefix)
            if mark is not None:
                return mark
        return self._source_mark(chain, line)

    def _source_mark(self, chain: str, line: int) -> Optional[TaintMark]:
        label = self.spec.sources.get(chain)
        if label is not None:
            return TaintMark(label, line, Confidence.HIGH)
        extra = self.context.extra_sources if self.context is not None else None
        if extra:
            label = extra.get(chain)
            if label is not None:
                return TaintMark(label, line, Confidence.HIGH)
        prefix = chain
        while "." in prefix:
            prefix = prefix.rsplit(".", 1)[0]
            label = self.spec.sources.get(prefix)
            if label is None and extra:
                label = extra.get(prefix)
            if label is not None:
                return TaintMark(label, line, Confidence.HIGH)
        return None

    def _is_sanitized(self, tokens: Sequence[Token]) -> bool:
        # Cùng lý do với _sanitizer_ranges: một cái tên do chính tệp này định
        # nghĩa thì không được hưởng quyền miễn trừ của bảng.
        for chain in self._chains(tokens):
            if chain in self.spec.sanitizers and chain not in self.declared:
                return True
        return False

    def _is_neutralized(self, tokens: Sequence[Token]) -> bool:
        if self._is_sanitized(tokens):
            return True
        chains = self._chains(tokens)
        if not chains:
            return False
        return all(chain in self.sanitized for chain in chains)

    def _chains(self, tokens: Sequence[Token]) -> List[str]:
        found: List[str] = []
        index = 0
        limit = len(tokens)
        while index < limit:
            chain, next_index = _read_chain(tokens, index, self.spec)
            if chain is not None:
                found.append(chain)
            index = max(next_index if chain else index + 1, index + 1)
        return found


_MUTATORS = frozenset(
    {"push", "unshift", "add", "addAll", "put", "putAll", "append", "insert", "extend", "offer", "Add", "AddRange", "Store", "set", "concat"}
)
# Đối tượng có phương thức trùng tên mutator nhưng không phải tập hợp dữ liệu:
# `res.set("X-Frame-Options", v)` không làm `res` thành dữ liệu bẩn.
_NOT_CONTAINERS = frozenset(
    {"res", "response", "resp", "w", "ctx", "c", "reply", "headers", "this", "self", "model", "app", "router", "logger", "log", "console", "cache", "redis", "client", "queue", "map", "url", "searchParams", "params", "cookies", "session", "req", "request", "r", "builder", "sb", "set"}
)
_ITERATORS = frozenset(
    {"forEach", "map", "flatMap", "filter", "find", "some", "every", "reduce", "then", "each", "forEachOrdered", "peek", "anyMatch", "allMatch"}
)
_CONFIG_OBJECTS = frozenset({"config", "nconf", "conf", "settings", "cfg"})
_JS_LANGUAGES = frozenset({"javascript", "typescript"})
_PROCESS_METHODS = frozenset({"exec", "execSync"})
_PROCESS_RECEIVERS = frozenset(
    {"child_process", "childProcess", "cp", "proc", "shell", "shelljs", "sh", "execa", "childproc", "child", "processes"}
)
_PROCESS_MODULES = frozenset({"child_process", "node:child_process", "shelljs", "execa", "child-process-promise"})
_ANY_SQL_SINK = GenericSink((), Category.SQL, "FSB-SQL-001", "FSB-SQL-002", "", require_sql=True)


def _argument_for(
    function: FunctionDef, parameter: int, arguments: Sequence[Sequence[Token]]
) -> Optional[List[Token]]:
    if parameter < 0:
        return None
    if function.variadic and function.params and parameter == len(function.params) - 1:
        if parameter >= len(arguments):
            return None
        merged: List[Token] = []
        for argument in arguments[parameter:]:
            merged.extend(argument)
        return merged
    if parameter >= len(arguments):
        return None
    return list(arguments[parameter])


def _merge_marks(current: Optional[TaintMark], new: TaintMark) -> TaintMark:
    if current is None:
        return new
    return replace(
        current,
        cleared=current.cleared & new.cleared,
        params=current.params | new.params,
    )


def _split_top_level(tokens: Sequence[Token]) -> List[List[Token]]:
    pieces: List[List[Token]] = [[]]
    depth = 0
    for token in tokens:
        if token.kind == OP and not token.in_string:
            if token.text in "([{":
                depth += 1
            elif token.text in ")]}":
                depth -= 1
            elif token.text == "," and depth == 0:
                pieces.append([])
                continue
        pieces[-1].append(token)
    return pieces


def _callback_parameters(statement: Sequence[Token], start: int) -> List[str]:
    """Tên tham số của hàm callback bắt đầu tại `start` ( `x =>`, `(a, b) =>`, `x ->` )."""
    limit = min(len(statement), start + 24)
    if start >= limit:
        return []
    first = statement[start]
    if first.kind == IDENT and first.text in ("async", "function"):
        start += 1
        if start < limit and statement[start].kind == IDENT and statement[start].text == "function":
            start += 1
        if start < limit and statement[start].kind == IDENT and statement[start - 1].text == "function":
            start += 1
        first = statement[start] if start < limit else first
    if first.kind == IDENT:
        following = statement[start + 1] if start + 1 < limit else None
        if following is not None and following.kind == OP and following.text in ("=>", "->"):
            return [first.text]
        return []
    if first.kind == OP and first.text == "(":
        names: List[str] = []
        cursor = start + 1
        expect_name = True
        while cursor < limit:
            token = statement[cursor]
            if token.kind == OP and token.text == ")":
                after = statement[cursor + 1] if cursor + 1 < limit else None
                if after is not None and after.kind == OP and after.text in ("=>", "->", "{"):
                    return names
                if after is None:
                    return names
                return names
            if token.kind == OP and token.text == ",":
                expect_name = True
            elif token.kind == IDENT and expect_name:
                names.append(token.text)
                expect_name = False
            cursor += 1
    return []


def _destructured_targets(left: Sequence[Token], spec: LanguageSpec) -> List[str]:
    """Tên được gán khi vế trái là mẫu phá cấu trúc hoặc danh sách nhiều tên."""
    tokens = [token for token in _strip_type_annotation_pattern(left, spec) if token.kind != NEWLINE]
    while tokens and tokens[0].kind == IDENT and tokens[0].text in _DECLARATORS:
        tokens = tokens[1:]
    if not tokens:
        return []
    first = tokens[0]
    if first.kind == OP and first.text in ("{", "[") and not first.in_string:
        names: List[str] = []
        depth = 0
        skipping_default = False
        for index, token in enumerate(tokens):
            if token.kind == OP and not token.in_string:
                if token.text in "{[(":
                    depth += 1
                elif token.text in "}])":
                    depth -= 1
                    if depth == 0:
                        break
                elif token.text == ",":
                    skipping_default = False
                elif token.text == "=":
                    skipping_default = True
                continue
            if token.kind != IDENT or skipping_default:
                continue
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if following is not None and following.kind == OP and following.text == ":":
                continue
            names.append(token.text)
        return names
    # Go / Lua: `a, err := f()` -- vế trái có dấu phẩy ở cấp ngoài cùng.
    pieces = _split_top_level(tokens)
    if len(pieces) < 2:
        return []
    names = []
    for piece in pieces:
        chain, _ = _read_chain(piece, 0, spec) if piece else (None, 0)
        if chain and chain != "_":
            names.append(chain)
    return names


_DECLARATORS = frozenset({"const", "let", "var", "val", "export", "local", "my", "our"})


def _strip_type_annotation_pattern(left: Sequence[Token], spec: LanguageSpec) -> Sequence[Token]:
    """`const { a }: Props = ...` -- bỏ phần kiểu sau mẫu phá cấu trúc."""
    if spec.annotation_separator is None:
        return left
    depth = 0
    for index, token in enumerate(left):
        if token.kind != OP or token.in_string:
            continue
        if token.text in "([{":
            depth += 1
        elif token.text in ")]}":
            depth -= 1
        elif depth == 0 and token.text == spec.annotation_separator and index > 0:
            return left[:index]
    return left


def _category_of(rule_id: str) -> Category:
    return get_rule(rule_id).category


def _split_statements(tokens: Sequence[Token]) -> List[List[Token]]:
    statements: List[List[Token]] = []
    current: List[Token] = []
    depth = 0
    patterns = _destructuring_braces(tokens)
    pattern_end = -1
    for position, token in enumerate(tokens):
        if token.kind == NEWLINE:
            if depth == 0 and current and not _continues(current[-1]) and position > pattern_end:
                statements.append(current)
                current = []
            continue
        if token.kind == OP and not token.in_string:
            if position in patterns:
                pattern_end = patterns[position]
            if position <= pattern_end:
                current.append(token)
                continue
            if token.text in "([":
                depth += 1
            elif token.text in ")]":
                depth = max(0, depth - 1)
            elif token.text in _STATEMENT_BREAKS:
                if current:
                    statements.append(current)
                current = []
                depth = 0
                continue
        current.append(token)
        if len(current) > _MAX_STATEMENT_TOKENS:
            statements.append(current)
            current = []
    if current:
        statements.append(current)
    return statements


def _destructuring_braces(tokens: Sequence[Token]) -> Dict[int, int]:
    """`const { a, b } = x`: ngoặc nhọn của mẫu phá cấu trúc không cắt câu lệnh."""
    found: Dict[int, int] = {}
    previous: Optional[Token] = None
    for index, token in enumerate(tokens):
        if token.kind == NEWLINE:
            continue
        if (
            token.kind == OP
            and token.text == "{"
            and not token.in_string
            and previous is not None
            and previous.kind == IDENT
            and previous.text in ("const", "let", "var")
        ):
            depth = 0
            for cursor in range(index, min(len(tokens), index + 256)):
                inner = tokens[cursor]
                if inner.kind != OP or inner.in_string:
                    continue
                if inner.text == "{":
                    depth += 1
                elif inner.text == "}":
                    depth -= 1
                    if depth == 0:
                        after = cursor + 1
                        while after < len(tokens) and tokens[after].kind == NEWLINE:
                            after += 1
                        if after < len(tokens) and tokens[after].kind == OP and tokens[after].text in ("=", ":"):
                            found[index] = cursor
                        break
                elif inner.text == ";":
                    break
        previous = token
    return found


def _continues(token: Token) -> bool:
    return token.kind == OP and token.text in _CONTINUATION_OPERATORS


def _assignment_position(statement: Sequence[Token], spec: LanguageSpec) -> Optional[int]:
    depth = 0
    for index, token in enumerate(statement):
        if token.kind != OP or token.in_string:
            continue
        if token.text in "([":
            depth += 1
        elif token.text in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and token.text in spec.assignment_operators:
            return index
    return None


def _strip_type_annotation(left: Sequence[Token], spec: LanguageSpec) -> Sequence[Token]:
    """Drop ``: T`` from ``const x: T = ...`` so the target stays ``x``.

    Only the first separator at bracket depth zero counts; a colon inside an
    object literal, a generic argument or an index type belongs to the type, not
    to the declaration.
    """
    separator = spec.annotation_separator
    if separator is None:
        return left
    depth = 0
    for index, token in enumerate(left):
        if token.kind != OP or token.in_string:
            continue
        if token.text in "([{":
            depth += 1
        elif token.text in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and token.text == separator:
            trimmed = list(left[:index])
            while trimmed and trimmed[-1].kind == OP and trimmed[-1].text == "?":
                trimmed.pop()
            return trimmed
    return left


def _assignment_target(left: Sequence[Token], spec: LanguageSpec) -> Optional[str]:
    left = _strip_type_annotation(left, spec)
    filtered = [token for token in left if token.kind in (IDENT, OP)]
    if not filtered:
        return None
    end = len(filtered)
    start = end - 1
    while start > 0:
        previous = filtered[start - 1]
        if previous.kind == OP and previous.text in spec.chain_separators:
            start -= 2
            continue
        break
    if start < 0:
        start = 0
    chain, _ = _read_chain(filtered, start, spec)
    if chain is None:
        return None
    if chain in spec.declaration_keywords:
        return None
    return chain


def _read_chain(
    tokens: Sequence[Token], index: int, spec: LanguageSpec
) -> Tuple[Optional[str], int]:
    limit = len(tokens)
    if index >= limit or tokens[index].kind != IDENT:
        return None, index
    parts = [tokens[index].text]
    cursor = index + 1
    while cursor + 1 < limit:
        separator = tokens[cursor]
        if separator.kind == OP and separator.text == "(" and cursor + 1 < limit:
            if tokens[cursor + 1].kind == OP and tokens[cursor + 1].text == ")":
                if (
                    cursor + 3 < limit
                    and tokens[cursor + 2].kind == OP
                    and tokens[cursor + 2].text in spec.chain_separators
                    and tokens[cursor + 3].kind == IDENT
                ):
                    parts.append(tokens[cursor + 3].text)
                    cursor += 4
                    continue
            break
        if separator.kind != OP or separator.text not in spec.chain_separators:
            break
        following = tokens[cursor + 1]
        if following.kind != IDENT:
            break
        parts.append(following.text)
        cursor += 2
    return ".".join(parts), cursor


def _read_arguments(
    tokens: Sequence[Token], open_index: int
) -> Tuple[List[List[Token]], int]:
    arguments: List[List[Token]] = []
    current: List[Token] = []
    depth = 0
    index = open_index
    limit = len(tokens)
    while index < limit:
        token = tokens[index]
        if token.kind == OP and not token.in_string:
            if token.text in "([{":
                depth += 1
                if depth == 1 and index == open_index:
                    index += 1
                    continue
            elif token.text in ")]}":
                depth -= 1
                if depth == 0:
                    if current:
                        arguments.append(current)
                    return arguments, index + 1
            elif token.text == "," and depth == 1:
                arguments.append(current)
                current = []
                index += 1
                continue
        current.append(token)
        index += 1
    if current:
        arguments.append(current)
    return arguments, limit


_SHELL_BINARIES = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "cmd", "cmd.exe", "powershell", "pwsh", "busybox"}
)
_SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command", "-command"})


def _shell_wrapper_argument(
    arguments: Sequence[Sequence[Token]],
) -> Optional[Sequence[Token]]:
    if len(arguments) < 3:
        return None
    program = _sole_string(arguments[0])
    if program is None:
        return None
    if program.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() not in _SHELL_BINARIES:
        return None
    for index in range(1, len(arguments) - 1):
        flag = _sole_string(arguments[index])
        if flag is not None and flag in _SHELL_FLAGS:
            return arguments[index + 1]
    return None


def _sole_string(argument: Sequence[Token]) -> Optional[str]:
    meaningful = [token for token in argument if not token.in_string]
    if len(meaningful) == 1 and meaningful[0].kind == STRING:
        return meaningful[0].text
    return None


_ALWAYS_SQL = frozenset(
    {
        "mysqli_query",
        "mysqli_multi_query",
        "mysql_query",
        "pg_query",
        "sqlite_query",
        "find_by_sql",
        "exec_query",
        "select_all",
        "knex.raw",
        "sequelize.query",
        "FromSqlRaw",
        "ExecuteSqlRaw",
        "createNativeQuery",
        "createSQLQuery",
    }
)


def _region_end(
    anchor: Token, anchor_end: Optional[Token]
) -> Tuple[Optional[int], Optional[int]]:
    """Điểm cuối của vùng báo lỗi, hoặc (None, None) nếu không chắc chắn.

    Chỉ nhận token IDENT đọc thẳng từ nguồn: với STRING thì `text` là phần
    thân đã bỏ nháy nên `column + len(text)` không còn là vị trí thật, còn
    token nội suy mang vị trí của cả chuỗi bọc ngoài. Thà để vùng rộng một ký
    tự như trước còn hơn tô sai đoạn mã.
    """
    candidate = anchor_end if anchor_end is not None else anchor
    if candidate.kind != IDENT or candidate.in_string or candidate.interpolated:
        candidate = anchor
    if candidate.kind != IDENT or candidate.in_string or candidate.interpolated:
        return None, None
    if candidate.line < anchor.line:
        return None, None
    if candidate.line == anchor.line and candidate.column < anchor.column:
        return None, None
    return candidate.line, candidate.column + len(candidate.text)


def _select_sql_argument(
    arguments: Sequence[Sequence[Token]],
    sink: GenericSink,
    chain: str,
    spend: Optional[Callable[[int], None]] = None,
) -> Sequence[Token]:
    for argument in arguments:
        text = " ".join(token.text for token in argument if token.kind == STRING)
        if looks_like_sql(text, spend):
            return argument
    tail = chain.rsplit(".", 1)[-1]
    if chain in _ALWAYS_SQL or tail in _ALWAYS_SQL:
        position = min(sink.argument_index, max(0, len(arguments) - 1))
        if arguments:
            return arguments[position]
    return ()


def _match_sink(chain: str, spec: LanguageSpec) -> Optional[GenericSink]:
    best: Optional[GenericSink] = None
    best_length = -1
    for sink in spec.sinks:
        for name in sink.names:
            if chain == name or chain.endswith("." + name):
                if len(name) > best_length:
                    best = sink
                    best_length = len(name)
    return best


def _sanitizer_ranges(
    tokens: Sequence[Token], spec: LanguageSpec, declared: Set[str]
) -> List[Tuple[int, int, FrozenSet[Category]]]:
    """Khoảng token nằm trong một lời gọi khử độc, kèm nhóm mà nó khử.

    `declared` là những cái tên chính tệp được quét tự định nghĩa. Bảng khử độc
    tra theo TÊN, nên không loại chúng ra thì bốn dòng dưới đây đủ để tắt một
    phát hiện critical, và tắt trong im lặng:

        function escapeHtml(s) { return s; }
        cp.exec("ping " + escapeHtml(req.query.host));

    Đây đúng lập luận đã dùng cho phía Python ở dccc9b8: bỏ sót một cái tên bị
    che ở phía sink chỉ tốn thêm một phát hiện, còn bỏ sót ở đây thì xoá mất
    một phát hiện thật.
    """
    ranges: List[Tuple[int, int, FrozenSet[Category]]] = []
    index = 0
    limit = len(tokens)
    while index < limit:
        cast = _cast_range(tokens, index, spec, declared)
        if cast is not None:
            ranges.append(cast)
            index = cast[1]
            continue
        chain, next_index = _read_chain(tokens, index, spec)
        categories = spec.sanitizers.get(chain) if chain is not None else None
        if categories is not None and chain not in declared:
            if next_index < limit and tokens[next_index].kind == OP:
                if tokens[next_index].text == "(":
                    _, after = _read_arguments(tokens, next_index)
                    ranges.append((index, after, categories))
                    index = after
                    continue
        index = max(next_index if chain else index + 1, index + 1)
    return ranges


def _cast_range(
    tokens: Sequence[Token], index: int, spec: LanguageSpec, declared: Set[str]
) -> Optional[Tuple[int, int, FrozenSet[Category]]]:
    """Phạm vi của một phép ép kiểu tiền tố, ví dụ `[int]$args[0]`.

    Phép ép kiểu bám vào ĐÚNG biểu thức đứng ngay sau nó, nên phạm vi dừng
    ngay sau chuỗi truy cập kế tiếp cùng các nhóm ngoặc bám theo. Kéo dài tới
    hết câu lệnh là sai theo hướng nguy hiểm: trong `[int]$a + $b`, phép ép
    kiểu không hề đụng tới `$b`.
    """
    delimiters = spec.cast_delimiters
    if not delimiters or index + 3 >= len(tokens):
        return None
    opening, closing = delimiters
    if tokens[index].kind != OP or tokens[index].text != opening:
        return None
    name, after_name = _read_chain(tokens, index + 1, spec)
    if name is None or after_name >= len(tokens):
        return None
    if tokens[after_name].kind != OP or tokens[after_name].text != closing:
        return None
    categories = spec.sanitizers.get(name)
    if categories is None or name in declared:
        return None
    return (after_name + 1, _postfix_end(tokens, after_name + 1, spec), categories)


def _postfix_end(tokens: Sequence[Token], start: int, spec: LanguageSpec) -> int:
    """Vị trí ngay sau biểu thức bắt đầu tại `start`, tính cả `[...]` và `(...)`."""
    chain, cursor = _read_chain(tokens, start, spec)
    if chain is None:
        cursor = start + 1
    limit = len(tokens)
    while cursor < limit and tokens[cursor].kind == OP and tokens[cursor].text in "([{":
        after = _group_end(tokens, cursor)
        if after is None:
            break
        cursor = after
    return cursor


def _group_end(tokens: Sequence[Token], opening: int) -> Optional[int]:
    """Vị trí ngay sau nhóm ngoặc mở tại `opening`; None nếu nó không đóng."""
    depth = 0
    for cursor in range(opening, len(tokens)):
        token = tokens[cursor]
        if token.kind != OP or token.in_string:
            continue
        if token.text in "([{":
            depth += 1
        elif token.text in ")]}":
            depth -= 1
            if depth == 0:
                return cursor + 1
    return None


def _is_literal(tokens: Sequence[Token]) -> bool:
    for token in tokens:
        if token.interpolated:
            return False
        if token.kind in (IDENT,):
            return False
    return True


def _following_interpolations(statement: Sequence[Token], index: int) -> List[Token]:
    collected: List[Token] = []
    cursor = index + 1
    while cursor < len(statement) and statement[cursor].in_string:
        collected.append(statement[cursor])
        cursor += 1
    return collected


def _next_declared_name(tokens: Sequence[Token], index: int) -> Optional[str]:
    cursor = index
    limit = min(len(tokens), index + 12)
    last: Optional[str] = None
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == IDENT:
            last = token.text
        elif token.kind == OP and token.text in (",", ")"):
            break
        cursor += 1
    return last
