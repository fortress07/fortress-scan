from __future__ import annotations

import re

from dataclasses import dataclass, replace
from typing import Callable, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...core.model import Category, Confidence, Finding, StepKind
from ...core.registry import get_rule
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from ..python.specs import looks_like_sql
from .lexer import IDENT, NEWLINE, OP, STRING, Token, tokenize
from .profiles import REQUEST_BOUND_PARAMETER, VALIDATION_ANNOTATIONS, GenericSink, LanguageSpec, spec_for

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

    def active_for(self, category: Category) -> bool:
        return category not in self.cleared


class GenericAnalyzer(Analyzer):
    name = "generic-dataflow"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        spec = spec_for(unit.language)
        if spec is None:
            return []
        try:
            source = unit.source
            if spec.strip_preprocessor:
                from ..native.cparse import strip_preprocessor

                source, _macros = strip_preprocessor(source)
            tokens = tokenize(source, spec.lexer, budget)
            if spec.case_insensitive:
                tokens = _canonical_case(tokens, spec)
            return _Analysis(unit, spec, budget).run(tokens)
        except BudgetExceeded:
            return []


class _Analysis:
    def __init__(self, unit: AnalysisUnit, spec: LanguageSpec, budget: Budget) -> None:
        self.unit = unit
        self.spec = spec
        self.budget = budget
        self.builder = FindingBuilder(unit)
        self.tainted: Dict[str, TaintMark] = {}
        self.sanitized: Set[str] = set()
        self.declared: Set[str] = set()
        # Biến đang mang văn bản SQL ( `q = "SELECT ... " + id` ): truyền nó vào
        # executeQuery(q) / db.Query(q) / new SqlCommand(q) là truyền một câu SQL,
        # dù tại chỗ gọi không còn literal nào để nhận ra.
        self.sql_like: Set[str] = set()
        # Biến giữ nguyên một GString có nội suy ( Groovy ): sink tham số hoá
        # nhận nó vẫn bind giá trị, không dán.
        self.parameterized: Set[str] = set()
        self.receiver_sinks: Dict[str, GenericSink] = {}
        for sink in spec.sinks:
            if sink.receiver:
                for name in sink.names:
                    self.receiver_sinks[name.rsplit(".", 1)[-1]] = sink
        self.tracks_parameterized = any(sink.interpolation_parameterized for sink in spec.sinks)
        # Tham số của một hàm chỉ sống trong thân hàm đó: `name` của handler này
        # không làm bẩn `name` của hàm tiện ích viết bên dưới. ( đầu, cuối, tên,
        # vết nhiễm hoặc None nghĩa là "sạch" ).
        self.scoped: List[Tuple[Tuple[int, int], Tuple[int, int], str, Optional[TaintMark]]] = []

    def run(self, tokens: Sequence[Token]) -> List[Finding]:
        self._collect_declarations(tokens)
        self._seed_annotations(tokens)
        statements = _split_statements(tokens)
        pending = sorted(self.scoped, key=lambda item: item[0])
        active: List[Tuple[Tuple[int, int], Tuple[int, int], str, Optional[TaintMark]]] = []
        for statement in statements[:_MAX_STATEMENTS]:
            self.budget.spend()
            if not statement:
                continue
            if pending or active:
                position = (statement[0].line, statement[0].column)
                while pending and pending[0][0] <= position:
                    entry = pending.pop(0)
                    self._enter_scope(entry)
                    active.append(entry)
                for entry in [item for item in active if item[1] <= position]:
                    active.remove(entry)
                    self._leave_scope(entry)
            self._analyze_statement(statement)
        return self.builder.findings

    def _enter_scope(self, entry) -> None:
        _, _, name, mark = entry
        if mark is None:
            self.tainted.pop(name, None)
            self.sanitized.add(name)
        else:
            self.tainted[name] = mark
            self.sanitized.discard(name)

    def _leave_scope(self, entry) -> None:
        _, _, name, mark = entry
        if mark is None:
            self.sanitized.discard(name)
        elif self.tainted.get(name) is mark:
            self.tainted.pop(name, None)

    def _seed_parameter(self, tokens: Sequence[Token], index: int, name: str, mark: Optional[TaintMark]) -> None:
        """Gắn vết nhiễm ( hoặc "sạch" ) cho tham số `name` khai ở vị trí `index`,
        chỉ trong thân hàm; không tìm được thân hàm thì gắn cho cả tệp như trước."""
        span = _body_span(tokens, index)
        if span is not None:
            self.scoped.append((span[0], span[1], name, mark))
        elif mark is None:
            self.sanitized.add(name)
        else:
            self.tainted[name] = mark

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
        if self.spec.conn_param_patterns:
            self._seed_conn_patterns(tokens)
        if self.spec.attribute_sources or self.spec.handler_annotations or self.spec.handler_body_markers:
            self._seed_handlers(tokens)
        if self.spec.lambda_sources:
            self._seed_lambda_sources(tokens)
        if self.spec.parameter_label_sources:
            self._seed_label_parameters(tokens)
        if not self.spec.annotation_sources:
            return
        index = 0
        limit = len(tokens)
        while index < limit - 2:
            token = tokens[index]
            if token.kind == OP and token.text == "@":
                label = self.spec.annotation_sources.get(tokens[index + 1].text)
                if label is not None:
                    name = _next_declared_name(tokens, index + 2, self.spec.annotation_separator)
                    if name is not None and _scalar_parameter(tokens, index + 2):
                        # Framework đã parse thành số: giá trị sạch, không chỉ "không bẩn".
                        self._seed_parameter(tokens, index, name, None)
                    elif name is not None:
                        self._seed_parameter(tokens, index, name, TaintMark(label, token.line, Confidence.HIGH))
            index += 1

    def _seed_handlers(self, tokens: Sequence[Token]) -> None:
        """Tham số mà framework gắn thẳng từ request.

        Hai dạng: attribute trên chính tham số ( `[FromQuery] string id` ), và
        tham số kiểu chuỗi của một phương thức mang annotation xử lý request
        ( `@GetMapping` của Spring, `[HttpGet]` của ASP.NET ). Ở dạng thứ hai
        framework tự gắn tham số không annotation từ query/form/route, nên đó
        là cách viết phổ biến nhất mà lại không có dấu hiệu nguồn nào tại chỗ.
        """
        spec = self.spec
        limit = len(tokens)
        for index, token in enumerate(tokens):
            if (
                spec.handler_body_markers
                and token.kind == IDENT
                and token.text == "def"
                and not token.in_string
                and _returns_action(tokens, index, spec)
            ):
                self._seed_handler_parameters(tokens, index + 1)
                continue
            if token.kind != OP or token.in_string or index + 1 >= limit:
                continue
            name_token = tokens[index + 1]
            if name_token.kind != IDENT:
                continue
            if token.text == "[":
                close = _group_end(tokens, index)
                if close is None:
                    continue
                label = spec.attribute_sources.get(name_token.text)
                if label is not None:
                    name = _next_declared_name(tokens, close, spec.annotation_separator)
                    if name is not None:
                        self._seed_parameter(tokens, index, name, TaintMark(label, token.line, Confidence.HIGH))
                    continue
                if name_token.text in spec.handler_annotations:
                    self._seed_handler_parameters(tokens, close)
            elif token.text == "@" and name_token.text in spec.handler_annotations:
                after = index + 2
                if after < limit and tokens[after].kind == OP and tokens[after].text == "(":
                    after = _group_end(tokens, after) or after
                self._seed_handler_parameters(tokens, after)

    def _seed_handler_parameters(self, tokens: Sequence[Token], start: int) -> None:
        spec = self.spec
        limit = len(tokens)
        cursor = start
        # Bỏ qua các annotation/attribute khác và modifier tới dấu `(` của
        # danh sách tham số; dừng nếu gặp thân hàm hoặc hết câu lệnh trước đó.
        while cursor < limit:
            current = tokens[cursor]
            if current.kind == IDENT and current.text in ("class", "interface", "object", "record", "struct"):
                return
            if current.kind == OP and not current.in_string:
                if current.text in ("{", "}", ";", "="):
                    return
                if current.text == "[" or (current.text == "@" and cursor + 1 < limit):
                    if current.text == "@":
                        cursor += 2
                        if cursor < limit and tokens[cursor].kind == OP and tokens[cursor].text == "(":
                            cursor = _group_end(tokens, cursor) or limit
                        continue
                    cursor = _group_end(tokens, cursor) or limit
                    continue
                if current.text == "(" and cursor > start and tokens[cursor - 1].kind == IDENT:
                    break
            cursor += 1
        if cursor >= limit:
            return
        close = _group_end(tokens, cursor)
        if close is None:
            return
        arguments, _ = _read_arguments(tokens, cursor)
        for parameter in arguments:
            name = _handler_parameter_name(parameter, spec)
            if name is not None:
                self._seed_parameter(
                    tokens, cursor + 1, name, TaintMark(REQUEST_BOUND_PARAMETER, parameter[0].line, Confidence.HIGH)
                )

    def _seed_label_parameters(self, tokens: Sequence[Token]) -> None:
        """`open url: URL`: tham số mang nhãn ngoài này đến từ bên ngoài app."""
        for index in range(1, len(tokens) - 2):
            token = tokens[index]
            if token.kind != IDENT or token.in_string:
                continue
            label = self.spec.parameter_label_sources.get(token.text)
            if label is None:
                continue
            back = index - 1
            while back > 0 and tokens[back].kind == NEWLINE:
                back -= 1
            before, name, colon = tokens[back], tokens[index + 1], tokens[index + 2]
            if before.kind != OP or before.text not in ("(", ","):
                continue
            if name.kind != IDENT or colon.kind != OP or colon.text != ":":
                continue
            self._seed_parameter(tokens, index, name.text, TaintMark(label, token.line, Confidence.HIGH))

    def _seed_lambda_sources(self, tokens: Sequence[Token]) -> None:
        """`parameter("q") { q => ... }`, `path("u" / Segment) { id => ... }`.

        Directive của Akka HTTP / Pekko đưa giá trị request vào tham số của
        lambda ngay sau nó; tên chỉ sống trong khối `{ ... }` đó.
        """
        limit = len(tokens)
        for index, token in enumerate(tokens):
            if token.kind != IDENT or token.in_string:
                continue
            label = self.spec.lambda_sources.get(token.text)
            if label is None or index + 1 >= limit or tokens[index + 1].text != "(":
                continue
            if index > 0 and tokens[index - 1].kind == OP and tokens[index - 1].text == ".":
                continue
            cursor = index + 1
            groups: List[Token] = []
            while cursor < limit and tokens[cursor].kind == OP and tokens[cursor].text == "(":
                after = _group_end(tokens, cursor)
                if after is None:
                    break
                groups.extend(tokens[cursor:after])
                cursor = after
            if token.text in ("path", "pathPrefix", "pathSuffix") and not any(
                item.kind == IDENT and item.text in _PATH_TEXT_MATCHERS for item in groups
            ):
                # path(IntNumber) / path("health"): không có đoạn chữ tự do nào.
                continue
            while cursor < limit and tokens[cursor].kind == NEWLINE:
                cursor += 1
            if cursor >= limit or tokens[cursor].text != "{":
                continue
            close = _group_end(tokens, cursor)
            if close is None:
                continue
            names = _lambda_parameters(tokens, cursor + 1, close)
            if not names:
                continue
            start = (tokens[cursor].line, tokens[cursor].column)
            end = (tokens[close - 1].line, tokens[close - 1].column)
            for name in names:
                self.scoped.append((start, end, name, TaintMark(label, token.line, Confidence.HIGH)))

    def _seed_conn_patterns(self, tokens: Sequence[Token]) -> None:
        """`def show(conn, %{"id" => id, "q" => q})`: id, q là tham số request.

        Chỉ nhận đầu hàm có `conn` ( action của Phoenix controller ); một hàm
        bình thường khớp mẫu map thì không phải nguồn.
        """
        limit = len(tokens)
        for index, token in enumerate(tokens):
            if token.kind != IDENT or token.text not in ("def", "defp"):
                continue
            if index + 3 >= limit or tokens[index + 2].text != "(":
                continue
            if tokens[index + 3].text not in ("conn", "_conn"):
                continue
            close = _group_end(tokens, index + 2)
            if close is None:
                continue
            for cursor in range(index + 3, close - 2):
                if (
                    tokens[cursor].kind == STRING
                    and tokens[cursor + 1].kind == OP
                    and tokens[cursor + 1].text == "=>"
                    and tokens[cursor + 2].kind == IDENT
                ):
                    self.tainted[tokens[cursor + 2].text] = TaintMark(
                        "tham số request Phoenix", tokens[cursor].line, Confidence.HIGH
                    )

    def _analyze_statement(self, statement: Sequence[Token]) -> None:
        if len(statement) > _MAX_STATEMENT_TOKENS:
            statement = statement[:_MAX_STATEMENT_TOKENS]
        if self.spec.language == "shell":
            self._analyze_shell_statement(statement)
            return
        self._analyze_assignment(statement)
        self._analyze_calls(statement)
        if self.receiver_sinks:
            self._analyze_receiver_calls(statement)
        if self.spec.stream_sources:
            self._analyze_extraction(statement)
        if self.spec.redirect_view_prefix:
            self._analyze_redirect_view(statement)
        if self.spec.spliced_sql_prefixes:
            self._analyze_sql_splices(statement)
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
        compound = statement[position].text not in ("=", ":=", "<-")
        if target is not None:
            if self._mentions_sql(right):
                self.sql_like.add(target)
            elif not compound:
                self.sql_like.discard(target)
            if self.tracks_parameterized:
                if not compound and _is_lone_template(right):
                    self.parameterized.add(target)
                else:
                    self.parameterized.discard(target)

        if target is not None:
            member = target.rsplit(".", 1)[-1]
            sink = self.spec.assignment_sinks.get(member)
            listed = _listed_elements(right) if sink is not None and sink[1] is Category.COMMAND else None
            if listed and _sole_string(listed[0]) in _SHELL_FLAGS:
                # `task.arguments = ["-c", cmd]`: phần còn lại là một lệnh shell.
                rest = [token for item in listed[1:] for token in item]
                self._report_expression(
                    rule_id="FSB-CMD-001",
                    dynamic_rule="FSB-CMD-003",
                    description="một lệnh shell truyền qua cờ thông dịch",
                    symbol=member,
                    tokens=rest,
                    mark=self._taint_of(rest),
                    confidence=Confidence.HIGH,
                )
            elif sink is not None:
                self._report_expression(
                    rule_id=sink[0],
                    dynamic_rule=None,
                    description=sink[2],
                    symbol=member,
                    tokens=right,
                    mark=mark,
                )
            if mark is not None:
                self.tainted[target] = mark
                self.sanitized.discard(target)
                simple = target.rsplit(".", 1)[-1]
                if simple != target:
                    self.tainted.setdefault(simple, mark)
            elif compound and target in self.tainted:
                # cmd += " -v": nối thêm vào chuỗi bẩn thì nó vẫn bẩn.
                return
            else:
                self.tainted.pop(target, None)
                literal = _is_literal_choice(right, _member_dot(self.spec)) or _is_builder_literal(right, self.spec)
                if self._is_neutralized(right) or (literal and (not compound or target in self.sanitized)):
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
                member = index > 0 and statement[index - 1].kind == OP and statement[index - 1].text in self.spec.chain_separators
                self._check_call(chain, statement[index], arguments, chain_end, member=member)
                if self.spec.fill_sources or self.spec.propagators:
                    self._apply_outputs(chain, statement[index], arguments)
                if self.spec.receiver_propagators:
                    self._propagate_to_receiver(chain, statement, index, arguments)
            elif chain in self.spec.bare_call_names and not _starts_assignment_or_access(
                statement, next_index, self.spec
            ):
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
        member: bool = False,
    ) -> None:
        sink = _match_sink(chain, self.spec)
        if sink is None:
            return
        if member and sink.exact_names:
            # `.popen(...)` / `x.sh(...)`: phương thức của một đối tượng, không phải hàm trần.
            return
        labels: List[Optional[str]] = []
        if self.spec.argument_labels:
            labels = [_argument_label(argument) for argument in arguments]
            if sink.argument_label is not None and sink.argument_label not in labels:
                # Cùng tên, khác nhãn: `FileHandle(forReadingAtPath:)` / `(forWritingAtPath:)`.
                sink = next(
                    (
                        candidate
                        for candidate in _matching_sinks(chain, self.spec)
                        if candidate.argument_label is None or candidate.argument_label in labels
                    ),
                    None,
                )
                if sink is None:
                    return
            arguments = [argument[2:] if label else argument for label, argument in zip(labels, arguments)]
            if self.spec.bound_argument_labels:
                arguments = [
                    [token for token in argument if not token.interpolated]
                    if label in self.spec.bound_argument_labels
                    else argument
                    for label, argument in zip(labels, arguments)
                ]
            if self.spec.bound_interpolation_labels:
                arguments = [_drop_bound_interpolations(argument, self.spec) for argument in arguments]
            if sink.argument_label is not None:
                if sink.argument_label not in labels:
                    return
                arguments = [arguments[labels.index(sink.argument_label)]]
        elif sink.argument_label is not None:
            return
        if sink.first_argument_names:
            if not arguments or _lone_name(arguments[0]) not in sink.first_argument_names:
                return
        if sink.interpolation_parameterized:
            # sql.rows("... ${id}") của Groovy: GString được tham số hoá, chỉ phần nối chuỗi mới nguy hiểm.
            arguments = [
                [] if _lone_name(argument) in self.parameterized
                else [token for token in argument if not token.interpolated]
                for argument in arguments
            ]
        if self.spec.value_wrappers:
            arguments = [_unwrap_call(argument, self.spec.value_wrappers, self.spec) for argument in arguments]
        dynamic_rule = sink.dynamic_rule
        if sink.require_sql:
            selected = _select_sql_argument(arguments, sink, chain, self.budget.spend, self._mentions_sql)
            if selected and not self._mentions_sql(selected):
                # executeQuery(query) với `query` là tham số không rõ gốc: không
                # thấy câu SQL nào được ghép ở đây, nên "ghép bằng định dạng
                # chuỗi" là không chứng minh được. Vẫn báo nếu giá trị là của người ngoài.
                dynamic_rule = None
        elif sink.program_position:
            wrapped = _shell_wrapper_argument(arguments)
            if sink.shell_option_label is not None and sink.shell_option_label in labels:
                option = arguments[labels.index(sink.shell_option_label)]
                if len(option) == 1 and option[0].text == "true":
                    # Process.run(cmd, args, runInShell: true): chương trình và đối số
                    # được ghép thành một dòng lệnh shell.
                    wrapped = [
                        token for argument, label in zip(arguments, labels) if label is None for token in argument
                    ]
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
        elif sink.all_arguments_from is not None:
            selected = [token for argument in arguments[sink.all_arguments_from :] for token in argument]
        else:
            position = min(sink.argument_index, max(0, len(arguments) - 1))
            selected = arguments[position] if arguments else ()
        if not selected:
            return
        if sink.file_constructors and _constructs(selected, sink.file_constructors):
            dynamic_rule = None
        mark = self._taint_of(selected)
        if sink.category is Category.REDIRECT and mark is not None and self._fixed_origin(selected):
            return
        self._report_expression(
            rule_id=sink.tainted_rule,
            dynamic_rule=dynamic_rule,
            description=sink.description,
            symbol=chain,
            tokens=selected,
            mark=mark,
            anchor=anchor,
            anchor_end=anchor_end,
            confidence=sink.confidence,
        )

    def _analyze_receiver_calls(self, statement: Sequence[Token]) -> None:
        """`"ls ${d}".execute()`, `cmd.execute()`, `Seq("sh", "-c", c).!!`.

        Giá trị nguy hiểm là vế TRƯỚC dấu chấm. Chỉ nhận lời gọi không đối số,
        và chỉ báo "không phải hằng" khi vế trước là một chuỗi hay một danh sách
        viết tại chỗ: `task.execute()` trên một đối tượng bất kỳ không phải lệnh.
        """
        limit = len(statement)
        for index in range(1, limit):
            token = statement[index]
            if token.in_string or token.kind not in (IDENT, OP):
                continue
            sink = self.receiver_sinks.get(token.text)
            if sink is None:
                continue
            dot = index - 1
            if statement[dot].kind != OP or statement[dot].text != ".":
                # Scala viết được `cmd !!` không có dấu chấm.
                if token.kind != OP:
                    continue
                dot = index
            elif token.kind == IDENT:
                # Chỉ `.execute()` không đối số; `.execute(x)` là phương thức khác.
                if index + 2 >= limit or statement[index + 1].text != "(" or statement[index + 2].text != ")":
                    continue
            receiver = _expression_before(statement, dot)
            if not receiver:
                continue
            last = receiver[-1]
            if last.kind == OP and not last.in_string and last.text not in (")", "]"):
                continue
            head, _ = _read_chain(receiver, 1 if receiver[0].text == "new" else 0, self.spec)
            if head is not None and _match_sink(head, self.spec) is not None:
                # Process(cmd).! : lời gọi Process(...) đã được kiểm như một sink.
                continue
            listed = _listed_elements(receiver)
            wrapped = _shell_wrapper_argument(listed) if listed is not None else None
            if wrapped is not None:
                self._report_expression(
                    rule_id="FSB-CMD-001",
                    dynamic_rule="FSB-CMD-003",
                    description="một lệnh shell truyền qua cờ thông dịch",
                    symbol=token.text,
                    tokens=wrapped,
                    mark=self._taint_of(wrapped),
                    anchor=receiver[0],
                    anchor_end=token,
                    confidence=Confidence.HIGH,
                )
                continue
            mark = self._taint_of(receiver)
            literal_receiver = listed is not None or any(item.kind == STRING for item in receiver)
            if mark is None and not literal_receiver:
                continue
            self._report_expression(
                rule_id=sink.tainted_rule,
                dynamic_rule=sink.dynamic_rule,
                description=sink.description,
                symbol=token.text,
                tokens=receiver,
                mark=mark,
                anchor=receiver[0],
                anchor_end=token,
                confidence=sink.confidence,
            )

    def _propagate_to_receiver(
        self, chain: str, statement: Sequence[Token], index: int, arguments: Sequence[Sequence[Token]]
    ) -> None:
        """sb.append(x): vết nhiễm, chữ SQL và mức "chỉ có literal" đổ vào `sb`."""
        method = chain.rsplit(".", 1)[-1]
        if method not in self.spec.receiver_propagators:
            return
        if "." in chain:
            root = chain.rsplit(".", 1)[0]
            if index > 0 and statement[index - 1].kind == IDENT and statement[index - 1].text == "new":
                return
        else:
            root = _chained_root(statement, index - 1, self.spec)
            if root is None:
                return
        tokens = [token for argument in arguments for token in argument]
        mark = self._taint_of(tokens)
        if mark is not None:
            self.tainted[root] = mark
            self.sanitized.discard(root)
        elif not _is_literal(tokens, _member_dot(self.spec)) and not self._is_neutralized(tokens):
            self.sanitized.discard(root)
        if self._mentions_sql(tokens):
            self.sql_like.add(root)

    def _analyze_sql_splices(self, statement: Sequence[Token]) -> None:
        """`sql"SELECT * FROM #$bang"`: `$x` thường là tham số bind, `#$x` thì dán thẳng."""
        for index, token in enumerate(statement):
            if token.kind != STRING or token.in_string or token.prefix not in self.spec.spliced_sql_prefixes:
                continue
            spliced = _following_interpolations(statement, index)
            if not spliced:
                continue
            self._report_expression(
                rule_id="FSB-SQL-001",
                dynamic_rule="FSB-SQL-002",
                description="phần dán nguyên văn `#$` của câu SQL",
                symbol=token.prefix,
                tokens=spliced,
                mark=self._taint_of(spliced),
                anchor=token,
            )

    def _analyze_redirect_view(self, statement: Sequence[Token]) -> None:
        """`return "redirect:" + url` / `new ModelAndView("redirect:" + url)` của Spring."""
        prefix = self.spec.redirect_view_prefix or ""
        for index, token in enumerate(statement):
            if token.kind != STRING or token.in_string or not token.text.startswith(prefix):
                continue
            tail = [item for item in statement[index + 1 :] if item.kind != OP or item.text not in (")", ";")]
            if not tail:
                return
            mark = self._taint_of(tail)
            if mark is None or self._fixed_origin(statement[index:], prefix):
                return
            self._report_expression(
                rule_id="FSB-REDIR-001",
                dynamic_rule=None,
                description="view chuyển hướng `%s`" % prefix,
                symbol=prefix,
                tokens=tail,
                mark=mark,
                anchor=token,
            )
            return

    def _fixed_origin(self, tokens: Sequence[Token], strip: str = "") -> bool:
        """Phần chữ cố định trước giá trị bẩn đã chốt máy chủ đích chưa.

        `"/signin?redirect=" + urlEncode(uri)`, `s"/${owner}/pulls?q=${q}"`:
        giá trị bẩn chỉ nằm sau một đường dẫn tương đối hay trong query, nên nó
        không đổi được nơi trình duyệt tới. Còn `"/" + x` thì x = `/evil.com`
        thành `//evil.com`, `"https://" + x` thì x chọn luôn máy chủ.
        """
        text = ""
        head: Optional[str] = None
        for kind in self._url_pieces(tokens):
            if kind == _PIECE_TAINTED:
                break
            if kind == _PIECE_VALUE:
                # Giá trị không bẩn nhưng cũng không biết trước: chữ trước nó là
                # phần duy nhất chắc chắn cố định.
                if head is None:
                    head = text
                text += "\0"
                continue
            text += kind
        else:
            return False
        if head is None:
            head = text
        if strip and text.startswith(strip):
            text = text[len(strip) :]
            head = head[len(strip) :] if head.startswith(strip) else ""
        if "?" in text or "#" in text:
            # Mọi thứ sau `?` / `#` đầu tiên là query hay fragment.
            return True
        return _pins_origin(head)

    def _url_pieces(self, tokens: Sequence[Token]) -> List[str]:
        """Các mảnh của một phép nối chuỗi: chữ, _PIECE_VALUE hoặc _PIECE_TAINTED."""
        pieces: List[str] = []
        for operand in _concatenation_operands(tokens):
            if len(operand) > 1 and operand[0].kind == OP and operand[0].text in _STRING_MARKERS:
                # `$"/items/{id}"` của C#: dấu `$` / `@` chỉ là kiểu chuỗi.
                if operand[1].kind == STRING:
                    operand = operand[1:]
            first = operand[0]
            if first.kind == STRING and not first.in_string and all(item.in_string for item in operand[1:]):
                pieces.extend(self._string_pieces(first.text, operand[1:]))
            else:
                pieces.append(self._piece_kind(operand))
        return pieces

    def _string_pieces(self, body: str, inner: Sequence[Token]) -> List[str]:
        groups: Dict[Tuple[int, int], List[Token]] = {}
        for token in inner:
            if token.span[0] < 0:
                return [_PIECE_TAINTED]
            groups.setdefault(token.span, []).append(token)
        pieces: List[str] = []
        cursor = 0
        for (start, end), group in sorted(groups.items()):
            if start < cursor:
                # Vùng lồng trong vùng trước đó: chỉ cần biết nó có bẩn không.
                if self._piece_kind(group) == _PIECE_TAINTED:
                    pieces.append(_PIECE_TAINTED)
                continue
            pieces.append(body[cursor:start])
            pieces.append(self._piece_kind(group))
            cursor = end
        pieces.append(body[cursor:])
        return pieces

    def _piece_kind(self, tokens: Sequence[Token]) -> str:
        mark = self._taint_of(tokens)
        if mark is not None and mark.active_for(Category.REDIRECT):
            return _PIECE_TAINTED
        return _PIECE_VALUE

    def _analyze_extraction(self, statement: Sequence[Token]) -> None:
        """std::cin >> name >> age: mọi vế sau >> nhận dữ liệu nhập."""
        index = 0
        limit = len(statement)
        while index < limit:
            chain, next_index = _read_chain(statement, index, self.spec)
            if chain is None:
                index += 1
                continue
            label = self.spec.stream_sources.get(chain)
            if label is not None:
                cursor = next_index
                while cursor + 1 < limit and statement[cursor].kind == OP and statement[cursor].text == ">>":
                    target, cursor = _read_chain(statement, cursor + 1, self.spec)
                    if target is None:
                        break
                    self.tainted[target] = TaintMark(label, statement[index].line, Confidence.HIGH)
                    self.sanitized.discard(target)
                return
            index = max(next_index, index + 1)

    def _apply_outputs(self, chain: str, anchor: Token, arguments: Sequence[Sequence[Token]]) -> None:
        if chain.startswith("std.") and chain not in self.spec.fill_sources:
            chain = chain[4:]
        fill = self.spec.fill_sources.get(chain)
        if fill is not None:
            position, label, stream = fill
            if stream >= 0 and (stream >= len(arguments) or not _is_standard_input(arguments[stream], self.spec)):
                return
            targets = arguments[abs(position) :] if position < 0 else arguments[position : position + 1]
            for argument in targets:
                target = _out_target(argument, self.spec)
                if target is not None:
                    self.tainted[target] = TaintMark(label, anchor.line, Confidence.HIGH)
                    self.sanitized.discard(target)
            return
        propagation = self.spec.propagators.get(chain)
        if propagation is None:
            return
        destination, first_source, overwrite = propagation
        if destination >= len(arguments):
            return
        target = _out_target(arguments[destination], self.spec)
        if target is None:
            return
        sources = [token for argument in arguments[first_source:] for token in argument]
        if first_source == 0:
            sources = list(arguments[0]) if arguments else []
        mark = self._taint_of(sources)
        if chain.endswith("printf") and first_source < len(arguments) and _numeric_format(arguments[first_source]):
            # snprintf(q, n, "PRAGMA cache_size = %d", x): chỉ có số đi vào chuỗi.
            self.tainted.pop(target, None)
            self.sanitized.add(target)
            return
        if mark is not None:
            self.tainted[target] = mark
            self.sanitized.discard(target)
        elif overwrite:
            self.tainted.pop(target, None)
            # snprintf(cmd, n, "sleep %d", atoi(s)): chuỗi dựng từ giá trị đã khử độc.
            if self._is_neutralized(sources):
                self.sanitized.add(target)
            else:
                self.sanitized.discard(target)

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
        if dynamic_rule is None or _is_literal(tokens, _member_dot(self.spec)) or self._is_neutralized(tokens):
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
            mark = self._mark_for(chain, tokens[index].line)
            if mark is None and chain in self.spec.argument_sources:
                mark = self._argument_source(chain, tokens, next_index)
            if mark is not None:
                hits.append((index, mark))
            index = max(next_index, index + 1)
        if not hits:
            return None

        protected = _sanitizer_ranges(tokens, self.spec, self.declared)
        surviving: Optional[TaintMark] = None
        cleared: Optional[FrozenSet[Category]] = None
        for position, mark in hits:
            here = mark.cleared
            for start, end, categories in protected:
                if start <= position < end:
                    here = here | categories
            if self.spec.postfix_sanitizers:
                here = here | _postfix_categories(tokens, position, self.spec)
            cleared = here if cleared is None else (cleared & here)
            if surviving is None and here != _EVERY_CATEGORY:
                surviving = mark
        if surviving is None or cleared is None or cleared == _EVERY_CATEGORY:
            return None
        return replace(surviving, cleared=cleared)

    def _argument_source(self, chain: str, tokens: Sequence[Token], open_index: int) -> Optional[TaintMark]:
        if open_index >= len(tokens) or tokens[open_index].text != "(":
            return None
        arguments, _ = _read_arguments(tokens, open_index)
        literal = _sole_string(arguments[0]) if arguments else None
        if literal is None:
            return None
        names, prefixes, label = self.spec.argument_sources[chain]
        if literal in names or any(literal.startswith(prefix) for prefix in prefixes):
            return TaintMark(label, tokens[open_index].line, Confidence.HIGH)
        return None

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
        tables = [self.spec.sources]
        if self.spec.low_signal_sources and self.unit.config.include_low_signal_sources:
            tables.append(self.spec.low_signal_sources)
        for table in tables:
            label = table.get(chain)
            if label is not None:
                return TaintMark(label, line, Confidence.HIGH)
            prefix = chain
            while "." in prefix:
                prefix = prefix.rsplit(".", 1)[0]
                label = table.get(prefix)
                if label is not None:
                    return TaintMark(label, line, Confidence.HIGH)
        return None

    def _is_sanitized(self, tokens: Sequence[Token]) -> bool:
        # Cùng lý do với _sanitizer_ranges: một cái tên do chính tệp này định
        # nghĩa thì không được hưởng quyền miễn trừ của bảng.
        for chain in self._chains(tokens):
            if chain in self.spec.sanitizers and chain not in self.declared:
                return True
        if self.spec.postfix_sanitizers:
            for index in range(len(tokens)):
                if _postfix_categories(tokens, index, self.spec) == _EVERY_CATEGORY:
                    return True
        return False

    def _mentions_sql(self, tokens: Sequence[Token]) -> bool:
        text = " ".join(token.text for token in tokens if token.kind == STRING)
        if text and looks_like_sql(text, self.budget.spend):
            return True
        if self.sql_like:
            # `sb.toString()` mang câu SQL của chính `sb`.
            return any(
                chain in self.sql_like
                or ("." in chain and chain.rsplit(".", 1)[1] in self.spec.value_accessors and chain.rsplit(".", 1)[0] in self.sql_like)
                for chain in self._chains(tokens)
            )
        return False

    def _is_neutralized(self, tokens: Sequence[Token]) -> bool:
        if self._is_sanitized(tokens):
            return True
        chains = self._chains(tokens)
        if not chains:
            return False
        if self.spec.value_accessors:
            chains = [
                chain.rsplit(".", 1)[0] if "." in chain and chain.rsplit(".", 1)[1] in self.spec.value_accessors else chain
                for chain in chains
            ]
        if self.spec.constant_case_names:
            chains = [chain for chain in chains if not _CONSTANT_NAME.match(chain.rsplit(".", 1)[-1])]
            if not chains:
                return True
        return all(chain in self.sanitized for chain in chains)

    def _chains(self, tokens: Sequence[Token]) -> List[str]:
        found: List[str] = []
        index = 0
        limit = len(tokens)
        while index < limit:
            chain, next_index = _read_chain(tokens, index, self.spec)
            # `"...".trimIndent()`: phương thức của chính literal không phải một giá trị.
            if chain is not None and not (_member_dot(self.spec) and _method_on_literal(tokens, index)):
                found.append(chain)
            index = max(next_index if chain else index + 1, index + 1)
        return found


def _category_of(rule_id: str) -> Category:
    return get_rule(rule_id).category


def _split_statements(tokens: Sequence[Token]) -> List[List[Token]]:
    statements: List[List[Token]] = []
    current: List[Token] = []
    depth = 0
    for token in tokens:
        if token.kind == NEWLINE:
            if depth == 0 and current and not _continues(current[-1]):
                statements.append(current)
                current = []
            continue
        if token.kind == OP and not token.in_string:
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
    if spec.annotation_keyword is not None:
        keyword = spec.annotation_keyword.lower()
        for index, token in enumerate(left):
            if token.kind == IDENT and token.text.lower() == keyword and index > 0:
                return list(left[:index])
    return _strip_annotation_separator(left, spec)


def _strip_annotation_separator(left: Sequence[Token], spec: LanguageSpec) -> Sequence[Token]:
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
    region = tokens[index].in_string
    cursor = index + 1
    while cursor + 1 < limit:
        separator = tokens[cursor]
        if separator.in_string != region:
            # `"... $x".trim()`: chuỗi truy cập không đi xuyên qua dấu đóng chuỗi.
            break
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
    if len(arguments) == 1:
        # ProcessBuilder(listOf("sh", "-c", cmd)), Process(Seq("bash", "-c", c)).
        listed = _listed_elements(arguments[0])
        if listed is not None and len(listed) >= 3:
            arguments = listed
    if len(arguments) < 2:
        return None
    program = _sole_string(arguments[0])
    if program is None:
        return None
    if program.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() not in _SHELL_BINARIES:
        return None
    # Process.run('sh', ['-c', cmd]) của Dart, spawn('sh', ['-c', cmd]) của Node.
    listed = _listed_elements(arguments[1])
    if listed is not None:
        for index in range(len(listed) - 1):
            if _sole_string(listed[index]) in _SHELL_FLAGS:
                return listed[index + 1]
    for index in range(1, len(arguments) - 1):
        flag = _sole_string(arguments[index])
        if flag is not None and flag in _SHELL_FLAGS:
            return arguments[index + 1]
    # Process.Start("cmd.exe", "/c " + q): cờ và lệnh chung một chuỗi.
    if len(arguments) == 2:
        first = next((token for token in arguments[1] if not token.in_string), None)
        if first is not None and first.kind == STRING:
            head = first.text.lstrip().split(" ", 1)[0]
            if head in _SHELL_FLAGS:
                return arguments[1]
    return None


_COLLECTION_CALLS = frozenset(
    {
        "listOf", "arrayOf", "mutableListOf", "List", "Seq", "Array", "Vector",
        "Arrays.asList", "List.of", "Collections.singletonList", "ImmutableList.of",
    }
)


def _listed_elements(argument: Sequence[Token]) -> Optional[List[List[Token]]]:
    """Phần tử của một danh sách viết tại chỗ: `[a, b]`, `listOf(a, b)`,
    `new String[]{a, b}`, `Seq(a, b)`; None nếu đối số không phải dạng đó."""
    tokens = [token for token in argument if not token.in_string or token.kind == STRING]
    if not tokens:
        return None
    first = tokens[0]
    if first.kind == OP and first.text == "[":
        if _group_end(tokens, 0) != len(tokens):
            return None
        return [list(item) for item in _read_arguments(list(argument), list(argument).index(first))[0]]
    if first.kind == IDENT and first.text == "new":
        brace = next((i for i, token in enumerate(tokens) if token.kind == OP and token.text == "{"), None)
        if brace is None or _group_end(tokens, brace) != len(tokens):
            return None
        start = list(argument).index(tokens[brace])
        return [list(item) for item in _read_arguments(list(argument), start)[0]]
    names: List[str] = []
    cursor = 0
    while cursor < len(tokens) and (tokens[cursor].kind == IDENT or (tokens[cursor].kind == OP and tokens[cursor].text == ".")):
        names.append(tokens[cursor].text)
        cursor += 1
    if "".join(names) not in _COLLECTION_CALLS or cursor >= len(tokens) or tokens[cursor].text != "(":
        return None
    if _group_end(tokens, cursor) != len(tokens):
        return None
    start = list(argument).index(tokens[cursor])
    return [list(item) for item in _read_arguments(list(argument), start)[0]]


_NUMERIC_CONVERSION = re.compile(r"%[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|j|z|t|L)?([a-zA-Z%])")


def _numeric_format(argument: Sequence[Token]) -> bool:
    """Định dạng printf chỉ có %d %u %x %f ... ( không %s, %c ): kết quả không chứa chữ do người khác chọn."""
    text = _sole_string(argument)
    if text is None:
        return False
    conversions = _NUMERIC_CONVERSION.findall(text)
    return bool(conversions) and all(c in "diouxXeEfFgGaA%" for c in conversions)


_STANDARD_INPUT_NAMES = frozenset({"stdin", "std.cin", "cin", "STDIN_FILENO", "0"})


def _is_standard_input(argument: Sequence[Token], spec: LanguageSpec) -> bool:
    meaningful = [token for token in argument if not (token.kind == OP and token.text in "()")]
    if len(meaningful) == 1 and meaningful[0].text in _STANDARD_INPUT_NAMES:
        return True
    chain, end = _read_chain(meaningful, 0, spec)
    return chain in _STANDARD_INPUT_NAMES and end == len(meaningful)


_EXPRESSION_STOPS = frozenset({"=", "(", ",", "[", "{", ";", "return", "->", "=>", ":"})


def _expression_before(statement: Sequence[Token], dot: int) -> List[Token]:
    """Biểu thức kết thúc ngay trước dấu chấm tại `dot`: chuỗi, ngoặc, hoặc tên."""
    cursor = dot - 1
    if cursor < 0:
        return []
    token = statement[cursor]
    if token.kind == OP and token.text in (")", "]"):
        depth = 0
        while cursor >= 0:
            current = statement[cursor]
            if current.kind == OP and current.text in (")", "]"):
                depth += 1
            elif current.kind == OP and current.text in ("(", "["):
                depth -= 1
                if depth == 0:
                    break
            cursor -= 1
        cursor = max(cursor, 0)
        # Seq("sh", "-c", c).!! / new File(p).delete(): lấy cả tên hàm đứng trước ngoặc.
        while cursor >= 1 and statement[cursor - 1].kind == IDENT and not statement[cursor - 1].in_string:
            cursor -= 1
            if cursor >= 2 and statement[cursor - 1].kind == OP and statement[cursor - 1].text == ".":
                cursor -= 1
                continue
            break
        return list(statement[cursor:dot])
    # Chuỗi nội suy: token STRING cùng các token nội suy đứng sau nó.
    start = cursor
    while start > 0 and statement[start].in_string and statement[start].kind != STRING:
        start -= 1
    if statement[start].kind == STRING:
        return list(statement[start:dot])
    while start > 0 and statement[start - 1].kind == OP and statement[start - 1].text == "." and start - 2 >= 0 and statement[start - 2].kind == IDENT:
        start -= 2
    return list(statement[start:dot])


def _chained_root(statement: Sequence[Token], dot: int, spec: LanguageSpec) -> Optional[str]:
    """Biến gốc của `sb.append(a).append(b)` khi đang đứng ở `.append` thứ hai."""
    if dot < 1 or statement[dot].kind != OP or statement[dot].text != ".":
        return None
    cursor = dot - 1
    while cursor >= 0:
        token = statement[cursor]
        if token.kind == OP and token.text == ")":
            depth = 0
            while cursor >= 0:
                current = statement[cursor]
                if current.kind == OP and current.text == ")":
                    depth += 1
                elif current.kind == OP and current.text == "(":
                    depth -= 1
                    if depth == 0:
                        break
                cursor -= 1
            cursor -= 1
            if cursor < 0 or statement[cursor].kind != IDENT:
                return None
            if statement[cursor].text not in spec.receiver_propagators:
                return None
            if cursor < 1 or statement[cursor - 1].text != ".":
                return None
            cursor -= 2
            continue
        if token.kind != IDENT:
            return None
        start = cursor
        while start >= 2 and statement[start - 1].kind == OP and statement[start - 1].text in spec.chain_separators and statement[start - 2].kind == IDENT:
            start -= 2
        if start > 0 and statement[start - 1].kind == IDENT and statement[start - 1].text == "new":
            return None
        chain, end = _read_chain(statement, start, spec)
        return chain
    return None


def _postfix_categories(tokens: Sequence[Token], position: int, spec: LanguageSpec) -> FrozenSet[Category]:
    """Nhóm được khử bởi các lời gọi VIẾT SAU giá trị tại `position`.

    `request.getParameter("p").toInt()`, `params[:id].to_i`, `id.toLong()`:
    đi tiếp qua các nhóm ngoặc và các `.ten` ngay sau giá trị; một bộ khử độc
    hậu tố ở bất kỳ mắt xích nào cũng áp cho cả biểu thức đứng trước nó.
    """
    _, cursor = _read_chain(tokens, position, spec)
    parts_start = position
    found: FrozenSet[Category] = frozenset()
    # Mắt xích nằm ngay trong chuỗi gọi: `id.toInt` được đọc thành một chuỗi.
    index = parts_start + 1
    while index < cursor:
        token = tokens[index]
        if token.kind == IDENT and index > parts_start:
            categories = spec.postfix_sanitizers.get(token.text)
            if categories is not None:
                found = found | categories
        index += 1
    limit = len(tokens)
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == OP and token.text in ("(", "[") and not token.in_string:
            after = _group_end(tokens, cursor)
            if after is None:
                break
            cursor = after
            continue
        if token.kind == OP and token.text in spec.chain_separators and cursor + 1 < limit:
            following = tokens[cursor + 1]
            if following.kind != IDENT:
                break
            categories = spec.postfix_sanitizers.get(following.text)
            if categories is not None:
                found = found | categories
            cursor += 2
            continue
        if token.kind == OP and token.text in ("!!", "?", "!") and not token.in_string:
            cursor += 1
            continue
        if token.kind == OP and token.text in (")", "]") and not token.in_string:
            # Ra khỏi nhóm đang chứa giá trị: `(name as NSString).lastPathComponent`,
            # `URL(fileURLWithPath: p).lastPathComponent` khử cả biểu thức trong ngoặc.
            cursor += 1
            continue
        if token.kind == IDENT and token.text == "as" and not token.in_string:
            # Ép kiểu `as` / `as?` / `as!` của Swift và Kotlin không đổi giá trị.
            cursor += 1
            if cursor < limit and tokens[cursor].kind == OP and tokens[cursor].text in ("?", "!"):
                cursor += 1
            _, cursor = _read_chain(tokens, cursor, spec)
            continue
        break
    return found


def _handler_parameter_name(parameter: Sequence[Token], spec: LanguageSpec) -> Optional[str]:
    """Tên của một tham số kiểu chuỗi không mang annotation loại trừ."""
    tokens = [token for token in parameter if not token.in_string and token.kind != NEWLINE]
    if not tokens:
        return None
    cursor = 0
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.kind == OP and token.text in ("@", "[") and cursor + 1 < len(tokens):
            annotation = tokens[cursor + 1].text
            if annotation not in VALIDATION_ANNOTATIONS:
                # Annotation nguồn đã được gắn riêng; annotation khác nghĩa là
                # giá trị đến từ một resolver riêng, không phải từ request.
                return None
            if token.text == "[":
                cursor = _group_end(tokens, cursor) or len(tokens)
                continue
            cursor += 2
            if cursor < len(tokens) and tokens[cursor].kind == OP and tokens[cursor].text == "(":
                cursor = _group_end(tokens, cursor) or len(tokens)
            continue
        break
    body = tokens[cursor:]
    default = next((i for i, token in enumerate(body) if token.kind == OP and token.text == "="), None)
    if default is not None:
        body = body[:default]
    names = [token for token in body if token.kind == IDENT]
    if len(names) < 2:
        return None
    separator = spec.annotation_separator
    if separator is not None and any(token.kind == OP and token.text == separator for token in body):
        # Kotlin/Scala: `name: String`
        split = next(i for i, token in enumerate(body) if token.kind == OP and token.text == separator)
        before = [token for token in body[:split] if token.kind == IDENT]
        after = [token for token in body[split + 1 :] if token.kind == IDENT]
        if not before or not after or after[0].text not in spec.handler_parameter_types:
            return None
        if len(after) > 1:
            return None
        return before[-1].text
    # Java/C#: `String name`, `string? name`
    type_names = [token.text for token in names[:-1]]
    if not type_names or type_names[-1] not in spec.handler_parameter_types:
        return None
    if any(token.kind == OP and token.text in ("<", "[") for token in body):
        return None
    return names[-1].text


# Kiểu mà framework chỉ gắn được khi giá trị ĐÃ parse thành số/ngày/UUID: chuỗi
# lạ không đi qua được, nên tham số kiểu này không mang ký tự đặc biệt nào.
_SCALAR_TYPES = frozenset(
    {
        "int", "Integer", "Int", "long", "Long", "short", "Short", "byte", "Byte",
        "double", "Double", "float", "Float", "boolean", "Boolean", "Bool", "bool",
        "UUID", "Guid", "BigDecimal", "BigInteger", "LocalDate", "LocalDateTime",
        "Instant", "DateTime", "decimal", "uint", "ulong",
    }
)


def _scalar_parameter(tokens: Sequence[Token], index: int) -> bool:
    """`@PathVariable Long id`, `@RequestParam id: Int`: kiểu số nên không phải nguồn chuỗi."""
    cursor = index
    if cursor < len(tokens) and tokens[cursor].kind == OP and tokens[cursor].text == "(":
        after = _group_end(tokens, cursor)
        if after is None:
            return False
        cursor = after
    limit = min(len(tokens), cursor + 12)
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == OP and token.text in (",", ")", "<", "["):
            return False
        if token.kind == IDENT and token.text in _SCALAR_TYPES:
            # Kiểu bọc như List<Long> dừng ở `<` phía trên nên không tới đây.
            following = tokens[cursor + 1] if cursor + 1 < len(tokens) else None
            if following is not None and following.kind == OP and following.text in ("<", "["):
                return False
            return True
        cursor += 1
    return False


def _body_span(
    tokens: Sequence[Token], index: int
) -> Optional[Tuple[Tuple[int, int], Tuple[int, int]]]:
    """Vị trí `{` và `}` của thân hàm có danh sách tham số chứa `index`."""
    limit = len(tokens)
    depth = 0
    cursor = index
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == OP and not token.in_string:
            if token.text in "([{":
                depth += 1
            elif token.text in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif token.text == ";" and depth <= 0:
                return None
        cursor += 1
    if cursor >= limit or tokens[cursor].text != ")":
        return None
    # Kiểu trả về, `throws X`, `where T : ...` đứng giữa `)` và `{`. Sau dấu `=`
    # ( thân dạng biểu thức của Kotlin/Scala, `= Action {` của Play ) thì hết
    # dòng là hết thân, trừ khi dòng kết thúc bằng chính dấu `=`.
    expression = False
    previous: Optional[Token] = None
    for brace in range(cursor + 1, min(limit, cursor + 40)):
        token = tokens[brace]
        if token.kind == NEWLINE:
            if expression and not (previous is not None and previous.kind == OP and previous.text == "="):
                return None
            continue
        previous = token
        if token.kind != OP or token.in_string:
            continue
        if token.text == "{":
            after = _group_end(tokens, brace)
            if after is None:
                return None
            closing = tokens[after - 1]
            return (token.line, token.column), (closing.line, closing.column)
        if token.text == "=":
            expression = True
            continue
        if token.text in (";", "}", "=>"):
            return None
    return None


_PATH_TEXT_MATCHERS = frozenset({"Segment", "Segments", "Remaining", "RemainingPath"})


def _lambda_parameters(tokens: Sequence[Token], start: int, stop: int) -> List[str]:
    """Tên tham số ở đầu khối `{ a => ...}`, `{ (a, b) => ...}`, `{ case (a, b) => ...}`."""
    cursor = start
    while cursor < stop and tokens[cursor].kind == NEWLINE:
        cursor += 1
    names: List[str] = []
    seen_arrow = False
    for index in range(cursor, min(stop, cursor + 24)):
        token = tokens[index]
        if token.kind == NEWLINE:
            break
        if token.kind == OP and token.text == "=>":
            seen_arrow = True
            break
        if token.kind == IDENT and token.text not in ("case", "implicit"):
            # `id: String` -> chỉ lấy tên, bỏ kiểu đứng sau `:`.
            if index > cursor and tokens[index - 1].kind == OP and tokens[index - 1].text == ":":
                continue
            names.append(token.text)
        elif token.kind == OP and token.text not in ("(", ")", ",", ":"):
            return []
    return names if seen_arrow else []


def _returns_action(tokens: Sequence[Token], index: int, spec: LanguageSpec) -> bool:
    """`def show(id: String) = Action ...` / `: Action[AnyContent] = Action.async {`."""
    limit = len(tokens)
    cursor = index + 2
    if cursor >= limit or tokens[index + 1].kind != IDENT or tokens[cursor].text != "(":
        return False
    after = _group_end(tokens, cursor)
    if after is None:
        return False
    for probe in range(after, min(limit, after + 16)):
        token = tokens[probe]
        if token.kind == OP and token.text == "=":
            following = probe + 1
            while following < limit and tokens[following].kind == NEWLINE:
                following += 1
            return following < limit and tokens[following].text in spec.handler_body_markers
        if token.kind == OP and token.text in ("{", ";", "}"):
            return False
    return False


def _starts_assignment_or_access(statement: Sequence[Token], index: int, spec: LanguageSpec) -> bool:
    """`sh = x`, `sh.foo`: tên trùng với lệnh bare-call nhưng không phải lời gọi."""
    if index >= len(statement):
        return True
    token = statement[index]
    if token.kind != OP or token.in_string:
        return False
    return token.text in spec.assignment_operators or token.text in spec.chain_separators or token.text in (")", ",", "]")


def _unwrap_call(argument: Sequence[Token], wrappers: FrozenSet[str], spec: LanguageSpec) -> Sequence[Token]:
    """`Sql('SELECT ...', types: [...])` -> `'SELECT ...'`: chỉ đối số đầu của kiểu bọc."""
    if not argument or argument[0].kind != IDENT or argument[0].in_string:
        return argument
    chain, cursor = _read_chain(argument, 0, spec)
    if chain not in wrappers or cursor >= len(argument) or argument[cursor].text != "(":
        return argument
    if _group_end(argument, cursor) != len(argument):
        return argument
    inner, _ = _read_arguments(list(argument), cursor)
    return list(inner[0]) if inner else argument


def _constructs(argument: Sequence[Token], types: FrozenSet[str]) -> bool:
    """Đối số là đúng một lời tạo `new T(...)` / `T(...)` với T thuộc `types`."""
    cursor = 1 if argument and argument[0].kind == IDENT and argument[0].text == "new" else 0
    if len(argument) < cursor + 3 or argument[cursor].kind != IDENT or argument[cursor].text not in types:
        return False
    if argument[cursor + 1].kind != OP or argument[cursor + 1].text != "(":
        return False
    return _group_end(argument, cursor + 1) == len(argument)


def _lone_name(argument: Sequence[Token]) -> Optional[str]:
    meaningful = [token for token in argument if not token.in_string]
    if len(meaningful) == 1 and meaningful[0].kind == IDENT:
        return meaningful[0].text
    return None


def _is_lone_template(tokens: Sequence[Token]) -> bool:
    """Vế phải chỉ là MỘT chuỗi có nội suy ( một GString trọn vẹn )."""
    meaningful = [token for token in tokens if not token.in_string]
    return len(meaningful) == 1 and meaningful[0].kind == STRING and any(token.interpolated for token in tokens)


def _is_builder_literal(tokens: Sequence[Token], spec: LanguageSpec) -> bool:
    """`new StringBuilder("SELECT ...")` / `StringBuilder()`: bộ dựng chỉ mang literal."""
    if not spec.builder_constructors:
        return False
    items = list(tokens)
    if items and items[0].kind == IDENT and items[0].text == "new":
        items = items[1:]
    chain, cursor = _read_chain(items, 0, spec)
    if chain is None or chain not in spec.builder_constructors:
        # `StringBuilder()` không đối số: _read_chain dừng ở `()` cuối.
        return False
    if cursor >= len(items):
        return True
    if items[cursor].kind != OP or items[cursor].text != "(":
        return False
    if _group_end(items, cursor) != len(items):
        return False
    return _is_literal(items[cursor + 1 : -1], _member_dot(spec))


def _canonical_case(tokens: Sequence[Token], spec: LanguageSpec) -> List[Token]:
    names: Set[str] = set(spec.sources) | set(spec.sanitizers) | set(spec.low_signal_sources)
    for sink in spec.sinks:
        names.update(sink.names)
    canon: Dict[str, str] = {}
    for name in names:
        for part in name.split("."):
            canon.setdefault(part.lower(), part)
    result: List[Token] = []
    for token in tokens:
        if token.kind == IDENT and not token.in_string:
            fixed = canon.get(token.text.lower())
            if fixed is not None and fixed != token.text:
                token = replace(token, text=fixed)
        result.append(token)
    return result


def _out_target(argument: Sequence[Token], spec: LanguageSpec) -> Optional[str]:
    """Biến nhận dữ liệu của `fgets(buf, ...)`, `scanf("%d", &n)`, `read(fd, (char *)p, n)`."""
    tokens = list(argument)
    while tokens and tokens[0].kind == OP and tokens[0].text in ("&", "*", "("):
        if tokens[0].text == "(":
            after = _group_end(tokens, 0)
            inner = tokens[1 : after - 1] if after is not None else []
            if after is not None and inner and all(t.kind == IDENT or t.text in ("*", "&") for t in inner) and after < len(tokens):
                # (char *)p: bỏ phép ép kiểu
                tokens = tokens[after:]
                continue
        tokens = tokens[1:]
    if not tokens:
        return None
    chain, _ = _read_chain(tokens, 0, spec)
    return chain


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
        "sqlite3_exec",
        "sqlite3_prepare",
        "sqlite3_prepare_v2",
        "sqlite3_prepare_v3",
        "mysql_real_query",
        "PQexec",
        "PQexecParams",
        "PQsendQuery",
        # JDBC, JPA, JdbcTemplate, Android: các API này chỉ nhận SQL/JPQL.
        "executeQuery",
        "executeUpdate",
        "executeLargeUpdate",
        "prepareStatement",
        "prepareCall",
        "addBatch",
        "createQuery",
        "queryForObject",
        "queryForList",
        "queryForMap",
        "queryForRowSet",
        "rawQuery",
        "execSQL",
        "Fragment.const",
        "Fragment.const0",
        # ADO.NET: đối số đầu của các lớp Command là văn bản lệnh.
        "SqlCommand",
        "OleDbCommand",
        "OdbcCommand",
        "MySqlCommand",
        "NpgsqlCommand",
        "SqliteCommand",
        "SQLiteCommand",
        "OracleCommand",
        "SqlDataAdapter",
        # database/sql của Go khi đối tượng nhận mang tên quen thuộc.
        "db.Query",
        "db.QueryRow",
        "db.Exec",
        "db.QueryContext",
        "db.QueryRowContext",
        "db.ExecContext",
        "tx.Query",
        "tx.QueryRow",
        "tx.Exec",
        "tx.QueryContext",
        "tx.ExecContext",
        "db.Raw",
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
    mentions_sql: Optional[Callable[[Sequence[Token]], bool]] = None,
) -> Sequence[Token]:
    for argument in arguments:
        if mentions_sql is not None:
            if mentions_sql(argument):
                return argument
            continue
        text = " ".join(token.text for token in argument if token.kind == STRING)
        if looks_like_sql(text, spend):
            return argument
    if _always_sql(chain):
        position = min(sink.argument_index, max(0, len(arguments) - 1))
        if arguments:
            return arguments[position]
    return ()


def _always_sql(chain: str) -> bool:
    """API chỉ nhận SQL: tên đơn khớp đuôi chuỗi gọi, tên có chấm khớp hậu tố."""
    if chain in _ALWAYS_SQL or chain.rsplit(".", 1)[-1] in _ALWAYS_SQL:
        return True
    parts = chain.split(".")
    for start in range(1, len(parts) - 1):
        if ".".join(parts[start:]) in _ALWAYS_SQL:
            return True
    return False


def _matching_sinks(chain: str, spec: LanguageSpec, receiver: bool = False) -> List[GenericSink]:
    """Mọi sink khớp `chain`, tên dài ( cụ thể ) trước."""
    found: List[Tuple[int, int, GenericSink]] = []
    for order, sink in enumerate(spec.sinks):
        if sink.receiver != receiver:
            continue
        lengths = [
            len(name)
            for name in sink.names
            if chain == name or (not sink.exact_names and chain.endswith("." + name))
        ]
        if lengths:
            found.append((-max(lengths), order, sink))
    return [sink for _, _, sink in sorted(found, key=lambda item: (item[0], item[1]))]


def _match_sink(chain: str, spec: LanguageSpec, receiver: bool = False) -> Optional[GenericSink]:
    best: Optional[GenericSink] = None
    best_length = -1
    for sink in spec.sinks:
        if sink.receiver != receiver:
            continue
        for name in sink.names:
            if chain == name or (not sink.exact_names and chain.endswith("." + name)):
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


def _member_dot(spec: LanguageSpec) -> bool:
    """`.` là truy cập thành viên, không phải phép nối chuỗi như của PHP / Perl."""
    return "." in spec.chain_separators


def _is_literal_choice(tokens: Sequence[Token], member_dot: bool = False) -> bool:
    """`"a"`, `"a" "b"`, hoặc `cond ? "a" : "b"`: mọi giá trị có thể đều là literal."""
    depth = 0
    for index, token in enumerate(tokens):
        if token.kind != OP or token.in_string:
            continue
        if token.text in "([":
            depth += 1
        elif token.text in ")]":
            depth -= 1
        elif token.text == "?" and depth == 0:
            branches = tokens[index + 1 :]
            inner = 0
            for split, item in enumerate(branches):
                if item.kind == OP and item.text in "([":
                    inner += 1
                elif item.kind == OP and item.text in ")]":
                    inner -= 1
                elif item.kind == OP and item.text == ":" and inner == 0:
                    return _is_literal(branches[:split], member_dot) and _is_literal_choice(
                        branches[split + 1 :], member_dot
                    )
            return False
    return bool(tokens) and _is_literal(tokens, member_dot)


def _is_literal(tokens: Sequence[Token], member_dot: bool = False) -> bool:
    for index, token in enumerate(tokens):
        if token.interpolated:
            return False
        if token.kind in (IDENT,):
            # `"""CREATE ...""".trimIndent()`, `"a b".trim().lowercase()`: phương
            # thức gọi trên chính một literal không đưa giá trị lạ nào vào;
            # đối số của nó ( nếu có ) vẫn được xét như mọi token khác.
            if member_dot and _method_on_literal(tokens, index):
                continue
            return False
    return True


def _method_on_literal(tokens: Sequence[Token], index: int, depth: int = 0) -> bool:
    if depth > 8 or index < 2:
        return False
    dot = tokens[index - 1]
    if dot.kind != OP or dot.text != "." or dot.in_string:
        return False
    # Bỏ qua phần nội suy dính sau chuỗi: `"""... $x""".trimIndent()`.
    cursor = index - 2
    while cursor > 0 and tokens[cursor].in_string:
        cursor -= 1
    receiver = tokens[cursor]
    if receiver.kind == STRING and not receiver.in_string:
        return True
    if receiver.kind == OP and receiver.text == ")" and not receiver.in_string:
        cursor = index - 2
        level = 0
        while cursor >= 0:
            current = tokens[cursor]
            if current.kind == OP and not current.in_string:
                if current.text == ")":
                    level += 1
                elif current.text == "(":
                    level -= 1
                    if level == 0:
                        break
            cursor -= 1
        if cursor < 1 or tokens[cursor - 1].kind != IDENT:
            return False
        return _method_on_literal(tokens, cursor - 1, depth + 1)
    return False


# Hai giá trị không thể là chữ thật của một chuỗi nguồn ( chứa NUL ).
_PIECE_VALUE = "\0value"
_PIECE_TAINTED = "\0tainted"
_STRING_MARKERS = frozenset({"$", "@", "$@", "@$"})
_ORIGIN_PREFIX = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*:[/\\\\]{2}[^/\\\\?#]+[/\\\\?#]")
_SCHEME_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")
_ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_URL_IGNORED = re.compile(r"[\t\n\r]")
_CONSTANT_NAME = re.compile(r"\A(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[A-Z]{2,}[0-9]*)\Z")


def _pins_origin(head: str) -> bool:
    """`/x/`, `https://host/`, `login?` chốt máy chủ; `/`, `//`, `https://`, `http` thì không."""
    # Trình duyệt bỏ khoảng trắng và ký tự điều khiển ở đầu, và bỏ tab, xuống
    # dòng ở bất kỳ đâu trong URL.
    head = _URL_IGNORED.sub("", head).lstrip("".join(chr(code) for code in range(0x21)))
    if not head:
        return False
    if head[0] in "/\\":
        # `/\evil.com` cũng được trình duyệt hiểu là `//evil.com`.
        return len(head) > 1 and head[1] not in "/\\"
    if _ORIGIN_PREFIX.match(head):
        return True
    if head[0] not in _ASCII_LETTERS:
        return True
    for char in head:
        if char == ":":
            # Đủ scheme nhưng chưa xong máy chủ: `https://`, `https://site.com`.
            return False
        if char not in _SCHEME_CHARACTERS:
            # Đường dẫn tương đối: ký tự này làm phần đầu không còn là scheme.
            return True
    # `http` + `s://evil.com`: giá trị bẩn còn viết tiếp được scheme.
    return False


def _argument_label(argument: Sequence[Token]) -> Optional[str]:
    """`sql: q` -> "sql". Nhãn là một định danh đứng ngay trước dấu `:` đơn."""
    if (
        len(argument) > 2
        and argument[0].kind == IDENT
        and not argument[0].in_string
        and argument[1].kind == OP
        and argument[1].text == ":"
        and not argument[1].in_string
    ):
        return argument[0].text
    return None


def _drop_bound_interpolations(argument: Sequence[Token], spec: LanguageSpec) -> List[Token]:
    """Bỏ những vùng nội suy mở đầu bằng nhãn bind: `\\(bind: name)` của SQLKit."""
    bound: Set[Tuple[int, int]] = set()
    seen: Set[Tuple[int, int]] = set()
    for index, token in enumerate(argument):
        if not token.interpolated or token.span in seen:
            continue
        seen.add(token.span)
        following = argument[index + 1] if index + 1 < len(argument) else None
        if (
            token.text in spec.bound_interpolation_labels
            and following is not None
            and following.span == token.span
            and following.text == ":"
        ):
            bound.add(token.span)
    if not bound:
        return list(argument)
    return [token for token in argument if not (token.interpolated and token.span in bound)]


def _concatenation_operands(tokens: Sequence[Token]) -> List[List[Token]]:
    """Các vế của `a + b + c` ở mức ngoài cùng, dừng ở `,` / `;` / ngoặc đóng thừa."""
    operands: List[List[Token]] = [[]]
    depth = 0
    for token in tokens:
        if token.kind == OP and not token.in_string:
            if token.text in ("(", "[", "{"):
                depth += 1
            elif token.text in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and token.text in (",", ";"):
                break
            elif depth == 0 and token.text == "+":
                operands.append([])
                continue
        operands[-1].append(token)
    return [operand for operand in operands if operand]


def _following_interpolations(statement: Sequence[Token], index: int) -> List[Token]:
    collected: List[Token] = []
    cursor = index + 1
    while cursor < len(statement) and statement[cursor].in_string:
        collected.append(statement[cursor])
        cursor += 1
    return collected


def _next_declared_name(
    tokens: Sequence[Token], index: int, separator: Optional[str] = None
) -> Optional[str]:
    cursor = index
    # @RequestParam("id") String id: bỏ qua phần đối số của chính annotation.
    if cursor < len(tokens) and tokens[cursor].kind == OP and tokens[cursor].text == "(":
        after = _group_end(tokens, cursor)
        if after is None:
            return None
        cursor = after
    limit = min(len(tokens), cursor + 12)
    last: Optional[str] = None
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == IDENT:
            last = token.text
        elif token.kind == OP and separator is not None and token.text == separator:
            # Kotlin/Scala/Swift: `@RequestParam id: String` -> tên đứng TRƯỚC dấu `:`.
            break
        elif token.kind == OP and token.text in (",", ")"):
            break
        cursor += 1
    return last
