"""Tách hàm, lớp, import/export của JavaScript và TypeScript từ dòng token.

Không dựng AST: bộ lexer chung đã cho ra token kèm vị trí, và mọi thứ phân
tích xuyên file cần -- tên hàm, tham số, thân hàm, ai xuất cái gì, ai import
từ đâu -- đều đọc được từ hình dạng token quanh từ khóa. Chỗ nào mập mờ thì
bỏ qua: một hàm không tách được chỉ làm mất một liên kết, còn một liên kết
sai thì gán sink về nhầm tệp.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from ..generic.lexer import IDENT, NEWLINE, OP, Token
from .model import ClassDef, FileFacts, FunctionDef, ImportBinding
from .stream import Stream

_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "function",
        "return",
        "with",
        "do",
        "else",
        "new",
        "typeof",
        "await",
        "yield",
        "delete",
        "void",
        "in",
        "of",
        "instanceof",
        "super",
        "import",
        "export",
        "throw",
        "case",
    }
)
_MODIFIERS = frozenset(
    {
        "static",
        "async",
        "public",
        "private",
        "protected",
        "readonly",
        "get",
        "set",
        "override",
        "abstract",
        "declare",
    }
)
_DECLARATIONS = frozenset({"const", "let", "var"})
_OBJECT_PRECEDERS = frozenset({"=", "(", ",", ":", "[", "?", "||", "&&", "??", "return", "default"})

# Decorator tham số của NestJS / routing-controllers đánh dấu giá trị đến
# thẳng từ request.
_PARAM_DECORATORS: Dict[str, str] = {
    "Query": "tham số truy vấn HTTP",
    "Body": "body của request HTTP",
    "Param": "tham số đường dẫn HTTP",
    "Headers": "header HTTP",
    "Cookies": "cookie HTTP",
    "QueryParam": "tham số truy vấn HTTP",
    "BodyParam": "body của request HTTP",
    "HeaderParam": "header HTTP",
    "CookieParam": "cookie HTTP",
}
_REQUEST_DECORATORS = frozenset({"Req", "Request"})

_ROUTE_METHODS = frozenset({"get", "post", "put", "delete", "patch", "all", "use", "options", "head"})
_ROUTER_OBJECTS = frozenset({"app", "router", "server", "api", "routes", "route", "r", "fastify"})
_NOT_FACTORIES = frozenset({"require", "async", "import", "function", "super", "this"})
_WRAPPER_TYPES = frozenset({"Promise", "Observable", "Readonly"})
_PRIMITIVE_TYPES = frozenset(
    {"string", "number", "boolean", "void", "any", "unknown", "never", "object", "undefined", "null", "bigint", "symbol"}
)
# Hàm bọc giữ nguyên hành vi của hàm được bọc: `util.promisify(exec)`.
_ALIAS_WRAPPERS = frozenset({"promisify", "util.promisify", "Bluebird.promisify", "Promise.promisify", "pify"})
_QUEUE_CLASSES = frozenset({"Queue", "Bull", "BullQueue"})
# Lời gọi cấu hình engine template cho cả ứng dụng: `swig.setDefaults(...)`,
# `nunjucks.configure(...)`, `new nunjucks.Environment(...)`.
_ENGINE_SETUP = frozenset({"setDefaults", "configure", "init", "Environment", "setup"})
# `Handlebars.compile(src, { noEscape: true })` chỉ tắt escape cho chuỗi đó.
_PER_TEMPLATE = frozenset({"compile", "precompile", "template", "render", "renderString", "renderFile"})


def extract(path: str, language: str, tokens: List[Token]) -> FileFacts:
    return _JsExtractor(path, language, tokens).run()


class _JsExtractor:
    def __init__(self, path: str, language: str, tokens: List[Token]) -> None:
        self.path = path
        self.facts = FileFacts(path=path, language=language)
        self.s = Stream(tokens)
        self.tokens = tokens
        # `{` -> ("class", tên) | ("object", tên) | ("block", "")
        self.containers: Dict[int, Tuple[str, str]] = {}
        self.functions: List[FunctionDef] = []
        self.anonymous: List[FunctionDef] = []
        self.function_at_open: Dict[int, FunctionDef] = {}

    # ------------------------------------------------------------------ run
    def run(self) -> FileFacts:
        self._classify_containers()
        self._find_functions()
        self._imports_and_exports()
        self._constants_and_objects()
        self._types()
        self._routes_and_queues()
        self.facts.functions = self.functions + self.anonymous
        return self.facts

    # ------------------------------------------------------------ containers
    def _classify_containers(self) -> None:
        s = self.s
        for index in range(s.size):
            if not s.is_ident(index, "class"):
                continue
            if s.is_op(s.back(index - 1), ".", "?."):
                continue
            cursor = s.sig(index + 1)
            name = ""
            if s.is_ident(cursor) and s.text(cursor) not in ("extends", "implements"):
                name = s.text(cursor)
                cursor = s.sig(cursor + 1)
                cursor = s.skip_generic(cursor, s.size)
            if not name:
                name = self._assigned_name(index) or ""
            bases: List[str] = []
            limit = min(s.size, cursor + 80)
            while cursor < limit and not s.is_op(cursor, "{"):
                if s.is_ident(cursor, "extends", "implements"):
                    chain, after = s.chain_at(s.sig(cursor + 1))
                    if chain:
                        bases.append(chain)
                        cursor = after
                        continue
                if s.is_op(cursor, ",") and bases:
                    chain, after = s.chain_at(s.sig(cursor + 1))
                    if chain:
                        bases.append(chain)
                        cursor = after
                        continue
                cursor += 1
            if not s.is_op(cursor, "{") or not name:
                continue
            self.containers[cursor] = ("class", name)
            self.facts.classes.setdefault(
                name, ClassDef(path=self.path, name=name, bases=tuple(bases), qualified=name)
            )
        for index in range(s.size):
            if not s.is_op(index, "{") or index in self.containers:
                continue
            previous = s.back(index - 1)
            if previous < 0:
                self.containers[index] = ("block", "")
                continue
            token = self.tokens[previous]
            if token.in_string:
                self.containers[index] = ("block", "")
                continue
            if token.kind == OP and token.text in _OBJECT_PRECEDERS:
                name = ""
                if token.text == "=":
                    name = self._target_before(previous) or ""
                elif token.text == "(" and s.is_op(s.back(previous - 1), "=>"):
                    name = ""
                self.containers[index] = ("object", name)
            elif token.kind == IDENT and token.text in ("return", "default"):
                name = "default" if token.text == "default" and self._is_export_default(previous) else ""
                self.containers[index] = ("object", name)
            else:
                self.containers[index] = ("block", "")

    def _is_export_default(self, default_index: int) -> bool:
        return self.s.is_ident(self.s.back(default_index - 1), "export")

    def _container_of(self, index: int) -> Tuple[str, str, int]:
        opener = self.s.parent[index]
        if opener < 0:
            return ("module", "", -1)
        kind, name = self.containers.get(opener, ("block", ""))
        return (kind, name, opener)

    # ------------------------------------------------------------- functions
    def _find_functions(self) -> None:
        s = self.s
        for index in range(s.size):
            token = self.tokens[index]
            if token.in_string:
                continue
            if token.kind == IDENT and token.text == "function":
                if s.is_op(s.back(index - 1), "."):
                    continue
                self._function_keyword(index)
            elif token.kind == OP and token.text == "=>":
                self._arrow(index)
            elif token.kind == IDENT and token.text not in _KEYWORDS:
                kind, owner, _ = self._container_of(index)
                if kind in ("class", "object"):
                    self._method(index, kind, owner)

    def _function_keyword(self, index: int) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        if s.is_op(cursor, "*"):
            cursor = s.sig(cursor + 1)
        name = ""
        if s.is_ident(cursor):
            name = s.text(cursor)
            cursor = s.sig(cursor + 1)
        cursor = s.skip_generic(cursor, s.size)
        if not s.is_op(cursor, "("):
            return
        close = s.closing(cursor)
        if close < 0:
            return
        body = self._body_after_params(close)
        if body < 0:
            return
        head = index
        if s.is_ident(s.back(index - 1), "async"):
            head = s.back(index - 1)
        owner = ""
        if not name:
            name, owner = self._context_name(head)
        else:
            # `const run = function inner(...)`: tên dùng để gọi là `run`.
            alias, alias_owner = self._context_name(head)
            if alias:
                name, owner = alias, alias_owner
        if not owner and self._is_default_export(head):
            self.facts.exports["default"] = name or "default"
            name = name or "default"
        self._record(name, owner, cursor, close, body, s.closing(body), False, index)

    def _arrow(self, index: int) -> None:
        s = self.s
        previous = s.back(index - 1)
        if previous < 0:
            return
        params_open = -1
        params_close = -1
        single = -1
        if s.is_op(previous, ")"):
            params_close = previous
            params_open = s.match[previous]
        elif s.is_ident(previous):
            # `(a: T): R =>` -- lùi qua kiểu trả về tới `)` đứng trước `:`.
            colon = -1
            cursor = previous
            floor = max(0, previous - 24)
            while cursor > floor:
                if s.is_op(cursor, ":") and s.is_op(s.back(cursor - 1), ")"):
                    colon = cursor
                    break
                if s.is_op(cursor, ";", "{", "}", "=", "=>", ","):
                    break
                cursor -= 1
            if colon >= 0:
                params_close = s.back(colon - 1)
                params_open = s.match[params_close]
            else:
                single = previous
        elif s.is_op(previous, ">"):
            cursor = previous
            floor = max(0, previous - 24)
            while cursor > floor and not s.is_op(cursor, ":"):
                cursor -= 1
            if s.is_op(cursor, ":") and s.is_op(s.back(cursor - 1), ")"):
                params_close = s.back(cursor - 1)
                params_open = s.match[params_close]
        if single < 0 and (params_open < 0 or params_close < 0):
            return
        head = single if single >= 0 else params_open
        before = s.back(head - 1)
        if s.is_ident(before, "async"):
            head = before
        # Tham số generic `<T>(x: T) =>`.
        if s.is_op(s.back(head - 1), ">"):
            pass
        name, owner = self._context_name(head)
        if not owner and self._is_default_export(head):
            self.facts.exports["default"] = name or "default"
            name = name or "default"
        start = s.sig(index + 1)
        if s.is_op(start, "{"):
            body_close = s.closing(start)
            if body_close < 0:
                return
            if single >= 0:
                self._record_single(name, owner, single, start + 1, body_close, False, index)
            else:
                self._record(name, owner, params_open, params_close, start, body_close, False, index)
            return
        end = self._expression_end(start)
        if end <= start:
            return
        if single >= 0:
            self._record_single(name, owner, single, start, end, True, index)
        else:
            self._record(name, owner, params_open, params_close, start, end, True, index)

    def _method(self, index: int, kind: str, owner: str) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        cursor = s.skip_generic(cursor, s.size)
        if not s.is_op(cursor, "("):
            return
        previous = s.back(index - 1)
        if previous >= 0:
            token = self.tokens[previous]
            allowed = (
                (token.kind == OP and token.text in ("{", "}", ";", ",", "*"))
                or (token.kind == IDENT and token.text in _MODIFIERS)
                or self._ends_decorator(previous)
            )
            if not allowed:
                return
        close = s.closing(cursor)
        if close < 0:
            return
        body = self._body_after_params(close)
        if body < 0:
            # Khai báo không thân trong lớp TypeScript ( abstract, overload ).
            return
        if kind == "object" and not owner:
            owner = ""
        name = s.text(index)
        if name == "constructor" and kind == "class":
            name = "constructor"
        self._record(name, owner if kind == "class" or owner else "", cursor, close, body, s.closing(body), False, index)

    def _ends_decorator(self, index: int) -> bool:
        s = self.s
        if s.is_op(index, ")"):
            opener = s.match[index]
            name_index = s.back(opener - 1)
            return s.is_ident(name_index) and s.is_op(s.back(name_index - 1), "@")
        if s.is_ident(index):
            return s.is_op(s.back(index - 1), "@")
        return False

    def _body_after_params(self, close: int) -> int:
        s = self.s
        cursor = s.sig(close + 1)
        if s.is_op(cursor, ":"):
            # Kiểu trả về: đi tới `{` mở thân ở cùng cấp.
            limit = min(s.size, cursor + 64)
            cursor += 1
            while cursor < limit:
                if s.is_op(cursor, "{"):
                    # `: { a: string }` là kiểu object, thân hàm là `{` sau nó.
                    after = s.closing(cursor)
                    following = s.sig(after + 1) if after > 0 else -1
                    if after > 0 and s.is_op(following, "{"):
                        return following
                    return cursor
                if s.is_op(cursor, ";", "=>", "=", "}"):
                    return -1
                if s.is_op(cursor, "(", "["):
                    closing = s.closing(cursor)
                    if closing < 0:
                        return -1
                    cursor = closing + 1
                    continue
                cursor += 1
            return -1
        if s.is_op(cursor, "{"):
            return cursor
        return -1

    def _expression_end(self, start: int) -> int:
        s = self.s
        cursor = start
        while cursor < s.size:
            token = self.tokens[cursor]
            if token.kind == OP and not token.in_string:
                if token.text in ("(", "[", "{"):
                    closing = s.closing(cursor)
                    if closing < 0:
                        return cursor
                    cursor = closing + 1
                    continue
                if token.text in (")", "]", "}", ",", ";"):
                    return cursor
            if token.kind == NEWLINE:
                previous = s.back(cursor - 1)
                following = s.sig(cursor + 1)
                continues = (
                    previous >= 0
                    and self.tokens[previous].kind == OP
                    and self.tokens[previous].text in ("+", "-", "*", "/", "?", ":", "&&", "||", "??", ".", "=>", ",", "(")
                ) or (s.is_op(following, ".", "?.", "+", "?", ":", "&&", "||", "??"))
                if not continues:
                    return cursor
            cursor += 1
        return cursor

    # Ngữ cảnh đặt tên cho hàm vô danh: `x = function`, `key: () =>`, ...
    def _context_name(self, head: int) -> Tuple[str, str]:
        s = self.s
        previous = s.back(head - 1)
        if previous < 0:
            return "", ""
        if s.is_op(previous, "="):
            target = self._target_before(previous)
            if not target:
                return "", ""
            kind, owner, _ = self._container_of(previous)
            if target.startswith("this."):
                target = target[len("this.") :]
                return target.split(".")[-1], self._this_owner(previous)
            if target.startswith("module.exports."):
                name = target[len("module.exports.") :]
                self.facts.exports[name] = name
                return name, ""
            if target.startswith("exports."):
                name = target[len("exports.") :]
                self.facts.exports[name] = name
                return name, ""
            if target == "module.exports":
                self.facts.exports["default"] = "default"
                return "default", ""
            if "." in target:
                head_name, _, tail = target.rpartition(".")
                if head_name.endswith(".prototype") and "." not in head_name[: -len(".prototype")]:
                    # `Dao.prototype.find = function` -- phương thức của lớp ES5.
                    head_name = head_name[: -len(".prototype")]
                    self.facts.classes.setdefault(head_name, ClassDef(path=self.path, name=head_name))
                return tail, head_name
            if kind == "class":
                return target, owner
            return target, ""
        if s.is_op(previous, ":"):
            key = s.back(previous - 1)
            kind, owner, _ = self._container_of(previous)
            if kind == "object" and (s.is_ident(key) or s.is_string(key)):
                return self.tokens[key].text, owner
        return "", ""

    def _this_owner(self, index: int) -> str:
        """Lớp mà `this` tại `index` trỏ về: lớp thật, hoặc hàm khởi tạo ES5.

        `function UserDAO(db) { this.find = (id) => ... }` dùng như một lớp
        qua `new UserDAO(db)`. Chỉ nhận hàm tên viết hoa ở ngoài cùng, theo
        quy ước của hàm khởi tạo, để `this.x = ...` trong hàm thường không
        biến hàm đó thành lớp.
        """
        opener = self.s.parent[index]
        while opener >= 0:
            kind, name = self.containers.get(opener, ("block", ""))
            if kind == "class":
                return name
            function = self.function_at_open.get(opener + 1)
            if function is not None and function.name and not function.owner and function.name[:1].isupper():
                self.facts.classes.setdefault(function.name, ClassDef(path=self.path, name=function.name))
                return function.name
            opener = self.s.parent[opener]
        return ""

    def _enclosing_class(self, index: int) -> str:
        opener = self.s.parent[index]
        while opener >= 0:
            kind, name = self.containers.get(opener, ("block", ""))
            if kind == "class":
                return name
            opener = self.s.parent[opener]
        return ""

    def _target_before(self, equals: int) -> Optional[str]:
        s = self.s
        cursor = s.back(equals - 1)
        # `const f: Handler = ...` -- bỏ chú thích kiểu.
        scan = cursor
        floor = max(0, cursor - 16)
        while scan > floor:
            if s.is_op(scan, ":") and s.is_ident(s.back(scan - 1)):
                inner = s.back(scan - 1)
                if s.is_ident(s.back(inner - 1), *_DECLARATIONS) or self._is_class_level(inner):
                    cursor = inner
                break
            if s.is_op(scan, ";", "{", "}", "(", ")", "=", ","):
                break
            scan -= 1
        chain, _ = s.chain_ending(cursor)
        return chain

    def _is_class_level(self, index: int) -> bool:
        kind, _, _ = self._container_of(index)
        return kind == "class"

    def _is_default_export(self, head: int) -> bool:
        s = self.s
        previous = s.back(head - 1)
        return s.is_ident(previous, "default") and s.is_ident(s.back(previous - 1), "export")

    def _record_single(
        self, name: str, owner: str, param: int, body_start: int, body_end: int, expression: bool, anchor: int
    ) -> None:
        function = FunctionDef(
            path=self.path,
            name=name,
            owner=owner,
            params=(self.s.text(param),),
            param_types=("",),
            param_sources=(None,),
            body_start=body_start,
            body_end=body_end,
            line=self.tokens[anchor].line,
            expression_body=expression,
        )
        self._store(function, anchor)

    def _record(
        self,
        name: str,
        owner: str,
        params_open: int,
        params_close: int,
        body: int,
        body_end: int,
        expression: bool,
        anchor: int,
    ) -> None:
        s = self.s
        if body_end < 0:
            return
        names: List[str] = []
        types: List[str] = []
        sources: List[Optional[str]] = []
        variadic = False
        request_names: List[str] = []
        for start, end in s.split_commas(params_open + 1, params_close):
            label: Optional[str] = None
            cursor = start
            while cursor < end and s.is_op(cursor, "@"):
                decorator = s.text(cursor + 1)
                if decorator in _PARAM_DECORATORS:
                    label = _PARAM_DECORATORS[decorator]
                if decorator in _REQUEST_DECORATORS:
                    label = "__request__"
                after = s.sig(cursor + 2)
                if s.is_op(after, "("):
                    closing = s.closing(after)
                    cursor = closing + 1 if closing > 0 else after + 1
                else:
                    cursor = after
                cursor = s.sig(cursor)
            while cursor < end and s.is_ident(cursor) and s.text(cursor) in _MODIFIERS:
                cursor = s.sig(cursor + 1)
            if s.is_op(cursor, "..."):
                variadic = True
                cursor = s.sig(cursor + 1)
            if s.is_op(cursor, "{", "["):
                # Tham số phá cấu trúc: đặt tên giả, các trường bên trong
                # được gắn kiểu riêng ở dưới.
                names.append("")
                types.append("")
                sources.append(label if label != "__request__" else None)
                continue
            if not s.is_ident(cursor):
                continue
            param_name = s.text(cursor)
            param_type = ""
            colon = s.sig(cursor + 1)
            if s.is_op(colon, "?"):
                colon = s.sig(colon + 1)
            if s.is_op(colon, ":"):
                type_chain, _ = s.chain_at(s.sig(colon + 1))
                param_type = type_chain or ""
            names.append(param_name)
            types.append(param_type)
            if label == "__request__":
                request_names.append(param_name)
                sources.append(None)
            else:
                sources.append(label)
            # `constructor(private readonly repo: Repo)` khai báo luôn trường.
            if name == "constructor" and owner and param_type:
                modifiers = [
                    s.text(i)
                    for i in range(start, cursor)
                    if s.is_ident(i) and s.text(i) in ("private", "public", "protected", "readonly")
                ]
                if modifiers and owner in self.facts.classes:
                    self.facts.classes[owner].fields[param_name] = param_type
            if param_type in ("Request", "express.Request", "FastifyRequest", "NextRequest"):
                request_names.append(param_name)
        body_start = body if expression else body + 1
        function = FunctionDef(
            path=self.path,
            name=name,
            owner=owner,
            params=tuple(names),
            param_types=tuple(types),
            param_sources=tuple(sources),
            body_start=body_start,
            body_end=body_end,
            line=self.tokens[anchor].line,
            return_type=self._return_annotation(params_close, body),
            expression_body=expression,
            variadic=variadic,
        )
        self._store(function, anchor)
        for request_name in request_names:
            self.facts.request_objects.append((body_start, body_end, request_name, "express"))

    def _return_annotation(self, params_close: int, body: int) -> str:
        """Kiểu trả về TypeScript `): Repo {` hoặc `): Promise<Repo> {`, hoặc ""."""
        s = self.s
        colon = s.sig(params_close + 1)
        if not s.is_op(colon, ":") or colon >= body:
            return ""
        chain, after = s.chain_at(s.sig(colon + 1))
        if chain in _WRAPPER_TYPES and s.is_op(s.sig(after), "<"):
            chain, after = s.chain_at(s.sig(s.sig(after) + 1))
        if not chain or chain in _PRIMITIVE_TYPES or s.is_op(s.sig(after), "[", "|"):
            return ""
        return chain

    def _store(self, function: FunctionDef, anchor: int) -> None:
        self.function_at_open[function.body_start] = function
        if not function.name:
            self.anonymous.append(function)
            return
        self.functions.append(function)
        if function.owner and function.owner in self.facts.classes:
            self.facts.classes[function.owner].methods.setdefault(function.name, []).append(function)

    # ---------------------------------------------------- imports / exports
    def _imports_and_exports(self) -> None:
        s = self.s
        for index in range(s.size):
            token = self.tokens[index]
            if token.in_string or token.kind != IDENT:
                continue
            if token.text == "import" and not s.is_op(s.back(index - 1), "."):
                self._import(index)
            elif token.text == "export" and not s.is_op(s.back(index - 1), "."):
                self._export(index)
            elif token.text == "require" and s.is_op(s.sig(index + 1), "("):
                self._require(index)
            elif token.text == "module" and s.is_op(index + 1, ".") and s.text(index + 2) == "exports":
                self._module_exports(index)
            elif token.text == "exports" and s.is_op(index + 1, ".") and not s.is_op(s.back(index - 1), "."):
                member = s.text(index + 2)
                after = s.sig(index + 3)
                if member and s.is_op(after, "="):
                    value = s.sig(after + 1)
                    if s.is_ident(value) and s.text(value) not in ("function", "async", "class"):
                        chain, _ = s.chain_at(value)
                        if chain and not s.is_op(s.sig(_chain_end(s, value)), "("):
                            self.facts.exports[member] = chain

    def _import(self, index: int) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        if s.is_op(cursor, "("):
            return
        if s.is_ident(cursor, "type", "typeof") and not s.is_ident(s.sig(cursor + 1), "from"):
            cursor = s.sig(cursor + 1)
        if s.is_string(cursor):
            return
        # `import x = require("m")`
        if s.is_ident(cursor) and s.is_op(s.sig(cursor + 1), "="):
            return
        bindings: List[Tuple[str, str]] = []
        limit = min(s.size, cursor + 400)
        while cursor < limit:
            if s.is_ident(cursor, "from"):
                spec_index = s.sig(cursor + 1)
                if s.is_string(spec_index):
                    spec = s.text(spec_index)
                    for local, remote in bindings:
                        self.facts.imports[local] = ImportBinding(spec, remote)
                return
            if s.is_op(cursor, "*"):
                alias = s.sig(cursor + 1)
                if s.is_ident(alias, "as"):
                    name = s.sig(alias + 1)
                    bindings.append((s.text(name), "*"))
                    cursor = s.sig(name + 1)
                    continue
            if s.is_op(cursor, "{"):
                close = s.closing(cursor)
                if close < 0:
                    return
                for start, end in s.split_commas(cursor + 1, close):
                    idents = [i for i in range(start, end) if s.is_ident(i) and s.text(i) != "type"]
                    if not idents:
                        continue
                    if len(idents) >= 3 and s.text(idents[1]) == "as":
                        bindings.append((s.text(idents[2]), s.text(idents[0])))
                    else:
                        bindings.append((s.text(idents[0]), s.text(idents[0])))
                cursor = s.sig(close + 1)
                continue
            if s.is_ident(cursor) and s.text(cursor) != "from":
                bindings.append((s.text(cursor), "default"))
            if s.is_op(cursor, ";"):
                return
            cursor += 1

    def _require(self, index: int) -> None:
        s = self.s
        open_paren = s.sig(index + 1)
        spec_index = s.sig(open_paren + 1)
        if not s.is_string(spec_index):
            return
        close = s.closing(open_paren)
        if close < 0:
            return
        spec = s.text(spec_index)
        member = ""
        after = s.sig(close + 1)
        if s.is_op(after, "."):
            member = s.text(after + 1)
        equals = s.back(index - 1)
        if not s.is_op(equals, "="):
            return
        target_end = s.back(equals - 1)
        is_data = spec.endswith(".json")
        if s.is_op(target_end, "}"):
            opener = s.match[target_end]
            for start, end in s.split_commas(opener + 1, target_end):
                idents = [i for i in range(start, end) if s.is_ident(i)]
                if not idents:
                    continue
                remote = s.text(idents[0])
                local = s.text(idents[-1])
                self.facts.imports[local] = ImportBinding(spec, remote)
            return
        if s.is_ident(target_end):
            local = s.text(target_end)
            if s.is_ident(s.back(target_end - 1), "import") or s.is_ident(
                s.back(target_end - 1), *_DECLARATIONS
            ) or s.back(target_end - 1) < 0 or not s.is_op(s.back(target_end - 1), "."):
                if is_data and not member:
                    self.facts.data_imports[local] = spec
                    return
                self.facts.imports[local] = ImportBinding(spec, member or "*")

    def _export(self, index: int) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        if s.is_ident(cursor, "type", "interface") and not s.is_op(s.sig(cursor + 1), "{", "*"):
            return
        if s.is_ident(cursor, "default"):
            value = s.sig(cursor + 1)
            if s.is_ident(value, "async"):
                value = s.sig(value + 1)
            if s.is_ident(value, "function"):
                name_index = s.sig(value + 1)
                if s.is_op(name_index, "*"):
                    name_index = s.sig(name_index + 1)
                if s.is_ident(name_index):
                    self.facts.exports["default"] = s.text(name_index)
                return
            if s.is_ident(value, "class"):
                name_index = s.sig(value + 1)
                if s.is_ident(name_index) and s.text(name_index) not in ("extends", "implements"):
                    self.facts.exports["default"] = s.text(name_index)
                return
            if s.is_ident(value, "new"):
                chain, _ = s.chain_at(s.sig(value + 1))
                if chain:
                    self.facts.module_types["default"] = chain
                    self.facts.exports["default"] = "default"
                return
            if s.is_ident(value):
                chain, after = s.chain_at(value)
                if chain and not s.is_op(s.sig(after), "(", "=>"):
                    self.facts.exports["default"] = chain
            return
        if s.is_ident(cursor, "async"):
            cursor = s.sig(cursor + 1)
        if s.is_ident(cursor, "abstract"):
            cursor = s.sig(cursor + 1)
        if s.is_ident(cursor, "function", "class", "interface", "enum", "namespace"):
            name_index = s.sig(cursor + 1)
            if s.is_op(name_index, "*"):
                name_index = s.sig(name_index + 1)
            if s.is_ident(name_index):
                name = s.text(name_index)
                self.facts.exports[name] = name
            return
        if s.is_ident(cursor, *_DECLARATIONS):
            name_index = s.sig(cursor + 1)
            if s.is_ident(name_index):
                name = s.text(name_index)
                self.facts.exports[name] = name
            elif s.is_op(name_index, "{"):
                close = s.closing(name_index)
                for start, end in s.split_commas(name_index + 1, close if close > 0 else name_index):
                    idents = [i for i in range(start, end) if s.is_ident(i)]
                    if idents:
                        self.facts.exports[s.text(idents[-1])] = s.text(idents[-1])
            return
        if s.is_op(cursor, "*"):
            after = s.sig(cursor + 1)
            exported = "*"
            if s.is_ident(after, "as"):
                exported = s.text(s.sig(after + 1))
                after = s.sig(s.sig(after + 1) + 1)
            if s.is_ident(after, "from") and s.is_string(s.sig(after + 1)):
                self.facts.reexports.append((s.text(s.sig(after + 1)), "*", exported))
            return
        if s.is_op(cursor, "{"):
            close = s.closing(cursor)
            if close < 0:
                return
            pairs: List[Tuple[str, str]] = []
            for start, end in s.split_commas(cursor + 1, close):
                idents = [i for i in range(start, end) if s.is_ident(i) and s.text(i) != "type"]
                if not idents:
                    continue
                if len(idents) >= 3 and s.text(idents[1]) == "as":
                    pairs.append((s.text(idents[0]), s.text(idents[2])))
                else:
                    pairs.append((s.text(idents[0]), s.text(idents[0])))
            after = s.sig(close + 1)
            if s.is_ident(after, "from") and s.is_string(s.sig(after + 1)):
                spec = s.text(s.sig(after + 1))
                for local, exported in pairs:
                    self.facts.reexports.append((spec, local, exported))
            else:
                for local, exported in pairs:
                    self.facts.exports[exported] = local

    def _module_exports(self, index: int) -> None:
        s = self.s
        after = s.sig(index + 3)
        if not s.is_op(after, "="):
            return
        value = s.sig(after + 1)
        if s.is_op(value, "{"):
            close = s.closing(value)
            if close < 0:
                return
            for start, end in s.split_commas(value + 1, close):
                first = s.sig(start)
                if not (s.is_ident(first) or s.is_string(first)):
                    continue
                key = s.text(first)
                following = s.sig(first + 1)
                if following >= end:
                    # `{ run }`: viết tắt.
                    self.facts.exports[key] = key
                elif s.is_op(following, ":"):
                    target = s.sig(following + 1)
                    if s.is_ident(target) and s.text(target) not in ("function", "async"):
                        chain, after_chain = s.chain_at(target)
                        if chain and s.sig(after_chain) >= end:
                            self.facts.exports[key] = chain
                            continue
                    self.facts.exports[key] = "module.exports.%s" % key
                elif s.is_op(following, "("):
                    self.facts.exports[key] = "module.exports.%s" % key
            return
        if s.is_ident(value, "new"):
            chain, _ = s.chain_at(s.sig(value + 1))
            if chain:
                self.facts.module_types["default"] = chain
                self.facts.exports["default"] = "default"
            return
        if s.is_ident(value) and s.text(value) not in ("function", "async", "class"):
            chain, after_chain = s.chain_at(value)
            if chain and not s.is_op(s.sig(after_chain), "(", "=>"):
                self.facts.exports["default"] = chain

    # ----------------------------------------------------- constants/objects
    def _constants_and_objects(self) -> None:
        s = self.s
        for opener, (kind, name) in self.containers.items():
            if kind != "object" or not name:
                continue
            close = s.closing(opener)
            if close < 0:
                continue
            members: Dict[str, str] = {}
            functions: List[str] = []
            for start, end in s.split_commas(opener + 1, close):
                first = s.sig(start)
                if not (s.is_ident(first) or s.is_string(first)):
                    continue
                key = s.text(first)
                following = s.sig(first + 1)
                if following >= end:
                    members[key] = key
                    continue
                if s.is_op(following, ":"):
                    value_start = s.sig(following + 1)
                    literal = s.string_value(value_start, end)
                    if literal is not None:
                        self.facts.constants["%s.%s" % (name, key)] = literal
                        continue
                    if s.is_ident(value_start) and s.text(value_start) not in ("function", "async", "new"):
                        chain, after = s.chain_at(value_start)
                        if chain and s.sig(after) >= end:
                            members[key] = chain
                            continue
                    members[key] = "%s.%s" % (name, key)
                    functions.append("%s.%s" % (name, key))
                elif s.is_op(following, "("):
                    members[key] = "%s.%s" % (name, key)
                    functions.append("%s.%s" % (name, key))
            if members:
                self.facts.objects[name] = members
            # Bảng điều phối `{ a: runA, b: runB }`: gọi qua `handlers[k](x)`
            # có thể chạy bất kỳ hàm nào trong đó.
            targets = tuple(sorted(set(members.values())))
            if len(targets) >= 2 and name not in ("module.exports", "default", "exports"):
                self.facts.dispatch_tables[name] = targets
        for index in range(s.size):
            if not s.is_ident(index, *_DECLARATIONS):
                continue
            if self.s.parent[index] >= 0:
                continue
            name_index = s.sig(index + 1)
            if not s.is_ident(name_index):
                continue
            equals = s.sig(name_index + 1)
            if s.is_op(equals, ":"):
                cursor = equals
                limit = min(s.size, equals + 16)
                while cursor < limit and not s.is_op(cursor, "=", ";"):
                    cursor += 1
                equals = cursor
            if not s.is_op(equals, "="):
                continue
            value = s.sig(equals + 1)
            end = value
            while end < s.size and not s.is_op(end, ";") and self.tokens[end].kind != NEWLINE:
                end += 1
            # chuỗi nối nhiều dòng
            while end < s.size and self.tokens[end].kind == NEWLINE and s.is_op(s.back(end - 1), "+"):
                end += 1
                while end < s.size and not s.is_op(end, ";") and self.tokens[end].kind != NEWLINE:
                    end += 1
            literal = s.string_value(value, end)
            if literal is not None:
                self.facts.constants[s.text(name_index)] = literal

    # ----------------------------------------------------------------- types
    def _types(self) -> None:
        s = self.s
        by_body = sorted(self.functions + self.anonymous, key=lambda f: f.body_start)
        for index in range(s.size):
            if not s.is_op(index, "="):
                continue
            value = s.sig(index + 1)
            if s.is_ident(value, "await"):
                value = s.sig(value + 1)
            target = self._target_before(index)
            if not target:
                continue
            type_name = ""
            deferred = ""
            if s.is_ident(value, "new"):
                chain, _ = s.chain_at(s.sig(value + 1))
                type_name = chain or ""
            elif s.is_ident(value):
                chain, after = s.chain_at(value)
                if chain in _ALIAS_WRAPPERS and s.is_op(s.sig(after), "(") and "." not in target:
                    wrapped, wrapped_end = s.chain_at(s.sig(s.sig(after) + 1))
                    if wrapped and s.is_op(s.sig(wrapped_end), ")"):
                        self.facts.aliases[target] = wrapped
                        continue
                if chain and s.is_op(s.sig(after), "(") and chain not in _NOT_FACTORIES:
                    deferred = chain
                elif chain and target.startswith("this.") and s.sig(after) < s.size:
                    # `this.repo = repo` trong constructor: kiểu khai báo của
                    # tham số, hoặc ( JS thuần ) kiểu của đối số ở nơi `new`.
                    owner_function = _innermost(by_body, index)
                    if owner_function is not None and chain in owner_function.params:
                        position = owner_function.params.index(chain)
                        type_name = owner_function.param_types[position]
                        if not type_name and self._constructor_like(owner_function, index):
                            type_name = "(param)%d" % position
            if not type_name and not deferred:
                continue
            if target.startswith("this."):
                field_name = target[len("this.") :]
                owner = self._this_owner(index)
                if owner and owner in self.facts.classes and "." not in field_name:
                    if type_name:
                        self.facts.classes[owner].fields[field_name] = type_name
                    else:
                        self.facts.classes[owner].fields.setdefault(field_name, "()" + deferred)
                continue
            if "." in target:
                continue
            kind, owner, _ = self._container_of(index)
            if kind == "class":
                if type_name:
                    self.facts.classes[owner].fields[target] = type_name
                continue
            function = _innermost(by_body, index)
            if function is None:
                if type_name:
                    self.facts.module_types[target] = type_name
                else:
                    self.facts.module_deferred[target] = deferred
            else:
                if type_name:
                    self.facts.envs.setdefault(function.key, {})[target] = type_name
                else:
                    self.facts.deferred.setdefault(function.key, {})[target] = deferred
        # Trường khai báo kiểu trong thân lớp: `private repo: Repo;`
        for opener, (kind, owner) in self.containers.items():
            if kind != "class":
                continue
            close = s.closing(opener)
            cursor = opener + 1
            while 0 < close and cursor < close:
                if s.is_op(cursor, "{", "("):
                    end = s.closing(cursor)
                    cursor = end + 1 if end > 0 else cursor + 1
                    continue
                if s.is_ident(cursor) and s.is_op(s.sig(cursor + 1), ":") and s.parent[cursor] == opener:
                    previous = s.back(cursor - 1)
                    if previous == opener or s.is_op(previous, ";", "}") or s.is_ident(previous, *_MODIFIERS) or self._ends_decorator(previous):
                        type_chain, _ = s.chain_at(s.sig(s.sig(cursor + 1) + 1))
                        if type_chain:
                            fields = self.facts.classes[owner].fields
                            if fields.get(s.text(cursor), "(param)").startswith("(param)"):
                                fields[s.text(cursor)] = type_chain
                cursor += 1
        self._object_types(by_body)
        self._factory_returns(by_body)
        self._constructions(by_body)

    def _constructor_like(self, function: FunctionDef, index: int) -> bool:
        if function.name == "constructor":
            return True
        # Hàm khởi tạo ES5: `function UserDAO(db) { this.db = db; }`.
        return bool(function.name) and not function.owner and function.name == self._this_owner(index)

    def _object_types(self, by_body: List[FunctionDef]) -> None:
        """Object literal mang đối tượng có kiểu thành một "lớp" vô danh.

            function createServices(db) {
              return { users: new UserService(new UserRepo(db)), files: fileService };
            }
            const api = { users: new UserService(repo) };

        Trường nào là `new X()` hay biến đã biết kiểu thì nhớ kiểu; trường nào
        là hàm thì thành phương thức. Lời gọi `services.users.find(x)` nhờ đó
        đi tới đúng `UserService.find`.
        """
        s = self.s
        for opener, (kind, name) in self.containers.items():
            if kind != "object":
                continue
            previous = s.back(opener - 1)
            returned = s.is_ident(previous, "return")
            if not returned and not (name and "." not in name and s.is_op(previous, "=")):
                continue
            close = s.closing(opener)
            if close < 0:
                continue
            function = _innermost(by_body, opener)
            env = self.facts.envs.get(function.key, {}) if function is not None else self.facts.module_types
            deferred = self.facts.deferred.get(function.key, {}) if function is not None else self.facts.module_deferred
            synthetic = "<obj:%d>" % opener
            info = ClassDef(path=self.path, name=synthetic, qualified=synthetic)
            typed = False
            for start, end in s.split_commas(opener + 1, close):
                first = s.sig(start)
                if not s.is_ident(first):
                    continue
                key = s.text(first)
                following = s.sig(first + 1)
                value = first if following >= end else (s.sig(following + 1) if s.is_op(following, ":") else -1)
                if s.is_op(following, "("):
                    method = self._function_starting(following, close)
                    if method is not None:
                        info.methods.setdefault(key, []).append(method)
                    continue
                if value < 0:
                    continue
                if s.is_ident(value, "new"):
                    chain, _ = s.chain_at(s.sig(value + 1))
                    if chain:
                        info.fields[key] = chain
                        typed = True
                    continue
                if s.is_ident(value, "function", "async") or s.is_op(value, "("):
                    method = self._function_starting(value, end)
                    if method is not None:
                        info.methods.setdefault(key, []).append(method)
                    continue
                chain, after = s.chain_at(value)
                if not chain or s.sig(after) < end:
                    continue
                if chain in env:
                    info.fields[key] = env[chain]
                    typed = True
                elif chain in deferred:
                    info.fields[key] = "()" + deferred[chain]
                    typed = True
            if not typed and not (returned and info.methods):
                continue
            self.facts.classes[synthetic] = info
            if returned:
                if function is not None:
                    self.facts.envs.setdefault(function.key, {}).setdefault("<return>", synthetic)
            elif function is None:
                self.facts.module_types.setdefault(name, synthetic)
            else:
                self.facts.envs.setdefault(function.key, {}).setdefault(name, synthetic)

    def _function_starting(self, start: int, end: int) -> Optional[FunctionDef]:
        """Hàm ( có tên hay vô danh ) mà thân nằm trong đoạn [start, end)."""
        best: Optional[FunctionDef] = None
        for function in self.functions + self.anonymous:
            if start <= function.body_start <= end:
                if best is None or function.body_start < best.body_start:
                    best = function
        return best

    def _factory_returns(self, by_body: List[FunctionDef]) -> None:
        """`return new Repo(db)` / `return repo` cho biết hàm factory trả về kiểu gì."""
        s = self.s
        for index in range(s.size):
            if not s.is_ident(index, "return"):
                continue
            function = _innermost(by_body, index)
            if function is None:
                continue
            value = s.sig(index + 1)
            if s.is_ident(value, "await"):
                value = s.sig(value + 1)
            type_name = ""
            if s.is_ident(value, "new"):
                chain, _ = s.chain_at(s.sig(value + 1))
                type_name = chain or ""
            elif s.is_ident(value):
                chain, after = s.chain_at(value)
                ends = after >= s.size or self.tokens[after].kind == NEWLINE or s.is_op(after, ";", "}")
                if chain and "." not in chain and ends:
                    type_name = self.facts.envs.get(function.key, {}).get(chain, "")
                    if not type_name and chain in self.facts.deferred.get(function.key, {}):
                        type_name = "()" + self.facts.deferred[function.key][chain]
            if type_name:
                self.facts.envs.setdefault(function.key, {}).setdefault("<return>", type_name)

    def _constructions(self, by_body: List[FunctionDef]) -> None:
        s = self.s
        for index in range(s.size):
            if not s.is_ident(index, "new"):
                continue
            chain, after = s.chain_at(s.sig(index + 1))
            if not chain:
                continue
            opener = s.skip_generic(s.sig(after), s.size)
            opener = s.sig(opener)
            if not s.is_op(opener, "("):
                continue
            close = s.closing(opener)
            if close < 0:
                continue
            arguments: List[str] = []
            for start, end in s.split_commas(opener + 1, close):
                first = s.sig(start)
                described = ""
                if s.is_ident(first, "new"):
                    inner, _ = s.chain_at(s.sig(first + 1))
                    described = "new:" + inner if inner else ""
                elif s.is_ident(first):
                    name, name_end = s.chain_at(first)
                    if name and s.sig(name_end) >= end:
                        described = "var:" + name
                arguments.append(described)
            if any(arguments):
                function = _innermost(by_body, index)
                self.facts.constructions.append(
                    (chain, function.body_start if function is not None else -1, tuple(arguments))
                )

    # ------------------------------------------------------- routes / queues
    def _routes_and_queues(self) -> None:
        s = self.s
        by_body = {f.body_start: f for f in self.functions + self.anonymous}
        for index in range(s.size):
            if not s.is_ident(index) or self.tokens[index].in_string:
                continue
            chain, after = s.chain_at(index)
            if chain is None or not s.is_op(after, "("):
                continue
            if s.is_op(s.back(index - 1), "."):
                continue
            close = s.closing(after)
            if close < 0:
                continue
            head, _, method = chain.rpartition(".")
            arguments = s.split_commas(after + 1, close)
            if method in _ROUTE_METHODS and head and head.split(".")[0] in _ROUTER_OBJECTS:
                if not arguments:
                    continue
                first = s.sig(arguments[0][0])
                if not s.is_string(first) and method != "use":
                    continue
                for start, end in arguments[1:] if s.is_string(first) else arguments:
                    self._route_argument(start, end, by_body)
            self._escape_setting(method, after, close)
            if method == "add" and head in self.facts.queues:
                self.facts.queue_producers.append((head, index))
            if (head == "" and method in _QUEUE_CLASSES) or (
                s.is_ident(s.back(index - 1), "new") and method in _QUEUE_CLASSES | {"Worker"}
            ):
                if not arguments:
                    continue
                first = s.sig(arguments[0][0])
                if not s.is_string(first):
                    continue
                queue_name = s.text(first)
                if method == "Worker" and len(arguments) >= 2:
                    self._queue_consumer(queue_name, arguments[1], by_body)
                    continue
                new_index = s.back(index - 1)
                equals = s.back(new_index - 1) if s.is_ident(new_index, "new") else s.back(index - 1)
                if s.is_op(equals, "="):
                    target = self._target_before(equals)
                    if target:
                        self.facts.queues[target] = queue_name
            if method == "process" and head in self.facts.queues and arguments:
                self._queue_consumer(self.facts.queues[head], arguments[-1], by_body)

    def _escape_setting(self, method: str, start: int, end: int) -> None:
        """`autoescape: false` / `noEscape: true` truyền cho engine template."""
        s = self.s
        if method in _PER_TEMPLATE:
            return
        for index in range(start + 1, end - 2):
            if not s.is_ident(index, "autoescape", "noEscape") or not s.is_op(s.sig(index + 1), ":"):
                continue
            value = s.sig(s.sig(index + 1) + 1)
            line = self.tokens[index].line
            if s.text(index) == "autoescape" and s.is_ident(value, "false") and method in _ENGINE_SETUP:
                self.facts.template_settings.append(("autoescape", line))
            elif s.text(index) == "noEscape" and s.is_ident(value, "true"):
                self.facts.template_settings.append(("noEscape", line))

    def _route_argument(self, start: int, end: int, by_body: Dict[int, FunctionDef]) -> None:
        s = self.s
        first = s.sig(start)
        function = self._function_in(first, end, by_body)
        if function is not None:
            if function.params and function.params[0]:
                self.facts.request_objects.append(
                    (function.body_start, function.body_end, function.params[0], "express")
                )
            return
        chain, after = s.chain_at(first)
        if chain and s.sig(after) >= end:
            self.facts.route_handlers.append((chain, first))

    def _queue_consumer(self, queue_name: str, argument: Tuple[int, int], by_body: Dict[int, FunctionDef]) -> None:
        s = self.s
        first = s.sig(argument[0])
        function = self._function_in(first, argument[1], by_body)
        if function is not None and function.params and function.params[0]:
            self.facts.queue_consumers.append((queue_name, function.body_start, function.params[0]))

    def _function_in(self, start: int, end: int, by_body: Dict[int, FunctionDef]) -> Optional[FunctionDef]:
        for function in by_body.values():
            if start <= function.body_start <= end and function.line == self.tokens[start].line:
                return function
        for function in by_body.values():
            if start <= function.body_start <= end:
                return function
        return None

    def _assigned_name(self, index: int) -> Optional[str]:
        previous = self.s.back(index - 1)
        if self.s.is_op(previous, "="):
            target = self._target_before(previous)
            if target:
                return target.split(".")[-1]
        return None


def _innermost(functions: List[FunctionDef], index: int) -> Optional[FunctionDef]:
    found: Optional[FunctionDef] = None
    for function in functions:
        if function.body_start <= index < function.body_end:
            if found is None or function.body_start >= found.body_start:
                found = function
    return found


def _chain_end(stream: Stream, index: int) -> int:
    _, end = stream.chain_at(index)
    return end


def exported_names(facts: FileFacts) -> Set[str]:
    return set(facts.exports)
