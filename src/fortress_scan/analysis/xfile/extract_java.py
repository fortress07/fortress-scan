"""Tách gói, import, lớp, trường và phương thức của Java ( kèm Kotlin cơ bản )."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..generic.lexer import IDENT, NEWLINE, OP, Token
from .model import ClassDef, FileFacts, FunctionDef, ImportBinding
from .stream import Stream

_MODIFIERS = frozenset(
    {
        "public",
        "private",
        "protected",
        "static",
        "final",
        "abstract",
        "synchronized",
        "native",
        "default",
        "transient",
        "volatile",
        "strictfp",
        "open",
        "override",
        "suspend",
        "internal",
        "inline",
        "operator",
    }
)
_NOT_NAMES = frozenset(
    {"if", "for", "while", "switch", "catch", "return", "new", "throw", "synchronized", "else", "try", "do", "super", "this"}
)

# Chú thích tham số mà Spring / JAX-RS dùng để bơm dữ liệu request vào.
_PARAM_SOURCES: Dict[str, str] = {
    "RequestParam": "tham số truy vấn HTTP",
    "PathVariable": "tham số đường dẫn HTTP",
    "RequestBody": "body của request HTTP",
    "RequestHeader": "header HTTP",
    "CookieValue": "cookie HTTP",
    "RequestPart": "body của request HTTP",
    "MatrixVariable": "tham số đường dẫn HTTP",
    "ModelAttribute": "trường form HTTP",
    "QueryParam": "tham số truy vấn HTTP",
    "PathParam": "tham số đường dẫn HTTP",
    "FormParam": "trường form HTTP",
    "HeaderParam": "header HTTP",
    "CookieParam": "cookie HTTP",
    "Payload": "payload hàng đợi tin nhắn",
    "Header": "header của tin nhắn",
}

# Phương thức nhận tin nhắn từ broker: mọi tham số là dữ liệu từ bên ngoài.
_LISTENERS = frozenset(
    {"KafkaListener", "RabbitListener", "JmsListener", "SqsListener", "StreamListener", "KafkaHandler", "RabbitHandler"}
)

# Phương thức xử lý request của Spring MVC: tham số kiểu đơn giản không có chú
# thích vẫn được Spring gán từ tham số request cùng tên.
_MAPPINGS = frozenset(
    {"GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping"}
)
_SIMPLE_TYPES = frozenset(
    {"String", "Integer", "Long", "int", "long", "Optional", "List", "Map", "MultiValueMap"}
)
_SAFE_SIMPLE = frozenset({"Integer", "Long", "int", "long", "boolean", "Boolean", "double", "Double", "UUID"})
_REQUEST_TYPES = {
    "HttpServletRequest": "servlet",
    "ServletRequest": "servlet",
    "HttpRequest": "servlet",
    "WebRequest": "webrequest",
    "NativeWebRequest": "webrequest",
}


def extract(path: str, language: str, tokens: List[Token]) -> FileFacts:
    return _JavaExtractor(path, language, tokens).run()


class _JavaExtractor:
    def __init__(self, path: str, language: str, tokens: List[Token]) -> None:
        self.path = path
        self.facts = FileFacts(path=path, language=language)
        self.s = Stream(tokens)
        self.tokens = tokens
        self.kotlin = path.endswith((".kt", ".kts"))
        # `{` -> tên lớp
        self.class_bodies: Dict[int, str] = {}

    def run(self) -> FileFacts:
        self._package_and_imports()
        self._classes()
        self._members()
        return self.facts

    def _package_and_imports(self) -> None:
        s = self.s
        for index in range(s.size):
            if self.s.parent[index] >= 0:
                continue
            if s.is_ident(index, "package"):
                chain, _ = s.chain_at(s.sig(index + 1))
                if chain:
                    self.facts.package = chain
            elif s.is_ident(index, "import"):
                cursor = s.sig(index + 1)
                static = False
                if s.is_ident(cursor, "static"):
                    static = True
                    cursor = s.sig(cursor + 1)
                chain, after = s.chain_at(cursor)
                if not chain:
                    continue
                wildcard = s.is_op(after, ".") and s.is_op(after + 1, "*")
                alias = ""
                if s.is_ident(s.sig(after), "as"):
                    alias = s.text(s.sig(s.sig(after) + 1))
                if static:
                    owner, _, member = chain.rpartition(".")
                    if wildcard:
                        self.facts.wildcard_imports.append("static:" + chain)
                    elif owner:
                        self.facts.static_imports[member] = (owner, member)
                elif wildcard:
                    self.facts.wildcard_imports.append(chain)
                else:
                    local = alias or chain.rsplit(".", 1)[-1]
                    self.facts.imports[local] = ImportBinding(chain, "class")

    def _classes(self) -> None:
        s = self.s
        for index in range(s.size):
            if not s.is_ident(index, "class", "interface", "enum", "record", "object"):
                continue
            if s.is_op(s.back(index - 1), ".", "::", "@"):
                continue
            kind = s.text(index)
            if kind == "object" and not self.kotlin:
                continue
            name_index = s.sig(index + 1)
            if not s.is_ident(name_index):
                continue
            name = s.text(name_index)
            cursor = s.sig(name_index + 1)
            cursor = s.skip_generic(cursor, s.size)
            bases: List[str] = []
            limit = min(s.size, cursor + 200)
            while cursor < limit and not s.is_op(cursor, "{", ";"):
                if s.is_op(cursor, "(") and kind in ("record", "class"):
                    closing = s.closing(cursor)
                    if closing < 0:
                        break
                    if self.kotlin:
                        self._kotlin_primary(name, cursor, closing)
                    cursor = closing + 1
                    continue
                if s.is_ident(cursor, "extends", "implements") or (self.kotlin and s.is_op(cursor, ":")):
                    cursor = s.sig(cursor + 1)
                    while cursor < limit:
                        chain, after = s.chain_at(cursor)
                        if not chain:
                            break
                        bases.append(chain)
                        after = s.skip_generic(s.sig(after), limit)
                        if s.is_op(after, "("):
                            closing = s.closing(after)
                            after = closing + 1 if closing > 0 else after + 1
                        after = s.sig(after)
                        if s.is_op(after, ","):
                            cursor = s.sig(after + 1)
                            continue
                        cursor = after
                        break
                    continue
                cursor += 1
            qualified = "%s.%s" % (self.facts.package, name) if self.facts.package else name
            info = self.facts.classes.get(name)
            if info is None:
                info = ClassDef(
                    path=self.path,
                    name=name,
                    bases=tuple(bases),
                    is_interface=kind == "interface",
                    qualified=qualified,
                )
                self.facts.classes[name] = info
            if s.is_op(cursor, "{"):
                self.class_bodies[cursor] = name

    def _kotlin_primary(self, owner: str, opener: int, closing: int) -> None:
        s = self.s
        for start, end in s.split_commas(opener + 1, closing):
            idents = [i for i in range(start, end) if s.is_ident(i)]
            keyword = [i for i in idents if s.text(i) in ("val", "var")]
            if not keyword:
                continue
            name_index = s.sig(keyword[0] + 1)
            colon = s.sig(name_index + 1)
            if s.is_ident(name_index) and s.is_op(colon, ":"):
                type_chain, _ = s.chain_at(s.sig(colon + 1))
                if type_chain:
                    self.facts.classes[owner].fields[s.text(name_index)] = type_chain

    def _members(self) -> None:
        s = self.s
        for opener, owner in self.class_bodies.items():
            close = s.closing(opener)
            if close < 0:
                continue
            cursor = opener + 1
            member_start = cursor
            while cursor < close:
                token = self.tokens[cursor]
                if token.kind == OP and not token.in_string:
                    if token.text == "(":
                        # Có thể là đầu phương thức.
                        handled = self._maybe_method(owner, member_start, cursor, close)
                        if handled > 0:
                            cursor = handled
                            member_start = cursor
                            continue
                        closing = s.closing(cursor)
                        cursor = closing + 1 if closing > 0 else cursor + 1
                        continue
                    if token.text == "{":
                        closing = s.closing(cursor)
                        cursor = closing + 1 if closing > 0 else cursor + 1
                        member_start = cursor
                        continue
                    if token.text == ";":
                        self._field(owner, member_start, cursor)
                        cursor += 1
                        member_start = cursor
                        continue
                    if token.text == "=" and self.kotlin:
                        pass
                if token.kind == NEWLINE and self.kotlin:
                    self._field(owner, member_start, cursor)
                    member_start = cursor + 1
                cursor += 1

    def _annotations(self, start: int, end: int) -> List[Tuple[str, int, int]]:
        """Chú thích trong đoạn: (tên, vị trí '(' hoặc -1, vị trí ')' hoặc -1)."""
        s = self.s
        found: List[Tuple[str, int, int]] = []
        cursor = start
        while cursor < end:
            if s.is_op(cursor, "@") and s.is_ident(cursor + 1):
                chain, after = s.chain_at(cursor + 1)
                name = (chain or "").rsplit(".", 1)[-1]
                after_sig = s.sig(after)
                if s.is_op(after_sig, "("):
                    closing = s.closing(after_sig)
                    found.append((name, after_sig, closing))
                    cursor = closing + 1 if closing > 0 else after_sig + 1
                    continue
                found.append((name, -1, -1))
                cursor = after
                continue
            cursor += 1
        return found

    def _annotation_string(self, opener: int, closing: int, key: str = "value") -> Optional[str]:
        s = self.s
        if opener < 0 or closing < 0:
            return None
        for start, end in s.split_commas(opener + 1, closing):
            first = s.sig(start)
            if s.is_ident(first) and s.is_op(s.sig(first + 1), "="):
                if s.text(first) != key:
                    continue
                first = s.sig(s.sig(first + 1) + 1)
            if s.is_op(first, "{"):
                inner = s.closing(first)
                if inner > 0:
                    value = s.string_value(s.sig(first + 1), inner)
                    if value is not None:
                        return value
                continue
            value = s.string_value(first, end)
            if value is not None:
                return value
        return None

    def _maybe_method(self, owner: str, member_start: int, paren: int, class_close: int) -> int:
        s = self.s
        name_index = s.back(paren - 1)
        if not s.is_ident(name_index) or s.text(name_index) in _NOT_NAMES:
            return -1
        # Chú thích có đối số `@GetMapping("/x")` cũng là IDENT + `(`.
        if s.is_op(s.back(name_index - 1), "@", "."):
            return -1
        previous = s.back(name_index - 1)
        is_ctor = s.text(name_index) == owner
        kotlin_fun = self.kotlin and s.is_ident(previous, "fun")
        if previous >= 0 and not is_ctor and not kotlin_fun:
            token = self.tokens[previous]
            # `List<Map<String, Object>> find(...)`: lexer gộp `>>` thành một token.
            if not (token.kind == IDENT or (token.kind == OP and token.text in (">", ">>", ">>>", "]", "?"))):
                return -1
            if token.kind == IDENT and token.text in ("new", "return", "throw", "else"):
                return -1
        close = s.closing(paren)
        if close < 0:
            return -1
        cursor = s.sig(close + 1)
        return_type = ""
        if self.kotlin and s.is_op(cursor, ":"):
            type_chain, after = s.chain_at(s.sig(cursor + 1))
            return_type = type_chain or ""
            cursor = s.sig(s.skip_generic(s.sig(after), class_close))
            if s.is_op(cursor, "?"):
                cursor = s.sig(cursor + 1)
        if s.is_ident(cursor, "throws"):
            while cursor < class_close and not s.is_op(cursor, "{", ";"):
                cursor += 1
        abstract = False
        expression = False
        if s.is_op(cursor, "{"):
            body_open = cursor
            body_close = s.closing(cursor)
            if body_close < 0:
                return -1
            body_start, body_end = body_open + 1, body_close
            next_member = body_close + 1
        elif s.is_op(cursor, ";") or s.is_ident(cursor, "default"):
            abstract = True
            body_start = body_end = cursor
            next_member = cursor + 1
            while next_member < class_close and not s.is_op(next_member - 1, ";"):
                next_member += 1
        elif self.kotlin and s.is_op(cursor, "="):
            expression = True
            body_start = s.sig(cursor + 1)
            body_end = body_start
            while body_end < class_close and self.tokens[body_end].kind != NEWLINE:
                if s.is_op(body_end, "(", "{", "["):
                    closing = s.closing(body_end)
                    body_end = closing + 1 if closing > 0 else body_end + 1
                    continue
                body_end += 1
            next_member = body_end
        elif self.kotlin and (previous < 0 or kotlin_fun):
            abstract = True
            body_start = body_end = cursor
            next_member = cursor
        else:
            return -1
        # Kiểu trả về Java: chuỗi truy cập ngay trước tên.
        if not self.kotlin and not is_ctor:
            type_end = previous
            if s.is_op(type_end, ">", ">>", ">>>"):
                depth = 0
                scan = type_end
                while scan > member_start:
                    if s.is_op(scan, ">", ">>", ">>>"):
                        depth += len(s.text(scan))
                    elif s.is_op(scan, "<"):
                        depth -= 1
                        if depth == 0:
                            break
                    scan -= 1
                type_end = s.back(scan - 1)
            chain, _ = s.chain_ending(type_end)
            return_type = chain or ""
        annotations = self._annotations(member_start, name_index)
        annotation_names = tuple(a[0] for a in annotations)
        pending_sql: List[Tuple[str, int, int]] = []
        for name, opener, closing in annotations:
            if name in ("Select", "Update", "Delete", "Insert") and opener > 0:
                text = self._annotation_string(opener, closing)
                if text:
                    pending_sql.append((text, self.tokens[opener].line, self.tokens[opener].column))
        names: List[str] = []
        types: List[str] = []
        sources: List[Optional[str]] = []
        aliases: List[str] = []
        listener = any(name in _LISTENERS for name in annotation_names)
        mapping = any(name in _MAPPINGS for name in annotation_names)
        request_names: List[Tuple[str, str]] = []
        for start, end in s.split_commas(paren + 1, close):
            param_annotations = self._annotations(start, end)
            label: Optional[str] = None
            alias = ""
            for ann_name, opener, closing in param_annotations:
                if ann_name in _PARAM_SOURCES:
                    label = _PARAM_SOURCES[ann_name]
                if ann_name == "Param":
                    alias = self._annotation_string(opener, closing) or ""
            # Bỏ qua phần chú thích để đọc kiểu và tên.
            idents: List[int] = []
            scan = start
            while scan < end:
                if s.is_op(scan, "@"):
                    chain, after = s.chain_at(scan + 1)
                    after = s.sig(after)
                    if s.is_op(after, "("):
                        closing = s.closing(after)
                        scan = closing + 1 if closing > 0 else after + 1
                    else:
                        scan = after
                    continue
                if s.is_op(scan, "<"):
                    skipped = s.skip_generic(scan, end)
                    if skipped > scan:
                        scan = skipped
                        continue
                if s.is_ident(scan) and s.text(scan) not in ("final", "val", "var", "vararg"):
                    idents.append(scan)
                scan += 1
            if not idents:
                continue
            if self.kotlin:
                param_name = s.text(idents[0])
                type_name = s.text(idents[1]) if len(idents) > 1 else ""
                if len(idents) > 2 and s.is_op(idents[1] + 1, "."):
                    type_name, _ = s.chain_at(idents[1])
                    type_name = type_name or ""
            else:
                param_name = s.text(idents[-1])
                type_chain, _ = s.chain_at(idents[0]) if len(idents) > 1 else ("", 0)
                type_name = (type_chain or "") if len(idents) > 1 else ""
                if type_name and any(s.is_op(i, "[") for i in range(idents[0], idents[-1])):
                    # `byte[] blob` là mảng, không phải một số.
                    type_name += "[]"
            simple_type = type_name.rsplit(".", 1)[-1]
            if listener and label is None:
                label = "payload hàng đợi tin nhắn"
            if (
                mapping
                and label is None
                and not param_annotations
                and simple_type in _SIMPLE_TYPES
                and simple_type not in _SAFE_SIMPLE
            ):
                label = "tham số request ( Spring gán ngầm theo tên )"
            if label is not None and simple_type in _SAFE_SIMPLE:
                label = None
            if simple_type in _REQUEST_TYPES:
                request_names.append((param_name, _REQUEST_TYPES[simple_type]))
            names.append(param_name)
            types.append(type_name)
            sources.append(label)
            aliases.append(alias)
        function = FunctionDef(
            path=self.path,
            name=s.text(name_index),
            owner=owner,
            params=tuple(names),
            param_types=tuple(types),
            param_sources=tuple(sources),
            body_start=body_start,
            body_end=body_end,
            line=self.tokens[name_index].line,
            return_type=return_type,
            expression_body=expression,
            param_aliases=tuple(aliases),
            abstract=abstract,
            annotations=annotation_names,
        )
        self.facts.functions.append(function)
        self.facts.classes[owner].methods.setdefault(function.name, []).append(function)
        for text, line, column in pending_sql:
            self.facts.inline_sql.append((function, text, line, column))
        for request_name, kind in request_names:
            self.facts.request_objects.append((body_start, body_end, request_name, kind))
        if not abstract:
            self._locals(function)
        return next_member

    def _locals(self, function: FunctionDef) -> None:
        s = self.s
        env: Dict[str, str] = {}
        for name, type_name in zip(function.params, function.param_types):
            if type_name:
                env[name] = type_name
        cursor = function.body_start
        while cursor < function.body_end:
            if s.is_ident(cursor, "var", "val"):
                name_index = s.sig(cursor + 1)
                equals = s.sig(name_index + 1)
                if s.is_op(equals, ":") and self.kotlin:
                    type_chain, _ = s.chain_at(s.sig(equals + 1))
                    if type_chain:
                        env[s.text(name_index)] = type_chain
                elif s.is_op(equals, "="):
                    value = s.sig(equals + 1)
                    if s.is_ident(value, "new"):
                        type_chain, _ = s.chain_at(s.sig(value + 1))
                        if type_chain:
                            env[s.text(name_index)] = type_chain
                    elif s.is_ident(value):
                        chain, after = s.chain_at(value)
                        if chain and s.is_op(s.sig(after), "("):
                            self.facts.deferred.setdefault(function.key, {})[s.text(name_index)] = chain
                cursor += 1
                continue
            if s.is_ident(cursor) and not s.is_op(s.back(cursor - 1), "."):
                chain, after = s.chain_at(cursor)
                after = s.skip_generic(s.sig(after), function.body_end)
                while s.is_op(after, "[") and s.is_op(s.sig(after + 1), "]"):
                    after = s.sig(s.sig(after + 1) + 1)
                # `Foo x` và cả tên đầy đủ `org.acme.Foo x`.
                if chain and s.is_ident(after) and chain.rsplit(".", 1)[-1][:1].isupper():
                    following = s.sig(after + 1)
                    if s.is_op(following, "=", ";", ":", ","):
                        env.setdefault(s.text(after), chain)
                        cursor = after
                        continue
            cursor += 1
        if env:
            self.facts.envs[function.key] = env

    def _field(self, owner: str, start: int, end: int) -> None:
        s = self.s
        annotations = self._annotations(start, end)
        equals = -1
        for index in range(start, end):
            if s.is_op(index, "="):
                equals = index
                break
        head_end = equals if equals >= 0 else end
        idents: List[int] = []
        scan = start
        while scan < head_end:
            if s.is_op(scan, "@"):
                chain, after = s.chain_at(scan + 1)
                after = s.sig(after)
                if s.is_op(after, "("):
                    closing = s.closing(after)
                    scan = closing + 1 if closing > 0 else after + 1
                else:
                    scan = after
                continue
            if s.is_op(scan, "<"):
                skipped = s.skip_generic(scan, head_end)
                if skipped > scan:
                    scan = skipped
                    continue
            if s.is_ident(scan) and s.text(scan) not in _MODIFIERS and s.text(scan) not in ("val", "var", "lateinit", "const"):
                idents.append(scan)
            scan += 1
        if not idents:
            return
        info = self.facts.classes[owner]
        if self.kotlin:
            name = s.text(idents[0])
            type_name = ""
            colon = s.sig(idents[0] + 1)
            if s.is_op(colon, ":"):
                type_name, _ = s.chain_at(s.sig(colon + 1))
                type_name = type_name or ""
        else:
            if len(idents) < 2:
                return
            name = s.text(idents[-1])
            type_name, _ = s.chain_at(idents[0])
            type_name = type_name or ""
        if type_name:
            info.fields[name] = type_name
        for ann_name, opener, closing in annotations:
            if ann_name == "Value":
                key = self._annotation_string(opener, closing)
                if key and key.startswith("${"):
                    inner = key[2:].rstrip("}")
                    info.config_fields[name] = inner.split(":", 1)[0]
        if equals >= 0:
            value = s.string_value(s.sig(equals + 1), end)
            if value is not None:
                info.constants[name] = value
                self.facts.constants["%s.%s" % (owner, name)] = value
            else:
                value_start = s.sig(equals + 1)
                if s.is_ident(value_start, "new"):
                    type_chain, _ = s.chain_at(s.sig(value_start + 1))
                    if type_chain and not type_name:
                        info.fields[name] = type_chain
