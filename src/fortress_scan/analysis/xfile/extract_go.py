"""Tách gói, import, hàm, phương thức, struct và hằng số của Go."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..generic.lexer import NEWLINE, Token
from .model import ClassDef, FileFacts, FunctionDef, ImportBinding
from .stream import Stream

_TYPE_STARTS = ("*", "[", "...", "<-", "(")
_REQUEST_TYPES: Dict[str, str] = {
    "http.Request": "nethttp",
    "gin.Context": "gin",
    "echo.Context": "echo",
    "fiber.Ctx": "fiber",
    "fasthttp.RequestCtx": "fasthttp",
}


def extract(path: str, language: str, tokens: List[Token]) -> FileFacts:
    return _GoExtractor(path, language, tokens).run()


def _clean_type(text: str) -> str:
    return text.lstrip("*&")


class _GoExtractor:
    def __init__(self, path: str, language: str, tokens: List[Token]) -> None:
        self.path = path
        self.facts = FileFacts(path=path, language=language)
        self.s = Stream(tokens)
        self.tokens = tokens

    def run(self) -> FileFacts:
        s = self.s
        for index in range(s.size):
            if s.parent[index] >= 0 or not s.is_ident(index):
                continue
            # Chỉ từ khóa đứng đầu dòng ở cấp gói mới mở khai báo.
            text = s.text(index)
            previous = index - 1
            if previous >= 0 and self.tokens[previous].kind != NEWLINE and not s.is_op(previous, ";", "}"):
                continue
            if text == "package":
                if s.is_ident(s.sig(index + 1)):
                    self.facts.package = s.text(s.sig(index + 1))
            elif text == "import":
                self._import(index)
            elif text == "func":
                self._func(index)
            elif text == "type":
                self._type(index)
            elif text in ("const", "var"):
                self._constants(index)
        return self.facts

    def _type_at(self, index: int, limit: int) -> Tuple[str, int]:
        """Đọc một kiểu bắt đầu tại `index`: trả về (tên kiểu gọn, vị trí sau)."""
        s = self.s
        cursor = s.sig(index)
        while cursor < limit and (s.is_op(cursor, "*", "&") or (s.is_op(cursor, "[") and s.is_op(cursor + 1, "]"))):
            cursor = cursor + (2 if s.is_op(cursor, "[") else 1)
        if s.is_op(cursor, "..."):
            cursor += 1
        chain, after = s.chain_at(cursor)
        if not chain:
            return "", cursor + 1
        after = s.skip_generic(after, limit)
        if s.is_op(after, "[") :
            closing = s.closing(after)
            if closing > 0:
                after = closing + 1
        return chain, after

    def _import(self, index: int) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        if s.is_op(cursor, "("):
            close = s.closing(cursor)
            if close < 0:
                return
            scan = cursor + 1
            while scan < close:
                scan = self._import_spec(scan, close)
            return
        self._import_spec(cursor, s.size)

    def _import_spec(self, cursor: int, limit: int) -> int:
        s = self.s
        cursor = s.sig(cursor)
        alias = ""
        if s.is_ident(cursor) or s.is_op(cursor, "."):
            alias = s.text(cursor)
            cursor = s.sig(cursor + 1)
        if not s.is_string(cursor):
            return cursor + 1
        path = s.text(cursor)
        local = alias or path.rstrip("/").rsplit("/", 1)[-1]
        # Gói kiểu `gopkg.in/yaml.v3` hay `.../v2` dùng tên khai báo trong gói,
        # không phải đoạn cuối đường dẫn; đoán theo quy ước phổ biến.
        if local.startswith("v") and local[1:].isdigit() and "/" in path:
            local = path.rstrip("/").rsplit("/", 2)[-2]
        if "." in local and not alias:
            local = local.split(".", 1)[0]
        if local == "-" or local == "_":
            return cursor + 1
        if local == ".":
            self.facts.wildcard_imports.append(path)
        else:
            self.facts.imports[local] = ImportBinding(path, "*")
        return cursor + 1

    def _params(self, opener: int, closer: int) -> Tuple[List[str], List[str], bool]:
        s = self.s
        pieces = s.split_commas(opener + 1, closer)
        names: List[str] = []
        types: List[str] = []
        named = False
        parsed: List[Tuple[str, str]] = []
        for start, end in pieces:
            first = s.sig(start)
            if s.is_ident(first):
                following = s.sig(first + 1)
                if following < end and (s.is_ident(following) or s.is_op(following, *_TYPE_STARTS)):
                    if not s.is_op(following, "."):
                        type_name, _ = self._type_at(following, end)
                        parsed.append((s.text(first), type_name))
                        named = True
                        continue
            type_name, _ = self._type_at(first, end)
            parsed.append(("", type_name))
        variadic = any(s.is_op(i, "...") for i in range(opener, closer))
        if named:
            # `a, b string`: tên đứng một mình nhận kiểu của nhóm sau nó.
            pending: List[int] = []
            for name, type_name in parsed:
                if not name:
                    names.append(type_name)
                    types.append("")
                    pending.append(len(names) - 1)
                    continue
                names.append(name)
                types.append(type_name)
                for position in pending:
                    types[position] = type_name
                pending = []
        else:
            for _, type_name in parsed:
                names.append("")
                types.append(type_name)
        return names, types, variadic

    def _func(self, index: int) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        owner = ""
        receiver_name = ""
        if s.is_op(cursor, "("):
            close = s.closing(cursor)
            if close < 0:
                return
            names, types, _ = self._params(cursor, close)
            if types:
                owner = _clean_type(types[0]).split(".")[-1]
            if names:
                receiver_name = names[0]
            cursor = s.sig(close + 1)
        if not s.is_ident(cursor):
            return
        name_index = cursor
        cursor = s.sig(cursor + 1)
        if s.is_op(cursor, "["):
            closing = s.closing(cursor)
            cursor = s.sig(closing + 1) if closing > 0 else cursor
        if not s.is_op(cursor, "("):
            return
        close = s.closing(cursor)
        if close < 0:
            return
        names, types, variadic = self._params(cursor, close)
        result_start = s.sig(close + 1)
        return_type = ""
        body = result_start
        if s.is_op(result_start, "("):
            result_close = s.closing(result_start)
            _, result_types, _ = self._params(result_start, result_close)
            return_type = result_types[0] if result_types else ""
            body = s.sig(result_close + 1)
        elif not s.is_op(result_start, "{"):
            return_type, after = self._type_at(result_start, s.size)
            body = s.sig(after)
            if s.is_op(body, "{") and s.closing(body) > 0 and return_type in ("struct", "interface"):
                body = s.sig(s.closing(body) + 1)
        if not s.is_op(body, "{"):
            return
        body_close = s.closing(body)
        if body_close < 0:
            return
        params = tuple(names)
        function = FunctionDef(
            path=self.path,
            name=s.text(name_index),
            owner=owner,
            params=params,
            param_types=tuple(types),
            param_sources=tuple(None for _ in params),
            body_start=body + 1,
            body_end=body_close,
            line=self.tokens[name_index].line,
            return_type=_clean_type(return_type),
            variadic=variadic,
            receiver=receiver_name if owner else "",
        )
        self.facts.functions.append(function)
        if owner:
            info = self.facts.classes.setdefault(
                owner, ClassDef(path=self.path, name=owner, qualified=owner)
            )
            info.methods.setdefault(function.name, []).append(function)
        env: Dict[str, str] = {}
        if receiver_name and owner:
            env[receiver_name] = owner
        for name, type_name in zip(names, types):
            if name and type_name:
                env[name] = _clean_type(type_name)
                kind = _REQUEST_TYPES.get(_clean_type(type_name))
                if kind is not None:
                    self.facts.request_objects.append((body + 1, body_close, name, kind))
        self._locals(function, env)

    def _locals(self, function: FunctionDef, env: Dict[str, str]) -> None:
        s = self.s
        deferred: Dict[str, str] = {}
        cursor = function.body_start
        while cursor < function.body_end:
            if s.is_op(cursor, ":=") or (s.is_op(cursor, "=") and s.is_ident(s.back(cursor - 1))):
                target = s.back(cursor - 1)
                # `a, err := f()` -- lấy tên đầu tiên.
                names_start = target
                while s.is_op(s.back(names_start - 1), ",") and s.is_ident(s.back(s.back(names_start - 1) - 1)):
                    names_start = s.back(s.back(names_start - 1) - 1)
                if not s.is_ident(names_start):
                    cursor += 1
                    continue
                name = s.text(names_start)
                value = s.sig(cursor + 1)
                if s.is_op(value, "&"):
                    value = s.sig(value + 1)
                chain, after = s.chain_at(value)
                if chain:
                    following = s.sig(after)
                    if s.is_op(following, "{"):
                        env[name] = chain
                    elif s.is_op(following, "("):
                        deferred[name] = chain
            elif s.is_ident(cursor, "var"):
                name_index = s.sig(cursor + 1)
                if s.is_ident(name_index):
                    type_name, _ = self._type_at(s.sig(name_index + 1), function.body_end)
                    if type_name and not s.is_op(s.sig(name_index + 1), "="):
                        env[s.text(name_index)] = _clean_type(type_name)
            cursor += 1
        if env:
            self.facts.envs[function.key] = env
        if deferred:
            self.facts.deferred[function.key] = deferred

    def _type(self, index: int) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        if s.is_op(cursor, "("):
            return
        if not s.is_ident(cursor):
            return
        name = s.text(cursor)
        kind_index = s.sig(cursor + 1)
        if s.is_op(kind_index, "["):
            closing = s.closing(kind_index)
            kind_index = s.sig(closing + 1) if closing > 0 else kind_index
        info = self.facts.classes.setdefault(name, ClassDef(path=self.path, name=name, qualified=name))
        if s.is_ident(kind_index, "struct"):
            opener = s.sig(kind_index + 1)
            close = s.closing(opener)
            if close < 0:
                return
            line_start = opener + 1
            for position in range(opener + 1, close + 1):
                if position == close or self.tokens[position].kind == NEWLINE or s.is_op(position, ";"):
                    self._struct_field(info, line_start, position)
                    line_start = position + 1
        elif s.is_ident(kind_index, "interface"):
            info.is_interface = True
            opener = s.sig(kind_index + 1)
            close = s.closing(opener)
            position = opener + 1
            while 0 < close and position < close:
                if s.is_ident(position) and s.is_op(position + 1, "("):
                    paren = position + 1
                    paren_close = s.closing(paren)
                    if paren_close < 0:
                        break
                    names, types, variadic = self._params(paren, paren_close)
                    function = FunctionDef(
                        path=self.path,
                        name=s.text(position),
                        owner=name,
                        params=tuple(names),
                        param_types=tuple(types),
                        param_sources=tuple(None for _ in names),
                        body_start=paren_close,
                        body_end=paren_close,
                        line=self.tokens[position].line,
                        abstract=True,
                        variadic=variadic,
                    )
                    self.facts.functions.append(function)
                    info.methods.setdefault(function.name, []).append(function)
                    position = paren_close + 1
                    continue
                position += 1
        else:
            type_name, _ = self._type_at(kind_index, s.size)
            if type_name:
                info.bases = (type_name,)

    def _struct_field(self, info: ClassDef, start: int, end: int) -> None:
        s = self.s
        first = s.sig(start)
        if first >= end or not s.is_ident(first):
            if s.is_op(first, "*"):
                type_name, _ = self._type_at(first, end)
                if type_name:
                    info.bases = info.bases + (_clean_type(type_name),)
            return
        names = [first]
        cursor = s.sig(first + 1)
        while s.is_op(cursor, ",") and s.is_ident(s.sig(cursor + 1)):
            names.append(s.sig(cursor + 1))
            cursor = s.sig(s.sig(cursor + 1) + 1)
        if cursor >= end or s.is_op(cursor, "."):
            # Trường nhúng `sync.Mutex` / `Base`.
            type_name, _ = self._type_at(first, end)
            if type_name:
                info.bases = info.bases + (_clean_type(type_name),)
            return
        type_name, _ = self._type_at(cursor, end)
        if not type_name:
            return
        for name_index in names:
            info.fields[s.text(name_index)] = _clean_type(type_name)

    def _constants(self, index: int) -> None:
        s = self.s
        cursor = s.sig(index + 1)
        if s.is_op(cursor, "("):
            close = s.closing(cursor)
            if close < 0:
                return
            line_start = cursor + 1
            for position in range(cursor + 1, close + 1):
                if position == close or self.tokens[position].kind == NEWLINE:
                    self._constant_line(line_start, position)
                    line_start = position + 1
            return
        end = cursor
        while end < s.size and self.tokens[end].kind != NEWLINE:
            end += 1
        while end < s.size and self.tokens[end].kind == NEWLINE and s.is_op(s.back(end - 1), "+"):
            end += 1
            while end < s.size and self.tokens[end].kind != NEWLINE:
                end += 1
        self._constant_line(cursor, end)

    def _constant_line(self, start: int, end: int) -> None:
        s = self.s
        first = s.sig(start)
        if not s.is_ident(first):
            return
        equals: Optional[int] = None
        for position in range(first, end):
            if s.is_op(position, "="):
                equals = position
                break
        if equals is None:
            return
        value = s.string_value(s.sig(equals + 1), end)
        if value is not None:
            self.facts.constants[s.text(first)] = value
