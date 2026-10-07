"""Bộ đọc cấu trúc cho C, C++ và Objective-C.

Không phải trình biên dịch, và cố ý không đòi đúng như trình biên dịch: nó
đọc được mã có macro lạ, header thiếu, phần mở rộng của từng hãng, vì mã thật
trong một repo lớn luôn có những thứ đó. Thứ nó dựng ra đủ cho các luật bộ nhớ:

* bảng hằng số ( ``#define N 64``, ``enum``, ``const int`` ) để biết một mảng
  dài bao nhiêu byte;
* ranh giới từng hàm, tên và danh sách tham số;
* cây câu lệnh có ``if/else``, vòng lặp, ``switch``, ``goto`` và các lệnh
  thoát, để phép phân tích luồng biết một ``free()`` có chảy tới dòng dưới
  hay không.

Chỗ nó không nhìn thấy được nói thẳng: macro dạng hàm không được mở, nên
``FREE(p)`` của từng dự án không được hiểu là giải phóng; con trỏ hàm và
gọi ảo không được lần theo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget
from ..generic.lexer import IDENT, NEWLINE, NUMBER, OP, STRING, LexerProfile, Token, tokenize

C_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'", '"'),
    interpolating_quotes=(),
    interpolation_markers=(),
    identifier_extra="_",
    multichar_operators=(
        "<<=",
        ">>=",
        "...",
        "->",
        "++",
        "--",
        "<<",
        ">>",
        "<=",
        ">=",
        "==",
        "!=",
        "&&",
        "||",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "&=",
        "|=",
        "^=",
        "::",
    ),
)

# Objective-C viết chuỗi NSString là @"...". Cùng bộ đọc, chỉ thêm @ vào phần
# định danh để `@"x"` không tách ra thành một toán tử lạc.
OBJC_LEXER = C_LEXER

CONTROL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "sizeof",
        "else",
        "do",
        "case",
        "alignof",
        "_Alignof",
        "decltype",
        "typeof",
        "__typeof__",
        "defined",
        "_Static_assert",
        "static_assert",
    }
)

_ATTRIBUTE_WORDS = frozenset(
    {"__attribute__", "__attribute", "__declspec", "alignas", "_Alignas", "__asm__", "asm"}
)

# Lời gọi không bao giờ trở về: sau chúng, luồng dừng hẳn như sau `return`.
NORETURN_CALLS = frozenset(
    {
        "exit",
        "_exit",
        "_Exit",
        "abort",
        "quick_exit",
        "longjmp",
        "siglongjmp",
        "err",
        "errx",
        "verr",
        "verrx",
        "panic",
        "BUG",
        "__builtin_unreachable",
        "pthread_exit",
        "ExitProcess",
        "fatal",
        "die",
    }
)

_MAX_DEFINE_DEPTH = 16
_MAX_TREE_DEPTH = 200


@dataclass
class Stmt:
    kind: str
    tokens: List[Token] = field(default_factory=list)
    body: List["Stmt"] = field(default_factory=list)
    alternate: List["Stmt"] = field(default_factory=list)
    init: List[Token] = field(default_factory=list)
    step: List[Token] = field(default_factory=list)
    label: str = ""
    line: int = 0


@dataclass
class Function:
    name: str
    line: int
    params: List[List[Token]]
    param_names: List[str]
    variadic: bool
    body_tokens: List[Token]
    body: List[Stmt]


@dataclass
class TranslationUnit:
    tokens: List[Token]
    constants: Dict[str, int]
    functions: List[Function]
    globals_tokens: List[Token]


_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\(?)(.*)$")
_PREPROCESSOR = re.compile(r"^[ \t]*#")


_CONDITIONAL = re.compile(r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif|elifdef|elifndef)\b(.*)$")


def strip_preprocessor(source: str) -> Tuple[str, Dict[str, str]]:
    """Thay mọi dòng chỉ thị tiền xử lý bằng khoảng trắng, giữ nguyên số dòng.

    Với `#if/#else`, chỉ GIỮ MỘT nhánh ( nhánh đầu, hoặc nhánh `#else` khi
    nhánh đầu là `#if 0` ). Giữ cả hai thì kiểu viết rất phổ biến này để lại
    hai dấu `{` cho một dấu `}`, và mọi hàm phía sau dính vào nhau:

        #ifdef HAVE_X
            if (x_call(a) < 0) {
        #else
            if (call(a) < 0) {
        #endif

    Trả về kèm bảng macro dạng đối tượng ( không phải dạng hàm ) để tính hằng.
    Dòng nối tiếp bằng `\\` cũng thuộc chỉ thị và được xoá cùng.
    """
    lines = source.split("\n")
    output: List[str] = []
    macros: Dict[str, str] = {}
    continuing = False
    pending_name: Optional[str] = None
    pending_body: List[str] = []
    # Mỗi mức: (đang giữ nhánh này?, đã giữ một nhánh nào chưa?)
    stack: List[Tuple[bool, bool]] = []
    for line in lines:
        active = all(keep for keep, _ in stack)
        if not continuing:
            conditional = _CONDITIONAL.match(line)
            if conditional is not None:
                word, rest = conditional.group(1), conditional.group(2).strip()
                if word in ("if", "ifdef", "ifndef"):
                    keep = not (word == "if" and rest.split("//")[0].strip() in ("0", "(0)"))
                    stack.append((keep, keep))
                elif word in ("elif", "elifdef", "elifndef", "else") and stack:
                    _, taken = stack[-1]
                    keep = not taken
                    stack[-1] = (keep, taken or keep)
                elif word == "endif" and stack:
                    stack.pop()
                output.append(" " * len(line))
                continuing = line.rstrip().endswith("\\")
                continue
        if not active:
            output.append(" " * len(line))
            continuing = line.rstrip().endswith("\\") and continuing
            continue
        if continuing or _PREPROCESSOR.match(line):
            body = line
            if not continuing:
                match = _DEFINE.match(line)
                if match and not match.group(2):
                    pending_name = match.group(1)
                    pending_body = [match.group(3)]
                else:
                    pending_name = None
                    pending_body = []
            elif pending_name is not None:
                pending_body.append(body)
            continuing = line.rstrip().endswith("\\")
            if not continuing and pending_name is not None:
                text = " ".join(part.rstrip("\\") for part in pending_body)
                text = re.sub(r"/\*.*?\*/", " ", text)
                text = text.split("//", 1)[0].strip()
                if pending_name not in macros:
                    macros[pending_name] = text
                pending_name = None
            output.append(" " * len(line))
            continue
        output.append(line)
    return "\n".join(output), macros


def significant(tokens: Sequence[Token]) -> List[Token]:
    return [token for token in tokens if token.kind != NEWLINE]


_INTEGER = re.compile(r"^(0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)([uUlLzZ]*)$")

TYPE_SIZES: Dict[str, int] = {
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "uint8_t": 1,
    "int8_t": 1,
    "u8": 1,
    "s8": 1,
    "u_char": 1,
    "uchar": 1,
    "BYTE": 1,
    "UCHAR": 1,
    "CHAR": 1,
    "gchar": 1,
    "guchar": 1,
    "guint8": 1,
    "gint8": 1,
    "char8_t": 1,
    "std::byte": 1,
    "byte": 1,
    "bool": 1,
    "_Bool": 1,
    "short": 2,
    "unsigned short": 2,
    "int16_t": 2,
    "uint16_t": 2,
    "u16": 2,
    "WORD": 2,
    "char16_t": 2,
    "int": 4,
    "unsigned": 4,
    "unsigned int": 4,
    "int32_t": 4,
    "uint32_t": 4,
    "u32": 4,
    "DWORD": 4,
    "float": 4,
    "char32_t": 4,
    "long long": 8,
    "unsigned long long": 8,
    "int64_t": 8,
    "uint64_t": 8,
    "u64": 8,
    "double": 8,
    "QWORD": 8,
}

CHAR_TYPES = frozenset(
    {
        "char",
        "uint8_t",
        "int8_t",
        "u8",
        "s8",
        "u_char",
        "uchar",
        "BYTE",
        "UCHAR",
        "CHAR",
        "gchar",
        "guchar",
        "guint8",
        "gint8",
        "char8_t",
        "TCHAR",
    }
)


def parse_int(text: str) -> Optional[int]:
    match = _INTEGER.match(text)
    if not match:
        return None
    digits = match.group(1)
    try:
        if digits.lower().startswith("0x"):
            return int(digits, 16)
        if digits.lower().startswith("0b"):
            return int(digits[2:], 2)
        if len(digits) > 1 and digits.startswith("0"):
            return int(digits, 8)
        return int(digits)
    except ValueError:
        return None


class ConstantEvaluator:
    """Tính giá trị hằng nguyên của một biểu thức token, hoặc None.

    Chỉ hỗ trợ những gì kích thước mảng thật hay dùng: số, macro, enum, hằng
    const, sizeof của kiểu cơ bản hoặc của mảng đã biết, và + - * / % << >>.
    Bất cứ thứ gì lạ hơn đều trả None, nghĩa là "không biết" -- và các luật
    phía sau coi "không biết" là không báo, không phải là báo.
    """

    def __init__(
        self,
        constants: Dict[str, int],
        macros: Dict[str, str],
        budget: Budget,
        array_bytes: Optional[Dict[str, int]] = None,
    ) -> None:
        self.constants = constants
        self.macros = macros
        self.budget = budget
        self.array_bytes = array_bytes if array_bytes is not None else {}
        self._macro_cache: Dict[str, Optional[int]] = {}
        self._expanding: Set[str] = set()

    def value_of_name(self, name: str) -> Optional[int]:
        if name in self.constants:
            return self.constants[name]
        if name in self._macro_cache:
            return self._macro_cache[name]
        text = self.macros.get(name)
        if text is None or name in self._expanding or len(self._expanding) > _MAX_DEFINE_DEPTH:
            return None
        self._expanding.add(name)
        try:
            tokens = significant(tokenize(text, C_LEXER, self.budget))
            value = self.evaluate(tokens)
        finally:
            self._expanding.discard(name)
        self._macro_cache[name] = value
        return value

    def evaluate(self, tokens: Sequence[Token]) -> Optional[int]:
        if not tokens or len(tokens) > 64:
            return None
        parser = _ExprParser(list(tokens), self)
        try:
            value = parser.expression()
        except _NotConstant:
            return None
        if parser.position != len(parser.tokens):
            return None
        return value

    def sizeof(self, tokens: Sequence[Token]) -> Optional[int]:
        words = [token.text for token in tokens if token.kind == IDENT]
        if not tokens:
            return None
        if len(tokens) == 1 and tokens[0].kind == IDENT:
            name = tokens[0].text
            if name in self.array_bytes:
                return self.array_bytes[name]
        if any(token.kind == OP and token.text == "*" for token in tokens):
            return 8
        joined = " ".join(word for word in words if word not in ("const", "volatile", "struct"))
        joined = joined.replace("std ", "std::")
        if joined in TYPE_SIZES:
            return TYPE_SIZES[joined]
        if joined in ("long", "unsigned long", "size_t", "ssize_t", "uintptr_t", "intptr_t", "ptrdiff_t", "off_t"):
            return 8
        return None


class _NotConstant(Exception):
    pass


class _ExprParser:
    def __init__(self, tokens: List[Token], evaluator: ConstantEvaluator) -> None:
        self.tokens = tokens
        self.position = 0
        self.evaluator = evaluator

    def peek(self) -> Optional[Token]:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> Token:
        token = self.peek()
        if token is None:
            raise _NotConstant()
        self.position += 1
        return token

    def expression(self) -> int:
        value = self.additive()
        while True:
            token = self.peek()
            if token is not None and token.kind == OP and token.text in ("<<", ">>"):
                self.position += 1
                right = self.additive()
                if right < 0 or right > 63:
                    raise _NotConstant()
                value = value << right if token.text == "<<" else value >> right
                continue
            return value

    def additive(self) -> int:
        value = self.term()
        while True:
            token = self.peek()
            if token is not None and token.kind == OP and token.text in ("+", "-"):
                self.position += 1
                right = self.term()
                value = value + right if token.text == "+" else value - right
                continue
            return value

    def term(self) -> int:
        value = self.unary()
        while True:
            token = self.peek()
            if token is not None and token.kind == OP and token.text in ("*", "/", "%"):
                self.position += 1
                right = self.unary()
                if token.text == "*":
                    value *= right
                else:
                    if right == 0:
                        raise _NotConstant()
                    value = value // right if token.text == "/" else value % right
                if abs(value) > 1 << 40:
                    raise _NotConstant()
                continue
            return value

    def unary(self) -> int:
        self.evaluator.budget.spend()
        token = self.take()
        if token.kind == OP and token.text == "-":
            return -self.unary()
        if token.kind == OP and token.text == "+":
            return self.unary()
        if token.kind == OP and token.text == "(":
            start = self.position
            close = _matching(self.tokens, start - 1)
            if close is None:
                raise _NotConstant()
            inner = self.tokens[start:close]
            if _looks_like_type(inner) and close + 1 < len(self.tokens):
                # Phép ép kiểu `(size_t)64` không đổi giá trị nguyên.
                self.position = close + 1
                return self.unary()
            value = ConstantEvaluator.evaluate(self.evaluator, inner)
            if value is None:
                raise _NotConstant()
            self.position = close + 1
            return value
        if token.kind == NUMBER:
            value = parse_int(token.text)
            if value is None:
                raise _NotConstant()
            return value
        if token.kind == STRING and token.quote == "'" and len(token.text) == 1:
            return ord(token.text)
        if token.kind == IDENT and token.text == "sizeof":
            following = self.peek()
            if following is not None and following.kind == OP and following.text == "(":
                close = _matching(self.tokens, self.position)
                if close is None:
                    raise _NotConstant()
                inner = self.tokens[self.position + 1 : close]
                self.position = close + 1
            else:
                operand = self.take()
                inner = [operand]
            value = self.evaluator.sizeof(inner)
            if value is None:
                raise _NotConstant()
            return value
        if token.kind == IDENT:
            value = self.evaluator.value_of_name(token.text)
            if value is None:
                raise _NotConstant()
            return value
        raise _NotConstant()


def _looks_like_type(tokens: Sequence[Token]) -> bool:
    if not tokens:
        return False
    words = [token for token in tokens if token.kind == IDENT]
    if len(words) != len([t for t in tokens if not (t.kind == OP and t.text == "*")]):
        return False
    names = {token.text for token in words}
    if names & {"size_t", "int", "unsigned", "long", "short", "char", "uint32_t", "uint64_t", "int32_t", "int64_t", "ssize_t", "uint16_t", "uint8_t", "signed"}:
        return True
    return False


def _matching(tokens: Sequence[Token], opening: int) -> Optional[int]:
    """Chỉ số của dấu đóng khớp với dấu mở tại `opening`."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    open_text = tokens[opening].text
    close_text = pairs.get(open_text)
    if close_text is None:
        return None
    depth = 0
    for index in range(opening, len(tokens)):
        token = tokens[index]
        if token.kind != OP:
            continue
        if token.text == open_text:
            depth += 1
        elif token.text == close_text:
            depth -= 1
            if depth == 0:
                return index
    return None


def matching(tokens: Sequence[Token], opening: int) -> Optional[int]:
    return _matching(tokens, opening)


def split_arguments(tokens: Sequence[Token], opening: int) -> Tuple[List[List[Token]], int]:
    """Các đối số của lời gọi có dấu mở ngoặc tại `opening`, và vị trí sau ngoặc đóng."""
    close = _matching(tokens, opening)
    if close is None:
        return [], len(tokens)
    arguments: List[List[Token]] = []
    current: List[Token] = []
    depth = 0
    for index in range(opening + 1, close):
        token = tokens[index]
        if token.kind == OP:
            if token.text in "([{":
                depth += 1
            elif token.text in ")]}":
                depth -= 1
            elif token.text == "," and depth == 0:
                arguments.append(current)
                current = []
                continue
        current.append(token)
    if current or arguments:
        arguments.append(current)
    return arguments, close + 1


# --------------------------------------------------------------------- hằng số


def collect_constants(
    tokens: Sequence[Token], macros: Dict[str, str], budget: Budget
) -> Dict[str, int]:
    """Hằng số nguyên khai báo bằng `enum` hoặc `const`/`constexpr`."""
    constants: Dict[str, int] = {}
    evaluator = ConstantEvaluator(constants, macros, budget)
    limit = len(tokens)
    index = 0
    while index < limit:
        budget.spend()
        token = tokens[index]
        if token.kind == IDENT and token.text == "enum":
            cursor = index + 1
            while cursor < limit and not (tokens[cursor].kind == OP and tokens[cursor].text in "{;"):
                cursor += 1
            if cursor < limit and tokens[cursor].text == "{":
                close = _matching(tokens, cursor)
                if close is not None:
                    _collect_enum(tokens[cursor + 1 : close], evaluator, constants)
                    index = close
        elif token.kind == IDENT and token.text in ("const", "constexpr"):
            _collect_const(tokens, index, evaluator, constants)
        index += 1
    return constants


def _collect_enum(
    body: Sequence[Token], evaluator: ConstantEvaluator, constants: Dict[str, int]
) -> None:
    next_value = 0
    entries: List[List[Token]] = [[]]
    depth = 0
    for token in body:
        if token.kind == OP and token.text in "([{":
            depth += 1
        elif token.kind == OP and token.text in ")]}":
            depth -= 1
        if token.kind == OP and token.text == "," and depth == 0:
            entries.append([])
            continue
        entries[-1].append(token)
    for entry in entries:
        if not entry or entry[0].kind != IDENT:
            continue
        name = entry[0].text
        if len(entry) > 2 and entry[1].kind == OP and entry[1].text == "=":
            value = evaluator.evaluate(entry[2:])
            if value is None:
                next_value = None  # type: ignore[assignment]
                continue
            next_value = value
        if next_value is None:
            continue
        constants.setdefault(name, next_value)
        next_value += 1


def _collect_const(
    tokens: Sequence[Token], index: int, evaluator: ConstantEvaluator, constants: Dict[str, int]
) -> None:
    cursor = index + 1
    limit = min(len(tokens), index + 8)
    name: Optional[str] = None
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == OP and token.text == "=":
            break
        if token.kind == OP and token.text not in ("::",):
            return
        if token.kind == IDENT:
            name = token.text
        cursor += 1
    if name is None or cursor >= limit:
        return
    end = cursor + 1
    while end < len(tokens) and not (tokens[end].kind == OP and tokens[end].text in (";", ",")):
        end += 1
        if end - cursor > 24:
            return
    value = evaluator.evaluate(tokens[cursor + 1 : end])
    if value is not None:
        constants.setdefault(name, value)


# ------------------------------------------------------------------- hàm và cây


def find_functions(tokens: Sequence[Token], budget: Budget) -> Tuple[List[Function], List[Token]]:
    """Tách thân hàm ra khỏi phần khai báo toàn cục.

    Một khối `{` ở ngoài mọi hàm là thân hàm khi phần đầu của nó có một nhóm
    tham số đứng sau một cái tên; còn lại ( struct, namespace, extern "C",
    khởi tạo mảng ) là vỏ chứa, và ta đi vào trong để tìm tiếp.
    """
    functions: List[Function] = []
    globals_tokens: List[Token] = []
    limit = len(tokens)
    header_start = 0
    index = 0
    while index < limit:
        budget.spend()
        token = tokens[index]
        if token.kind == OP and token.text in (";", "}"):
            globals_tokens.extend(tokens[header_start : index + 1])
            header_start = index + 1
            index += 1
            continue
        if token.kind == OP and token.text == "{":
            header = list(tokens[header_start:index])
            close = _matching(tokens, index)
            if close is None:
                close = limit - 1
            method = _objc_method(header)
            if method is not None:
                name, name_line, params = method
                body_tokens = list(tokens[index + 1 : close])
                functions.append(
                    Function(
                        name=name,
                        line=name_line,
                        params=params,
                        param_names=[param[-1].text for param in params],
                        variadic=False,
                        body_tokens=body_tokens,
                        body=parse_block(body_tokens, budget),
                    )
                )
                index = close + 1
                header_start = index
                continue
            signature = _function_signature(header)
            if signature is not None and not _is_initializer(header):
                name, name_index, params_open, params_close = signature
                params, _ = split_arguments(header, params_open)
                body_tokens = list(tokens[index + 1 : close])
                param_names = [_param_name(param) for param in params]
                variadic = any(
                    len(param) == 1 and param[0].text == "..." for param in params
                )
                body = parse_block(body_tokens, budget)
                functions.append(
                    Function(
                        name=name,
                        line=header[name_index].line,
                        params=params,
                        param_names=[p for p in param_names if p],
                        variadic=variadic,
                        body_tokens=body_tokens,
                        body=body,
                    )
                )
                index = close + 1
                header_start = index
                continue
            if _is_initializer(header):
                # `int bang[] = { 1, 2 };` -- phần khởi tạo, không phải vỏ chứa.
                index = close + 1
                continue
            # Vỏ chứa: struct, namespace, extern "C". Ghi phần đầu rồi đi vào.
            globals_tokens.extend(header)
            globals_tokens.append(token)
            header_start = index + 1
            index += 1
            continue
        index += 1
    globals_tokens.extend(tokens[header_start:])
    return functions, globals_tokens


def _objc_method(header: Sequence[Token]) -> Optional[Tuple[str, int, List[List[Token]]]]:
    """`- (void)greet:(const char *)who with:(int)n` -> ("greet", dòng, [[const char * who], [int n]])."""
    start = None
    depth = 0
    for position, token in enumerate(header):
        if token.kind != OP:
            continue
        if token.text in "([":
            depth += 1
        elif token.text in ")]":
            depth -= 1
        elif depth == 0 and token.text in ("-", "+") and position + 1 < len(header) and header[position + 1].text == "(":
            if position > 0 and header[position - 1].text == "operator":
                return None
            start = position
    if start is None:
        return None
    close = _matching(header, start + 1)
    if close is None or close + 1 >= len(header) or header[close + 1].kind != IDENT:
        return None
    name_token = header[close + 1]
    params: List[List[Token]] = []
    cursor = close + 2
    while cursor < len(header):
        token = header[cursor]
        if token.kind == OP and token.text == ":" and cursor + 1 < len(header) and header[cursor + 1].text == "(":
            type_close = _matching(header, cursor + 1)
            if type_close is None or type_close + 1 >= len(header) or header[type_close + 1].kind != IDENT:
                return None
            params.append(list(header[cursor + 2 : type_close]) + [header[type_close + 1]])
            cursor = type_close + 2
            continue
        cursor += 1
    return name_token.text, name_token.line, params


def _is_initializer(header: Sequence[Token]) -> bool:
    depth = 0
    for token in header:
        if token.kind != OP:
            continue
        if token.text in "([":
            depth += 1
        elif token.text in ")]":
            depth -= 1
        elif token.text == "=" and depth == 0:
            return True
    return False


_STATEMENT_WORDS = frozenset({"if", "for", "while", "switch", "catch", "do", "else", "return"})
_SIGNATURE_SKIP = _ATTRIBUTE_WORDS | frozenset(
    {"throw", "noexcept", "decltype", "typeof", "__typeof__", "sizeof", "alignof", "requires"}
)


def _function_signature(header: Sequence[Token]) -> Optional[Tuple[str, int, int, int]]:
    """Tên hàm và nhóm tham số trong phần đầu của một khối `{`.

    Lấy nhóm ngoặc CUỐI CÙNG đứng sau một cái tên, vì trước nó có thể là một
    macro dạng hàm của dự án ( `DECLARE_X(y) int f(void) {` ), còn sau nó chỉ
    có thuộc tính và `noexcept`. Danh sách khởi tạo của constructor
    ( `) : a(x), b(y) {` ) bị cắt bỏ trước khi chọn.
    """
    if not header:
        return None
    first_words = {token.text for token in header[:3] if token.kind == IDENT}
    if first_words & {"struct", "class", "union", "enum", "namespace"}:
        if not any(token.kind == OP and token.text == "(" for token in header):
            return None
    depth = 0
    candidates: List[Tuple[str, int, int, int]] = []
    for index, token in enumerate(header):
        if token.kind != OP:
            continue
        if token.text == ":" and depth == 0 and candidates:
            break
        if token.text == "(" and depth == 0:
            previous = header[index - 1] if index else None
            if previous is not None and previous.kind == IDENT:
                if previous.text in _STATEMENT_WORDS:
                    return None
                if previous.text not in _SIGNATURE_SKIP:
                    close = _matching(header, index)
                    if close is None:
                        return None
                    candidates.append((previous.text, index - 1, index, close))
        if token.text in "([":
            depth += 1
        elif token.text in ")]":
            depth -= 1
    return candidates[-1] if candidates else None


def _param_name(param: Sequence[Token]) -> Optional[str]:
    names = [token for token in param if token.kind == IDENT]
    if not names:
        return None
    # `char *buf[]`, `int (*cb)(int)` -- tên là định danh cuối cùng trước `[`
    # hoặc `)`, không phải định danh cuối cùng của cả cụm.
    depth = 0
    candidate: Optional[str] = None
    for token in param:
        if token.kind == OP and token.text in "[":
            break
        if token.kind == OP and token.text == "=":
            break
        if token.kind == IDENT and depth == 0:
            candidate = token.text
        if token.kind == OP and token.text == "(":
            depth += 1
        elif token.kind == OP and token.text == ")":
            depth -= 1
    if candidate in ("void", "const", "int", "char"):
        return None
    return candidate


def parse_block(tokens: Sequence[Token], budget: Budget, depth: int = 0) -> List[Stmt]:
    statements: List[Stmt] = []
    index = 0
    limit = len(tokens)
    while index < limit:
        budget.spend()
        statement, index = _parse_statement(tokens, index, budget, depth)
        if statement is not None:
            statements.append(statement)
    return statements


def _parse_statement(
    tokens: Sequence[Token], index: int, budget: Budget, depth: int
) -> Tuple[Optional[Stmt], int]:
    limit = len(tokens)
    if index >= limit:
        return None, limit
    if depth > _MAX_TREE_DEPTH:
        return Stmt("simple", list(tokens[index:]), line=tokens[index].line), limit
    token = tokens[index]
    text = token.text
    if token.kind == OP and text == ";":
        return None, index + 1
    if token.kind == OP and text == "{":
        close = _matching(tokens, index)
        if close is None:
            close = limit
        body = parse_block(tokens[index + 1 : close], budget, depth + 1)
        return Stmt("block", body=body, line=token.line), close + 1
    if token.kind == IDENT:
        if text == "if":
            return _parse_if(tokens, index, budget, depth)
        if text in ("while", "for"):
            return _parse_loop(tokens, index, budget, depth)
        if text == "do":
            body_stmt, after = _parse_statement(tokens, index + 1, budget, depth + 1)
            cond: List[Token] = []
            if after < limit and tokens[after].text == "while":
                if after + 1 < limit and tokens[after + 1].text == "(":
                    close = _matching(tokens, after + 1)
                    if close is not None:
                        cond = list(tokens[after + 2 : close])
                        after = close + 1
            if after < limit and tokens[after].text == ";":
                after += 1
            return (
                Stmt(
                    "do",
                    tokens=cond,
                    body=[body_stmt] if body_stmt else [],
                    line=token.line,
                ),
                after,
            )
        if text == "switch":
            cond, after = _paren_group(tokens, index + 1)
            body_stmt, after = _parse_statement(tokens, after, budget, depth + 1)
            body = body_stmt.body if body_stmt is not None and body_stmt.kind == "block" else (
                [body_stmt] if body_stmt else []
            )
            return Stmt("switch", tokens=cond, body=body, line=token.line), after
        if text in ("case", "default"):
            cursor = index + 1
            while cursor < limit and not (tokens[cursor].kind == OP and tokens[cursor].text == ":"):
                cursor += 1
            return Stmt("case", label=text, line=token.line), cursor + 1
        if text == "try":
            body_stmt, after = _parse_statement(tokens, index + 1, budget, depth + 1)
            handlers: List[Stmt] = []
            while after < limit and tokens[after].text == "catch":
                _, after = _paren_group(tokens, after + 1)
                handler, after = _parse_statement(tokens, after, budget, depth + 1)
                if handler is not None:
                    handlers.append(handler)
            return (
                Stmt(
                    "try",
                    body=[body_stmt] if body_stmt else [],
                    alternate=handlers,
                    line=token.line,
                ),
                after,
            )
        if text in ("return", "break", "continue", "goto", "throw", "co_return"):
            end = _statement_end(tokens, index)
            label = ""
            if text == "goto" and index + 1 < limit:
                label = tokens[index + 1].text
            kind = "return" if text in ("throw", "co_return") else text
            return Stmt("jump", tokens=list(tokens[index + 1 : end]), label=kind + ":" + label, line=token.line), end + 1
        if (
            index + 1 < limit
            and tokens[index + 1].kind == OP
            and tokens[index + 1].text == ":"
            and text not in ("public", "private", "protected", "default")
        ):
            return Stmt("label", label=text, line=token.line), index + 2
    if token.kind == IDENT and token.text not in _ATTRIBUTE_WORDS and index + 1 < limit and tokens[index + 1].text == "(":
        close = _matching(tokens, index + 1)
        if close is not None and close + 1 < limit:
            following = tokens[close + 1]
            if (following.kind == OP and following.text == "{") or (
                following.kind == IDENT and following.text not in ("const", "noexcept", "override")
            ):
                # `TAILQ_FOREACH(x, head, link) { ... }`, `list_for_each_entry(...)`:
                # một lời gọi hàm không bao giờ đứng ngay trước một khối hay một
                # câu lệnh, nên đây chỉ có thể là macro vòng lặp.
                body_stmt, after = _parse_statement(tokens, close + 1, budget, depth + 1)
                return (
                    Stmt(
                        "loop",
                        tokens=list(tokens[index + 2 : close]),
                        body=[body_stmt] if body_stmt else [],
                        label="macro",
                        line=token.line,
                    ),
                    after,
                )
    end = _statement_end(tokens, index)
    return Stmt("simple", tokens=list(tokens[index:end]), line=token.line), end + 1


def _paren_group(tokens: Sequence[Token], index: int) -> Tuple[List[Token], int]:
    if index < len(tokens) and tokens[index].kind == OP and tokens[index].text == "(":
        close = _matching(tokens, index)
        if close is not None:
            return list(tokens[index + 1 : close]), close + 1
    return [], index


def _parse_if(
    tokens: Sequence[Token], index: int, budget: Budget, depth: int
) -> Tuple[Optional[Stmt], int]:
    line = tokens[index].line
    cursor = index + 1
    if cursor < len(tokens) and tokens[cursor].text in ("constexpr",):
        cursor += 1
    cond, after = _paren_group(tokens, cursor)
    then_stmt, after = _parse_statement(tokens, after, budget, depth + 1)
    alternate: List[Stmt] = []
    if after < len(tokens) and tokens[after].kind == IDENT and tokens[after].text == "else":
        else_stmt, after = _parse_statement(tokens, after + 1, budget, depth + 1)
        if else_stmt is not None:
            alternate = [else_stmt]
    return (
        Stmt("if", tokens=cond, body=[then_stmt] if then_stmt else [], alternate=alternate, line=line),
        after,
    )


def _parse_loop(
    tokens: Sequence[Token], index: int, budget: Budget, depth: int
) -> Tuple[Optional[Stmt], int]:
    keyword = tokens[index].text
    header, after = _paren_group(tokens, index + 1)
    body_stmt, after = _parse_statement(tokens, after, budget, depth + 1)
    statement = Stmt("loop", body=[body_stmt] if body_stmt else [], line=tokens[index].line)
    if keyword == "for":
        parts: List[List[Token]] = [[]]
        nesting = 0
        for token in header:
            if token.kind == OP and token.text in "([{":
                nesting += 1
            elif token.kind == OP and token.text in ")]}":
                nesting -= 1
            if token.kind == OP and token.text == ";" and nesting == 0:
                parts.append([])
                continue
            parts[-1].append(token)
        if len(parts) == 3:
            statement.init, statement.tokens, statement.step = parts[0], parts[1], parts[2]
        else:
            # Range-for `for (auto &x : v)` -- coi cả cụm là điều kiện.
            statement.tokens = header
    else:
        statement.tokens = header
    statement.label = keyword
    return statement, after


def _statement_end(tokens: Sequence[Token], index: int) -> int:
    depth = 0
    limit = len(tokens)
    cursor = index
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == OP:
            if token.text in "([{":
                depth += 1
            elif token.text in ")]}":
                depth -= 1
                if depth < 0:
                    return cursor
            elif token.text == ";" and depth == 0:
                return cursor
        cursor += 1
    return limit


def parse_translation_unit(source: str, budget: Budget) -> Tuple[TranslationUnit, Dict[str, str]]:
    stripped, macros = strip_preprocessor(source)
    lines = stripped.split("\n")
    tokens = [
        _decode_literal(token, lines)
        for token in significant(tokenize(stripped, C_LEXER, budget))
        # Dấu `\` ngoài chuỗi chỉ có thể là nối dòng; trình biên dịch xoá nó ở
        # pha 2, trước cả khi tách token.
        if not (token.kind == OP and token.text == "\\")
    ]
    tokens = _merge_objc_strings(tokens)
    constants = collect_constants(tokens, macros, budget)
    functions, globals_tokens = find_functions(tokens, budget)
    return TranslationUnit(tokens, constants, functions, globals_tokens), macros


_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}


def decode_c_literal(raw: str, start: int) -> Optional[str]:
    """Giải mã literal C bắt đầu bằng dấu nháy tại raw[start], đúng như trình biên dịch.

    Bộ đọc token chung chỉ bỏ dấu `\\` trước ký tự thoát, nên `"\\106"` thành
    ba ký tự `106` thay vì một. Với luật đếm độ dài chuỗi, đếm dư là báo nhầm
    "literal quá dài" -- nên độ dài phải tính lại theo đúng ngữ pháp C.
    """
    if start >= len(raw) or raw[start] not in "\"'":
        return None
    quote = raw[start]
    index = start + 1
    out: List[str] = []
    length = len(raw)
    while index < length:
        char = raw[index]
        if char == quote:
            return "".join(out)
        if char == "\\" and index + 1 < length:
            following = raw[index + 1]
            if following in "01234567":
                end = index + 1
                while end < length and end < index + 4 and raw[end] in "01234567":
                    end += 1
                out.append(chr(int(raw[index + 1 : end], 8) & 0xFF))
                index = end
                continue
            if following == "x":
                end = index + 2
                while end < length and raw[end] in "0123456789abcdefABCDEF":
                    end += 1
                digits = raw[index + 2 : end] or "0"
                out.append(chr(int(digits, 16) & 0x10FFFF))
                index = end
                continue
            out.append(_SIMPLE_ESCAPES.get(following, following))
            index += 2
            continue
        out.append(char)
        index += 1
    return None


def _decode_literal(token: Token, lines: Sequence[str]) -> Token:
    if token.kind != STRING or token.in_string:
        return token
    if not 1 <= token.line <= len(lines):
        return token
    decoded = decode_c_literal(lines[token.line - 1], token.column)
    if decoded is None or decoded == token.text:
        return token
    return Token(
        kind=token.kind,
        text=decoded,
        line=token.line,
        column=token.column,
        in_string=token.in_string,
        interpolated=token.interpolated,
        quote=token.quote,
    )


def _merge_objc_strings(tokens: List[Token]) -> List[Token]:
    """`@"..."` của Objective-C là MỘT chuỗi literal, không phải `@` cộng chuỗi."""
    merged: List[Token] = []
    for token in tokens:
        if (
            token.kind == STRING
            and merged
            and merged[-1].kind == OP
            and merged[-1].text == "@"
            and merged[-1].line == token.line
        ):
            merged.pop()
        elif (
            token.kind == STRING
            and merged
            and merged[-1].kind == IDENT
            and merged[-1].text in _STRING_PREFIXES
            and merged[-1].line == token.line
            and merged[-1].column + len(merged[-1].text) == token.column
        ):
            # L"...", u8"...", u"...", U"...": tiền tố của literal, không phải tên biến.
            merged.pop()
        merged.append(token)
    return merged


_STRING_PREFIXES = frozenset({"L", "u8", "u", "U", "_T", "TEXT"})
