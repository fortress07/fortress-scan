"""Luật an toàn bộ nhớ cho C, C++ và Objective-C.

Mọi luật ở đây đọc CẤU TRÚC chứ không khớp tên hàm trần. `strcpy` không tự
nó là lỗi: `strcpy(buf, "ok")` vào mảng 64 byte là đúng, và một công cụ báo
mọi `strcpy` thì người ta tắt nó đi sau một tuần. Phát hiện chỉ ra khi đọc
được cả hai vế:

* kích thước thật của vùng đích ( mảng khai báo cố định, hằng, macro, enum,
  thành viên struct ) và
* độ dài tối đa của thứ được ghi vào ( literal, mảng khác, độ rộng của
  định dạng, một con số đã hoặc chưa được kiểm ).

Khi một trong hai vế là "không biết", luật im lặng -- trừ khi dữ liệu đến
thẳng từ bên ngoài ( mạng, stdin, tệp, argv ), lúc đó "không biết độ dài"
chính là lỗi.

Use-after-free và double free chạy trên cây câu lệnh với phép hợp trạng
thái ở mỗi chỗ rẽ nhánh, nên một `free()` nằm trong nhánh lỗi đã `return`
thì không chảy xuống dòng dưới.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...core.model import Confidence, Finding, Severity, StepKind
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from ..generic.lexer import IDENT, NUMBER, OP, STRING, Token
from .cparse import (
    CHAR_TYPES,
    NORETURN_CALLS,
    TYPE_SIZES,
    ConstantEvaluator,
    decode_c_literal,
    Function,
    Stmt,
    TranslationUnit,
    matching,
    parse_translation_unit,
    split_arguments,
)

NETWORK = "dữ liệu nhận qua mạng"
INPUT = "dữ liệu đọc từ đầu vào"
ARGV = "tham số dòng lệnh"
ENVIRONMENT = "biến môi trường"


@dataclass(frozen=True)
class Taint:
    label: str
    line: int
    strong: bool  # mạng / stdin / tệp: True; argv / env: False
    # "data": nội dung bộ đệm; "number": số phân tích ra từ dữ liệu ngoài hoặc
    # đọc thẳng từ dây; "length": strlen() của dữ liệu ngoài -- một độ dài thật
    # của chuỗi đang nằm trong bộ nhớ, nên cộng thêm vài byte không thể tràn.
    kind: str = "data"


@dataclass(frozen=True)
class ArrayInfo:
    count: int
    element_size: Optional[int]
    is_char: bool
    line: int
    inner: Tuple[int, ...] = ()

    @property
    def bytes(self) -> Optional[int]:
        if self.element_size is None:
            return None
        total = self.count * self.element_size
        for dimension in self.inner:
            total *= dimension
        return total


@dataclass(frozen=True)
class FreeFact:
    line: int
    column: int
    verb: str
    definite: bool = True


# ------------------------------------------------------------- bảng hàm thư viện

_STRIP_PREFIXES = ("std.", "::", "")

# Hàm sao chép không có giới hạn: (vị trí đích, vị trí nguồn).
_UNBOUNDED_COPY: Dict[str, Tuple[int, int]] = {
    "strcpy": (0, 1),
    "stpcpy": (0, 1),
    "strcat": (0, 1),
    "wcscpy": (0, 1),
    "wcscat": (0, 1),
    "lstrcpy": (0, 1),
    "lstrcpyA": (0, 1),
    "lstrcpyW": (0, 1),
    "lstrcat": (0, 1),
    "lstrcatA": (0, 1),
    "lstrcatW": (0, 1),
    "_tcscpy": (0, 1),
    "_tcscat": (0, 1),
    "_mbscpy": (0, 1),
    "_mbscat": (0, 1),
    "StrCpy": (0, 1),
    "StrCat": (0, 1),
}
_APPENDS = frozenset({"strcat", "wcscat", "lstrcat", "lstrcatA", "lstrcatW", "_tcscat", "_mbscat", "StrCat"})

# Hàm có giới hạn: (vị trí đích, các vị trí đối số mà TÍCH của chúng là số byte ghi).
_SIZED_WRITE: Dict[str, Tuple[int, Tuple[int, ...]]] = {
    "memcpy": (0, (2,)),
    "memmove": (0, (2,)),
    "memset": (0, (2,)),
    "bzero": (0, (1,)),
    "explicit_bzero": (0, (1,)),
    "bcopy": (1, (2,)),
    "strncpy": (0, (2,)),
    "strlcpy": (0, (2,)),
    "strlcat": (0, (2,)),
    "snprintf": (0, (1,)),
    "vsnprintf": (0, (1,)),
    "fgets": (0, (1,)),
    "read": (1, (2,)),
    "pread": (1, (2,)),
    "recv": (1, (2,)),
    "recvfrom": (1, (2,)),
    "fread": (0, (1, 2)),
    "readlink": (1, (2,)),
    "getcwd": (0, (1,)),
    "gethostname": (0, (1,)),
    "CopyMemory": (0, (2,)),
    "RtlCopyMemory": (0, (2,)),
    "MoveMemory": (0, (2,)),
}

# Hàm đổ dữ liệu ngoài vào bộ đệm đối số: vị trí bộ đệm và nhãn nguồn.
_INPUT_FILL: Dict[str, Tuple[int, str]] = {
    "fgets": (0, INPUT),
    "gets": (0, INPUT),
    "fgetws": (0, INPUT),
    "read": (1, INPUT),
    "pread": (1, INPUT),
    "fread": (0, INPUT),
    "recv": (1, NETWORK),
    "recvfrom": (1, NETWORK),
    "ReadFile": (1, INPUT),
    "getline": (0, INPUT),
    "getdelim": (0, INPUT),
    "SSL_read": (1, NETWORK),
    "BIO_read": (1, NETWORK),
}

# Hàm chép: đích nhiễm khi bất kỳ nguồn nào nhiễm.
_PROPAGATE: Dict[str, int] = {
    "strcpy": 0,
    "strncpy": 0,
    "strlcpy": 0,
    "strcat": 0,
    "strncat": 0,
    "strlcat": 0,
    "stpcpy": 0,
    "memcpy": 0,
    "memmove": 0,
    "sprintf": 0,
    "snprintf": 0,
    "vsprintf": 0,
    "vsnprintf": 0,
    "wcscpy": 0,
    "wcscat": 0,
}

_INTEGER_PARSE = frozenset(
    {
        "atoi",
        "atol",
        "atoll",
        "strtol",
        "strtoul",
        "strtoll",
        "strtoull",
        "strtoimax",
        "strtoumax",
        "stoi",
        "stol",
        "stoul",
        "stoll",
        "stoull",
        "strlen",
        "wcslen",
        "strnlen",
    }
)

# Đổi thứ tự byte: gần như chỉ dùng cho số đọc từ dây mạng hoặc tệp nhị phân.
_WIRE_INTEGER = frozenset(
    {
        "ntohl",
        "ntohs",
        "be16toh",
        "be32toh",
        "be64toh",
        "le16toh",
        "le32toh",
        "le64toh",
        "bswap_16",
        "bswap_32",
        "bswap_64",
        "__builtin_bswap16",
        "__builtin_bswap32",
        "__builtin_bswap64",
        "get_unaligned_be16",
        "get_unaligned_be32",
        "get_unaligned_le16",
        "get_unaligned_le32",
        "AV_RB16",
        "AV_RB32",
        "AV_RL16",
        "AV_RL32",
    }
)

_BOUNDING_CALLS = frozenset({"MIN", "min", "std.min", "fmin", "clamp", "std.clamp", "MIN_T", "min_t"})

_ALLOCATORS: Dict[str, int] = {
    "malloc": 0,
    "alloca": 0,
    "_alloca": 0,
    "xmalloc": 0,
    "g_malloc": 0,
    "g_malloc0": 0,
    "kmalloc": 0,
    "kzalloc": 0,
    "vmalloc": 0,
    "av_malloc": 0,
    "av_mallocz": 0,
    "OPENSSL_malloc": 0,
    "realloc": 1,
    "xrealloc": 1,
    "g_realloc": 1,
    "krealloc": 1,
    "av_realloc": 1,
    "HeapAlloc": 2,
}

# (tên hàm, vị trí con trỏ bị giải phóng)
_FREE_CALLS: Dict[str, int] = {
    "free": 0,
    "cfree": 0,
    "xfree": 0,
    "g_free": 0,
    "kfree": 0,
    "kvfree": 0,
    "vfree": 0,
    "kfree_sensitive": 0,
    "OPENSSL_free": 0,
    "CRYPTO_free": 0,
    "av_free": 0,
    "sqlite3_free": 0,
    "LocalFree": 0,
    "GlobalFree": 0,
    "CoTaskMemFree": 0,
    "kmem_cache_free": 1,
    "HeapFree": 2,
    "fclose": 0,
}

_PRINTF_FORMAT: Dict[str, int] = {
    "printf": 0,
    "vprintf": 0,
    "wprintf": 0,
    "vwprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "fwprintf": 1,
    "vfwprintf": 1,
    "dprintf": 1,
    "vdprintf": 1,
    "sprintf": 1,
    "vsprintf": 1,
    "snprintf": 2,
    "vsnprintf": 2,
    "swprintf": 2,
    "vswprintf": 2,
    "asprintf": 1,
    "vasprintf": 1,
    "syslog": 1,
    "vsyslog": 1,
    "err": 1,
    "errx": 1,
    "warn": 0,
    "warnx": 0,
    "printk": 0,
    "g_printf": 0,
    "g_strdup_printf": 0,
    "g_error": 0,
    "g_warning": 0,
    "g_message": 0,
    "setproctitle": 0,
    "NSLog": 0,
}
_VA_LIST_PRINTF = frozenset(
    {"vprintf", "vfprintf", "vsprintf", "vsnprintf", "vasprintf", "vsyslog", "vdprintf", "vwprintf", "vfwprintf", "vswprintf"}
)

_GETTEXT = frozenset(
    {"_", "gettext", "dgettext", "dcgettext", "ngettext", "N_", "Q_", "C_", "P_", "_T", "TEXT", "_TEXT", "__T", "tr", "i18n"}
)

_SCANF: Dict[str, int] = {"scanf": 0, "fscanf": 1, "sscanf": 1, "vscanf": 0, "wscanf": 0, "fwscanf": 1, "swscanf": 1, "scanf_s": -1}

_SIGNED_WORDS = frozenset({"int", "long", "short", "ssize_t", "int32_t", "int64_t", "int16_t", "off_t", "signed", "ptrdiff_t", "intptr_t", "gint", "LONG", "INT"})
_UNSIGNED_WORDS = frozenset({"unsigned", "size_t", "uint32_t", "uint64_t", "uint16_t", "uint8_t", "u32", "u64", "u16", "u8", "DWORD", "UINT", "ULONG", "guint", "gsize", "uintptr_t"})

# Số 8/16 bit được nâng lên int trước khi cộng hay nhân với hằng nhỏ: không quấn vòng.
_NARROW_WORDS = frozenset(
    {"char", "short", "uint16_t", "uint8_t", "int16_t", "int8_t", "u16", "u8", "s16", "s8", "WORD", "BYTE", "guint16", "guint8", "gint16", "gint8", "UCHAR", "USHORT"}
)

_DECLARATION_STOP = frozenset(
    {"return", "goto", "case", "sizeof", "delete", "new", "throw", "else", "if", "while", "for", "switch", "do", "typedef"}
)


def _base(chain: str) -> str:
    for prefix in ("std.", "::"):
        if chain.startswith(prefix):
            chain = chain[len(prefix) :]
    return chain


def _chain(tokens: Sequence[Token], index: int) -> Tuple[Optional[str], int]:
    """Đọc `a`, `a.b`, `a->b`, `ns::f` bắt đầu tại index. Dấu nối chuẩn hoá thành `.`."""
    limit = len(tokens)
    if index >= limit or tokens[index].kind != IDENT:
        return None, index
    parts = [tokens[index].text]
    cursor = index + 1
    while cursor + 1 < limit:
        separator = tokens[cursor]
        if separator.kind != OP or separator.text not in (".", "->", "::"):
            break
        following = tokens[cursor + 1]
        if following.kind != IDENT:
            break
        parts.append(following.text)
        cursor += 2
    return ".".join(parts), cursor


def _string_length(tokens: Sequence[Token]) -> Optional[int]:
    """Độ dài của một literal chuỗi ( kể cả nhiều literal nối liền ), hoặc None."""
    meaningful = [token for token in tokens if not (token.kind == OP and token.text in "()")]
    if not meaningful or any(token.kind != STRING or token.quote != '"' for token in meaningful):
        return None
    return sum(len(token.text) for token in meaningful)


def _is_literal_string(tokens: Sequence[Token]) -> bool:
    return _string_length(tokens) is not None


class NativeMemoryAnalyzer(Analyzer):
    name = "native-memory"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        analysis: Optional[_FileAnalysis] = None
        try:
            translation, macros = parse_translation_unit(unit.source, budget)
            analysis = _FileAnalysis(unit, translation, macros, budget)
            return analysis.run()
        except BudgetExceeded:
            # Hết hạn mức: giữ những gì đã tìm được, engine tự ghi lỗi "chưa hoàn tất".
            return analysis.builder.findings if analysis is not None else []


class _FileAnalysis:
    def __init__(self, unit: AnalysisUnit, translation, macros: Dict[str, str], budget: Budget) -> None:
        self.unit = unit
        self.translation = translation
        self.macros = macros
        self.budget = budget
        self.builder = FindingBuilder(unit)
        self.constants: Dict[str, int] = dict(translation.constants)
        self.evaluator = ConstantEvaluator(self.constants, macros, budget)
        self.global_arrays: Dict[str, ArrayInfo] = {}
        self.member_arrays: Dict[str, ArrayInfo] = {}
        self.ambiguous: Set[str] = set()
        self.member_ambiguous: Set[str] = set()
        self.function_names: Set[str] = {function.name for function in translation.functions}
        self.structs: Dict[str, _StructInfo] = {}
        self.global_types: Dict[str, Tuple[str, ...]] = {}
        self.literal_globals: Set[str] = set()
        self.free_summaries: Dict[str, Tuple[int, ...]] = {}
        # hàm -> {chỉ số tham số: [(hậu tố trường, vết nhiễm)]}: hàm đọc từ mạng
        # rồi ghi vào `h->length` của tham số thì bên gọi nhận lại vết nhiễm đó.
        self.taint_summaries: Dict[str, Dict[int, List[Tuple[str, Taint]]]] = {}
        self.noreturn: Set[str] = _noreturn_functions(translation)
        self.deref_summaries: Dict[str, Set[int]] = {}

    def run(self) -> List[Finding]:
        member_ids = _struct_member_token_ids(self.translation.tokens)
        _collect_arrays(
            [t for t in self.translation.globals_tokens if id(t) not in member_ids],
            self.evaluator,
            self.global_arrays,
            self.ambiguous,
            set(),
            self.budget,
            self.global_types,
        )
        self.structs = _collect_structs(self.translation.tokens, self.evaluator, self.budget)
        self.literal_globals = _literal_variables(self.translation.globals_tokens, self.macros)
        for function in self.translation.functions:
            self.budget.spend()
            freed = _FreeFlow(self, function, report=False).summary()
            if freed:
                self.free_summaries[function.name] = freed
        self._summarize_taint()
        self._summarize_derefs()
        for function in self.translation.functions:
            self.budget.spend()
            _FunctionAnalysis(self, function).run()
            _FreeFlow(self, function, report=True).run()
        return self.builder.findings

    def _summarize_derefs(self) -> None:
        """Hàm nào thật sự đọc qua tham số con trỏ thứ i ( p->x, p[i], *p, strlen(p) )."""
        for _round in range(2):
            changed = False
            for function in self.translation.functions:
                self.budget.spend()
                found = self.deref_summaries.get(function.name, set())
                before = len(found)
                tokens = function.body_tokens
                for position, param in enumerate(function.param_names):
                    if position in found:
                        continue
                    if _derefs(tokens, param, self.deref_summaries):
                        found.add(position)
                if found and len(found) != before:
                    self.deref_summaries[function.name] = found
                    changed = True
            if not changed:
                break

    def _summarize_taint(self) -> None:
        sources = set(_INPUT_FILL) | set(_SCANF) | set(_WIRE_INTEGER) | {"cin", "getenv"}
        # Hai vòng là đủ cho chuỗi helper -> helper thường gặp; không lặp tới điểm bất động.
        for _round in range(2):
            changed = False
            for function in self.translation.functions:
                self.budget.spend()
                if not any(i for i, t in enumerate(function.params) if "*" in [x.text for x in t] or "&" in [x.text for x in t]):
                    continue
                names = {t.text for t in function.body_tokens if t.kind == IDENT}
                if not (names & sources or names & set(self.taint_summaries)):
                    continue
                analysis = _FunctionAnalysis(self, function, report=False)
                analysis.run()
                summary = analysis.out_taints()
                if summary and summary != self.taint_summaries.get(function.name):
                    self.taint_summaries[function.name] = summary
                    changed = True
            if not changed:
                break


# --------------------------------------------------------------- mảng và hằng


_NORETURN_MARKERS = frozenset({"_Noreturn", "noreturn", "__noreturn__", "__dead", "__dead2", "NORETURN"})


def _is_noreturn_marker(text: str) -> bool:
    upper = text.upper()
    return text in _NORETURN_MARKERS or "NORETURN" in upper or "NO_RETURN" in upper


def _after_pointer_cast(tokens: Sequence[Token], index: int) -> bool:
    """`(void **)&ptr`: dấu `)` đứng trước là phép ép kiểu con trỏ, không phải `x) & y`."""
    if index < 3 or tokens[index - 1].text != ")" or tokens[index - 2].text != "*":
        return False
    cursor = index - 2
    while cursor > 0 and (tokens[cursor].kind == IDENT or tokens[cursor].text == "*"):
        cursor -= 1
    return tokens[cursor].kind == OP and tokens[cursor].text == "("


def _derefs(tokens: Sequence[Token], name: str, summaries: Dict[str, Set[int]]) -> bool:
    limit = len(tokens)
    for index, token in enumerate(tokens):
        if token.kind != IDENT or token.text != name:
            continue
        previous = tokens[index - 1] if index > 0 else None
        if previous is not None and previous.kind == OP and previous.text in (".", "->"):
            continue
        following = tokens[index + 1] if index + 1 < limit else None
        if following is not None and following.kind == OP and following.text in ("->", "["):
            return True
        if previous is not None and previous.kind == OP and previous.text == "*":
            before = tokens[index - 2] if index >= 2 else None
            if before is None or (before.kind == OP and before.text not in (")", "]")):
                return True
    # Truyền nguyên con trỏ cho hàm khác cũng đọc qua nó.
    for index, token in enumerate(tokens):
        if token.kind != IDENT or index + 1 >= limit or tokens[index + 1].text != "(":
            continue
        callee = _base(token.text)
        positions = summaries.get(callee)
        if callee not in _DEREF_CALLS and not positions:
            continue
        arguments, _ = split_arguments(tokens, index + 1)
        for position, argument in enumerate(arguments):
            if _target_name(argument) == name and _is_plain_pointer(argument):
                if callee in _DEREF_CALLS or (positions and position in positions):
                    return True
    return False


def _noreturn_functions(translation: TranslationUnit) -> Set[str]:
    """Hàm khai báo kèm _Noreturn / __attribute__((noreturn)) / PCAP_NORETURN,
    hoặc thân hàm kết thúc vô điều kiện bằng exit()/longjmp()/abort()."""
    names: Set[str] = set()
    tokens = translation.tokens
    limit = len(tokens)
    for index, token in enumerate(tokens):
        if token.kind != IDENT or not _is_noreturn_marker(token.text):
            continue
        cursor = index + 1
        while cursor + 1 < limit and cursor < index + 40:
            current = tokens[cursor]
            if current.kind == OP and current.text in (";", "{", "}"):
                break
            if current.kind == IDENT and tokens[cursor + 1].text == "(" and not _is_noreturn_marker(current.text) and current.text != "__attribute__":
                names.add(current.text)
                break
            cursor += 1
    for function in translation.functions:
        last = [s for s in function.body if s.kind != "label"][-1:] if function.body else []
        if last and last[0].kind == "simple" and last[0].tokens:
            first = last[0].tokens[0]
            if first.kind == IDENT and (first.text in NORETURN_CALLS or first.text in names) and len(last[0].tokens) > 1 and last[0].tokens[1].text == "(":
                names.add(function.name)
    return names


def _collect_arrays(
    tokens: Sequence[Token],
    evaluator: ConstantEvaluator,
    arrays: Dict[str, ArrayInfo],
    ambiguous: Set[str],
    declared_positions: Set[int],
    budget: Budget,
    declared_types: Optional[Dict[str, Tuple[str, ...]]] = None,
    token_offset: int = 0,
) -> None:
    """Mảng kích thước cố định khai báo trong dãy token này.

    `declared_positions` nhận vị trí ( theo id token ) của dấu `[` trong lời
    khai báo, để luật chỉ số không đọc nhầm `char buf[64]` thành một phép
    truy cập buf[64].
    """
    for statement in _split_on_semicolons(tokens):
        budget.spend()
        if not statement or statement[0].kind != IDENT or statement[0].text in _DECLARATION_STOP:
            continue
        _collect_declarators(statement, evaluator, arrays, ambiguous, declared_positions, declared_types)


def _split_on_semicolons(tokens: Sequence[Token]) -> List[List[Token]]:
    statements: List[List[Token]] = []
    current: List[Token] = []
    depth = 0
    for token in tokens:
        if token.kind == OP:
            if token.text in "([":
                depth += 1
            elif token.text in ")]":
                depth = max(0, depth - 1)
            elif token.text in (";", "{", "}") and depth == 0:
                if current:
                    statements.append(current)
                current = []
                continue
        current.append(token)
    if current:
        statements.append(current)
    return statements


def _collect_declarators(
    statement: Sequence[Token],
    evaluator: ConstantEvaluator,
    arrays: Dict[str, ArrayInfo],
    ambiguous: Set[str],
    declared_positions: Set[int],
    declared_types: Optional[Dict[str, Tuple[str, ...]]],
) -> None:
    # Phần kiểu: các định danh ở đầu câu, trước định danh đầu tiên được theo
    # sau bởi `[`, `=`, `,`, `;` hoặc kết thúc.
    limit = len(statement)
    type_words: List[str] = []
    index = 0
    # `XXH_ALIGN(16) u64 acc[8];`, `__attribute__((aligned)) char b[4];`:
    # macro thuộc tính đứng đầu không đổi được đây là một lời khai báo.
    while (
        index + 1 < limit
        and statement[index].kind == IDENT
        and statement[index + 1].kind == OP
        and statement[index + 1].text == "("
    ):
        close = matching(statement, index + 1)
        if close is None or close + 1 >= limit or statement[close + 1].kind != IDENT:
            break
        index = close + 1
    while index < limit:
        token = statement[index]
        if token.kind == IDENT:
            following = statement[index + 1] if index + 1 < limit else None
            if following is None or (following.kind == OP and following.text in ("[", "=", ",", ":", ")")):
                break
            if following.kind == OP and following.text == "(":
                return  # lời gọi hàm hoặc khai báo hàm, không phải biến
            type_words.append(token.text)
            index += 1
            continue
        if token.kind == OP and token.text in ("*", "&", "::", "<", ">"):
            index += 1
            continue
        return
    if not type_words or index >= limit:
        return
    pointer = any(t.kind == OP and t.text == "*" for t in statement[:index])
    element_size = _type_size(type_words)
    is_char = bool(set(type_words) & CHAR_TYPES) and not pointer
    cursor = index
    expect_name = True
    pointer_here = pointer
    while cursor < limit:
        token = statement[cursor]
        if token.kind == OP and token.text in "({":
            close = matching(statement, cursor)
            cursor = (close if close is not None else limit) + 1
            continue
        if token.kind == OP and token.text == ",":
            expect_name = True
            pointer_here = False
            cursor += 1
            continue
        if token.kind == OP and token.text == "*" and expect_name:
            pointer_here = True
            cursor += 1
            continue
        if token.kind == IDENT and expect_name:
            name = token.text
            expect_name = False
            dims: List[Optional[int]] = []
            after = cursor + 1
            while after < limit and statement[after].kind == OP and statement[after].text == "[":
                close = matching(statement, after)
                if close is None:
                    break
                declared_positions.add(id(statement[after]))
                inner = statement[after + 1 : close]
                dims.append(evaluator.evaluate(inner) if inner else -1)
                after = close + 1
            if declared_types is not None:
                declared_types[name] = (
                    tuple(type_words) + (("*",) if pointer_here else ()) + (("[]",) if dims else ())
                )
            if dims:
                first = dims[0]
                if first == -1:
                    first = _initializer_length(statement, after)
                if first is not None and first > 1 and all(d is not None and d > 0 for d in dims[1:]):
                    element = 8 if pointer_here else element_size
                    info = ArrayInfo(
                        count=first,
                        element_size=element,
                        is_char=is_char and not pointer_here,
                        line=token.line,
                        inner=tuple(int(d) for d in dims[1:] if d is not None),
                    )
                    previous = arrays.get(name)
                    if previous is not None and previous != info:
                        ambiguous.add(name)
                    arrays[name] = info
            cursor = after
            continue
        if token.kind == OP and token.text == "=":
            # bỏ qua phần khởi tạo tới dấu phẩy ở mức 0
            cursor += 1
            while cursor < limit:
                inner = statement[cursor]
                if inner.kind == OP and inner.text in "({[":
                    close = matching(statement, cursor)
                    cursor = (close if close is not None else limit) + 1
                    continue
                if inner.kind == OP and inner.text == ",":
                    break
                cursor += 1
            continue
        cursor += 1


@dataclass
class _StructInfo:
    types: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    arrays: Dict[str, ArrayInfo] = field(default_factory=dict)
    ambiguous: Set[str] = field(default_factory=set)


def _collect_structs(
    tokens: Sequence[Token], evaluator: ConstantEvaluator, budget: Budget
) -> Dict[str, _StructInfo]:
    """Định nghĩa struct/union/class trong tệp, theo tên thẻ và tên typedef.

    Mảng thành viên chỉ được tra QUA KIỂU của biến: `p->name` là mảng 32 byte
    khi và chỉ khi `p` khai báo là con trỏ tới một struct định nghĩa ngay
    trong tệp có `char name[32]`. Tra theo mỗi tên thành viên thì hai struct
    khác nhau cùng có trường `name` -- một cái khai báo ở header -- sẽ cho ra
    kích thước của nhau.
    """
    structs: Dict[str, _StructInfo] = {}
    limit = len(tokens)
    index = 0
    while index < limit:
        budget.spend()
        token = tokens[index]
        if token.kind == IDENT and token.text in ("struct", "union", "class"):
            typedef = index > 0 and tokens[index - 1].kind == IDENT and tokens[index - 1].text == "typedef"
            cursor = index + 1
            tag: Optional[str] = None
            while cursor < limit and tokens[cursor].kind == IDENT:
                tag = tokens[cursor].text
                cursor += 1
            if cursor < limit and tokens[cursor].kind == OP and tokens[cursor].text == ":" and tag is not None:
                # class X : public Y {
                while cursor < limit and not (tokens[cursor].kind == OP and tokens[cursor].text in "{;"):
                    cursor += 1
            if cursor < limit and tokens[cursor].kind == OP and tokens[cursor].text == "{":
                close = matching(tokens, cursor)
                if close is None:
                    index += 1
                    continue
                info = _StructInfo()
                body = _flatten_nested(tokens[cursor + 1 : close])
                for statement in _split_on_semicolons(body):
                    if statement and statement[0].kind == IDENT:
                        _collect_declarators(statement, evaluator, info.arrays, info.ambiguous, set(), info.types)
                names: List[str] = [tag] if tag else []
                after = close + 1
                if typedef:
                    while after < limit and not (tokens[after].kind == OP and tokens[after].text == ";"):
                        if tokens[after].kind == IDENT:
                            names.append(tokens[after].text)
                        after += 1
                for name in names:
                    if name in structs:
                        structs[name] = _StructInfo()  # hai định nghĩa: không tin cái nào
                    else:
                        structs[name] = info
                index = close + 1
                continue
        index += 1
    return structs


def _flatten_nested(tokens: Sequence[Token]) -> List[Token]:
    """Bỏ thân của struct/union lồng bên trong, giữ lời khai báo của nó."""
    result: List[Token] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind == OP and token.text == "{":
            close = matching(tokens, index)
            index = (close if close is not None else len(tokens)) + 1
            continue
        result.append(token)
        index += 1
    return result


def _struct_name(types: Sequence[str]) -> Optional[str]:
    words = [w for w in types if w not in ("struct", "union", "class", "const", "volatile", "static", "*", "[]", "extern", "register")]
    return words[-1] if words else None


def _struct_member_token_ids(tokens: Sequence[Token]) -> Set[int]:
    """id() của mọi token nằm trong thân `struct/union/class { ... }`."""
    ids: Set[int] = set()
    limit = len(tokens)
    index = 0
    while index < limit:
        token = tokens[index]
        if token.kind == IDENT and token.text in ("struct", "union", "class"):
            cursor = index + 1
            while cursor < limit and cursor < index + 4 and tokens[cursor].kind in (IDENT,) :
                cursor += 1
            if cursor < limit and tokens[cursor].kind == OP and tokens[cursor].text == "{":
                close = matching(tokens, cursor)
                if close is not None:
                    for inner in range(cursor + 1, close):
                        ids.add(id(tokens[inner]))
                    index = close + 1
                    continue
        index += 1
    return ids


def _initializer_length(statement: Sequence[Token], after: int) -> Optional[int]:
    """`char s[] = "abc"` dài 4; `int a[] = {1, 2}` dài 2."""
    if after >= len(statement) or statement[after].text != "=":
        return None
    rest = statement[after + 1 :]
    length = _string_length(rest[:1])
    if length is not None:
        return length + 1
    if rest and rest[0].kind == OP and rest[0].text == "{":
        close = matching(rest, 0)
        if close is None:
            return None
        arguments, _ = split_arguments([Token(OP, "(", 0, 0)] + list(rest[1:close]) + [Token(OP, ")", 0, 0)], 0)
        return len([a for a in arguments if a]) or None
    return None


def _type_size(words: Sequence[str]) -> Optional[int]:
    cleaned = [w for w in words if w not in ("const", "static", "volatile", "register", "extern", "struct", "thread_local", "_Thread_local", "auto", "inline", "constexpr")]
    joined = " ".join(cleaned)
    if joined in TYPE_SIZES:
        return TYPE_SIZES[joined]
    if len(cleaned) == 1 and cleaned[0] in TYPE_SIZES:
        return TYPE_SIZES[cleaned[0]]
    if cleaned and cleaned[-1] in TYPE_SIZES and cleaned[0] in ("unsigned", "signed"):
        return TYPE_SIZES[cleaned[-1]]
    return None


def _literal_variables(tokens: Sequence[Token], macros: Dict[str, str]) -> Set[str]:
    """Biến chuỗi mà mọi phép gán đều là literal: dùng làm định dạng thì an toàn."""
    assigned: Dict[str, bool] = {}
    for statement in _split_on_semicolons(tokens):
        position = _assignment_index(statement)
        if position is None or position == 0:
            continue
        left = list(statement[:position])
        # `static const char msg[] = "..."` -- tên đứng trước nhóm ngoặc vuông.
        while left and left[-1].kind == OP and left[-1].text == "]":
            depth = 0
            for cut in range(len(left) - 1, -1, -1):
                if left[cut].text == "]":
                    depth += 1
                elif left[cut].text == "[":
                    depth -= 1
                    if depth == 0:
                        left = left[:cut]
                        break
            else:
                break
        target = _last_name(left)
        if target is None:
            continue
        right = statement[position + 1 :]
        literal = _is_safe_format(right, macros, set(), set())
        assigned[target] = assigned.get(target, True) and literal
    return {name for name, literal in assigned.items() if literal}


def _assignment_index(statement: Sequence[Token]) -> Optional[int]:
    depth = 0
    for index, token in enumerate(statement):
        if token.kind != OP:
            continue
        if token.text in "([{":
            depth += 1
        elif token.text in ")]}":
            depth -= 1
        elif token.text == "=" and depth == 0:
            return index
    return None


def _last_name(tokens: Sequence[Token]) -> Optional[str]:
    """Tên được gán: `char *p` -> p; `s->buf` -> s.buf; `a[i]` -> None."""
    meaningful = [t for t in tokens if not (t.kind == OP and t.text in ("*", "&"))]
    if not meaningful:
        return None
    if meaningful[-1].kind == OP and meaningful[-1].text == "]":
        return None
    end = len(meaningful) - 1
    if meaningful[end].kind != IDENT:
        return None
    start = end
    while start >= 2 and meaningful[start - 1].kind == OP and meaningful[start - 1].text in (".", "->") and meaningful[start - 2].kind == IDENT:
        start -= 2
    chain, _ = _chain(meaningful, start)
    return chain


def _is_safe_format(
    tokens: Sequence[Token],
    macros: Dict[str, str],
    literal_names: Set[str],
    wrapper_params: Set[str],
) -> bool:
    tokens = [t for t in tokens]
    if not tokens:
        return False
    # Bỏ ngoặc bao ngoài.
    while tokens and tokens[0].kind == OP and tokens[0].text == "(":
        close = matching(tokens, 0)
        if close != len(tokens) - 1:
            break
        tokens = tokens[1:-1]
    if not tokens:
        return False
    # Toán tử ba ngôi: điều kiện không quan trọng, hai nhánh phải an toàn.
    question = _top_level(tokens, "?")
    if question is not None:
        colon = _top_level(tokens[question + 1 :], ":")
        if colon is None:
            return False
        colon += question + 1
        return _is_safe_format(tokens[question + 1 : colon], macros, literal_names, wrapper_params) and _is_safe_format(
            tokens[colon + 1 :], macros, literal_names, wrapper_params
        )
    first = tokens[0]
    if first.kind == IDENT and first.text in _GETTEXT and len(tokens) > 1 and tokens[1].text == "(":
        arguments, after = split_arguments(tokens, 1)
        if after != len(tokens):
            return False
        return any(_is_safe_format(arg, macros, literal_names, wrapper_params) for arg in arguments)
    if len(tokens) == 1 and first.kind == IDENT:
        name = first.text
        if name in literal_names or name in wrapper_params:
            return True
        if name in macros or (name.isupper() and len(name) > 1):
            return True
        return False
    saw_string = False
    for token in tokens:
        if token.kind == STRING:
            saw_string = True
            continue
        if token.kind == IDENT and (token.text in macros or token.text.isupper() or token.text.startswith("PRI") or token.text.startswith("SCN")):
            continue
        # `"usage: " LUA_QL("x") "\n"` -- macro dạng hàm nằm giữa các literal.
        if token.kind == OP and token.text in ("(", ")"):
            continue
        return False
    return saw_string


def _split_top_level(tokens: Sequence[Token], text: str) -> List[List[Token]]:
    parts: List[List[Token]] = [[]]
    depth = 0
    for token in tokens:
        if token.kind == OP:
            if token.text in "([{":
                depth += 1
            elif token.text in ")]}":
                depth -= 1
            elif token.text == text and depth == 0:
                parts.append([])
                continue
        parts[-1].append(token)
    return parts


def _top_level(tokens: Sequence[Token], text: str) -> Optional[int]:
    depth = 0
    for index, token in enumerate(tokens):
        if token.kind != OP:
            continue
        if token.text in "([{":
            depth += 1
        elif token.text in ")]}":
            depth -= 1
        elif token.text == text and depth == 0:
            return index
    return None


# ---------------------------------------------------------- phân tích một hàm


@dataclass
class _Guard:
    upper: bool = False
    lower: bool = False


class _FunctionAnalysis:
    """Một lượt tuyến tính qua thân hàm: vết nhiễm, phép kiểm, các luật ghi."""

    def __init__(self, file: _FileAnalysis, function: Function, report: bool = True) -> None:
        self.file = file
        self.function = function
        self.report = report
        self.builder = file.builder
        self.budget = file.budget
        self.arrays: Dict[str, ArrayInfo] = {}
        # Cùng một tên khai báo ở hai khối khác nhau với hai kích thước khác
        # nhau ( `char buf[4]` trong nhánh này, `char buf[6]` trong nhánh kia ):
        # không có bảng phạm vi khối thì không biết lời gọi nào thấy mảng nào,
        # nên tên đó bị loại hẳn khỏi các luật kích thước.
        self.ambiguous: Set[str] = set()
        self.declared_positions: Set[int] = set()
        self.types: Dict[str, Tuple[str, ...]] = {}
        self.tainted: Dict[str, Taint] = {}
        self.guards: Dict[str, _Guard] = {}
        self.read_counts: Dict[str, Tuple[str, bool]] = {}
        # n = fread(buf, 1, 64, f): n không vượt 64 dù nội dung do ai gửi.
        self.bounds: Dict[str, int] = {}
        self.terminated: Set[str] = set()
        self.literal_names: Set[str] = set(file.literal_globals)
        self.params = set(function.param_names)
        # Mảng khai báo trong thân hàm che mảng toàn cục cùng tên; tham số
        # dạng `char buf[64]` thật ra là con trỏ nên KHÔNG được coi là mảng.
        array_bytes: Dict[str, int] = {}
        self.local_names: Set[str] = set(self.params)
        _collect_arrays(
            function.body_tokens,
            file.evaluator,
            self.arrays,
            self.ambiguous,
            self.declared_positions,
            self.budget,
            self.types,
        )
        for param in function.params:
            for name in _param_names(param):
                self.types.setdefault(name, tuple(t.text for t in param if t.kind == IDENT or t.text == "*"))
        self.local_names |= set(self.types)
        for name, info in file.global_arrays.items():
            if name not in self.local_names and name not in self.arrays and name not in file.ambiguous:
                self.arrays[name] = info
        for name, info in self.arrays.items():
            if info.bytes is not None:
                array_bytes[name] = info.bytes
        self.evaluator = ConstantEvaluator(file.constants, file.macros, self.budget, array_bytes)
        self.literal_names |= _literal_variables(function.body_tokens, file.macros)
        if function.name in ("main", "wmain", "_tmain", "WinMain") and len(function.param_names) >= 2:
            self.tainted[function.param_names[1]] = Taint(ARGV, function.line, False)

    # ---------------------------------------------------------------- tra cứu

    def array_of(self, tokens: Sequence[Token]) -> Optional[Tuple[str, ArrayInfo]]:
        meaningful = [t for t in tokens if not (t.kind == OP and t.text in ("(", ")"))]
        if not meaningful:
            return None
        if meaningful[0].kind == OP and meaningful[0].text == "&":
            return None
        chain, after = _chain(meaningful, 0)
        if chain is None:
            return None
        if "." in chain:
            info = self._member_array(chain)
        else:
            if chain in self.ambiguous:
                return None
            info = self.arrays.get(chain)
        if info is None:
            return None
        if after == len(meaningful):
            return chain, info
        # names[i] của mảng hai chiều là một mảng con.
        if info.inner and meaningful[after].kind == OP and meaningful[after].text == "[":
            close = matching(meaningful, after)
            if close == len(meaningful) - 1:
                inner = info.inner
                return chain + "[]", ArrayInfo(inner[0], info.element_size, info.is_char, info.line, inner[1:])
        return None

    def _member_array(self, chain: str) -> Optional[ArrayInfo]:
        parts = chain.split(".")
        types = self.types.get(parts[0]) or (
            self.file.global_types.get(parts[0]) if parts[0] not in self.local_names else None
        )
        for member in parts[1:]:
            if types is None:
                return None
            struct = self.file.structs.get(_struct_name(types) or "")
            if struct is None or member in struct.ambiguous:
                return None
            if member == parts[-1]:
                return struct.arrays.get(member)
            types = struct.types.get(member)
        return None

    def taint_of(self, tokens: Sequence[Token]) -> Optional[Taint]:
        index = 0
        limit = len(tokens)
        found: Optional[Taint] = None
        while index < limit:
            token = tokens[index]
            if token.kind == IDENT and token.text == "sizeof":
                # sizeof không đọc giá trị
                if index + 1 < limit and tokens[index + 1].text == "(":
                    close = matching(tokens, index + 1)
                    index = (close if close is not None else limit) + 1
                    continue
            chain, after = _chain(tokens, index)
            if chain is None:
                index += 1
                continue
            if after < limit and tokens[after].text == "(" and _base(chain) in _INTEGER_PARSE:
                # strlen(x), atoi(x): kết quả là SỐ, mang vết nhiễm của đối số.
                close = matching(tokens, after)
                end = close if close is not None else limit
                inner = self.taint_of(tokens[after + 1 : end])
                if inner is not None:
                    kind = "length" if _base(chain) in ("strlen", "wcslen", "strnlen") else "number"
                    inner = replace(inner, kind=kind)
                    if found is None or (inner.strong and not found.strong):
                        found = inner
                index = end + 1
                continue
            taint = self._lookup(chain)
            if taint is not None and taint.kind == "data" and "." in chain and chain not in self.tainted:
                # Trường của một struct vừa fread()/recv() vào là con số
                # người gửi chọn ( img.width, hdr.len ).
                taint = replace(taint, kind="number")
            if taint is None and _base(chain) in ("getenv", "secure_getenv") and after < limit and tokens[after].text == "(":
                taint = Taint(ENVIRONMENT, token.line, False)
            if taint is None and _base(chain) in _WIRE_INTEGER and after < limit and tokens[after].text == "(":
                taint = Taint(NETWORK, token.line, True, "number")
            if taint is not None and (found is None or (taint.strong and not found.strong)):
                found = taint
            index = max(after, index + 1)
        return found

    def _lookup(self, chain: str) -> Optional[Taint]:
        taint = self.tainted.get(chain)
        if taint is not None:
            return taint
        prefix = chain
        while "." in prefix:
            prefix = prefix.rsplit(".", 1)[0]
            taint = self.tainted.get(prefix)
            if taint is not None:
                return taint
        return None

    def names_in(self, tokens: Sequence[Token]) -> List[str]:
        names: List[str] = []
        index = 0
        while index < len(tokens):
            chain, after = _chain(tokens, index)
            if chain is not None:
                names.append(chain)
                index = after
                continue
            index += 1
        return names

    def guarded_upper(self, tokens: Sequence[Token]) -> bool:
        for name in self.names_in(tokens):
            guard = self.guards.get(name)
            if guard is not None and guard.upper:
                return True
        return False

    def bounded_by(self, tokens: Sequence[Token], limit: Optional[int]) -> bool:
        if limit is None:
            return False
        names = self.names_in(tokens)
        return bool(names) and all(name in self.bounds and self.bounds[name] <= limit for name in names)

    def is_integer(self, name: str) -> bool:
        words = set(self.types.get(name, ()))
        if not words or "*" in words or "[]" in words:
            return False
        return bool(words & (_SIGNED_WORDS | _UNSIGNED_WORDS))

    def is_narrow(self, name: str) -> bool:
        words = set(self.types.get(name, ()) or self.file.global_types.get(name, ()))
        if not words or "*" in words or "[]" in words:
            return False
        return bool(words & _NARROW_WORDS) and "long" not in words

    def is_signed(self, name: str) -> bool:
        words = set(self.types.get(name, ()))
        if not words or "*" in words:
            return False
        if words & _UNSIGNED_WORDS:
            return False
        return bool(words & _SIGNED_WORDS)

    def constant(self, tokens: Sequence[Token]) -> Optional[int]:
        return self.evaluator.evaluate([t for t in tokens])

    # ---------------------------------------------------------------- lượt chính

    def run(self) -> None:
        statements = _split_on_semicolons(self.function.body_tokens)
        for statement in statements:
            self.budget.spend()
            self._record_guards(statement)
            self._check_statement(statement)
            self._propagate(statement)
        self._check_loops(self.function.body)

    def out_taints(self) -> Dict[int, List[Tuple[str, Taint]]]:
        result: Dict[int, List[Tuple[str, Taint]]] = {}
        for index, param in enumerate(self.function.param_names):
            if index >= len(self.function.params):
                break
            texts = [t.text for t in self.function.params[index]]
            if "*" not in texts and "&" not in texts and "[" not in texts:
                continue
            if param in self.guards and self.guards[param].upper:
                continue
            for key, taint in sorted(self.tainted.items()):
                if key != param and not key.startswith(param + "."):
                    continue
                if key in self.guards and self.guards[key].upper:
                    continue
                result.setdefault(index, []).append((key[len(param) :], taint))
        return result

    def _record_guards(self, statement: Sequence[Token]) -> None:
        for index, token in enumerate(statement):
            if token.kind == OP and token.text in ("==", "!=") and self.read_counts:
                # if (ret == sizeof(buf)) return;  -- đã chặn trường hợp đọc đầy.
                for side in (_operand_before(statement, index), _operand_after(statement, index)):
                    if len(side) == 1 and side[0].text in self.read_counts:
                        buffer_name, _full = self.read_counts[side[0].text]
                        self.read_counts[side[0].text] = (buffer_name, False)
                continue
            if token.kind != OP or token.text not in ("<", ">", "<=", ">="):
                continue
            left = _operand_before(statement, index)
            right = _operand_after(statement, index)
            for side, other, is_left in ((left, right, True), (right, left, False)):
                for name in self.names_in(side):
                    guard = self.guards.setdefault(name, _Guard())
                    smaller = (token.text in ("<", "<=")) == is_left
                    # name < X  ( hoặc X > name ): chặn trên. name > 0: chặn dưới.
                    other_value = self.constant(other) if other else None
                    unsigned_cast = any(t.text in ("size_t", "unsigned") for t in side)
                    if other_value is not None and other_value <= 1:
                        # len < 0, n <= 0, len >= 0: kiểm cận dưới, không phải trần.
                        guard.lower = True
                    else:
                        guard.upper = True
                        if smaller and unsigned_cast:
                            guard.lower = True
            # size_needed > sizeof(out) - 1: có người đã đo trước khi ghi vào out.
            for side in (left, right):
                for position, item in enumerate(side):
                    if item.kind == IDENT and item.text == "sizeof" and position + 1 < len(side):
                        inner = side[position + 2 :] if side[position + 1].text == "(" else side[position + 1 :]
                        chain, _ = _chain(inner, 0)
                        if chain is not None:
                            self.guards.setdefault("sizeof:" + chain, _Guard()).upper = True
            # strlen(x) < N cũng là phép kiểm cho chính x
            for side in (left, right):
                if len(side) >= 4 and side[0].text in ("strlen", "wcslen", "strnlen"):
                    inner = side[2:-1]
                    for name in self.names_in(inner):
                        self.guards.setdefault("strlen:" + name, _Guard()).upper = True
        for index, token in enumerate(statement):
            if token.kind == IDENT and token.text in _BOUNDING_CALLS and index + 1 < len(statement) and statement[index + 1].text == "(":
                arguments, _ = split_arguments(statement, index + 1)
                for argument in arguments:
                    for name in self.names_in(argument):
                        self.guards.setdefault(name, _Guard()).upper = True

    def _propagate(self, statement: Sequence[Token]) -> None:
        # Hàm đổ dữ liệu vào đối số
        for index, token in enumerate(statement):
            if token.kind != IDENT:
                continue
            chain, after = _chain(statement, index)
            if chain is None or after >= len(statement) or statement[after].text != "(":
                continue
            name = _base(chain)
            arguments, _ = split_arguments(statement, after)
            fill = _INPUT_FILL.get(name)
            if fill is not None and len(arguments) > fill[0]:
                target = _target_name(arguments[fill[0]])
                if target is not None:
                    # read(fd, &n, sizeof n): con số người gửi chọn, không phải chuỗi.
                    kind = "number" if self.is_integer(target) else "data"
                    self.tainted[target] = Taint(fill[1], token.line, True, kind)
            scanf = _SCANF.get(name)
            if scanf is not None and scanf >= 0 and len(arguments) > scanf and _is_literal_string(arguments[scanf]):
                strong = name != "sscanf" and name != "swscanf"
                source_taint = None
                if not strong and arguments:
                    source_taint = self.taint_of(arguments[0])
                if strong or source_taint is not None:
                    text = "".join(t.text for t in arguments[scanf] if t.kind == STRING)
                    targets = arguments[scanf + 1 :]
                    cursor = 0
                    for conversion, _width, suppressed, _allocating in _scanf_directives(text):
                        if suppressed:
                            continue
                        argument = targets[cursor] if cursor < len(targets) else None
                        cursor += 1
                        # %n chỉ là số ký tự đã đọc, không phải giá trị người gửi chọn.
                        if argument is None or conversion == "n":
                            continue
                        target = _target_name(argument)
                        if target is None:
                            continue
                        base = source_taint or Taint(INPUT, token.line, True)
                        kind = "data" if conversion in ("s", "[", "c") else "number"
                        self.tainted[target] = replace(base, kind=kind)
            summary = self.file.taint_summaries.get(name)
            if summary is not None and name != self.function.name:
                for position, entries in summary.items():
                    if position >= len(arguments):
                        continue
                    target = _target_name(arguments[position])
                    if target is None:
                        continue
                    for suffix, taint in entries:
                        self.tainted[target + suffix] = replace(taint, line=token.line)
            dest = _PROPAGATE.get(name)
            if dest is not None and len(arguments) > dest + 1:
                taint = self.taint_of([t for arg in arguments[dest + 1 :] for t in arg])
                target = _target_name(arguments[dest])
                if target is not None:
                    if taint is not None:
                        self.tainted[target] = taint
        # std::cin >> x
        for index, token in enumerate(statement):
            if token.kind == IDENT and token.text == "cin":
                cursor = index + 1
                while cursor + 1 < len(statement) and statement[cursor].text == ">>":
                    target, after = _chain(statement, cursor + 1)
                    if target is None:
                        break
                    kind = "number" if self.is_integer(target) else "data"
                    self.tainted[target] = Taint(INPUT, token.line, True, kind)
                    cursor = after
        position = _assignment_index(statement)
        compound = None
        if position is None:
            for index, token in enumerate(statement):
                if token.kind == OP and token.text in ("+=", "-=", "*=", "<<="):
                    compound = index
                    break
        if position is None and compound is None:
            return
        split = position if position is not None else compound
        assert split is not None
        target = _last_name(statement[:split])
        if target is None:
            return
        right = statement[split + 1 :]
        if compound is not None:
            return
        if right and right[0].kind == IDENT and right[0].text in _BOUNDING_CALLS:
            self.tainted.pop(target, None)
            return
        self.bounds.pop(target, None)
        # n = read(fd, buf, sizeof buf) -- ghi nhớ để bắt buf[n] = 0
        if len(right) > 2 and right[0].kind == IDENT and _base(right[0].text) in ("read", "recv", "recvfrom", "fread", "readlink", "pread") and right[1].text == "(":
            self._remember_read_count(target, right)
        taint = self.taint_of(right)
        if taint is not None and self._bounded_difference(right):
            # rem = 40 - nread sau khi đã kiểm nread < 40: nằm gọn trong [0, 40].
            self.tainted.pop(target, None)
            self.guards[target] = _Guard(upper=True, lower=True)
            return
        if taint is not None and not _masks(right):
            arithmetic = [t for t in _top_level_tokens(right) if t.kind == OP and t.text in ("*", "+", "<<")]
            if arithmetic and taint.kind == "number" and not self.guarded_upper(right):
                # size = a * b với a, b từ dữ liệu ngoài: tràn xảy ra NGAY ở
                # phép gán này, còn malloc(size) phía sau chỉ nhận kết quả.
                taint = replace(
                    taint,
                    kind="product" if any(t.text in ("*", "<<") for t in arithmetic) else "sum",
                )
            self.tainted[target] = taint
            self.guards.pop(target, None)
        else:
            self.tainted.pop(target, None)
            if right and _base(right[0].text) not in ("read", "recv", "recvfrom", "fread", "readlink", "pread"):
                self.read_counts.pop(target, None)

    def _bounded_difference(self, right: Sequence[Token]) -> bool:
        top = {id(t) for t in _top_level_tokens(right)}
        for position, token in enumerate(right):
            if id(token) in top and token.kind == OP and token.text == "-" and position > 0:
                if self.constant(right[:position]) is None:
                    return False
                names = self.names_in(right[position + 1 :])
                return bool(names) and all(name in self.guards and self.guards[name].upper for name in names)
        return False

    def _remember_read_count(self, target: str, right: Sequence[Token]) -> None:
        name = _base(right[0].text)
        arguments, _ = split_arguments(right, 1)
        spec = _SIZED_WRITE.get(name)
        if spec is None or len(arguments) <= max(spec[1]) or len(arguments) <= spec[0]:
            return
        found = self.array_of(arguments[spec[0]])
        if found is None:
            return
        buffer_name, info = found
        size_tokens = arguments[spec[1][0]]
        if len(spec[1]) > 1:
            first = self.constant(arguments[spec[1][0]])
            second = self.constant(arguments[spec[1][1]])
            if first != 1 or second is None:
                return
            requested = second
        else:
            requested = self.constant(size_tokens)
        if requested is None or info.bytes is None:
            return
        self.read_counts[target] = (buffer_name, requested >= info.bytes)
        self.bounds[target] = requested
        self.guards.pop(target, None)
        self.tainted[target] = Taint(INPUT, right[0].line, True)

    # ------------------------------------------------------------ các luật ghi

    def _check_statement(self, statement: Sequence[Token]) -> None:
        index = 0
        limit = len(statement)
        while index < limit:
            token = statement[index]
            if token.kind == IDENT:
                chain, after = _chain(statement, index)
                if chain is not None and after < limit and statement[after].kind == OP and statement[after].text == "(":
                    arguments, _ = split_arguments(statement, after)
                    self._check_call(_base(chain), token, arguments, statement, index)
                if chain is not None and after < limit and statement[after].kind == OP and statement[after].text == "[":
                    self._check_index(chain, statement, index, after)
                if chain is not None and _base(chain) == "cin":
                    self._check_cin(statement, after - 1)
                index = max(after, index + 1) if chain is not None else index + 1
                continue
            index += 1

    def _report(
        self,
        rule_id: str,
        anchor: Token,
        symbol: str,
        message: str,
        severity: Severity,
        confidence: Confidence,
        source: Optional[Taint] = None,
        sink_label: str = "",
    ) -> None:
        if not self.report:
            return
        trace = []
        if source is not None:
            trace.append(self.builder.step(StepKind.SOURCE, source.line, 0, "%s đi vào từ đây" % source.label))
        trace.append(self.builder.step(StepKind.SINK, anchor.line, anchor.column, sink_label or message))
        self.builder.add(
            rule_id=rule_id,
            line=anchor.line,
            column=anchor.column,
            symbol=symbol,
            message=message,
            end_line=anchor.line,
            end_column=anchor.column + len(anchor.text),
            severity=severity,
            confidence=confidence,
            trace=tuple(trace),
        )

    def _severity_for(self, taint: Optional[Taint]) -> Tuple[Severity, Confidence]:
        if taint is None:
            return Severity.MEDIUM, Confidence.MEDIUM
        if taint.strong:
            return Severity.CRITICAL, Confidence.HIGH
        return Severity.HIGH, Confidence.HIGH

    def _check_call(
        self,
        name: str,
        anchor: Token,
        arguments: List[List[Token]],
        statement: Sequence[Token],
        position: int,
    ) -> None:
        if name == "gets" and arguments:
            self._report(
                "FSB-MEM-001",
                anchor,
                name,
                "gets() đọc một dòng không giới hạn độ dài vào bộ đệm; hàm này đã bị gỡ khỏi C11",
                Severity.CRITICAL,
                Confidence.CERTAIN,
                Taint(INPUT, anchor.line, True),
            )
            return
        if name in _UNBOUNDED_COPY:
            self._check_unbounded(name, anchor, arguments)
        if name in ("sprintf", "vsprintf"):
            self._check_sprintf(name, anchor, arguments)
        if name in _SCANF:
            self._check_scanf(name, anchor, arguments)
        if name in _SIZED_WRITE:
            self._check_sized(name, anchor, arguments)
        if name in _ALLOCATORS:
            self._check_allocation(name, anchor, arguments)
        if name in _PRINTF_FORMAT:
            self._check_format(name, anchor, arguments)
        if name == "strncpy" and len(arguments) == 3:
            self._check_strncpy_termination(anchor, arguments, statement)
        if name == "strncat" and len(arguments) == 3:
            self._check_strncat(anchor, arguments)

    def _check_strncat(self, anchor: Token, arguments: List[List[Token]]) -> None:
        """strncat(d, s, n) ghi n ký tự RỒI thêm ký tự kết thúc: n phải chừa chỗ cho nó.

        Hai cách viết sai phổ biến nhất đều lệch đúng một byte: truyền nguyên
        sizeof(d), và truyền sizeof(d) - strlen(d) mà quên trừ thêm 1.
        """
        found = self.array_of(arguments[0])
        if found is None:
            return
        destination, info = found
        if info.element_size not in (None, 1):
            return
        size = arguments[2]
        value = self.constant(size)
        texts = [t.text for t in size]
        wrong = False
        if value is not None and value >= info.count:
            wrong = True
        elif "strlen" in texts and texts.count("-") == 1:
            minus = texts.index("-")
            left = self.constant(size[:minus])
            if left is not None and left >= info.count:
                wrong = True
        if wrong:
            self._report(
                "FSB-MEM-006",
                anchor,
                "strncat",
                "strncat() thêm ký tự kết thúc SAU n ký tự, nên giới hạn %s cho %s[%d] vượt một byte"
                % (" ".join(texts), destination, info.count),
                Severity.HIGH,
                Confidence.HIGH,
            )

    def _check_unbounded(self, name: str, anchor: Token, arguments: List[List[Token]]) -> None:
        destination_index, source_index = _UNBOUNDED_COPY[name]
        if len(arguments) <= max(destination_index, source_index):
            return
        found = self.array_of(arguments[destination_index])
        if found is None:
            return
        destination, info = found
        source = arguments[source_index]
        literal = _string_length(source)
        if literal is None and len(source) == 1 and source[0].kind == IDENT:
            literal = self._macro_string_length(source[0].text)
        if literal is not None:
            if name in _APPENDS:
                return
            if literal + 1 > info.count:
                self._report(
                    "FSB-MEM-001",
                    anchor,
                    name,
                    "%s() chép chuỗi literal %d byte ( kể cả ký tự kết thúc ) vào %s chỉ có %d phần tử"
                    % (name, literal + 1, destination, info.count),
                    Severity.HIGH,
                    Confidence.HIGH,
                )
            return
        other = self.array_of(source)
        if other is not None and other[1].count <= info.count and name not in _APPENDS:
            return
        source_names = self.names_in(source)
        if any(self.guards.get("strlen:" + n) for n in source_names):
            return
        taint = self.taint_of(source)
        if taint is None and other is None and self.guards.get("sizeof:" + destination):
            return
        severity, confidence = self._severity_for(taint)
        if taint is None and other is not None:
            message = "%s() chép %s ( %d phần tử ) vào %s chỉ có %d phần tử" % (
                name,
                other[0],
                other[1].count,
                destination,
                info.count,
            )
            severity, confidence = Severity.HIGH, Confidence.HIGH
        elif taint is not None:
            message = "%s chảy vào %s() và bị chép không giới hạn vào %s[%d]" % (
                taint.label,
                name,
                destination,
                info.count,
            )
        else:
            message = "%s() chép một chuỗi không rõ độ dài vào %s[%d] mà không kiểm độ dài trước" % (
                name,
                destination,
                info.count,
            )
        self._report("FSB-MEM-001", anchor, name, message, severity, confidence, taint)

    def _check_sprintf(self, name: str, anchor: Token, arguments: List[List[Token]]) -> None:
        if len(arguments) < 2:
            return
        found = self.array_of(arguments[0])
        if found is None:
            return
        destination, info = found
        if not _is_literal_string(arguments[1]):
            return
        directives = _format_directives("".join(t.text for t in arguments[1] if t.kind == STRING))
        if directives is None:
            return
        static, items = directives
        total = static
        unbounded: Optional[List[Token]] = None
        tainted_bounded: Optional[Taint] = None
        values = arguments[2:]
        cursor = 0
        for conversion, width, precision in items:
            argument = values[cursor] if cursor < len(values) else []
            if conversion != "%":
                cursor += 1
            if conversion == "%":
                total += 1
                continue
            if conversion == "s":
                if precision is not None:
                    total += max(precision, width or 0)
                    continue
                length = _string_length(argument)
                if length is None:
                    array = self.array_of(argument)
                    if array is not None:
                        length = array[1].count - 1
                        tainted_bounded = tainted_bounded or self.taint_of(argument)
                if length is None:
                    unbounded = argument
                    continue
                total += max(length, width or 0)
                continue
            total += max(_numeric_width(conversion), width or 0)
        if unbounded is not None:
            names = self.names_in(unbounded)
            if any(self.guards.get("strlen:" + n) for n in names):
                return
            taint = self.taint_of(unbounded)
            if taint is None and self.guards.get("sizeof:" + destination):
                return
            severity, confidence = self._severity_for(taint)
            label = taint.label if taint is not None else "một chuỗi không rõ độ dài"
            self._report(
                "FSB-MEM-001",
                anchor,
                name,
                "%s đi vào %%s của %s() không có giới hạn độ chính xác, ghi vào %s[%d]"
                % (label, name, destination, info.count),
                severity,
                confidence,
                taint,
            )
            return
        if total + 1 > info.count and tainted_bounded is not None:
            self._report(
                "FSB-MEM-001",
                anchor,
                name,
                "%s đi vào %%s của %s(); với độ dài tối đa của nó, kết quả dài tới %d byte trong khi %s chỉ có %d phần tử"
                % (tainted_bounded.label, name, total + 1, destination, info.count),
                Severity.HIGH,
                Confidence.HIGH,
                tainted_bounded,
            )
            return
        if total + 1 > info.count:
            self._report(
                "FSB-MEM-001",
                anchor,
                name,
                "%s() có thể ghi tới %d byte ( kể cả ký tự kết thúc ) vào %s chỉ có %d phần tử"
                % (name, total + 1, destination, info.count),
                Severity.MEDIUM,
                Confidence.MEDIUM,
            )

    def _check_scanf(self, name: str, anchor: Token, arguments: List[List[Token]]) -> None:
        format_index = _SCANF[name]
        if format_index < 0 or len(arguments) <= format_index:
            return
        fmt = arguments[format_index]
        if not _is_literal_string(fmt):
            return
        text = "".join(t.text for t in fmt if t.kind == STRING)
        targets = arguments[format_index + 1 :]
        cursor = 0
        strong = name not in ("sscanf", "swscanf")
        source_taint = Taint(INPUT, anchor.line, True) if strong else (self.taint_of(arguments[0]) if arguments else None)
        for conversion, width, suppressed, allocating in _scanf_directives(text):
            if suppressed:
                continue
            target = targets[cursor] if cursor < len(targets) else None
            cursor += 1
            if target is None or allocating or conversion not in ("s", "["):
                continue
            found = self.array_of(target)
            if width is None:
                severity, confidence = self._severity_for(source_taint)
                if found is None and source_taint is None:
                    continue
                self._report(
                    "FSB-MEM-001",
                    anchor,
                    name,
                    "%s() đọc %%%s không có độ rộng vào %s, không có giới hạn nào cho số byte ghi"
                    % (name, conversion, found[0] if found else "bộ đệm"),
                    severity if found else Severity.HIGH,
                    confidence if found else Confidence.MEDIUM,
                    source_taint,
                )
            elif found is not None and width + 1 > found[1].count:
                self._report(
                    "FSB-MEM-001",
                    anchor,
                    name,
                    "%s() cho phép %%%d%s ghi %d byte vào %s chỉ có %d phần tử"
                    % (name, width, conversion, width + 1, found[0], found[1].count),
                    Severity.HIGH,
                    Confidence.HIGH,
                    source_taint,
                )

    def _check_sized(self, name: str, anchor: Token, arguments: List[List[Token]]) -> None:
        destination_index, size_indexes = _SIZED_WRITE[name]
        if len(arguments) <= max((destination_index,) + size_indexes):
            return
        found = self.array_of(arguments[destination_index])
        if found is None:
            return
        destination, info = found
        size_tokens = arguments[size_indexes[-1]]
        if len(size_indexes) == 2:
            unit = self.constant(arguments[size_indexes[0]])
            if unit is None:
                return
        else:
            unit = 1
        capacity = info.bytes if name not in ("strncpy", "strlcpy", "strlcat", "fgets", "snprintf", "vsnprintf") else info.count
        if name in ("strncpy", "strlcpy", "strlcat", "fgets", "snprintf", "vsnprintf") and info.element_size not in (None, 1):
            return
        value = self.constant(size_tokens)
        if value is not None:
            if capacity is not None and value * unit > capacity:
                self._report(
                    "FSB-MEM-001",
                    anchor,
                    name,
                    "%s() được phép ghi %d byte vào %s chỉ có %d byte"
                    % (name, value * unit, destination, capacity),
                    Severity.HIGH,
                    Confidence.HIGH,
                )
            return
        if name in ("snprintf", "vsnprintf", "strlcpy", "strlcat"):
            return
        # Độ dài không phải hằng.
        size_names = self.names_in(size_tokens)
        if self._strlen_of_unbounded(size_tokens):
            source = size_tokens[2:]
            close = matching(size_tokens, 1)
            inner = size_tokens[2:close] if close is not None else source
            if any(self.guards.get("strlen:" + n) or (self.guards.get(n) and self.guards[n].upper) for n in self.names_in(inner)):
                return
            taint = self.taint_of(inner)
            severity, confidence = self._severity_for(taint)
            self._report(
                "FSB-MEM-001",
                anchor,
                name,
                "%s() chép strlen() của một chuỗi không rõ độ dài vào %s[%d] mà không kiểm trước"
                % (name, destination, info.count),
                severity,
                confidence,
                taint,
            )
            return
        taint = self.taint_of(size_tokens)
        if taint is None:
            return
        if capacity is not None and self.bounded_by(size_tokens, capacity // max(unit, 1)):
            return
        upper = self.guarded_upper(size_tokens)
        if not upper:
            severity, confidence = self._severity_for(taint)
            self._report(
                "FSB-MEM-001",
                anchor,
                name,
                "độ dài của %s() lấy từ %s mà không được so với kích thước %s ( %s byte )"
                % (name, taint.label, destination, capacity if capacity is not None else "?"),
                severity,
                confidence,
                taint,
            )
            return
        for size_name in size_names:
            guard = self.guards.get(size_name)
            if guard is not None and guard.upper and not guard.lower and self.is_signed(size_name):
                self._report(
                    "FSB-MEM-005",
                    anchor,
                    name,
                    "%s là số có dấu lấy từ %s, chỉ bị chặn trên: một giá trị âm lọt qua phép "
                    "so sánh rồi thành độ dài khổng lồ khi tới %s()" % (size_name, taint.label, name),
                    Severity.HIGH,
                    Confidence.MEDIUM if not taint.strong else Confidence.HIGH,
                    taint,
                )
                return

    def _macro_string_length(self, name: str) -> Optional[int]:
        text = self.file.macros.get(name)
        if not text:
            return None
        stripped = text.strip()
        while stripped.startswith("(") and stripped.endswith(")"):
            stripped = stripped[1:-1].strip()
        if not stripped.startswith('"'):
            return None
        total = 0
        cursor = 0
        while cursor < len(stripped):
            if stripped[cursor] in " \t":
                cursor += 1
                continue
            if stripped[cursor] != '"':
                return None
            decoded = decode_c_literal(stripped, cursor)
            if decoded is None:
                return None
            total += len(decoded)
            # tìm dấu nháy đóng
            end = cursor + 1
            while end < len(stripped):
                if stripped[end] == "\\":
                    end += 2
                    continue
                if stripped[end] == '"':
                    break
                end += 1
            cursor = end + 1
        return total

    def _strlen_of_unbounded(self, tokens: Sequence[Token]) -> bool:
        if len(tokens) < 4 or tokens[0].kind != IDENT or tokens[0].text not in ("strlen", "wcslen"):
            return False
        if tokens[1].text != "(":
            return False
        close = matching(tokens, 1)
        if close is None:
            return False
        rest = tokens[close + 1 :]
        if rest and not (len(rest) == 2 and rest[0].text == "+" and rest[1].kind == NUMBER):
            return False
        inner = tokens[2:close]
        if _is_literal_string(inner) or self.array_of(inner) is not None:
            return False
        return True

    def _check_allocation(self, name: str, anchor: Token, arguments: List[List[Token]]) -> None:
        index = _ALLOCATORS[name]
        if len(arguments) <= index:
            return
        size = arguments[index]
        operators = [t for t in _top_level_tokens(size) if t.kind == OP and t.text in ("*", "+", "<<")]
        if not operators:
            names = self.names_in(size)
            if len(names) == 1 and len([t for t in size if t.kind != OP or t.text not in "()"]) <= 3:
                carried = self.tainted.get(names[0])
                if carried is not None and carried.kind in ("product", "sum") and not self.guarded_upper(size):
                    if carried.kind == "sum" and not carried.strong:
                        return
                    self._report(
                        "FSB-MEM-005",
                        anchor,
                        name,
                        "%s được tính bằng %s trên số lấy từ %s mà không kiểm tràn, rồi dùng làm kích "
                        "thước cấp phát của %s(): kết quả quấn vòng cho ra vùng nhớ nhỏ hơn dữ liệu"
                        % (names[0], "phép nhân" if carried.kind == "product" else "phép cộng", carried.label, name),
                        Severity.HIGH if carried.strong else Severity.MEDIUM,
                        Confidence.HIGH if carried.strong else Confidence.MEDIUM,
                        carried,
                    )
            return
        multiplies = any(o.text in ("*", "<<") for o in operators)
        for operand in _operands(size):
            taint = self.taint_of(operand)
            if taint is None or taint.kind not in ("number", "product", "sum"):
                continue
            # Cộng vài byte vào một số 32 bit đọc từ dây là quấn vòng thật;
            # cộng vào atoi(argv[1]) thì chỉ người chạy chương trình tự hại mình.
            if not multiplies and not taint.strong:
                continue
            if self.guarded_upper(operand):
                continue
            if self.constant(operand) is not None:
                continue
            names = self.names_in(operand)
            if len(names) == 1 and self.is_narrow(names[0]):
                continue
            self._report(
                "FSB-MEM-005",
                anchor,
                name,
                "kích thước cấp phát của %s() được tính bằng %s từ %s mà không kiểm tràn: phép "
                "tính quấn vòng sẽ cấp ra vùng nhớ nhỏ hơn dữ liệu ghi vào sau đó"
                % (name, "phép nhân" if any(o.text in ("*", "<<") for o in operators) else "phép cộng", taint.label),
                # argv/getenv: người chạy chương trình tự đưa số vào, chỉ đáng kể với chương trình setuid.
                Severity.HIGH if taint.strong else Severity.MEDIUM,
                Confidence.HIGH if taint.strong else Confidence.MEDIUM,
                taint,
            )
            return

    def _check_format(self, name: str, anchor: Token, arguments: List[List[Token]]) -> None:
        index = _PRINTF_FORMAT[name]
        if len(arguments) <= index:
            return
        fmt = arguments[index]
        if name == "swprintf" and len(arguments) > 1 and _is_literal_string(arguments[1]):
            # swprintf(buf, L"%s", x) kiểu MSVC cũ: định dạng ở vị trí 1.
            return
        wrapper: Set[str] = {
            param for param in self.function.param_names if "fmt" in param.lower() or "format" in param.lower()
        }
        if self.function.variadic or name in _VA_LIST_PRINTF:
            wrapper = set(self.function.param_names)
        if _is_safe_format(fmt, self.file.macros, self.literal_names, wrapper):
            return
        if len(fmt) == 1 and fmt[0].kind == IDENT and fmt[0].text in ("NULL", "nullptr"):
            return
        taint = self.taint_of(fmt)
        if taint is None and len(fmt) == 1 and fmt[0].kind == IDENT and "[]" in self.types.get(fmt[0].text, ()):
            # Mảng cục bộ do chính chương trình dựng định dạng vào ( như cách
            # string.format của Lua làm ): không có vết nhiễm thì không báo.
            return
        if taint is not None:
            severity, confidence = Severity.CRITICAL if taint.strong else Severity.HIGH, Confidence.HIGH
            message = "%s được dùng làm chuỗi định dạng của %s(); %%n trong đó ghi được vào bộ nhớ" % (
                taint.label,
                name,
            )
        else:
            severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
            message = "chuỗi định dạng của %s() là một giá trị thay đổi được, không phải literal" % name
        self._report("FSB-MEM-002", anchor, name, message, severity, confidence, taint)

    def _check_strncpy_termination(
        self, anchor: Token, arguments: List[List[Token]], statement: Sequence[Token]
    ) -> None:
        found = self.array_of(arguments[0])
        if found is None:
            return
        destination, info = found
        if info.element_size not in (None, 1):
            return
        value = self.constant(arguments[2])
        if value is None or value != info.count:
            return
        literal = _string_length(arguments[1])
        if literal is not None and literal < value:
            # strncpy đệm số 0 tới đủ n byte: nguồn ngắn hơn thì luôn có ký tự kết thúc.
            return
        # Có ghi ký tự kết thúc ở phần sau của hàm không?
        body = self.function.body_tokens
        start = next((i for i, t in enumerate(body) if t is anchor), None)
        if start is None:
            return
        for cursor in range(start, len(body) - 2):
            token = body[cursor]
            if token.kind == IDENT and token.text == destination and body[cursor + 1].text == "[":
                close = matching(body, cursor + 1)
                if close is not None and close + 1 < len(body) and body[close + 1].text == "=":
                    return
        self._report(
            "FSB-MEM-006",
            anchor,
            "strncpy",
            "strncpy() chép tối đa sizeof(%s) byte nên không đặt ký tự kết thúc khi nguồn đủ dài; "
            "hàm không ghi %s[sizeof %s - 1] = 0 ở phía sau" % (destination, destination, destination),
            Severity.MEDIUM,
            Confidence.MEDIUM,
        )

    def _check_index(self, chain: str, statement: Sequence[Token], index: int, bracket: int) -> None:
        if id(statement[bracket]) in self.declared_positions:
            return
        if index > 0 and statement[index - 1].kind == OP and statement[index - 1].text == "&":
            return
        if _inside_sizeof(statement, index):
            return
        found = self.array_of(statement[index:bracket])
        if found is None:
            return
        name, info = found
        close = matching(statement, bracket)
        if close is None:
            return
        inner = statement[bracket + 1 : close]
        is_write = close + 1 < len(statement) and statement[close + 1].kind == OP and statement[close + 1].text in ("=", "+=", "-=", "|=", "&=", "++", "--")
        anchor = statement[index]
        value = self.constant(inner)
        if value is not None:
            if value == info.count:
                self._report(
                    "FSB-MEM-006",
                    anchor,
                    name,
                    "%s[%d] nằm ngay sau phần tử cuối của mảng %d phần tử" % (name, value, info.count),
                    Severity.HIGH if is_write else Severity.MEDIUM,
                    Confidence.HIGH,
                )
            elif value > info.count:
                self._report(
                    "FSB-MEM-001",
                    anchor,
                    name,
                    "%s[%d] vượt ra ngoài mảng %d phần tử" % (name, value, info.count),
                    Severity.HIGH,
                    Confidence.HIGH,
                )
            return
        if len(inner) == 1 and inner[0].kind == IDENT and inner[0].text in self.read_counts:
            buffer_name, full = self.read_counts[inner[0].text]
            guard = self.guards.get(inner[0].text)
            if buffer_name == name and full and (guard is None or not guard.upper) and is_write:
                self._report(
                    "FSB-MEM-006",
                    anchor,
                    name,
                    "%s là số byte vừa đọc vào %s với giới hạn bằng ĐÚNG kích thước mảng, nên %s[%s] "
                    "ghi ra ngoài mảng khi lần đọc lấp đầy bộ đệm ( và vào %s[-1] khi hàm đọc trả -1 )"
                    % (inner[0].text, name, name, inner[0].text, name),
                    Severity.HIGH,
                    Confidence.HIGH,
                )
            return
        taint = self.taint_of(inner)
        if taint is None or self.guarded_upper(inner):
            return
        if self.bounded_by(inner, info.count - 1):
            return
        # buf[strlen(buf) - 1]: độ dài của chính chuỗi nằm trong mảng thì
        # không vượt được mảng đó.
        if taint.kind == "length":
            return
        if not is_write and not taint.strong:
            return
        severity, confidence = self._severity_for(taint)
        if not is_write:
            severity = Severity.MEDIUM
        self._report(
            "FSB-MEM-001",
            anchor,
            name,
            "chỉ số của %s lấy từ %s mà không được so với kích thước mảng ( %d phần tử )"
            % (name, taint.label, info.count),
            severity,
            confidence,
            taint,
        )

    def _check_cin(self, statement: Sequence[Token], index: int) -> None:
        cursor = index + 1
        while cursor + 1 < len(statement) and statement[cursor].text == ">>":
            target, after = _chain(statement, cursor + 1)
            if target is None:
                return
            found = self.array_of(statement[cursor + 1 : after])
            if found is not None and found[1].is_char:
                if not any(t.text == "setw" for t in statement[:cursor]):
                    self._report(
                        "FSB-MEM-001",
                        statement[cursor + 1],
                        "cin",
                        "cin >> %s đọc một từ không giới hạn độ dài vào mảng %d byte" % (found[0], found[1].count),
                        Severity.CRITICAL,
                        Confidence.HIGH,
                        Taint(INPUT, statement[index].line, True),
                    )
            cursor = after

    # -------------------------------------------------------- vòng lặp lệch một

    def _check_loops(self, statements: Sequence[Stmt]) -> None:
        for statement in _walk(statements):
            self.budget.spend()
            if statement.kind != "loop" or statement.label != "for":
                continue
            bound = _inclusive_bound(statement.tokens)
            if bound is None:
                continue
            variable, limit_tokens = bound
            for access_name, info, anchor in self._accesses(statement.body, variable):
                expected = self._bound_matches(limit_tokens, access_name, info)
                if not expected:
                    continue
                self._report(
                    "FSB-MEM-006",
                    anchor,
                    access_name,
                    "vòng lặp chạy tới %s <= %s nên lần lặp cuối truy cập %s[%d], ngay sau phần tử "
                    "cuối của mảng" % (variable, " ".join(t.text for t in limit_tokens), access_name, info.count),
                    Severity.HIGH,
                    Confidence.HIGH,
                )
                break

    def _bound_matches(self, limit_tokens: Sequence[Token], name: str, info: ArrayInfo) -> bool:
        value = self.constant(limit_tokens)
        if value is not None and value == info.count:
            return True
        texts = [t.text for t in limit_tokens]
        if texts[:1] in (["ARRAY_SIZE"], ["countof"], ["_countof"], ["N_ELEMENTS"], ["G_N_ELEMENTS"], ["ARRAYSIZE"]):
            return name in texts
        if texts[:1] == ["sizeof"] and name in texts and "/" in texts:
            return True
        return False

    def _accesses(self, statements: Sequence[Stmt], variable: str) -> Iterable[Tuple[str, ArrayInfo, Token]]:
        for statement in _walk(statements):
            for tokens in (statement.tokens, statement.init, statement.step):
                for index in range(len(tokens) - 3):
                    token = tokens[index]
                    if token.kind != IDENT or tokens[index + 1].text != "[":
                        continue
                    close = matching(tokens, index + 1)
                    if close is None:
                        continue
                    inner = tokens[index + 2 : close]
                    if len(inner) == 1 and inner[0].text == variable:
                        found = self.array_of([token])
                        if found is not None and not (index > 0 and tokens[index - 1].text in (".", "->")):
                            yield found[0], found[1], token


def _walk(statements: Sequence[Stmt]) -> Iterable[Stmt]:
    stack = list(reversed(statements))
    while stack:
        statement = stack.pop()
        yield statement
        stack.extend(reversed(statement.alternate))
        stack.extend(reversed(statement.body))


def _inclusive_bound(condition: Sequence[Token]) -> Optional[Tuple[str, List[Token]]]:
    for index, token in enumerate(condition):
        if token.kind != OP:
            continue
        if token.text == "<=" and index == 1 and condition[0].kind == IDENT:
            return condition[0].text, list(condition[2:])
        if token.text == ">=" and index == len(condition) - 2 and condition[-1].kind == IDENT:
            return condition[-1].text, list(condition[:index])
    return None


def _inside_sizeof(statement: Sequence[Token], index: int) -> bool:
    # `sizeof *p`, `sizeof &x` -- không có ngoặc.
    cursor = index - 1
    while cursor >= 0 and statement[cursor].kind == OP and statement[cursor].text in ("*", "&"):
        cursor -= 1
    if cursor >= 0 and statement[cursor].kind == IDENT and statement[cursor].text == "sizeof":
        return True
    depth = 0
    for cursor in range(index - 1, -1, -1):
        token = statement[cursor]
        if token.kind == OP and token.text == ")":
            depth += 1
        elif token.kind == OP and token.text == "(":
            if depth == 0:
                return cursor > 0 and statement[cursor - 1].text in ("sizeof", "ARRAY_SIZE", "countof", "_countof", "offsetof")
            depth -= 1
    return index > 0 and statement[index - 1].text == "sizeof"


def _masks(tokens: Sequence[Token]) -> bool:
    """`x & 0xff` hay `x % N` với N hằng: kết quả bị chặn dù x nhiễm."""
    for index, token in enumerate(tokens):
        if token.kind == OP and token.text in ("&", "%") and index > 0 and index + 1 < len(tokens):
            if tokens[index + 1].kind == NUMBER or (tokens[index + 1].kind == IDENT and tokens[index + 1].text.isupper()):
                return True
    return False


def _chains_in(tokens: Sequence[Token]) -> List[str]:
    names: List[str] = []
    index = 0
    while index < len(tokens):
        chain, after = _chain(tokens, index)
        if chain is not None:
            names.append(chain)
            index = after
            continue
        index += 1
    return names


_CAST_WORDS = frozenset(
    {"void", "char", "const", "struct", "unsigned", "signed", "int", "long", "short", "uint8_t", "u_char", "volatile", "union", "enum"}
)


def _strip_cast(argument: Sequence[Token]) -> List[Token]:
    """Bỏ phép ép kiểu đứng đầu: `(void *)p` -> `p`, `(struct x *)q` -> `q`."""
    tokens = list(argument)
    while len(tokens) > 2 and tokens[0].kind == OP and tokens[0].text == "(":
        close = matching(tokens, 0)
        if close is None or close + 1 >= len(tokens):
            break
        inner = tokens[1:close]
        if not inner or not all(t.kind == IDENT or t.text in ("*", "::") for t in inner):
            break
        if not any(t.text == "*" for t in inner) and inner[0].text not in _CAST_WORDS:
            break
        tokens = tokens[close + 1 :]
    return tokens


def _target_name(argument: Sequence[Token]) -> Optional[str]:
    argument = _strip_cast(argument)
    meaningful = [t for t in argument if not (t.kind == OP and t.text in ("&", "(", ")"))]
    if not meaningful:
        return None
    if meaningful[0].kind == OP and meaningful[0].text == "*":
        meaningful = meaningful[1:]
    chain, after = _chain(meaningful, 0)
    if chain is None:
        return None
    return chain


def _param_names(param: Sequence[Token]) -> List[str]:
    names = [t.text for t in param if t.kind == IDENT]
    return names[-1:] if names else []


def _operand_before(statement: Sequence[Token], index: int) -> List[Token]:
    collected: List[Token] = []
    depth = 0
    cursor = index - 1
    while cursor >= 0:
        token = statement[cursor]
        if token.kind == OP:
            if token.text in ")]":
                depth += 1
            elif token.text in "([":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and token.text in ("&&", "||", ",", "?", ":", "=", "!", "==", "!=", ";", "return"):
                break
        collected.append(token)
        cursor -= 1
    collected.reverse()
    return collected


def _operand_after(statement: Sequence[Token], index: int) -> List[Token]:
    collected: List[Token] = []
    depth = 0
    cursor = index + 1
    while cursor < len(statement):
        token = statement[cursor]
        if token.kind == OP:
            if token.text in "([":
                depth += 1
            elif token.text in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and token.text in ("&&", "||", ",", "?", ":", "=", "==", "!=", ";"):
                break
        collected.append(token)
        cursor += 1
    return collected


def _top_level_tokens(tokens: Sequence[Token]) -> List[Token]:
    result: List[Token] = []
    depth = 0
    for token in tokens:
        if token.kind == OP and token.text in "([":
            depth += 1
            continue
        if token.kind == OP and token.text in ")]":
            depth -= 1
            continue
        if depth == 0:
            result.append(token)
    return result


def _operands(tokens: Sequence[Token]) -> List[List[Token]]:
    operands: List[List[Token]] = [[]]
    depth = 0
    for token in tokens:
        if token.kind == OP and token.text in "([":
            depth += 1
        elif token.kind == OP and token.text in ")]":
            depth -= 1
        if depth == 0 and token.kind == OP and token.text in ("*", "+", "<<", "-"):
            operands.append([])
            continue
        operands[-1].append(token)
    return [operand for operand in operands if operand]


def _numeric_width(conversion: str) -> int:
    if conversion in ("d", "i"):
        return 11
    if conversion in ("u",):
        return 10
    if conversion in ("ld", "li", "lld", "lli", "jd", "zd", "lu", "llu", "zu", "ju"):
        return 20
    if conversion in ("x", "X", "o"):
        return 11
    if conversion in ("lx", "lX", "llx", "llX", "zx", "lo", "llo"):
        return 22
    if conversion == "c":
        return 1
    if conversion == "p":
        return 18
    if conversion in ("hd", "hi", "hu", "hx", "hX"):
        return 6
    if conversion in ("hhd", "hhi", "hhu", "hhx"):
        return 4
    if conversion in ("f", "F", "lf", "Lf"):
        # Trường hợp xấu nhất thật là 317 ký tự, nhưng chỉ khi giá trị gần DBL_MAX;
        # lấy độ dài thực tế ( -1234567.123456 ) để không báo mọi sprintf("%.1f").
        return 15
    return 13  # %e, %g: -1.234568e+308


def _format_directives(text: str) -> Optional[Tuple[int, List[Tuple[str, Optional[int], Optional[int]]]]]:
    static = 0
    items: List[Tuple[str, Optional[int], Optional[int]]] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char != "%":
            static += 1
            index += 1
            continue
        index += 1
        if index < length and text[index] == "%":
            items.append(("%", None, None))
            index += 1
            continue
        while index < length and text[index] in "-+ #0'":
            index += 1
        width_start = index
        while index < length and text[index].isdigit():
            index += 1
        if index < length and text[index] == "*":
            return None
        width = int(text[width_start:index]) if index > width_start else None
        precision: Optional[int] = None
        if index < length and text[index] == ".":
            index += 1
            if index < length and text[index] == "*":
                return None
            precision_start = index
            while index < length and text[index].isdigit():
                index += 1
            precision = int(text[precision_start:index] or "0")
        modifier_start = index
        while index < length and text[index] in "hlLqjzt":
            index += 1
        if index >= length:
            return None
        conversion = text[modifier_start : index + 1]
        index += 1
        letter = conversion[-1]
        if letter == "n":
            return None
        if letter == "s":
            items.append(("s", width, precision))
        elif letter in "fFeEgGaA":
            items.append(("f", width, precision))
        else:
            items.append((conversion, width, precision))
    return static, items


def _scanf_directives(text: str) -> List[Tuple[str, Optional[int], bool, bool]]:
    result: List[Tuple[str, Optional[int], bool, bool]] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] != "%":
            index += 1
            continue
        index += 1
        if index < length and text[index] == "%":
            index += 1
            continue
        suppressed = False
        if index < length and text[index] == "*":
            suppressed = True
            index += 1
        start = index
        while index < length and text[index].isdigit():
            index += 1
        width = int(text[start:index]) if index > start else None
        allocating = False
        while index < length and text[index] in "hlLqjztm":
            if text[index] == "m":
                allocating = True
            index += 1
        if index < length and text[index] == "a" and index + 1 < length and text[index + 1] in "s[":
            allocating = True
            index += 1
        if index >= length:
            break
        conversion = text[index]
        if conversion == "[":
            close = text.find("]", index + 2)
            index = close if close != -1 else length
        result.append((conversion, width, suppressed, allocating))
        index += 1
    return result


# ------------------------------------------------- use-after-free / double free


State = Optional[Dict[str, FreeFact]]


def _join(first: State, second: State) -> State:
    if first is None:
        return None if second is None else dict(second)
    if second is None:
        return dict(first)
    merged: Dict[str, FreeFact] = {}
    for name in set(first) | set(second):
        a = first.get(name)
        b = second.get(name)
        if a is not None and b is not None:
            merged[name] = replace(a, definite=a.definite and b.definite)
        else:
            fact = a or b
            assert fact is not None
            merged[name] = replace(fact, definite=False)
    return merged


class _FreeFlow:
    """Phân tích luồng "đã giải phóng" trên cây câu lệnh của một hàm."""

    def __init__(self, file: _FileAnalysis, function: Function, report: bool) -> None:
        self.file = file
        self.function = function
        self.report = report
        self.budget = file.budget
        self.builder = file.builder
        self.breaks: List[State] = []
        self.continues: List[State] = []
        self.gotos: Dict[str, State] = {}
        self.exits: List[State] = []
        declared: Dict[str, Tuple[str, ...]] = {}
        _collect_arrays(function.body_tokens, file.evaluator, {}, set(), set(), file.budget, declared)
        self.locals: Set[str] = set(declared) | set(function.param_names)

    def run(self) -> State:
        state = self._block(self.function.body, {})
        return state

    def summary(self) -> Tuple[int, ...]:
        end = self.run()
        if end is None:
            return ()
        freed: List[int] = []
        for position, name in enumerate(self.function.param_names):
            fact = end.get(name)
            if fact is not None and fact.definite:
                freed.append(position)
        return tuple(freed)

    # ------------------------------------------------------------ duyệt cây

    def _block(self, statements: Sequence[Stmt], state: State) -> State:
        for statement in statements:
            self.budget.spend()
            state = self._statement(statement, state)
        return state

    def _statement(self, statement: Stmt, state: State) -> State:
        kind = statement.kind
        if kind == "label":
            incoming = self.gotos.get(statement.label)
            if incoming is not None:
                state = _join(state, incoming)
            return state
        if state is None:
            return None
        if kind == "simple":
            return self._simple(statement.tokens, state)
        if kind == "block":
            return self._block(statement.body, state)
        if kind == "if":
            state = self._simple(statement.tokens, state)
            if state is None:
                return None
            then_state = self._block(statement.body, dict(state))
            else_state = self._block(statement.alternate, dict(state)) if statement.alternate else dict(state)
            return _join(then_state, else_state)
        if kind in ("loop", "do"):
            return self._loop(statement, state)
        if kind == "switch":
            return self._switch(statement, state)
        if kind == "try":
            body = self._block(statement.body, dict(state))
            result = body
            for handler in statement.alternate:
                result = _join(result, self._block([handler], dict(state)))
            return result
        if kind == "jump":
            jump = statement.label.split(":", 1)[0]
            if jump == "return":
                state = self._simple(statement.tokens, state, returning=True)
                self.exits.append(state)
                return None
            if jump == "break":
                self.breaks.append(state)
                return None
            if jump == "continue":
                self.continues.append(state)
                return None
            if jump == "goto":
                target = statement.label.split(":", 1)[1]
                self.gotos[target] = _join(self.gotos.get(target), state) if target in self.gotos else dict(state)
                return None
        if kind == "case":
            return state
        return state

    def _loop(self, statement: Stmt, state: Dict[str, FreeFact]) -> State:
        """Chạy thân vòng lặp hai lượt: lượt hai nhận cả trạng thái quay lại.

        Hai lượt là đủ cho phép hợp này ( tập "đã giải phóng" chỉ lớn lên ), và
        đó cũng là cách bắt `while (c) { free(p); }` -- con trỏ bị giải phóng
        lần hai ở vòng sau.
        """
        outer_breaks, outer_continues = self.breaks, self.continues
        entry: State = self._simple(statement.init, state) if statement.init else state
        is_do = statement.kind == "do"
        infinite = statement.label != "macro" and _always_true(statement.tokens)
        exit_state: State = None
        breaks: List[State] = []
        current: State = entry
        for _ in range(2):
            if current is None:
                break
            self.breaks, self.continues = [], []
            head: State = current
            if statement.label == "macro":
                # Macro vòng lặp gán lại biến lặp ở mỗi vòng.
                head = self._kill_names(statement.tokens, dict(current))
            elif not is_do:
                head = self._simple(statement.tokens, head)
                if not infinite:
                    exit_state = _join(exit_state, head)
            body = self._block(statement.body, dict(head) if head is not None else None)
            for value in self.continues:
                body = _join(body, value)
            if is_do and body is not None:
                body = self._simple(statement.tokens, body)
                if not infinite:
                    exit_state = _join(exit_state, body)
            if body is not None and statement.step:
                body = self._simple(statement.step, body)
            breaks.extend(self.breaks)
            previous = current
            current = _join(entry, body) if body is not None else None
            if current == previous:
                # Lượt hai sẽ y hệt lượt một: bỏ qua, nếu không vòng lồng nhau nhân đôi theo độ sâu.
                break
        self.breaks, self.continues = outer_breaks, outer_continues
        for value in breaks:
            exit_state = _join(exit_state, value)
        return exit_state

    def _switch(self, statement: Stmt, state: Dict[str, FreeFact]) -> State:
        entry = self._simple(statement.tokens, state)
        if entry is None:
            return None
        outer_breaks = self.breaks
        self.breaks = []
        current: State = None
        for child in statement.body:
            self.budget.spend()
            if child.kind == "case":
                current = _join(current, entry)
                continue
            current = self._statement(child, current)
        has_default = any(_is_default(child) for child in statement.body)
        result = current
        for value in self.breaks:
            result = _join(result, value)
        if not has_default:
            result = _join(result, entry)
        self.breaks = outer_breaks
        return result

    # ---------------------------------------------------------- một câu lệnh

    def _simple(self, tokens: Sequence[Token], state: State, returning: bool = False) -> State:
        if state is None or not tokens:
            return state
        state = dict(state)
        declared: Dict[str, Tuple[str, ...]] = {}
        if tokens[0].kind == IDENT and tokens[0].text not in _DECLARATION_STOP:
            _collect_declarators(tokens, self.file.evaluator, {}, set(), set(), declared)
        if declared:
            # Lời khai báo tạo biến MỚI: `*` trong `int *p` không phải phép đọc.
            for part in _split_top_level(tokens, ","):
                position = _assignment_index(part)
                if position is not None:
                    state = self._events(part[position + 1 :], state) or {}
            for name in declared:
                for key in list(state):
                    if key == name or key.startswith(name + "."):
                        state.pop(key, None)
            return state
        position = _assignment_index(tokens)
        if position is not None:
            left = tokens[:position]
            right = tokens[position + 1 :]
            target = _last_name(left)
            state = self._events(right, state, returning=False)
            if state is None:
                return None
            if target is None:
                state = self._events(left, state)
            else:
                # Ghi vào p->x qua con trỏ đã giải phóng vẫn là dùng.
                if len(left) > 1:
                    state = self._uses(left, state, skip_exact=target)
                for name in list(state):
                    if name == target or name.startswith(target + "."):
                        state.pop(name, None)
            return state
        if returning:
            # `return f != NULL;` so sánh giá trị con trỏ, không trả con trỏ ra ngoài.
            expression = [t for t in tokens if not (t.kind == IDENT and t.text == "return")]
            expression = [t for t in _strip_cast(expression) if not (t.kind == OP and t.text in "()")]
            chain, after = _chain(expression, 0)
            returning = chain is not None and after == len(expression)
        return self._events(tokens, state, returning=returning)

    def _kill_names(self, tokens: Sequence[Token], state: Dict[str, FreeFact]) -> Dict[str, FreeFact]:
        for name in _chains_in(tokens):
            for key in list(state):
                if key == name or key.startswith(name + "."):
                    state.pop(key, None)
        return state

    def _events(self, tokens: Sequence[Token], state: Dict[str, FreeFact], returning: bool = False) -> State:
        limit = len(tokens)
        index = 0
        # Phép gán lồng trong điều kiện: `while ((p = next()) != NULL)`, và
        # con trỏ dịch đi bằng `p++` / `p += n`: cả hai đều trỏ sang vùng khác.
        for cursor, token in enumerate(tokens):
            if token.kind == OP and token.text in ("++", "--"):
                for neighbour in (cursor - 1, cursor + 1):
                    if 0 <= neighbour < limit and tokens[neighbour].kind == IDENT:
                        name = tokens[neighbour].text
                        for key in list(state):
                            if key == name or key.startswith(name + "."):
                                state.pop(key, None)
            if token.kind == OP and token.text in ("=", "+=", "-=") and cursor > 0:
                target = _last_name(_operand_before(tokens, cursor))
                if target is not None:
                    for key in list(state):
                        if key == target or key.startswith(target + "."):
                            state.pop(key, None)
        # Con trỏ bị lấy địa chỉ ( `&p` ) có thể được hàm khác gán lại.
        for cursor, token in enumerate(tokens):
            if token.kind == OP and token.text == "&" and cursor + 1 < limit and tokens[cursor + 1].kind == IDENT:
                if cursor == 0 or (tokens[cursor - 1].kind == OP and tokens[cursor - 1].text not in (")", "]")) or _after_pointer_cast(tokens, cursor):
                    name, _ = _chain(tokens, cursor + 1)
                    if name is not None:
                        for key in list(state):
                            if key == name or key.startswith(name + "."):
                                state.pop(key, None)
        while index < limit:
            self.budget.spend()
            token = tokens[index]
            if token.kind == IDENT and token.text == "delete":
                cursor = index + 1
                if cursor + 1 < limit and tokens[cursor].text == "[" and tokens[cursor + 1].text == "]":
                    cursor += 2
                name, after = _chain(tokens, cursor)
                if name is not None and name != "this":
                    if after < limit and tokens[after].kind == OP and tokens[after].text in ("[", "("):
                        # delete arg[i].thread: phần tử, không phải chính biến arg.
                        index = after
                        continue
                    state = self._free(name, token, "delete", state, definite=True)
                    index = after
                    continue
            if token.kind == IDENT:
                chain, after = _chain(tokens, index)
                if chain is not None and after < limit and tokens[after].text == "(":
                    base = _base(chain)
                    arguments, end = split_arguments(tokens, after)
                    position = _FREE_CALLS.get(base)
                    freed_by_callee: Tuple[int, ...] = ()
                    if position is None:
                        freed_by_callee = self.file.free_summaries.get(base, ())
                        if "." in chain:
                            # job->run(): gọi phương thức qua con trỏ là đọc chính đối tượng đó.
                            self._use_at(tokens, index, after, state)
                    # Đối số được đọc TRƯỚC khi hàm chạy.
                    for argument_index, argument in enumerate(arguments):
                        if argument_index == position or argument_index in freed_by_callee:
                            # Truyền con trỏ đã giải phóng vào free lần nữa là double free,
                            # không phải "dùng"; xử lý ở _free.
                            inner = _target_name(argument)
                            if inner is not None and _is_plain_pointer(argument):
                                continue
                        label = base
                        if base in self.file.function_names and base not in _DEREF_CALLS:
                            if argument_index not in self.file.deref_summaries.get(base, ()):
                                label = ""
                        state = self._uses(argument, state, call=label)
                    if position is not None and len(arguments) > position:
                        target = _target_name(arguments[position])
                        if target is not None and _is_plain_pointer(arguments[position]):
                            verb = "fclose" if base == "fclose" else base
                            state = self._free(target, token, verb, state, definite=True)
                    if position is None and base in self.file.function_names:
                        # delete db_; Open();  -- hàm cùng tệp có thể gán lại biến toàn cục / thành viên.
                        for key in list(state):
                            if key.split(".", 1)[0] not in self.locals:
                                state.pop(key, None)
                    if position is None:
                        # Hàm nhận `a` có thể gán lại a->out: trường cũ không còn là đối tượng đã giải phóng.
                        for argument in arguments:
                            holder = _target_name(argument)
                            if holder is not None:
                                for key in list(state):
                                    if key.startswith(holder + "."):
                                        state.pop(key, None)
                    for freed_index in freed_by_callee:
                        if freed_index < len(arguments):
                            target = _target_name(arguments[freed_index])
                            if target is not None and _is_plain_pointer(arguments[freed_index]):
                                state = self._free(target, token, base, state, definite=False)
                    if base in NORETURN_CALLS or base in self.file.noreturn:
                        self.exits.append(state)
                        return None
                    index = end
                    continue
                if chain is not None:
                    self._use_at(tokens, index, after, state, returning=returning)
                    index = after
                    continue
            index += 1
        return state

    def _uses(
        self,
        tokens: Sequence[Token],
        state: Dict[str, FreeFact],
        call: str = "",
        skip_exact: str = "",
    ) -> Dict[str, FreeFact]:
        index = 0
        limit = len(tokens)
        while index < limit and state:
            token = tokens[index]
            if token.kind == IDENT and token.text == "sizeof":
                if index + 1 < limit and tokens[index + 1].text == "(":
                    close = matching(tokens, index + 1)
                    index = (close if close is not None else limit) + 1
                    continue
            chain, after = _chain(tokens, index)
            if chain is None:
                index += 1
                continue
            self._use_at(tokens, index, after, state, call=call, skip_exact=skip_exact)
            index = after
        return state

    def _use_at(
        self,
        tokens: Sequence[Token],
        index: int,
        after: int,
        state: Dict[str, FreeFact],
        call: str = "",
        skip_exact: str = "",
        returning: bool = False,
    ) -> None:
        if not state:
            return
        chain, _ = _chain(tokens, index)
        if chain is None:
            return
        previous = tokens[index - 1] if index > 0 else None
        if previous is not None and previous.kind == OP and previous.text in (".", "->", "&"):
            return
        if _inside_sizeof(tokens, index):
            return
        hit = self._freed_prefix(chain, state)
        if hit is None:
            return
        name, fact = hit
        if chain == skip_exact and name == chain:
            return
        limit = len(tokens)
        following = tokens[after] if after < limit else None
        deref = chain != name or (following is not None and following.kind == OP and following.text in ("[", "->", "."))
        if not deref and previous is not None and previous.kind == OP and previous.text == "*":
            before = tokens[index - 2] if index >= 2 else None
            deref = before is None or (before.kind == OP and before.text not in (")", "]"))
        passed = (
            bool(call)
            and chain == name
            and (call in _DEREF_CALLS or (call in self.file.function_names and not call.isupper()))
        )
        if deref or passed or (returning and chain == name):
            self._report_use(name, fact, tokens[index], deref)
            state.pop(name, None)

    def _freed_prefix(self, chain: str, state: Dict[str, FreeFact]) -> Optional[Tuple[str, FreeFact]]:
        candidate = chain
        while True:
            fact = state.get(candidate)
            if fact is not None:
                return candidate, fact
            if "." not in candidate:
                return None
            candidate = candidate.rsplit(".", 1)[0]

    def _free(self, name: str, anchor: Token, verb: str, state: Dict[str, FreeFact], definite: bool) -> Dict[str, FreeFact]:
        if name in _STANDARD_STREAMS or name in ("NULL", "nullptr", "0"):
            return state
        previous = state.get(name)
        if previous is not None and self.report:
            certain = previous.definite and definite
            self.builder.add(
                rule_id="FSB-MEM-004",
                line=anchor.line,
                column=anchor.column,
                symbol=name,
                message="%s bị %s lần nữa trong khi đã được %s ở dòng %d mà chưa gán lại%s"
                % (
                    name,
                    verb,
                    previous.verb,
                    previous.line,
                    "" if previous.definite else " ( trên ít nhất một đường chạy )",
                ),
                end_line=anchor.line,
                end_column=anchor.column + len(anchor.text),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH if certain else Confidence.MEDIUM,
                trace=(
                    self.builder.step(StepKind.CALL, previous.line, previous.column, "giải phóng lần đầu"),
                    self.builder.step(StepKind.SINK, anchor.line, anchor.column, "giải phóng lần hai"),
                ),
            )
            state.pop(name, None)
            return state
        state[name] = FreeFact(anchor.line, anchor.column, verb, definite)
        # Các thành viên đọc qua con trỏ cũ không còn là đối tượng riêng nữa.
        return state

    def _report_use(self, name: str, fact: FreeFact, anchor: Token, deref: bool) -> None:
        if not self.report:
            return
        how = "bị truy cập" if deref else "bị dùng tiếp"
        self.builder.add(
            rule_id="FSB-MEM-003",
            line=anchor.line,
            column=anchor.column,
            symbol=name,
            message="%s %s sau khi đã được %s ở dòng %d%s"
            % (name, how, fact.verb, fact.line, "" if fact.definite else " ( trên ít nhất một đường chạy )"),
            end_line=anchor.line,
            end_column=anchor.column + len(anchor.text),
            severity=Severity.HIGH if deref else Severity.MEDIUM,
            confidence=Confidence.HIGH if fact.definite and deref else Confidence.MEDIUM,
            trace=(
                self.builder.step(StepKind.CALL, fact.line, fact.column, "giải phóng ở đây"),
                self.builder.step(StepKind.SINK, anchor.line, anchor.column, "dùng lại ở đây"),
            ),
        )


# fclose(stdout) rồi in tiếp là chuyện của luồng chuẩn, không phải vùng nhớ heap.
_STANDARD_STREAMS = frozenset({"stdin", "stdout", "stderr"})

# Truyền con trỏ đã giải phóng vào một hàm chỉ là "dùng" khi hàm đó chắc chắn
# đọc vùng nhớ nó trỏ tới. So sánh con trỏ, in địa chỉ hay macro kiểm thử
# ( `expect_ptr_eq(p, q)` ) không chạm vào vùng nhớ, nên chỉ tính hàm thư viện
# đã biết là đọc/ghi qua con trỏ, cộng với hàm định nghĩa ngay trong tệp.
_DEREF_CALLS = frozenset(
    {
        "strlen", "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strcasecmp",
        "strchr", "strrchr", "strstr", "strdup", "strndup", "strtok", "memcpy", "memmove",
        "memset", "memcmp", "memchr", "fputs", "puts", "fwrite", "fread", "fgets", "fprintf",
        "sprintf", "snprintf", "atoi", "atol", "strtol", "strtoul", "realloc", "fflush", "fseek",
        "ftell", "fileno", "fgetc", "fputc", "getc", "putc", "ungetc", "rewind",
    }
)


def _is_plain_pointer(argument: Sequence[Token]) -> bool:
    argument = _strip_cast(argument)
    meaningful = [t for t in argument if not (t.kind == OP and t.text in ("(", ")"))]
    if not meaningful:
        return False
    # (void *)p
    while len(meaningful) > 1 and meaningful[0].kind == IDENT and meaningful[0].text in ("void", "char", "const", "struct", "unsigned") :
        meaningful = meaningful[1:]
        while meaningful and meaningful[0].kind in (IDENT, OP) and meaningful[0].text in ("*",):
            meaningful = meaningful[1:]
        if len(meaningful) > 1 and meaningful[0].kind == IDENT and meaningful[1].kind == IDENT:
            meaningful = meaningful[1:]
    chain, after = _chain(meaningful, 0)
    return chain is not None and after == len(meaningful)


def _is_default(statement: Stmt) -> bool:
    return statement.kind == "case" and statement.label == "default"


def _always_true(condition: Sequence[Token]) -> bool:
    if not condition:
        return True
    texts = [t.text for t in condition]
    return texts in (["1"], ["true"], ["TRUE"])
