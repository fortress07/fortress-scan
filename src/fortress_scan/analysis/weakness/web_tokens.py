"""CORS phản chiếu mọi origin và cookie phiên thiếu HttpOnly, đọc theo token.

Giống `web_python` nhưng cho 11 ngôn ngữ còn lại. Hai chỗ cần cẩn thận hơn bản
AST:

* **hàm quyết định origin**: `origin: (o, cb) => cb(null, true)` cho qua tất,
  còn `(o, cb) => { if (list.includes(o)) cb(null, true) }` thì không -- nên
  thân hàm phải được đọc xem có điều kiện nào không, chứ không chỉ tìm chuỗi
  `cb(null, true)`;
* **mặc định của từng framework**: thiếu `HttpOnly` chỉ là lỗ hổng ở nơi mặc
  định của nó là tắt. Đã kiểm trực tiếp: express `res.cookie`, PHP `setcookie`
  và struct `http.Cookie` của Go đều không có HttpOnly khi không truyền gì,
  còn express-session thì mặc định BẬT nên ở đó chỉ bắt lúc bị tắt thẳng.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Sequence, Tuple

from ...core.model import Confidence
from ...languages import CSHARP, GO, JAVA, JAVASCRIPT, PHP, TYPESCRIPT
from ..generic.lexer import IDENT, OP, STRING, Token
from . import words
from .config_tokens import (
    _in_same_region,
    _is_declaration,
    _statement_tokens,
    _texts,
    guard_names,
)

if TYPE_CHECKING:  # pragma: no cover
    from .tokens import _Call, _Scan

_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"

# Tên cho thấy giá trị lấy từ request đang xử lý, không từ cấu hình.
_REQUEST_TOKENS = frozenset(
    {
        "req",
        "request",
        "r",
        "c",
        "ctx",
        "context",
        "headers",
        "header",
        "getheader",
        "get",
        "env",
        "environ",
        "_server",
        "server",
        "meta",
        "httpcontext",
    }
)

# Tên GHÉP mà một từ của nó đã nói rõ nguồn: `requestOrigin`, `origin_header`.
_REQUEST_WORDS = frozenset({"request", "req", "headers", "header", "environ"})

# Thân hàm có một trong những thứ này là có kiểm tra, không phải cho qua tất.
_CONDITION_MARKERS = frozenset(
    {
        "if",
        "unless",
        "switch",
        "case",
        "contains",
        "includes",
        "indexof",
        "index",
        "find",
        "test",
        "match",
        "matches",
        "some",
        "every",
        "filter",
        "has",
        "haskey",
        "hasprefix",
        "hassuffix",
        "equals",
        "equalsignorecase",
        "allowed",
        "allowlist",
        "whitelist",
        "elem",
        "any",
        "lookup",
        "exists",
        "valid",
        "validate",
        "check",
    }
)
_CONDITION_OPERATORS = frozenset({"==", "===", "!=", "!==", "?", "&&", "||", "!"})

_HTTPONLY_NAMES = frozenset({"httponly", "http_only", "httponlypolicy"})
_HTTPONLY_OFF = frozenset({"false", "0", "none", "nil", "no", "off"})
# Chỉ báo khi câu lệnh thật sự nói về cookie, để `HttpOnly = false` của một
# lớp khác trùng tên không bị gán nghĩa.
_COOKIE_CONTEXT_WORDS = frozenset(
    {"cookie", "cookies", "session", "token", "jwt", "auth", "authentication", "remember"}
)

_SPRING_ORIGIN_PATTERNS = frozenset(
    {"allowedOriginPatterns", "setAllowedOriginPatterns", "addAllowedOriginPattern", "originPatterns"}
)
_SPRING_CREDENTIALS = frozenset({"allowCredentials", "setAllowCredentials"})

_GO_ORIGIN_FUNCS = frozenset({"AllowOriginFunc", "AllowOriginRequestFunc", "AllowOriginVaryRequestFunc"})


def check(scan: "_Scan") -> None:
    _reflected_origin(scan)
    language = scan.language
    if language in (JAVASCRIPT, TYPESCRIPT):
        _javascript(scan)
    elif language == JAVA:
        _java(scan)
    elif language == CSHARP:
        _csharp(scan)
    elif language == GO:
        _go(scan)
    elif language == PHP:
        _php(scan)
    # Sau cùng, để không báo lại dòng mà kiểm tra riêng của từng ngôn ngữ đã báo.
    _explicit_httponly_off(scan)


# --------------------------------------------------------------------- CORS


def _reflected_origin(scan: "_Scan") -> None:
    """`w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`

    Đọc trên token thô để bắt được cả nội suy chuỗi của PHP và Ruby
    ( `header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}")` ).
    """
    raw = scan.raw
    origins: List[Tuple[int, Token]] = []
    credentials: List[int] = []
    for index, token in enumerate(raw):
        if token.kind != STRING:
            continue
        text = token.text.strip().lower()
        if text.startswith(_ACAO):
            origins.append((index, token))
        elif text.startswith(_ACAC) and _says_true(raw, index, text):
            credentials.append(token.line)
    if not origins or not credentials:
        return
    for index, token in origins:
        scan.budget.spend()
        reflection = _origin_from_request(raw, index)
        if reflection is None:
            continue
        line = next((other for other in credentials if abs(other - token.line) <= 10), None)
        if line is None:
            continue
        if _guarded_by_allowlist(scan, token):
            continue
        scan._report(
            "FSB-CORS-001",
            token,
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Origin lấy thẳng Origin của người gửi trong khi "
            "Access-Control-Allow-Credentials là true",
            evidence=(reflection, "Access-Control-Allow-Credentials được đặt ở dòng %d" % line),
        )


def _guarded_by_allowlist(scan: "_Scan", token: Token) -> bool:
    """`if (allowedOrigins.includes(origin)) { ... }` bao quanh chỗ ghi header."""
    index = scan.position.get(id(token))
    if index is None:
        return False
    return any(words.names_an_allowlist(name) for name in guard_names(scan, index))


def _says_true(raw: Sequence[Token], index: int, text: str) -> bool:
    if ":" in text and "true" in text.split(":", 1)[1]:
        return True
    for token in raw[index + 1 : index + 7]:
        if token.kind in (IDENT, STRING) and token.text.strip().lower() == "true":
            return True
        if token.kind == OP and token.text == ";":
            break
    return False


def _origin_from_request(raw: Sequence[Token], index: int) -> Optional[str]:
    window = _value_window(raw, index)
    if not any(_is_origin_token(token) for token in window):
        return None
    for token in window:
        text = token.text.strip().lstrip("$@:")
        lowered = text.lower()
        if lowered in _REQUEST_TOKENS or "http_origin" in lowered:
            return "giá trị đọc từ header Origin của request"
        if any(word in _REQUEST_WORDS for word in words.split_words(text)):
            return "giá trị đọc từ header Origin của request"
    return None


def _is_origin_token(token: Token) -> bool:
    if token.kind not in (IDENT, STRING):
        return False
    text = token.text.strip().lower()
    return "origin" in text and not text.startswith("access-control")


def _value_window(raw: Sequence[Token], index: int, limit: int = 25) -> List[Token]:
    """Phần GIÁ TRỊ đứng sau tên header, dừng trước mục kế tiếp của cùng danh sách."""
    collected: List[Token] = []
    depth = 0
    for token in raw[index + 1 : index + 1 + limit]:
        if token.kind == OP:
            if token.text in "([{":
                depth += 1
            elif token.text in ")]}":
                if depth:
                    depth -= 1
                elif any(t.kind != OP for t in collected):
                    break
                else:
                    # `headers["Access-Control-Allow-Origin"] = ...`: dấu `]` này
                    # chỉ đóng chỗ chứa TÊN header, giá trị còn ở phía sau.
                    continue
            elif token.text == ";":
                break
            elif token.text == "," and depth == 0 and any(t.kind != OP for t in collected):
                break
        collected.append(token)
    return collected


def _callback_always_true(tokens: Sequence[Token]) -> bool:
    """Hàm quyết định origin trả về true mà không kiểm gì.

    `(o, cb) => cb(null, true)`, `func(origin string) bool { return true }`,
    `_ => true`. Có `if`, `includes`, `==` thì là bộ kiểm thật, không báo.
    """
    texts = [token.text.strip().lower() for token in tokens]
    if any(text in _CONDITION_MARKERS or text in _CONDITION_OPERATORS for text in texts):
        return False
    for position, text in enumerate(texts):
        if text == "return" and position + 1 < len(texts) and texts[position + 1] == "true":
            return True
        if text == "=>" and position + 1 < len(texts) and texts[position + 1] == "true":
            return True
        # cb(null, true) hoặc cb(null, origin)
        if text == "null" and position + 2 < len(texts) and texts[position + 1] == ",":
            following = texts[position + 2]
            if following == "true" or "origin" in following or following in ("o", "org"):
                return True
    return False


# --------------------------------------------------------------- JavaScript


def _javascript(scan: "_Scan") -> None:
    for call in scan.calls:
        scan.budget.spend()
        name = call.parts[-1]
        if name == "cors" and call.arguments and not _is_declaration(scan, call):
            _js_cors(scan, call)
        elif name == "cookie" and len(call.arguments) >= 2:
            _js_cookie(scan, call)


def _js_cors(scan: "_Scan", call: "_Call") -> None:
    credentials = False
    origin: Optional[int] = None
    for token in call.argument(0):
        if token.kind != IDENT:
            continue
        index = scan.position.get(id(token))
        if index is None:
            continue
        if token.text == "credentials" and scan._pair_value(index) == "true":
            credentials = True
        elif token.text == "origin" and origin is None:
            origin = index
    if not credentials or origin is None:
        return
    reason = _js_origin_reason(scan, origin)
    if reason is None:
        return
    scan._report(
        "FSB-CORS-001",
        call.anchor,
        "cors",
        "cors() bật credentials với origin mở, nên mọi trang web đều đọc được phản hồi sau đăng nhập",
        evidence=(
            reason,
            "gói cors dội lại Origin của người gửi khi origin không phải chuỗi '*'",
        ),
    )


def _js_origin_reason(scan: "_Scan", index: int) -> Optional[str]:
    flat = scan.flat
    if index + 2 >= len(flat) or flat[index + 1].text != ":":
        return None
    value = flat[index + 2]
    if value.kind == IDENT and value.text == "true":
        return "origin: true nghĩa là dội lại mọi Origin"
    if value.kind == OP and value.text == "/":
        pattern = _regex_literal(scan, index + 2)
        if pattern is not None:
            described = words.matches_any_origin(pattern)
            if described is not None:
                return "origin: /%s/ -- %s" % (pattern, described)
        return None
    if value.kind == STRING or (value.kind == OP and value.text == "["):
        # '*' thì trình duyệt tự từ chối khi có credentials; danh sách thì đóng.
        return None
    if (value.kind == OP and value.text == "(") or (
        value.kind == IDENT and value.text in ("function", "async")
    ):
        body = _statement_tokens(scan, index + 2, limit=120, stop_at_comma=True)
        if _callback_always_true(body):
            return "hàm quyết định origin trả về true cho mọi origin"
    return None


def _regex_literal(scan: "_Scan", index: int) -> Optional[str]:
    flat = scan.flat
    line = flat[index].line
    parts: List[str] = []
    for token in flat[index + 1 : index + 30]:
        if token.line != line:
            return None
        if token.kind == OP and token.text == "/":
            return "".join(parts)
        parts.append(token.text)
    return None


def _js_cookie(scan: "_Scan", call: "_Call") -> None:
    name = scan._string_value(call.argument(0))
    if name is None:
        return
    word = words.names_a_session_cookie(name)
    if word is None:
        return
    options = call.argument(2)
    state = _httponly_state(scan, options)
    if state is True:
        return
    if state is False:
        confidence = Confidence.HIGH
        how = "httpOnly được đặt thẳng là false"
    else:
        confidence = Confidence.MEDIUM
        how = "không truyền httpOnly, mà mặc định của res.cookie là không có HttpOnly"
    _report_cookie(
        scan,
        call.anchor,
        name,
        _cookie_subject(name),
        confidence,
        (how, "tên cookie chứa từ %r" % word),
    )


def _httponly_state(scan: "_Scan", tokens: Sequence[Token]) -> Optional[bool]:
    """True / False khi cờ được đặt thẳng, None khi không thấy cờ nào."""
    for token in tokens:
        if token.kind not in (IDENT, STRING):
            continue
        if token.text.strip().lower().lstrip(":$@") not in _HTTPONLY_NAMES:
            continue
        index = scan.position.get(id(token))
        if index is None:
            continue
        value = (scan._pair_value(index) or "").strip("'\"").lower()
        if value in _HTTPONLY_OFF:
            return False
        if value:
            return True
    return None


# --------------------------------------------------------------------- Java


def _java(scan: "_Scan") -> None:
    patterns: List["_Call"] = []
    credentials: List["_Call"] = []
    for call in scan.calls:
        scan.budget.spend()
        name = call.parts[-1]
        if _is_declaration(scan, call):
            continue
        if name in _SPRING_ORIGIN_PATTERNS and _allows_any_origin(call):
            patterns.append(call)
        elif name in _SPRING_CREDENTIALS and _texts(call.argument(0)) == ["true"]:
            credentials.append(call)
        elif name == "setHttpOnly" and _texts(call.argument(0)) == ["false"]:
            _report_cookie(
                scan,
                call.anchor,
                "setHttpOnly",
                "cookie được cấu hình ở đây",
                Confidence.HIGH,
                ("setHttpOnly(false) tắt thẳng cờ HttpOnly",),
            )
        elif name == "CrossOrigin":
            _java_cross_origin(scan, call)
    for call in patterns:
        allowed = next(
            (other for other in credentials if _in_same_region(scan, call.index, other.index)),
            None,
        )
        if allowed is None:
            continue
        scan._report(
            "FSB-CORS-001",
            call.anchor,
            call.parts[-1],
            "%s cho qua mọi origin trong khi allowCredentials là true, nên Spring dội lại Origin "
            "của người gửi" % call.parts[-1],
            evidence=(
                "allowCredentials(true) ở dòng %d" % allowed.anchor.line,
                "allowedOrigins(\"*\") thì Spring tự ném IllegalArgumentException, "
                "còn allowedOriginPatterns(\"*\") thì chạy và dội lại Origin",
            ),
        )


def _allows_any_origin(call: "_Call") -> bool:
    for argument in call.arguments:
        for token in argument:
            if token.kind == STRING and words.matches_any_origin(token.text) is not None:
                return True
    return False


def _java_cross_origin(scan: "_Scan", call: "_Call") -> None:
    """`@CrossOrigin(originPatterns = "*", allowCredentials = "true")`"""
    flat = scan.flat
    pattern = False
    credentials = False
    for index in range(call.open_index + 1, min(call.close_index, len(flat))):
        token = flat[index]
        if token.kind != IDENT:
            continue
        value = (scan._pair_value(index) or "").strip("'\"").lower()
        if token.text in _SPRING_ORIGIN_PATTERNS and words.matches_any_origin(value) is not None:
            pattern = True
        elif token.text == "allowCredentials" and value == "true":
            credentials = True
    if pattern and credentials:
        scan._report(
            "FSB-CORS-001",
            call.anchor,
            "CrossOrigin",
            "@CrossOrigin mở originPatterns cho mọi origin trong khi allowCredentials là \"true\"",
            evidence=("origin được so bằng mẫu khớp mọi tên miền",),
        )


# ----------------------------------------------------------------------- C#


def _csharp(scan: "_Scan") -> None:
    origin_calls: List["_Call"] = []
    credentials: List["_Call"] = []
    for call in scan.calls:
        scan.budget.spend()
        name = call.parts[-1]
        if name == "SetIsOriginAllowed" and not _is_declaration(scan, call):
            body = _statement_tokens(scan, call.open_index + 1, limit=60)
            if _callback_always_true(body):
                origin_calls.append(call)
        elif name == "AllowCredentials":
            credentials.append(call)
    for call in origin_calls:
        allowed = next(
            (other for other in credentials if _in_same_region(scan, call.index, other.index)),
            None,
        )
        if allowed is None:
            continue
        scan._report(
            "FSB-CORS-001",
            call.anchor,
            "SetIsOriginAllowed",
            "SetIsOriginAllowed nhận mọi origin trong khi AllowCredentials() được bật, nên "
            "ASP.NET dội lại Origin của người gửi",
            evidence=(
                "AllowCredentials() ở dòng %d" % allowed.anchor.line,
                "AllowAnyOrigin() đi với AllowCredentials() thì CorsPolicyBuilder.Build() ném lỗi, "
                "còn lối này thì chạy",
            ),
        )


# ----------------------------------------------------------------------- Go


def _go(scan: "_Scan") -> None:
    flat = scan.flat
    for index, token in enumerate(flat):
        scan.budget.spend()
        if token.kind != IDENT:
            continue
        if token.text in _GO_ORIGIN_FUNCS:
            _go_origin_func(scan, index, token)
        elif token.text == "Cookie" and index + 1 < len(flat) and flat[index + 1].text == "{":
            _go_cookie(scan, index + 1)


def _go_origin_func(scan: "_Scan", index: int, token: Token) -> None:
    flat = scan.flat
    if index + 1 >= len(flat) or flat[index + 1].text != ":":
        return
    body = _statement_tokens(scan, index + 2, limit=80, stop_at_comma=True)
    if not _callback_always_true(body):
        return
    braces = _enclosing_braces(scan, index)
    if braces is None:
        return
    credentials = _go_credentials(scan, braces)
    if credentials is None:
        return
    scan._report(
        "FSB-CORS-001",
        token,
        token.text,
        "%s cho qua mọi origin trong khi AllowCredentials là true, nên middleware dội lại Origin "
        "của người gửi" % token.text,
        evidence=(
            "hàm quyết định origin trả về true cho mọi origin",
            "AllowCredentials: true ở dòng %d" % credentials,
        ),
    )


def _go_credentials(scan: "_Scan", braces: Tuple[int, int]) -> Optional[int]:
    flat = scan.flat
    for index in range(braces[0], min(braces[1], len(flat))):
        token = flat[index]
        if token.kind == IDENT and token.text == "AllowCredentials":
            if (scan._pair_value(index) or "").lower() == "true":
                return token.line
    return None


def _go_cookie(scan: "_Scan", brace: int) -> None:
    flat = scan.flat
    close = scan.matching.get(brace)
    if close is None:
        return
    name: Optional[str] = None
    anchor: Optional[Token] = None
    state: Optional[bool] = None
    for index in range(brace + 1, min(close, len(flat))):
        token = flat[index]
        if token.kind != IDENT:
            continue
        if token.text == "Name" and name is None:
            value = scan._pair_value(index)
            if value and value.startswith("'"):
                name = value.strip("'")
                anchor = token
        elif token.text in ("HttpOnly", "HTTPOnly"):
            state = (scan._pair_value(index) or "").lower() == "true"
    if name is None or anchor is None or state is True:
        return
    word = words.names_a_session_cookie(name)
    if word is None:
        return
    if _go_httponly_set_later(scan, close):
        return
    if state is False:
        confidence = Confidence.HIGH
        how = "HttpOnly được đặt thẳng là false"
    else:
        confidence = Confidence.MEDIUM
        how = "struct không đặt HttpOnly, mà giá trị rỗng của bool là false"
    _report_cookie(
        scan,
        anchor,
        name,
        _cookie_subject(name),
        confidence,
        (how, "tên cookie chứa từ %r" % word),
    )


def _go_httponly_set_later(scan: "_Scan", close: int) -> bool:
    """`c := &http.Cookie{...}` rồi `c.HttpOnly = true` ở dòng sau."""
    flat = scan.flat
    region = scan._function_at(close)
    end = region[1] if region is not None else min(len(flat), close + 80)
    for index in range(close, min(end, len(flat))):
        token = flat[index]
        if token.kind == IDENT and token.text in ("HttpOnly", "HTTPOnly"):
            if (scan._pair_value(index) or "").lower() == "true":
                return True
    return False


def _enclosing_braces(scan: "_Scan", index: int) -> Optional[Tuple[int, int]]:
    best: Optional[Tuple[int, int]] = None
    for open_index, close_index in scan.matching.items():
        if scan.flat[open_index].text != "{":
            continue
        if open_index < index < close_index:
            if best is None or open_index > best[0]:
                best = (open_index, close_index)
    return best


# ---------------------------------------------------------------------- PHP


def _php(scan: "_Scan") -> None:
    for call in scan.calls:
        scan.budget.spend()
        name = call.parts[-1]
        if name == "setcookie":
            _php_setcookie(scan, call)
        elif name == "ini_set" and len(call.arguments) == 2:
            key = scan._string_value(call.argument(0))
            value = "".join(_texts(call.argument(1))).strip("'\"").lower()
            if key == "session.cookie_httponly" and value in _HTTPONLY_OFF:
                _report_cookie(
                    scan,
                    call.anchor,
                    "session.cookie_httponly",
                    "cookie phiên của PHP",
                    Confidence.HIGH,
                    ("ini_set đặt session.cookie_httponly về %s" % value,),
                )


def _php_setcookie(scan: "_Scan", call: "_Call") -> None:
    name = scan._string_value(call.argument(0))
    if name is None:
        return
    word = words.names_a_session_cookie(name)
    if word is None:
        return
    state: Optional[bool] = None
    if len(call.arguments) >= 7:
        value = "".join(_texts(call.argument(6))).strip().lower()
        state = value in ("true", "1")
    for argument in call.arguments[2:]:
        found = _httponly_state(scan, argument)
        if found is not None:
            state = found
    if state is True:
        return
    if state is False:
        confidence = Confidence.HIGH
        how = "httponly được truyền là false"
    else:
        confidence = Confidence.MEDIUM
        how = "không truyền httponly, mà mặc định của setcookie là không có HttpOnly"
    _report_cookie(
        scan,
        call.anchor,
        name,
        _cookie_subject(name),
        confidence,
        (how, "tên cookie chứa từ %r" % word),
    )


# ------------------------------------------------------- cookie, mọi ngôn ngữ


def _explicit_httponly_off(scan: "_Scan") -> None:
    """`httpOnly: false`, `HttpOnly = false`, `httponly: false`, `HttpOnlyPolicy.None`"""
    flat = scan.flat
    for index, token in enumerate(flat):
        scan.budget.spend()
        if token.kind not in (IDENT, STRING):
            continue
        if token.text.strip().lower().lstrip(":'\"") not in _HTTPONLY_NAMES:
            continue
        if not _is_structure_key(scan, index):
            continue
        value = (scan._pair_value(index) or "").strip("'\":").lower()
        if value not in _HTTPONLY_OFF:
            continue
        if token.line in _reported_lines(scan):
            continue
        if not _mentions_cookie(flat[max(0, index - 40) : index + 10]):
            continue
        _report_cookie(
            scan,
            token,
            token.text,
            "cookie được cấu hình ở đây",
            Confidence.HIGH,
            ("%s được đặt thẳng là %s" % (token.text, value),),
        )


def _is_structure_key(scan: "_Scan", index: int) -> bool:
    """Cờ phải là KHOÁ của một cấu trúc hay THUỘC TÍNH, không phải biến cục bộ.

    `{ httpOnly: false }` và `options.HttpOnly = false` là cấu hình cookie;
    `$httponly = false;` hay `bool httpOnly = false;` chỉ là một biến mà dòng
    này chưa cho biết sẽ đi đâu.
    """
    flat = scan.flat
    if flat[index].text[:1] in ("$", "@"):
        return False
    previous = flat[index - 1] if index else None
    return previous is None or previous.kind != IDENT


def _mentions_cookie(tokens: Sequence[Token]) -> bool:
    for token in tokens:
        if token.kind not in (IDENT, STRING):
            continue
        if any(word in _COOKIE_CONTEXT_WORDS for word in words.split_words(token.text)):
            return True
    return False


def _reported_lines(scan: "_Scan") -> set:
    found = getattr(scan, "cookie_lines", None)
    if found is None:
        found = set()
        setattr(scan, "cookie_lines", found)
    return found


def _report_cookie(
    scan: "_Scan",
    token: Token,
    symbol: str,
    subject: str,
    confidence: Confidence,
    evidence: Sequence[str],
) -> None:
    _reported_lines(scan).add(token.line)
    scan._report(
        "FSB-COOKIE-001",
        token,
        symbol,
        "%s đọc được bằng document.cookie vì không có cờ HttpOnly" % subject,
        confidence=confidence,
        evidence=tuple(evidence),
    )


def _cookie_subject(name: str) -> str:
    return "cookie %r mang phiên đăng nhập" % name


__all__ = ["check"]
