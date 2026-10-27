"""Quyết định quyền bằng trường của request, và mass assignment, đọc theo token.

Cùng nguyên tắc với `access_python`: khoá được đọc ra trước, rồi mới xét xem giá
trị đó dùng để QUYẾT ĐỊNH hay chỉ để lọc. Phần thêm so với bản AST là mỗi ngôn
ngữ có một lối đọc request riêng, nên mỗi lối được khai báo thành bảng chứ không
đoán theo tên chung chung:

* JavaScript gọi theo thuộc tính ( `req.query.role` );
* PHP đọc siêu biến toàn cục ( `$_GET['role']` );
* Java, Go gọi hàm có tên khoá làm đối số ( `request.getParameter("role")` );
* C#, Ruby dùng chỉ số ( `Request.Query["role"]`, `params[:admin]` ).

`session` của Rails và Django không có ở đây: đó là phiên server đã ký, người
gửi sửa được nội dung thì chữ ký hỏng.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from ...core.model import Confidence
from ...languages import CSHARP, GO, JAVA, JAVASCRIPT, PHP, PYTHON, RUBY, TYPESCRIPT
from ..generic.lexer import IDENT, OP, STRING, Token
from . import words
from .config_tokens import _is_declaration, _texts

if TYPE_CHECKING:  # pragma: no cover
    from .tokens import _Call, _Scan

_CONDITION_KEYWORDS = frozenset({"if", "elsif", "elif", "unless", "while", "switch", "when", "return"})
_COMPARISONS = frozenset({"==", "===", "!=", "!==", "<>", "eq", "equals", "equalsIgnoreCase", "is"})

_QUERY = "tham số truy vấn HTTP"
_FORM = "trường form HTTP"
_BODY = "body của request HTTP"
_COOKIE = "cookie HTTP"
_HEADER = "header HTTP"
_PARAM = "tham số của request HTTP"

# receiver -> member: `req.query.role`, `Request.Cookies["role"]`
_RECEIVERS: Dict[str, frozenset] = {
    JAVASCRIPT: frozenset({"req", "request", "ctx"}),
    TYPESCRIPT: frozenset({"req", "request", "ctx"}),
    CSHARP: frozenset({"Request", "HttpContext", "context"}),
}
_MEMBERS: Dict[str, Dict[str, str]] = {
    JAVASCRIPT: {
        "query": _QUERY,
        "body": _BODY,
        "params": _PARAM,
        "cookies": _COOKIE,
        "headers": _HEADER,
    },
    TYPESCRIPT: {
        "query": _QUERY,
        "body": _BODY,
        "params": _PARAM,
        "cookies": _COOKIE,
        "headers": _HEADER,
    },
    CSHARP: {
        "Query": _QUERY,
        "QueryString": _QUERY,
        "Form": _FORM,
        "Cookies": _COOKIE,
        "Headers": _HEADER,
        "Params": _PARAM,
    },
}

# tên đứng một mình: siêu biến của PHP, `params` của Rails
_GLOBALS: Dict[str, Dict[str, str]] = {
    PHP: {
        "$_GET": _QUERY,
        "$_POST": _FORM,
        "$_REQUEST": _PARAM,
        "$_COOKIE": _COOKIE,
        "$_SERVER": _HEADER,
    },
    RUBY: {"params": _PARAM, "cookies": _COOKIE},
}

# hàm nhận tên khoá làm đối số
_METHODS: Dict[str, Dict[str, str]] = {
    JAVA: {
        "getParameter": _QUERY,
        "getParameterValues": _QUERY,
        "getHeader": _HEADER,
    },
    GO: {
        "FormValue": _FORM,
        "PostFormValue": _FORM,
        "PostForm": _FORM,
        "Query": _QUERY,
        "DefaultQuery": _QUERY,
        "Param": _PARAM,
        "GetHeader": _HEADER,
        "Cookie": _COOKIE,
    },
}
# `r.URL.Query().Get("role")`, `r.Header.Get("X-Admin")`: Get quá chung, phải
# nhìn chuỗi gọi mới biết nó đọc gì.
_GO_GET_CHAINS: Dict[str, str] = {"Query": _QUERY, "Header": _HEADER, "Form": _FORM, "PostForm": _FORM}

_HEADER_LABELS = frozenset({_HEADER})

_MASS_BODY_MEMBERS = frozenset({"body"})
_MONGOOSE_WRITES = frozenset(
    {
        "create",
        "findByIdAndUpdate",
        "findOneAndUpdate",
        "findByIdAndReplace",
        "updateOne",
        "updateMany",
        "replaceOne",
        "insertMany",
        "set",
    }
)
_LARAVEL_WRITES = frozenset({"create", "update", "fill", "forceFill", "firstOrCreate", "updateOrCreate"})


# Hàm gộp: tên hàm nói ra ý định ghi khoá của nguồn sang đích. Đòi tên ( hoặc
# đệ quy ) là phép lọc độ chính xác: một vòng lặp `for (k in src)` bất kỳ thì
# chưa nói gì, còn `mergeDeep(target, source)` thì nói rất rõ.
_MERGE_WORDS = ("merge", "extend", "assign", "deep", "copy", "defaults", "populate", "mixin")
# Dấu hiệu tác giả ĐÃ nghĩ tới nguyên mẫu. Đủ một cái là im lặng.
_PROTO_GUARDS = frozenset(
    {
        "hasOwnProperty",
        "__proto__",
        "prototype",
        "constructor",
        "create",
        "freeze",
        "Map",
        "WeakMap",
        "defineProperty",
        "getOwnPropertyNames",
    }
)


def check(scan: "_Scan") -> None:
    if scan.language == PYTHON:  # pragma: no cover - phía Python đi theo AST
        return
    _privilege_decisions(scan)
    _mass_assignment(scan)
    _prototype_pollution(scan)


# ------------------------------------------------------- quyết định quyền


def _privilege_decisions(scan: "_Scan") -> None:
    for token, index, key, label in _request_keys(scan):
        scan.budget.spend()
        if label in _HEADER_LABELS:
            candidates = words.header_key_variants(key)
        else:
            candidates = frozenset({words.normalized_key(key)})
        normalized = next((name for name in candidates if name in words.PRIVILEGE_KEYS), None)
        if normalized is None:
            continue
        window = _condition_window(scan, index)
        if window is None:
            continue
        literal = _privilege_literal(scan, window, index)
        if literal is not None:
            reason = "được so với %r để quyết định quyền" % literal
        elif normalized in words.BOOLEAN_PRIVILEGE_KEYS:
            reason = "được dùng thẳng làm điều kiện cấp quyền"
        else:
            continue
        confidence = Confidence.MEDIUM if label in _HEADER_LABELS else Confidence.HIGH
        evidence = [reason]
        if confidence is Confidence.MEDIUM:
            evidence.append(
                "nếu gateway phía trước XOÁ header này trên mọi request từ ngoài thì đây là "
                "thiết kế có chủ ý, không phải lỗ hổng"
            )
        scan._report(
            "FSB-ACCESS-001",
            token,
            key,
            "quyền được quyết định bằng %r lấy từ %s, thứ người gửi tự đặt được" % (key, label),
            confidence=confidence,
            evidence=tuple(evidence),
        )


def _request_keys(scan: "_Scan") -> List[Tuple[Token, int, str, str]]:
    """( token neo, chỉ số, khoá, nhãn vùng ) của mọi chỗ đọc một khoá từ request."""
    found: List[Tuple[Token, int, str, str]] = []
    flat = scan.flat
    receivers = _RECEIVERS.get(scan.language, frozenset())
    members = _MEMBERS.get(scan.language, {})
    globals_ = _GLOBALS.get(scan.language, {})
    for index, token in enumerate(flat):
        if token.kind != IDENT:
            continue
        label = globals_.get(token.text)
        if label is not None:
            key = _subscript_key(scan, index)
            if key is not None:
                found.append((token, index, key, label))
            continue
        label = members.get(token.text)
        if label is None or index < 2:
            continue
        if flat[index - 1].text not in (".", "?.") or flat[index - 2].text not in receivers:
            continue
        key = _subscript_key(scan, index)
        if key is None and index + 2 < len(flat) and flat[index + 1].text == "." :
            if flat[index + 2].kind == IDENT:
                key = flat[index + 2].text
                found.append((token, index + 2, key, label))
                continue
        if key is not None:
            found.append((token, index, key, label))
    for call in scan.calls:
        label = _call_label(scan, call)
        if label is None or _is_declaration(scan, call):
            continue
        key = scan._string_value(call.argument(0))
        if key is not None:
            found.append((call.anchor, call.index, key, label))
    return found


def _call_label(scan: "_Scan", call: "_Call") -> Optional[str]:
    methods = _METHODS.get(scan.language, {})
    name = call.parts[-1]
    label = methods.get(name)
    if label is not None:
        return label
    if scan.language == GO and name == "Get":
        for part in call.parts:
            found = _GO_GET_CHAINS.get(part)
            if found is not None:
                return found
    return None


def _subscript_key(scan: "_Scan", index: int) -> Optional[str]:
    """`params[:admin]`, `$_GET['role']`, `Request.Query["role"]`"""
    flat = scan.flat
    if index + 2 >= len(flat) or flat[index + 1].text != "[":
        return None
    key = flat[index + 2]
    if key.kind == STRING:
        return key.text
    if key.kind == OP and key.text == ":" and index + 3 < len(flat) and flat[index + 3].kind == IDENT:
        return flat[index + 3].text  # ký hiệu của Ruby
    return None


def _condition_window(scan: "_Scan", index: int) -> Optional[Tuple[int, int]]:
    """Khoảng token của điều kiện bao quanh chỗ đọc, nếu có."""
    flat = scan.flat
    cursor = index
    for _ in range(6):
        opening = _enclosing_paren(scan, cursor)
        if opening is None:
            break
        if opening and flat[opening - 1].kind == IDENT and flat[opening - 1].text in _CONDITION_KEYWORDS:
            close = scan.matching.get(opening)
            if close is not None:
                return (opening + 1, close)
        cursor = opening
    line = flat[index].line
    start = index
    while start > 0 and flat[start - 1].line == line and index - start < 40:
        start -= 1
        if flat[start].kind == IDENT and flat[start].text in _CONDITION_KEYWORDS:
            if _guards_only_an_assignment(scan, start):
                return None
            end = index
            while end + 1 < len(flat) and flat[end + 1].line == line:
                end += 1
            return (start + 1, end + 1)
    # `grant_admin if params[:admin]` của Ruby và Perl
    end = index
    while end + 1 < len(flat) and flat[end + 1].line == line and end - index < 40:
        end += 1
        if flat[end].kind == IDENT and flat[end].text in ("if", "unless"):
            if _guards_only_an_assignment(scan, end):
                return None
            return (index, end)
    return None


_ASSIGNMENTS = frozenset({"=", "||=", "&&=", "+=", "-=", "*=", "|=", "<<="})


def _guards_only_an_assignment(scan: "_Scan", keyword: int) -> bool:
    """`translated_params[:role_ids] = ... if params[:permissions] == 'staff'`

    Hậu tố `if` của Ruby che một câu nằm BÊN TRÁI nó. Khi câu đó là một phép
    gán thì so sánh kia chỉ chọn DỮ LIỆU chứ không cấp quyền: hai chỗ trong
    admin controller của mastodon đúng hình này, và cả hai là bộ lọc truy vấn
    ( `?permissions=staff` nghĩa là "liệt kê tài khoản staff" ), còn phép kiểm
    quyền thật nằm ở `authorize`. Phép cấp quyền thì gọi hàm hoặc trả về.
    """
    flat = scan.flat
    if flat[keyword].text not in ("if", "unless"):
        return False
    line = flat[keyword].line
    depth = 0
    position = keyword - 1
    while position >= 0 and flat[position].line == line:
        text = flat[position].text
        if text in (")", "]", "}"):
            depth += 1
        elif text in ("(", "[", "{"):
            depth -= 1
        elif depth == 0 and text in _ASSIGNMENTS:
            return True
        position -= 1
    return False


def _enclosing_paren(scan: "_Scan", index: int) -> Optional[int]:
    best: Optional[int] = None
    for open_index, close_index in scan.matching.items():
        if scan.flat[open_index].text != "(":
            continue
        if open_index < index <= close_index and (best is None or open_index > best):
            best = open_index
    return best


def _privilege_literal(scan: "_Scan", window: Tuple[int, int], index: int) -> Optional[str]:
    flat = scan.flat
    start, end = window
    has_comparison = any(
        flat[position].text in _COMPARISONS for position in range(start, min(end, len(flat)))
    )
    if not has_comparison:
        return None
    for position in range(start, min(end, len(flat))):
        token = flat[position]
        if position == index or token.kind != STRING:
            continue
        if words.normalized_key(token.text) in words.PRIVILEGE_VALUES:
            return token.text
    return None


# ------------------------------------------------------- prototype pollution


def _prototype_pollution(scan: "_Scan") -> None:
    if scan.language not in (JAVASCRIPT, TYPESCRIPT):
        return
    flat = scan.flat
    for index, token in enumerate(flat):
        if token.kind != IDENT or token.text != "for" or index + 1 >= len(flat):
            continue
        scan.budget.spend()
        if flat[index + 1].text != "(":
            continue
        close = scan.matching.get(index + 1)
        if close is None:
            continue
        key = _loop_key(scan, index + 2, close)
        if key is None:
            continue
        body = _loop_body(scan, close)
        if body is None:
            continue
        target = _writes_key(scan, body, key)
        if target is None:
            continue
        region = scan._function_at(index)
        if not _looks_like_a_merge(scan, region):
            continue
        if _names_in(scan, region) & _PROTO_GUARDS:
            continue
        fed = _request_in_header(scan, index + 2, close) or _fed_request_data(scan, region)
        if fed is None:
            continue
        scan._report(
            "FSB-PROTO-001",
            flat[target],
            flat[target].text,
            "ghi `%s[%s]` theo khoá của đối tượng nguồn: khoá `__proto__` đi thẳng vào nguyên "
            "mẫu, nên một thuộc tính bơm vào đó hiện ra ở MỌI đối tượng"
            % (flat[target].text, key),
            evidence=(
                "không thấy phép loại khoá nào trong hàm ( hasOwnProperty, so với "
                "'__proto__' / 'constructor', hay Object.create(null) )",
                fed,
            ),
        )


def _loop_key(scan: "_Scan", start: int, close: int) -> Optional[str]:
    """`for (const k in src)` và `for (const k of Object.keys(src))` -> tên k."""
    flat = scan.flat
    for position in range(start, min(close, len(flat))):
        text = flat[position].text
        if text not in ("in", "of") or flat[position].kind != IDENT:
            continue
        if text == "of" and not any(
            flat[rest].text == "keys" for rest in range(position, min(close, len(flat)))
        ):
            return None
        name = flat[position - 1]
        return name.text if name.kind == IDENT else None
    return None


def _loop_body(scan: "_Scan", close: int) -> Optional[Tuple[int, int]]:
    flat = scan.flat
    if close + 1 >= len(flat) or flat[close + 1].text != "{":
        return None
    end = scan.matching.get(close + 1)
    return (close + 2, end) if end is not None else None


def _writes_key(scan: "_Scan", body: Tuple[int, int], key: str) -> Optional[int]:
    """Chỉ số token của đích trong `target[key] = ...`."""
    flat = scan.flat
    start, end = body
    for position in range(start, min(end, len(flat) - 4)):
        if flat[position].kind != IDENT or flat[position + 1].text != "[":
            continue
        if flat[position + 2].kind != IDENT or flat[position + 2].text != key:
            continue
        if flat[position + 3].text != "]" or flat[position + 4].text != "=":
            continue
        return position
    return None


# Khoá phải CÓ TỪ NGOÀI VÀO mới thành lỗ hổng. Bản đầu của rule bỏ qua điều
# đó và báo đúng 9 chỗ trên 28 repo thật -- tất cả đều là hàm gộp nội bộ của
# thư viện đi kèm ( moment, globalize, cldrjs, ace ), nơi nguồn là chính cấu
# hình của thư viện. Nên giờ phải thấy dữ liệu request hoặc JSON.parse ở ngay
# đường vào, trong cùng tệp.
_REQUEST_SOURCES = (
    ("req", "body"),
    ("req", "query"),
    ("req", "params"),
    ("request", "body"),
    ("request", "query"),
    ("ctx", "request"),
)
_PARSERS = frozenset({"parse", "parseQuery", "qs"})


def _request_in_header(scan: "_Scan", start: int, close: int) -> Optional[str]:
    """`for (const key in req.body)`: dữ liệu người gửi nằm ngay trong đầu vòng lặp."""
    flat = scan.flat
    for position in range(start, min(close - 1, len(flat) - 2)):
        if flat[position + 1].text != ".":
            continue
        if _is_request_pair(flat[position].text, flat[position + 2].text):
            return "vòng lặp duyệt thẳng khoá của %s.%s" % (
                flat[position].text,
                flat[position + 2].text,
            )
    return None


def _fed_request_data(scan: "_Scan", region: Optional[Tuple[int, int, str]]) -> Optional[str]:
    """Câu bằng chứng, nếu thấy dữ liệu người gửi đi vào hàm gộp này.

    Hai lối: chính vòng lặp duyệt `req.body`, hoặc hàm gộp được gọi ở đâu đó
    trong cùng tệp với một đối số là dữ liệu request hay `JSON.parse(...)`.
    """
    name = (region[2] if region is not None else "") or ""
    if name == "":
        return None
    for call in scan.calls:
        if call.parts[-1] != name:
            continue
        if region is not None and region[0] <= call.index <= region[1]:
            continue  # lời gọi đệ quy bên trong chính nó
        for argument in call.arguments:
            texts = [token.text for token in argument if token.kind == IDENT]
            for position in range(1, len(texts)):
                if _is_request_pair(texts[position - 1], texts[position]):
                    return "%s() được gọi với %s.%s ở dòng %d" % (
                        name,
                        texts[position - 1],
                        texts[position],
                        call.anchor.line,
                    )
            if "JSON" in texts and _PARSERS & set(texts):
                return "%s() được gọi với JSON.parse(...) ở dòng %d" % (name, call.anchor.line)
    return None


def _is_request_pair(receiver: str, member: str) -> bool:
    return (receiver, member) in _REQUEST_SOURCES


def _looks_like_a_merge(scan: "_Scan", region: Optional[Tuple[int, int, str]]) -> bool:
    """Tên hàm nói ra ý định gộp, hoặc hàm gọi lại chính nó để đi vào đối tượng lồng."""
    if region is None:
        return False
    name = region[2] or ""
    if any(word in name.lower() for word in _MERGE_WORDS):
        return True
    if name == "":
        return False
    return any(token.text == name for token in scan.flat[region[0] : region[1] + 1])


def _names_in(scan: "_Scan", region: Optional[Tuple[int, int, str]]) -> frozenset:
    start, end = (region[0], region[1]) if region is not None else (0, len(scan.flat))
    return frozenset(
        token.text for token in scan.flat[start : end + 1] if token.kind in (IDENT, STRING)
    )


# ---------------------------------------------------------- mass assignment


def _mass_assignment(scan: "_Scan") -> None:
    language = scan.language
    if language in (JAVASCRIPT, TYPESCRIPT):
        _javascript_mass(scan)
    elif language == RUBY:
        _ruby_mass(scan)
    elif language == PHP:
        _php_mass(scan)


def _javascript_mass(scan: "_Scan") -> None:
    receivers = _RECEIVERS[scan.language]
    for call in scan.calls:
        scan.budget.spend()
        position = _whole_body_argument(call, receivers)
        if position is None:
            continue
        name = call.parts[-1]
        if name == "assign" and call.parts[:1] == ("Object",):
            target = "Object.assign"
        elif name in _MONGOOSE_WRITES or _is_constructor(scan, call):
            target = ".".join(call.parts)
        else:
            continue
        scan._report(
            "FSB-MASS-001",
            call.anchor,
            name,
            "%s nhận thẳng cả req.body, nên người gửi ghi được mọi trường của đối tượng" % target,
            confidence=Confidence.MEDIUM,
            evidence=(
                "không thấy danh sách trường được phép giữa body và đối tượng được lưu",
            ),
        )


def _whole_body_argument(call: "_Call", receivers) -> Optional[int]:
    """Đối số nào là NGUYÊN cả body ( `req.body` ), không phải một trường của nó."""
    for position, argument in enumerate(call.arguments):
        texts = _texts(argument)
        if len(texts) != 3 or texts[1] != ".":
            continue
        if texts[0] in receivers and texts[2] in _MASS_BODY_MEMBERS:
            return position
    return None


def _is_constructor(scan: "_Scan", call: "_Call") -> bool:
    """`new User(req.body)`"""
    flat = scan.flat
    if not call.index or flat[call.index - 1].text != "new":
        return False
    return call.parts[-1][:1].isupper()


def _ruby_mass(scan: "_Scan") -> None:
    flat = scan.flat
    for index, token in enumerate(flat):
        scan.budget.spend()
        if token.kind != IDENT:
            continue
        name = token.text
        if name == "permit!" or (name == "permit" and index + 1 < len(flat) and flat[index + 1].text == "!"):
            if index and flat[index - 1].text in (".", "&."):
                scan._report(
                    "FSB-MASS-001",
                    token,
                    "permit!",
                    "params.permit! cho phép ghi MỌI khoá người gửi đưa lên vào model",
                    confidence=Confidence.HIGH,
                    evidence=("permit! bỏ hẳn danh sách trường được phép",),
                )
        elif name == "permit" and index and flat[index - 1].text == ".":
            _ruby_permits_privilege(scan, index, token)


def _ruby_permits_privilege(scan: "_Scan", index: int, token: Token) -> None:
    flat = scan.flat
    if index + 1 >= len(flat) or flat[index + 1].text != "(":
        return
    close = scan.matching.get(index + 1)
    if close is None:
        return
    for position in range(index + 2, min(close, len(flat))):
        inner = flat[position]
        if not _is_literal_field(scan, position):
            continue
        if words.normalized_key(inner.text) in words.PRIVILEGE_KEYS:
            scan._report(
                "FSB-MASS-001",
                token,
                "permit",
                "permit cho phép ghi %r, tức là người gửi tự đặt được quyền của mình" % inner.text,
                confidence=Confidence.MEDIUM,
                evidence=(
                    "cột quyết định quyền chỉ nên đổi được qua một đường riêng có kiểm quyền",
                ),
            )
            return


def _is_literal_field(scan: "_Scan", position: int) -> bool:
    """Chỉ `:role` hay `'role'` mới là tên trường được permit.

    `permit(:page, *Admin::ActionLogFilter::KEYS)` của mastodon từng bị báo vì
    token `Admin` nằm trong đường dẫn hằng -- đó là TÊN MÔ ĐUN, không phải cột
    nào cả, và danh sách trường thật thì nằm ở tệp khác.
    """
    flat = scan.flat
    token = flat[position]
    if token.kind == STRING:
        return True
    if token.kind != IDENT or position == 0:
        return False
    if flat[position - 1].text != ":":
        return False
    if position >= 2 and flat[position - 2].text in (":", "::"):
        return False
    return position + 1 >= len(flat) or flat[position + 1].text not in (":", "::")


def _php_mass(scan: "_Scan") -> None:
    for call in scan.calls:
        scan.budget.spend()
        if call.parts[-1] not in _LARAVEL_WRITES:
            continue
        for argument in call.arguments:
            texts = _texts(argument)
            if texts[:1] == ["$request"] and "all" in texts:
                scan._report(
                    "FSB-MASS-001",
                    call.anchor,
                    call.parts[-1],
                    "%s() nhận thẳng $request->all(), nên người gửi ghi được mọi cột của model"
                    % call.parts[-1],
                    confidence=Confidence.MEDIUM,
                    evidence=("không thấy danh sách trường được phép giữa request và model",),
                )
                break


__all__ = ["check"]
