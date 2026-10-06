"""Cấu hình nguy hiểm đọc theo token: giải tuần tự đa hình và JWT không xác minh.

Hai họ này không có "nguồn chảy tới sink": lỗi nằm ở một công tắc cấu hình
( `TypeNameHandling.All`, `enableDefaultTyping()`, `RequireSignedTokens = false` )
hoặc ở việc gọi đúng API bỏ qua chữ ký. Mỗi kiểm tra ở đây khớp một công tắc
cụ thể của một thư viện cụ thể, không khớp tên hàm chung chung như `decode`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence

from ...core.model import Confidence
from ...languages import CSHARP, GO, JAVA, JAVASCRIPT, RUBY, TYPESCRIPT
from ..generic.lexer import IDENT, OP, STRING, Token
from . import words

if TYPE_CHECKING:  # pragma: no cover
    from .tokens import _Call, _Scan

_SEPARATORS = frozenset({".", "::", "->", "?."})

# Json.NET: mọi giá trị khác None đều để payload tự khai "$type".
_TYPE_NAME_PROPERTIES = frozenset({"TypeNameHandling", "ItemTypeNameHandling"})
_POLYMORPHIC_TYPE_NAMES = frozenset({"All", "Auto", "Objects", "Arrays"})
_BINDER_PROPERTIES = frozenset({"SerializationBinder", "Binder"})

_JACKSON_DEFAULT_TYPING = frozenset({"enableDefaultTyping", "enableDefaultTypingAsProperty"})
_JACKSON_ACTIVATE_TYPING = frozenset({"activateDefaultTyping", "activateDefaultTypingAsProperty"})

# jjwt: các API này CHỈ nhận token không ký.
_JJWT_UNSIGNED_PARSERS = frozenset(
    {"parseClaimsJwt", "parsePlaintextJwt", "parseUnsecuredClaims", "parseUnsecuredContent"}
)
# API của jjwt trước 0.12: ở đó parse() trả về cả token không ký.
_JJWT_LEGACY_SETUP = frozenset({"setSigningKey", "setSigningKeyResolver", "parserBuilder"})
_JJWT_MODERN_SETUP = frozenset({"verifyWith", "keyLocator", "unsecured"})

_GO_VERIFYING_PARSERS = frozenset({"Parse", "ParseWithClaims"})


def check(scan: "_Scan") -> None:
    language = scan.language
    if language == CSHARP:
        _csharp(scan)
    elif language == JAVA:
        _java(scan)
    elif language == RUBY:
        _ruby(scan)
    elif language == GO:
        _go(scan)
    elif language in (JAVASCRIPT, TYPESCRIPT):
        _javascript(scan)


# ---------------------------------------------------------------- helpers


def receivers(scan: "_Scan", index: int) -> List[str]:
    """Tên đứng trước một lời gọi theo chuỗi phương thức, gần nhất trước.

    `Jwts.parser().setSigningKey(k).parse(t)` đứng ở `parse` cho ra
    `["setSigningKey", "parser", "Jwts"]`.
    """
    flat = scan.flat
    found: List[str] = []
    cursor = index
    for _ in range(40):
        if cursor < 2 or flat[cursor - 1].kind != OP or flat[cursor - 1].text not in _SEPARATORS:
            break
        previous = cursor - 2
        token = flat[previous]
        if token.kind == OP and token.text == ")":
            opening = scan.opening.get(previous)
            if opening is None or opening == 0 or flat[opening - 1].kind != IDENT:
                break
            previous = opening - 1
        elif token.kind != IDENT:
            break
        found.append(flat[previous].text.lstrip("$:"))
        cursor = previous
    return found


def _full_chain(scan: "_Scan", call: "_Call") -> List[str]:
    return list(reversed(receivers(scan, call.index))) + list(call.parts)


def _texts(tokens: Iterable[Token]) -> List[str]:
    return [token.text for token in tokens]


def _contains_sequence(tokens: Sequence[Token], sequence: Sequence[str]) -> bool:
    texts = _texts(tokens)
    size = len(sequence)
    return any(texts[start : start + size] == list(sequence) for start in range(len(texts) - size + 1))


def _resolve(scan: "_Scan", tokens: Sequence[Token]) -> Sequence[Token]:
    """Một tên đứng một mình -> vế phải của phép gán duy nhất cho nó."""
    if len(tokens) == 1 and tokens[0].kind == IDENT:
        values = scan.bindings.get(tokens[0].text.lstrip("$")) or []
        if len(values) == 1 and values[0] is not None:
            return values[0]
    return tokens


def _next_is_assignment(scan: "_Scan", index: int) -> bool:
    flat = scan.flat
    return index + 1 < len(flat) and flat[index + 1].kind == OP and flat[index + 1].text in ("=", ":")


def _statement_tokens(scan: "_Scan", index: int, limit: int = 80, stop_at_comma: bool = False) -> List[Token]:
    """Từ `index` tới hết câu lệnh ( `;` cùng cấp, hoặc ngoặc đóng lệch ).

    `stop_at_comma` dừng cả ở dấu phẩy cùng cấp: một mục trong object
    initializer `{ A = x, B = y }` chỉ là `A = x`.
    """
    collected: List[Token] = []
    depth = 0
    for token in scan.flat[index : index + limit]:
        if token.kind == OP:
            if token.text in "([{":
                depth += 1
            elif token.text in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif depth == 0 and (token.text == ";" or (stop_at_comma and token.text == ",")):
                break
        collected.append(token)
    return collected


def _is_declaration(scan: "_Scan", call: "_Call") -> bool:
    """`public ObjectMapper enableDefaultTyping() {` là khai báo, không phải lời gọi."""
    flat = scan.flat
    after = call.close_index + 1
    if after < len(flat) and flat[after].text in ("{", "throws"):
        return True
    if call.index and flat[call.index - 1].text == ")":
        # Go: func (p *Parser) ParseUnverified(...)
        opening = scan.opening.get(call.index - 1)
        if opening and flat[opening - 1].text == "func":
            return True
    previous = flat[call.index - 1] if call.index else None
    if previous is not None and previous.kind == IDENT and previous.line == call.anchor.line:
        # `ObjectMapper enableDefaultTyping(`: kiểu trả về đứng ngay trước tên.
        return previous.text not in (
            "return", "new", "throw", "await", "yield", "else", "case", "defer", "go", "then", "do"
        )
    return False


def _implements(scan: "_Scan", call: "_Call", names) -> bool:
    """Thư viện cài đặt chính công tắc đó, như jackson-databind với enableDefaultTyping."""
    region = scan._function_at(call.index)
    return region is not None and region[2] in names


def _mentions_jwt(scan: "_Scan") -> bool:
    return any(
        token.kind in (IDENT, STRING) and "jwt" in token.text.lower() for token in scan.flat
    )


def _in_same_region(scan: "_Scan", first: int, second: int) -> bool:
    region = scan._function_at(first)
    if region is None:
        return scan._function_at(second) is None
    return region[0] <= second <= region[1]


def _report_unverified(scan: "_Scan", call: "_Call", symbol: str, how: str, verifying) -> None:
    """Đọc claims không xác minh: bỏ qua khi chỉ là đọc trước iss / kid."""
    region = scan._function_at(call.index)
    if region is not None and words.names_a_peek(region[2]):
        return
    elsewhere = None
    for other in scan.calls:
        if other is call or not verifying(other):
            continue
        if region is not None and region[0] <= other.index <= region[1]:
            return
        elsewhere = elsewhere or other
    outputs, _ = scan._output_names(call)
    outputs.extend(_subscript_keys(scan, call))
    if any(words.names_a_peek(name) for name in outputs):
        return
    evidence = [
        "không thấy lời gọi xác minh nào khác trong cùng hàm",
        "nếu chữ ký đã được kiểm ở tầng khác ( gateway, middleware ) thì đây không phải lỗ hổng",
    ]
    confidence = Confidence.MEDIUM
    if elsewhere is not None:
        # Cùng tệp có xác minh thật: lời gọi này nhiều khả năng chỉ đọc trước để định tuyến.
        confidence = Confidence.LOW
        evidence.append("cùng tệp có lời gọi xác minh ở dòng %d" % elsewhere.anchor.line)
    scan._report(
        "FSB-JWT-001",
        call.anchor,
        symbol,
        "%s đọc claims với %s; ai cũng sửa được nội dung token mà không cần khoá" % (symbol, how),
        confidence=confidence,
        evidence=tuple(evidence),
    )


def guard_names(scan: "_Scan", index: int) -> List[str]:
    """Mọi tên trong điều kiện quyết định dòng này có chạy hay không.

    Gồm điều kiện các `if` bao quanh ( trong cùng hàm ), `if` / `unless` đặt
    cuối dòng của Ruby và Perl, và nhãn `case` gần nhất phía trên trong cùng
    khối `switch`. Dấu `{` của object literal hay composite literal
    ( `{ rejectUnauthorized: false }`, `&tls.Config{...}` ) được đi xuyên qua.
    """
    flat = scan.flat
    names: List[str] = []
    line = flat[index].line
    cursor = index + 1
    while cursor < len(flat) and flat[cursor].line == line:
        if flat[cursor].kind == IDENT and flat[cursor].text in ("if", "unless"):
            names.extend(
                t.text for t in flat[cursor + 1 : cursor + 12] if t.line == line and t.kind in (IDENT, STRING)
            )
            break
        cursor += 1
    region = scan._function_at(index)
    # Vùng "hàm" có thể chính là khối `if f(x) {` ( trông y như khai báo hàm ),
    # nên dấu `{` mở vùng vẫn được xét.
    floor = region[0] if region is not None else 0
    depth = 0
    seen_case = False
    cursor = index - 1
    while cursor >= floor and index - cursor < 400:
        token = flat[cursor]
        if token.kind == OP and token.text == "}":
            depth += 1
        elif token.kind == OP and token.text == "{":
            if depth:
                depth -= 1
            else:
                condition = _if_condition_before(scan, cursor)
                if condition is not None:
                    names.extend(condition)
                elif _switch_body(scan, cursor):
                    seen_case = True  # đã ra khỏi khối switch, các case phía trên không còn của mình
        elif depth == 0 and not seen_case and token.kind == IDENT and token.text == "case":
            names.extend(t.text for t in flat[cursor + 1 : cursor + 4] if t.kind in (IDENT, STRING))
            seen_case = True
        cursor -= 1
    return names


def _if_condition_before(scan: "_Scan", brace: int) -> Optional[List[str]]:
    """`if (cond) {` hoặc `if cond {` ( Go, Rust ): tên trong cond."""
    flat = scan.flat
    before = brace - 1
    if before >= 0 and flat[before].text == ")":
        opening = scan.opening.get(before)
        if opening and flat[opening - 1].text == "if":
            return [t.text for t in flat[opening + 1 : before] if t.kind in (IDENT, STRING)]
    # Go / Rust: không có ngoặc, điều kiện nằm trên cùng dòng với `{`.
    line = flat[brace].line
    back = brace - 1
    collected: List[str] = []
    while back >= 0 and flat[back].line == line and brace - back < 40:
        token = flat[back]
        if token.kind == IDENT and token.text == "if":
            return collected
        if token.kind in (IDENT, STRING):
            collected.append(token.text)
        back -= 1
    return None


def _switch_body(scan: "_Scan", brace: int) -> bool:
    flat = scan.flat
    before = brace - 1
    if before >= 0 and flat[before].text == ")":
        opening = scan.opening.get(before)
        return bool(opening) and flat[opening - 1].text == "switch"
    line = flat[brace].line
    back = brace - 1
    while back >= 0 and flat[back].line == line and brace - back < 20:
        if flat[back].kind == IDENT and flat[back].text in ("switch", "select"):
            return True
        back -= 1
    return False


def _guard_condition(scan: "_Scan", index: int) -> List[str]:
    """Tên trong điều kiện `if` bao quanh token ( dùng cho keyfunc của golang-jwt )."""
    return guard_names(scan, index)


def _subscript_keys(scan: "_Scan", call: "_Call") -> List[str]:
    flat = scan.flat
    after = call.close_index + 1
    if after + 2 < len(flat) and flat[after].text == "[" and flat[after + 1].kind == STRING:
        return [flat[after + 1].text]
    return []


def _jwt_none(scan: "_Scan", token: Token, symbol: str, message: str) -> None:
    scan._report("FSB-JWT-001", token, symbol, message)


def _deser(scan: "_Scan", token: Token, symbol: str, message: str, evidence: Sequence[str] = ()) -> None:
    scan._report("FSB-DESER-003", token, symbol, message, evidence=evidence)


def _none_in_list(tokens: Sequence[Token]) -> Optional[Token]:
    for token in tokens:
        if token.kind == STRING and token.text.strip().lower() == "none":
            return token
    return None


def _pair_list(scan: "_Scan", index: int, separators: Sequence[str] = (":", "=>")) -> Sequence[Token]:
    """`algorithms: ['HS256', 'none']` -> các token trong cặp ngoặc vuông.

    Chỉ nhận dạng cặp khoá / giá trị của object literal hay hash: phép gán
    `options.algorithms = ['none']` là mã bên trong chính thư viện JWT.
    """
    flat = scan.flat
    cursor = index + 1
    if cursor + 1 >= len(flat) or flat[cursor].text not in separators:
        return ()
    opening = cursor + 1
    if flat[opening].text != "[":
        # `algorithms: algs` -> lần theo tên
        value = scan.bindings.get(flat[opening].text.lstrip("$")) if flat[opening].kind == IDENT else None
        if value and len(value) == 1 and value[0] is not None:
            return value[0]
        if flat[opening].kind == STRING:
            return (flat[opening],)
        return ()
    close = scan.matching.get(opening)
    if close is None:
        return ()
    return tuple(flat[opening + 1 : close])


# ------------------------------------------------------------------- C#


def _csharp(scan: "_Scan") -> None:
    flat = scan.flat
    binders = [
        index
        for index, token in enumerate(flat)
        if token.kind == IDENT and token.text in _BINDER_PROPERTIES and _next_is_assignment(scan, index)
    ]
    for index, token in enumerate(flat):
        scan.budget.spend()
        if token.kind != IDENT:
            continue
        if token.text in _TYPE_NAME_PROPERTIES and _next_is_assignment(scan, index):
            value = scan._pair_value(index)
            if value in _POLYMORPHIC_TYPE_NAMES:
                if any(_in_same_region(scan, index, binder) for binder in binders):
                    continue  # có SerializationBinder giới hạn kiểu đi kèm
                _deser(
                    scan,
                    token,
                    token.text,
                    "Json.NET đặt %s = %s nên payload tự chọn kiểu qua trường $type" % (token.text, value),
                    evidence=("không thấy SerializationBinder giới hạn kiểu trong cùng hàm",),
                )
        elif token.text == "SimpleTypeResolver" and index and flat[index - 1].text == "new":
            _deser(
                scan,
                token,
                "SimpleTypeResolver",
                "JavaScriptSerializer dùng SimpleTypeResolver nên payload tự chọn kiểu qua trường __type",
            )
        elif token.text == "RequireSignedTokens" and _next_is_assignment(scan, index):
            if scan._pair_value(index) == "false":
                _jwt_none(
                    scan,
                    token,
                    "RequireSignedTokens",
                    "TokenValidationParameters đặt RequireSignedTokens = false nên nhận cả JWT không ký",
                )
        elif token.text == "SignatureValidator" and _next_is_assignment(scan, index):
            statement = _statement_tokens(scan, index + 2, stop_at_comma=True)
            builds_token = _contains_sequence(statement, ("new", "JwtSecurityToken")) or _contains_sequence(
                statement, ("new", "JsonWebToken")
            )
            # Bộ xác minh tự viết có kiểm gì đó trước khi trả token thì không phải bypass.
            checks_something = any(
                t.kind == IDENT and (t.text in ("if", "throw") or t.text.startswith(("Validate", "Verify", "Check")))
                for t in statement
            )
            if builds_token and not checks_something:
                _jwt_none(
                    scan,
                    token,
                    "SignatureValidator",
                    "SignatureValidator trả token về mà không kiểm chữ ký nên mọi chữ ký đều được nhận",
                )


# ------------------------------------------------------------------- Java


_JAVA_SWITCHES = (
    _JACKSON_DEFAULT_TYPING | _JACKSON_ACTIVATE_TYPING | {"setAutoTypeSupport", "setRegistrationRequired"}
)


def _java(scan: "_Scan") -> None:
    flat = scan.flat
    for call in scan.calls:
        scan.budget.spend()
        name = call.parts[-1]
        if _is_declaration(scan, call) or _implements(scan, call, _JAVA_SWITCHES):
            continue
        if name in _JACKSON_DEFAULT_TYPING:
            _deser(
                scan,
                call.anchor,
                name,
                "Jackson bật %s() nên payload tự chọn lớp được khởi tạo qua thông tin kiểu" % name,
            )
        elif name in _JACKSON_ACTIVATE_TYPING and call.arguments:
            validator = _resolve(scan, call.argument(0))
            if _permissive_validator(scan, validator):
                _deser(
                    scan,
                    call.anchor,
                    name,
                    "Jackson %s() với bộ kiểm kiểu cho phép mọi lớp" % name,
                    evidence=("validator là LaissezFaireSubTypeValidator hoặc cho phép Object.class",),
                )
        elif name == "setAutoTypeSupport" and _texts(call.argument(0)) == ["true"]:
            _deser(scan, call.anchor, name, "fastjson bật autoType nên payload tự chọn lớp qua trường @type")
        elif name == "setRegistrationRequired" and _texts(call.argument(0)) == ["false"]:
            _deser(
                scan,
                call.anchor,
                name,
                "Kryo tắt bắt buộc đăng ký lớp nên payload khởi tạo được lớp bất kỳ trên classpath",
            )
        elif name in _JJWT_UNSIGNED_PARSERS:
            _jwt_none(scan, call.anchor, name, "jjwt %s() chỉ nhận JWT không ký, tức là không có chữ ký để xác minh" % name)
        elif name == "unsecured" and "Jwts" in _full_chain(scan, call):
            _jwt_none(scan, call.anchor, "unsecured", "parser của jjwt bật unsecured() nên nhận cả JWT không ký")
        elif name == "parse" and len(call.arguments) == 1:
            chain = _full_chain(scan, call)
            # JwtParser p = Jwts.parser().setSigningKey(k);  p.parse(t)
            chain.extend(t.text for t in _resolve(scan, (call.anchor,)) if t.kind == IDENT)
            if (
                ("Jwts" in chain or "parser" in chain)
                and any(part in _JJWT_LEGACY_SETUP for part in chain)
                and not any(part in _JJWT_MODERN_SETUP for part in chain)
            ):
                scan._report(
                    "FSB-JWT-001",
                    call.anchor,
                    "parse",
                    "parse() của jjwt trước 0.12 trả về cả JWT không ký ( alg none ) dù đã đặt khoá",
                    confidence=Confidence.MEDIUM,
                    evidence=(
                        "chuỗi gọi dùng %s, API của jjwt trước 0.12"
                        % next(part for part in chain if part in _JJWT_LEGACY_SETUP),
                        "parseClaimsJws() mới bắt buộc chữ ký",
                    ),
                )
        elif name == "require" and "JWT" in _full_chain(scan, call):
            for argument in call.arguments:
                if _contains_sequence(argument, ("Algorithm", ".", "none")):
                    _jwt_none(scan, call.anchor, "Algorithm.none", "JWT.require(Algorithm.none()) nhận token không ký")
    for index, token in enumerate(flat):
        if token.kind != IDENT:
            continue
        if token.text == "SupportAutoType" and index >= 2 and flat[index - 2].text == "Feature":
            _deser(scan, token, "Feature.SupportAutoType", "fastjson bật Feature.SupportAutoType cho lần đọc này")
        elif (
            token.text == "AnyTypePermission"
            and index + 2 < len(flat)
            and flat[index + 1].text == "."
            and flat[index + 2].text == "ANY"
        ):
            _deser(scan, token, "AnyTypePermission.ANY", "XStream cho phép mọi kiểu ( AnyTypePermission.ANY )")


def _permissive_validator(scan: "_Scan", tokens: Sequence[Token]) -> bool:
    if any(token.text == "LaissezFaireSubTypeValidator" for token in tokens):
        return True
    for method in ("allowIfSubType", "allowIfBaseType"):
        if _contains_sequence(tokens, (method, "(", "Object", ".", "class", ")")):
            return True
    return False


# ------------------------------------------------------------------- Ruby


def _ruby(scan: "_Scan") -> None:
    flat = scan.flat
    for call in scan.calls:
        scan.budget.spend()
        chain = _full_chain(scan, call)
        if chain[:1] == ["Oj"]:
            for argument in call.arguments:
                _ruby_oj_mode(scan, argument)
        if chain == ["JWT", "decode"]:
            _ruby_jwt(scan, call)
    for index, token in enumerate(flat):
        if token.kind not in (IDENT, STRING):
            continue
        if token.text == "create_additions" and scan._pair_value(index) == "true":
            _deser(
                scan,
                token,
                "create_additions",
                "JSON được đặt create_additions: true nên payload tự chọn lớp qua trường json_class",
            )
        elif token.text == "default_options" and index >= 2 and flat[index - 2].text == "Oj":
            if index + 1 < len(flat) and flat[index + 1].text == "=":
                _ruby_oj_mode(scan, _statement_tokens(scan, index + 2))


def _ruby_oj_mode(scan: "_Scan", tokens: Sequence[Token]) -> None:
    for position, token in enumerate(tokens):
        if token.text != "mode" or token.kind not in (IDENT, STRING):
            continue
        index = scan.position.get(id(token))
        if index is not None and scan._pair_value(index) == ":object":
            _deser(scan, token, "mode: :object", "Oj chạy ở mode :object nên payload tự chọn lớp qua trường ^o")


def _ruby_jwt(scan: "_Scan", call: "_Call") -> None:
    flat = scan.flat
    for index in range(call.open_index + 1, min(call.close_index, len(flat))):
        token = flat[index]
        if token.text in ("algorithm", "algorithms") and token.kind in (IDENT, STRING):
            hit = _none_in_list(_pair_list(scan, index))
            if hit is not None:
                _jwt_none(scan, call.anchor, "JWT.decode", "JWT.decode nhận thuật toán 'none', tức là nhận token không ký")
                return
    if len(call.arguments) >= 3 and _texts(call.argument(2)) == ["false"]:
        _report_unverified(scan, call, "JWT.decode", "tham số verify = false", _ruby_verifies)


def _ruby_verifies(call: "_Call") -> bool:
    if call.parts[-1] != "decode" or len(call.arguments) < 2:
        return False
    return len(call.arguments) < 3 or _texts(call.argument(2)) != ["false"]


# --------------------------------------------------------------------- Go


_GO_PARSER_IMPLEMENTATIONS = _GO_VERIFYING_PARSERS | {"ParseUnverified"}


def _go(scan: "_Scan") -> None:
    flat = scan.flat
    for call in scan.calls:
        scan.budget.spend()
        if call.parts[-1] != "ParseUnverified":
            continue
        if _is_declaration(scan, call) or _implements(scan, call, _GO_PARSER_IMPLEMENTATIONS):
            continue  # chính thư viện golang-jwt
        _report_unverified(scan, call, "ParseUnverified", "API bỏ qua chữ ký", _go_verifies)
    for index, token in enumerate(flat):
        if token.kind != IDENT or token.text != "UnsafeAllowNoneSignatureType":
            continue
        if index and flat[index - 1].text in ("const", "var"):
            continue  # nơi khai báo hằng
        guard = _guard_condition(scan, index)
        if any(words.names_a_guard(name) or "none" in words.split_words(name) for name in guard):
            scan._report(
                "FSB-JWT-001",
                token,
                "UnsafeAllowNoneSignatureType",
                "keyfunc trả UnsafeAllowNoneSignatureType khi người dùng chọn alg none",
                confidence=Confidence.LOW,
                evidence=("chỉ chạy khi điều kiện %s() đúng, có vẻ là tuỳ chọn người dùng tự bật" % guard[-1],),
            )
            continue
        _jwt_none(
            scan,
            token,
            "UnsafeAllowNoneSignatureType",
            "keyfunc trả UnsafeAllowNoneSignatureType nên chấp nhận JWT ký bằng 'none'",
        )


def _go_verifies(call: "_Call") -> bool:
    return call.parts[-1] in _GO_VERIFYING_PARSERS and len(call.arguments) >= 2


# ------------------------------------------------------------- JavaScript


def _javascript(scan: "_Scan") -> None:
    if not _mentions_jwt(scan):
        return
    flat = scan.flat
    for call in scan.calls:
        scan.budget.spend()
        if call.parts[-2:] == ("UnsecuredJWT", "decode"):
            _jwt_none(scan, call.anchor, "UnsecuredJWT.decode", "jose UnsecuredJWT.decode nhận token không ký")
    for index, token in enumerate(flat):
        # jwt.verify, express-jwt, koa-jwt, passport-jwt: { algorithms: ['none'] }
        if token.text != "algorithms" or token.kind not in (IDENT, STRING):
            continue
        hit = _none_in_list(_pair_list(scan, index, (":",)))
        if hit is not None:
            _jwt_none(scan, hit, "algorithms", "cấu hình xác minh JWT nhận thuật toán 'none', tức là nhận token không ký")


__all__ = ["check", "receivers"]
