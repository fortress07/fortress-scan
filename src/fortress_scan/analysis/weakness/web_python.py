"""CORS phản chiếu mọi origin và cookie phiên thiếu HttpOnly, đọc trên AST Python.

Cả hai họ nằm ở ĐỒNG THỜI hai công tắc, không ở một lời gọi: origin mở rộng chỉ
thành lỗ hổng khi có credentials đi kèm, còn HttpOnly chỉ đáng nói khi cookie đó
mang phiên đăng nhập. Nên mỗi kiểm tra ở đây đọc đủ cả hai phía rồi mới báo, và
hình `Access-Control-Allow-Origin: *` -- thứ trình duyệt tự từ chối khi request
có credentials -- được bỏ qua.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Tuple

from ...core.model import Confidence
from . import words

if TYPE_CHECKING:  # pragma: no cover
    from .python import PythonWeaknessChecks

_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"

_FLASK_CORS = frozenset({"flask_cors.CORS", "flask_cors.extension.CORS"})
_FLASK_CROSS_ORIGIN = frozenset({"flask_cors.cross_origin", "flask_cors.decorator.cross_origin"})

# Tên cho thấy giá trị lấy từ request đang xử lý, chứ không từ cấu hình.
_REQUEST_NAMES = frozenset(
    {
        "request",
        "req",
        "environ",
        "env",
        "meta",
        "headers",
        "header",
        "ctx",
        "context",
        "scope",
        "get",
        "wsgi",
    }
)

# Tên GHÉP mà một từ của nó đã nói rõ nguồn: `request_origin`, `origin_header`.
_REQUEST_WORDS = frozenset({"request", "req", "headers", "header", "environ"})

_DJANGO_ALLOW_ALL = ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL")
_DJANGO_REGEXES = ("CORS_ALLOWED_ORIGIN_REGEXES", "CORS_ORIGIN_REGEX_WHITELIST")
_DJANGO_CREDENTIALS = "CORS_ALLOW_CREDENTIALS"

_HTTPONLY_SETTINGS = (
    "SESSION_COOKIE_HTTPONLY",
    "REMEMBER_COOKIE_HTTPONLY",
    "JWT_COOKIE_HTTPONLY",
)


def check(checks: "PythonWeaknessChecks") -> None:
    _cors_libraries(checks)
    _cors_settings(checks)
    _reflected_origin(checks)
    _cookies(checks)
    _cookie_settings(checks)


# --------------------------------------------------------------------- CORS


def _cors_libraries(checks: "PythonWeaknessChecks") -> None:
    for call in checks.calls:
        checks.budget.spend()
        qual = checks._qual(call.func)
        tail = qual.rsplit(".", 1)[-1]
        if qual in _FLASK_CORS or qual in _FLASK_CROSS_ORIGIN:
            _flask_cors(checks, call, qual)
        elif tail == "CORSMiddleware":
            _starlette_cors(checks, call, call)
        elif tail == "add_middleware" and call.args:
            if checks._qual(call.args[0]).rsplit(".", 1)[-1] == "CORSMiddleware":
                _starlette_cors(checks, call, call)


def _flask_cors(checks: "PythonWeaknessChecks", call: ast.Call, qual: str) -> None:
    credentials = checks._keyword(call, "supports_credentials")
    if credentials is None or not _is_true(checks, credentials):
        return
    if _is_true(checks, checks._keyword(call, "send_wildcard")):
        # flask-cors tự ném ValueError cho tổ hợp này, nó không chạy được.
        return
    origins = checks._keyword(call, "origins") or checks._keyword(call, "origin")
    where = "origins"
    if origins is None:
        origins, where = _resources_origins(checks, call)
    if origins is None and where == "origins":
        reason = "không truyền origins nên flask-cors dùng mặc định '*'"
    else:
        reason = _permissive_origins(checks, origins)
        if reason is None:
            return
        reason = "%s: %s" % (where, reason)
    name = qual.rsplit(".", 1)[-1]
    _report_cors(
        checks,
        call,
        name,
        "%s() bật supports_credentials với origin mở, nên mọi trang web đều đọc được phản hồi "
        "sau đăng nhập" % name,
        (reason, "flask-cors dội lại Origin của người gửi thay vì ghi '*' khi có credentials"),
    )


def _resources_origins(
    checks: "PythonWeaknessChecks", call: ast.Call
) -> Tuple[Optional[ast.expr], str]:
    """`CORS(app, resources={r"/api/*": {"origins": "..."}})`"""
    resources = checks._keyword(call, "resources")
    if isinstance(resources, ast.Name):
        resources = _single_binding(checks, resources.id)
    if not isinstance(resources, ast.Dict):
        return None, "origins"
    for value in resources.values:
        if isinstance(value, ast.Dict):
            for key, inner in zip(value.keys, value.values):
                if isinstance(key, ast.Constant) and key.value in ("origins", "origin"):
                    return inner, "resources.origins"
    return None, "origins"


def _starlette_cors(checks: "PythonWeaknessChecks", call: ast.Call, node: ast.Call) -> None:
    if not _is_true(checks, checks._keyword(call, "allow_credentials")):
        return
    origins = checks._keyword(call, "allow_origins")
    reason = _permissive_origins(checks, origins)
    if reason is None:
        pattern = _string_value(checks, checks._keyword(call, "allow_origin_regex"))
        if pattern is not None:
            described = words.matches_any_origin(pattern)
            reason = "allow_origin_regex: %s" % described if described else None
        if reason is None:
            return
    else:
        reason = "allow_origins: %s" % reason
    _report_cors(
        checks,
        node,
        "CORSMiddleware",
        "CORSMiddleware bật allow_credentials với origin mở, nên mọi trang web đều đọc được phản "
        "hồi sau đăng nhập",
        (reason, "Starlette dội lại Origin của người gửi thay vì ghi '*' khi có credentials"),
    )


def _cors_settings(checks: "PythonWeaknessChecks") -> None:
    """Tệp settings của Django: hai hằng ở hai dòng khác nhau."""
    settings = _module_constants(checks)
    credentials = settings.get(_DJANGO_CREDENTIALS)
    if credentials is None or not _is_true(checks, credentials[1]):
        return
    for name in _DJANGO_ALLOW_ALL:
        found = settings.get(name)
        if found is not None and _is_true(checks, found[1]):
            _report_cors(
                checks,
                found[0],
                name,
                "%s = True đi cùng %s = True, nên django-cors-headers dội lại Origin của người gửi"
                % (name, _DJANGO_CREDENTIALS),
                ("%s được đặt ở dòng %d" % (_DJANGO_CREDENTIALS, credentials[0].lineno),),
            )
            return
    for name in _DJANGO_REGEXES:
        found = settings.get(name)
        if found is None:
            continue
        reason = _permissive_origins(checks, found[1])
        if reason is not None:
            _report_cors(
                checks,
                found[0],
                name,
                "%s nhận mọi origin trong khi %s = True" % (name, _DJANGO_CREDENTIALS),
                (reason, "%s được đặt ở dòng %d" % (_DJANGO_CREDENTIALS, credentials[0].lineno)),
            )
            return


def _reflected_origin(checks: "PythonWeaknessChecks") -> None:
    """`resp.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]`"""
    origins = _header_writes(checks, _ACAO)
    if not origins:
        return
    credentials = _header_writes(checks, _ACAC)
    for node, value in origins:
        reflection = _reflects_origin(checks, value)
        if reflection is None:
            continue
        allowed = _credentials_near(checks, node, credentials)
        if allowed is None:
            continue
        guard = _allowlist_guard(checks, node)
        if guard is not None:
            continue
        _report_cors(
            checks,
            node,
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Origin lấy thẳng Origin của người gửi trong khi "
            "Access-Control-Allow-Credentials là true",
            (reflection, "Access-Control-Allow-Credentials được đặt ở dòng %d" % allowed),
        )


def _allowlist_guard(checks: "PythonWeaknessChecks", node: ast.AST) -> Optional[str]:
    """`if origin_match:` bao quanh -- origin đã được so với một danh sách."""
    current = checks.parents.get(id(node))
    child: ast.AST = node
    while current is not None:
        if isinstance(current, (ast.If, ast.IfExp)) and child is not current.test:
            for name in checks._names_in(current.test):
                if words.names_an_allowlist(name):
                    return name
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            break
        child = current
        current = checks.parents.get(id(current))
    return None


def _header_writes(
    checks: "PythonWeaknessChecks", header: str
) -> List[Tuple[ast.AST, Optional[ast.expr]]]:
    """Mọi chỗ ghi một header theo tên, dù qua subscript, lời gọi hay dict."""
    found: List[Tuple[ast.AST, Optional[ast.expr]]] = []
    for node in checks.assignments:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Subscript) and _constant_is(target.slice, header):
                found.append((target, node.value))
    for node in checks.tuples:
        # ASGI thô: headers = [(b"access-control-allow-origin", origin), ...]
        if len(node.elts) == 2 and _constant_is(node.elts[0], header):
            found.append((node.elts[0], node.elts[1]))
    for call in checks.calls:
        if not isinstance(call.func, ast.Attribute):
            continue
        if call.func.attr not in ("add", "set", "setdefault", "append", "add_header", "__setitem__"):
            continue
        if len(call.args) >= 2 and _constant_is(call.args[0], header):
            found.append((call, call.args[1]))
    for call in checks.calls:
        for keyword in call.keywords:
            if keyword.arg != "headers":
                continue
            value = keyword.value
            if isinstance(value, ast.Name):
                value = _single_binding(checks, value.id)
            if isinstance(value, ast.Dict):
                for key, inner in zip(value.keys, value.values):
                    if _constant_is(key, header):
                        found.append((key, inner))
    return found


def _credentials_near(
    checks: "PythonWeaknessChecks",
    node: ast.AST,
    credentials: Sequence[Tuple[ast.AST, Optional[ast.expr]]],
) -> Optional[int]:
    function = checks._function_of(node)
    for other, value in credentials:
        if not _is_true(checks, value):
            continue
        if function is None or checks._function_of(other) is function:
            return getattr(other, "lineno", 0)
    return None


def _reflects_origin(checks: "PythonWeaknessChecks", node: Optional[ast.AST], depth: int = 0) -> Optional[str]:
    """Giá trị này có lấy từ Origin của request đang xử lý không."""
    if node is None or depth > 1:
        return None
    names = checks._names_in(node)
    if not any("origin" in name.lower() for name in names):
        return None
    for name in names:
        lowered = name.lower()
        if lowered in _REQUEST_NAMES or "http_origin" in lowered:
            return "giá trị đọc từ header Origin của request"
        if any(word in _REQUEST_WORDS for word in words.split_words(name)):
            return "giá trị đọc từ header Origin của request"
    if depth == 0:
        for name in checks._names_in(node):
            bound = _single_binding(checks, name)
            if bound is not None:
                found = _reflects_origin(checks, bound, depth + 1)
                if found is not None:
                    return found
    return None


def _permissive_origins(
    checks: "PythonWeaknessChecks", node: Optional[ast.expr], depth: int = 0
) -> Optional[str]:
    """Danh sách origin này có cho qua mọi tên miền không."""
    if node is None or depth > 2:
        return None
    if isinstance(node, ast.Name):
        return _permissive_origins(checks, _single_binding(checks, node.id), depth + 1)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return words.matches_any_origin(node.value)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for element in node.elts:
            found = _permissive_origins(checks, element, depth + 1)
            if found is not None:
                return found
    return None


def _report_cors(
    checks: "PythonWeaknessChecks",
    node: ast.AST,
    symbol: str,
    message: str,
    evidence: Sequence[str],
) -> None:
    checks.builder.add(
        "FSB-CORS-001",
        node.lineno,  # type: ignore[attr-defined]
        node.col_offset,  # type: ignore[attr-defined]
        symbol,
        message,
        end_line=getattr(node, "end_lineno", None),
        end_column=getattr(node, "end_col_offset", None),
        evidence=tuple(part for part in evidence if part),
    )


# ------------------------------------------------------------------- cookie


def _cookies(checks: "PythonWeaknessChecks") -> None:
    for call in checks.calls:
        checks.budget.spend()
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr != "set_cookie":
            continue
        name = _cookie_name(checks, call)
        if name is None:
            continue
        word = words.names_a_session_cookie(name)
        if word is None:
            continue
        httponly = checks._keyword(call, "httponly")
        if httponly is None:
            httponly = checks._keyword(call, "httpOnly")
        if httponly is not None and not checks._is_false(httponly):
            continue
        if httponly is None:
            confidence = Confidence.MEDIUM
            how = "không truyền httponly, mà mặc định của set_cookie là False"
        else:
            confidence = Confidence.HIGH
            how = "httponly được đặt thẳng là False"
        checks.builder.add(
            "FSB-COOKIE-001",
            call.lineno,
            call.col_offset,
            name,
            "cookie %r mang phiên đăng nhập nhưng đọc được bằng document.cookie" % name,
            end_line=getattr(call, "end_lineno", None),
            end_column=getattr(call, "end_col_offset", None),
            confidence=confidence,
            evidence=(how, "tên cookie chứa từ %r" % word),
        )


def _cookie_name(checks: "PythonWeaknessChecks", call: ast.Call) -> Optional[str]:
    argument = checks._argument(call, 0, ("key", "name"))
    if isinstance(argument, ast.Name):
        argument = _single_binding(checks, argument.id)
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    return None


def _cookie_settings(checks: "PythonWeaknessChecks") -> None:
    """`SESSION_COOKIE_HTTPONLY = False`, `app.config["SESSION_COOKIE_HTTPONLY"] = False`"""
    for node in checks.assignments:
        if not isinstance(node, ast.Assign) or not checks._is_false(node.value):
            continue
        for target in node.targets:
            name = _setting_name(target)
            if name in _HTTPONLY_SETTINGS:
                _report_cookie_setting(checks, target, name)
    for call in checks.calls:
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
            continue
        for keyword in call.keywords:
            if keyword.arg in _HTTPONLY_SETTINGS and checks._is_false(keyword.value):
                _report_cookie_setting(checks, keyword.value, keyword.arg)


def _setting_name(target: ast.AST) -> Optional[str]:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        key = target.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
    return None


def _report_cookie_setting(checks: "PythonWeaknessChecks", node: ast.AST, name: str) -> None:
    checks.builder.add(
        "FSB-COOKIE-001",
        node.lineno,  # type: ignore[attr-defined]
        node.col_offset,  # type: ignore[attr-defined]
        name,
        "%s = False nên cookie phiên của framework đọc được bằng document.cookie" % name,
        end_column=getattr(node, "end_col_offset", None),
        confidence=Confidence.HIGH,
    )


# ------------------------------------------------------------------ helpers


def _module_constants(checks: "PythonWeaknessChecks") -> Dict[str, Tuple[ast.AST, Optional[ast.expr]]]:
    found: Dict[str, Tuple[ast.AST, Optional[ast.expr]]] = {}
    for node in checks.assignments:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.isupper():
                found.setdefault(target.id, (target, node.value))
    return found


def _constant_is(node: Optional[ast.AST], text: str) -> bool:
    if not isinstance(node, ast.Constant):
        return False
    value = node.value
    if isinstance(value, bytes):
        # Mã ASGI thô viết tên header dạng bytes: b"access-control-allow-origin".
        value = value.decode("latin-1")
    return isinstance(value, str) and value.strip().lower() == text


def _string_value(checks: "PythonWeaknessChecks", node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Name):
        node = _single_binding(checks, node.id)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_true(checks: "PythonWeaknessChecks", node: Optional[ast.AST]) -> bool:
    if isinstance(node, ast.Constant):
        value = node.value
        if value is True:
            return True
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes", "on")
        return False
    if isinstance(node, ast.Name):
        values = checks.bindings.get(node.id) or []
        return bool(values) and all(
            isinstance(value, ast.Constant) and value.value is True for value in values
        )
    return False


def _single_binding(checks: "PythonWeaknessChecks", name: str) -> Optional[ast.expr]:
    values = checks.bindings.get(name) or []
    if len(values) == 1:
        return values[0]
    return None


__all__ = ["check"]
