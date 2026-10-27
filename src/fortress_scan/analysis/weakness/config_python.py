"""Cấu hình xác thực trên AST Python: JWT được nhận mà không xác minh chữ ký.

Tách khỏi `python.py` để mỗi họ rule một tệp; dùng lại chỉ mục ( cha, lời gọi,
binding, import ) mà `PythonWeaknessChecks` đã dựng.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Iterable, List, Optional

from ...core.model import Confidence
from . import words

if TYPE_CHECKING:  # pragma: no cover
    from .python import PythonWeaknessChecks

# PyJWT ( `import jwt` ) và python-jose ( `from jose import jwt` ).
_JWT_DECODERS = frozenset({"jwt.decode", "jwt.api_jwt.decode", "jose.jwt.decode"})
# API chỉ đọc, không có tham số khoá nào để xác minh.
_JWT_UNVERIFIED_READERS = frozenset({"jose.jwt.get_unverified_claims"})


def check_jwt(checks: "PythonWeaknessChecks") -> None:
    decodes = []
    for call in checks.calls:
        checks.budget.spend()
        qual = checks._qual(call.func)
        if qual in _JWT_DECODERS or qual in _JWT_UNVERIFIED_READERS:
            decodes.append((call, qual))
    if not decodes:
        return
    for call, qual in decodes:
        none_algorithm = _accepts_none(checks, call) if qual in _JWT_DECODERS else None
        if none_algorithm is not None:
            checks.builder.add(
                "FSB-JWT-001",
                call.lineno,
                call.col_offset,
                qual,
                "%s() nhận thuật toán 'none', tức là nhận cả token không có chữ ký" % qual,
                end_line=getattr(call, "end_lineno", None),
                end_column=getattr(call, "end_col_offset", None),
                evidence=("danh sách algorithms có %r" % none_algorithm,),
            )
            continue
        how = _unverified_by(checks, call, qual)
        if how is None:
            continue
        reason = _peek_reason(checks, call, decodes)
        if reason is not None:
            continue
        confidence = Confidence.MEDIUM
        evidence = [
            "không thấy lời gọi xác minh nào khác trong cùng hàm",
            "nếu chữ ký đã được kiểm ở tầng khác ( gateway, middleware ) thì đây không phải lỗ hổng",
        ]
        elsewhere = next(
            (other for other, other_qual in decodes if other is not call and _verifies(checks, other, other_qual)),
            None,
        ) or _verifying_wrapper(checks, decodes)
        if elsewhere is not None:
            # Cùng tệp có xác minh thật: lời gọi này nhiều khả năng chỉ đọc trước để định tuyến.
            confidence = Confidence.LOW
            evidence.append("cùng tệp có lời gọi xác minh ở dòng %d" % elsewhere.lineno)
        checks.builder.add(
            "FSB-JWT-001",
            call.lineno,
            call.col_offset,
            qual,
            "%s() đọc claims với %s; ai cũng sửa được nội dung token mà không cần khoá" % (qual, how),
            end_line=getattr(call, "end_lineno", None),
            end_column=getattr(call, "end_col_offset", None),
            confidence=confidence,
            evidence=tuple(evidence),
        )


def _unverified_by(checks: "PythonWeaknessChecks", call: ast.Call, qual: str) -> Optional[str]:
    if qual in _JWT_UNVERIFIED_READERS:
        return "API không xác minh"
    options = checks._keyword(call, "options")
    for key, value in _dict_items(checks, options):
        if key == "verify_signature" and checks._is_false(value):
            return "options={'verify_signature': False}"
    # PyJWT 1.x
    if checks._is_false(checks._keyword(call, "verify")):
        return "verify=False"
    return None


def _accepts_none(checks: "PythonWeaknessChecks", call: ast.Call) -> Optional[str]:
    algorithms = checks._keyword(call, "algorithms")
    if isinstance(algorithms, ast.Name):
        algorithms = _single_binding(checks, algorithms.id)
    if not isinstance(algorithms, (ast.List, ast.Tuple, ast.Set)):
        return None
    for element in algorithms.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            if element.value.strip().lower() == "none":
                return element.value
    return None


def _verifies(checks: "PythonWeaknessChecks", call: ast.Call, qual: str) -> bool:
    """Một lời gọi decode có khoá và không tắt xác minh."""
    if qual not in _JWT_DECODERS:
        return False
    if _unverified_by(checks, call, qual) is not None:
        return False
    return checks._argument(call, 1, ("key",)) is not None


_VERIFY_VERBS = frozenset({"decode", "verify", "validate"})


def _verifying_wrapper(checks: "PythonWeaknessChecks", decodes) -> Optional[ast.Call]:
    """`jwt_manager.decode(token)`, `verify_jwt(token)`: lớp bọc xác minh của dự án."""
    unverified = {id(call) for call, _ in decodes}
    for call in checks.calls:
        if id(call) in unverified:
            continue
        found = set()
        for name in checks._names_in(call.func):
            found.update(words.split_words(name))
        if found & _VERIFY_VERBS and ("jwt" in found or "token" in found):
            return call
    return None


def _peek_reason(checks: "PythonWeaknessChecks", call: ast.Call, decodes) -> Optional[str]:
    """Đọc trước iss / kid để chọn khoá, rồi mới xác minh thật."""
    function = checks._function_of(call)
    if function is not None:
        if words.names_a_peek(getattr(function, "name", "")):
            return "hàm %s() tự nhận là chỉ đọc chưa xác minh" % function.name  # type: ignore[attr-defined]
        for other, qual in decodes:
            if other is not call and checks._function_of(other) is function and _verifies(checks, other, qual):
                return "cùng hàm có lời gọi xác minh ở dòng %d" % other.lineno
    outputs, _ = checks._output_names(call)
    outputs.extend(_peeked_keys(checks, call))
    if any(words.names_a_peek(name) for name in outputs):
        return "kết quả chỉ dùng để đọc %s" % ", ".join(outputs)
    return None


def _peeked_keys(checks: "PythonWeaknessChecks", call: ast.Call) -> List[str]:
    """`jwt.decode(...)["iss"]`, `jwt.decode(...).get("kid")`"""
    parent = checks.parents.get(id(call))
    if isinstance(parent, ast.Subscript):
        index = parent.slice
        if isinstance(index, ast.Constant) and isinstance(index.value, str):
            return [index.value]
    if isinstance(parent, ast.Attribute) and parent.attr == "get":
        outer = checks.parents.get(id(parent))
        if isinstance(outer, ast.Call) and outer.args:
            first = outer.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return [first.value]
    return []


def _dict_items(checks: "PythonWeaknessChecks", node: Optional[ast.AST]) -> Iterable:
    if isinstance(node, ast.Name):
        node = _single_binding(checks, node.id)
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                yield key.value, value
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        for keyword in node.keywords:
            if keyword.arg:
                yield keyword.arg, keyword.value


def _single_binding(checks: "PythonWeaknessChecks", name: str) -> Optional[ast.expr]:
    values = checks.bindings.get(name) or []
    if len(values) == 1:
        return values[0]
    return None


__all__ = ["check_jwt"]
