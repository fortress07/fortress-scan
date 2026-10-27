"""Quyết định quyền bằng trường của request, và mass assignment, trên AST Python.

Khác các họ khác ở chỗ chính TÊN KHOÁ mang nghĩa: `request.args.get("role")` và
`request.args.get("page")` là cùng một lời gọi, chỉ khác một chuỗi, mà một bên
là lỗ hổng leo thang quyền còn bên kia là phân trang. Nên mỗi kiểm tra ở đây
đọc khoá, rồi đọc tiếp xem giá trị đó được dùng để QUYẾT ĐỊNH hay chỉ để lọc:

* so với một giá trị quyền ( `== "admin"` ) trong một điều kiện, hoặc
* dùng thẳng làm điều kiện, và khi đó khoá phải là một cờ đúng / sai
  ( `is_admin`, `logged_in` ), chứ `if request.args.get("role")` thì mới chỉ là
  "người dùng có truyền role hay không".
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Iterable, List, Optional, Tuple

from ...core.model import Confidence
from ..python.specs import REQUEST_MEMBERS, REQUEST_RECEIVER_NAMES
from . import words

if TYPE_CHECKING:  # pragma: no cover
    from .python import PythonWeaknessChecks

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)

# Header đi qua gateway có thể đã được chính gateway đặt, nên hạ một mức.
_HEADER_MEMBERS = frozenset({"headers", "META"})
# Phiên của server đã ký, không phải thứ người gửi tự đặt.
_SERVER_MEMBERS = frozenset({"session"})

_GETTERS = frozenset({"get", "getlist", "getall"})

# Ghi cả gói dữ liệu của người gửi vào một đối tượng được lưu. Chỉ những tên
# hàm THẬT SỰ ghi: `filter(**request.GET)` cũng đáng nói nhưng là lớp lỗi khác
# ( lộ dữ liệu ), và gộp hai thứ vào một rule thì người đọc mất nghĩa.
_MASS_WRITES = frozenset(
    {
        "create",
        "bulk_create",
        "update",
        "update_or_create",
        "get_or_create",
        "insert",
        "insert_one",
        "insert_many",
        "save",
    }
)
# `request.POST.dict()`, `request.data.copy()`: vẫn là cả gói đó.
_PASSTHROUGH = frozenset({"dict", "copy", "to_dict", "model_dump", "items"})
# Header không phải trường của mô hình, và tệp tải lên đi đường khác.
_NOT_MODEL_FIELDS = frozenset({"headers", "META", "FILES", "files"})


def check(checks: "PythonWeaknessChecks") -> None:
    _privilege_decisions(checks)
    _mass_assignment(checks)


# ------------------------------------------------------- quyết định quyền


def _privilege_decisions(checks: "PythonWeaknessChecks") -> None:
    for node, member, key in _request_keys(checks):
        checks.budget.spend()
        if member in _HEADER_MEMBERS:
            candidates = words.header_key_variants(key)
        else:
            candidates = frozenset({words.normalized_key(key)})
        normalized = next((name for name in candidates if name in words.PRIVILEGE_KEYS), None)
        if normalized is None:
            continue
        reason = _decides_access(checks, node, normalized)
        if reason is None:
            continue
        confidence = Confidence.MEDIUM if member in _HEADER_MEMBERS else Confidence.HIGH
        evidence = [reason]
        if confidence is Confidence.MEDIUM:
            evidence.append(
                "nếu gateway phía trước XOÁ header này trên mọi request từ ngoài thì đây là "
                "thiết kế có chủ ý, không phải lỗ hổng"
            )
        checks.builder.add(
            "FSB-ACCESS-001",
            node.lineno,  # type: ignore[attr-defined]
            node.col_offset,  # type: ignore[attr-defined]
            key,
            "quyền được quyết định bằng %r lấy từ %s, thứ người gửi tự đặt được"
            % (key, _member_label(member)),
            end_line=getattr(node, "end_lineno", None),
            end_column=getattr(node, "end_col_offset", None),
            confidence=confidence,
            evidence=tuple(evidence),
        )


def _request_keys(checks: "PythonWeaknessChecks") -> List[Tuple[ast.AST, str, str]]:
    """Mọi chỗ đọc một khoá cụ thể ra khỏi request: ( nút, tên vùng, khoá )."""
    found: List[Tuple[ast.AST, str, str]] = []
    for call in checks.calls:
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr not in _GETTERS:
            continue
        member = _request_member(checks, func.value)
        if member is None or not call.args:
            continue
        key = _string(call.args[0])
        if key is not None:
            found.append((call, member, key))
    for node in ast.walk(checks.tree):
        if not isinstance(node, ast.Subscript):
            continue
        member = _request_member(checks, node.value)
        if member is None:
            continue
        key = _string(node.slice)
        if key is not None:
            found.append((node, member, key))
    return found


def _request_member(checks: "PythonWeaknessChecks", node: ast.AST) -> Optional[str]:
    """`request.args`, `self.request.GET`, `req.cookies` -> tên vùng của request."""
    if not isinstance(node, ast.Attribute):
        return None
    if node.attr in _SERVER_MEMBERS or node.attr not in REQUEST_MEMBERS:
        return None
    receiver = node.value
    name = checks._qual(receiver) or _dotted(receiver)
    if not name:
        return None
    tail = name.rsplit(".", 1)[-1]
    if name in REQUEST_RECEIVER_NAMES or tail in REQUEST_RECEIVER_NAMES:
        return node.attr
    return None


def _decides_access(
    checks: "PythonWeaknessChecks", node: ast.AST, normalized: str
) -> Optional[str]:
    """Giá trị này có đang quyết định cho phép hay không."""
    current: ast.AST = node
    parent = checks.parents.get(id(node))
    while parent is not None:
        if isinstance(parent, ast.Compare):
            literal = _privilege_literal(parent, current)
            if literal is not None and _inside_test(checks, parent):
                return "được so với %r để quyết định quyền" % literal
            if literal is not None and _inside_return(checks, parent):
                return "hàm trả về kết quả so %r làm quyết định quyền" % literal
        if isinstance(parent, (ast.BoolOp, ast.UnaryOp)):
            current = parent
            parent = checks.parents.get(id(parent))
            continue
        if isinstance(parent, (ast.If, ast.IfExp, ast.While, ast.Assert)):
            if current is parent.test and normalized in words.BOOLEAN_PRIVILEGE_KEYS:
                return "được dùng thẳng làm điều kiện cấp quyền"
            return None
        if isinstance(parent, ast.stmt):
            return None
        current = parent
        parent = checks.parents.get(id(parent))
    return None


def _inside_test(checks: "PythonWeaknessChecks", node: ast.AST) -> bool:
    current: ast.AST = node
    parent = checks.parents.get(id(node))
    while parent is not None:
        if isinstance(parent, (ast.If, ast.IfExp, ast.While, ast.Assert)) and current is parent.test:
            return True
        if isinstance(parent, ast.comprehension) and current in parent.ifs:
            return True
        if isinstance(parent, ast.stmt) and not isinstance(parent, (ast.If, ast.While, ast.Assert)):
            return False
        current = parent
        parent = checks.parents.get(id(parent))
    return False


def _inside_return(checks: "PythonWeaknessChecks", node: ast.AST) -> bool:
    parent = checks.parents.get(id(node))
    while parent is not None:
        if isinstance(parent, ast.Return):
            return True
        if isinstance(parent, ast.stmt):
            return False
        parent = checks.parents.get(id(parent))
    return False


def _privilege_literal(compare: ast.Compare, current: ast.AST) -> Optional[str]:
    for operand in [compare.left] + list(compare.comparators):
        if operand is current:
            continue
        for value in _strings(operand):
            if words.normalized_key(value) in words.PRIVILEGE_VALUES:
                return value
    return None


def _strings(node: ast.AST) -> Iterable[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                yield element.value


# ---------------------------------------------------------- mass assignment


def _mass_assignment(checks: "PythonWeaknessChecks") -> None:
    """`User.objects.create(**request.POST)` -- người gửi chọn luôn tên trường."""
    for call in checks.calls:
        keyword = next((kw for kw in call.keywords if kw.arg is None), None)
        if keyword is None:
            continue
        checks.budget.spend()
        member = _whole_request(checks, keyword.value)
        if member is None or not _writes_a_record(call.func):
            continue
        checks.builder.add(
            "FSB-MASS-001",
            call.lineno,
            call.col_offset,
            _callee_name(call.func),
            "cả %s được ghi thẳng vào đối tượng được lưu, nên người gửi chọn luôn "
            "những trường mà form không hề có" % _member_label(member),
            end_line=getattr(call, "end_lineno", None),
            end_column=getattr(call, "end_col_offset", None),
            confidence=Confidence.MEDIUM,
            evidence=(
                "chỉ an toàn nếu mô hình có danh sách trường được phép ghi; "
                "nếu không, một trường như is_staff hay role đi kèm là đủ",
            ),
        )


def _whole_request(checks: "PythonWeaknessChecks", node: ast.AST) -> Optional[str]:
    """Giá trị này có phải CẢ gói dữ liệu người gửi, chứ không phải một khoá."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _PASSTHROUGH and not node.args:
            return _whole_request(checks, func.value)
        return None
    member = _request_member(checks, node)
    if member is None or member in _NOT_MODEL_FIELDS:
        return None
    return member


def _writes_a_record(func: ast.AST) -> bool:
    if isinstance(func, ast.Attribute):
        if func.attr in _MASS_WRITES:
            return True
        return _looks_like_a_model(func.attr)
    if isinstance(func, ast.Name):
        return _looks_like_a_model(func.id)
    return False


def _looks_like_a_model(name: str) -> bool:
    """`User(**request.POST)`: tên lớp viết hoa chữ đầu theo PEP 8.

    Không đòi tên phải nghe như mô hình người dùng: Order, Invoice, Listing
    cũng là bản ghi được lưu, và trường leo quyền không nhất thiết tên là
    is_admin -- `price`, `status`, `owner_id` cũng đủ gây hại.
    """
    return bool(name) and name[0].isupper()


def _callee_name(func: ast.AST) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


# ------------------------------------------------------------------ helpers


def _member_label(member: str) -> str:
    spec = REQUEST_MEMBERS.get(member)
    return spec.label if spec is not None else "request HTTP"


def _string(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dotted(node: ast.AST) -> str:
    parts: List[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


__all__ = ["check"]
