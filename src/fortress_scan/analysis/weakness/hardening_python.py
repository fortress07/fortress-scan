"""Giải nén tar, quyền tệp, tệp tạm đoán được và chế độ debug, trên AST Python.

Bốn họ ở đây có một điểm chung đáng nói ra: cái quyết định là MỘT HẰNG SỐ --
`0o777`, một đường dẫn tạm cố định, `debug=True`, hay sự VẮNG MẶT của
`filter=`. Nên chúng dễ
dò đúng, và cũng rất dễ dò bừa. Mấy lằn ranh dưới đây được vạch bằng cách đọc
tài liệu và mã của thư viện chuẩn, không vạch cho tiện:

* `zipfile.extractall` TỰ chuẩn hoá tên thành viên ( bỏ dấu phân cách đầu và
  `..` -- xem `ZipFile._extract_member` ), nên nó KHÔNG bị báo. `tarfile` thì
  không làm vậy, và đó là CVE-2007-4559, vá bằng `filter=` của PEP 706.
* `chmod` bỏ qua umask, còn `open`, `mkdir`, `os.makedirs` thì không. Nên chỉ
  họ `chmod` bị báo: `os.makedirs(p, 0o777)` với umask 022 ra 0755, báo nó là
  báo vào thứ thường vô hại.
* `app.run(debug=True)` nằm trong `if __name__ == "__main__"` là cách chạy máy
  dev, không phải cấu hình đi kèm ứng dụng, nên im lặng ở đó.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, List, Optional, Set

from ...core.model import Confidence, Severity

if TYPE_CHECKING:  # pragma: no cover
    from .python import PythonWeaknessChecks

# `tarfile.open` trả về đối tượng mà `.extractall()` của nó không chuẩn hoá tên.
_TAR_FACTORIES = frozenset({"tarfile.open", "tarfile.TarFile", "tarfile.TarFile.open"})

_CHMOD_QUALS = frozenset({"os.chmod", "os.fchmod", "os.lchmod"})
_WORLD_WRITE = 0o002

# NOSONAR ở từng dòng là có chủ đích, và nhánh IR đã gặp đúng chuyện này trên
# PR #22: S5443 đọc mỗi chuỗi dưới đây như một đường dẫn mà công cụ sắp GHI
# vào. Thực tế đây là dữ liệu bộ dò ĐI TÌM trong mã của người khác; cả mô-đun
# analysis/ không có một lời gọi mở tệp để ghi nào. Khối sonar.issue.ignore
# trong sonar-project.properties nói cùng điều đó, nhưng Automatic Analysis
# đọc cấu hình từ nhánh chính nên nó chỉ có hiệu lực sau khi merge.
_TEMP_PREFIXES = (
    "/tmp/",  # NOSONAR
    "/var/tmp/",  # NOSONAR
    "/dev/shm/",  # NOSONAR
)
_WRITE_MODES = ("w", "a", "x", "+")

_SETTINGS_WORDS = ("settings", "config", "conf", "configuration")
# Tệp cấu hình của máy dev được đặt tên đúng như vậy, và DEBUG = True ở đó là
# chủ ý. Không giấu, chỉ không gọi nó là lỗ hổng.
_DEV_WORDS = ("dev", "development", "local", "debug", "sample", "template")


def check(checks: "PythonWeaknessChecks") -> None:
    _archive_extraction(checks)
    _permissions(checks)
    _temp_files(checks)
    _debug_mode(checks)


# ------------------------------------------------------- giải nén tệp nén


def _archive_extraction(checks: "PythonWeaknessChecks") -> None:
    tars = _tar_names(checks)
    for call in checks.calls:
        checks.budget.spend()
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr == "extractall":
            if not _is_tar(checks, func.value, tars):
                continue
            if _keyword(call, "filter") is not None or _keyword(call, "members") is not None:
                continue
            _report(
                checks,
                "FSB-PATH-002",
                call,
                "extractall",
                "tarfile.extractall() không có `filter=`, nên một thành viên tên "
                "`../../etc/cron.d/x` trong tệp nén ghi được ra ngoài thư mục đích",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                evidence=(
                    "tarfile không chuẩn hoá tên thành viên; zipfile thì có, nên "
                    "`ZipFile.extractall` không bị báo",
                    "Python 3.14 đổi mặc định sang filter='data'; trước đó, và với mọi bản "
                    "đang chạy 3.9-3.13, mặc định vẫn là giải nén nguyên tên",
                ),
            )
            continue
        if checks._qual(func) == "shutil.unpack_archive":
            _report(
                checks,
                "FSB-PATH-002",
                call,
                "unpack_archive",
                "shutil.unpack_archive() giải nén theo đuôi tệp, và với .tar / .tar.gz nó "
                "dùng tarfile nên tên thành viên không được chuẩn hoá",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                evidence=(
                    "chỉ là lỗ hổng khi định dạng thật là tar; với .zip thì zipfile đã "
                    "chuẩn hoá tên",
                ),
            )


def _tar_names(checks: "PythonWeaknessChecks") -> Set[str]:
    """Tên biến đang giữ một đối tượng tarfile, kể cả qua `with ... as`."""
    names: Set[str] = set()
    for node in ast.walk(checks.tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None and _is_tar_call(checks, item.context_expr):
                    _add_target(names, item.optional_vars)
        elif isinstance(node, ast.Assign):
            if _is_tar_call(checks, node.value):
                for target in node.targets:
                    _add_target(names, target)
    return names


def _add_target(names: Set[str], target: ast.AST) -> None:
    if isinstance(target, ast.Name):
        names.add(target.id)


def _is_tar_call(checks: "PythonWeaknessChecks", node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and checks._qual(node.func) in _TAR_FACTORIES


def _is_tar(checks: "PythonWeaknessChecks", node: ast.AST, tars: Set[str]) -> bool:
    if _is_tar_call(checks, node):
        return True
    return isinstance(node, ast.Name) and node.id in tars


# --------------------------------------------------------------- quyền tệp


def _permissions(checks: "PythonWeaknessChecks") -> None:
    for call in checks.calls:
        checks.budget.spend()
        func = call.func
        qualified = checks._qual(func)
        mode: Optional[ast.AST] = None
        if qualified in _CHMOD_QUALS and len(call.args) >= 2:
            mode = call.args[1]
        elif isinstance(func, ast.Attribute) and func.attr == "chmod" and len(call.args) == 1:
            mode = call.args[0]  # Path.chmod
        if mode is not None:
            value = _int(mode)
            if value is not None and value & _WORLD_WRITE:
                _report(
                    checks,
                    "FSB-PERM-001",
                    call,
                    "chmod",
                    "chmod %s cho mọi người dùng trên máy quyền GHI tệp này" % _octal(value),
                    confidence=Confidence.HIGH,
                    evidence=(
                        "chmod không chịu umask, nên con số này là quyền thật sau khi chạy",
                        "nếu tệp là mã sẽ được chạy hay cấu hình sẽ được đọc, bất kỳ ai trên "
                        "máy cũng sửa được nội dung nó",
                    ),
                )
            continue
        if qualified == "os.umask" and call.args and _int(call.args[0]) == 0:
            if not isinstance(checks.parents.get(id(call)), ast.Expr):
                continue  # `current = os.umask(0)` chỉ là lối ĐỌC umask rồi đặt lại
            _report(
                checks,
                "FSB-PERM-001",
                call,
                "umask",
                "os.umask(0) làm mọi tệp và thư mục tạo sau đó mang quyền ghi cho cả máy",
                confidence=Confidence.HIGH,
                evidence=(
                    "umask 0 bỏ hết bit che, nên chế độ truyền cho open / mkdir giữ nguyên",
                    "kết quả của lời gọi bị bỏ, nên đây là phép ĐẶT: lối `cũ = os.umask(0)` "
                    "rồi `os.umask(cũ)` chỉ để đọc giá trị hiện tại và không bị báo",
                ),
            )


# ---------------------------------------------------------------- tệp tạm


def _temp_files(checks: "PythonWeaknessChecks") -> None:
    for call in checks.calls:
        checks.budget.spend()
        qualified = checks._qual(call.func)
        if qualified in ("tempfile.mktemp", "os.tempnam", "os.tmpnam"):
            _report(
                checks,
                "FSB-TMP-001",
                call,
                qualified.rsplit(".", 1)[-1],
                "%s() chỉ sinh TÊN rồi trả về, nên giữa lúc đó và lúc mở tệp, ai cũng chen "
                "được một liên kết tượng trưng vào đúng tên ấy" % qualified.rsplit(".", 1)[-1],
                confidence=Confidence.HIGH,
                evidence=(
                    "chính tài liệu thư viện chuẩn gọi hàm này là không an toàn và chỉ cho "
                    "tồn tại vì tương thích ngược",
                ),
            )
            continue
        if qualified not in ("open", "io.open", "os.open", "codecs.open"):
            continue
        path = _string(call.args[0]) if call.args else None
        if path is None or not path.startswith(_TEMP_PREFIXES):
            continue
        if not _opens_for_writing(call):
            continue
        _report(
            checks,
            "FSB-TMP-001",
            call,
            path,
            "ghi vào đường dẫn tạm đoán trước được %r: ai cũng tạo sẵn tệp hoặc liên kết ở "
            "đúng tên đó trước khi tiến trình này chạy" % path,
            confidence=Confidence.MEDIUM,
            evidence=(
                "đường dẫn là hằng, nên tên không đổi giữa các lượt chạy",
                "tempfile.NamedTemporaryFile hoặc tempfile.mkstemp tạo tệp với tên ngẫu nhiên "
                "và quyền chỉ chủ sở hữu, trong cùng một bước",
            ),
        )


def _opens_for_writing(call: ast.Call) -> bool:
    mode = _string(call.args[1]) if len(call.args) > 1 else None
    if mode is None:
        keyword = _keyword(call, "mode")
        mode = _string(keyword) if keyword is not None else None
    if mode is None:
        flags = _keyword(call, "flags")
        return flags is not None  # os.open: không có "r" nào để đọc
    return any(letter in mode for letter in _WRITE_MODES)


# -------------------------------------------------------------- chế độ debug


def _debug_mode(checks: "PythonWeaknessChecks") -> None:
    for call in checks.calls:
        checks.budget.spend()
        func = call.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name == "run" and _is_true(_keyword(call, "debug")):
            if _inside_main_guard(checks, call):
                continue
            _report(
                checks,
                "FSB-DEBUG-001",
                call,
                "debug",
                "chạy ứng dụng với debug=True: bộ gỡ lỗi của Werkzeug mở một shell Python "
                "ngay trên trang lỗi",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                evidence=(
                    "lời gọi không nằm trong `if __name__ == \"__main__\"`, nên nó đi kèm ứng "
                    "dụng chứ không chỉ là lối chạy trên máy dev",
                    "console đó đòi một mã PIN từ 0.11, nhưng mã PIN sinh từ dữ liệu đọc được "
                    "của máy nên không phải là biên an toàn",
                ),
            )
            continue
        if name == "DebuggedApplication" and _is_true(_keyword(call, "evalex")):
            _report(
                checks,
                "FSB-DEBUG-001",
                call,
                "DebuggedApplication",
                "DebuggedApplication(evalex=True) cho phép chạy biểu thức Python tuỳ ý qua "
                "trang lỗi",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
            )
    _debug_setting(checks)


def _debug_setting(checks: "PythonWeaknessChecks") -> None:
    path = checks.unit.relative_path.replace("\\", "/").lower()
    if not any(word in path for word in _SETTINGS_WORDS):
        return
    if any(word in path for word in _DEV_WORDS):
        return
    for node in ast.walk(checks.tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in ("DEBUG", "TEMPLATE_DEBUG"):
            continue
        if not _is_true(node.value):
            continue
        checks.builder.add(
            "FSB-DEBUG-001",
            node.lineno,
            node.col_offset,
            target.id,
            "%s = True trong tệp cấu hình: trang lỗi của Django in ra cấu hình, biến môi "
            "trường và truy vết của mọi request lỗi" % target.id,
            end_line=getattr(node, "end_lineno", None),
            end_column=getattr(node, "end_col_offset", None),
            confidence=Confidence.MEDIUM,
            evidence=(
                "tệp cấu hình riêng cho máy dev thường có tên chứa dev / local, và những tệp "
                "đó không bị báo",
                "nếu giá trị này được ghi đè bằng biến môi trường ở nơi triển khai thì đây "
                "chỉ là mặc định, không phải cấu hình đang chạy",
            ),
        )


def _inside_main_guard(checks: "PythonWeaknessChecks", node: ast.AST) -> bool:
    current: ast.AST = node
    parent = checks.parents.get(id(node))
    while parent is not None:
        if isinstance(parent, ast.If) and _tests_main(parent.test):
            return True
        current = parent
        parent = checks.parents.get(id(current))
    return False


def _tests_main(test: ast.AST) -> bool:
    if not isinstance(test, ast.Compare):
        return False
    operands: List[ast.AST] = [test.left] + list(test.comparators)
    names = {node.id for node in operands if isinstance(node, ast.Name)}
    values = {
        node.value for node in operands if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    return "__name__" in names and "__main__" in values


# ------------------------------------------------------------------ helpers


def _report(
    checks: "PythonWeaknessChecks",
    rule_id: str,
    call: ast.Call,
    symbol: str,
    message: str,
    severity: Optional[Severity] = None,
    confidence: Optional[Confidence] = None,
    evidence: tuple = (),
) -> None:
    checks.builder.add(
        rule_id,
        call.lineno,
        call.col_offset,
        symbol,
        message,
        end_line=getattr(call, "end_lineno", None),
        end_column=getattr(call, "end_col_offset", None),
        severity=severity,
        confidence=confidence,
        evidence=evidence,
    )


def _keyword(call: ast.Call, name: str) -> Optional[ast.AST]:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_true(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _string(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _int(node: Optional[ast.AST]) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _octal(value: int) -> str:
    return "0o%o" % value


__all__ = ["check"]
