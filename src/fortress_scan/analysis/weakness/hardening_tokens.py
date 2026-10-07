"""Zip slip, quyền tệp, tệp tạm và chế độ debug, trên token của các ngôn ngữ khác.

Phần Python nằm ở `hardening_python.py`; ở đây là Java, Go, PHP, Ruby, C#,
JavaScript và shell. Hai lằn ranh quan trọng, giống hệt bên AST:

* chỉ họ `chmod` bị báo, vì chmod bỏ qua umask. `os.MkdirAll(p, 0777)` của Go
  với umask 022 ra 0755, nên báo nó là báo vào thứ thường vô hại -- mà hình
  `0777` ở lời gọi tạo thì gặp khắp nơi trong mã Go thật.
* zip slip chỉ báo khi hàm bao quanh KHÔNG có phép kiểm đường dẫn nào. Phép
  kiểm đúng là so tiền tố sau khi chuẩn hoá; `filepath.Join` tự gọi `Clean`
  nhưng Clean chạy SAU khi nối nên nó không phải phép kiểm, và vì vậy một chữ
  `Clean` đứng một mình không được tính là đã canh.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, Optional, Sequence, Tuple

from ...core.model import Confidence, Severity
from ...languages import (
    CSHARP,
    GO,
    JAVA,
    JAVASCRIPT,
    PHP,
    POWERSHELL,
    PYTHON,
    RUBY,
    SHELL,
    TYPESCRIPT,
)
from ..generic.lexer import IDENT, NUMBER, OP, STRING, Token

if TYPE_CHECKING:  # pragma: no cover
    from .tokens import _Scan

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

# Hàm GHI, theo từng ngôn ngữ. Đọc một tệp ở /tmp là chuyện khác và không bị báo.
_WRITERS: Dict[str, frozenset] = {
    JAVASCRIPT: frozenset(
        {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "openSync"}
    ),
    TYPESCRIPT: frozenset(
        {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "openSync"}
    ),
    JAVA: frozenset(
        {"File", "FileOutputStream", "FileWriter", "PrintWriter", "newOutputStream", "newBufferedWriter"}
    ),
    GO: frozenset({"Create", "OpenFile", "WriteFile"}),
    PHP: frozenset({"fopen", "file_put_contents", "touch", "move_uploaded_file"}),
    RUBY: frozenset({"write", "new", "open"}),
    CSHARP: frozenset({"WriteAllText", "WriteAllBytes", "WriteAllLines", "AppendAllText", "Create"}),
}

_ARCHIVE_MARKERS = frozenset(
    {
        "ZipEntry",
        "ZipFile",
        "ZipInputStream",
        "ZipArchive",
        "JarEntry",
        "JarFile",
        "TarArchiveEntry",
        "TarArchiveInputStream",
        "ArchiveEntry",
        "getNextEntry",
        "getNextTarEntry",
        "tar",
        "zip",
    }
)
# Phép kiểm đường dẫn thật: so tiền tố, hoặc tính đường dẫn tương đối rồi xét.
_PATH_GUARDS = frozenset(
    {"getCanonicalPath", "getCanonicalFile", "toRealPath", "startsWith", "HasPrefix", "Rel", "Contains"}
)
_JAVA_PATH_SINKS = frozenset(
    {"File", "FileOutputStream", "FileWriter", "Paths", "newOutputStream", "resolve", "copy"}
)

_MODE_WORLD_WRITE = 0o002
_SHELL_MODE = re.compile(r"(?<![\w/.-])([0-7]{3,4})(?![\w/.-])")
_SHELL_SYMBOLIC = re.compile(r"\b([ao]|ugo)[+=][rwx]{0,2}w")
_SHELL_TEMP = re.compile(r"(?:>>?|\btee\b\s+(?:-a\s+)?)\s*[\"']?(/tmp/|/var/tmp/|/dev/shm/)([^\s\"'|;&>]+)")  # NOSONAR

_TRUTHY = frozenset({"1", "on", "true", "yes"})


def check(scan: "_Scan") -> None:
    if scan.language == PYTHON:
        return
    _archives(scan)
    _permissions(scan)
    _temp_files(scan)
    _debug(scan)


# ----------------------------------------------------------------- zip slip


def _archives(scan: "_Scan") -> None:
    if scan.language == JAVA:
        sinks, needle = _JAVA_PATH_SINKS, "getName"
    elif scan.language == GO:
        sinks, needle = frozenset({"Join"}), "Name"
    else:
        return
    for call in scan.calls:
        scan.budget.spend()
        if call.parts[-1] not in sinks:
            continue
        if not any(_mentions(argument, needle) for argument in call.arguments):
            continue
        region = scan._function_at(call.index)
        names = _region_names(scan, region)
        if not names & _ARCHIVE_MARKERS:
            continue
        if names & _PATH_GUARDS:
            continue
        scan._report(
            "FSB-PATH-002",
            call.anchor,
            call.parts[-1],
            "tên thành viên trong tệp nén được nối vào đường dẫn đích mà hàm này không kiểm "
            "lại, nên `../` trong tên ghi được ra ngoài thư mục giải nén",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            evidence=(
                "không thấy phép so tiền tố nào trong cùng hàm ( getCanonicalPath / "
                "startsWith, hoặc HasPrefix / Rel )",
                "filepath.Join tự gọi Clean, nhưng Clean chạy sau khi nối nên nó không chặn "
                "được `../`",
            ),
        )


def _mentions(tokens: Sequence[Token], needle: str) -> bool:
    return any(token.kind == IDENT and token.text == needle for token in tokens)


def _region_names(scan: "_Scan", region: Optional[Tuple[int, int, str]]) -> frozenset:
    start, end = (region[0], region[1]) if region is not None else (0, len(scan.flat))
    return frozenset(
        token.text for token in scan.flat[start : end + 1] if token.kind == IDENT
    )


# --------------------------------------------------------------- quyền tệp


def _permissions(scan: "_Scan") -> None:
    if scan.language in (SHELL, POWERSHELL):
        _shell_chmod(scan)
        return
    for call in scan.calls:
        scan.budget.spend()
        name = call.parts[-1]
        if name in ("chmod", "Chmod"):
            for argument in call.arguments:
                mode = _mode(argument)
                if mode is not None and mode & _MODE_WORLD_WRITE:
                    _report_mode(scan, call.anchor, mode)
                    break
            continue
        if name == "setWritable" and _texts(call.argument(0)) == ["true"]:
            if _texts(call.argument(1)) == ["false"]:
                scan._report(
                    "FSB-PERM-001",
                    call.anchor,
                    "setWritable",
                    "setWritable(true, false): tham số thứ hai là false nghĩa là KHÔNG chỉ "
                    "chủ sở hữu, tức mọi người dùng trên máy ghi được tệp",
                    confidence=Confidence.HIGH,
                )
            continue
        if name == "fromString":
            value = scan._string_value(call.argument(0))
            if value is not None and len(value) == 9 and value[7] == "w":
                scan._report(
                    "FSB-PERM-001",
                    call.anchor,
                    "fromString",
                    "quyền POSIX %r cho mọi người dùng trên máy quyền ghi" % value,
                    confidence=Confidence.HIGH,
                )
            continue
        if name in ("umask", "Umask") and _mode(call.argument(0)) == 0:
            if _result_is_kept(scan, call):
                continue  # `cũ := syscall.Umask(0)` là lối đọc giá trị hiện tại
            scan._report(
                "FSB-PERM-001",
                call.anchor,
                "umask",
                "umask(0) làm mọi tệp tạo sau đó mang quyền ghi cho cả máy",
                confidence=Confidence.HIGH,
            )


def _result_is_kept(scan: "_Scan", call) -> bool:
    """Kết quả lời gọi có được gán đi đâu không.

    `umask` trả về giá trị CŨ, nên `current = os.umask(0)` rồi `os.umask(current)`
    là lối đọc umask hiện tại -- django/core/management/templates.py làm đúng
    vậy. Chỉ khi kết quả bị bỏ thì lời gọi mới thật sự là phép đặt.
    """
    flat = scan.flat
    start = scan.position.get(id(call.anchor))
    if start is None:
        return False
    while start > 0 and flat[start - 1].text in (".", "::") and start >= 2:
        start -= 2
    return start > 0 and flat[start - 1].text in ("=", ":=", "<-")


def _shell_chmod(scan: "_Scan") -> None:
    lines = scan.unit.lines
    for token in scan.flat:
        if token.kind != IDENT or token.text != "chmod":
            continue
        scan.budget.spend()
        line = lines[token.line - 1] if token.line - 1 < len(lines) else ""
        tail = line[line.find("chmod") + 5 :]
        mode: Optional[int] = None
        found = _SHELL_MODE.search(tail)
        if found is not None:
            mode = int(found.group(1), 8)
            if not mode & _MODE_WORLD_WRITE:
                continue
        elif _SHELL_SYMBOLIC.search(tail) is None:
            continue
        scan._report(
            "FSB-PERM-001",
            token,
            "chmod",
            "chmod %s cho mọi người dùng trên máy quyền ghi"
            % (("0%o" % mode) if mode is not None else "cộng quyền ghi cho mọi người"),
            confidence=Confidence.HIGH,
            evidence=("chmod không chịu umask, nên đây là quyền thật sau khi script chạy",),
        )


def _report_mode(scan: "_Scan", token: Token, mode: int) -> None:
    scan._report(
        "FSB-PERM-001",
        token,
        "chmod",
        "chmod 0%o cho mọi người dùng trên máy quyền GHI tệp này" % mode,
        confidence=Confidence.HIGH,
        evidence=(
            "chmod không chịu umask, nên con số này là quyền thật sau khi chạy",
            "chế độ truyền cho hàm TẠO tệp hay thư mục thì còn bị umask che, nên không bị báo",
        ),
    )


def _mode(tokens: Sequence[Token]) -> Optional[int]:
    meaningful = [token for token in tokens if token.kind in (NUMBER, IDENT, STRING)]
    if len(meaningful) != 1 or meaningful[0].kind != NUMBER:
        return None
    text = meaningful[0].text
    try:
        if text[:2].lower() == "0o":
            return int(text[2:], 8)
        if len(text) > 1 and text[0] == "0" and text.isdigit():
            return int(text, 8)
        if text == "0":
            return 0
    except ValueError:
        return None
    return None


# ----------------------------------------------------------------- tệp tạm


def _temp_files(scan: "_Scan") -> None:
    if scan.language in (SHELL, POWERSHELL):
        _shell_temp(scan)
        return
    writers = _WRITERS.get(scan.language, frozenset())
    if not writers:
        return
    for call in scan.calls:
        scan.budget.spend()
        if call.parts[-1] not in writers:
            continue
        for argument in call.arguments:
            value = scan._string_value(argument)
            if value is None or not value.startswith(_TEMP_PREFIXES):
                continue
            if value.rstrip("/") in [prefix.rstrip("/") for prefix in _TEMP_PREFIXES]:
                continue
            scan._report(
                "FSB-TMP-001",
                call.anchor,
                value,
                "ghi vào đường dẫn tạm đoán trước được %r: ai cũng tạo sẵn một liên kết "
                "tượng trưng ở đúng tên đó trước khi tiến trình này chạy" % value,
                confidence=Confidence.MEDIUM,
                evidence=(
                    "đường dẫn là hằng, nên tên không đổi giữa các lượt chạy",
                    "hàm tạo tệp tạm của ngôn ngữ ( Files.createTempFile, os.CreateTemp, "
                    "tmpfile ) sinh tên ngẫu nhiên và quyền chỉ chủ sở hữu trong một bước",
                ),
            )
            break


def _shell_temp(scan: "_Scan") -> None:
    for number, line in enumerate(scan.unit.lines, start=1):
        found = _SHELL_TEMP.search(line)
        if found is None:
            continue
        scan.budget.spend()
        path = found.group(1) + found.group(2)
        scan.builder.add(
            "FSB-TMP-001",
            number,
            found.start(),
            path,
            "ghi vào đường dẫn tạm đoán trước được %r: ai cũng tạo sẵn một liên kết tượng "
            "trưng ở đúng tên đó trước khi script này chạy" % path,
            confidence=Confidence.MEDIUM,
            evidence=("`mktemp` sinh tên ngẫu nhiên và tạo tệp trong cùng một bước",),
        )


# -------------------------------------------------------------- chế độ debug


def _debug(scan: "_Scan") -> None:
    if scan.language == CSHARP:
        _csharp_debug(scan)
    elif scan.language == PHP:
        _php_debug(scan)


def _csharp_debug(scan: "_Scan") -> None:
    for index, token in enumerate(scan.flat):
        if token.kind != IDENT or token.text != "UseDeveloperExceptionPage":
            continue
        scan.budget.spend()
        region = scan._function_at(index)
        names = _region_names(scan, region)
        if "IsDevelopment" in names or "IsStaging" in names:
            continue
        scan._report(
            "FSB-DEBUG-001",
            token,
            "UseDeveloperExceptionPage",
            "UseDeveloperExceptionPage() không nằm sau một phép kiểm môi trường, nên trang "
            "lỗi in mã nguồn, truy vết và giá trị cấu hình cho cả người ngoài",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=("không thấy env.IsDevelopment() trong cùng hàm",),
        )


def _php_debug(scan: "_Scan") -> None:
    for call in scan.calls:
        scan.budget.spend()
        if call.parts[-1] != "ini_set":
            continue
        name = scan._string_value(call.argument(0))
        if name != "display_errors":
            continue
        value = _flag(scan, call.argument(1))
        if value is not True:
            continue
        scan._report(
            "FSB-DEBUG-001",
            call.anchor,
            "display_errors",
            "ini_set('display_errors', ...) bật: thông báo lỗi của PHP in ra đường dẫn tệp, "
            "câu truy vấn và chuỗi kết nối ngay trên trang",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=("nơi triển khai nên để display_errors = Off và log_errors = On",),
        )


def _flag(scan: "_Scan", tokens: Sequence[Token]) -> Optional[bool]:
    meaningful = [token for token in tokens if token.kind != OP]
    if len(meaningful) != 1:
        return None
    text = meaningful[0].text.strip("'\"").lower()
    if text in _TRUTHY:
        return True
    if text in ("0", "off", "false", "no"):
        return False
    return None


def _texts(tokens: Sequence[Token]) -> list:
    return [token.text for token in tokens if token.kind != OP or token.text not in (",",)]


__all__ = ["check"]
