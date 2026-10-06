"""Cơ chế trụ lại và cửa hậu truy cập trong tệp hiện vật ứng cứu.

Khi một dịch vụ đã bị vào, thứ quyết định việc dọn sạch được hay không nằm
ngoài mã nguồn: một dòng trong ``cron.d``, một ``ExecStart`` trỏ vào
``/tmp``, một khoá thêm vào ``authorized_keys``, một tài khoản UID 0 mới.
Vá lỗ hổng vào mà bỏ qua những chỗ này thì dịch vụ bị lấy lại sau vài phút,
nên trong một ca ứng cứu đây là phần phải đọc TRƯỚC phần mã.

Mọi phép so là chuỗi con hoặc cắt trường theo dấu phân cách, không regex --
xem lý do ở `indicators.py`.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Dict, Optional, Sequence, Tuple

from ...core.budget import Budget
from ...core.model import Confidence, StepKind
from ..base import AnalysisUnit, FindingBuilder
from . import indicators

MAX_LINES = 5_000
MAX_LINE_LENGTH = 4_096
MAX_REPORTS_PER_RULE = 10

CRON = "cron"
SYSTEMD = "systemd"
SHELL_RC = "shell-rc"
AUTHORIZED_KEYS = "authorized-keys"
PRELOAD = "preload"
WEB_CONFIG = "web-config"
SUDOERS = "sudoers"
ACCOUNTS = "accounts"
INIT_SCRIPT = "init-script"

# Cơ chế tự chạy: nội dung của chúng chạy mà không ai gọi. Ba rule đầu chỉ áp
# cho nhóm này, vì cùng một dòng `curl | sh` nằm trong README thì vô hại.
_AUTOSTART = frozenset({CRON, SYSTEMD, SHELL_RC, INIT_SCRIPT, PRELOAD})

_DOWNLOADERS: Tuple[str, ...] = (
    "curl ",
    "wget ",
    "ftpget",
    "tftp ",
    "invoke-webrequest",
    "start-bitstransfer",
    "bitsadmin",
    "certutil -urlcache",
    "certutil.exe -urlcache",
    "nc ",
    "ncat ",
    "socat ",
)

_PIPE_TO_SHELL: Tuple[str, ...] = (
    "| sh",
    "|sh",
    "| bash",
    "|bash",
    "| zsh",
    "|zsh",
    "| python",
    "|python",
    "| perl",
    "|perl",
    "| ruby",
    "|ruby",
    "| node",
    "|node",
    "$(curl",
    "$(wget",
    "`curl",
    "`wget",
    "| iex",
    "|iex",
)

_DECODERS: Tuple[str, ...] = (
    "base64 -d",
    "base64 --decode",
    "base64 -di",
    "base64 -D",
    "openssl enc -d",
    "openssl base64 -d",
    "xxd -r",
    "uudecode",
    "frombase64string",
    "[convert]::frombase64string",
    "b64decode",
    "gzip -d",
    "gunzip -c",
)

_EVAL_SHAPES: Tuple[str, ...] = ("eval ", "eval(", "exec ", "| sh", "|sh", "iex ", "python -c", "perl -e", "sh -c", "bash -c")

# Thư mục ai cũng ghi được. Một cơ chế tự chạy trỏ vào đây gần như không bao
# giờ là cấu hình của người quản trị: nội dung ở đó bất kỳ tiến trình nào
# cũng thay được, nên nó không phải chỗ đặt mã khởi động.
_WORLD_WRITABLE: Tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/var/lock/",
    "c:\\windows\\temp\\",
    "%temp%",
)

_SHELL_IN_COMMAND: Tuple[str, ...] = (
    "/sh",
    "/bash",
    "/zsh",
    "/ksh",
    "/python",
    "/perl",
    "/ruby",
    "/nc",
    "/ncat",
    "/socat",
    "sh -c",
    "bash -c",
)

_SHELL_RC_NAMES = frozenset(
    {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zlogin",
        ".kshrc",
        ".cshrc",
        "bashrc",
        "profile",
        "zshrc",
    }
)

_HANDLER_DIRECTIVES: Tuple[str, ...] = (
    "addtype application/x-httpd-php",
    "addhandler application/x-httpd-php",
    "sethandler application/x-httpd-php",
    "addhandler php",
    "addhandler x-httpd-php",
    "php_flag engine on",
    "php_admin_flag engine on",
    "options +execcgi",
    "addhandler cgi-script",
    "sethandler fcgid-script",
)


def kind_of(relative_path: str) -> Optional[str]:
    """Loại hiện vật, suy từ tên và vị trí. None nghĩa là không nhận ra."""
    normalized = relative_path.replace("\\", "/")
    name = PurePath(normalized).name
    lowered_name = name.lower()
    parents = [part.lower() for part in PurePath(normalized).parts[:-1]]
    suffix = PurePath(lowered_name).suffix

    if lowered_name.startswith("authorized_keys"):
        return AUTHORIZED_KEYS
    if lowered_name == "ld.so.preload":
        return PRELOAD
    if lowered_name in ("passwd", "shadow"):
        return ACCOUNTS
    if lowered_name == "sudoers" or "sudoers.d" in parents:
        return SUDOERS
    if lowered_name in ("nginx.conf", "httpd.conf", "apache2.conf", "web.config"):
        return WEB_CONFIG
    if lowered_name == ".htaccess":
        return WEB_CONFIG
    if "sites-enabled" in parents or "sites-available" in parents:
        return WEB_CONFIG
    if suffix in (".service", ".timer", ".socket") or "systemd" in parents:
        return SYSTEMD
    if lowered_name == "crontab" or lowered_name.endswith(".cron"):
        return CRON
    if any(part.startswith("cron.") for part in parents):
        return CRON
    if lowered_name in ("rc.local",) or "init.d" in parents or "rc.d" in parents:
        return INIT_SCRIPT
    # Danh sách rc phải LIỆT KÊ, không được bắt mọi tên bắt đầu bằng dấu chấm:
    # `kind_of` chạy cho mọi tệp được phân tích, nên một phép bắt rộng sẽ đem
    # luật của cơ chế tự chạy áp lên `.gitignore` và `.editorconfig`.
    if lowered_name in _SHELL_RC_NAMES or "profile.d" in parents:
        return SHELL_RC
    return None


def _is_comment(stripped: str, kind: str) -> bool:
    if not stripped:
        return True
    if kind == WEB_CONFIG:
        return stripped.startswith("#") or stripped.startswith("<!--")
    return stripped.startswith("#") or stripped.startswith(";")


def _command_of(stripped: str, kind: str) -> str:
    """Phần LỆNH của một dòng, bỏ phần lịch hoặc phần khoá cấu hình.

    Cần tách vì các dấu hiệu bên dưới đều nói về lệnh. Một đường dẫn `/tmp/`
    nằm trong `WorkingDirectory=` là chuyện khác hẳn với `/tmp/` nằm trong
    `ExecStart=`, và không tách thì hai thứ đó trộn vào nhau.
    """
    if kind == SYSTEMD:
        head, separator, tail = stripped.partition("=")
        if not separator:
            return ""
        if head.strip().lower() not in (
            "execstart",
            "execstartpre",
            "execstartpost",
            "execstop",
            "execreload",
            "execcondition",
        ):
            return ""
        return tail.strip()
    if kind == CRON:
        # Năm trường lịch rồi tới lệnh; `@reboot` là dạng một trường.
        if stripped.startswith("@"):
            parts = stripped.split(None, 1)
            return parts[1] if len(parts) > 1 else ""
        fields = stripped.split(None, 5)
        if len(fields) < 6:
            return ""
        return fields[5]
    return stripped


class _Reporter:
    """Đếm số lần mỗi rule đã bắn để một tệp thù địch không phình báo cáo."""

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}

    def allow(self, rule_id: str) -> bool:
        used = self._counts.get(rule_id, 0)
        if used >= MAX_REPORTS_PER_RULE:
            return False
        self._counts[rule_id] = used + 1
        return True


def _check_autostart(
    kind: str,
    line_number: int,
    stripped: str,
    builder: FindingBuilder,
    reporter: _Reporter,
) -> None:
    command = _command_of(stripped, kind)
    if not command:
        return
    lowered = command.lower()
    column = stripped.find(command)
    if column < 0:
        column = 0

    downloader = next((item for item in _DOWNLOADERS if item in lowered), None)
    piped = next((item for item in _PIPE_TO_SHELL if item in lowered), None)
    if downloader is not None and piped is not None and reporter.allow("FSB-IR-010"):
        builder.add(
            rule_id="FSB-IR-010",
            line=line_number,
            column=column,
            symbol=downloader.strip(),
            message=(
                "cơ chế tự chạy này tải nội dung từ xa về rồi đưa thẳng cho shell; "
                "nội dung chạy không hề được kiểm, và nó đổi được bất cứ lúc nào ở "
                "đầu bên kia"
            ),
            trace=(
                builder.step(StepKind.SOURCE, line_number, column, "tải về bằng %s" % downloader.strip()),
                builder.step(StepKind.SINK, line_number, column, "đưa cho shell qua %s" % piped.strip()),
            ),
            evidence=(
                "tệp là %s nên dòng này chạy mà không ai gọi" % kind,
                "lệnh tải: %r" % downloader.strip(),
                "chuyển cho trình thông dịch: %r" % piped.strip(),
            ),
            tags=("ir", "persistence", "compromise"),
        )
        return

    writable = next((item for item in _WORLD_WRITABLE if item in lowered), None)
    if writable is not None and reporter.allow("FSB-IR-011"):
        builder.add(
            rule_id="FSB-IR-011",
            line=line_number,
            column=column,
            symbol=writable,
            message=(
                "cơ chế tự chạy này thực thi thứ nằm trong %s, là thư mục mọi tiến "
                "trình đều ghi được; ai ghi được vào đó thì chạy được mã ở lần khởi "
                "động sau" % writable
            ),
            trace=(
                builder.step(StepKind.SINK, line_number, column, "chạy từ thư mục ai cũng ghi được"),
            ),
            evidence=(
                "tệp là %s nên dòng này chạy mà không ai gọi" % kind,
                "đường dẫn thực thi nằm trong %r" % writable,
            ),
            tags=("ir", "persistence", "compromise"),
        )
        return

    decoder = next((item for item in _DECODERS if item in lowered), None)
    if decoder is not None and any(item in lowered for item in _EVAL_SHAPES):
        if reporter.allow("FSB-IR-012"):
            builder.add(
                rule_id="FSB-IR-012",
                line=line_number,
                column=column,
                symbol=decoder,
                message=(
                    "cơ chế tự chạy này giải mã một khối nội dung rồi thực thi kết quả; "
                    "lệnh thật không nằm trong tệp nên không ai đọc tệp mà biết nó làm gì"
                ),
                trace=(
                    builder.step(StepKind.PROPAGATION, line_number, column, "giải mã bằng %s" % decoder),
                    builder.step(StepKind.SINK, line_number, column, "thực thi kết quả"),
                ),
                evidence=(
                    "tệp là %s nên dòng này chạy mà không ai gọi" % kind,
                    "lớp giải mã: %r" % decoder,
                ),
                tags=("ir", "persistence", "compromise"),
            )
        return

    if kind == SHELL_RC and "ld_preload" in lowered and reporter.allow("FSB-IR-013"):
        builder.add(
            rule_id="FSB-IR-013",
            line=line_number,
            column=column,
            symbol="LD_PRELOAD",
            message=(
                "tệp rc này đặt LD_PRELOAD, nên thư viện được nêu sẽ chen vào MỌI "
                "tiến trình của phiên đăng nhập và ghi đè được cả hàm thư viện chuẩn"
            ),
            trace=(builder.step(StepKind.SINK, line_number, column, "đặt LD_PRELOAD"),),
            evidence=("tệp rc chạy ở mỗi lần đăng nhập",),
            tags=("ir", "persistence", "compromise"),
        )


def _check_preload_entry(
    line_number: int, stripped: str, builder: FindingBuilder, reporter: _Reporter
) -> None:
    if not reporter.allow("FSB-IR-013"):
        return
    builder.add(
        rule_id="FSB-IR-013",
        line=line_number,
        column=0,
        symbol=stripped[:120],
        message=(
            "ld.so.preload nạp thư viện này vào mọi tiến trình chạy trên máy, kể cả "
            "tiến trình của root; đây là chỗ rootkit vùng người dùng cắm vào, và một "
            "hệ thống bình thường để tệp này rỗng"
        ),
        trace=(builder.step(StepKind.SINK, line_number, 0, "thư viện nạp trước toàn hệ thống"),),
        evidence=(
            "ld.so.preload có hiệu lực toàn máy, không riêng một tiến trình",
            "mục được nạp: %r" % stripped[:120],
        ),
        tags=("ir", "persistence", "rootkit", "compromise"),
    )


def _check_authorized_key(
    line_number: int, stripped: str, builder: FindingBuilder, reporter: _Reporter
) -> None:
    lowered = stripped.lower()
    if "command=" in lowered:
        forced = any(item in lowered for item in _SHELL_IN_COMMAND)
        if forced and reporter.allow("FSB-IR-014"):
            builder.add(
                rule_id="FSB-IR-014",
                line=line_number,
                column=lowered.find("command="),
                symbol="command=",
                message=(
                    "khoá này mang lệnh cưỡng chế chạy một trình thông dịch, nên ai "
                    "giữ khoá riêng tương ứng có shell ngay khi kết nối, bất kể cấu "
                    "hình của tài khoản"
                ),
                trace=(
                    builder.step(StepKind.SINK, line_number, 0, "lệnh cưỡng chế của khoá SSH"),
                ),
                evidence=("tuỳ chọn command= chạy trước mọi thứ khác khi khoá này được dùng",),
                tags=("ir", "backdoor", "compromise"),
            )
            return
    if "environment=" in lowered and reporter.allow("FSB-IR-014"):
        builder.add(
            rule_id="FSB-IR-014",
            line=line_number,
            column=lowered.find("environment="),
            symbol="environment=",
            message=(
                "khoá này đặt biến môi trường cho phiên đăng nhập; kèm LD_PRELOAD "
                "hoặc PATH thì nó đổi được mã chạy trong phiên mà không sửa tệp nào"
            ),
            confidence=Confidence.MEDIUM,
            trace=(builder.step(StepKind.SINK, line_number, 0, "tuỳ chọn environment="),),
            evidence=("tuỳ chọn này chỉ có tác dụng khi PermitUserEnvironment được bật",),
            tags=("ir", "backdoor", "compromise"),
        )


def _check_account(
    line_number: int, stripped: str, builder: FindingBuilder, reporter: _Reporter
) -> None:
    fields = stripped.split(":")
    if len(fields) < 4:
        return
    name = fields[0]
    uid_text = fields[2]
    if not uid_text.isdigit():
        return
    if int(uid_text) == 0 and name != "root" and reporter.allow("FSB-IR-015"):
        builder.add(
            rule_id="FSB-IR-015",
            line=line_number,
            column=0,
            symbol=name,
            message=(
                "tài khoản %r có UID 0, tức là quyền ngang root nhưng dưới một cái "
                "tên khác; đó là cách một cửa hậu sống qua việc đổi mật khẩu root" % name
            ),
            trace=(builder.step(StepKind.SINK, line_number, 0, "tài khoản UID 0 thứ hai"),),
            evidence=(
                "UID 0 là thứ quyết định quyền, tên tài khoản không quyết định gì",
                "dòng khai báo: %r" % stripped[:120],
            ),
            tags=("ir", "backdoor", "privilege", "compromise"),
        )


def _check_sudoers(
    line_number: int, stripped: str, builder: FindingBuilder, reporter: _Reporter
) -> None:
    lowered = stripped.lower()
    if "nopasswd:" not in lowered:
        return
    if "all" not in lowered.split("nopasswd:", 1)[1]:
        return
    if not reporter.allow("FSB-IR-016"):
        return
    builder.add(
        rule_id="FSB-IR-016",
        line=line_number,
        column=0,
        symbol=stripped.split(None, 1)[0][:60],
        message=(
            "quy tắc này cho chạy mọi lệnh với quyền root mà không cần mật khẩu, nên "
            "bất cứ ai đã vào được tài khoản đó đều lên root ngay, không cần lỗ hổng nào"
        ),
        confidence=Confidence.MEDIUM,
        trace=(builder.step(StepKind.SINK, line_number, 0, "NOPASSWD cho mọi lệnh"),),
        evidence=("dòng quy tắc: %r" % stripped[:120],),
        tags=("ir", "privilege", "compromise"),
    )


def _check_web_config(
    relative_path: str,
    line_number: int,
    stripped: str,
    builder: FindingBuilder,
    reporter: _Reporter,
) -> None:
    lowered = stripped.lower()
    directive = next((item for item in _HANDLER_DIRECTIVES if item in lowered), None)
    if directive is None:
        return
    if not reporter.allow("FSB-IR-017"):
        return
    in_upload = indicators.upload_directory_of(relative_path)
    builder.add(
        rule_id="FSB-IR-017",
        line=line_number,
        column=max(0, lowered.find(directive)),
        symbol=directive,
        message=(
            "cấu hình này bật bộ xử lý mã cho thư mục chứa nó%s; mọi tệp tải lên "
            "được ở đây trở thành mã chạy trên máy chủ"
            % (", và đó là thư mục tải lên" if in_upload else "")
        ),
        confidence=Confidence.HIGH if in_upload else Confidence.MEDIUM,
        trace=(builder.step(StepKind.SINK, line_number, 0, "chỉ thị bật bộ xử lý mã"),),
        evidence=tuple(
            item
            for item in (
                "chỉ thị: %r" % directive,
                ("thư mục tải lên: %s" % in_upload) if in_upload else "",
            )
            if item
        ),
        tags=("ir", "webshell", "misconfiguration"),
    )


def scan(unit: AnalysisUnit, builder: FindingBuilder, budget: Budget) -> None:
    kind = kind_of(unit.relative_path)
    if kind is None:
        return
    reporter = _Reporter()
    lines: Sequence[str] = unit.lines[:MAX_LINES]
    for index, text in enumerate(lines, start=1):
        budget.spend()
        if len(text) > MAX_LINE_LENGTH:
            continue
        stripped = text.strip()
        if _is_comment(stripped, kind):
            continue

        if kind in _AUTOSTART:
            if kind == PRELOAD:
                _check_preload_entry(index, stripped, builder, reporter)
            else:
                _check_autostart(kind, index, stripped, builder, reporter)
        elif kind == AUTHORIZED_KEYS:
            _check_authorized_key(index, stripped, builder, reporter)
        elif kind == ACCOUNTS:
            _check_account(index, stripped, builder, reporter)
        elif kind == SUDOERS:
            _check_sudoers(index, stripped, builder, reporter)
        elif kind == WEB_CONFIG:
            _check_web_config(unit.relative_path, index, stripped, builder, reporter)
