from __future__ import annotations

from pathlib import Path, PurePath
from typing import Dict, Optional, Tuple

PYTHON = "python"
JAVASCRIPT = "javascript"
TYPESCRIPT = "typescript"
PHP = "php"
JAVA = "java"
RUBY = "ruby"
GO = "go"
CSHARP = "csharp"
SHELL = "shell"
RUST = "rust"
POWERSHELL = "powershell"
PERL = "perl"
LUA = "lua"
MANIFEST = "manifest"
# Workflow CI là mã thật: nó chạy trên máy có token đẩy được lên registry và
# ký được release, và `run:` của nó là một shell script mà GitHub dán chuỗi
# vào TRƯỚC khi shell nhìn thấy. Đó là một ngôn ngữ riêng chứ không phải YAML
# vô hại, nên nó có bộ phân tích riêng.
WORKFLOW = "workflow"
# Tệp mà một ca ứng cứu phải đọc nhưng không lập trình viên nào coi là mã
# nguồn: crontab, unit của systemd, tệp rc của shell, authorized_keys,
# ld.so.preload, cấu hình máy chủ web, sudoers. Chúng nằm ngoài mọi bảng phần
# mở rộng nên trước bản này bộ duyệt cây không hề NHÌN THẤY chúng -- mà đó
# đúng là nơi kẻ tấn công cắm cơ chế trụ lại, vì nó chạy mà không cần sửa một
# dòng mã nào của dự án.
IR_ARTIFACT = "ir-artifact"

_EXTENSION_MAP: Dict[str, str] = {
    ".py": PYTHON,
    ".pyw": PYTHON,
    ".pyi": PYTHON,
    ".js": JAVASCRIPT,
    ".mjs": JAVASCRIPT,
    ".cjs": JAVASCRIPT,
    ".jsx": JAVASCRIPT,
    ".ts": TYPESCRIPT,
    ".tsx": TYPESCRIPT,
    ".mts": TYPESCRIPT,
    ".cts": TYPESCRIPT,
    ".vue": JAVASCRIPT,
    ".svelte": JAVASCRIPT,
    ".php": PHP,
    ".php3": PHP,
    ".php4": PHP,
    ".php5": PHP,
    ".php7": PHP,
    ".phtml": PHP,
    ".inc": PHP,
    ".java": JAVA,
    ".jsp": JAVA,
    ".jspx": JAVA,
    ".kt": JAVA,
    ".kts": JAVA,
    ".groovy": JAVA,
    ".scala": JAVA,
    ".rb": RUBY,
    ".rake": RUBY,
    ".erb": RUBY,
    ".go": GO,
    ".cs": CSHARP,
    ".cshtml": CSHARP,
    ".aspx": CSHARP,
    ".ashx": CSHARP,
    ".sh": SHELL,
    ".bash": SHELL,
    ".zsh": SHELL,
    ".ksh": SHELL,
    ".rs": RUST,
    ".ps1": POWERSHELL,
    ".psm1": POWERSHELL,
    ".psd1": POWERSHELL,
    ".pl": PERL,
    ".pm": PERL,
    ".t": PERL,
    ".cgi": PERL,
    ".lua": LUA,
    # Unit của systemd. Phần mở rộng CUỐI mới quyết định, nên `foo.service.ts`
    # của Angular vẫn là TypeScript và không rơi vào đây.
    ".service": IR_ARTIFACT,
    ".timer": IR_ARTIFACT,
    ".socket": IR_ARTIFACT,
}

_FILENAME_MAP: Dict[str, str] = {
    "package.json": MANIFEST,
    "composer.json": MANIFEST,
    "Gemfile": RUBY,
    "Rakefile": RUBY,
    "Dockerfile": SHELL,
    "Makefile": SHELL,
    # Tệp hiện vật ứng cứu. Những cái bắt đầu bằng dấu chấm phải có mặt ở
    # ĐÂY chứ không chỉ trong bộ dò: `is_scannable_name()` loại mọi tên ẩn
    # trừ tên nằm trong bảng này, nên thiếu một dòng là tệp đó không bao giờ
    # được liệt kê, và lỗ hổng biến mất trong im lặng.
    ".bashrc": IR_ARTIFACT,
    ".bash_profile": IR_ARTIFACT,
    ".bash_login": IR_ARTIFACT,
    ".bash_logout": IR_ARTIFACT,
    ".profile": IR_ARTIFACT,
    ".zshrc": IR_ARTIFACT,
    ".zprofile": IR_ARTIFACT,
    ".kshrc": IR_ARTIFACT,
    ".htaccess": IR_ARTIFACT,
    "authorized_keys": IR_ARTIFACT,
    "authorized_keys2": IR_ARTIFACT,
    "crontab": IR_ARTIFACT,
    "ld.so.preload": IR_ARTIFACT,
    "sudoers": IR_ARTIFACT,
    "passwd": IR_ARTIFACT,
    "shadow": IR_ARTIFACT,
    "nginx.conf": IR_ARTIFACT,
    "httpd.conf": IR_ARTIFACT,
    "apache2.conf": IR_ARTIFACT,
    "web.config": IR_ARTIFACT,
    "rc.local": IR_ARTIFACT,
}

# Thư mục mà nội dung bên trong là hiện vật ứng cứu bất kể tên tệp. `cron.d`
# chứa tệp không có phần mở rộng, `profile.d` chứa .sh, `sites-enabled` chứa
# .conf -- không có bảng tên nào bắt được cả ba, chỉ vị trí mới bắt được.
_IR_DIRECTORIES: Tuple[str, ...] = (
    "cron.d",
    "cron.daily",
    "cron.hourly",
    "cron.weekly",
    "cron.monthly",
    "sudoers.d",
    "profile.d",
    "sites-enabled",
    "sites-available",
    "init.d",
    "rc.d",
    "systemd",
    "authorized_keys.d",
)

_SHEBANG_MAP: Tuple[Tuple[str, str], ...] = (
    ("python", PYTHON),
    ("node", JAVASCRIPT),
    ("php", PHP),
    ("ruby", RUBY),
    ("bash", SHELL),
    ("zsh", SHELL),
    ("perl", PERL),
    ("lua", LUA),
    ("pwsh", POWERSHELL),
    ("sh", SHELL),
)

_MAX_FILENAME_LENGTH = 255

# Thư mục chứa định nghĩa workflow của các nền tảng CI dùng cú pháp GitHub
# Actions. Gitea và Forgejo chạy lại đúng bộ chạy đó, kể cả biểu thức
# ${{ ... }}, nên chúng chia sẻ cùng một loạt lỗ hổng.
_WORKFLOW_DIRECTORIES: Tuple[Tuple[str, str], ...] = (
    (".github", "workflows"),
    (".gitea", "workflows"),
    (".forgejo", "workflows"),
)

_WORKFLOW_SUFFIXES: Tuple[str, ...] = (".yml", ".yaml")


def language_from_relative(relative_path: str) -> Optional[str]:
    """Ngôn ngữ suy từ VỊ TRÍ chứ không phải từ phần mở rộng.

    `.yml` nói chung không phải mã, nhưng `.github/workflows/build.yml` thì có:
    nó là một script chạy trên máy giữ token đẩy release. Phân biệt được hai
    thứ đó chỉ có đường dẫn, nên phép nhận dạng này phải nhận cả đường dẫn --
    trả None nghĩa là "không biết", và người gọi rơi về nhận dạng theo tên.
    """
    parts = [part for part in relative_path.replace("\\", "/").split("/") if part]
    # Hiện vật ứng cứu xét trước: một tệp trong `cron.d` là lịch chạy lệnh dù
    # tên nó không có phần mở rộng nào, và không bảng tên nào bắt được điều đó.
    #
    # Nhưng vị trí chỉ được quyết khi TÊN không nói gì: `scripts/init.d/x.py`
    # vẫn phải là Python. Thiếu phép nhường này thì một thư mục trùng tên sẽ
    # âm thầm gỡ cả cây con khỏi phần dò injection.
    if len(parts) >= 2 and language_from_name(parts[-1]) is None:
        for part in parts[:-1]:
            if part.lower() in _IR_DIRECTORIES:
                return IR_ARTIFACT
    if len(parts) < 3:
        return None
    if not parts[-1].lower().endswith(_WORKFLOW_SUFFIXES):
        return None
    for index in range(len(parts) - 2):
        pair = (parts[index].lower(), parts[index + 1].lower())
        if pair in _WORKFLOW_DIRECTORIES:
            return WORKFLOW
    return None


def is_scannable_name(name: str) -> bool:
    if not name or len(name) > _MAX_FILENAME_LENGTH:
        return False
    return not name.startswith(".") or name in _FILENAME_MAP


def language_from_name(name: str) -> Optional[str]:
    """Ngôn ngữ suy được CHỈ từ tên, không chạm vào đĩa.

    Dùng để đếm những tệp bị tệp ignore loại bỏ: ở đó ta cần biết "đây có phải
    mã nguồn không" mà không được mở tệp -- mở ra thì hoá ra vẫn đọc đúng thứ
    vừa tuyên bố là bỏ qua. Đổi lại, script không có phần mở rộng (nhận diện
    bằng shebang) không được tính, nên số đếm là cận dưới.
    """
    mapped = _FILENAME_MAP.get(name)
    if mapped is not None:
        return mapped
    return _EXTENSION_MAP.get(PurePath(name).suffix.lower())


def detect_language(path: Path, name: Optional[str] = None) -> Optional[str]:
    """`name` tách tên hiển thị khỏi tệp thật trên đĩa.

    Khi đi theo một liên kết, cái tên nằm trong cây được quét là tên của
    liên kết, còn nội dung nằm ở đích -- nên ngôn ngữ đoán theo tên liên kết
    nhưng shebang phải đọc từ đích.
    """
    label = name or path.name
    mapped = _FILENAME_MAP.get(label)
    if mapped is not None:
        return mapped
    suffix = PurePath(label).suffix.lower()
    mapped = _EXTENSION_MAP.get(suffix)
    if mapped is not None:
        return mapped
    if suffix == "":
        return _detect_by_shebang(path)
    return None


def _detect_by_shebang(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            first = handle.readline(256)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    try:
        header = first.decode("utf-8", errors="replace").lower()
    except Exception:
        return None
    for token, language in _SHEBANG_MAP:
        if token in header:
            return language
    return None


def display_name(language: str) -> str:
    return {
        PYTHON: "Python",
        JAVASCRIPT: "JavaScript",
        TYPESCRIPT: "TypeScript",
        PHP: "PHP",
        JAVA: "Java/JVM",
        RUBY: "Ruby",
        GO: "Go",
        CSHARP: "C#",
        SHELL: "Shell",
        RUST: "Rust",
        POWERSHELL: "PowerShell",
        PERL: "Perl",
        LUA: "Lua",
        MANIFEST: "Package manifest",
        WORKFLOW: "CI workflow",
        IR_ARTIFACT: "Hiện vật ứng cứu",
    }.get(language, language)
