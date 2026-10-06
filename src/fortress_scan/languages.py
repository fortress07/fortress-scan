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

# Mã native: lỗi bộ nhớ là họ lỗ hổng riêng của nhóm này.
C = "c"
CPP = "cpp"
OBJC = "objective-c"

# Các ngôn ngữ JVM khác Java: cùng thư viện chuẩn, khác cú pháp chuỗi và khai báo.
KOTLIN = "kotlin"
SCALA = "scala"
# Groovy gồm cả Jenkinsfile và script Gradle: `sh "..."` của pipeline là một
# lệnh shell chạy trên máy build giữ credential.
GROOVY = "groovy"

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
    ".kt": KOTLIN,
    ".kts": KOTLIN,
    ".groovy": GROOVY,
    ".gvy": GROOVY,
    ".gy": GROOVY,
    ".gsh": GROOVY,
    ".gradle": GROOVY,
    ".jenkinsfile": GROOVY,
    ".scala": SCALA,
    ".sc": SCALA,
    ".c": C,
    ".h": C,
    ".cc": CPP,
    ".cpp": CPP,
    ".cxx": CPP,
    ".c++": CPP,
    ".hpp": CPP,
    ".hh": CPP,
    ".hxx": CPP,
    ".h++": CPP,
    ".ipp": CPP,
    ".inl": CPP,
    ".tcc": CPP,
    ".mm": OBJC,
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
}

_FILENAME_MAP: Dict[str, str] = {
    "package.json": MANIFEST,
    "composer.json": MANIFEST,
    "Gemfile": RUBY,
    "Rakefile": RUBY,
    "Dockerfile": SHELL,
    "Makefile": SHELL,
    "Jenkinsfile": GROOVY,
}

# Tiền tố tên tệp: `Jenkinsfile.release`, `Jenkinsfile-nightly`.
_FILENAME_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("Jenkinsfile.", GROOVY),
    ("Jenkinsfile-", GROOVY),
    ("Jenkinsfile_", GROOVY),
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

# `.m` là Objective-C hoặc MATLAB/Octave: chỉ biết được bằng cách nhìn nội dung.
_OBJC_MARKERS = ("#import", "@interface", "@implementation", "@end", "NSString")
_SNIFF_BYTES = 16384

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
    mapped = _by_prefix(name)
    if mapped is not None:
        return mapped
    return _EXTENSION_MAP.get(PurePath(name).suffix.lower())


def _by_prefix(name: str) -> Optional[str]:
    for prefix, language in _FILENAME_PREFIXES:
        if name.startswith(prefix) and len(name) > len(prefix):
            return language
    return None


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
    mapped = _by_prefix(label)
    if mapped is not None:
        return mapped
    suffix = PurePath(label).suffix.lower()
    mapped = _EXTENSION_MAP.get(suffix)
    if mapped is not None:
        return mapped
    if suffix == ".m":
        return _detect_objective_c(path)
    if suffix == "":
        return _detect_by_shebang(path)
    return None


def _detect_objective_c(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            head = handle.read(_SNIFF_BYTES)
    except OSError:
        return None
    if b"\x00" in head:
        return None
    text = head.decode("utf-8", errors="replace")
    return OBJC if any(marker in text for marker in _OBJC_MARKERS) else None


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
        JAVA: "Java",
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
        C: "C",
        CPP: "C++",
        OBJC: "Objective-C",
        KOTLIN: "Kotlin",
        SCALA: "Scala",
        GROOVY: "Groovy",
    }.get(language, language)
