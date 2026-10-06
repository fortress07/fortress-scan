"""Bảng dấu hiệu cho bộ truy vết xâm nhập.

Mọi phép so ở đây là so CHUỖI CON trên bản đã hạ chữ thường, không phải regex.
Đó là một quyết định về an toàn chứ không phải về khẩu vị: công cụ này đọc tệp
của người lạ, và `tests/test_regex_complexity.py` đo từng mẫu regex trong src/
vì hai lỗ hổng từ chối dịch vụ bậc hai đã từng tồn tại thật ở đây. `in` trên
str chạy tuyến tính và không có đường quay lui nào để ai khai thác, nên cả lớp
lỗ hổng đó không diễn đạt được trong tệp này.

Mỗi bảng là một TRỤ: một loại bằng chứng độc lập. Bộ dò kết luận bằng cách
đếm trụ nào có mặt trong cùng một tệp, chứ không bằng cách khớp một mẫu duy
nhất -- xem `webshell.py`.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Tuple

from ...languages import (
    CSHARP,
    JAVA,
    JAVASCRIPT,
    PERL,
    PHP,
    POWERSHELL,
    PYTHON,
    RUBY,
    SHELL,
    TYPESCRIPT,
)

# Ngôn ngữ mà một webshell thật được viết bằng. Rust hay Go không có mặt vì
# webshell cần chạy được ngay khi ghi tệp xuống, còn mã biên dịch thì không:
# kẻ tấn công cắm nhị phân, và nhị phân là việc của bộ phân tích tệp thực thi.
WEBSHELL_LANGUAGES: FrozenSet[str] = frozenset(
    {PHP, JAVA, CSHARP, PYTHON, JAVASCRIPT, TYPESCRIPT, PERL, RUBY, SHELL, POWERSHELL}
)

# Bảng nào dò trên MÃ, bảng nào dò trên văn bản thô
# -------------------------------------------------
# Dấu hiệu là lời gọi hàm hoặc biến siêu toàn cục thì phải nằm NGOÀI chuỗi mới
# có nghĩa, nên chúng dò trên bản đã xóa chuỗi và chú thích ( `scrub.py` ).
# Ngược lại, dấu hiệu bản chất là THAM SỐ dạng chuỗi -- `php://input`,
# `display_errors` -- thì chỉ tồn tại bên trong nháy, nên chúng dò trên văn bản
# thô. Tên biến dưới đây nói rõ bảng nào thuộc nhóm nào, vì trộn hai nhóm là
# cách bộ dò vừa bỏ sót webshell thật vừa báo nhầm trên tệp nói về webshell.

# TRỤ 1 -- đầu vào từ xa. Kẻ tấn công phải ra lệnh được cho thứ mình cắm, nên
# một webshell luôn đọc dữ liệu request ở đâu đó.
_INPUT_COMMON: Tuple[str, ...] = (
    "$_get",
    "$_post",
    "$_request",
    "$_cookie",
    "$_files",
    "$_server[",
    "getallheaders(",
    "apache_request_headers(",
    "request.getparameter",
    "request.getheader",
    "request.getinputstream",
    "request.getparametervalues",
    "request.querystring",
    "request.form",
    "request.params",
    "request.args",
    "request.values",
    "request.get_json(",
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "query_string",
    "http_user_agent",
)

INPUT_MARKERS: Dict[str, Tuple[str, ...]] = {
    PHP: _INPUT_COMMON,
    JAVA: _INPUT_COMMON,
    CSHARP: _INPUT_COMMON,
    PYTHON: _INPUT_COMMON,
    JAVASCRIPT: _INPUT_COMMON,
    TYPESCRIPT: _INPUT_COMMON,
    PERL: _INPUT_COMMON + ("param(", "$env{'query_string'}"),
    RUBY: _INPUT_COMMON + ("params[",),
    SHELL: ("query_string", "$http_", "request_method"),
    POWERSHELL: ("$request.", "query_string"),
}

# Đầu vào chỉ xuất hiện dưới dạng tham số chuỗi, nên dò trên văn bản thô.
INPUT_LITERAL_MARKERS: Tuple[str, ...] = (
    "php://input",
    "php://stdin",
    "http_raw_post_data",
)

# TRỤ 2 -- nơi thực thi. Một webshell không có sink thì không làm được gì;
# đây là chỗ lệnh của kẻ tấn công thành hành động.
_SINK_PHP: Tuple[str, ...] = (
    "eval(",
    "assert(",
    "system(",
    "shell_exec(",
    "passthru(",
    "popen(",
    "proc_open(",
    "pcntl_exec(",
    "create_function(",
    "call_user_func(",
    "preg_replace_callback(",
    "file_put_contents(",
)

_SINK_JAVA: Tuple[str, ...] = (
    "runtime.getruntime().exec",
    "processbuilder(",
    "scriptenginemanager",
    "defineclass(",
    "classloader",
    "getmethod(",
    "invoke(",
)

_SINK_DOTNET: Tuple[str, ...] = (
    "process.start",
    "createobject(",
    "wscript.shell",
    "executeglobal",
    "execute(",
    "assembly.load",
)

_SINK_PYTHON: Tuple[str, ...] = (
    "eval(",
    "exec(",
    "os.system(",
    "os.popen(",
    "subprocess.",
    "compile(",
    "__import__(",
    "marshal.loads(",
)

_SINK_NODE: Tuple[str, ...] = (
    "child_process",
    "execsync(",
    "spawnsync(",
    "eval(",
    "new function(",
    "vm.runin",
)

_SINK_SHELLY: Tuple[str, ...] = ("eval ", "eval(", "system(", "exec ", "`", "$(")

SINK_MARKERS: Dict[str, Tuple[str, ...]] = {
    PHP: _SINK_PHP,
    JAVA: _SINK_JAVA,
    CSHARP: _SINK_DOTNET,
    PYTHON: _SINK_PYTHON,
    JAVASCRIPT: _SINK_NODE,
    TYPESCRIPT: _SINK_NODE,
    PERL: _SINK_SHELLY + ("qx(",),
    RUBY: _SINK_SHELLY + ("%x(",),
    SHELL: _SINK_SHELLY,
    POWERSHELL: ("invoke-expression", "iex ", "start-process", "invoke-command"),
}

# TRỤ 3 -- lớp làm rối. Mã mà chính người bảo trì viết hiếm khi cần giải mã
# chính nó trước khi chạy; webshell thì gần như luôn, để qua mắt bộ dò theo
# từ khoá và để người đọc log không hiểu nó làm gì.
DECODER_MARKERS: Tuple[str, ...] = (
    "base64_decode(",
    "gzinflate(",
    "gzuncompress(",
    "gzdecode(",
    "str_rot13(",
    "hex2bin(",
    "convert_uudecode(",
    "strrev(",
    "base64.b64decode(",
    "base64.b64encode(",
    "codecs.decode(",
    "zlib.decompress(",
    "bytes.fromhex(",
    "base64.getdecoder()",
    "frombase64string(",
    "buffer.from(",
    "atob(",
    "unescape(",
    "[convert]::frombase64string",
)

# Dạng gọi gián tiếp: tên hàm được ghép lúc chạy nên không có từ khoá nào để
# dò. ``$$x`` là lối viết kinh điển của webshell PHP.
#
# Theo ngôn ngữ chứ không dùng một bảng chung, vì cùng một chuỗi mang hai nghĩa
# khác hẳn: ``$$`` trong PHP là biến của biến, còn trong shell nó chỉ là số
# hiệu tiến trình. Một bảng chung sẽ gắn trụ "làm rối" cho gần như mọi script
# shell có thật.
INDIRECTION_MARKERS: Dict[str, Tuple[str, ...]] = {
    PHP: ("$$", "call_user_func_array(", "${$"),
    PYTHON: ("globals()[", "getattr(__builtins__", "vars()["),
    JAVASCRIPT: ("window[", "globalthis[", "constructor("),
    TYPESCRIPT: ("window[", "globalthis[", "constructor("),
    JAVA: ("getdeclaredmethod(", "forname("),
    CSHARP: ("gettype(", "invokemember("),
    PERL: ("->can(",),
    RUBY: ("send(", "public_send("),
}

# TRỤ 4 -- dấu che. Khúc mở đầu quen thuộc của webshell: tắt báo lỗi để lỗi
# cú pháp của chính nó không lọt vào log, bỏ giới hạn thời gian để chạy được
# lệnh dài, nới bộ nhớ để nén được thư mục trước khi mang đi.
CONCEALMENT_MARKERS: Tuple[str, ...] = (
    "error_reporting(0)",
    "@error_reporting",
    "@ini_set",
    "set_time_limit(0)",
    "@set_time_limit",
    "ignore_user_abort(true)",
    "ob_clean()",
    "ob_end_clean()",
)

# Tên thiết lập PHP luôn nằm trong nháy ( ``ini_set('display_errors', 0)`` ),
# nên chúng dò trên văn bản thô. Nhóm này một mình KHÔNG dựng được kết luận:
# nó chỉ là một trong nhiều trụ, và trụ sink thì bắt buộc phải là mã thật.
CONCEALMENT_LITERAL_MARKERS: Tuple[str, ...] = (
    "display_errors",
    "max_execution_time",
    "memory_limit",
    "allow_url_fopen",
    "disable_functions",
)

# Thư mục mà máy chủ web ghi được nhưng KHÔNG nên có mã chạy được. Một tệp
# .php nằm ở đây gần như luôn là tệp được tải lên, không phải tệp của dự án.
UPLOAD_DIRECTORIES: Tuple[str, ...] = (
    "uploads/",
    "upload/",
    "userfiles/",
    "attachments/",
    "avatars/",
    "images/",
    "img/",
    "media/",
    "static/",
    "assets/",
    "public/files/",
    "files/",
    "tmp/",
    "temp/",
    "cache/",
    "backup/",
    "wp-content/uploads/",
    "sites/default/files/",
    "storage/app/public/",
)

# Phần mở rộng trông như dữ liệu. ``anh.jpg.php`` khai thác chỗ máy chủ chọn
# bộ xử lý theo phần mở rộng CUỐI còn người kiểm duyệt nhìn phần đầu.
DECOY_SUFFIXES: Tuple[str, ...] = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".webp",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".zip",
    ".txt",
    ".csv",
    ".ico",
    ".svg",
)

# TRỤ 5 -- cổng mật khẩu. Kẻ tấn công không muốn đội khác dùng được cửa hậu
# của mình, nên webshell hay có một phép so với hằng băm cứng.
AUTH_GATE_MARKERS: Tuple[str, ...] = (
    "md5(",
    "sha1(",
    "crypt(",
    "password_verify(",
    "hash('md5'",
    "hashlib.md5(",
    "hashlib.sha1(",
)

# Dấu hiệu cho thấy tệp thuộc một dự án thật chứ không phải tệp cắm vào:
# khai báo không gian tên, khung ứng dụng, giấy phép. Có mặt thì hạ trụ "dấu
# che" vì tệp rõ ràng được viết để sống chung với phần còn lại của dự án.
SCAFFOLDING_MARKERS: Tuple[str, ...] = (
    "namespace ",
    "declare(strict_types",
    "use illuminate\\",
    "use symfony\\",
    "extends controller",
    "@app\\",
    "spdx-license-identifier",
    "copyright (c)",
    "from django",
    "from flask",
    "from fastapi",
    "import org.springframework",
    "@restcontroller",
    "@controller",
    "module.exports",
    "describe(",
    "it(",
    "def test_",
)


def upload_directory_of(relative_path: str) -> Optional[str]:
    """Thư mục tải lên chứa đường dẫn này, hoặc None.

    Dùng ở cả hai bộ dò: `webshell.py` coi đây là dấu tệp bị cắm, còn
    `persistence.py` coi đây là thứ nâng mức một chỉ thị bật bộ xử lý mã. Để
    hai bản sao thì một lần sửa bảng sẽ chỉ có tác dụng ở một nửa.
    """
    lowered = relative_path.replace("\\", "/").lower()
    for directory in UPLOAD_DIRECTORIES:
        if lowered.startswith(directory) or ("/" + directory) in lowered:
            return directory
    return None
