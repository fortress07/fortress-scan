from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Optional, Tuple

from ...core.model import Category, Confidence

ALWAYS = "always"
SHELL_KWARG = "shell-kwarg"
SHELL_ALWAYS = "shell-always"
ARGV = "argv"
SQL_TEXT = "sql-text"
YAML_LOAD = "yaml-load"
NUMPY_LOAD = "numpy-load"
TORCH_LOAD = "torch-load"
TAINT_ONLY = "taint-only"
XML_PARSER = "xml-parser"


@dataclass(frozen=True)
class SourceSpec:
    label: str
    confidence: Confidence = Confidence.HIGH
    low_signal: bool = False


@dataclass(frozen=True)
class SinkSpec:
    qualname: str
    category: Category
    tainted_rule: str
    dynamic_rule: Optional[str]
    description: str
    positions: Tuple[int, ...] = (0,)
    keywords: Tuple[str, ...] = ()
    condition: str = ALWAYS


SOURCE_CALLS: Dict[str, SourceSpec] = {
    "input": SourceSpec("dữ liệu nhập từ bàn phím"),
    "raw_input": SourceSpec("dữ liệu nhập từ bàn phím"),
    "os.getenv": SourceSpec("biến môi trường", Confidence.MEDIUM, low_signal=True),
    "os.environ.get": SourceSpec("biến môi trường", Confidence.MEDIUM, low_signal=True),
    "sys.stdin.read": SourceSpec("luồng nhập chuẩn"),
    "sys.stdin.readline": SourceSpec("luồng nhập chuẩn"),
    "sys.stdin.readlines": SourceSpec("luồng nhập chuẩn"),
    "flask.request.args.get": SourceSpec("tham số truy vấn HTTP"),
    "flask.request.form.get": SourceSpec("trường form HTTP"),
    "flask.request.values.get": SourceSpec("giá trị trong request HTTP"),
    "flask.request.headers.get": SourceSpec("header HTTP"),
    "flask.request.cookies.get": SourceSpec("cookie HTTP"),
    "flask.request.get_json": SourceSpec("body JSON của request HTTP"),
    "flask.request.get_data": SourceSpec("body của request HTTP"),
    "urllib.request.urlopen": SourceSpec("phản hồi HTTP từ xa", Confidence.MEDIUM),
    "requests.get": SourceSpec("phản hồi HTTP từ xa", Confidence.MEDIUM),
    "requests.post": SourceSpec("phản hồi HTTP từ xa", Confidence.MEDIUM),
    "requests.request": SourceSpec("phản hồi HTTP từ xa", Confidence.MEDIUM),
    "socket.socket.recv": SourceSpec("socket mạng"),
    "argparse.ArgumentParser.parse_args": SourceSpec(
        "tham số dòng lệnh", Confidence.MEDIUM, low_signal=True
    ),
    "fastapi.Query": SourceSpec("tham số truy vấn HTTP"),
    "fastapi.Body": SourceSpec("body của request HTTP"),
    "fastapi.Form": SourceSpec("trường form HTTP"),
    "fastapi.Header": SourceSpec("header HTTP"),
    "fastapi.Cookie": SourceSpec("cookie HTTP"),
    "fastapi.Path": SourceSpec("tham số đường dẫn HTTP"),
}

SOURCE_ATTRIBUTES: Dict[str, SourceSpec] = {
    "sys.argv": SourceSpec("tham số dòng lệnh", Confidence.MEDIUM, low_signal=True),
    "os.environ": SourceSpec("biến môi trường", Confidence.MEDIUM, low_signal=True),
    "flask.request": SourceSpec("request HTTP"),
    "django.http.HttpRequest": SourceSpec("request HTTP"),
}

REQUEST_RECEIVER_NAMES: FrozenSet[str] = frozenset(
    {
        "request",
        "req",
        "http_request",
        "incoming",
        "flask.request",
        "self.request",
        "starlette.requests.Request",
    }
)

REQUEST_MEMBERS: Dict[str, SourceSpec] = {
    "args": SourceSpec("tham số truy vấn HTTP"),
    "form": SourceSpec("trường form HTTP"),
    "files": SourceSpec("tệp tải lên qua HTTP"),
    "values": SourceSpec("giá trị trong request HTTP"),
    "json": SourceSpec("body JSON của request HTTP"),
    "data": SourceSpec("body của request HTTP"),
    "body": SourceSpec("body của request HTTP"),
    "headers": SourceSpec("header HTTP"),
    "cookies": SourceSpec("cookie HTTP"),
    "query_params": SourceSpec("tham số truy vấn HTTP"),
    "path_params": SourceSpec("tham số đường dẫn HTTP"),
    "GET": SourceSpec("tham số truy vấn HTTP"),
    "POST": SourceSpec("trường form HTTP"),
    "COOKIES": SourceSpec("cookie HTTP"),
    "META": SourceSpec("header HTTP"),
    "FILES": SourceSpec("tệp tải lên qua HTTP"),
    "query_string": SourceSpec("query string HTTP"),
    "url": SourceSpec("URL của request HTTP"),
    "path": SourceSpec("đường dẫn của request HTTP"),
    "full_path": SourceSpec("đường dẫn của request HTTP"),
    "stream": SourceSpec("body của request HTTP"),
}

REQUEST_METHODS: Dict[str, SourceSpec] = {
    "get_json": SourceSpec("body JSON của request HTTP"),
    "get_data": SourceSpec("body của request HTTP"),
    "read_body": SourceSpec("body của request HTTP"),
    "get_argument": SourceSpec("tham số truy vấn HTTP"),
    "get_arguments": SourceSpec("tham số truy vấn HTTP"),
}

# Code thật hầu như không gọi socket.recv() trực tiếp từ lớp mà qua một biến
# giữ kết nối, nên khớp theo tên phương thức trên mọi receiver. Đọc từ socket
# là dữ liệu từ bên ngoài dù nó đi qua biến, nên chỉ tin mức medium: kết nối
# nội bộ giữa hai dịch vụ của chính mình không nhất thiết là không tin cậy.
SOCKET_READ_METHODS: Dict[str, SourceSpec] = {
    "recv": SourceSpec("socket mạng", Confidence.MEDIUM),
    "recvfrom": SourceSpec("socket mạng", Confidence.MEDIUM),
    "recv_into": SourceSpec("socket mạng", Confidence.MEDIUM),
    "recvmsg": SourceSpec("socket mạng", Confidence.MEDIUM),
    "recvmsg_into": SourceSpec("socket mạng", Confidence.MEDIUM),
}

HANDLER_METHODS: Dict[str, SourceSpec] = {
    "get_argument": SourceSpec("tham số truy vấn HTTP"),
    "get_arguments": SourceSpec("tham số truy vấn HTTP"),
    "get_query_argument": SourceSpec("tham số truy vấn HTTP"),
    "get_body_argument": SourceSpec("trường form HTTP"),
    "get_secure_cookie": SourceSpec("cookie HTTP"),
}

ROUTE_DECORATOR_ATTRIBUTES: FrozenSet[str] = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "websocket",
        "api_route",
        "endpoint",
        "expose",
        "task",
    }
)

ROUTE_DECORATOR_RECEIVERS: FrozenSet[str] = frozenset(
    {"app", "router", "api", "blueprint", "bp", "application", "server", "web", "celery"}
)

HANDLER_PARAMETER_NAMES: FrozenSet[str] = frozenset({"event", "payload", "body", "message"})

HANDLER_FUNCTION_NAMES: FrozenSet[str] = frozenset(
    {"lambda_handler", "handler", "handle", "main_handler", "on_message", "process_event"}
)

_ALL_CATEGORIES: FrozenSet[Category] = frozenset(Category)

SANITIZERS: Dict[str, FrozenSet[Category]] = {
    "shlex.quote": frozenset({Category.COMMAND}),
    "shlex.join": frozenset({Category.COMMAND}),
    "pipes.quote": frozenset({Category.COMMAND}),
    "int": _ALL_CATEGORIES,
    "float": _ALL_CATEGORIES,
    "complex": _ALL_CATEGORIES,
    "bool": _ALL_CATEGORIES,
    "len": _ALL_CATEGORIES,
    "ord": _ALL_CATEGORIES,
    "abs": _ALL_CATEGORIES,
    "round": _ALL_CATEGORIES,
    "hash": _ALL_CATEGORIES,
    "uuid.UUID": _ALL_CATEGORIES,
    "decimal.Decimal": _ALL_CATEGORIES,
    "ipaddress.ip_address": _ALL_CATEGORIES,
    "ipaddress.ip_network": _ALL_CATEGORIES,
    "ipaddress.ip_interface": _ALL_CATEGORIES,
    "datetime.datetime.fromisoformat": _ALL_CATEGORIES,
    "html.escape": frozenset({Category.MARKUP}),
    "cgi.escape": frozenset({Category.MARKUP}),
    "markupsafe.escape": frozenset({Category.MARKUP}),
    "django.utils.html.escape": frozenset({Category.MARKUP}),
    "urllib.parse.quote": frozenset({Category.MARKUP}),
    "urllib.parse.quote_plus": frozenset({Category.MARKUP}),
    "ldap.filter.escape_filter_chars": frozenset({Category.LDAP}),
    "ldap3.utils.conv.escape_filter_chars": frozenset({Category.LDAP}),
    "os.path.basename": frozenset({Category.PATH}),
    "werkzeug.utils.secure_filename": frozenset({Category.PATH}),
    "secure_filename": frozenset({Category.PATH}),
}

TRUSTED_PRODUCERS: FrozenSet[str] = frozenset(
    {
        "pickle.dumps",
        "pickle.dump",
        "cPickle.dumps",
        "_pickle.dumps",
        "dill.dumps",
        "marshal.dumps",
        "json.dumps",
        "jsonpickle.encode",
        "yaml.dump",
        "yaml.safe_dump",
        "yaml.dump_all",
        "numpy.save",
        "torch.save",
        "joblib.dump",
    }
)

WEAK_SANITIZERS: Dict[str, FrozenSet[Category]] = {
    "MySQLdb.escape_string": frozenset({Category.SQL}),
    "pymysql.escape_string": frozenset({Category.SQL}),
    "pymysql.converters.escape_string": frozenset({Category.SQL}),
    "psycopg2.extensions.adapt": frozenset({Category.SQL}),
    "sqlite3.Connection.escape": frozenset({Category.SQL}),
    "re.escape": frozenset({Category.SQL, Category.COMMAND}),
}

SCALAR_GUARD_METHODS: FrozenSet[str] = frozenset(
    {"isdigit", "isnumeric", "isdecimal", "isalpha", "isalnum", "isidentifier", "isascii"}
)

PROPAGATING_METHODS: FrozenSet[str] = frozenset(
    {
        "format",
        "format_map",
        "join",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "title",
        "capitalize",
        "casefold",
        "replace",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "encode",
        "decode",
        "get",
        "pop",
        "read",
        "readline",
        "readlines",
        "getvalue",
        "copy",
        "values",
        "keys",
        "items",
        "expandtabs",
        "zfill",
        "ljust",
        "rjust",
        "center",
        "removeprefix",
        "removesuffix",
    }
)

# Phương thức mà đối số ĐẦU TIÊN là một khoá tra cứu, không phải dữ liệu chảy
# ra. Kết quả sinh ra từ chính đối tượng được tra, nên vết nhiễm của khoá dừng
# ở đây.
KEYED_LOOKUP_METHODS: FrozenSet[str] = frozenset({"get", "pop", "setdefault"})

PROPAGATING_CALLS: FrozenSet[str] = frozenset(
    {
        "str",
        "bytes",
        "bytearray",
        "repr",
        "format",
        "list",
        "tuple",
        "set",
        "dict",
        "frozenset",
        "sorted",
        "reversed",
        "json.loads",
        "json.load",
        # sqlalchemy.text() bọc một chuỗi câu lệnh; nó KHÔNG làm chuỗi đó an
        # toàn hơn, nhưng cũng không làm nó kém hằng đi. Không nhận ra thì
        # dạng tham số hoá đúng chuẩn -- text("... :id") kèm dict tham số --
        # bị báo là "câu lệnh không phải hằng", tức là báo nhầm vào đúng cách
        # sửa mà chính công cụ này khuyên dùng.
        "sqlalchemy.text",
        "sqlalchemy.sql.text",
        "sqlalchemy.sql.expression.text",
        "ast.literal_eval",
        "base64.b64decode",
        "base64.b64encode",
        "base64.b16decode",
        "base64.b32decode",
        "base64.urlsafe_b64decode",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
        "urllib.parse.parse_qs",
        "urllib.parse.parse_qsl",
        "urllib.parse.urlparse",
        "os.path.join",
        "os.path.normpath",
        "os.path.abspath",
        "os.path.expanduser",
        "pathlib.Path",
        "posixpath.join",
        "ntpath.join",
        "textwrap.dedent",
        "functools.reduce",
        "itertools.chain",
        "copy.copy",
        "copy.deepcopy",
    }
)

_SINK_LIST: Tuple[SinkSpec, ...] = (
    SinkSpec("eval", Category.CODE_EXECUTION, "FSB-EXEC-001", "FSB-EXEC-002", "eval()"),
    SinkSpec("exec", Category.CODE_EXECUTION, "FSB-EXEC-001", "FSB-EXEC-002", "exec()"),
    SinkSpec("execfile", Category.CODE_EXECUTION, "FSB-EXEC-001", "FSB-EXEC-002", "execfile()"),
    SinkSpec("compile", Category.CODE_EXECUTION, "FSB-EXEC-001", "FSB-EXEC-002", "compile()"),
    SinkSpec(
        "builtins.eval", Category.CODE_EXECUTION, "FSB-EXEC-001", "FSB-EXEC-002", "builtins.eval()"
    ),
    SinkSpec(
        "builtins.exec", Category.CODE_EXECUTION, "FSB-EXEC-001", "FSB-EXEC-002", "builtins.exec()"
    ),
    SinkSpec(
        "code.compile_command",
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "code.compile_command()",
    ),
    SinkSpec(
        "code.InteractiveInterpreter.runsource",
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "InteractiveInterpreter.runsource()",
    ),
    SinkSpec(
        "os.system",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "os.system()",
        condition=SHELL_ALWAYS,
    ),
    SinkSpec(
        "os.popen",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "os.popen()",
        condition=SHELL_ALWAYS,
    ),
    SinkSpec(
        "subprocess.getoutput",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "subprocess.getoutput()",
        condition=SHELL_ALWAYS,
    ),
    SinkSpec(
        "subprocess.getstatusoutput",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "subprocess.getstatusoutput()",
        condition=SHELL_ALWAYS,
    ),
    SinkSpec(
        "commands.getoutput",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "commands.getoutput()",
        condition=SHELL_ALWAYS,
    ),
    SinkSpec(
        "asyncio.create_subprocess_shell",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "asyncio.create_subprocess_shell()",
        condition=SHELL_ALWAYS,
    ),
    SinkSpec(
        "subprocess.run",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "subprocess.run()",
        condition=SHELL_KWARG,
    ),
    SinkSpec(
        "subprocess.call",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "subprocess.call()",
        condition=SHELL_KWARG,
    ),
    SinkSpec(
        "subprocess.check_call",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "subprocess.check_call()",
        condition=SHELL_KWARG,
    ),
    SinkSpec(
        "subprocess.check_output",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "subprocess.check_output()",
        condition=SHELL_KWARG,
    ),
    SinkSpec(
        "subprocess.Popen",
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "subprocess.Popen()",
        condition=SHELL_KWARG,
    ),
    SinkSpec(
        "os.execv", Category.COMMAND, "FSB-CMD-002", None, "os.execv()", (0, 1), condition=ARGV
    ),
    SinkSpec(
        "os.execve", Category.COMMAND, "FSB-CMD-002", None, "os.execve()", (0, 1), condition=ARGV
    ),
    SinkSpec(
        "os.execvp", Category.COMMAND, "FSB-CMD-002", None, "os.execvp()", (0, 1), condition=ARGV
    ),
    SinkSpec(
        "os.execl", Category.COMMAND, "FSB-CMD-002", None, "os.execl()", (0, 1, 2), condition=ARGV
    ),
    SinkSpec(
        "os.execlp", Category.COMMAND, "FSB-CMD-002", None, "os.execlp()", (0, 1, 2), condition=ARGV
    ),
    SinkSpec(
        "os.spawnv", Category.COMMAND, "FSB-CMD-002", None, "os.spawnv()", (1, 2), condition=ARGV
    ),
    SinkSpec(
        "os.posix_spawn",
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        "os.posix_spawn()",
        (0, 1),
        condition=ARGV,
    ),
    SinkSpec(
        "asyncio.create_subprocess_exec",
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        "asyncio.create_subprocess_exec()",
        (0, 1),
        condition=ARGV,
    ),
    SinkSpec(
        "pty.spawn", Category.COMMAND, "FSB-CMD-002", None, "pty.spawn()", (0,), condition=ARGV
    ),
    SinkSpec(
        "pickle.loads",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "pickle.loads()",
    ),
    SinkSpec(
        "pickle.load", Category.DESERIALIZATION, "FSB-DESER-001", "FSB-DESER-002", "pickle.load()"
    ),
    SinkSpec(
        "pickle.Unpickler",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "pickle.Unpickler()",
    ),
    SinkSpec(
        "cPickle.loads",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "cPickle.loads()",
    ),
    SinkSpec(
        "_pickle.loads",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "_pickle.loads()",
    ),
    SinkSpec(
        "dill.loads", Category.DESERIALIZATION, "FSB-DESER-001", "FSB-DESER-002", "dill.loads()"
    ),
    SinkSpec(
        "dill.load", Category.DESERIALIZATION, "FSB-DESER-001", "FSB-DESER-002", "dill.load()"
    ),
    SinkSpec(
        "marshal.loads",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "marshal.loads()",
    ),
    SinkSpec(
        "marshal.load",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "marshal.load()",
    ),
    SinkSpec(
        "jsonpickle.decode",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "jsonpickle.decode()",
    ),
    SinkSpec(
        "joblib.load", Category.DESERIALIZATION, "FSB-DESER-001", "FSB-DESER-002", "joblib.load()"
    ),
    SinkSpec(
        "pandas.read_pickle",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "pandas.read_pickle()",
    ),
    SinkSpec(
        "yaml.unsafe_load",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "yaml.unsafe_load()",
    ),
    SinkSpec(
        "yaml.unsafe_load_all",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "yaml.unsafe_load_all()",
    ),
    SinkSpec(
        "yaml.full_load",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "yaml.full_load()",
    ),
    SinkSpec(
        "yaml.load",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "yaml.load()",
        condition=YAML_LOAD,
    ),
    SinkSpec(
        "yaml.load_all",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "yaml.load_all()",
        condition=YAML_LOAD,
    ),
    SinkSpec(
        "numpy.load",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "numpy.load(allow_pickle=True)",
        condition=NUMPY_LOAD,
    ),
    SinkSpec(
        "torch.load",
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "torch.load()",
        condition=TORCH_LOAD,
    ),
    SinkSpec(
        "jinja2.Template", Category.TEMPLATE, "FSB-TMPL-001", "FSB-TMPL-002", "jinja2.Template()"
    ),
    SinkSpec(
        "jinja2.Environment.from_string",
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        "Environment.from_string()",
    ),
    SinkSpec(
        "flask.render_template_string",
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        "render_template_string()",
    ),
    SinkSpec(
        "django.template.Template",
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        "django.template.Template()",
    ),
    SinkSpec(
        "mako.template.Template",
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        "mako.template.Template()",
    ),
    SinkSpec(
        "tornado.template.Template",
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        "tornado.template.Template()",
    ),
    SinkSpec(
        "importlib.import_module",
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "importlib.import_module()",
    ),
    SinkSpec(
        "__import__",
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "__import__()",
    ),
    SinkSpec(
        "importlib.util.spec_from_file_location",
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "spec_from_file_location()",
        (0, 1),
    ),
    SinkSpec(
        "imp.load_source",
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "imp.load_source()",
        (0, 1),
    ),
    SinkSpec(
        "runpy.run_path",
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "runpy.run_path()",
    ),
    SinkSpec(
        "runpy.run_module",
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "runpy.run_module()",
    ),
    SinkSpec(
        "getattr",
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "getattr()",
        (1,),
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "setattr",
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "setattr()",
        (1,),
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "delattr",
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "delattr()",
        (1,),
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "operator.attrgetter",
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "operator.attrgetter()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "operator.methodcaller",
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "operator.methodcaller()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "sqlalchemy.text",
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "sqlalchemy.text()",
        condition=SQL_TEXT,
    ),
    SinkSpec(
        "sqlalchemy.sql.text",
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "sqlalchemy.sql.text()",
        condition=SQL_TEXT,
    ),
    SinkSpec(
        "ldap.filter.filter_format",
        Category.LDAP,
        "FSB-LDAP-001",
        None,
        "bộ lọc LDAP",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "markupsafe.Markup",
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        "Markup()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "flask.Markup", Category.MARKUP, "FSB-XSS-001", None, "Markup()", condition=TAINT_ONLY
    ),
    SinkSpec(
        "django.utils.safestring.mark_safe",
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        "mark_safe()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "lxml.etree.XMLParser",
        Category.XML,
        "FSB-XML-001",
        "FSB-XML-001",
        "XMLParser của lxml",
        (),
        condition=XML_PARSER,
    ),
    # Bốn họ sink mới của 0.2. Chỉ có biến thể tainted: các biến thể "biểu
    # thức không hằng" ( dynamic_rule ) ở đây sẽ bắn vào gần như mọi lời gọi
    # open() hợp lệ của mọi dự án.
    SinkSpec("open", Category.PATH, "FSB-PATH-001", None, "open()", condition=TAINT_ONLY),
    SinkSpec("io.open", Category.PATH, "FSB-PATH-001", None, "open()", condition=TAINT_ONLY),
    SinkSpec(
        "flask.send_file",
        Category.PATH,
        "FSB-PATH-001",
        None,
        "send_file()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "flask.send_from_directory",
        Category.PATH,
        "FSB-PATH-001",
        None,
        "send_from_directory()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "werkzeug.utils.send_file",
        Category.PATH,
        "FSB-PATH-001",
        None,
        "send_file()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "shutil.copy",
        Category.PATH,
        "FSB-PATH-001",
        None,
        "shutil.copy()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "shutil.copyfile",
        Category.PATH,
        "FSB-PATH-001",
        None,
        "shutil.copyfile()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "requests.get", Category.SSRF, "FSB-SSRF-001", None, "requests.get()", condition=TAINT_ONLY
    ),
    SinkSpec(
        "requests.post",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "requests.post()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "requests.put", Category.SSRF, "FSB-SSRF-001", None, "requests.put()", condition=TAINT_ONLY
    ),
    SinkSpec(
        "requests.patch",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "requests.patch()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "requests.delete",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "requests.delete()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "requests.head",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "requests.head()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "requests.request",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "requests.request()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "urllib.request.urlopen",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "urlopen()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "urllib.request.Request",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "urllib.request.Request()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "httpx.get", Category.SSRF, "FSB-SSRF-001", None, "httpx.get()", condition=TAINT_ONLY
    ),
    SinkSpec(
        "httpx.post", Category.SSRF, "FSB-SSRF-001", None, "httpx.post()", condition=TAINT_ONLY
    ),
    SinkSpec(
        "httpx.request",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "httpx.request()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "socket.create_connection",
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "socket.create_connection()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "flask.redirect",
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        "redirect()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "werkzeug.utils.redirect",
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        "redirect()",
        condition=TAINT_ONLY,
    ),
    SinkSpec(
        "django.shortcuts.redirect",
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        "redirect()",
        condition=TAINT_ONLY,
    ),
)

SINKS: Dict[str, SinkSpec] = {spec.qualname: spec for spec in _SINK_LIST}

METHOD_SINKS: Dict[str, SinkSpec] = {
    "execute": SinkSpec(
        "execute", Category.SQL, "FSB-SQL-001", "FSB-SQL-002", "cursor.execute()", condition=SQL_TEXT
    ),
    "executemany": SinkSpec(
        "executemany",
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "cursor.executemany()",
        condition=SQL_TEXT,
    ),
    "executescript": SinkSpec(
        "executescript",
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "cursor.executescript()",
        condition=SQL_TEXT,
    ),
    "execute_sql": SinkSpec(
        "execute_sql",
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "execute_sql()",
        condition=SQL_TEXT,
    ),
    "raw": SinkSpec(
        "raw", Category.SQL, "FSB-SQL-001", "FSB-SQL-002", "queryset.raw()", condition=SQL_TEXT
    ),
    "extra": SinkSpec(
        "extra",
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "queryset.extra()",
        (0,),
        ("where", "select", "tables"),
        condition=SQL_TEXT,
    ),
    "from_string": SinkSpec(
        "from_string",
        Category.TEMPLATE,
        "FSB-TMPL-001",
        None,
        "Environment.from_string()",
        condition=TAINT_ONLY,
    ),
    "xpath": SinkSpec(
        "xpath", Category.XPATH, "FSB-XPATH-001", None, "xpath()", condition=TAINT_ONLY
    ),
    "search_s": SinkSpec(
        "search_s",
        Category.LDAP,
        "FSB-LDAP-001",
        None,
        "bộ lọc tìm kiếm LDAP",
        (2,),
        ("filterstr",),
        condition=TAINT_ONLY,
    ),
    "search_ext_s": SinkSpec(
        "search_ext_s",
        Category.LDAP,
        "FSB-LDAP-001",
        None,
        "bộ lọc tìm kiếm LDAP",
        (2,),
        ("filterstr",),
        condition=TAINT_ONLY,
    ),
    "runsource": SinkSpec(
        "runsource",
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        None,
        "runsource()",
        condition=TAINT_ONLY,
    ),
}

SQL_METHOD_RECEIVER_HINTS: FrozenSet[str] = frozenset(
    {
        "cursor",
        "cur",
        "conn",
        "connection",
        "db",
        "database",
        "session",
        "engine",
        "client",
        "sql",
        "tx",
        "transaction",
    }
)

SAFE_YAML_LOADERS: FrozenSet[str] = frozenset(
    {
        "SafeLoader",
        "CSafeLoader",
        "BaseLoader",
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.BaseLoader",
    }
)

XML_UNSAFE_KEYWORDS: Dict[str, bool] = {
    "resolve_entities": True,
    "load_dtd": True,
    "no_network": False,
    "huge_tree": True,
}

# Mọi nhánh ở đây đều có khoảng trống BỊ CHẶN ( \w+, \s+ giữa hai từ khóa cố
# định ), nên thời gian quét tuyến tính theo độ dài - kể cả trên payload thù
# địch. Nhánh `select ... from` KHÔNG nằm ở đây: xem _SELECT_OR_FROM.
SQL_STATEMENT = re.compile(
    r"(?is)\b(?:insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b|"
    r"create\s+(?:table|view|index)\b|drop\s+(?:table|view|database)\b|alter\s+table\b|"
    r"union\s+(?:all\s+)?select\b|truncate\s+table\b|merge\s+into\b|with\s+\w+\s+as\s*\()"
)

# Nhánh `select ... from` không viết thành regex. `select\s+.+?\bfrom\b` là
# lazy dot-star: trên chuỗi vài MB có "select" mà không có "from", nó quét lại
# phần đuôi ở mỗi vị trí select, tức là bậc hai.
#
# Cắt cụt đầu vào thì hết treo nhưng sinh âm tính giả, vì một câu SELECT liệt
# kê 40 cột đã dài hơn 600 ký tự trước khi tới FROM. Thay vào đó là quét một
# lượt các từ khoá như token: alternation của hai chuỗi cố định không có gì để
# quay lui, đo được 0,25 giây cho 2 MB payload thù địch.
_SELECT_OR_FROM = re.compile(r"(?i)\b(select|from)\b")

# Chặn trên cho MỘT lần gọi. Tuyến tính rồi thì đây chỉ là lưới an toàn cuối
# ( ~1ms ở mức này ), và đủ rộng để không câu SQL thật nào chạm tới.
SQL_HINT_WINDOW = 8192


def _has_select_from(text: str) -> bool:
    """Có `select` đứng trước `from` không - một lượt quét, không quay lui."""
    seen_select = False
    for match in _SELECT_OR_FROM.finditer(text):
        if match.group(1)[0] in "sS":
            seen_select = True
        elif seen_select:
            return True
    return False


def looks_like_sql(text: str, spend: Optional[Callable[[int], None]] = None) -> bool:
    window = text[:SQL_HINT_WINDOW]
    if spend is not None:
        # Chi phí tuyến tính theo độ dài đã quét: chặn số LẦN gọi trên một tệp
        # dày đặc payload, phần bù cho chặn trên độ lớn của SQL_HINT_WINDOW.
        spend(2 + len(window) // 8)
    return bool(SQL_STATEMENT.search(window)) or _has_select_from(window) or _is_jdbc_call(window)


def _is_jdbc_call(text: str) -> bool:
    """Cú pháp escape gọi thủ tục của JDBC: `{call proc(?)}`, `{?= call f(?)}`."""
    compact = text.lstrip().lower().replace(" ", "")
    return compact.startswith(("{call", "{?=call"))


NOSQL_OPERATOR_KEYS: FrozenSet[str] = frozenset({"$where", "$expr", "$function", "$accumulator"})
