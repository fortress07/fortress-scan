"""Elixir: Phoenix, Plug, LiveView, Ecto.

Ba điều khác hẳn các ngôn ngữ họ C:

* `{` `}` là tuple và map, còn khối lệnh là `do ... end`; tham số request đến
  qua mẫu khớp ở đầu hàm ( `def show(conn, %{"id" => id})` ), nên vết nhiễm
  gắn theo thân `do ... end` của đúng hàm đó;
* `a |> f(b)` là `f(a, b)`: sink nhận giá trị đi qua pipe ở đối số đầu;
* sigil ( `~s(...)`, `~r/.../` ) là chuỗi, và chỉ dạng chữ thường mới nội suy.

`redirect(conn, to: p)` của Phoenix tự từ chối URL ngoài, nên chỉ
`external:` là sink chuyển hướng.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

from ...core.model import Category, Confidence
from ...languages import ELIXIR
from .lexer import LexerProfile
from .profiles import (
    _ALL_CATEGORIES,
    _URI_COMPONENT,
    COMMAND_LINE_ARG,
    ENVIRONMENT_VARIABLE,
    HTTP_COOKIE,
    HTTP_HEADER,
    PATH_PARAM,
    QUERY_PARAM,
    QUERY_STRING,
    REQUEST_BODY,
    REQUEST_PARAM,
    SINK_EVAL,
    SINK_FILE_PATH,
    SINK_OBJECT_DESERIALIZER,
    SINK_OUTBOUND_URL,
    SINK_PROCESS_SPAWN,
    SINK_RAW_HTML,
    SINK_REDIRECT,
    SINK_SHELL_COMMAND,
    SINK_SQL_QUERY,
    SINK_TEMPLATE_COMPILER,
    STANDARD_INPUT,
    GenericSink,
    LanguageSpec,
)

_PATH_ONLY: FrozenSet[Category] = frozenset({Category.PATH})

_ELIXIR_LEXER = LexerProfile(
    line_comments=("#",),
    block_comments=(),
    # Nháy kép là chuỗi, nháy đơn là charlist; cả hai đều nội suy `#{}`.
    plain_quotes=(),
    interpolating_quotes=('"', "'"),
    interpolation_markers=(("#{", "}"),),
    identifier_extra="_",
    triple_quotes=(('"""', True), ("'''", True)),
    sigils=True,
    question_char_literals=True,
    identifier_suffixes="?!",
    multichar_operators=(
        "===",
        "!==",
        "|>",
        "<>",
        "<-",
        "->",
        "=>",
        "==",
        "!=",
        "=~",
        "<=",
        ">=",
        "&&",
        "||",
        "::",
        "++",
        "--",
        "..",
        "\\\\",
        "<<",
        ">>",
    ),
)

_ELIXIR_SOURCES: Dict[str, str] = {
    # Plug.Conn
    "conn.params": REQUEST_PARAM,
    "conn.query_params": QUERY_PARAM,
    "conn.body_params": REQUEST_BODY,
    "conn.path_params": PATH_PARAM,
    "conn.query_string": QUERY_STRING,
    "conn.req_headers": HTTP_HEADER,
    "conn.cookies": HTTP_COOKIE,
    "conn.req_cookies": HTTP_COOKIE,
    "get_req_header": HTTP_HEADER,
    "Plug.Conn.get_req_header": HTTP_HEADER,
    "Conn.get_req_header": HTTP_HEADER,
    "read_body": REQUEST_BODY,
    "Plug.Conn.read_body": REQUEST_BODY,
    "Conn.read_body": REQUEST_BODY,
    "IO.gets": STANDARD_INPUT,
    "IO.read": STANDARD_INPUT,
}

_ELIXIR_LOW_SIGNAL: Dict[str, str] = {
    "System.get_env": ENVIRONMENT_VARIABLE,
    "System.fetch_env": ENVIRONMENT_VARIABLE,
    "System.fetch_env!": ENVIRONMENT_VARIABLE,
    "System.argv": COMMAND_LINE_ARG,
}

_FILE_FUNCTIONS: Tuple[str, ...] = tuple(
    "File.%s" % name
    for name in (
        "read",
        "read!",
        "write",
        "write!",
        "open",
        "open!",
        "stream!",
        "rm",
        "rm!",
        "rm_rf",
        "rm_rf!",
        "mkdir_p",
        "mkdir_p!",
        "ls",
        "ls!",
        "chmod",
        "chmod!",
    )
)

_ELIXIR_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        # `:os.cmd/1` và `System.shell/1` đưa cả chuỗi cho /bin/sh.
        ("os.cmd", "System.shell"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        # `System.cmd(prog, args)` chạy thẳng chương trình, không qua shell,
        # trừ khi chính chương trình là `sh -c`.
        ("System.cmd", "MuonTrap.cmd"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        program_position=True,
    ),
    GenericSink(
        ("Repo.query", "Repo.query!", "Repo.query_many", "Repo.query_many!"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        # Đối số đầu là repo hay kết nối, câu SQL đứng thứ hai.
        (
            "SQL.query",
            "SQL.query!",
            "SQL.query_many",
            "SQL.stream",
            "Postgrex.query",
            "Postgrex.query!",
            "MyXQL.query",
            "MyXQL.query!",
            "Sqlite3.execute",
            "Sqlite3.prepare",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        argument_index=1,
        require_sql=True,
    ),
    GenericSink(
        ("Code.eval_string", "Code.compile_string"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        # AST dựng trong macro là chuyện thường ngày của Elixir: chỉ báo khi
        # dữ liệu ngoài tới được.
        ("Code.eval_quoted", "Code.eval_quoted_with_env", "Code.compile_quoted"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        None,
        SINK_EVAL,
    ),
    GenericSink(
        ("Code.eval_file", "Code.require_file", "Code.compile_file"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        None,
        "việc nạp và chạy một tệp mã Elixir",
    ),
    GenericSink(
        # `EEx.compile_string` chỉ dựng AST, không chạy gì.
        ("EEx.eval_string",),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        SINK_TEMPLATE_COMPILER,
    ),
    GenericSink(
        # `Plug.Crypto.non_executable_binary_to_term` mới là bản an toàn.
        ("erlang.binary_to_term",),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        None,
        SINK_OBJECT_DESERIALIZER,
    ),
    GenericSink(
        _FILE_FUNCTIONS + ("File.cp", "File.cp!", "File.rename", "File.rename!"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        # Đúng module File của Elixir; `Livebook.FileSystem.File.read` là lớp
        # trừu tượng riêng của dự án.
        exact_names=True,
    ),
    GenericSink(
        ("send_file", "Plug.Conn.send_file", "Conn.send_file"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_index=2,
    ),
    GenericSink(
        ("send_download", "Phoenix.Controller.send_download", "Controller.send_download"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_index=1,
        argument_prefix=("{", ":", "file"),
    ),
    GenericSink(
        ("redirect", "Phoenix.Controller.redirect", "Phoenix.LiveView.redirect"),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
        argument_label="external",
    ),
    GenericSink(
        ("raw",),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
        exact_names=True,
    ),
    GenericSink(
        ("Phoenix.HTML.raw", "HTML.raw"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        # `html(conn, body)` của Phoenix gửi body kèm `text/html`.
        ("html",),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
        argument_index=1,
        exact_names=True,
    ),
    GenericSink(
        (
            "HTTPoison.get",
            "HTTPoison.get!",
            "HTTPoison.post",
            "HTTPoison.post!",
            "HTTPoison.put",
            "HTTPoison.put!",
            "HTTPoison.patch",
            "HTTPoison.delete",
            "HTTPoison.head",
            "Req.get",
            "Req.get!",
            "Req.post",
            "Req.post!",
            "Req.put",
            "Req.delete",
            "Req.head",
        ),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("HTTPoison.request", "HTTPoison.request!", "Finch.build"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        argument_index=1,
    ),
    GenericSink(
        # `apply(Mod, String.to_atom(params["f"]), args)` gọi được mọi hàm công
        # khai của module đó.
        ("apply", "Kernel.apply"),
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "tên hàm được gọi động",
        argument_index=1,
    ),
)

_ELIXIR_SPEC = LanguageSpec(
    language=ELIXIR,
    lexer=_ELIXIR_LEXER,
    sources=_ELIXIR_SOURCES,
    sinks=_ELIXIR_SINKS,
    sanitizers={
        "String.to_integer": _ALL_CATEGORIES,
        "String.to_float": _ALL_CATEGORIES,
        "Integer.parse": _ALL_CATEGORIES,
        "Float.parse": _ALL_CATEGORIES,
        "Ecto.UUID.cast": _ALL_CATEGORIES,
        "Ecto.UUID.cast!": _ALL_CATEGORIES,
        "Path.basename": _PATH_ONLY,
        "Path.safe_relative": _PATH_ONLY,
        "Path.safe_relative_to": _PATH_ONLY,
        "URI.encode_www_form": _URI_COMPONENT,
        "html_escape": frozenset({Category.MARKUP}),
        "Phoenix.HTML.html_escape": frozenset({Category.MARKUP}),
        "HTML.html_escape": frozenset({Category.MARKUP}),
        "Plug.HTML.html_escape": frozenset({Category.MARKUP}),
    },
    low_signal_sources=_ELIXIR_LOW_SIGNAL,
    chain_separators=(".",),
    assignment_operators=("=", "<-"),
    argument_labels=True,
    conn_param_patterns=True,
    brace_statements=False,
    pipe_operators=frozenset({"|>"}),
    pattern_assignments=True,
    framework_names=frozenset({"conn", "socket"}),
    callback_parameters={
        # LiveView
        "handle_event": (1,),
        "mount": (0,),
        "handle_params": (0, 1),
        # Channel
        "handle_in": (1,),
        "join": (0, 1),
    },
    value_wrappers=frozenset({"String.to_charlist", "to_charlist"}),
    attribute_constants=True,
)

ELIXIR_SPECS: Dict[str, LanguageSpec] = {ELIXIR: _ELIXIR_SPEC}
