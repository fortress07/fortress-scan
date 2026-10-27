"""Swift và Dart: ứng dụng di động cùng máy chủ viết bằng hai ngôn ngữ đó.

Swift chạy trên iOS / macOS và máy chủ Vapor, Hummingbird, Kitura. Dart chạy
Flutter và máy chủ shelf, Dart Frog, dart:io.

Hai điều khác hẳn các ngôn ngữ họ C:

* đối số mang nhãn ( `execute(sql: q)`, `contents(atPath: p)` ): nhãn là cú
  pháp, và chính nó cho biết đối số nào là câu SQL hay đường dẫn;
* nội suy `"\\(x)"` có thể mang nhãn bind: `\\(bind: x)` của SQLKit được tham số
  hoá, còn `db.execute(literal: "...\\(x)")` của GRDB thì bind mọi phần nội suy.

Ở phía app, dữ liệu bên ngoài là deep link ( `open url: URL`,
`URLContexts`, `userActivity.webpageURL` ) và tin nhắn JavaScript từ WebView.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

from ...core.model import Category, Confidence
from ...languages import DART, SWIFT
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

REQUEST_PATH = "đường dẫn của request HTTP"
DEEP_LINK = "URL deep link ( app khác hay trang web mở được )"
WEBVIEW_MESSAGE = "tin nhắn JavaScript từ WebView"

_PATH_ONLY: FrozenSet[Category] = frozenset({Category.PATH})

_SWIFT_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    # Swift không có nháy đơn: ký tự cũng viết bằng nháy kép.
    plain_quotes=(),
    interpolating_quotes=('"',),
    interpolation_markers=(("\\(", ")"),),
    identifier_extra="_",
    triple_quotes=(('"""', True),),
    multichar_operators=(
        "===",
        "!==",
        "...",
        "..<",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "??",
        "?.",
        "!.",
        "->",
        "+=",
        "-=",
        "*=",
        "/=",
    ),
)

_SWIFT_SOURCES: Dict[str, str] = {
    # Vapor
    "req.query": QUERY_PARAM,
    "req.parameters": PATH_PARAM,
    "req.content": REQUEST_BODY,
    "req.body": REQUEST_BODY,
    "req.headers": HTTP_HEADER,
    "req.cookies": HTTP_COOKIE,
    "req.url": REQUEST_PATH,
    # Hummingbird
    "request.uri.queryParameters": QUERY_PARAM,
    "context.parameters": PATH_PARAM,
    # Kitura
    "request.queryParameters": QUERY_PARAM,
    "request.parameters": REQUEST_PARAM,
    "request.readString": REQUEST_BODY,
    # App: deep link, universal link, cầu nối JavaScript.
    "URLContexts": DEEP_LINK,
    "connectionOptions.urlContexts": DEEP_LINK,
    "userActivity.webpageURL": DEEP_LINK,
    "message.body": WEBVIEW_MESSAGE,
    "readLine": STANDARD_INPUT,
}

_SWIFT_LOW_SIGNAL: Dict[str, str] = {
    "CommandLine.arguments": COMMAND_LINE_ARG,
    "ProcessInfo.processInfo.environment": ENVIRONMENT_VARIABLE,
}

_SWIFT_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        # `system()` không dùng được trên nền tảng Apple, còn `.system(...)` của
        # SwiftUI ( `Font.system(size:)` ) thì ở khắp nơi: chỉ nhận `popen` trần.
        ("popen",),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
        exact_names=True,
    ),
    GenericSink(
        ("Process.launchedProcess",),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        argument_label="launchPath",
    ),
    GenericSink(
        # SQLite C API: câu lệnh là đối số thứ hai.
        ("sqlite3_exec", "sqlite3_prepare_v2", "sqlite3_prepare_v3", "sqlite3_prepare", "sqlite3_prepare16_v2"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        argument_index=1,
        require_sql=True,
    ),
    GenericSink(
        # GRDB: `db.execute(sql: q)`, `Row.fetchAll(db, sql: q)`. Bản `literal:` tự bind.
        ("execute", "fetchAll", "fetchOne", "fetchCursor", "fetchSet", "makeStatement", "cachedStatement"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
        argument_label="sql",
    ),
    GenericSink(
        # FMDB và SQLite.swift: câu lệnh là đối số đầu, không nhãn.
        ("executeQuery", "executeUpdate", "executeStatements", "db.run", "db.execute", "db.prepare", "db.scalar"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        # SQLKit của Vapor: `\(bind: x)` được bind, `\(unsafeRaw: x)` và `\(x)` thì không.
        ("db.raw", "sql.raw", "database.raw", "SQLRawBuilder", "SQLQueryString"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        # `NSPredicate(format: "name == '\(x)'")`: chuỗi định dạng là cả câu truy vấn
        # Core Data; giá trị phải đi qua `%@`.
        ("NSPredicate",),
        Category.NOSQL,
        "FSB-NOSQL-001",
        None,
        "chuỗi định dạng NSPredicate",
        argument_label="format",
    ),
    GenericSink(
        ("NSExpression",),
        Category.EXPRESSION_LANGUAGE,
        "FSB-EL-001",
        None,
        "chuỗi định dạng NSExpression",
        argument_label="format",
    ),
    GenericSink(
        ("evaluateScript", "JSContext.evaluateScript"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
    ),
    GenericSink(
        ("NSAppleScript",),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "một AppleScript",
        argument_label="source",
    ),
    GenericSink(
        ("contents", "removeItem", "createFile", "copyItem", "moveItem", "contentsOfDirectory", "createDirectory"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_label="atPath",
    ),
    GenericSink(
        ("String", "NSString", "NSData", "NSDictionary", "NSArray"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_label="contentsOfFile",
    ),
    GenericSink(
        ("URL", "NSURL"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_label="fileURLWithPath",
    ),
    GenericSink(
        ("FileHandle",),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_label="forReadingAtPath",
    ),
    GenericSink(
        ("FileHandle", "FileManager.default.createFile"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_label="forWritingAtPath",
    ),
    GenericSink(
        ("appendingPathComponent", "appendPathComponent"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        # Vapor: `req.fileio.streamFile(at: path)`.
        ("streamFile", "readFile", "collectFile"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_label="at",
    ),
    GenericSink(
        ("redirect",),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
        argument_label="to",
    ),
    GenericSink(
        ("client.get", "client.post", "client.put", "client.delete", "client.patch", "client.send", "AF.request", "Alamofire.request", "AF.download"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("dataTask", "downloadTask", "uploadTask", "dataTaskPublisher"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        argument_label="with",
    ),
    GenericSink(
        ("URLSession.shared.data", "session.data", "URLSession.shared.download", "session.download"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        argument_label="from",
    ),
    GenericSink(
        ("loadHTMLString",),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        ("evaluateJavaScript", "callAsyncJavaScript", "stringByEvaluatingJavaScript"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        "JavaScript chạy trong WebView",
    ),
    GenericSink(
        ("NSKeyedUnarchiver.unarchiveObject", "NSKeyedUnarchiver.unarchiveTopLevelObjectWithData", "NSUnarchiver.unarchiveObject"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        None,
        SINK_OBJECT_DESERIALIZER,
    ),
    GenericSink(
        # Stencil: template dựng từ chuỗi của người dùng.
        ("Template", "Environment.renderTemplate"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        None,
        SINK_TEMPLATE_COMPILER,
        argument_label="templateString",
    ),
)

_SWIFT_SPEC = LanguageSpec(
    language=SWIFT,
    lexer=_SWIFT_LEXER,
    sources=_SWIFT_SOURCES,
    sinks=_SWIFT_SINKS,
    assignment_sinks={
        # let p = Process(); p.executableURL = ...; p.arguments = [...]
        "launchPath": ("FSB-CMD-002", Category.COMMAND, "chương trình mà Process chạy"),
        "executableURL": ("FSB-CMD-002", Category.COMMAND, "chương trình mà Process chạy"),
        "arguments": ("FSB-CMD-002", Category.COMMAND, "đối số của Process"),
    },
    sanitizers={
        "Int": _ALL_CATEGORIES,
        "Int32": _ALL_CATEGORIES,
        "Int64": _ALL_CATEGORIES,
        "UInt": _ALL_CATEGORIES,
        "Double": _ALL_CATEGORIES,
        "Bool": _ALL_CATEGORIES,
        "UUID": _ALL_CATEGORIES,
    },
    postfix_sanitizers={
        "lastPathComponent": _PATH_ONLY,
        "addingPercentEncoding": _URI_COMPONENT,
    },
    low_signal_sources=_SWIFT_LOW_SIGNAL,
    declaration_keywords=frozenset({"let", "var"}),
    chain_separators=(".", "?.", "!."),
    annotation_separator=":",
    assignment_operators=("=", "+="),
    argument_labels=True,
    bound_argument_labels=frozenset({"literal"}),
    bound_interpolation_labels=frozenset({"bind", "binds", "literal", "ident", "idents"}),
    parameter_label_sources={"open": DEEP_LINK, "openURL": DEEP_LINK},
)

# ----------------------------------------------------------------------- Dart

_DART_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    # Cả hai loại nháy đều nội suy `$x` / `${x}`; `r'...'` thì không.
    plain_quotes=(),
    interpolating_quotes=("'", '"'),
    interpolation_markers=(("${", "}"),),
    dollar_interpolation=True,
    dollar_bare_name=True,
    identifier_extra="_",
    triple_quotes=(('"""', True), ("'''", True)),
    string_prefixes=(("r", False),),
    multichar_operators=(
        "...?",
        "...",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "??=",
        "??",
        "?.",
        "=>",
        "+=",
        "-=",
        "*=",
        "/=",
        "~/",
    ),
)

_DART_SOURCES: Dict[str, str] = {
    # dart:io HttpServer và shelf
    "request.uri.queryParameters": QUERY_PARAM,
    "request.uri.queryParametersAll": QUERY_PARAM,
    "request.url.queryParameters": QUERY_PARAM,
    "request.requestedUri.queryParameters": QUERY_PARAM,
    "request.readAsString": REQUEST_BODY,
    "request.params": PATH_PARAM,
    "request.headers": HTTP_HEADER,
    "request.cookies": HTTP_COOKIE,
    # Dart Frog
    "context.request.uri.queryParameters": QUERY_PARAM,
    "context.request.body": REQUEST_BODY,
    "context.request.json": REQUEST_BODY,
    "context.request.formData": REQUEST_BODY,
    "context.request.headers": HTTP_HEADER,
    # Flutter: deep link qua go_router, app_links, uni_links, và trang web.
    "state.uri.queryParameters": DEEP_LINK,
    "state.pathParameters": DEEP_LINK,
    "state.queryParameters": DEEP_LINK,
    "state.extra": DEEP_LINK,
    "getInitialLink": DEEP_LINK,
    "getInitialUri": DEEP_LINK,
    "appLinks.getInitialLink": DEEP_LINK,
    "appLinks.getInitialAppLink": DEEP_LINK,
    "Uri.base.queryParameters": QUERY_PARAM,
    "Uri.base.fragment": QUERY_PARAM,
    # webview_flutter JavaScriptChannel
    "message.message": WEBVIEW_MESSAGE,
    "stdin.readLineSync": STANDARD_INPUT,
}

_DART_LOW_SIGNAL: Dict[str, str] = {
    "Platform.environment": ENVIRONMENT_VARIABLE,
}

_DART_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("Process.run", "Process.runSync", "Process.start"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        program_position=True,
        shell_option_label="runInShell",
    ),
    GenericSink(
        # sqflite, drift, sqlite3, postgres, mysql1
        (
            "rawQuery",
            "rawInsert",
            "rawUpdate",
            "rawDelete",
            "customSelect",
            "customStatement",
            "customUpdate",
            "customInsert",
            "db.execute",
            "database.execute",
            "connection.execute",
            "connection.query",
            "conn.query",
            "conn.execute",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("File", "Directory", "Link", "io.File"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        (
            "http.get",
            "http.post",
            "http.put",
            "http.delete",
            "http.head",
            "http.read",
            "http.patch",
            "getUrl",
            "postUrl",
            "openUrl",
            "dio.get",
            "dio.post",
            "dio.request",
            "Dio.get",
            "client.get",
            "client.post",
        ),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("Response.found", "Response.movedPermanently", "Response.seeOther", "response.redirect"),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
    GenericSink(
        ("loadHtmlString", "Element.html"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        ("runJavaScript", "runJavaScriptReturningResult", "runJavascript", "evaluateJavascript", "evalJavascript"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        "JavaScript chạy trong WebView",
    ),
    GenericSink(
        ("Isolate.spawnUri",),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp mã Dart từ một URI",
    ),
)

_DART_SPEC = LanguageSpec(
    language=DART,
    lexer=_DART_LEXER,
    sources=_DART_SOURCES,
    sinks=_DART_SINKS,
    assignment_sinks={
        "innerHtml": ("FSB-XSS-001", Category.MARKUP, "innerHtml"),
    },
    sanitizers={
        "int.parse": _ALL_CATEGORIES,
        "int.tryParse": _ALL_CATEGORIES,
        "double.parse": _ALL_CATEGORIES,
        "double.tryParse": _ALL_CATEGORIES,
        "num.parse": _ALL_CATEGORIES,
        "Uri.encodeComponent": _URI_COMPONENT,
        "Uri.encodeQueryComponent": _URI_COMPONENT,
        "htmlEscape.convert": frozenset({Category.MARKUP}),
        "HtmlEscape.convert": frozenset({Category.MARKUP}),
        "basename": _PATH_ONLY,
        "p.basename": _PATH_ONLY,
        "path.basename": _PATH_ONLY,
    },
    low_signal_sources=_DART_LOW_SIGNAL,
    declaration_keywords=frozenset({"var", "final", "const", "late"}),
    chain_separators=(".", "?."),
    assignment_operators=("=", "+=", "??="),
    argument_labels=True,
    receiver_propagators=frozenset({"write", "writeAll", "writeln"}),
    builder_constructors=frozenset({"StringBuffer"}),
    value_accessors=frozenset({"toString"}),
    value_wrappers=frozenset(
        {"Sql", "Sql.named", "Sql.indexed", "StatementInfo", "Uri.parse", "Uri.tryParse", "Uri.file", "Uri.directory"}
    ),
)

MOBILE_SPECS: Dict[str, LanguageSpec] = {
    SWIFT: _SWIFT_SPEC,
    DART: _DART_SPEC,
}
