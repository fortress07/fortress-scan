"""Ngôn ngữ ứng dụng thêm sau Java: Kotlin, Scala, Groovy.

Dùng chung bộ phân tích token với các ngôn ngữ trong profiles.py; tệp này chỉ
khai cú pháp chuỗi, nguồn, sink và bộ khử độc riêng của từng ngôn ngữ. Ba ngôn
ngữ JVM ở đây dùng lại nguyên bảng sink của Java ( JDBC, Servlet, Spring, tệp,
URL ) vì chúng gọi đúng những thư viện đó.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

from ...core.model import Category, Confidence
from ...languages import GROOVY, KOTLIN, SCALA
from .lexer import LexerProfile
from .profiles import (
    _ALL_CATEGORIES,
    _ANDROID_SOURCES,
    _HTML_ONLY,
    _JAVA_ANNOTATIONS,
    _JAVA_SINKS,
    _JAVA_SOURCES,
    _JVM_BUILDERS,
    _JVM_LOW_SIGNAL,
    _JVM_POSTFIX_SANITIZERS,
    _JVM_SANITIZERS,
    _JVM_SINKS,
    _SPRING_HANDLERS,
    _SPRING_NOT_REQUEST,
    _WEBFLUX_SOURCES,
    FORM_FIELD,
    HTTP_COOKIE,
    HTTP_HEADER,
    PATH_PARAM,
    QUERY_PARAM,
    QUERY_STRING,
    REQUEST_BODY,
    REQUEST_PARAM,
    SINK_EVAL,
    SINK_OUTBOUND_URL,
    SINK_PROCESS_SPAWN,
    SINK_RAW_HTML,
    SINK_REDIRECT,
    SINK_SHELL_COMMAND,
    SINK_SQL_QUERY,
    SINK_TEMPLATE_COMPILER,
    GenericSink,
    LanguageSpec,
)

REQUEST_PATH = "đường dẫn của request HTTP"

# --------------------------------------------------------------------- Kotlin

_KOTLIN_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("${", "}"),),
    dollar_interpolation=True,
    dollar_bare_name=True,
    identifier_extra="_",
    # Tên bọc backtick ( `fun \`tra ve 404\`()` ) là định danh, không phải chuỗi
    # lệnh như ở shell. Đọc nó như một khối nguyên văn để dấu nháy bên trong
    # không mở chuỗi giả.
    raw_quotes=("`",),
    triple_quotes=(('"""', True),),
    multichar_operators=(
        "===",
        "!==",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "?.",
        "?:",
        "!!",
        "::",
        "->",
        "..<",
        "..",
        "+=",
        "-=",
        "*=",
        "/=",
        "++",
        "--",
    ),
)

_KTOR_SOURCES: Dict[str, str] = {
    "call.parameters": REQUEST_PARAM,
    "call.request.queryParameters": QUERY_PARAM,
    "call.request.headers": HTTP_HEADER,
    "call.request.header": HTTP_HEADER,
    "call.request.cookies": HTTP_COOKIE,
    "call.request.uri": REQUEST_PATH,
    "call.request.path": REQUEST_PATH,
    "call.receiveText": REQUEST_BODY,
    "call.receive": REQUEST_BODY,
    "call.receiveParameters": FORM_FIELD,
    "call.receiveMultipart": REQUEST_BODY,
    "call.receiveChannel": REQUEST_BODY,
}

_KOTLIN_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        # Exposed: `exec("SELECT ... $id")` trong một transaction.
        ("exec", "TransactionManager.current.exec"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("respondRedirect",),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
)

_KOTLIN_SPEC = LanguageSpec(
    language=KOTLIN,
    lexer=_KOTLIN_LEXER,
    sources={**_JAVA_SOURCES, **_ANDROID_SOURCES, **_WEBFLUX_SOURCES, **_KTOR_SOURCES},
    sinks=_JAVA_SINKS + _JVM_SINKS + _KOTLIN_SINKS,
    sanitizers=_JVM_SANITIZERS,
    low_signal_sources=_JVM_LOW_SIGNAL,
    declaration_keywords=frozenset({"val", "var"}),
    chain_separators=(".", "?."),
    annotation_separator=":",
    annotation_sources=_JAVA_ANNOTATIONS,
    assignment_operators=("=", "+="),
    receiver_propagators=frozenset({"append", "appendLine", "insert"}),
    builder_constructors=_JVM_BUILDERS,
    postfix_sanitizers=_JVM_POSTFIX_SANITIZERS,
    handler_annotations=_SPRING_HANDLERS,
    handler_parameter_types=frozenset({"String", "CharSequence"}),
    handler_parameter_exclusions=_SPRING_NOT_REQUEST,
    redirect_view_prefix="redirect:",
    value_accessors=frozenset({"toString"}),
    constant_case_names=True,
)

# ---------------------------------------------------------------------- Scala

_SCALA_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("${", "}"),),
    dollar_interpolation=True,
    dollar_bare_name=True,
    identifier_extra="_",
    raw_quotes=("`",),
    triple_quotes=(('"""', True),),
    # Chuỗi thường của Scala không nội suy: `"$x"` là chữ. Chỉ `s"..."`,
    # `f"..."`, `raw"..."` dán giá trị vào chuỗi; `sql"..."` ( Slick, doobie ),
    # `fr"..."` ( doobie ) và `SQL"..."` ( Anorm ) biến chúng thành tham số bind.
    string_prefixes=(
        ("s", True),
        ("f", True),
        ("raw", True),
        ("uri", True),
        ("sql", False),
        ("sqlu", False),
        ("fr", False),
        ("fr0", False),
        ("SQL", False),
        ("cql", False),
    ),
    prefix_only_interpolation=True,
    splice_marker="#$",
    multichar_operators=(
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "=>",
        "<-",
        "->",
        "::",
        "++",
        "+=",
        "-=",
        "!!",
        ":=",
        "#::",
    ),
)

_SCALA_SOURCES: Dict[str, str] = {
    # Play
    "request.getQueryString": QUERY_PARAM,
    "request.queryString": QUERY_PARAM,
    "request.rawQueryString": QUERY_STRING,
    "request.body": REQUEST_BODY,
    "request.headers": HTTP_HEADER,
    "request.cookies": HTTP_COOKIE,
    "request.path": REQUEST_PATH,
    "request.uri": REQUEST_PATH,
    # http4s
    "req.params": QUERY_PARAM,
    "req.multiParams": QUERY_PARAM,
    "req.uri.query": QUERY_PARAM,
    "req.headers": HTTP_HEADER,
    "req.cookies": HTTP_COOKIE,
    "req.bodyText": REQUEST_BODY,
    # Servlet trong Scala
    "request.getParameter": QUERY_PARAM,
    "request.getHeader": HTTP_HEADER,
}

# Directive Akka HTTP / Pekko HTTP đưa giá trị request vào tham số lambda.
_AKKA_DIRECTIVES: Dict[str, str] = {
    "parameter": QUERY_PARAM,
    "parameters": QUERY_PARAM,
    "parameterMap": QUERY_PARAM,
    "formField": FORM_FIELD,
    "formFields": FORM_FIELD,
    "headerValueByName": HTTP_HEADER,
    "optionalHeaderValueByName": HTTP_HEADER,
    "cookie": HTTP_COOKIE,
    "entity": REQUEST_BODY,
    "path": PATH_PARAM,
    "pathPrefix": PATH_PARAM,
    "pathSuffix": PATH_PARAM,
    "extractUri": REQUEST_PATH,
}

_SCALA_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        # sys.process: Process("ls " + d) tách chuỗi theo khoảng trắng rồi chạy,
        # KHÔNG qua shell. Dạng Process(Seq("sh", "-c", c)) mới là lệnh shell
        # ( bắt riêng ).
        ("Process", "sys.process.Process", "scala.sys.process.Process"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        program_position=True,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        # "ping " + host !! / s"ls $d".! : cùng ngữ nghĩa với Process(...).
        ("!", "!!", "lazyLines", "lineStream"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        receiver=True,
    ),
    GenericSink(
        # Anorm SQL("...{id}") an toàn; SQL(s"... $id") thì không.
        ("SQL", "anorm.SQL", "Fragment.const", "Fragment.const0", "spark.sql", "sqlContext.sql", "sparkSession.sql"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("Redirect", "redirect"),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
    GenericSink(
        ("Html", "play.twirl.api.Html", "HtmlFormat.raw"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        (
            "ws.url",
            "wsClient.url",
            "WS.url",
            "basicRequest.get",
            "basicRequest.post",
            "quickRequest.get",
            "quickRequest.post",
            "Http.singleRequest",
        ),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("HttpRequest",),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        all_arguments_from=0,
    ),
    GenericSink(
        ("tb.eval", "toolbox.eval", "toolBox.eval", "tb.compile", "toolbox.compile"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "ToolBox của Scala reflection",
        confidence=Confidence.HIGH,
    ),
)

_SCALA_POSTFIX: Dict[str, FrozenSet[Category]] = {
    **_JVM_POSTFIX_SANITIZERS,
    "toIntOption": _ALL_CATEGORIES,
    "toLongOption": _ALL_CATEGORIES,
    "toDoubleOption": _ALL_CATEGORIES,
    "toBooleanOption": _ALL_CATEGORIES,
}

_SCALA_SPEC = LanguageSpec(
    language=SCALA,
    lexer=_SCALA_LEXER,
    sources=_SCALA_SOURCES,
    sinks=_JAVA_SINKS + _JVM_SINKS + _SCALA_SINKS,
    sanitizers={
        **_JVM_SANITIZERS,
        "HtmlFormat.escape": _HTML_ONLY,
    },
    low_signal_sources=_JVM_LOW_SIGNAL,
    declaration_keywords=frozenset({"val", "var", "lazy"}),
    annotation_separator=":",
    annotation_sources=_JAVA_ANNOTATIONS,
    assignment_operators=("=", "+=", "<-"),
    receiver_propagators=frozenset({"append"}),
    builder_constructors=_JVM_BUILDERS | frozenset({"StringBuilder"}),
    postfix_sanitizers=_SCALA_POSTFIX,
    handler_annotations=_SPRING_HANDLERS,
    handler_parameter_types=frozenset({"String"}),
    handler_parameter_exclusions=_SPRING_NOT_REQUEST,
    handler_body_markers=frozenset({"Action", "authenticatedAction", "AuthenticatedAction", "SecuredAction"}),
    lambda_sources=_AKKA_DIRECTIVES,
    spliced_sql_prefixes=frozenset({"sql", "sqlu"}),
    value_accessors=frozenset({"toString", "mkString"}),
    constant_case_names=True,
)

# --------------------------------------------------------------------- Groovy

_GROOVY_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("${", "}"),),
    dollar_interpolation=True,
    dollar_bare_name=True,
    identifier_extra="_",
    # `'''...'''` không nội suy: `sh '''echo $X'''` để shell tự khai triển biến
    # môi trường, và đó chính là cách viết an toàn trong Jenkinsfile.
    triple_quotes=(('"""', True), ("'''", False)),
    multichar_operators=(
        "==~",
        "=~",
        "<=>",
        "===",
        "!==",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "?.",
        "*.",
        ".&",
        "?:",
        "->",
        "::",
        "..<",
        "..",
        "<<",
        ">>",
        "+=",
        "-=",
        "**",
    ),
)

PR_METADATA = "thông tin pull request do người gửi PR đặt"
BUILD_PARAMETER = "tham số `params` ( request Grails hoặc tham số build Jenkins )"

_GROOVY_SOURCES: Dict[str, str] = {
    **_JAVA_SOURCES,
    # Grails gom tham số request vào `params`; pipeline Jenkins gom tham số
    # build vào đúng cái tên đó.
    "params": BUILD_PARAMETER,
    "request.JSON": REQUEST_BODY,
    "request.XML": REQUEST_BODY,
    # Multibranch pipeline: các biến này lấy từ chính pull request, kể cả PR
    # từ fork của người lạ.
    "env.CHANGE_TITLE": PR_METADATA,
    "env.CHANGE_BRANCH": PR_METADATA,
    "env.CHANGE_AUTHOR": PR_METADATA,
    "env.CHANGE_AUTHOR_DISPLAY_NAME": PR_METADATA,
    "env.CHANGE_AUTHOR_EMAIL": PR_METADATA,
    "env.CHANGE_FORK": PR_METADATA,
    "CHANGE_TITLE": PR_METADATA,
    "CHANGE_BRANCH": PR_METADATA,
    "CHANGE_AUTHOR": PR_METADATA,
    "CHANGE_AUTHOR_DISPLAY_NAME": PR_METADATA,
    "CHANGE_AUTHOR_EMAIL": PR_METADATA,
    "CHANGE_FORK": PR_METADATA,
    "currentBuild.changeSets": "thông điệp commit của pull request",
}

_GROOVY_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        # Bước pipeline Jenkins: chuỗi được đưa nguyên cho sh -c / cmd /c.
        # Chuỗi nháy kép của Groovy được dán TRƯỚC khi shell nhìn thấy, y như
        # ${{ }} của GitHub Actions. Chỉ báo khi giá trị là của người ngoài:
        # gần như mọi `sh` đều ghép biến build của chính pipeline.
        ("sh", "bat", "powershell", "pwsh"),
        Category.COMMAND,
        "FSB-CMD-001",
        None,
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
        exact_names=True,
    ),
    GenericSink(
        # "ls ${d}".execute() tách chuỗi theo khoảng trắng, KHÔNG qua shell.
        # ["sh", "-c", c].execute() mới là lệnh shell ( bắt riêng ).
        ("execute",),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        receiver=True,
    ),
    GenericSink(
        ("toURL",),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        receiver=True,
    ),
    GenericSink(
        # groovy.sql.Sql nhận GString thì tự đổi `${x}` thành tham số bind; chỉ
        # phần NỐI chuỗi bằng + mới đi thẳng vào câu lệnh.
        (
            "sql.rows",
            "sql.execute",
            "sql.eachRow",
            "sql.firstRow",
            "sql.executeUpdate",
            "sql.executeInsert",
            "sql.query",
            "Sql.rows",
            "db.rows",
            "db.execute",
            "db.eachRow",
            "db.firstRow",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
        interpolation_parameterized=True,
    ),
    GenericSink(
        (
            "Eval.me",
            "Eval.x",
            "Eval.xy",
            "Eval.xyz",
            "GroovyShell.evaluate",
            "GroovyShell.parse",
            "GroovyClassLoader.parseClass",
            "shell.evaluate",
            "shell.parse",
        ),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        # `evaluate(code)` ở mức script; `rule.evaluate(ctx)` là phương thức khác.
        ("evaluate",),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
        confidence=Confidence.HIGH,
        exact_names=True,
        file_constructors=frozenset({"File"}),
    ),
    GenericSink(
        (
            "SimpleTemplateEngine.createTemplate",
            "GStringTemplateEngine.createTemplate",
            "StreamingTemplateEngine.createTemplate",
            "MarkupTemplateEngine.createTemplate",
            "engine.createTemplate",
            "templateEngine.createTemplate",
        ),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        None,
        SINK_TEMPLATE_COMPILER,
    ),
)

_GROOVY_SPEC = LanguageSpec(
    language=GROOVY,
    lexer=_GROOVY_LEXER,
    sources=_GROOVY_SOURCES,
    sinks=_JAVA_SINKS + _JVM_SINKS + _GROOVY_SINKS,
    sanitizers=_JVM_SANITIZERS,
    low_signal_sources=_JVM_LOW_SIGNAL,
    declaration_keywords=frozenset({"def", "var", "final"}),
    chain_separators=(".", "?."),
    annotation_sources=_JAVA_ANNOTATIONS,
    assignment_operators=("=", "+="),
    bare_call_names=frozenset({"sh", "bat", "powershell", "pwsh"}),
    receiver_propagators=frozenset({"append"}),
    builder_constructors=_JVM_BUILDERS,
    postfix_sanitizers=_JVM_POSTFIX_SANITIZERS,
    handler_annotations=_SPRING_HANDLERS,
    handler_parameter_types=frozenset({"String"}),
    handler_parameter_exclusions=_SPRING_NOT_REQUEST,
    redirect_view_prefix="redirect:",
    value_accessors=frozenset({"toString"}),
)

APPLICATION_SPECS: Dict[str, LanguageSpec] = {
    KOTLIN: _KOTLIN_SPEC,
    SCALA: _SCALA_SPEC,
    GROOVY: _GROOVY_SPEC,
}
