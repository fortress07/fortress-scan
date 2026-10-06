from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple

from ...core.model import Category, Confidence
from ...languages import (
    C,
    CPP,
    CSHARP,
    GO,
    JAVA,
    JAVASCRIPT,
    LUA,
    OBJC,
    PERL,
    PHP,
    POWERSHELL,
    RUBY,
    RUST,
    SHELL,
    TYPESCRIPT,
)
from .lexer import LexerProfile


@dataclass(frozen=True)
class GenericSink:
    names: Tuple[str, ...]
    category: Category
    tainted_rule: str
    dynamic_rule: Optional[str]
    description: str
    argument_index: int = 0
    require_sql: bool = False
    program_position: bool = False
    confidence: Confidence = Confidence.MEDIUM
    # Giá trị nguy hiểm là VẾ TRƯỚC dấu chấm, không phải đối số:
    # `"ls ${dir}".execute()` của Groovy, `cmd.execute()`.
    receiver: bool = False
    # `sql.rows("... ${id}")` của Groovy: GString đi vào đây được tách thành
    # câu lệnh có tham số bind, nên chỉ phần NỐI chuỗi mới nguy hiểm.
    interpolation_parameterized: bool = False
    # fmt.Fprintf(w, "<p>%s</p>", id): giá trị nguy hiểm là MỌI đối số từ vị trí
    # này trở đi, không phải một đối số duy nhất.
    all_arguments_from: Optional[int] = None
    # ... và chỉ khi đối số đầu là luồng phản hồi HTTP ( w, rw ), không phải
    # os.Stderr hay một tệp log.
    first_argument_names: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class LanguageSpec:
    language: str
    lexer: LexerProfile
    sources: Dict[str, str]
    sinks: Tuple[GenericSink, ...]
    assignment_sinks: Dict[str, Tuple[str, Category, str]] = field(default_factory=dict)
    # Mỗi bộ khử độc kèm ĐÚNG những nhóm nó thật sự khử, giống hệt bảng
    # SANITIZERS bên phân tích Python. Một tập tên phẳng, không nhóm, nói rằng
    # htmlspecialchars() khử được cả command injection -- mà nó không đụng tới
    # một ký tự đặc biệt nào của shell.
    sanitizers: Dict[str, FrozenSet[Category]] = field(default_factory=dict)
    weak_sanitizers: FrozenSet[str] = frozenset()
    declaration_keywords: FrozenSet[str] = frozenset()
    chain_separators: Tuple[str, ...] = (".",)
    # Languages that write the type after the name (``const x: T = ...``) need
    # it stripped, or the type name gets bound as the assignment target.
    annotation_separator: Optional[str] = None
    annotation_sources: Dict[str, str] = field(default_factory=dict)
    backtick_command: bool = False
    bare_call_names: FrozenSet[str] = frozenset()
    assignment_operators: Tuple[str, ...] = ("=", "+=", ".=")
    # Cú pháp ép kiểu dạng tiền tố: `[int]$x` của PowerShell, `(int)x` của C#.
    # Đây là cách khử độc IDIOMATIC nhất của những ngôn ngữ đó -- không đọc
    # được nó thì mọi script viết đúng đều bị kêu, mà bảng sanitizers lại chỉ
    # nhận dạng `ten(...)`.
    cast_delimiters: Tuple[str, str] = ()
    # C: hàm ĐỔ dữ liệu ngoài vào đối số ( fgets(buf, ...), recv(s, buf, ...) )
    # thay vì trả về: tên -> ( vị trí đối số, nhãn nguồn ). Vị trí âm nghĩa là
    # mọi đối số từ |vị trí| trở đi ( scanf("%s %d", a, &b) ).
    # Phần tử thứ ba là vị trí đối số luồng phải là stdin ( fgets(buf, n, stdin) );
    # -1 nghĩa là không cần điều kiện đó ( recv luôn là dữ liệu mạng ).
    fill_sources: Dict[str, Tuple[int, str, int]] = field(default_factory=dict)
    # Nguồn chỉ bật khi người dùng chọn --include-low-signal-sources, giống
    # sys.argv / os.getenv bên Python: argv của một công cụ dòng lệnh là chính
    # người chạy nó, fopen(argv[1]) là đúng chức năng chứ không phải lỗ hổng.
    low_signal_sources: Dict[str, str] = field(default_factory=dict)
    # getenv("QUERY_STRING") trong chương trình CGI là request HTTP thật:
    # tên hàm -> ( các giá trị literal của đối số đầu, tiền tố, nhãn ).
    argument_sources: Dict[str, Tuple[FrozenSet[str], Tuple[str, ...], str]] = field(default_factory=dict)
    # std::cin >> x
    stream_sources: Dict[str, str] = field(default_factory=dict)
    # `std::string q = "PRAGMA ..."` rồi sqlite3_exec(db, q.c_str()): biến chỉ
    # mang literal thì không phải "giá trị không phải hằng".
    literal_assignments: bool = False
    value_accessors: FrozenSet[str] = frozenset()
    # `Dim x As String = ...` của VB.NET: kiểu đứng sau một TỪ KHOÁ chứ không
    # phải một dấu như `:`.
    annotation_keyword: Optional[str] = None
    # VB.NET không phân biệt hoa thường: `process.start` vẫn là Process.Start.
    case_insensitive: bool = False
    # Phoenix: `def show(conn, %{"id" => id})` gắn id với tham số request.
    conn_param_patterns: bool = False
    # sprintf(cmd, "ping %s", host): vết nhiễm của các đối số từ vị trí thứ hai
    # chảy vào đối số đích. ( đích, nguồn đầu tiên, ghi đè hay nối thêm ).
    propagators: Dict[str, Tuple[int, int, bool]] = field(default_factory=dict)
    # Bỏ các dòng #define/#include trước khi đọc, giữ một nhánh #if.
    strip_preprocessor: bool = False
    # sb.append(x) / sb.Append(x) / b.WriteString(x): phương thức ĐỔ đối số vào
    # chính đối tượng nhận, nên vết nhiễm đi vào `sb`.
    receiver_propagators: FrozenSet[str] = frozenset()
    # `new StringBuilder("SELECT ...")`: bộ dựng chuỗi khởi tạo bằng literal
    # vẫn chỉ mang literal.
    builder_constructors: FrozenSet[str] = frozenset()
    # Bộ khử độc viết SAU giá trị: `id.toInt()` của Kotlin, `params[:n].to_i`
    # của Ruby, `s.toInt` của Scala.
    postfix_sanitizers: Dict[str, FrozenSet[Category]] = field(default_factory=dict)
    # Tham số kiểu chuỗi của một hàm xử lý request được framework gắn thẳng từ
    # request: `@GetMapping fun find(name: String)` của Spring,
    # `[HttpGet] IActionResult Find(string name)` của ASP.NET.
    handler_annotations: FrozenSet[str] = frozenset()
    handler_parameter_types: FrozenSet[str] = frozenset()
    # Annotation trên tham số đánh dấu nó KHÔNG đến từ request
    # ( @AuthenticationPrincipal, @Value, [FromServices] ).
    handler_parameter_exclusions: FrozenSet[str] = frozenset()
    # `[FromQuery] string id` của ASP.NET: attribute trong ngoặc vuông.
    attribute_sources: Dict[str, str] = field(default_factory=dict)
    # `return "redirect:" + url` của Spring MVC là một lệnh chuyển hướng.
    redirect_view_prefix: Optional[str] = None


# Ép về số hoặc UUID thì không còn ký tự đặc biệt nào sống sót, ở bất kỳ nhóm
# nào. Đây là nhóm duy nhất xứng đáng với "khử sạch mọi thứ".
_ALL_CATEGORIES: FrozenSet[Category] = frozenset(Category)

# Bộ thoát HTML chỉ đổi < > & " thành thực thể. Dấu ; | & $ ` của shell và dấu
# nháy đơn của SQL đi qua nguyên vẹn.
_HTML_ONLY: FrozenSet[Category] = frozenset({Category.MARKUP})

# Bộ trích dẫn shell chỉ lo cho shell. escapeshellarg() bọc chuỗi trong nháy
# đơn, đưa thẳng vào một câu SQL thì nháy đơn đó lại là ký tự phá cú pháp.
_COMMAND_ONLY: FrozenSet[Category] = frozenset({Category.COMMAND})

# basename() cắt phần thư mục, đúng cho file inclusion. basename("a;id") vẫn
# trả về "a;id" -- không giúp gì cho một câu lệnh shell.
_PATH_ONLY: FrozenSet[Category] = frozenset({Category.DYNAMIC_IMPORT})

# encodeURIComponent() mã hoá < > ; | & $ ` nhưng KHÔNG mã hoá dấu nháy đơn:
# nó nằm trong tập ký tự không dè dặt của RFC 3986. Nên nó chặn được XSS và
# lệnh shell, còn SQL thì không.
_URI_COMPONENT: FrozenSet[Category] = frozenset({Category.MARKUP, Category.COMMAND})

# preg_quote() thoát ký tự đặc biệt của regex. Dấu nháy đơn và dấu chấm phẩy
# không nằm trong danh sách đó, nên nó không khử được nhóm nào ở đây.
_NOTHING: FrozenSet[Category] = frozenset()

_JS_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"', "`"),
    interpolation_markers=(("${", "}"),),
    identifier_extra="_$",
)

_PHP_LEXER = LexerProfile(
    line_comments=("//", "#"),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("{$", "}"),),
    dollar_interpolation=True,
    identifier_extra="_$",
    heredoc_markers=("<<<",),
    multichar_operators=("===", "!==", "==", "!=", "<=", ">=", "&&", "||", "->", "::", ".=", "=>"),
)

_JAVA_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(),
    identifier_extra="_$",
)

_RUBY_LEXER = LexerProfile(
    line_comments=("#",),
    block_comments=(("=begin", "=end"),),
    plain_quotes=("'",),
    interpolating_quotes=('"', "`"),
    interpolation_markers=(("#{", "}"),),
    identifier_extra="_@$?!",
    heredoc_markers=("<<~", "<<-"),
)

_GO_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(),
    raw_quotes=("`",),
    identifier_extra="_",
    multichar_operators=(
        ":=",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "+=",
        "-=",
        "*=",
        "/=",
        "<-",
        "...",
    ),
)

_CSHARP_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("{", "}"),),
    identifier_extra="_@",
)

_SHELL_LEXER = LexerProfile(
    line_comments=("#",),
    block_comments=(),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(),
    dollar_interpolation=True,
    identifier_extra="_$-./",
    heredoc_markers=("<<",),
    multichar_operators=("&&", "||", ">>", "<<", "|&"),
)


# Mô tả của sink hiện thẳng trong thông điệp báo cáo, và cùng một mô tả được
# dùng lại cho hàng chục API ở mười ngôn ngữ. Gõ tay mỗi lần thì chỉ cần sai
# một bản là báo cáo mô tả cùng một loại điểm nguy hiểm theo hai kiểu khác nhau --
# cùng lý do đã gộp nhãn nguồn dữ liệu thành hằng số ở ngay dưới.
SINK_EVAL = "eval()"
SINK_SHELL_COMMAND = "một lệnh shell"
SINK_PROCESS_SPAWN = "việc tạo tiến trình"
SINK_SQL_QUERY = "một truy vấn SQL"
SINK_MODULE_LOAD = "việc nạp module"
SINK_OUTBOUND_URL = "một URL gửi request ra ngoài"
SINK_REDIRECT = "lệnh chuyển hướng"
SINK_FILE_PATH = "một đường dẫn tệp"
SINK_RAW_HTML = "nơi xuất HTML thô"
SINK_OBJECT_DESERIALIZER = "một bộ giải tuần tự đối tượng"
SINK_TEMPLATE_COMPILER = "một trình biên dịch template"

_JS_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval", "globalEval", "window.eval", "geval"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("Function", "vm.compileFunction"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "hàm khởi tạo Function",
    ),
    GenericSink(
        ("vm.runInThisContext", "vm.runInNewContext", "vm.runInContext", "vm.Script"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "module vm",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("setTimeout", "setInterval", "setImmediate"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        None,
        "callback của timer bị thực thi như mã",
    ),
    GenericSink(
        ("exec", "execSync", "child_process.exec", "child_process.execSync", "shelljs.exec"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("spawn", "spawnSync", "execFile", "execFileSync", "fork"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        program_position=True,
    ),
    GenericSink(
        ("query", "raw", "unsafe", "sequelize.query", "knex.raw", "db.query", "client.query"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("require", "import"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        SINK_MODULE_LOAD,
    ),
    GenericSink(
        ("fetch", "axios.get", "axios.post", "axios.put", "axios.delete", "axios.request"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("redirect",),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
    GenericSink(
        ("setHeader",),
        Category.HTTP_HEADER,
        "FSB-HDR-001",
        None,
        "header HTTP của phản hồi",
        argument_index=1,
    ),
    GenericSink(
        ("readFile", "readFileSync", "createReadStream", "download", "sendFile"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        ("write", "writeln", "document.write", "document.writeln", "insertAdjacentHTML", "html"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        ("unserialize", "node_serialize.unserialize", "serialize.unserialize"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        SINK_OBJECT_DESERIALIZER,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("yaml.load", "jsyaml.load", "safeLoadAll"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "một bộ giải tuần tự YAML",
    ),
)

# Nhãn nguồn dữ liệu hiện thẳng trong báo cáo, và cùng một nhãn được dùng lại
# cho hàng chục API khác nhau. Gõ tay mỗi lần thì chỉ cần sai một bản là báo
# cáo mô tả cùng một loại nguồn theo hai kiểu khác nhau.
QUERY_PARAM = "tham số truy vấn HTTP"
REQUEST_BODY = "body của request HTTP"
PATH_PARAM = "tham số đường dẫn HTTP"
HTTP_HEADER = "header HTTP"
HTTP_COOKIE = "cookie HTTP"
REQUEST_PARAM = "tham số của request HTTP"
FORM_FIELD = "trường form HTTP"
URL_QUERY_FRAGMENT = "fragment hoặc query của URL"
DOCUMENT_URL = "URL của tài liệu"
COMMAND_LINE_ARG = "tham số dòng lệnh"
ENVIRONMENT_VARIABLE = "biến môi trường"
QUERY_STRING = "query string HTTP"
STANDARD_INPUT = "luồng nhập chuẩn"
REQUEST_BOUND_PARAMETER = "tham số được framework gắn từ request"

_JS_SOURCES: Dict[str, str] = {
    "req.query": QUERY_PARAM,
    "req.body": REQUEST_BODY,
    "req.params": PATH_PARAM,
    "req.headers": HTTP_HEADER,
    "req.cookies": HTTP_COOKIE,
    "req.rawBody": REQUEST_BODY,
    "req.param": REQUEST_PARAM,
    "req.get": HTTP_HEADER,
    "request.query": QUERY_PARAM,
    "request.body": REQUEST_BODY,
    "request.params": PATH_PARAM,
    "request.headers": HTTP_HEADER,
    "ctx.query": QUERY_PARAM,
    "ctx.request": "request HTTP",
    "ctx.params": PATH_PARAM,
    "location.search": URL_QUERY_FRAGMENT,
    "location.hash": URL_QUERY_FRAGMENT,
    "location.href": URL_QUERY_FRAGMENT,
    "location.pathname": "đường dẫn URL",
    "window.location": URL_QUERY_FRAGMENT,
    "window.name": "tên cửa sổ",
    "document.URL": DOCUMENT_URL,
    "document.documentURI": DOCUMENT_URL,
    "document.referrer": "referrer của tài liệu",
    "document.location": DOCUMENT_URL,
    "localStorage.getItem": "kho lưu trữ trình duyệt",
    "sessionStorage.getItem": "kho lưu trữ trình duyệt",
    "event.data": "dữ liệu sự kiện message",
    "event.body": "dữ liệu sự kiện",
    "event.queryStringParameters": "dữ liệu sự kiện",
    "process.argv": COMMAND_LINE_ARG,
}

_PHP_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval", "assert", "create_function"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("preg_replace", "preg_replace_callback"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        None,
        "một phép thay thế bằng biểu thức chính quy",
        argument_index=1,
    ),
    GenericSink(
        ("system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("mysqli_query", "mysqli_multi_query", "pg_query", "sqlite_query", "mysqli_prepare"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        argument_index=1,
        require_sql=True,
    ),
    GenericSink(
        ("mysql_query", "query", "exec", "prepare"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("unserialize",),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "unserialize()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("include", "include_once", "require", "require_once"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "một lệnh nạp tệp",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("header",),
        Category.HTTP_HEADER,
        "FSB-HDR-001",
        None,
        "header()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("file_get_contents", "curl_exec"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        "một URL lấy nội dung từ xa",
    ),
    GenericSink(
        ("fopen", "readfile", "file_put_contents"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        ("call_user_func", "call_user_func_array", "array_map", "usort"),
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "một callable động",
    ),
    GenericSink(
        ("extract", "parse_str"),
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "việc chèn biến vào phạm vi cục bộ",
    ),
    GenericSink(
        ("ldap_search", "ldap_list", "ldap_read"),
        Category.LDAP,
        "FSB-LDAP-001",
        None,
        "một bộ lọc LDAP",
        argument_index=2,
    ),
    GenericSink(
        ("simplexml_load_string", "DOMDocument.loadXML"),
        Category.XML,
        "FSB-XML-001",
        None,
        "một bộ phân tích XML",
    ),
)

_PHP_SOURCES: Dict[str, str] = {
    "$_GET": QUERY_PARAM,
    "$_POST": FORM_FIELD,
    "$_REQUEST": REQUEST_PARAM,
    "$_COOKIE": HTTP_COOKIE,
    "$_SERVER": "biến server HTTP",
    "$_FILES": "tệp tải lên qua HTTP",
    "$_ENV": ENVIRONMENT_VARIABLE,
    "$HTTP_RAW_POST_DATA": REQUEST_BODY,
    "$argv": COMMAND_LINE_ARG,
    "getenv": ENVIRONMENT_VARIABLE,
    "filter_input": REQUEST_PARAM,
    "apache_request_headers": HTTP_HEADER,
    "getallheaders": HTTP_HEADER,
}

_JAVA_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("Runtime.exec", "getRuntime.exec", "Runtime.getRuntime.exec"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "Runtime.exec()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("ProcessBuilder", "ProcessBuilder.command"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        "ProcessBuilder",
        program_position=True,
    ),
    GenericSink(
        ("ScriptEngine.eval", "engine.eval", "GroovyShell.evaluate", "shell.evaluate"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "một script engine",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        (
            "executeQuery",
            "executeUpdate",
            "execute",
            "createQuery",
            "createNativeQuery",
            "createSQLQuery",
            "queryForObject",
            "queryForList",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL hoặc JPQL",
        require_sql=True,
    ),
    GenericSink(
        ("readObject", "XMLDecoder", "readUnshared"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "việc giải tuần tự đối tượng Java",
    ),
    GenericSink(
        (
            "parseExpression",
            "Ognl.getValue",
            "MVEL.eval",
            "ExpressionParser.parseExpression",
            "getValue",
        ),
        Category.EXPRESSION_LANGUAGE,
        "FSB-EL-001",
        None,
        "một bộ đánh giá expression language",
    ),
    GenericSink(
        ("Class.forName", "loadClass", "Assembly.load"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp class động",
    ),
    GenericSink(
        # Không dùng "compile" trần: Pattern.compile( regex ) không phải XPath.
        (
            "XPathExpression.evaluate",
            "xpath.evaluate",
            "xPath.evaluate",
            "XPath.evaluate",
            "xpath.compile",
            "xPath.compile",
            "XPath.compile",
            "newXPath.evaluate",
            "newXPath.compile",
        ),
        Category.XPATH,
        "FSB-XPATH-001",
        None,
        "một biểu thức XPath",
    ),
)

SINK_LDAP_FILTER = "một bộ lọc LDAP"

# Sink chung của mọi ngôn ngữ chạy trên JVM ( Java, Kotlin, Scala, Groovy ): cùng
# một thư viện chuẩn, cùng Servlet, Spring, JDBC.
_JVM_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        (
            "prepareStatement",
            "prepareCall",
            "addBatch",
            "executeLargeUpdate",
            "jdbcTemplate.query",
            "jdbcTemplate.update",
            "jdbcTemplate.batchUpdate",
            "queryForMap",
            "queryForRowSet",
            "rawQuery",
            "execSQL",
            "session.createQuery",
            "entityManager.createQuery",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL hoặc JPQL",
        require_sql=True,
    ),
    GenericSink(
        # new File(thu_muc, ten): phần nguy hiểm là tên ở đối số thứ hai.
        ("File", "java.io.File", "FileSystemResource", "Paths.get", "Path.of"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_index=1,
    ),
    GenericSink(
        (
            "FileInputStream",
            "FileOutputStream",
            "FileReader",
            "FileWriter",
            "RandomAccessFile",
            "PrintWriter.File",
            "Files.readAllBytes",
            "Files.readString",
            "Files.readAllLines",
            "Files.lines",
            "Files.newInputStream",
            "Files.newOutputStream",
            "Files.newBufferedReader",
            "Files.newBufferedWriter",
            "Files.write",
            "Files.writeString",
            "Files.delete",
            "Files.deleteIfExists",
            "Files.copy",
            "Files.move",
            "Source.fromFile",
        ),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        (
            "URL",
            "java.net.URL",
            "URI.create",
            "HttpGet",
            "HttpPost",
            "HttpPut",
            "HttpDelete",
            "HttpHead",
            "Jsoup.connect",
            "Request.Builder.url",
            "restTemplate.getForObject",
            "restTemplate.getForEntity",
            "restTemplate.postForObject",
            "restTemplate.postForEntity",
            "restTemplate.exchange",
            "Source.fromURL",
        ),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("sendRedirect", "RedirectView", "respondRedirect"),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
    GenericSink(
        ("setHeader", "addHeader"),
        Category.HTTP_HEADER,
        "FSB-HDR-001",
        None,
        "header HTTP của phản hồi",
        argument_index=1,
    ),
    GenericSink(
        (
            "getWriter.write",
            "getWriter.print",
            "getWriter.println",
            "getWriter.append",
            "getWriter.printf",
        ),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        # ctx.search(base, filter, controls): bộ lọc ở đối số thứ hai.
        (
            "ctx.search",
            "context.search",
            "dirContext.search",
            "ldapContext.search",
            "DirContext.search",
            "InitialDirContext.search",
            "InitialLdapContext.search",
            "ldapTemplate.search",
            "ldapTemplate.searchForObject",
            "ldapTemplate.authenticate",
        ),
        Category.LDAP,
        "FSB-LDAP-001",
        None,
        SINK_LDAP_FILTER,
        argument_index=1,
    ),
    GenericSink(
        # Velocity.evaluate(ctx, writer, tag, template): template ở đối số thứ tư.
        ("Velocity.evaluate", "velocityEngine.evaluate", "VelocityEngine.evaluate", "engine.evaluate"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        SINK_TEMPLATE_COMPILER,
        argument_index=3,
    ),
    GenericSink(
        ("jinjava.render", "Jinjava.render", "getLiteralTemplate", "StringTemplateLoader.putTemplate"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        None,
        SINK_TEMPLATE_COMPILER,
    ),
    GenericSink(
        # SnakeYAML trước 2.0 dựng được kiểu bất kỳ từ tag; XStream trước 1.4.18
        # không có danh sách cho phép mặc định. Chỉ báo khi dữ liệu là của người ngoài.
        (
            "Yaml.load",
            "yaml.load",
            "Yaml.loadAll",
            "yaml.loadAll",
            "fromXML",
            "ObjectInputStream",
            "XMLDecoder",
            "SerializationUtils.deserialize",
            "Kryo.readClassAndObject",
            "kryo.readClassAndObject",
        ),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        None,
        SINK_OBJECT_DESERIALIZER,
    ),
)

_JAVA_SOURCES: Dict[str, str] = {
    "request.getParameter": QUERY_PARAM,
    "request.getParameterValues": QUERY_PARAM,
    "request.getHeader": HTTP_HEADER,
    "request.getHeaders": HTTP_HEADER,
    "request.getQueryString": QUERY_STRING,
    "request.getCookies": HTTP_COOKIE,
    "request.getInputStream": REQUEST_BODY,
    "request.getReader": REQUEST_BODY,
    "request.getRequestURI": "đường dẫn của request HTTP",
    "request.getPathInfo": "đường dẫn của request HTTP",
    "req.getParameter": QUERY_PARAM,
    "req.getHeader": HTTP_HEADER,
    "request.getParameterMap": QUERY_PARAM,
    "request.getPart": REQUEST_BODY,
    "req.getParameterValues": QUERY_PARAM,
    "req.getQueryString": QUERY_STRING,
    "req.getInputStream": REQUEST_BODY,
    "req.getReader": REQUEST_BODY,
    "req.getCookies": HTTP_COOKIE,
    "System.getenv": ENVIRONMENT_VARIABLE,
    "System.getProperty": "thuộc tính hệ thống",
}

# Annotation xử lý request: tham số chuỗi KHÔNG annotation của chúng vẫn được
# Spring gắn từ query/form cùng tên.
_SPRING_HANDLERS: FrozenSet[str] = frozenset(
    {"GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping"}
)

# Tham số mang annotation này lấy giá trị từ chỗ khác, không từ request.
_SPRING_NOT_REQUEST: FrozenSet[str] = frozenset(
    {
        "AuthenticationPrincipal",
        "Value",
        "RequestAttribute",
        "SessionAttribute",
        "ModelAttribute",
        "CurrentSecurityContext",
        "Autowired",
    }
)

_JVM_SANITIZERS: Dict[str, FrozenSet[Category]] = {
    "Integer.parseInt": _ALL_CATEGORIES,
    "Integer.valueOf": _ALL_CATEGORIES,
    "Long.parseLong": _ALL_CATEGORIES,
    "Long.valueOf": _ALL_CATEGORIES,
    "Double.parseDouble": _ALL_CATEGORIES,
    "UUID.fromString": _ALL_CATEGORIES,
    "Encode.forHtml": _HTML_ONLY,
    "StringEscapeUtils.escapeHtml4": _HTML_ONLY,
    "HtmlUtils.htmlEscape": _HTML_ONLY,
    "ESAPI.encoder": _HTML_ONLY,
    # URLEncoder mã hoá cả dấu nháy đơn, dấu `/` và ký tự điều khiển.
    "URLEncoder.encode": _ALL_CATEGORIES,
    "FilenameUtils.getName": frozenset({Category.PATH, Category.DYNAMIC_IMPORT}),
    "Encode.forLdap": frozenset({Category.LDAP}),
    "LdapEncoder.filterEncode": frozenset({Category.LDAP}),
}

_JVM_POSTFIX_SANITIZERS: Dict[str, FrozenSet[Category]] = {
    "toInt": _ALL_CATEGORIES,
    "toLong": _ALL_CATEGORIES,
    "toShort": _ALL_CATEGORIES,
    "toDouble": _ALL_CATEGORIES,
    "toFloat": _ALL_CATEGORIES,
    "toBoolean": _ALL_CATEGORIES,
    "toIntOrNull": _ALL_CATEGORIES,
    "toLongOrNull": _ALL_CATEGORIES,
    "toDoubleOrNull": _ALL_CATEGORIES,
    "toInteger": _ALL_CATEGORIES,
    "toBigDecimal": _ALL_CATEGORIES,
}

_JVM_BUILDERS: FrozenSet[str] = frozenset({"StringBuilder", "StringBuffer", "StringWriter"})

_JAVA_ANNOTATIONS: Dict[str, str] = {
    "RequestParam": QUERY_PARAM,
    "PathVariable": PATH_PARAM,
    "RequestBody": REQUEST_BODY,
    "RequestHeader": HTTP_HEADER,
    "CookieValue": HTTP_COOKIE,
    "QueryParam": QUERY_PARAM,
    "PathParam": PATH_PARAM,
    "FormParam": FORM_FIELD,
    "HeaderParam": HTTP_HEADER,
}

_RUBY_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval", "instance_eval", "class_eval", "module_eval", "binding.eval"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("system", "exec", "spawn", "IO.popen", "Open3.capture2", "Open3.capture3"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("send", "public_send", "__send__", "const_get", "method"),
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "việc điều phối phương thức động",
    ),
    GenericSink(
        ("find_by_sql", "execute", "where", "order", "select_all", "exec_query"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("Marshal.load", "YAML.load", "Psych.load", "Marshal.restore"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        SINK_OBJECT_DESERIALIZER,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("ERB.new", "Erubi.new", "Liquid.Template.parse"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        SINK_TEMPLATE_COMPILER,
    ),
)

_RUBY_SOURCES: Dict[str, str] = {
    "params": REQUEST_PARAM,
    "request.params": REQUEST_PARAM,
    "request.body": REQUEST_BODY,
    "request.query_string": QUERY_STRING,
    "request.env": HTTP_HEADER,
    "cookies": HTTP_COOKIE,
    "session": "giá trị session",
    "ENV": ENVIRONMENT_VARIABLE,
    "ARGV": COMMAND_LINE_ARG,
    "gets": STANDARD_INPUT,
    "STDIN.gets": STANDARD_INPUT,
}

_GO_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("exec.Command", "exec.CommandContext"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        "os/exec",
        program_position=True,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("db.Query", "db.Exec", "db.QueryRow", "Query", "Exec", "QueryRow", "QueryContext"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("template.HTML", "template.JS", "template.URL", "template.HTMLAttr"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        "một giá trị template không được escape",
    ),
    GenericSink(
        ("Parse", "template.New", "ParseGlob"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        None,
        SINK_TEMPLATE_COMPILER,
    ),
    GenericSink(
        ("gob.NewDecoder", "Decode"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        None,
        "một bộ giải mã",
    ),
    GenericSink(
        (
            "os.Open",
            "os.OpenFile",
            "os.ReadFile",
            "ioutil.ReadFile",
            "os.Create",
            "os.WriteFile",
            "ioutil.WriteFile",
            "os.Remove",
            "os.RemoveAll",
            "os.ReadDir",
            "c.File",
            "c.FileAttachment",
            "ctx.SendFile",
            "c.SendFile",
        ),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        # http.ServeFile(w, r, name)
        ("http.ServeFile",),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
        argument_index=2,
    ),
    GenericSink(
        # http.Redirect(w, r, url, code)
        ("http.Redirect",),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
        argument_index=2,
    ),
    GenericSink(
        # c.Redirect(code, url) của gin và echo.
        ("c.Redirect",),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
        argument_index=1,
    ),
    GenericSink(
        ("http.Get", "http.Post", "http.Head", "http.PostForm"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("http.NewRequest",),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        argument_index=1,
    ),
    GenericSink(
        ("http.NewRequestWithContext",),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        argument_index=2,
    ),
    GenericSink(
        # fmt.Fprintf(w, "<p>%s</p>", name): chỉ khi đích là luồng phản hồi HTTP.
        ("fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln", "io.WriteString"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
        all_arguments_from=1,
        first_argument_names=frozenset({"w", "rw", "writer", "resp", "res"}),
    ),
    GenericSink(
        ("w.Write", "rw.Write", "c.Writer.Write"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
        all_arguments_from=0,
    ),
    GenericSink(
        ("w.Header.Set", "w.Header.Add", "c.Header"),
        Category.HTTP_HEADER,
        "FSB-HDR-001",
        None,
        "header HTTP của phản hồi",
        argument_index=1,
    ),
)

_GO_SOURCES: Dict[str, str] = {
    "r.URL.Query": QUERY_PARAM,
    "r.FormValue": FORM_FIELD,
    "r.PostFormValue": FORM_FIELD,
    "r.Header.Get": HTTP_HEADER,
    "r.Body": REQUEST_BODY,
    "req.URL.Query": QUERY_PARAM,
    "req.FormValue": FORM_FIELD,
    "mux.Vars": PATH_PARAM,
    "c.Param": PATH_PARAM,
    "c.Query": QUERY_PARAM,
    "c.DefaultQuery": QUERY_PARAM,
    "c.QueryArray": QUERY_PARAM,
    "c.PostForm": FORM_FIELD,
    "c.DefaultPostForm": FORM_FIELD,
    "c.GetHeader": HTTP_HEADER,
    "c.Cookie": HTTP_COOKIE,
    "c.QueryParam": QUERY_PARAM,
    "c.FormValue": FORM_FIELD,
    "c.Params": PATH_PARAM,
    "c.Query.Get": QUERY_PARAM,
    "r.URL.Path": "đường dẫn của request HTTP",
    "r.URL.RawQuery": QUERY_STRING,
    "r.Form": FORM_FIELD,
    "r.PostForm": FORM_FIELD,
    "r.Header": HTTP_HEADER,
    "r.Cookie": HTTP_COOKIE,
    "r.PathValue": PATH_PARAM,
    "r.Referer": HTTP_HEADER,
    "r.UserAgent": HTTP_HEADER,
    "req.URL.Path": "đường dẫn của request HTTP",
    "req.Header": HTTP_HEADER,
    "req.Body": REQUEST_BODY,
    "req.PostFormValue": FORM_FIELD,
    "chi.URLParam": PATH_PARAM,
    "os.Args": COMMAND_LINE_ARG,
    "os.Getenv": ENVIRONMENT_VARIABLE,
}

_CSHARP_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        # Process.Start(file, args) không qua shell; chỉ dạng
        # Process.Start("cmd.exe", "/c " + x) là lệnh shell ( bắt riêng ).
        ("Process.Start", "ProcessStartInfo"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        program_position=True,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        (
            "SqlCommand",
            "OleDbCommand",
            "MySqlCommand",
            "NpgsqlCommand",
            "ExecuteReader",
            "ExecuteNonQuery",
            "ExecuteScalar",
            "FromSqlRaw",
            "ExecuteSqlRaw",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một câu lệnh SQL",
        require_sql=True,
    ),
    GenericSink(
        (
            "BinaryFormatter.Deserialize",
            "Deserialize",
            "LosFormatter.Deserialize",
            "NetDataContractSerializer.Deserialize",
            "ObjectStateFormatter.Deserialize",
        ),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "một bộ giải tuần tự .NET",
    ),
    GenericSink(
        ("Assembly.Load", "Assembly.LoadFrom", "Type.GetType", "Activator.CreateInstance"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp assembly hoặc kiểu động",
    ),
    GenericSink(
        ("CompileAssemblyFromSource", "CSharpScript.EvaluateAsync", "CSharpScript.RunAsync"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "việc biên dịch lúc chạy",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        (
            "File.ReadAllText",
            "File.ReadAllBytes",
            "File.ReadAllLines",
            "File.ReadLines",
            "File.OpenRead",
            "File.OpenText",
            "File.Open",
            "File.WriteAllText",
            "File.WriteAllBytes",
            "File.AppendAllText",
            "File.Create",
            "File.Delete",
            "File.Copy",
            "File.Move",
            "FileStream",
            "StreamReader",
            "StreamWriter",
            "PhysicalFile",
            "Directory.Delete",
            "Directory.GetFiles",
            "Directory.CreateDirectory",
        ),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        ("Redirect", "RedirectPermanent", "Response.Redirect", "RedirectPreserveMethod"),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
    GenericSink(
        (
            "GetStringAsync",
            "GetByteArrayAsync",
            "GetStreamAsync",
            "WebRequest.Create",
            "HttpWebRequest.Create",
            "DownloadString",
            "DownloadData",
            "DownloadFile",
            "DownloadStringTaskAsync",
            "OpenRead.WebClient",
            "httpClient.GetAsync",
            "_httpClient.GetAsync",
            "HttpClient.GetAsync",
            "httpClient.PostAsync",
            "_httpClient.PostAsync",
            "httpClient.SendAsync",
        ),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("HttpRequestMessage",),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
        argument_index=1,
    ),
    GenericSink(
        ("Html.Raw", "Response.Write", "HtmlString", "MarkupString"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        ("Response.Headers.Add", "Response.AppendHeader", "Response.AddHeader", "Headers.Append"),
        Category.HTTP_HEADER,
        "FSB-HDR-001",
        None,
        "header HTTP của phản hồi",
        argument_index=1,
    ),
    GenericSink(
        ("DirectorySearcher",),
        Category.LDAP,
        "FSB-LDAP-001",
        None,
        "một bộ lọc LDAP",
    ),
    GenericSink(
        ("SelectNodes", "SelectSingleNode", "XPathNavigator.Evaluate", "XPathNavigator.Select"),
        Category.XPATH,
        "FSB-XPATH-001",
        None,
        "một biểu thức XPath",
    ),
)

# Attribute trên tham số của action ASP.NET Core.
_CSHARP_ATTRIBUTE_SOURCES: Dict[str, str] = {
    "FromQuery": QUERY_PARAM,
    "FromRoute": PATH_PARAM,
    "FromForm": FORM_FIELD,
    "FromBody": REQUEST_BODY,
    "FromHeader": HTTP_HEADER,
}

_CSHARP_HANDLERS: FrozenSet[str] = frozenset(
    {"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "Route", "AcceptVerbs"}
)

NETWORK_DATA = "dữ liệu nhận qua mạng"
FILE_OR_STREAM = "dữ liệu đọc từ tệp hoặc luồng"

_NATIVE_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'", '"'),
    interpolating_quotes=(),
    interpolation_markers=(),
    identifier_extra="_",
    multichar_operators=("->", "::", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-="),
)

_NATIVE_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("system", "popen", "_popen", "_wsystem", "_wpopen", "std.system"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("execl", "execlp", "execle", "execv", "execvp", "execvpe", "execve", "_execl", "_execvp"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        program_position=True,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("sqlite3_exec", "sqlite3_prepare", "sqlite3_prepare_v2", "sqlite3_prepare_v3", "mysql_query", "mysql_real_query", "PQexec", "PQexecParams", "PQsendQuery"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        argument_index=1,
        require_sql=True,
    ),
    GenericSink(
        ("dlopen", "LoadLibraryA", "LoadLibraryW", "LoadLibrary", "LoadLibraryExA", "LoadLibraryExW"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        None,
        "việc nạp thư viện động",
    ),
    GenericSink(
        ("fopen", "freopen", "open", "openat", "creat", "unlink", "remove", "rename", "chmod", "std.ifstream", "std.ofstream", "std.fstream", "ifstream", "ofstream"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
)

_NATIVE_SOURCES: Dict[str, str] = {}

_NATIVE_LOW_SIGNAL: Dict[str, str] = {
    "argv": COMMAND_LINE_ARG,
    "getenv": ENVIRONMENT_VARIABLE,
    "secure_getenv": ENVIRONMENT_VARIABLE,
    "_wgetenv": ENVIRONMENT_VARIABLE,
    "std.getenv": ENVIRONMENT_VARIABLE,
}

CGI_REQUEST = "biến CGI mang dữ liệu request HTTP"

_CGI_VARIABLES: FrozenSet[str] = frozenset(
    {"QUERY_STRING", "REQUEST_URI", "PATH_INFO", "PATH_TRANSLATED", "CONTENT_TYPE", "SCRIPT_NAME", "REMOTE_USER", "DOCUMENT_URI"}
)

_NATIVE_ARGUMENT_SOURCES: Dict[str, Tuple[FrozenSet[str], Tuple[str, ...], str]] = {
    name: (_CGI_VARIABLES, ("HTTP_",), CGI_REQUEST) for name in ("getenv", "secure_getenv", "std.getenv")
}

# Chỉ đọc từ stdin hoặc mạng mới là dữ liệu ngoài; đọc tệp cấu hình của chính
# chương trình thì không ( giống bên Python: sys.stdin là nguồn, open().read() thì không ).
_NATIVE_FILLS: Dict[str, Tuple[int, str, int]] = {
    "fgets": (0, STANDARD_INPUT, 2),
    "fgetws": (0, STANDARD_INPUT, 2),
    "gets": (0, STANDARD_INPUT, -1),
    "getline": (0, STANDARD_INPUT, 2),
    "getdelim": (0, STANDARD_INPUT, 3),
    "fread": (0, STANDARD_INPUT, 3),
    "read": (1, STANDARD_INPUT, 0),
    "recv": (1, NETWORK_DATA, -1),
    "recvfrom": (1, NETWORK_DATA, -1),
    "recvmsg": (1, NETWORK_DATA, -1),
    "SSL_read": (1, NETWORK_DATA, -1),
    "BIO_read": (1, NETWORK_DATA, -1),
    "scanf": (-1, STANDARD_INPUT, -1),
    "std.getline": (1, STANDARD_INPUT, 0),
}

_NATIVE_PROPAGATORS: Dict[str, Tuple[int, int, bool]] = {
    "sprintf": (0, 1, True),
    "snprintf": (0, 2, True),
    "vsnprintf": (0, 2, True),
    "strcpy": (0, 1, True),
    "strncpy": (0, 1, True),
    "strlcpy": (0, 1, True),
    "memcpy": (0, 1, True),
    "strcat": (0, 1, False),
    "strncat": (0, 1, False),
    "strlcat": (0, 1, False),
    "asprintf": (0, 1, True),
    "sscanf": (2, 0, True),
}

_NATIVE_SANITIZERS: Dict[str, FrozenSet[Category]] = {
    "atoi": _ALL_CATEGORIES,
    "atol": _ALL_CATEGORIES,
    "atoll": _ALL_CATEGORIES,
    "strtol": _ALL_CATEGORIES,
    "strtoul": _ALL_CATEGORIES,
    "strtoll": _ALL_CATEGORIES,
    "strtoull": _ALL_CATEGORIES,
    "strtod": _ALL_CATEGORIES,
    "std.stoi": _ALL_CATEGORIES,
    "std.stol": _ALL_CATEGORIES,
    "basename": _PATH_ONLY | frozenset({Category.PATH}),
    "realpath": frozenset({Category.PATH}),
}

_CSHARP_SOURCES: Dict[str, str] = {
    "Request.QueryString": QUERY_PARAM,
    "Request.Form": FORM_FIELD,
    "Request.Params": REQUEST_PARAM,
    "Request.Headers": HTTP_HEADER,
    "Request.Cookies": HTTP_COOKIE,
    "Request.Body": REQUEST_BODY,
    "Request.Query": QUERY_PARAM,
    "Request.RouteValues": PATH_PARAM,
    "Request.Path": "đường dẫn của request HTTP",
    "Request.RawUrl": "đường dẫn của request HTTP",
    "Request.Url": "đường dẫn của request HTTP",
    "Request.UserAgent": HTTP_HEADER,
    "HttpContext.Request.Query": QUERY_PARAM,
    "HttpContext.Request.Form": FORM_FIELD,
    "HttpContext.Request.Headers": HTTP_HEADER,
    "HttpContext.Request.Cookies": HTTP_COOKIE,
    "HttpContext.Request.Body": REQUEST_BODY,
    "context.Request.Query": QUERY_PARAM,
    "context.Request.Form": FORM_FIELD,
    "context.Request.Headers": HTTP_HEADER,
    "Environment.GetEnvironmentVariable": ENVIRONMENT_VARIABLE,
}

_SHELL_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval",),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "eval",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("source", "."),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc source một script",
    ),
)

_SHELL_SOURCES: Dict[str, str] = {
    "$1": COMMAND_LINE_ARG,
    "$2": COMMAND_LINE_ARG,
    "$3": COMMAND_LINE_ARG,
    "$4": COMMAND_LINE_ARG,
    "$5": COMMAND_LINE_ARG,
    "$@": COMMAND_LINE_ARG,
    "$*": COMMAND_LINE_ARG,
    "$REPLY": STANDARD_INPUT,
    "$QUERY_STRING": QUERY_STRING,
    "$HTTP_USER_AGENT": HTTP_HEADER,
    "$GITHUB_HEAD_REF": "tham chiếu CI không tin cậy",
    "$GITHUB_EVENT_NAME": "đầu vào CI không tin cậy",
}


_RUST_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    # Rust KHÔNG có chuỗi nháy đơn. Dấu nháy đơn ở đây là literal ký tự
    # ( 'a' ) và, quan trọng hơn, là lifetime ( &'a str, Vec<'static> ) --
    # coi nó là mở chuỗi thì mọi struct có lifetime đều nuốt phần còn lại
    # của tệp vào trong một chuỗi không bao giờ đóng.
    plain_quotes=(),
    interpolating_quotes=('"',),
    interpolation_markers=(("{", "}"),),
    identifier_extra="_",
    multichar_operators=(
        "::",
        "->",
        "=>",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "+=",
        "-=",
        "*=",
        "/=",
        "..=",
        "..",
    ),
)

_POWERSHELL_LEXER = LexerProfile(
    line_comments=("#",),
    block_comments=(("<#", "#>"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("$(", ")"),),
    dollar_interpolation=True,
    identifier_extra="_$:-",
    heredoc_markers=("@\"", "@'"),
    multichar_operators=("-eq", "-ne", "-like", "-match", "::", "|", "&&", "||", "+="),
)

_PERL_LEXER = LexerProfile(
    line_comments=("#",),
    block_comments=(),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("${", "}"), ("@{", "}")),
    dollar_interpolation=True,
    identifier_extra="_$@%:",
    heredoc_markers=("<<",),
    heredoc_bare_adjacent=True,
    multichar_operators=("=>", "->", "==", "!=", "<=", ">=", "&&", "||", "=~", "::", ".="),
)

_LUA_LEXER = LexerProfile(
    line_comments=("--",),
    block_comments=(("--[[", "]]"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(),
    raw_quotes=("[[",),
    identifier_extra="_",
    multichar_operators=("==", "~=", "<=", ">=", "..", "::"),
)


_RUST_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("Command.new", "process.Command.new", "std.process.Command.new"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        SINK_PROCESS_SPAWN,
        program_position=True,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("sql_query", "sqlx.query", "sqlx.query_as", "query_unchecked", "raw_sql"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("execute", "query", "query_row", "prepare"),
        Category.SQL,
        "FSB-SQL-001",
        None,
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("render_template", "register_template_string", "Tera.one_off"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        SINK_TEMPLATE_COMPILER,
    ),
    GenericSink(
        ("File.open", "fs.read", "fs.read_to_string", "fs.write", "NamedFile.open"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        ("reqwest.get", "Client.get", "get", "Url.parse"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("Library.new", "libloading.Library.new"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp thư viện động",
    ),
    GenericSink(
        ("Redirect.to", "Redirect.temporary", "Redirect.permanent"),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
    GenericSink(
        ("Html", "PreEscaped", "raw_html"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
)

_RUST_SOURCES: Dict[str, str] = {
    "env.args": COMMAND_LINE_ARG,
    "std.env.args": COMMAND_LINE_ARG,
    "env.var": ENVIRONMENT_VARIABLE,
    "std.env.var": ENVIRONMENT_VARIABLE,
    "req.query_string": QUERY_STRING,
    "req.match_info": PATH_PARAM,
    "req.headers": HTTP_HEADER,
    "request.headers": HTTP_HEADER,
    "web.Query": QUERY_PARAM,
    "web.Path": PATH_PARAM,
    "web.Form": FORM_FIELD,
    "web.Json": REQUEST_BODY,
    "Query": QUERY_PARAM,
    "Path": PATH_PARAM,
    "Form": FORM_FIELD,
    "stdin": STANDARD_INPUT,
    "read_line": STANDARD_INPUT,
}

# PowerShell gọi cmdlet không có dấu ngoặc, nên bộ đọc không tách được đối số
# thật khỏi tên tham số: trong `Start-Process -FilePath ping` thì `-FilePath`
# cũng là một định danh. Phép hỏi "giá trị này có phải hằng không" vì thế luôn
# trả lời "không", kể cả trên dòng đúng chuẩn nhất, nên các sink ở đây bỏ hẳn
# dynamic_rule và chỉ báo khi có vết nhiễm thật.
#
# Invoke-Expression là ngoại lệ: nhận một giá trị không phải hằng thì tự nó đã
# đáng rà, bất kể có dựng được đường đi hay không.
_POWERSHELL_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("Invoke-Expression", "iex", "IEX"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "Invoke-Expression",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("Add-Type", "ScriptBlock.Create", "Invoke-Command"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        None,
        "việc biên dịch mã lúc chạy",
    ),
    GenericSink(
        ("Start-Process", "Invoke-Item", "cmd.exe", "Start-Job"),
        Category.COMMAND,
        "FSB-CMD-001",
        None,
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("Invoke-Sqlcmd", "ExecuteReader", "ExecuteNonQuery", "ExecuteScalar"),
        Category.SQL,
        "FSB-SQL-001",
        None,
        "một câu lệnh SQL",
        require_sql=True,
    ),
    GenericSink(
        ("Import-Module", "Import-Clixml"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        None,
        SINK_MODULE_LOAD,
    ),
    GenericSink(
        ("Invoke-WebRequest", "Invoke-RestMethod", "wget", "curl"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("Get-Content", "Set-Content", "Out-File", "Remove-Item"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
)

_POWERSHELL_SOURCES: Dict[str, str] = {
    "$args": COMMAND_LINE_ARG,
    "$Args": COMMAND_LINE_ARG,
    "$input": STANDARD_INPUT,
    "$PSBoundParameters": "tham số của script",
    "Read-Host": STANDARD_INPUT,
    "$env:QUERY_STRING": QUERY_STRING,
    "$env:GITHUB_HEAD_REF": "tham chiếu CI không tin cậy",
    "$env:GITHUB_EVENT_PATH": "đầu vào CI không tin cậy",
    "$Request": "request HTTP",
}

_PERL_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval",),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        SINK_EVAL,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("system", "exec", "qx", "readpipe"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        # `open(FH, $cmd)` hai đối số là câu lệnh shell nếu chuỗi kết thúc
        # bằng ống dẫn -- một trong những lỗ hổng Perl lâu đời nhất còn sống.
        ("open",),
        Category.COMMAND,
        "FSB-CMD-001",
        None,
        "open() hai đối số ( chạy shell khi chuỗi có ống dẫn )",
        argument_index=1,
    ),
    GenericSink(
        ("do", "require"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp tệp mã",
    ),
    GenericSink(
        ("prepare", "selectall_arrayref", "selectrow_array", "selectcol_arrayref"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
    GenericSink(
        ("Storable.thaw", "thaw", "Data.Dumper.Eval"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        SINK_OBJECT_DESERIALIZER,
    ),
)

_PERL_SOURCES: Dict[str, str] = {
    "@ARGV": COMMAND_LINE_ARG,
    "$ARGV": COMMAND_LINE_ARG,
    "%ENV": ENVIRONMENT_VARIABLE,
    "$ENV": ENVIRONMENT_VARIABLE,
    "param": REQUEST_PARAM,
    "$q.param": REQUEST_PARAM,
    "$cgi.param": REQUEST_PARAM,
    "url_param": QUERY_PARAM,
    "http": HTTP_HEADER,
    "$req.param": REQUEST_PARAM,
    "STDIN": STANDARD_INPUT,
}

_LUA_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("load", "loadstring", "dofile", "loadfile", "assert"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "bộ nạp mã của Lua",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("os.execute", "io.popen"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        SINK_SHELL_COMMAND,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("require",),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        SINK_MODULE_LOAD,
    ),
    GenericSink(
        ("io.open", "io.lines", "io.input"),
        Category.PATH,
        "FSB-PATH-001",
        None,
        SINK_FILE_PATH,
    ),
    GenericSink(
        ("ngx.say", "ngx.print"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        SINK_RAW_HTML,
    ),
    GenericSink(
        ("ngx.redirect",),
        Category.REDIRECT,
        "FSB-REDIR-001",
        None,
        SINK_REDIRECT,
    ),
    GenericSink(
        ("ngx.location.capture", "http.request"),
        Category.SSRF,
        "FSB-SSRF-001",
        None,
        SINK_OUTBOUND_URL,
    ),
    GenericSink(
        ("query", "execute"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        SINK_SQL_QUERY,
        require_sql=True,
    ),
)

_LUA_SOURCES: Dict[str, str] = {
    "arg": COMMAND_LINE_ARG,
    "os.getenv": ENVIRONMENT_VARIABLE,
    "io.read": STANDARD_INPUT,
    "ngx.var": "biến của request nginx",
    "ngx.req.get_uri_args": QUERY_PARAM,
    "ngx.req.get_post_args": FORM_FIELD,
    "ngx.req.get_headers": HTTP_HEADER,
    "ngx.req.get_body_data": REQUEST_BODY,
}


SPECS: Dict[str, LanguageSpec] = {
    JAVASCRIPT: LanguageSpec(
        language=JAVASCRIPT,
        lexer=_JS_LEXER,
        sources=_JS_SOURCES,
        sinks=_JS_SINKS,
        assignment_sinks={
            "innerHTML": ("FSB-XSS-001", Category.MARKUP, "innerHTML"),
            "outerHTML": ("FSB-XSS-001", Category.MARKUP, "outerHTML"),
            "srcdoc": ("FSB-XSS-001", Category.MARKUP, "srcdoc"),
            "dangerouslySetInnerHTML": (
                "FSB-XSS-001",
                Category.MARKUP,
                "dangerouslySetInnerHTML",
            ),
        },
        sanitizers={
            "encodeURIComponent": _URI_COMPONENT,
            "encodeURI": _URI_COMPONENT,
            "parseInt": _ALL_CATEGORIES,
            "parseFloat": _ALL_CATEGORIES,
            "Number": _ALL_CATEGORIES,
            "DOMPurify.sanitize": _HTML_ONLY,
            "sanitizeHtml": _HTML_ONLY,
            "validator.escape": _HTML_ONLY,
            "shellQuote.quote": _COMMAND_ONLY,
            "escapeHtml": _HTML_ONLY,
        },
        declaration_keywords=frozenset({"var", "let", "const"}),
    ),
    TYPESCRIPT: LanguageSpec(
        language=TYPESCRIPT,
        lexer=_JS_LEXER,
        sources=_JS_SOURCES,
        sinks=_JS_SINKS,
        assignment_sinks={
            "innerHTML": ("FSB-XSS-001", Category.MARKUP, "innerHTML"),
            "outerHTML": ("FSB-XSS-001", Category.MARKUP, "outerHTML"),
            "dangerouslySetInnerHTML": (
                "FSB-XSS-001",
                Category.MARKUP,
                "dangerouslySetInnerHTML",
            ),
        },
        sanitizers={
            "encodeURIComponent": _URI_COMPONENT,
            "encodeURI": _URI_COMPONENT,
            "parseInt": _ALL_CATEGORIES,
            "parseFloat": _ALL_CATEGORIES,
            "Number": _ALL_CATEGORIES,
            "DOMPurify.sanitize": _HTML_ONLY,
            "sanitizeHtml": _HTML_ONLY,
            "escapeHtml": _HTML_ONLY,
        },
        declaration_keywords=frozenset({"var", "let", "const"}),
        annotation_separator=":",
    ),
    PHP: LanguageSpec(
        language=PHP,
        lexer=_PHP_LEXER,
        sources=_PHP_SOURCES,
        sinks=_PHP_SINKS,
        sanitizers={
            "escapeshellarg": _COMMAND_ONLY,
            "escapeshellcmd": _COMMAND_ONLY,
            "intval": _ALL_CATEGORIES,
            "floatval": _ALL_CATEGORIES,
            "htmlspecialchars": _HTML_ONLY,
            "htmlentities": _HTML_ONLY,
            "preg_quote": _NOTHING,
            # filter_var() khử tới đâu là do đối số bộ lọc quyết định, mà đối
            # số đó ở đây chưa đọc được. Giữ nguyên mức cũ để không đổi hành vi
            # ngoài phạm vi lỗ hổng đang vá.
            "filter_var": _ALL_CATEGORIES,
            "basename": _PATH_ONLY,
            # urlencode/rawurlencode mã hoá cả dấu nháy đơn, khác
            # encodeURIComponent của JavaScript.
            "urlencode": _ALL_CATEGORIES,
            "rawurlencode": _ALL_CATEGORIES,
        },
        weak_sanitizers=frozenset(
            {"addslashes", "mysql_real_escape_string", "mysqli_real_escape_string", "quote"}
        ),
        chain_separators=("->", "::"),
        backtick_command=True,
        bare_call_names=frozenset(
            {"include", "include_once", "require", "require_once", "echo", "print"}
        ),
    ),
    JAVA: LanguageSpec(
        language=JAVA,
        lexer=_JAVA_LEXER,
        sources=_JAVA_SOURCES,
        sinks=_JAVA_SINKS + _JVM_SINKS,
        sanitizers=_JVM_SANITIZERS,
        annotation_sources=_JAVA_ANNOTATIONS,
        receiver_propagators=frozenset({"append", "insert"}),
        builder_constructors=_JVM_BUILDERS,
        handler_annotations=_SPRING_HANDLERS,
        handler_parameter_types=frozenset({"String"}),
        handler_parameter_exclusions=_SPRING_NOT_REQUEST,
        redirect_view_prefix="redirect:",
        value_accessors=frozenset({"toString"}),
    ),
    RUBY: LanguageSpec(
        language=RUBY,
        lexer=_RUBY_LEXER,
        sources=_RUBY_SOURCES,
        sinks=_RUBY_SINKS,
        sanitizers={
            "Integer": _ALL_CATEGORIES,
            "Float": _ALL_CATEGORIES,
            "to_i": _ALL_CATEGORIES,
            "to_f": _ALL_CATEGORIES,
            "Shellwords.escape": _COMMAND_ONLY,
            "Shellwords.shellescape": _COMMAND_ONLY,
            "ERB::Util.html_escape": _HTML_ONLY,
            "CGI.escapeHTML": _HTML_ONLY,
        },
        backtick_command=True,
    ),
    GO: LanguageSpec(
        language=GO,
        lexer=_GO_LEXER,
        sources=_GO_SOURCES,
        sinks=_GO_SINKS,
        sanitizers={
            "strconv.Atoi": _ALL_CATEGORIES,
            "strconv.ParseInt": _ALL_CATEGORIES,
            "strconv.ParseFloat": _ALL_CATEGORIES,
            "html.EscapeString": _HTML_ONLY,
            # url.QueryEscape mã hoá cả dấu nháy đơn.
            "url.QueryEscape": _ALL_CATEGORIES,
            "template.HTMLEscapeString": _HTML_ONLY,
            "filepath.Base": frozenset({Category.PATH, Category.DYNAMIC_IMPORT}),
            "path.Base": frozenset({Category.PATH, Category.DYNAMIC_IMPORT}),
            "uuid.Parse": _ALL_CATEGORIES,
        },
        declaration_keywords=frozenset({"var", "const"}),
        assignment_operators=("=", ":=", "+="),
        receiver_propagators=frozenset({"WriteString"}),
        value_accessors=frozenset({"String"}),
    ),
    CSHARP: LanguageSpec(
        language=CSHARP,
        lexer=_CSHARP_LEXER,
        sources=_CSHARP_SOURCES,
        sinks=_CSHARP_SINKS,
        sanitizers={
            "int.Parse": _ALL_CATEGORIES,
            "Int32.Parse": _ALL_CATEGORIES,
            "Int64.Parse": _ALL_CATEGORIES,
            "long.Parse": _ALL_CATEGORIES,
            "Convert.ToInt32": _ALL_CATEGORIES,
            "Convert.ToInt64": _ALL_CATEGORIES,
            "Guid.Parse": _ALL_CATEGORIES,
            "HttpUtility.HtmlEncode": _HTML_ONLY,
            "WebUtility.HtmlEncode": _HTML_ONLY,
            "HtmlEncoder.Default.Encode": _HTML_ONLY,
            "AntiXss.HtmlEncode": _HTML_ONLY,
            "Uri.EscapeDataString": _ALL_CATEGORIES,
            "HttpUtility.UrlEncode": _ALL_CATEGORIES,
            "Path.GetFileName": frozenset({Category.PATH, Category.DYNAMIC_IMPORT}),
        },
        declaration_keywords=frozenset({"var", "string", "int", "object"}),
        receiver_propagators=frozenset({"Append", "AppendLine", "AppendFormat", "Insert"}),
        builder_constructors=frozenset({"StringBuilder"}),
        value_accessors=frozenset({"ToString"}),
        attribute_sources=_CSHARP_ATTRIBUTE_SOURCES,
        handler_annotations=_CSHARP_HANDLERS,
        handler_parameter_types=frozenset({"string", "String"}),
        handler_parameter_exclusions=frozenset({"FromServices", "FromKeyedServices"}),
    ),
    SHELL: LanguageSpec(
        language=SHELL,
        lexer=_SHELL_LEXER,
        sources=_SHELL_SOURCES,
        sinks=_SHELL_SINKS,
        sanitizers={"printf": _COMMAND_ONLY},
        backtick_command=True,
    ),
    RUST: LanguageSpec(
        language=RUST,
        lexer=_RUST_LEXER,
        sources=_RUST_SOURCES,
        sinks=_RUST_SINKS,
        sanitizers={
            # parse::<T>() trả về Result nên phần khử độc chỉ có thật khi kết
            # quả được mở ra; giữ ở mức khử sạch vì con số qua được parse
            # không còn ký tự đặc biệt nào của bất kỳ nhóm nào.
            "parse": _ALL_CATEGORIES,
            "from_str_radix": _ALL_CATEGORIES,
            "Uuid.parse_str": _ALL_CATEGORIES,
            "shell_escape.escape": _COMMAND_ONLY,
            "html_escape.encode_safe": _HTML_ONLY,
            "askama_escape.escape": _HTML_ONLY,
            "urlencoding.encode": _ALL_CATEGORIES,
        },
        declaration_keywords=frozenset({"let", "const", "static"}),
        chain_separators=(".", "::"),
        annotation_separator=":",
        assignment_operators=("=", "+="),
    ),
    POWERSHELL: LanguageSpec(
        language=POWERSHELL,
        lexer=_POWERSHELL_LEXER,
        sources=_POWERSHELL_SOURCES,
        sinks=_POWERSHELL_SINKS,
        sanitizers={
            "int": _ALL_CATEGORIES,
            "long": _ALL_CATEGORIES,
            "guid": _ALL_CATEGORIES,
            "System.Web.HttpUtility.HtmlEncode": _HTML_ONLY,
            "System.Web.HttpUtility.UrlEncode": _ALL_CATEGORIES,
        },
        chain_separators=(".", "::"),
        cast_delimiters=("[", "]"),
        # PowerShell gọi cmdlet KHÔNG có dấu ngoặc: `Invoke-Expression $x`.
        # Thiếu bảng này thì mọi sink của ngôn ngữ chỉ khớp ở dạng viết bằng
        # cú pháp .NET, tức là gần như không bao giờ khớp.
        bare_call_names=frozenset(
            {
                "Invoke-Expression",
                "iex",
                "IEX",
                "Invoke-Command",
                "Add-Type",
                "Start-Process",
                "Start-Job",
                "Invoke-Item",
                "Import-Module",
                "Invoke-WebRequest",
                "Invoke-RestMethod",
                "Invoke-Sqlcmd",
                "Get-Content",
                "Set-Content",
                "Out-File",
                "Remove-Item",
            }
        ),
    ),
    PERL: LanguageSpec(
        language=PERL,
        lexer=_PERL_LEXER,
        sources=_PERL_SOURCES,
        sinks=_PERL_SINKS,
        sanitizers={
            "int": _ALL_CATEGORIES,
            "uri_escape": _ALL_CATEGORIES,
            "encode_entities": _HTML_ONLY,
            "String.ShellQuote.shell_quote": _COMMAND_ONLY,
            "shell_quote": _COMMAND_ONLY,
            # quotemeta() thoát ký tự đặc biệt của REGEX. Dấu chấm phẩy, ống
            # dẫn và dấu nháy đơn không nằm trong tập đó, nên nó không cứu
            # được sink nào ở đây -- cùng lý do với preg_quote() của PHP.
            "quotemeta": _NOTHING,
        },
        declaration_keywords=frozenset({"my", "our", "local"}),
        chain_separators=("->", "::"),
        backtick_command=True,
    ),
    LUA: LanguageSpec(
        language=LUA,
        lexer=_LUA_LEXER,
        sources=_LUA_SOURCES,
        sinks=_LUA_SINKS,
        sanitizers={
            "tonumber": _ALL_CATEGORIES,
            "ngx.escape_uri": _ALL_CATEGORIES,
            "ngx.quote_sql_str": frozenset({Category.SQL}),
        },
        declaration_keywords=frozenset({"local"}),
    ),
    C: LanguageSpec(
        language=C,
        lexer=_NATIVE_LEXER,
        sources=_NATIVE_SOURCES,
        sinks=_NATIVE_SINKS,
        sanitizers=_NATIVE_SANITIZERS,
        chain_separators=(".", "->", "::"),
        assignment_operators=("=", "+="),
        fill_sources=_NATIVE_FILLS,
        propagators=_NATIVE_PROPAGATORS,
        strip_preprocessor=True,
        low_signal_sources=_NATIVE_LOW_SIGNAL,
        argument_sources=_NATIVE_ARGUMENT_SOURCES,
        stream_sources={"std.cin": STANDARD_INPUT, "cin": STANDARD_INPUT},
        literal_assignments=True,
        value_accessors=frozenset({"c_str", "data", "str", "UTF8String"}),
    ),
    CPP: LanguageSpec(
        language=CPP,
        lexer=_NATIVE_LEXER,
        sources=_NATIVE_SOURCES,
        sinks=_NATIVE_SINKS,
        sanitizers=_NATIVE_SANITIZERS,
        chain_separators=(".", "->", "::"),
        assignment_operators=("=", "+="),
        fill_sources=_NATIVE_FILLS,
        propagators=_NATIVE_PROPAGATORS,
        strip_preprocessor=True,
        low_signal_sources=_NATIVE_LOW_SIGNAL,
        argument_sources=_NATIVE_ARGUMENT_SOURCES,
        stream_sources={"std.cin": STANDARD_INPUT, "cin": STANDARD_INPUT},
        literal_assignments=True,
        value_accessors=frozenset({"c_str", "data", "str", "UTF8String"}),
    ),
    OBJC: LanguageSpec(
        language=OBJC,
        lexer=_NATIVE_LEXER,
        sources=_NATIVE_SOURCES,
        sinks=_NATIVE_SINKS,
        sanitizers=_NATIVE_SANITIZERS,
        chain_separators=(".", "->", "::"),
        assignment_operators=("=", "+="),
        fill_sources=_NATIVE_FILLS,
        propagators=_NATIVE_PROPAGATORS,
        strip_preprocessor=True,
        low_signal_sources=_NATIVE_LOW_SIGNAL,
        argument_sources=_NATIVE_ARGUMENT_SOURCES,
        stream_sources={"std.cin": STANDARD_INPUT, "cin": STANDARD_INPUT},
        literal_assignments=True,
        value_accessors=frozenset({"c_str", "data", "str", "UTF8String"}),
    ),
}


def _register_application_languages() -> None:
    # Đặt ở tệp riêng để bảng này không phình thêm hàng nghìn dòng; tệp đó
    # dùng lại các hằng ở trên nên chỉ nạp được sau khi chúng đã có.
    from .profiles_app import APPLICATION_SPECS

    SPECS.update(APPLICATION_SPECS)


_register_application_languages()


def spec_for(language: str) -> Optional[LanguageSpec]:
    return SPECS.get(language)
