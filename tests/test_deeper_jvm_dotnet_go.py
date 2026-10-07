"""Java, C# và Go: những cách viết phổ biến nhất mà bộ token trước đây bỏ sót.

Mỗi phát hiện mới đi kèm một bản viết đúng phải im lặng: câu SQL dựng sẵn trong
một biến rồi mới truyền vào executeQuery / db.Query / new SqlCommand, tham số
handler không annotation của Spring và ASP.NET, cùng các sink path, redirect,
SSRF, XSS của thư viện chuẩn.
"""

from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import CSHARP, GO, JAVA


def hits(source: str, language: str):
    return sorted((f.rule_id, f.line) for f in scan_source(source, language, "mau", Config()))


# ------------------------------------------------------------------------ Java


def test_java_query_built_in_a_variable_then_executed():
    source = (
        "class A {\n"
        "  void a(HttpServletRequest request, Connection conn) throws Exception {\n"
        '    String id = request.getParameter("id");\n'
        '    String q = "SELECT * FROM users WHERE id = " + id;\n'
        "    conn.createStatement().executeQuery(q);\n"
        "  }\n"
        "}\n"
    )
    assert hits(source, JAVA) == [("FSB-SQL-001", 5)]


def test_java_placeholder_query_in_a_variable_is_silent():
    source = (
        "class A {\n"
        "  void a(HttpServletRequest request, Connection conn) throws Exception {\n"
        '    String id = request.getParameter("id");\n'
        '    String q = "SELECT * FROM users WHERE id = ?";\n'
        "    PreparedStatement ps = conn.prepareStatement(q);\n"
        "    ps.setString(1, id);\n"
        "    int n = Integer.parseInt(id);\n"
        '    conn.createStatement().executeQuery("SELECT * FROM t LIMIT " + n);\n'
        "  }\n"
        "}\n"
    )
    assert hits(source, JAVA) == []


def test_java_string_builder_carries_taint_and_literal_builder_is_silent():
    source = (
        "class A {\n"
        "  void a(HttpServletRequest request, Statement st) throws Exception {\n"
        '    StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE a = ");\n'
        '    sb.append(request.getParameter("a"));\n'
        "    st.executeQuery(sb.toString());\n"
        '    StringBuilder ok = new StringBuilder("SELECT * FROM t");\n'
        '    ok.append(" WHERE a = ?").append(" LIMIT 10");\n'
        "    st.executeQuery(ok.toString());\n"
        "  }\n"
        "}\n"
    )
    assert hits(source, JAVA) == [("FSB-SQL-001", 5)]


def test_spring_handler_parameters_without_annotation_are_request_data():
    source = (
        "class C {\n"
        '  @GetMapping("/f")\n'
        "  public String find(String name, @PathVariable Long pid, Model model) {\n"
        '    jdbcTemplate.query("SELECT * FROM u WHERE n = \'" + name + "\'", mapper);\n'
        '    jdbcTemplate.query("SELECT * FROM u WHERE id = " + pid, mapper);\n'
        '    return "redirect:" + name;\n'
        "  }\n"
        "  public String helper(String name) {\n"
        '    return "redirect:" + name;\n'
        "  }\n"
        "}\n"
    )
    # pid đã được Spring parse thành Long; helper() không phải handler.
    assert hits(source, JAVA) == [("FSB-REDIR-001", 6), ("FSB-SQL-001", 4)]


def test_java_path_redirect_and_pattern_compile():
    source = (
        "class A {\n"
        "  void a(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        '    String f = request.getParameter("f");\n'
        '    File file = new File("/data", f);\n'
        "    response.sendRedirect(f);\n"
        "    Pattern p = Pattern.compile(f);\n"
        '    File ok = new File("/data", FilenameUtils.getName(f));\n'
        "  }\n"
        "}\n"
    )
    # Pattern.compile là regex chứ không phải XPath.
    assert hits(source, JAVA) == [("FSB-PATH-001", 4), ("FSB-REDIR-001", 5)]


def test_java_redirect_with_a_fixed_origin_is_silent():
    source = (
        "class A {\n"
        "  void a(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        '    String f = request.getParameter("f");\n'
        '    response.sendRedirect("/" + f);\n'
        '    response.sendRedirect("/\\\\" + f);\n'
        '    response.sendRedirect("https://example.com" + f);\n'
        '    response.sendRedirect("http" + f);\n'
        '    response.sendRedirect("/login?next=" + f);\n'
        '    response.sendRedirect("/files/" + f);\n'
        '    response.sendRedirect("https://example.com/" + f);\n'
        '    response.sendRedirect("/" + owner + "/x?q=" + f);\n'
        '    response.sendRedirect("page_" + f);\n'
        "  }\n"
        "}\n"
    )
    # Bốn dòng đầu thì giá trị bẩn còn chọn được máy chủ ( `//evil`, `/\evil`,
    # `example.com.evil`, `https://evil` ); các dòng sau thì không.
    assert hits(source, JAVA) == [
        ("FSB-REDIR-001", 4),
        ("FSB-REDIR-001", 5),
        ("FSB-REDIR-001", 6),
        ("FSB-REDIR-001", 7),
    ]


def test_java_constant_names_and_uri_of_the_own_request():
    source = (
        "class A {\n"
        "  void a(HttpServletRequest request, SQLiteDatabase db, String where) throws Exception {\n"
        '    db.rawQuery("SELECT " + LocalStore.FOLDER_COLS + " FROM folders", null);\n'
        '    db.rawQuery("SELECT * FROM t WHERE " + where, null);\n'
        "    URI uri = URI.create(request.getRequestURI());\n"
        "  }\n"
        "}\n"
    )
    assert hits(source, JAVA) == [("FSB-SQL-002", 4)]


# -------------------------------------------------------------------------- C#


def test_csharp_action_parameters_and_command_text_variable():
    source = (
        "public class C : Controller {\n"
        '  [HttpGet("{id}")]\n'
        "  public IActionResult Get(string id, int page, [FromServices] IFoo foo) {\n"
        '    string sql = "SELECT * FROM users WHERE id = " + id;\n'
        "    var cmd = new SqlCommand(sql, conn);\n"
        '    var text = System.IO.File.ReadAllText(Path.Combine("/data", id));\n'
        '    var ok = System.IO.File.ReadAllText(Path.Combine("/data", Path.GetFileName(id)));\n'
        "    return Redirect(id);\n"
        "  }\n"
        "}\n"
    )
    assert hits(source, CSHARP) == [("FSB-PATH-001", 6), ("FSB-REDIR-001", 8), ("FSB-SQL-001", 5)]


def test_csharp_cmd_wrapper_is_a_shell_command():
    source = (
        "public class C : Controller {\n"
        "  public void Run() {\n"
        '    var q = Request.Query["host"];\n'
        '    Process.Start("cmd.exe", "/c ping " + q);\n'
        '    Process.Start("ping.exe", "-n 1 example.org");\n'
        "  }\n"
        "}\n"
    )
    assert hits(source, CSHARP) == [("FSB-CMD-001", 4)]


def test_csharp_interpolated_redirect_with_a_fixed_path():
    source = (
        "public class C : Controller {\n"
        "  [HttpGet]\n"
        "  public IActionResult Get(string id) {\n"
        '    if (a) return Redirect($"/items/{id}");\n'
        '    return Redirect($"{id}");\n'
        "  }\n"
        "}\n"
    )
    assert hits(source, CSHARP) == [("FSB-REDIR-001", 5)]


def test_csharp_command_text_and_ldap_filter_properties():
    source = (
        "public class C : Controller {\n"
        "  public IActionResult A() {\n"
        '    var v = Request.Query["v"];\n'
        "    cmd.CommandText = \"SELECT * FROM t WHERE a = '\" + v + \"'\";\n"
        '    cmd.CommandText = "SELECT * FROM t WHERE a = @a";\n'
        '    searcher.Filter = "(uid=" + v + ")";\n'
        '    searcher.Filter = "(uid=" + Encoder.LdapFilterEncode(v) + ")";\n'
        "    return Ok();\n"
        "  }\n"
        "}\n"
    )
    assert hits(source, CSHARP) == [("FSB-LDAP-001", 6), ("FSB-SQL-001", 4)]


def test_csharp_from_query_attribute():
    source = (
        "public class C : ControllerBase {\n"
        "  public IActionResult Find([FromQuery] string name) {\n"
        "    return Content(System.IO.File.ReadAllText(name));\n"
        "  }\n"
        "}\n"
    )
    assert hits(source, CSHARP) == [("FSB-PATH-001", 3)]


# -------------------------------------------------------------------------- Go


def test_go_prebuilt_query_and_placeholder_query():
    source = (
        "package main\n"
        "func h(w http.ResponseWriter, r *http.Request) {\n"
        '\tid := r.URL.Query().Get("id")\n'
        '\tq := "SELECT * FROM users WHERE id = " + id\n'
        "\trows, _ := db.Query(q)\n"
        '\tsafe := "SELECT * FROM users WHERE id = $1"\n'
        "\trows2, _ := db.Query(safe, id)\n"
        "}\n"
    )
    assert hits(source, GO) == [("FSB-SQL-001", 5)]


def test_go_path_redirect_ssrf_and_response_writer():
    source = (
        "package main\n"
        "func h(w http.ResponseWriter, r *http.Request) {\n"
        '\tid := r.URL.Query().Get("id")\n'
        '\tf, _ := os.Open(filepath.Join("/data", id))\n'
        '\tg, _ := os.Open(filepath.Join("/data", filepath.Base(id)))\n'
        "\thttp.Redirect(w, r, id, 302)\n"
        "\tresp, _ := http.Get(id)\n"
        '\tfmt.Fprintf(w, "<p>%s</p>", id)\n'
        '\tfmt.Fprintf(os.Stderr, "bad %s", id)\n'
        "}\n"
    )
    assert hits(source, GO) == [
        ("FSB-PATH-001", 4),
        ("FSB-REDIR-001", 6),
        ("FSB-SSRF-001", 7),
        ("FSB-XSS-001", 8),
    ]
