"""Kotlin, Scala, Groovy và Jenkinsfile.

Cả ba chạy trên JVM nên dùng lại bảng sink của Java; cái khác nằm ở cú pháp
chuỗi, và chính ở đó là chỗ dễ bắt nhầm nhất:

* Kotlin và Groovy nội suy `"$x"` trong MỌI chuỗi nháy kép;
* Scala chỉ nội suy khi có tiền tố ( `s"..."` ), còn `sql"..."` của Slick hay
  doobie lại biến giá trị thành tham số bind;
* GString đưa vào `groovy.sql.Sql` cũng được bind, còn nối bằng `+` thì không;
* `sh '...'` nháy đơn trong Jenkinsfile để shell tự khai triển biến môi trường,
  nên nó an toàn, còn `sh "..."` dán giá trị vào lệnh trước khi shell thấy.

Mỗi phát hiện đi kèm bản viết đúng phải im lặng.
"""

from __future__ import annotations

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Severity
from fortress_scan.languages import GROOVY, KOTLIN, PHP, SCALA, detect_language, language_from_name


def hits(source: str, language: str):
    return sorted((f.rule_id, f.line) for f in scan_source(source, language, "mau", Config()))


# ---------------------------------------------------------------------- Kotlin


def test_kotlin_spring_template_string_reaches_jdbc():
    source = (
        "@RestController\n"
        "class UserController(private val jdbc: JdbcTemplate) {\n"
        '    @GetMapping("/users")\n'
        "    fun find(@RequestParam name: String, @RequestParam page: Int): List<User> {\n"
        "        val sql = \"SELECT * FROM users WHERE name = '$name' LIMIT ${page * 10}\"\n"
        "        return jdbc.queryForList(sql)\n"
        "    }\n"
        "}\n"
    )
    assert hits(source, KOTLIN) == [("FSB-SQL-001", 6)]


def test_kotlin_bound_parameters_and_numbers_are_silent():
    source = (
        "@RestController\n"
        "class UserController(private val jdbc: JdbcTemplate) {\n"
        '    @GetMapping("/users")\n'
        "    fun find(@RequestParam name: String, @RequestParam page: Int): List<User> {\n"
        '        jdbc.query("SELECT * FROM users WHERE name = ?", mapper, name)\n'
        '        return jdbc.queryForList("SELECT * FROM users LIMIT ${page * 10}")\n'
        "    }\n"
        "}\n"
    )
    assert hits(source, KOTLIN) == []


def test_kotlin_ktor_shell_wrapper_and_safe_conversion():
    source = (
        "fun Application.routes() {\n"
        "    routing {\n"
        '        get("/ping") {\n'
        '            val host = call.request.queryParameters["host"]\n'
        '            ProcessBuilder(listOf("sh", "-c", "ping -c1 $host")).start()\n'
        '            val n = call.parameters["n"]?.toIntOrNull() ?: 1\n'
        '            ProcessBuilder(listOf("sh", "-c", "sleep $n")).start()\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert hits(source, KOTLIN) == [("FSB-CMD-001", 5)]


def test_kotlin_android_intent_into_raw_query():
    source = (
        "class Exported : Activity() {\n"
        "    override fun onCreate(b: Bundle?) {\n"
        '        val q = intent.getStringExtra("q")\n'
        "        db.rawQuery(\"SELECT * FROM notes WHERE title = '\" + q + \"'\", null)\n"
        '        db.rawQuery("SELECT * FROM notes WHERE title = ?", arrayOf(q))\n'
        "    }\n"
        "}\n"
    )
    assert hits(source, KOTLIN) == [("FSB-SQL-001", 4)]


def test_kotlin_backtick_test_names_do_not_open_a_string():
    """`fun \\`tra ve "loi"\\`()`: dấu nháy kép trong tên hàm không mở chuỗi."""
    source = (
        "class T {\n"
        '    fun `tra ve "loi" khi rong`() {}\n'
        "    fun h(call: ApplicationCall) {\n"
        '        val f = call.request.queryParameters["f"]\n'
        '        File("/srv", f).readText()\n'
        "    }\n"
        "}\n"
    )
    assert hits(source, KOTLIN) == [("FSB-PATH-001", 5)]


def test_kotlin_const_names_inside_a_raw_string_are_constants():
    source = (
        'private const val TABLE_NAME = "prefs"\n'
        "fun create(db: SQLiteDatabase, column: String) {\n"
        '    db.execSQL("""\n'
        "        CREATE TABLE $TABLE_NAME ( $column TEXT )\n"
        '        """.trimIndent())\n'
        '    db.execSQL("""CREATE TABLE $TABLE_NAME ( v TEXT )""".trimIndent())\n'
        "}\n"
    )
    # Chỉ câu thứ nhất có một tên không phải hằng ( column ).
    assert hits(source, KOTLIN) == [("FSB-SQL-002", 3)]


def test_kotlin_spring_redirect_with_a_fixed_path_is_not_open():
    source = (
        '@GetMapping("/r")\n'
        "fun r(name: String): String {\n"
        '    if (a) return "redirect:/home/$name"\n'
        '    if (b) return "redirect:/login?next=$name"\n'
        '    return "redirect:$name"\n'
        "}\n"
    )
    assert hits(source, KOTLIN) == [("FSB-REDIR-001", 5)]


def test_php_concatenation_dot_is_not_a_method_on_the_literal():
    # `"...".trimIndent()` chỉ là phương thức của literal ở ngôn ngữ dùng `.` để
    # truy cập thành viên; `.` của PHP là phép nối, nên $cmd vẫn là giá trị lạ.
    source = '<?php\nfunction f($cmd) {\n  system("ls " . $cmd);\n}\n'
    assert hits(source, PHP) == [("FSB-CMD-003", 3)]


# ----------------------------------------------------------------------- Scala


def test_scala_play_action_parameters_and_interpolators():
    source = (
        "class Home @Inject()(db: Database) extends BaseController {\n"
        "  def search(q: String, page: Int) = Action { implicit request =>\n"
        "    db.withConnection { conn =>\n"
        "      conn.createStatement().executeQuery(s\"SELECT * FROM items WHERE name = '$q'\")\n"
        '      SQL"SELECT * FROM items WHERE name = $q".as(parser.*)\n'
        '      SQL("SELECT * FROM items WHERE name = {q}").on("q" -> q).as(parser.*)\n'
        "    }\n"
        '    Ok(Html(s"<p>$q</p>"))\n'
        "  }\n"
        "}\n"
    )
    assert hits(source, SCALA) == [("FSB-SQL-001", 4), ("FSB-XSS-001", 8)]


def test_scala_plain_strings_do_not_interpolate():
    source = (
        "class Home extends BaseController {\n"
        "  def search(q: String) = Action { implicit request =>\n"
        '    conn.createStatement().executeQuery("SELECT * FROM t WHERE name = \'$q\'")\n'
        "  }\n"
        "}\n"
    )
    # Không có tiền tố `s`: `$q` là chữ, câu SQL là hằng.
    assert hits(source, SCALA) == []


def test_scala_sys_process_runs_without_a_shell_unless_wrapped():
    source = (
        "class Ops extends BaseController {\n"
        "  def ping = Action { request =>\n"
        '    val host = request.getQueryString("host").getOrElse("")\n'
        '    val out = s"ping -c1 $host".!!\n'
        '    val sh = Seq("sh", "-c", s"nslookup $host").!!\n'
        '    val n = request.getQueryString("n").map(_.toInt).getOrElse(1)\n'
        '    val ok = Seq("ping", "-c", "1", "example.org").!!\n'
        "  }\n"
        "}\n"
    )
    assert hits(source, SCALA) == [("FSB-CMD-001", 5), ("FSB-CMD-002", 4)]


def test_scala_akka_directives_bind_lambda_parameters():
    source = (
        "object Routes {\n"
        "  val route =\n"
        '    path("files" / Segment) { name =>\n'
        '      getFromFile(new File("/srv", name))\n'
        "    } ~\n"
        '    parameter("url") { url =>\n'
        "      complete(Source.fromURL(url).mkString)\n"
        "    } ~\n"
        "    path(IntNumber) { id =>\n"
        '      getFromFile(new File("/srv", id.toString))\n'
        "    }\n"
        "}\n"
    )
    assert hits(source, SCALA) == [("FSB-PATH-001", 4), ("FSB-SSRF-001", 7)]


def test_scala_redirect_only_when_the_value_can_pick_the_host():
    source = (
        "object C {\n"
        "  def a(q: String) = Action { implicit request =>\n"
        '    Redirect(s"/${repo.owner}/${repo.name}/pulls?q=${q}")\n'
        '    Redirect(s"/${q}/x")\n'
        '    Redirect(s"/files/${q}")\n'
        '    Redirect("https://" + q)\n'
        "  }\n"
        "}\n"
    )
    # `"/" + q` cho q = `/evil.com` thành `//evil.com`; query và đường dẫn con thì không.
    assert hits(source, SCALA) == [("FSB-REDIR-001", 4), ("FSB-REDIR-001", 6)]


def test_scala_slick_bind_versus_splice():
    source = (
        "object Repo {\n"
        '  val route = parameter("col") { col =>\n'
        '    db.run(sql"SELECT * FROM t WHERE name = $col".as[Int])\n'
        '    db.run(sql"SELECT * FROM t ORDER BY #$col".as[Int])\n'
        "  }\n"
        "}\n"
    )
    assert hits(source, SCALA) == [("FSB-SQL-001", 4)]


# ---------------------------------------------------------------------- Groovy


def test_groovy_sql_binds_gstrings_but_not_concatenation():
    source = (
        "class BookController {\n"
        "    def sql\n"
        "    def search() {\n"
        '        sql.rows("SELECT * FROM book WHERE title = ${params.title}")\n'
        '        def q = "SELECT * FROM book WHERE title = ${params.title}"\n'
        "        sql.rows(q)\n"
        "        sql.rows(\"SELECT * FROM book WHERE title = '\" + params.title + \"'\")\n"
        "        def n = params.id.toInteger()\n"
        '        sql.rows("SELECT * FROM book WHERE id = " + n)\n'
        "    }\n"
        "}\n"
    )
    assert hits(source, GROOVY) == [("FSB-SQL-001", 7)]


def test_groovy_execute_eval_template_and_url():
    source = (
        "class Tools {\n"
        "    def run() {\n"
        '        def out = "git log -1 ${params.ref}".execute().text\n'
        '        def sh = ["sh", "-c", "ls ${params.dir}"].execute().text\n'
        '        def ok = ["git", "log", "-1"].execute().text\n'
        "        Eval.me(params.expr)\n"
        "        new SimpleTemplateEngine().createTemplate(params.tpl).make([:])\n"
        "        def body = params.url.toURL().text\n"
        "        rule.evaluate(ctx)\n"
        "    }\n"
        "}\n"
    )
    assert hits(source, GROOVY) == [
        ("FSB-CMD-001", 4),
        ("FSB-CMD-002", 3),
        ("FSB-EXEC-001", 6),
        ("FSB-SSRF-001", 8),
        ("FSB-TMPL-001", 7),
    ]


# ----------------------------------------------------------------- Jenkinsfile


JENKINSFILE = """pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh "make build VERSION=${env.BUILD_NUMBER}"
                sh "echo Building PR: ${env.CHANGE_TITLE}"
                sh 'echo "Title: $CHANGE_TITLE"'
                sh '''
                    echo "$CHANGE_BRANCH"
                '''
                sh \"\"\"
                    git checkout ${env.CHANGE_BRANCH}
                \"\"\"
                sh(script: "deploy.sh ${params.TARGET}", returnStdout: true)
                bat "deploy.bat ${params.TARGET}"
            }
        }
    }
}
"""


def test_jenkinsfile_double_quoted_steps_with_pr_data_and_parameters():
    assert hits(JENKINSFILE, GROOVY) == [
        ("FSB-CMD-001", 7),
        ("FSB-CMD-001", 12),
        ("FSB-CMD-001", 15),
        ("FSB-CMD-001", 16),
    ]


def test_jenkinsfile_findings_are_high_severity_shell_injection():
    found = [f for f in scan_source(JENKINSFILE, GROOVY, "Jenkinsfile", Config()) if f.line == 7]
    assert [f.severity for f in found] == [Severity.CRITICAL]


def test_a_variable_named_sh_is_not_a_pipeline_step():
    source = 'def sh = params.cmd\nsh.trim()\nprintln(sh)\n'
    assert hits(source, GROOVY) == []


# ------------------------------------------------------------ nhận diện và an toàn


@pytest.mark.parametrize(
    "name,expected",
    [
        ("App.kt", KOTLIN),
        ("build.gradle.kts", KOTLIN),
        ("Main.scala", SCALA),
        ("script.sc", SCALA),
        ("Tool.groovy", GROOVY),
        ("build.gradle", GROOVY),
        ("Jenkinsfile", GROOVY),
        ("Jenkinsfile.release", GROOVY),
        ("ci/Jenkinsfile-nightly", GROOVY),
    ],
)
def test_jvm_files_map_to_their_own_language(tmp_path, name: str, expected: str):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("// x\n", encoding="utf-8")
    assert detect_language(target) == expected
    assert language_from_name(target.name) == expected


@pytest.mark.parametrize("language", [KOTLIN, SCALA, GROOVY])
@pytest.mark.parametrize(
    "source",
    [
        "",
        "\x00\x01",
        '"""' * 7,
        "'''never closed",
        's"${' * 100,
        "$" * 500,
        "`" * 99,
        "((((((((((",
        "@GetMapping(" * 50,
        "parameter(\"a\") {" * 80,
        'sql"#$' * 100,
    ],
)
def test_broken_sources_do_not_raise(language: str, source: str):
    scan_source(source, language, "mau", Config(min_severity=Severity.INFO))


@pytest.mark.parametrize(
    "language,source,line",
    [
        (
            KOTLIN,
            "fun h(call: ApplicationCall) {\n"
            '    val doc = """\n'
            "// fortress-scan: ignore-file\n"
            '"""\n'
            '    val f = call.request.queryParameters["f"]\n'
            '    File("/srv", f).readText()\n'
            "}\n",
            6,
        ),
        (
            GROOVY,
            "def doc = '''\n"
            "// fortress-scan: ignore-file\n"
            "'''\n"
            'sh "echo ${env.CHANGE_TITLE}"\n',
            4,
        ),
        (
            SCALA,
            'val route = parameter("url") { url =>\n'
            '  val doc = s"""\n'
            "// fortress-scan: ignore-file\n"
            '"""\n'
            "  complete(Source.fromURL(url).mkString)\n"
            "}\n",
            5,
        ),
    ],
)
def test_a_directive_inside_a_triple_quoted_string_is_data(language: str, source: str, line: int):
    assert [found_line for _, found_line in hits(source, language)] == [line]


def test_a_real_directive_still_works_in_kotlin():
    source = (
        "fun h(call: ApplicationCall) {\n"
        '    val f = call.request.queryParameters["f"]\n'
        "    // fortress-scan: ignore-next-line\n"
        '    File("/srv", f).readText()\n'
        "}\n"
    )
    assert hits(source, KOTLIN) == []
