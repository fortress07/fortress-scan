"""Mỗi họ rule mà README ghi cho một ngôn ngữ có ít nhất một mẫu ở đây bắt được.

Bảng ngôn ngữ trong README đếm số họ rule bắt được của từng ngôn ngữ quét
theo token. Con số đó lấy từ chính bảng này, nên README không ghi được một họ
mà máy quét chưa bắt thật.
"""

from __future__ import annotations

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import CSHARP, GO, GROOVY, JAVA, KOTLIN, SCALA

_JAVA = (
    "class A {\n"
    "  void a(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
    '    String v = request.getParameter("v");\n'
    "    %s;\n"
    "  }\n"
    "}\n"
)
_KOTLIN = (
    "class A {\n"
    "  fun a(request: HttpServletRequest, response: HttpServletResponse) {\n"
    '    val v = request.getParameter("v")\n'
    "    %s\n"
    "  }\n"
    "}\n"
)
_GROOVY = (
    "class A {\n"
    "  def a(HttpServletRequest request, HttpServletResponse response) {\n"
    '    def v = request.getParameter("v")\n'
    "    %s\n"
    "  }\n"
    "}\n"
)
_SCALA = (
    "class C @Inject()(ws: WSClient) extends InjectedController {\n"
    "  def a(v: String) = Action { implicit request =>\n"
    "    %s\n"
    "  }\n"
    "}\n"
)
_GO = (
    "package main\n"
    "func h(w http.ResponseWriter, r *http.Request) {\n"
    '\tv := r.URL.Query().Get("v")\n'
    "\t%s\n"
    "}\n"
)
_CSHARP = (
    "public class C : Controller {\n"
    "  public IActionResult A() {\n"
    '    var v = Request.Query["v"];\n'
    "    %s;\n"
    "    return Ok();\n"
    "  }\n"
    "}\n"
)

_JVM_SINKS = {
    "CMD": "Runtime.getRuntime().exec(v)",
    "SQL": "stmt.executeQuery(\"SELECT * FROM t WHERE a = '\" + v + \"'\")",
    "EL": "new SpelExpressionParser().parseExpression(v)",
    "EXEC": "engine.eval(v)",
    "PATH": 'new File("/data", v)',
    "REDIR": "response.sendRedirect(v)",
    "SSRF": "new URL(v).openStream()",
    "XSS": "response.getWriter().write(v)",
    "HDR": 'response.setHeader("X-A", v)',
    "LDAP": 'ctx.search("ou=people", "(uid=" + v + ")", controls)',
    "XPATH": "xpath.evaluate(\"//user[@name='\" + v + \"']\", doc)",
    "DESER": "new Yaml().load(v)",
    "TMPL": 'Velocity.evaluate(context, writer, "t", v)',
    "IMPORT": "Class.forName(v)",
}

CASES = [
    *[(JAVA, family, _JAVA % sink) for family, sink in _JVM_SINKS.items()],
    *[(KOTLIN, family, _KOTLIN % sink.replace("new ", "")) for family, sink in _JVM_SINKS.items()],
    *[(GROOVY, family, _GROOVY % sink) for family, sink in _JVM_SINKS.items()],
    (SCALA, "CMD", _SCALA % 'Seq("sh", "-c", v).!!'),
    (SCALA, "SQL", _SCALA % 'SQL(s"SELECT * FROM t WHERE a = \'$v\'").as(parser.*)'),
    (SCALA, "PATH", _SCALA % 'new File("/data", v)'),
    (SCALA, "REDIR", _SCALA % "Redirect(v)"),
    (SCALA, "SSRF", _SCALA % "ws.url(v).get()"),
    (SCALA, "XSS", _SCALA % 'Ok(Html(s"<p>$v</p>"))'),
    (SCALA, "EXEC", _SCALA % "tb.eval(tb.parse(v))"),
    (SCALA, "DESER", _SCALA % "new Yaml().load(v)"),
    (SCALA, "IMPORT", _SCALA % "Class.forName(v)"),
    (GO, "CMD", _GO % 'exec.Command("sh", "-c", v).Run()'),
    (GO, "SQL", _GO % 'db.Query("SELECT * FROM t WHERE a = \'" + v + "\'")'),
    (GO, "PATH", _GO % "os.Open(v)"),
    (GO, "REDIR", _GO % "http.Redirect(w, r, v, 302)"),
    (GO, "SSRF", _GO % "http.Get(v)"),
    (GO, "XSS", _GO % 'fmt.Fprintf(w, "<p>%s</p>", v)'),
    (GO, "HDR", _GO % 'w.Header().Set("X-A", v)'),
    (GO, "TMPL", _GO % 'template.New("t").Parse(v)'),
    (CSHARP, "CMD", _CSHARP % 'Process.Start("cmd.exe", "/c " + v)'),
    (CSHARP, "SQL", _CSHARP % "new SqlCommand(\"SELECT * FROM t WHERE a = '\" + v + \"'\", conn)"),
    (CSHARP, "PATH", _CSHARP % "System.IO.File.ReadAllText(v)"),
    (CSHARP, "REDIR", _CSHARP % "Response.Redirect(v)"),
    (CSHARP, "SSRF", _CSHARP % "new HttpClient().GetStringAsync(v)"),
    (CSHARP, "XSS", _CSHARP % "Response.Write(v)"),
    (CSHARP, "HDR", _CSHARP % 'Response.Headers.Add("X-A", v)'),
    (CSHARP, "LDAP", _CSHARP % 'new DirectorySearcher(entry, "(uid=" + v + ")")'),
    (CSHARP, "XPATH", _CSHARP % "doc.SelectNodes(\"//user[@name='\" + v + \"']\")"),
    (CSHARP, "DESER", _CSHARP % "new BinaryFormatter().Deserialize(new MemoryStream(Convert.FromBase64String(v)))"),
    (CSHARP, "EXEC", _CSHARP % "CSharpScript.EvaluateAsync(v)"),
    (CSHARP, "IMPORT", _CSHARP % "Type.GetType(v)"),
]


def families(source: str, language: str):
    return {f.rule_id.rsplit("-", 1)[0].replace("FSB-", "") for f in scan_source(source, language, "mau", Config())}


@pytest.mark.parametrize(
    ("language", "family", "source"),
    CASES,
    ids=["%s-%s" % (language, family) for language, family, _ in CASES],
)
def test_family_is_caught(language: str, family: str, source: str):
    assert family in families(source, language)


def coverage():
    """Số họ rule bắt được cho từng ngôn ngữ, dùng cho bảng trong README."""
    counts = {}
    for language, family, _ in CASES:
        counts.setdefault(language, set()).add(family)
    return {language: len(found) for language, found in counts.items()}
