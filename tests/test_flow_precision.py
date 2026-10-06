"""Độ chính xác của luồng: nhánh chết, tập hợp theo khóa, sink đọc từ đối tượng.

Mỗi mẫu là một biến thể nhỏ của mẫu kiểm thử OWASP Benchmark: cùng một luồng
từ request tới SQL, chỉ khác ở chỗ giá trị bẩn có thật sự tới được sink hay
không. Bản thật phải bị báo, bản an toàn phải im.
"""

from __future__ import annotations

from pathlib import Path

from fortress_scan.analysis.generic import folding
from fortress_scan.analysis.generic.lexer import tokenize
from fortress_scan.analysis.generic.profiles import spec_for
from fortress_scan.core.budget import Budget
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan

HEAD = (
    "import javax.servlet.http.*;\n"
    "public class T extends HttpServlet {\n"
    "    public void doPost(HttpServletRequest request) throws Exception {\n"
    "        String param = request.getParameter(\"a\");\n"
    "        String bar = \"safe\";\n"
)
TAIL = (
    "        java.sql.Statement statement = DatabaseHelper.getSqlStatement();\n"
    "        statement.execute(\"SELECT * FROM users WHERE name = '\" + bar + \"'\");\n"
    "    }\n"
    "}\n"
)


def _sql_hits(tmp_path: Path, body: str):
    (tmp_path / "T.java").write_text(HEAD + body + TAIL, encoding="utf-8")
    findings = scan(str(tmp_path), Config()).findings
    return [f for f in findings if f.rule_id == "FSB-SQL-001"]


def _fold(text: str, env=None):
    spec = spec_for("java")
    tokens = tokenize(text, spec.lexer, Budget(10_000, 5))
    return folding.fold(tokens, env or {})


def test_fold_arithmetic_strings_and_chars():
    assert _fold("(7 * 42) - num > 200", {"num": 86}) is True
    assert _fold("(7 * 42) - num > 200", {"num": 106}) is False
    assert _fold("(500 / 42) + num > 200", {"num": 196}) is True
    assert _fold("-7 / 2") == -3
    assert _fold("guess.charAt(1)", {"guess": "ABC"}) == "B"
    assert _fold("\"ab\" + 1") == "ab1"
    assert _fold("param != null", {}) is None
    assert _fold("x.size() > 0", {"x": "abc"}) is None


def test_constant_condition_kills_only_the_dead_branch(tmp_path: Path):
    # 7 * 42 - 86 = 208 > 200: nhánh if luôn chạy, nhánh else chết.
    body = (
        "        int num = 86;\n"
        "        if ((7 * 42) - num > 200) bar = \"This_should_always_happen\";\n"
        "        else bar = param;\n"
    )
    assert _sql_hits(tmp_path, body) == []
    body = (
        "        int num = 86;\n"
        "        if ((7 * 42) - num > 200) bar = param;\n"
        "        else bar = \"This_should_never_happen\";\n"
    )
    assert len(_sql_hits(tmp_path, body)) == 1


def test_braced_branches_and_ternary(tmp_path: Path):
    braced = (
        "        int num = %d;\n"
        "        if ((7 * 42) - num > 200) {\n"
        "            bar = param;\n"
        "        } else {\n"
        "            bar = \"x\";\n"
        "        }\n"
    )
    assert len(_sql_hits(tmp_path, braced % 86)) == 1
    assert _sql_hits(tmp_path, braced % 106) == []
    body = "        int num = 106;\n        bar = (7 * 18) + num > 200 ? \"always\" : param;\n"
    assert _sql_hits(tmp_path, body) == []
    body = "        int num = 106;\n        bar = (7 * 18) + num > 200 ? param : \"never\";\n"
    assert len(_sql_hits(tmp_path, body)) == 1


def test_unknown_condition_keeps_both_branches(tmp_path: Path):
    body = "        if (param.length() > 3) {\n            bar = param;\n        }\n"
    assert len(_sql_hits(tmp_path, body)) == 1
    body = "        if (param == null) param = \"\";\n        bar = param;\n"
    assert len(_sql_hits(tmp_path, body)) == 1


def test_switch_on_constant_follows_fallthrough(tmp_path: Path):
    switch = (
        "        String guess = \"ABC\";\n"
        "        char target = guess.charAt(%d);\n"
        "        switch (target) {\n"
        "            case 'A':\n"
        "                bar = param;\n"
        "                break;\n"
        "            case 'B':\n"
        "                bar = \"bob\";\n"
        "                break;\n"
        "            case 'C':\n"
        "            case 'D':\n"
        "                bar = param;\n"
        "                break;\n"
        "            default:\n"
        "                bar = \"uncle\";\n"
        "                break;\n"
        "        }\n"
    )
    assert _sql_hits(tmp_path, switch % 1) == []
    assert len(_sql_hits(tmp_path, switch % 2)) == 1


def test_map_and_list_track_constant_keys_and_indexes(tmp_path: Path):
    body = (
        "        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n"
        "        map.put(\"keyA\", \"a-Value\");\n"
        "        map.put(\"keyB\", param);\n"
        "        bar = (String) map.get(\"%s\");\n"
    )
    assert _sql_hits(tmp_path, body % "keyA") == []
    assert len(_sql_hits(tmp_path, body % "keyB")) == 1
    body = (
        "        java.util.List<String> values = new java.util.ArrayList<String>();\n"
        "        values.add(\"safe\");\n"
        "        values.add(param);\n"
        "        values.add(\"moresafe\");\n"
        "        values.remove(0);\n"
        "        bar = values.get(%d);\n"
    )
    assert _sql_hits(tmp_path, body % 1) == []
    assert len(_sql_hits(tmp_path, body % 0)) == 1


def test_unmodelled_mutation_falls_back_to_whole_collection(tmp_path: Path):
    body = (
        "        java.util.HashMap<String, Object> store = new java.util.HashMap<String, Object>();\n"
        "        store.put(param, param);\n"
        "        bar = (String) store.get(\"keyA\");\n"
    )
    assert len(_sql_hits(tmp_path, body)) == 1


def test_prepared_statement_built_from_tainted_sql(tmp_path: Path):
    (tmp_path / "T.java").write_text(
        HEAD
        + "        String sql = \"SELECT * FROM users WHERE name = '\" + param + \"'\";\n"
        "        java.sql.PreparedStatement st = connection.prepareStatement(sql);\n"
        "        st.execute();\n"
        "        java.sql.PreparedStatement ok = connection.prepareStatement(\"SELECT * FROM users WHERE name = ?\");\n"
        "        ok.setString(1, param);\n"
        "        ok.execute();\n"
        "    }\n}\n",
        encoding="utf-8",
    )
    findings = scan(str(tmp_path), Config()).findings
    assert [(f.rule_id, f.line) for f in findings] == [("FSB-SQL-001", 8)]


def test_foreach_over_tainted_collection(tmp_path: Path):
    body = (
        "        for (javax.servlet.http.Cookie c : request.getCookies()) {\n"
        "            if (c.getName().equals(\"x\")) {\n"
        "                bar = c.getValue();\n"
        "            }\n"
        "        }\n"
    )
    assert len(_sql_hits(tmp_path, body)) == 1
