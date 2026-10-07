"""Phân tích xuyên file cho JavaScript/TypeScript, Java và Go.

Mỗi test dựng một dự án nhiều thư mục thật trong tmp_path rồi chạy qua
engine.scan(), vì chỉ ở tầng engine mới có đủ hai pha: tách sự thật của mọi
tệp, tính summary tới điểm bất động, rồi mới báo cáo.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan


def _project(root: Path, files: Dict[str, str]) -> Path:
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return root


def _findings(root: Path, **overrides):
    return scan(str(root), Config(**overrides)).findings


def _at(findings, path: str, rule: str) -> List:
    return [f for f in findings if f.path == path and f.rule_id == rule]


# --------------------------------------------------------------- JavaScript
EXPRESS = {
    "src/routes/users.js": (
        "const express = require('express');\n"
        "const router = express.Router();\n"
        "const { findUser } = require('../services/userService');\n"
        "const svc = require('../services/userService');\n"
        "router.get('/user', (req, res) => {\n"
        "  res.json(findUser(req.query.name));\n"
        "});\n"
        "router.get('/report', (req, res) => {\n"
        "  svc.runReport(req.query.file);\n"
        "});\n"
        "router.get('/profile', (req, res) => {\n"
        "  res.render('profile', { bio: req.query.bio, title: 'x' });\n"
        "});\n"
        "router.get('/safe', (req, res) => {\n"
        "  res.render('profile', { title: req.query.t });\n"
        "});\n"
    ),
    "src/services/userService.js": (
        "const db = require('../lib/db');\n"
        "const { shell } = require('../lib/shell');\n"
        "function findUser(name) {\n"
        "  return db.rawQuery(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n"
        "}\n"
        "function runReport(file) {\n"
        "  return shell('generate-report ' + file);\n"
        "}\n"
        "module.exports = { findUser, runReport };\n"
    ),
    "src/lib/db.js": (
        "const pool = require('pg').Pool;\n"
        "exports.rawQuery = function (sql) {\n"
        "  return pool.query(sql);\n"
        "};\n"
    ),
    "src/lib/shell.js": (
        "import { exec } from 'child_process';\n"
        "export function shell(cmd) {\n"
        "  exec(cmd);\n"
        "}\n"
    ),
    "views/profile.ejs": "<h1><%= title %></h1>\n<div><%- bio %></div>\n",
}


def test_js_command_flow_through_three_files(tmp_path: Path):
    findings = _findings(_project(tmp_path, EXPRESS))
    hits = _at(findings, "src/routes/users.js", "FSB-CMD-001")
    assert [f.line for f in hits] == [9]
    finding = hits[0]
    assert "cross-file" in finding.tags
    assert finding.trace[-1].path == "src/lib/shell.js"
    assert finding.trace[-1].line == 3
    assert "runReport() -> shell()" in finding.message


def test_js_sql_wrapper_needs_sql_text_from_caller(tmp_path: Path):
    """`rawQuery(sql)` không tự có chữ SELECT: nơi gọi phải chứng minh đó là SQL."""
    findings = _findings(_project(tmp_path, EXPRESS))
    hits = _at(findings, "src/routes/users.js", "FSB-SQL-001")
    assert [f.line for f in hits] == [6]
    assert hits[0].trace[-1].path == "src/lib/db.js"


def test_js_template_render_reaches_unescaped_output(tmp_path: Path):
    findings = _findings(_project(tmp_path, EXPRESS))
    hits = _at(findings, "src/routes/users.js", "FSB-XSS-001")
    # Dòng 15 chỉ đưa vào `title`, mà template in `title` bằng <%= %> ( có escape ).
    assert [f.line for f in hits] == [12]
    assert hits[0].trace[-1].path == "views/profile.ejs"
    assert hits[0].trace[-1].line == 2


def test_cross_file_switch_turns_the_links_off(tmp_path: Path):
    findings = _findings(_project(tmp_path, EXPRESS), cross_file_analysis=False)
    assert not [f for f in findings if "cross-file" in f.tags]


def test_js_same_name_in_two_modules_links_to_the_imported_one(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.js": (
                "const { run } = require('./safe/runner');\n"
                "app.get('/a', (req, res) => run(req.query.x));\n"
            ),
            "safe/runner.js": "exports.run = (value) => console.log(value);\n",
            "unsafe/runner.js": (
                "const cp = require('child_process');\n"
                "exports.run = (value) => cp.exec(value);\n"
            ),
        },
    )
    findings = _findings(tmp_path)
    assert not _at(findings, "app.js", "FSB-CMD-001")


def test_js_sanitizer_in_helper_file_is_honoured(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.js": (
                "const { toId } = require('./util/numbers');\n"
                "const db = require('./db');\n"
                "app.get('/a', (req, res) => {\n"
                "  db.query('SELECT * FROM t WHERE id = ' + toId(req.query.id));\n"
                "});\n"
            ),
            "util/numbers.js": "exports.toId = (v) => parseInt(v, 10);\n",
            "db.js": "module.exports = require('pg');\n",
        },
    )
    findings = _findings(tmp_path)
    assert not _at(findings, "app.js", "FSB-SQL-001")


def test_js_source_returned_from_helper(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.js": (
                "const { host } = require('./input');\n"
                "const cp = require('child_process');\n"
                "app.get('/a', (req, res) => {\n"
                "  const h = host(req);\n"
                "  cp.exec('ping ' + h);\n"
                "});\n"
            ),
            "input.js": "exports.host = (req) => req.query.host;\n",
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "app.js", "FSB-CMD-001")] == [5]


TYPESCRIPT = {
    "tsconfig.json": (
        "{\n  // jsonc\n  \"compilerOptions\": {\n    \"baseUrl\": \".\",\n"
        "    \"paths\": { \"@app/*\": [\"src/*\"], \"@utils\": [\"src/common/index.ts\"] },\n  }\n}\n"
    ),
    "src/users/users.controller.ts": (
        "import { Controller, Get, Query } from '@nestjs/common';\n"
        "import { UsersService } from './users.service';\n"
        "import { toId } from '@utils';\n"
        "@Controller('users')\n"
        "export class UsersController {\n"
        "  constructor(private readonly usersService: UsersService) {}\n"
        "  @Get('search')\n"
        "  search(@Query('q') q: string) {\n"
        "    return this.usersService.search(q);\n"
        "  }\n"
        "  @Get('byId')\n"
        "  byId(@Query('id') id: string) {\n"
        "    return this.usersService.byId(toId(id));\n"
        "  }\n"
        "}\n"
    ),
    "src/users/users.service.ts": (
        "import { UserRepository } from '@app/users/user.repository';\n"
        "export class UsersService {\n"
        "  constructor(private repo: UserRepository) {}\n"
        "  async search(term: string) {\n"
        "    return this.repo.raw(`SELECT * FROM users WHERE name LIKE '%${term}%'`);\n"
        "  }\n"
        "  async byId(id: number) {\n"
        "    return this.repo.raw('SELECT * FROM users WHERE id = ' + id);\n"
        "  }\n"
        "}\n"
    ),
    "src/users/user.repository.ts": (
        "export class UserRepository {\n"
        "  constructor(private ds: DataSource) {}\n"
        "  raw(sql: string) {\n"
        "    return this.ds.query(sql);\n"
        "  }\n"
        "}\n"
    ),
    "src/common/index.ts": "export * from './numbers';\n",
    "src/common/numbers.ts": "export function toId(v: string): number {\n  return parseInt(v, 10);\n}\n",
}


def test_ts_constructor_injection_path_alias_and_barrel(tmp_path: Path):
    findings = _findings(_project(tmp_path, TYPESCRIPT))
    controller = "src/users/users.controller.ts"
    hits = _at(findings, controller, "FSB-SQL-001")
    # search(): decorator @Query là nguồn, đi qua service rồi repository.
    # byId(): toId() trong barrel `@utils` -> parseInt khử sạch.
    assert [f.line for f in hits] == [9]


def test_express_handler_wired_by_route_in_another_file(tmp_path: Path):
    """Handler dùng tên tham số lạ ( `rq` ) chỉ được biết là request nhờ route."""
    _project(
        tmp_path,
        {
            "routes/index.js": (
                "const ctrl = require('../controllers/files');\n"
                "app.get('/convert', ctrl.convert);\n"
            ),
            "controllers/files.js": (
                "const { exec } = require('child_process');\n"
                "function convert(rq, rs) {\n"
                "  const names = rq.query.files.split(',');\n"
                "  names.forEach((n) => exec('convert ' + n));\n"
                "}\n"
                "function unused(rq) {\n"
                "  exec('convert ' + rq.name);\n"
                "}\n"
                "module.exports = { convert };\n"
            ),
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "controllers/files.js", "FSB-CMD-001")] == [4]


def test_queue_payload_crosses_from_producer_to_worker(tmp_path: Path):
    _project(
        tmp_path,
        {
            "api.js": (
                "const Queue = require('bull');\n"
                "const thumbs = new Queue('thumbnails');\n"
                "app.post('/t', (req, res) => thumbs.add({ path: req.body.path }));\n"
            ),
            "worker.js": (
                "const Queue = require('bull');\n"
                "const { execSync } = require('child_process');\n"
                "const thumbs = new Queue('thumbnails');\n"
                "thumbs.process(async (job) => {\n"
                "  execSync('convert ' + job.data.path);\n"
                "});\n"
            ),
            "other-worker.js": (
                "const Queue = require('bull');\n"
                "const { execSync } = require('child_process');\n"
                "const mails = new Queue('mails');\n"
                "mails.process(async (job) => {\n"
                "  execSync('sendmail ' + job.data.to);\n"
                "});\n"
            ),
        },
    )
    findings = _findings(tmp_path)
    hits = _at(findings, "worker.js", "FSB-CMD-001")
    assert [f.line for f in hits] == [5]
    assert "api.js:3" in hits[0].message
    # Hàng đợi `mails` không ai đẩy dữ liệu bẩn vào: không có nguồn để báo.
    assert not _at(findings, "other-worker.js", "FSB-CMD-001")


def test_dispatch_table_reaches_every_handler(tmp_path: Path):
    _project(
        tmp_path,
        {
            "ops.js": (
                "const cp = require('child_process');\n"
                "exports.untar = function (t) { return cp.execSync('tar xf ' + t); };\n"
            ),
            "app.js": (
                "const ops = require('./ops');\n"
                "const handlers = { untar: ops.untar, noop: (x) => x };\n"
                "app.get('/op', (req, res) => {\n"
                "  handlers[req.query.op](req.query.target);\n"
                "});\n"
            ),
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "app.js", "FSB-CMD-001")] == [4]


# --------------------------------------------------------------------- Java
SPRING = {
    "src/main/java/com/acme/web/UserController.java": (
        "package com.acme.web;\n"
        "import com.acme.service.UserService;\n"
        "import com.acme.repo.UserMapper;\n"
        "@Controller\n"
        "public class UserController {\n"
        "    @Autowired private UserService userService;\n"
        "    @Autowired private UserMapper userMapper;\n"
        "    @GetMapping(\"/search\")\n"
        "    public String search(@RequestParam(\"q\") String q) {\n"
        "        userService.search(q);\n"
        "        return \"ok\";\n"
        "    }\n"
        "    @GetMapping(\"/byName\")\n"
        "    public Object byName(String name) {\n"
        "        return userMapper.findByName(name);\n"
        "    }\n"
        "    @GetMapping(\"/byId\")\n"
        "    public Object byId(String id) {\n"
        "        return userMapper.findById(id);\n"
        "    }\n"
        "    @GetMapping(\"/export\")\n"
        "    public void export(@RequestParam String file) {\n"
        "        userService.export(file);\n"
        "    }\n"
        "    @GetMapping(\"/hello\")\n"
        "    public String hello(@RequestParam String who, Model model) {\n"
        "        model.addAttribute(\"who\", who);\n"
        "        return \"hello\";\n"
        "    }\n"
        "}\n"
    ),
    "src/main/java/com/acme/service/UserService.java": (
        "package com.acme.service;\n"
        "public interface UserService {\n"
        "    void search(String q);\n"
        "    void export(String file);\n"
        "}\n"
    ),
    "src/main/java/com/acme/service/UserServiceImpl.java": (
        "package com.acme.service;\n"
        "import com.acme.util.Shell;\n"
        "@Service\n"
        "public class UserServiceImpl implements UserService {\n"
        "    private JdbcTemplate jdbc;\n"
        "    @Value(\"${queries.search}\")\n"
        "    private String searchSql;\n"
        "    @Override\n"
        "    public void search(String q) {\n"
        "        jdbc.queryForList(searchSql + q + \"'\");\n"
        "    }\n"
        "    @Override\n"
        "    public void export(String file) {\n"
        "        Shell.run(\"tar czf /tmp/out.tgz \" + file);\n"
        "    }\n"
        "}\n"
    ),
    "src/main/java/com/acme/util/Shell.java": (
        "package com.acme.util;\n"
        "public final class Shell {\n"
        "    public static void run(String command) throws Exception {\n"
        "        Runtime.getRuntime().exec(command);\n"
        "    }\n"
        "}\n"
    ),
    "src/main/java/com/acme/repo/UserMapper.java": (
        "package com.acme.repo;\n"
        "public interface UserMapper {\n"
        "    Object findByName(@Param(\"name\") String name);\n"
        "    Object findById(String id);\n"
        "}\n"
    ),
    "src/main/resources/mapper/UserMapper.xml": (
        "<mapper namespace=\"com.acme.repo.UserMapper\">\n"
        "  <select id=\"findByName\">SELECT * FROM users WHERE name = '${name}'</select>\n"
        "  <select id=\"findById\">SELECT * FROM users WHERE id = #{id}</select>\n"
        "</mapper>\n"
    ),
    "src/main/resources/application.yml": "queries:\n  search: \"SELECT * FROM users WHERE name LIKE '\"\n",
    "src/main/resources/templates/hello.html": "<p th:utext=\"${who}\">x</p>\n",
}
CONTROLLER = "src/main/java/com/acme/web/UserController.java"


def test_java_interface_injection_resolves_to_implementation(tmp_path: Path):
    findings = _findings(_project(tmp_path, SPRING))
    hits = _at(findings, CONTROLLER, "FSB-CMD-001")
    assert [f.line for f in hits] == [23]
    assert hits[0].trace[-1].path == "src/main/java/com/acme/util/Shell.java"


def test_java_sql_text_comes_from_yaml_config(tmp_path: Path):
    findings = _findings(_project(tmp_path, SPRING))
    assert [f.line for f in _at(findings, CONTROLLER, "FSB-SQL-001") if f.trace[-1].path.endswith(".java")] == [10]


def test_java_mybatis_dollar_placeholder_is_a_sink_hash_is_not(tmp_path: Path):
    findings = _findings(_project(tmp_path, SPRING))
    xml_hits = [
        f for f in _at(findings, CONTROLLER, "FSB-SQL-001") if f.trace[-1].path.endswith(".xml")
    ]
    # findByName dùng ${name} ( nối chuỗi ); findById dùng #{id} ( tham số hóa ).
    assert [f.line for f in xml_hits] == [15]


def test_java_model_attribute_rendered_by_thymeleaf_utext(tmp_path: Path):
    findings = _findings(_project(tmp_path, SPRING))
    hits = _at(findings, CONTROLLER, "FSB-XSS-001")
    assert [f.line for f in hits] == [27]
    assert hits[0].trace[-1].path == "src/main/resources/templates/hello.html"


def test_java_kafka_listener_payload_is_a_source(tmp_path: Path):
    _project(
        tmp_path,
        {
            "Listener.java": (
                "package a;\n"
                "public class Listener {\n"
                "    @KafkaListener(topics = \"jobs\")\n"
                "    public void on(String payload) throws Exception {\n"
                "        Runtime.getRuntime().exec(\"run \" + payload);\n"
                "    }\n"
                "}\n"
            )
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "Listener.java", "FSB-CMD-001")] == [5]


def test_java_static_final_query_in_other_class(tmp_path: Path):
    _project(
        tmp_path,
        {
            "src/a/Queries.java": (
                "package a;\n"
                "public final class Queries {\n"
                "    public static final String FIND = \"SELECT * FROM t WHERE n = '\";\n"
                "}\n"
            ),
            "src/b/Dao.java": (
                "package b;\n"
                "import a.Queries;\n"
                "public class Dao {\n"
                "    public void find(HttpServletRequest request, Statement st) throws Exception {\n"
                "        st.executeQuery(Queries.FIND + request.getParameter(\"n\") + \"'\");\n"
                "    }\n"
                "    public void safe(Statement st) throws Exception {\n"
                "        st.executeQuery(Queries.FIND + \"x'\");\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "src/b/Dao.java", "FSB-SQL-001")] == [5]
    # Toàn hằng số: không có phát hiện "giá trị không phải hằng" nào ở dòng 8.
    assert not [f for f in findings if f.path == "src/b/Dao.java" and f.line == 8]


# ----------------------------------------------------------------------- Go
GO = {
    "go.mod": "module github.com/acme/shop\n\ngo 1.22\n",
    "internal/handlers/handlers.go": (
        "package handlers\n"
        "import (\n"
        "\t\"net/http\"\n"
        "\t\"github.com/acme/shop/internal/store\"\n"
        "\t\"github.com/acme/shop/internal/runner\"\n"
        ")\n"
        "type Handler struct {\n"
        "\tdb *store.Store\n"
        "}\n"
        "func (h *Handler) Item(w http.ResponseWriter, req *http.Request) {\n"
        "\tid := req.URL.Query().Get(\"id\")\n"
        "\th.db.FindItem(id)\n"
        "}\n"
        "func (h *Handler) Convert(w http.ResponseWriter, req *http.Request) {\n"
        "\trunner.Convert(req.FormValue(\"name\"))\n"
        "}\n"
        "func (h *Handler) Count(w http.ResponseWriter, req *http.Request) {\n"
        "\th.db.Count(req.FormValue(\"n\"))\n"
        "}\n"
    ),
    "internal/store/store.go": (
        "package store\n"
        "import \"database/sql\"\n"
        "const itemQuery = \"SELECT * FROM items WHERE id = '\"\n"
        "type Store struct {\n"
        "\tconn *sql.DB\n"
        "}\n"
        "func (s *Store) FindItem(id string) {\n"
        "\ts.conn.Query(itemQuery + id + \"'\")\n"
        "}\n"
        "func (s *Store) Count(n string) {\n"
        "\ts.conn.Query(\"SELECT count(*) FROM items WHERE n = $1\", n)\n"
        "}\n"
    ),
    "internal/runner/runner.go": (
        "package runner\n"
        "import \"os/exec\"\n"
        "func Convert(name string) error {\n"
        "\treturn exec.Command(\"sh\", \"-c\", \"convert \"+name).Run()\n"
        "}\n"
    ),
}


def test_go_struct_field_method_and_package_function(tmp_path: Path):
    findings = _findings(_project(tmp_path, GO))
    handlers = "internal/handlers/handlers.go"
    assert [f.line for f in _at(findings, handlers, "FSB-SQL-001")] == [12]
    assert [f.line for f in _at(findings, handlers, "FSB-CMD-001")] == [15]


def test_go_gin_context_parameter_is_a_source(tmp_path: Path):
    _project(
        tmp_path,
        {
            "main.go": (
                "package main\n"
                "import (\n\t\"os/exec\"\n\t\"github.com/gin-gonic/gin\"\n)\n"
                "func ping(ctx *gin.Context) {\n"
                "\texec.Command(\"sh\", \"-c\", \"ping \"+ctx.Query(\"h\")).Run()\n"
                "}\n"
            )
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "main.go", "FSB-CMD-001")] == [7]


def test_diff_scope_keeps_cross_file_finding_when_caller_changes(tmp_path: Path):
    """Sửa đúng dòng gọi helper cũ ở tệp khác vẫn phải hiện phát hiện."""
    from fortress_scan.core import diffscope

    _project(tmp_path, EXPRESS)
    patch = (
        "--- a/src/routes/users.js\n+++ b/src/routes/users.js\n"
        "@@ -9,1 +9,1 @@\n-  x\n+  svc.runReport(req.query.file);\n"
    )
    changed = diffscope.parse_patch(patch)
    findings = scan(str(tmp_path), Config(changed_lines=changed)).findings
    assert [f.rule_id for f in findings] == ["FSB-CMD-001"]


# ------------------------------------------------------- ngữ nghĩa luồng chung
def test_reassignment_inside_a_branch_does_not_clear_taint(tmp_path: Path):
    _project(
        tmp_path,
        {
            "main.go": (
                "package main\n"
                "import (\n\t\"html/template\"\n\t\"net/http\"\n)\n"
                "func search(r *http.Request, strict bool) template.HTML {\n"
                "\tterm := r.FormValue(\"t\")\n"
                "\tif strict {\n"
                "\t\tterm = template.HTMLEscapeString(term)\n"
                "\t}\n"
                "\treturn template.HTML(\"<p>\" + term + \"</p>\")\n"
                "}\n"
                "func clean(r *http.Request) template.HTML {\n"
                "\tterm := r.FormValue(\"t\")\n"
                "\tterm = template.HTMLEscapeString(term)\n"
                "\treturn template.HTML(\"<p>\" + term + \"</p>\")\n"
                "}\n"
            )
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "main.go", "FSB-XSS-001")] == [11]


def test_js_destructuring_and_regexp_exec(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.js": (
                "const cp = require('child_process');\n"
                "const app = require('express')();\n"
                "app.get('/a', (req, res) => {\n"
                "  const m = /a(b)/.exec(req.query.x);\n"
                "  const re = new RegExp('x');\n"
                "  res.json([m, re.exec(req.query.y)]);\n"
                "});\n"
                "app.get('/b', (req, res) => {\n"
                "  const { host, port = 80 } = req.query;\n"
                "  cp.exec('ping ' + host);\n"
                "});\n"
                "app.get('/c', (req, res) => {\n"
                "  let [first, second] = [req.body.a, 'x'];\n"
                "  cp.execSync('ls ' + first);\n"
                "});\n"
            )
        },
    )
    findings = _findings(tmp_path)
    assert sorted((f.rule_id, f.line) for f in findings) == [("FSB-CMD-001", 10), ("FSB-CMD-001", 14)]


def test_js_es5_constructor_prototype_and_closure(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app/data/user-dao.js": (
                "const mysql = require('mysql');\n"
                "function UserDAO(db) {\n"
                "  const conn = mysql.createConnection(db);\n"
                "  this.findByName = (name, callback) => {\n"
                "    const where = () => {\n"
                "      return \"WHERE name = '\" + name + \"'\";\n"
                "    };\n"
                "    conn.query('SELECT * FROM users ' + where(), callback);\n"
                "  };\n"
                "  this.count = (name) => conn.query('SELECT count(*) FROM users WHERE name = ?', [name]);\n"
                "}\n"
                "UserDAO.prototype.remove = function (id) {\n"
                "  return this.conn.query('DELETE FROM users WHERE id = ' + id);\n"
                "};\n"
                "module.exports = { UserDAO };\n"
            ),
            "app/routes/users.js": (
                "const UserDAO = require('../data/user-dao').UserDAO;\n"
                "function UsersHandler(db) {\n"
                "  const userDAO = new UserDAO(db);\n"
                "  this.show = (req, res) => {\n"
                "    userDAO.findByName(req.query.name, (err, rows) => res.json(rows));\n"
                "  };\n"
                "  this.total = (req, res) => userDAO.count(req.query.name);\n"
                "  this.drop = (req, res) => {\n"
                "    userDAO.remove(req.params.id);\n"
                "  };\n"
                "}\n"
                "module.exports = UsersHandler;\n"
            ),
        },
    )
    findings = _findings(tmp_path)
    assert [f.line for f in _at(findings, "app/routes/users.js", "FSB-SQL-001")] == [5, 9]


def test_js_engine_wide_autoescape_off_makes_plain_output_raw(tmp_path: Path):
    files = {
        "server.js": (
            "const swig = require('swig');\n"
            "const app = require('express')();\n"
            "app.get('/hello', (req, res) => {\n"
            "  res.render('hello', { name: req.query.name, title: 'x' });\n"
            "});\n"
        ),
        "views/hello.html": "<h1>{{ title }}</h1>\n<p>{{ name }}</p>\n<p>{{ name | escape }}</p>\n",
    }
    _project(tmp_path, files)
    assert _at(_findings(tmp_path), "server.js", "FSB-XSS-001") == []
    files["server.js"] += "swig.setDefaults({ cache: false, autoescape: false });\n"
    _project(tmp_path, files)
    hits = _at(_findings(tmp_path), "server.js", "FSB-XSS-001")
    assert [(f.line, f.trace[-1].line) for f in hits] == [(4, 2)]
    assert "server.js:6" in hits[0].message
