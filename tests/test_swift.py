"""Swift: máy chủ Vapor / Hummingbird và ứng dụng iOS.

Nhãn đối số quyết định đối số nào là câu SQL hay đường dẫn ( `execute(sql:)`,
`contents(atPath:)` ), và cũng quyết định chỗ nào đã được bind
( `execute(literal:)`, `\\(bind: x)` ). Ở phía app, dữ liệu ngoài là deep link
và tin nhắn JavaScript từ WebView.
"""

from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import JAVA, SWIFT, detect_language


def hits(source: str, language: str = SWIFT):
    return sorted((f.rule_id, f.line) for f in scan_source(source, language, "mau", Config()))


def test_vapor_query_into_grdb_sql_label_but_not_literal_label():
    source = (
        'app.get("user") { req -> String in\n'
        '    let name = try req.query.get(String.self, at: "name")\n'
        "    try db.execute(sql: \"DELETE FROM t WHERE n = '\\(name)'\")\n"
        '    try db.execute(literal: "DELETE FROM t WHERE n = \\(name)")\n'
        '    try db.execute(sql: "DELETE FROM t WHERE n = ?", arguments: [name])\n'
        '    return "ok"\n'
        "}\n"
    )
    assert hits(source) == [("FSB-SQL-001", 3)]


def test_sqlkit_bind_interpolation_is_a_parameter():
    source = (
        'app.get("u") { req async throws -> [Row] in\n'
        '    let name = req.query["name"] ?? ""\n'
        "    let sql = req.db as! SQLDatabase\n"
        '    _ = try await sql.raw("SELECT * FROM users WHERE name = \\(bind: name)").all()\n'
        '    return try await sql.raw("SELECT * FROM users WHERE name = \'\\(unsafeRaw: name)\'").all()\n'
        "}\n"
    )
    assert hits(source) == [("FSB-SQL-001", 5)]


def test_vapor_file_stream_and_open_redirect():
    source = (
        'app.get("f") { req -> Response in\n'
        '    let file = req.query["file"] ?? "index.html"\n'
        '    if a { return req.fileio.streamFile(at: "/srv/files/" + file) }\n'
        '    if b { return req.redirect(to: "/items/\\(file)") }\n'
        "    return req.redirect(to: file)\n"
        "}\n"
    )
    assert hits(source) == [("FSB-PATH-001", 3), ("FSB-REDIR-001", 5)]


def test_deep_link_parameter_reaches_sqlite_webview_and_predicate():
    source = (
        "class AppDelegate: UIResponder, UIApplicationDelegate {\n"
        "    func application(_ app: UIApplication, open url: URL,\n"
        "                     options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {\n"
        "        let page = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first?.value ?? \"\"\n"
        '        webView.loadHTMLString("<h1>\\(page)</h1>", baseURL: nil)\n'
        "        _ = NSPredicate(format: \"title == '\\(page)'\")\n"
        '        _ = NSPredicate(format: "title == %@", page)\n'
        "        sqlite3_exec(db, \"DELETE FROM notes WHERE title = '\\(page)'\", nil, nil, nil)\n"
        '        sqlite3_prepare_v2(db, "SELECT * FROM notes WHERE title = ?", -1, &stmt, nil)\n'
        "        _ = documents.appendingPathComponent(page)\n"
        "        _ = documents.appendingPathComponent((page as NSString).lastPathComponent)\n"
        "        return true\n"
        "    }\n"
        "    func helper(url: URL) {\n"
        "        _ = documents.appendingPathComponent(url.path)\n"
        "    }\n"
        "}\n"
    )
    assert hits(source) == [
        ("FSB-NOSQL-001", 6),
        ("FSB-PATH-001", 10),
        ("FSB-SQL-001", 8),
        ("FSB-XSS-001", 5),
    ]


def test_webview_message_into_process_and_unarchiver():
    source = (
        "func userContentController(_ c: WKUserContentController, didReceive message: WKScriptMessage) {\n"
        '    let cmd = message.body as? String ?? ""\n'
        "    webView.evaluateJavaScript(\"render('\\(cmd)')\")\n"
        "    let task = Process()\n"
        '    task.launchPath = "/bin/sh"\n'
        '    task.arguments = ["-c", cmd]\n'
        '    task.arguments = ["--name", "fixed"]\n'
        "    _ = NSKeyedUnarchiver.unarchiveObject(with: Data(base64Encoded: cmd)!)\n"
        "}\n"
    )
    assert hits(source) == [("FSB-CMD-001", 6), ("FSB-DESER-001", 8), ("FSB-XSS-001", 3)]


def test_swiftui_system_font_and_enum_cases_are_not_commands():
    source = (
        "enum Icon { case system(String) }\n"
        "let f = Font.system(size: 12, weight: .bold)\n"
        "Text(title).font(.system(.caption, design: .monospaced))\n"
        "switch icon { case .system(let name): print(name) }\n"
    )
    assert hits(source) == []


def test_hummingbird_login_redirect_from_query():
    source = (
        "func login(request: Request, context: Context) async throws -> Response {\n"
        '    return .redirect(to: request.uri.queryParameters.get("from") ?? "/", type: .found)\n'
        "}\n"
    )
    assert hits(source) == [("FSB-REDIR-001", 2)]


def test_swift_files_map_to_swift(tmp_path):
    path = tmp_path / "Routes.swift"
    path.write_text("import Vapor\n", encoding="utf-8")
    assert detect_language(path) == SWIFT


def test_an_escape_letter_does_not_mix_scripts():
    # `\n` dính liền một từ tiếng Nga trong chuỗi không phải là token trộn hai hệ chữ.
    source = 'class A { String s = "Mô tả:\\nПривет"; }\n'
    assert hits(source, JAVA) == []
