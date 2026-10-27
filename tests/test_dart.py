"""Dart: máy chủ shelf / Dart Frog và ứng dụng Flutter.

Cả hai loại nháy của Dart đều nội suy `$x`, chỉ chuỗi `r'...'` là không. Phía
máy chủ, dữ liệu ngoài là query của request; phía app, là deep link của
go_router và tin nhắn từ WebView.
"""

from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.context import PathContext, classify
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import DART, GROOVY, detect_language


def hits(source: str, language: str = DART):
    return sorted((f.rule_id, f.line) for f in scan_source(source, language, "mau", Config()))


def test_shelf_query_into_sqflite_but_not_bound_or_parsed():
    source = (
        "Future<Response> handler(Request request) async {\n"
        "  final name = request.url.queryParameters['name'] ?? '';\n"
        "  await db.rawQuery(\"SELECT * FROM users WHERE name = '$name'\");\n"
        "  await db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);\n"
        "  final id = int.parse(request.url.queryParameters['id']!);\n"
        "  await db.rawDelete('DELETE FROM users WHERE id = $id');\n"
        "  await db.rawQuery(r'SELECT * FROM users WHERE name = $name');\n"
        "  return Response.ok('ok');\n"
        "}\n"
    )
    assert hits(source) == [("FSB-SQL-001", 3)]


def test_postgres_sql_wrapper_holding_a_literal_is_constant():
    source = (
        "Future<void> run(Connection database, Request request, String table) async {\n"
        "  await database.execute(Sql('SELECT COUNT(*) FROM __schema'));\n"
        "  await database.execute(Sql(r'UPDATE __schema SET version = $1', types: [Type.integer]));\n"
        "  await database.execute(Sql.named('SELECT * FROM t WHERE id = @id'), parameters: {'id': 1});\n"
        "  final q = request.url.queryParameters['q'];\n"
        "  await database.execute(Sql(\"SELECT * FROM t WHERE name = '$q'\"));\n"
        "  await database.execute(Sql('DROP TABLE $table'));\n"
        "}\n"
    )
    assert hits(source) == [("FSB-SQL-001", 6), ("FSB-SQL-002", 7)]


def test_process_run_is_a_shell_only_with_run_in_shell_or_sh_c():
    source = (
        "Future<Response> onRequest(RequestContext context) async {\n"
        "  final host = context.request.uri.queryParameters['host'] ?? '';\n"
        "  await Process.run('ping', ['-c', '1', host]);\n"
        "  await Process.run('ping -c 1 $host', [], runInShell: true);\n"
        "  await Process.run('sh', ['-c', 'ping $host']);\n"
        "  await Process.run(host, []);\n"
        "  await Process.run('git', ['status'], runInShell: true);\n"
        "  return Response(body: 'ok');\n"
        "}\n"
    )
    assert hits(source) == [("FSB-CMD-001", 4), ("FSB-CMD-001", 5), ("FSB-CMD-002", 6)]


def test_file_url_and_redirect_from_query():
    source = (
        "Future<Response> handler(Request request) async {\n"
        "  final file = request.url.queryParameters['file'] ?? 'index.html';\n"
        "  final a = File('/srv/files/$file').readAsStringSync();\n"
        "  final b = File(p.join('/srv/files', p.basename(file))).readAsStringSync();\n"
        "  final target = request.url.queryParameters['url']!;\n"
        "  final c = await http.get(Uri.parse(target));\n"
        "  if (a.isEmpty) return Response.found(target);\n"
        "  return Response.found('/items/$file');\n"
        "}\n"
    )
    assert hits(source) == [("FSB-PATH-001", 3), ("FSB-REDIR-001", 7), ("FSB-SSRF-001", 6)]


def test_go_router_deep_link_into_webview():
    source = (
        "GoRoute(\n"
        "  path: '/article',\n"
        "  builder: (context, state) {\n"
        "    final title = state.uri.queryParameters['title'] ?? '';\n"
        "    controller.loadHtmlString('<h1>$title</h1>');\n"
        "    controller.loadHtmlString('<h1>${htmlEscape.convert(title)}</h1>');\n"
        "    controller.runJavaScript(\"render('$title')\");\n"
        "    return ArticlePage(title: title);\n"
        "  },\n"
        ")\n"
    )
    assert hits(source) == [("FSB-XSS-001", 5), ("FSB-XSS-001", 7)]


def test_webview_message_chooses_the_isolate_uri():
    source = (
        "JavaScriptChannel(\n"
        "  name: 'Bridge',\n"
        "  onMessageReceived: (JavaScriptMessage message) {\n"
        "    final uri = message.message;\n"
        "    Isolate.spawnUri(Uri.parse(uri), [], null);\n"
        "    Isolate.spawnUri(Uri.parse('package:app/worker.dart'), [], null);\n"
        "  },\n"
        ")\n"
    )
    assert hits(source) == [("FSB-IMPORT-001", 5)]


def test_dart_files_and_generated_parts(tmp_path):
    path = tmp_path / "server.dart"
    path.write_text("void main() {}\n", encoding="utf-8")
    assert detect_language(path) == DART
    assert classify("lib/src/schema.drift.dart") is PathContext.GENERATED
    assert classify("lib/models/user.freezed.dart") is PathContext.GENERATED
    assert classify("lib/models/user.g.dart") is PathContext.GENERATED
    assert classify("lib/drift/database.dart") is PathContext.PRODUCTION


def test_flutter_settings_gradle_evaluates_a_project_file_not_a_string():
    # Mẫu add-to-app của Flutter: chạy một tệp script cố định của dự án.
    source = (
        "setBinding(new Binding([gradle: this]))\n"
        "evaluate(new File(settingsDir.parentFile, 'module/.android/include_flutter.groovy'))\n"
        "def script = new File(path).text\n"
        "evaluate(script)\n"
    )
    assert hits(source, GROOVY) == [("FSB-EXEC-002", 4)]
