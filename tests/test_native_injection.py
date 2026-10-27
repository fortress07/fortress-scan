"""Chèn lệnh, SQL, đường dẫn và thư viện động trong C, C++, Objective-C.

Khác các ngôn ngữ web, dữ liệu ngoài trong C thường không phải giá trị trả về
mà được ĐỔ vào bộ đệm ( fgets, recv, scanf ), rồi được dựng thành chuỗi lệnh
bằng sprintf. Các mẫu dưới đây kiểm đúng hai bước đó, và kiểm luôn cái giá của
việc bắt nhầm: argv của công cụ dòng lệnh, tệp cấu hình của chính chương trình
và chuỗi dựng toàn bằng số đều không được kêu.
"""

from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Severity
from fortress_scan.languages import C, CPP, OBJC


def hits(source: str, language: str = C, config: Config = None):
    return [
        (f.rule_id, f.line)
        for f in scan_source(source, language, "mau.c", config or Config())
        if not f.rule_id.startswith("FSB-MEM")
    ]


def test_stdin_line_built_into_shell_command():
    source = (
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "void run(void) {\n"
        "    char host[64];\n"
        "    char cmd[128];\n"
        "    if (!fgets(host, sizeof host, stdin))\n"
        "        return;\n"
        "    snprintf(cmd, sizeof cmd, \"ping -c1 %s\", host);\n"
        "    system(cmd);\n"
        "}\n"
    )
    found = scan_source(source, C, "mau.c", Config())
    command = [f for f in found if f.rule_id == "FSB-CMD-001"]
    assert [(f.line, f.severity) for f in command] == [(9, Severity.CRITICAL)]


def test_number_formatted_command_is_silent():
    source = (
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "void nap(void) {\n"
        "    char line[32];\n"
        "    char cmd[64];\n"
        "    fgets(line, sizeof line, stdin);\n"
        "    int n = atoi(line);\n"
        "    snprintf(cmd, sizeof cmd, \"sleep %d\", n);\n"
        "    system(cmd);\n"
        "}\n"
    )
    assert hits(source) == []


def test_cgi_query_string_is_a_web_source():
    source = (
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "int main(void) {\n"
        "    const char *q = getenv(\"QUERY_STRING\");\n"
        "    char cmd[256];\n"
        "    snprintf(cmd, sizeof cmd, \"/usr/bin/lookup %s\", q);\n"
        "    return system(cmd);\n"
        "}\n"
    )
    assert ("FSB-CMD-001", 7) in hits(source)


def test_argv_and_plain_environment_need_the_low_signal_flag():
    source = (
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "int main(int argc, char **argv) {\n"
        "    FILE *in = fopen(argv[1], \"r\");\n"
        "    const char *home = getenv(\"HOME\");\n"
        "    FILE *rc = fopen(home, \"r\");\n"
        "    return in == 0 || rc == 0;\n"
        "}\n"
    )
    assert hits(source) == []
    loud = hits(source, config=Config(include_low_signal_sources=True))
    assert ("FSB-PATH-001", 4) in loud
    assert ("FSB-PATH-001", 6) in loud


def test_reading_the_programs_own_config_file_is_not_a_source():
    source = (
        "#include <stdio.h>\n"
        "void load(FILE *cfg) {\n"
        "    char path[256];\n"
        "    if (fgets(path, sizeof path, cfg))\n"
        "        fopen(path, \"r\");\n"
        "}\n"
    )
    assert hits(source) == []


def test_network_data_into_sqlite_query_and_parameterized_form():
    source = (
        "#include <sqlite3.h>\n#include <stdio.h>\n#include <sys/socket.h>\n"
        "void find(sqlite3 *db, int s) {\n"
        "    char name[64];\n"
        "    char sql[256];\n"
        "    int n = recv(s, name, sizeof name - 1, 0);\n"
        "    if (n <= 0) return;\n"
        "    name[n] = 0;\n"
        "    snprintf(sql, sizeof sql, \"SELECT * FROM users WHERE name = '%s'\", name);\n"
        "    sqlite3_exec(db, sql, 0, 0, 0);\n"
        "}\n"
        "void find_ok(sqlite3 *db, const char *name) {\n"
        "    sqlite3_stmt *st;\n"
        "    sqlite3_prepare_v2(db, \"SELECT * FROM users WHERE name = ?\", -1, &st, 0);\n"
        "    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);\n"
        "}\n"
    )
    assert hits(source) == [("FSB-SQL-001", 11)]


def test_literal_and_numeric_queries_are_not_dynamic():
    source = (
        "#include <sqlite3.h>\n#include <string>\n"
        "void tune(sqlite3 *db, int pages, bool sync) {\n"
        "    char q[100];\n"
        "    std::snprintf(q, sizeof q, \"PRAGMA cache_size = %d\", pages);\n"
        "    sqlite3_exec(db, q, nullptr, nullptr, nullptr);\n"
        "    std::string mode = sync ? \"PRAGMA synchronous = FULL\" : \"PRAGMA synchronous = OFF\";\n"
        "    sqlite3_exec(db, mode.c_str(), nullptr, nullptr, nullptr);\n"
        "    std::string create = \"CREATE TABLE t (k blob)\";\n"
        "    create += \" WITHOUT ROWID\";\n"
        "    sqlite3_exec(db, create.c_str(), nullptr, nullptr, nullptr);\n"
        "}\n"
    )
    assert hits(source, CPP) == []


def test_appending_to_a_tainted_string_keeps_it_tainted():
    source = (
        "#include <iostream>\n#include <string>\n#include <cstdlib>\n"
        "int main() {\n"
        "    std::string host;\n"
        "    std::cin >> host;\n"
        "    std::string cmd = \"nslookup \" + host;\n"
        "    cmd += \" 8.8.8.8\";\n"
        "    return std::system(cmd.c_str());\n"
        "}\n"
    )
    assert hits(source, CPP) == [("FSB-CMD-001", 9)]


def test_cpp_getline_from_cin():
    source = (
        "#include <iostream>\n#include <string>\n#include <cstdio>\n"
        "void open_it() {\n"
        "    std::string name;\n"
        "    std::getline(std::cin, name);\n"
        "    FILE *f = fopen(name.c_str(), \"r\");\n"
        "}\n"
    )
    assert hits(source, CPP) == [("FSB-PATH-001", 7)]


def test_shell_wrapper_through_execl():
    source = (
        "#include <unistd.h>\n#include <stdio.h>\n"
        "void run(void) {\n"
        "    char line[128];\n"
        "    fgets(line, sizeof line, stdin);\n"
        "    execl(\"/bin/sh\", \"sh\", \"-c\", line, (char *)0);\n"
        "}\n"
    )
    assert hits(source) == [("FSB-CMD-001", 6)]


def test_constant_and_parameter_commands():
    source = (
        "#include <stdlib.h>\n"
        "int clear(void) { return system(\"clear\"); }\n"
        "int run(const char *c) { return system(c); }\n"
    )
    # Hằng: im. Tham số: không biết ai gọi, báo ở mức "không phải hằng".
    assert hits(source) == [("FSB-CMD-003", 3)]


def test_macro_definitions_are_not_calls():
    source = "#include <stdlib.h>\n#define RUN(x) system(x)\nint main(void) { return 0; }\n"
    assert hits(source) == []


def test_network_name_loaded_as_library():
    source = (
        "#include <dlfcn.h>\n#include <sys/socket.h>\n"
        "void *plug(int s) {\n"
        "    char lib[128];\n"
        "    recv(s, lib, sizeof lib - 1, 0);\n"
        "    return dlopen(lib, RTLD_NOW);\n"
        "}\n"
    )
    assert hits(source) == [("FSB-IMPORT-001", 6)]


def test_objective_c_shares_the_c_sinks():
    source = (
        "#import <Foundation/Foundation.h>\n"
        "@implementation Runner\n"
        "- (void)run {\n"
        "    char line[64];\n"
        "    fgets(line, sizeof line, stdin);\n"
        "    system(line);\n"
        "}\n"
        "@end\n"
    )
    assert hits(source, OBJC) == [("FSB-CMD-001", 6)]
