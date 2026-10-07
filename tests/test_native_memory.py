"""Luật an toàn bộ nhớ cho C, C++ và Objective-C ( FSB-MEM-001..006 ).

Mỗi lớp lỗi được kiểm theo cặp: một bản thủng phải bắn đúng dòng, một bản
viết đúng phải im. Các mẫu cố tình nhiều hàm, nhiều nhánh, có macro, có
#if, vì một bộ luật chỉ đo trên ví dụ một dòng thì ra mã thật sẽ báo nhầm
hàng loạt. Mẫu chỉ là đoạn mã lỗi tối thiểu, không phải mã khai thác.
"""

from __future__ import annotations

from typing import List, Tuple

import pytest

from fortress_scan.core.budget import Budget
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Confidence, Severity
from fortress_scan.languages import C, CPP, OBJC, detect_language


def found(source: str, language: str = C) -> List[Tuple[str, int]]:
    return [(f.rule_id, f.line) for f in scan_source(source, language, "mau.c", Config()) if f.rule_id.startswith("FSB-MEM")]


def finding(source: str, rule: str, language: str = C):
    hits = [f for f in scan_source(source, language, "mau.c", Config()) if f.rule_id == rule]
    assert hits, "%s không bắn; thực tế: %s" % (rule, found(source, language))
    return hits[0]


def memory_ids(source: str, language: str = C) -> List[str]:
    return [rule for rule, _ in found(source, language)]


# ----------------------------------------------------------- nhận diện tệp


@pytest.mark.parametrize(
    "path, language",
    [
        ("src/packet.c", C),
        ("include/packet.h", C),
        ("src/engine.cpp", CPP),
        ("src/engine.cc", CPP),
        ("include/engine.hpp", CPP),
        ("src/view.mm", OBJC),
    ],
)
def test_native_files_are_detected(tmp_path, path, language):
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    assert detect_language(target) == language


def test_dot_m_is_objective_c_only_when_it_looks_like_it(tmp_path):
    objc = tmp_path / "View.m"
    objc.write_text("#import <UIKit/UIKit.h>\n@implementation View\n@end\n", encoding="utf-8")
    matlab = tmp_path / "solve.m"
    matlab.write_text("function x = solve(A, b)\n  x = A \\ b;\nend\n", encoding="utf-8")
    assert detect_language(objc) == OBJC
    assert detect_language(matlab) is None


# -------------------------------------------------- FSB-MEM-001 tràn bộ đệm

PACKET = """\
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define NAME_MAX_LEN 32

struct header {
    unsigned int length;
    char name[NAME_MAX_LEN];
};

static int read_header(int sock, struct header *h) {
    unsigned char raw[4];
    if (recv(sock, raw, sizeof raw, 0) != 4)
        return -1;
    h->length = ntohl(*(unsigned int *)raw);
    return 0;
}

int handle_client(int sock) {
    struct header h;
    char payload[128];
    unsigned int len;
    if (read_header(sock, &h) < 0)
        return -1;
    len = h.length;
    recv(sock, payload, len, 0);
    return 0;
}
"""


def test_network_length_into_fixed_buffer_is_critical():
    hit = finding(PACKET, "FSB-MEM-001")
    assert hit.line == 27
    assert hit.severity == Severity.CRITICAL


def test_network_length_checked_against_capacity_is_silent():
    safe = PACKET.replace(
        "    recv(sock, payload, len, 0);\n",
        "    if (len > sizeof(payload))\n        return -1;\n    recv(sock, payload, len, 0);\n",
    )
    assert memory_ids(safe) == []


def test_strcpy_from_argv_and_strcat_chain():
    source = (
        "#include <string.h>\n"
        "int main(int argc, char **argv) {\n"
        "    char path[64];\n"
        "    if (argc < 2) return 1;\n"
        "    strcpy(path, \"/var/spool/\");\n"
        "    strcat(path, argv[1]);\n"
        "    return 0;\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-001", 6)]


def test_literal_copies_are_measured_not_guessed():
    source = (
        "#include <string.h>\n"
        "void tag(void) {\n"
        "    char small[8];\n"
        "    char exact[6];\n"
        "    strcpy(small, \"ok\");\n"
        "    strcpy(exact, \"hello\");\n"
        "    strcpy(small, \"this is far too long\");\n"
        "    strcpy(exact, \"\\x41\\x42\\103\\104\\105\");\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-001", 7)]


def test_gets_is_always_reported():
    source = "#include <stdio.h>\nvoid ask(void) {\n    char name[40];\n    gets(name);\n}\n"
    hit = finding(source, "FSB-MEM-001")
    assert (hit.line, hit.severity, hit.confidence) == (4, Severity.CRITICAL, Confidence.CERTAIN)


def test_gets_in_disabled_preprocessor_branch_is_ignored():
    source = (
        "#include <stdio.h>\n"
        "void ask(char *out, int n) {\n"
        "#if 0\n"
        "    gets(out);\n"
        "#else\n"
        "    fgets(out, n, stdin);\n"
        "#endif\n"
        "}\n"
    )
    assert memory_ids(source) == []


def test_scanf_width_is_compared_with_the_buffer():
    source = (
        "#include <stdio.h>\n"
        "void ask(void) {\n"
        "    char name[32];\n"
        "    scanf(\"%31s\", name);\n"
        "    scanf(\"%s\", name);\n"
        "    scanf(\"%64s\", name);\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-001", 5), ("FSB-MEM-001", 6)]


def test_sprintf_worst_case_length_exceeds_buffer():
    source = (
        "#include <stdio.h>\n"
        "void label(int id, const char *who) {\n"
        "    char small[8];\n"
        "    char wide[64];\n"
        "    sprintf(wide, \"id=%d\", id);\n"
        "    sprintf(small, \"id=%d\", id);\n"
        "    sprintf(wide, \"user %s\", who);\n"
        "}\n"
    )
    ids = found(source)
    assert ("FSB-MEM-001", 6) in ids
    assert ("FSB-MEM-001", 7) in ids
    assert ("FSB-MEM-001", 5) not in ids


def test_struct_member_array_size_comes_from_the_declared_type():
    source = (
        "#include <stdio.h>\n#include <string.h>\n"
        "struct user { char name[16]; int age; };\n"
        "struct group { char name[256]; };\n"
        "void load(FILE *fp) {\n"
        "    struct user u;\n"
        "    struct group g;\n"
        "    char line[128];\n"
        "    if (!fgets(line, sizeof line, fp)) return;\n"
        "    strcpy(g.name, line);\n"
        "    strcpy(u.name, line);\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-001", 11)]


def test_same_name_arrays_in_sibling_blocks_are_not_confused():
    source = (
        "#include <string.h>\n"
        "void pick(int mode, const char *src) {\n"
        "    if (mode) {\n"
        "        char buf[4];\n"
        "        memcpy(buf, src, 4);\n"
        "    } else {\n"
        "        char buf[64];\n"
        "        memcpy(buf, src, 32);\n"
        "    }\n"
        "}\n"
    )
    assert memory_ids(source) == []


def test_constant_size_larger_than_destination():
    source = (
        "#include <string.h>\n"
        "#define WIRE_LEN 64\n"
        "enum { SLOT = 16 };\n"
        "void copy(const unsigned char *src) {\n"
        "    unsigned char slot[SLOT];\n"
        "    memcpy(slot, src, WIRE_LEN);\n"
        "    memcpy(slot, src, sizeof(slot));\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-001", 6)]


# ------------------------------------------------ FSB-MEM-002 format string


def test_received_buffer_used_as_format_is_critical():
    source = (
        "#include <stdio.h>\n#include <syslog.h>\n#include <sys/socket.h>\n"
        "void audit(int s) {\n"
        "    char msg[256];\n"
        "    int n = recv(s, msg, sizeof msg - 1, 0);\n"
        "    if (n <= 0) return;\n"
        "    msg[n] = 0;\n"
        "    syslog(LOG_INFO, msg);\n"
        "    printf(\"%s\\n\", msg);\n"
        "}\n"
    )
    hit = finding(source, "FSB-MEM-002")
    assert (hit.line, hit.severity) == (9, Severity.CRITICAL)
    assert memory_ids(source) == ["FSB-MEM-002"]


def test_format_wrappers_gettext_and_macros_are_safe():
    source = (
        "#include <stdio.h>\n#include <stdarg.h>\n#include <libintl.h>\n"
        "#define _(s) gettext(s)\n"
        "#define BANNER \"fortress %s\\n\"\n"
        "static const char usage[] = \"usage: %s file\\n\";\n"
        "void logf(const char *fmt, ...) {\n"
        "    va_list ap;\n"
        "    va_start(ap, fmt);\n"
        "    vfprintf(stderr, fmt, ap);\n"
        "    va_end(ap);\n"
        "}\n"
        "void show(const char *prog, int verbose) {\n"
        "    printf(_(\"hello %s\\n\"), prog);\n"
        "    printf(BANNER, prog);\n"
        "    fprintf(stderr, usage, prog);\n"
        "    printf(verbose ? \"%s!\\n\" : \"%s\\n\", prog);\n"
        "}\n"
    )
    assert memory_ids(source) == []


def test_parameter_used_as_format_is_reported_with_lower_confidence():
    source = "#include <stdio.h>\nvoid say(const char *text) {\n    fprintf(stderr, text);\n}\n"
    hit = finding(source, "FSB-MEM-002")
    assert (hit.line, hit.severity) == (3, Severity.MEDIUM)


# ------------------------------------------------ FSB-MEM-003 use-after-free

SESSION = """\
#include <stdlib.h>
#include <string.h>

struct session {
    int fd;
    char *buf;
};

static void session_release(struct session *s) {
    free(s->buf);
    free(s);
}

int session_close(struct session *s, int force) {
    if (force)
        session_release(s);
    return s->fd;
}
"""


def test_use_after_free_through_a_same_file_helper():
    hit = finding(SESSION, "FSB-MEM-003")
    assert hit.line == 17
    # Chỉ một nhánh giải phóng: "có thể" đã giải phóng.
    assert hit.confidence == Confidence.MEDIUM


def test_helper_free_followed_by_return_is_silent():
    safe = SESSION.replace(
        "    if (force)\n        session_release(s);\n    return s->fd;\n",
        "    int fd = s->fd;\n    if (force)\n        session_release(s);\n    return fd;\n",
    )
    assert memory_ids(safe) == []


def test_definite_use_after_free_is_high_confidence():
    source = (
        "#include <stdlib.h>\n"
        "struct node { struct node *next; int v; };\n"
        "int pop(struct node *head) {\n"
        "    free(head);\n"
        "    return head->v;\n"
        "}\n"
    )
    hit = finding(source, "FSB-MEM-003")
    assert (hit.line, hit.confidence) == (5, Confidence.HIGH)


def test_cpp_delete_then_member_call():
    source = (
        "class Job { public: void run(); };\n"
        "void finish(Job *job, bool cancel) {\n"
        "    delete job;\n"
        "    if (cancel)\n"
        "        return;\n"
        "    job->run();\n"
        "}\n"
    )
    assert ("FSB-MEM-003", 6) in found(source, CPP)


@pytest.mark.parametrize(
    "body",
    [
        # danh sách liên kết: lấy next trước khi giải phóng
        "    while (n) {\n        struct node *next = n->next;\n        free(n);\n        n = next;\n    }\n",
        "    struct node *next;\n    for (; n; n = next) {\n        next = n->next;\n        free(n);\n    }\n",
        # cấp phát lại mỗi vòng
        "    for (int i = 0; i < 4; i++) {\n        char *p = malloc(8);\n        p[0] = 1;\n        free(p);\n    }\n",
        # giải phóng ở nhánh lỗi rồi thoát
        "    char *p = malloc(8);\n    if (!n) {\n        free(p);\n        return;\n    }\n    p[0] = 1;\n    free(p);\n",
        # gán NULL sau khi giải phóng
        "    char *p = malloc(8);\n    free(p);\n    p = NULL;\n    if (p) p[0] = 1;\n",
        # realloc thất bại: chỉ giải phóng bản cũ rồi thoát
        "    char *p = malloc(8);\n    char *t = realloc(p, 64);\n    if (!t) {\n        free(p);\n        return;\n    }\n    p = t;\n    p[0] = 1;\n    free(p);\n",
        # sizeof sau free không đọc bộ nhớ
        "    char *p = malloc(8);\n    free(p);\n    size_t k = sizeof *p;\n    (void)k;\n",
    ],
)
def test_ordinary_ownership_patterns_are_silent(body):
    source = "#include <stdlib.h>\nstruct node { struct node *next; };\nvoid walk(struct node *n) {\n" + body + "}\n"
    assert memory_ids(source) == [], source


# ---------------------------------------------------- FSB-MEM-004 double free


def test_double_free_through_goto_cleanup():
    source = (
        "#include <stdlib.h>\n#include <stdio.h>\n"
        "int load(const char *path) {\n"
        "    char *buf = malloc(256);\n"
        "    FILE *fp = fopen(path, \"rb\");\n"
        "    if (!fp) {\n"
        "        free(buf);\n"
        "        goto fail;\n"
        "    }\n"
        "    fclose(fp);\n"
        "    free(buf);\n"
        "    return 0;\n"
        "fail:\n"
        "    free(buf);\n"
        "    return -1;\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-004", 14)]


def test_cleanup_label_with_null_reset_is_silent():
    source = (
        "#include <stdlib.h>\n#include <stdio.h>\n"
        "int load(const char *path) {\n"
        "    char *buf = malloc(256);\n"
        "    FILE *fp = fopen(path, \"rb\");\n"
        "    if (!fp) {\n"
        "        free(buf);\n"
        "        buf = NULL;\n"
        "        goto fail;\n"
        "    }\n"
        "    fclose(fp);\n"
        "    return 0;\n"
        "fail:\n"
        "    free(buf);\n"
        "    return -1;\n"
        "}\n"
    )
    assert memory_ids(source) == []


def test_double_free_after_error_branch_falls_through():
    source = (
        "#include <stdlib.h>\n"
        "void drop(char *p, int err) {\n"
        "    if (err)\n"
        "        free(p);\n"
        "    free(p);\n"
        "}\n"
    )
    hit = finding(source, "FSB-MEM-004")
    assert (hit.line, hit.confidence) == (5, Confidence.MEDIUM)


# ------------------------------------------- FSB-MEM-005 tràn số nguyên


ALLOC = """\
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

struct item { uint32_t id; char label[60]; };

struct item *load_items(int fd) {
    uint32_t count;
    if (read(fd, &count, sizeof count) != sizeof count)
        return NULL;
    count = ntohl(count);
    struct item *items = malloc(count * sizeof(struct item));
    if (!items)
        return NULL;
    read(fd, items, count * sizeof(struct item));
    return items;
}
"""


def test_wire_count_multiplied_into_malloc():
    hit = finding(ALLOC, "FSB-MEM-005")
    assert (hit.line, hit.severity, hit.confidence) == (13, Severity.HIGH, Confidence.HIGH)


@pytest.mark.parametrize(
    "fix",
    [
        ("malloc(count * sizeof(struct item))", "calloc(count, sizeof(struct item))"),
        (
            "    struct item *items = malloc",
            "    if (count > SIZE_MAX / sizeof(struct item))\n        return NULL;\n    struct item *items = malloc",
        ),
        ("    struct item *items = malloc", "    if (count > 4096)\n        return NULL;\n    struct item *items = malloc"),
    ],
)
def test_overflow_checked_or_calloc_is_silent(fix):
    safe = ALLOC.replace(*fix)
    assert "FSB-MEM-005" not in memory_ids(safe)


def test_narrow_length_plus_one_does_not_wrap():
    source = (
        "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n"
        "char *word(FILE *fp) {\n"
        "    uint16_t wlen;\n"
        "    if (fread(&wlen, 2, 1, fp) != 1) return NULL;\n"
        "    char *w = malloc(wlen + 1);\n"
        "    return w;\n"
        "}\n"
    )
    assert memory_ids(source) == []


def test_signed_length_with_only_an_upper_bound():
    source = (
        "#include <string.h>\n#include <sys/socket.h>\n#include <arpa/inet.h>\n"
        "void frame(int s) {\n"
        "    char out[256];\n"
        "    char hdr[4];\n"
        "    int len;\n"
        "    recv(s, hdr, 4, 0);\n"
        "    len = ntohl(*(int *)hdr);\n"
        "    if (len > (int)sizeof(out))\n"
        "        return;\n"
        "    memcpy(out, hdr, len);\n"
        "}\n"
    )
    assert ("FSB-MEM-005", 12) in found(source)
    both = source.replace("if (len > (int)sizeof(out))", "if (len < 0 || len > (int)sizeof(out))")
    assert memory_ids(both) == []


# --------------------------------------------------- FSB-MEM-006 lệch một


def test_loop_bound_off_by_one():
    source = (
        "#define SLOTS 10\n"
        "static int table[SLOTS];\n"
        "void reset(void) {\n"
        "    for (int i = 0; i <= SLOTS; i++)\n"
        "        table[i] = 0;\n"
        "}\n"
        "void reset_ok(void) {\n"
        "    for (int i = 0; i < SLOTS; i++)\n"
        "        table[i] = 0;\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-006", 5)]


def test_read_count_used_as_terminator_index():
    source = (
        "#include <unistd.h>\n"
        "void line(int fd) {\n"
        "    char buf[64];\n"
        "    ssize_t n = read(fd, buf, sizeof buf);\n"
        "    if (n <= 0) return;\n"
        "    buf[n] = 0;\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-006", 6)]
    fixed = source.replace("read(fd, buf, sizeof buf)", "read(fd, buf, sizeof buf - 1)")
    assert memory_ids(fixed) == []


def test_strncat_with_full_buffer_size():
    source = (
        "#include <string.h>\n"
        "void join(char *dst_in, const char *s) {\n"
        "    char d[32] = \"\";\n"
        "    strncat(d, s, sizeof(d));\n"
        "    strncat(d, s, sizeof(d) - strlen(d) - 1);\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-006", 4)]


def test_strncpy_without_terminator():
    source = (
        "#include <string.h>\n"
        "void name(const char *s) {\n"
        "    char d[16];\n"
        "    strncpy(d, s, sizeof d);\n"
        "}\n"
    )
    assert found(source) == [("FSB-MEM-006", 4)]
    terminated = source.replace("sizeof d);\n", "sizeof d - 1);\n    d[sizeof d - 1] = '\\0';\n")
    assert memory_ids(terminated) == []


# ------------------------------------------------------ Objective-C, C++


def test_objective_c_file_runs_the_same_rules():
    source = (
        "#import <Foundation/Foundation.h>\n"
        "@implementation Greeter\n"
        "- (void)greet:(const char *)who {\n"
        "    char buf[16];\n"
        "    strcpy(buf, who);\n"
        "    NSLog(@\"hi %s\", buf);\n"
        "}\n"
        "@end\n"
    )
    assert ("FSB-MEM-001", 5) in found(source, OBJC)


def test_cpp_classes_namespaces_and_templates_parse():
    source = (
        "#include <cstring>\n#include <vector>\n"
        "namespace net {\n"
        "template <typename T> class Buffer {\n"
        "public:\n"
        "    explicit Buffer(size_t n) : data_(n) {}\n"
        "    void copy(const char *src) {\n"
        "        char tmp[8];\n"
        "        std::strcpy(tmp, src);\n"
        "    }\n"
        "private:\n"
        "    std::vector<T> data_;\n"
        "};\n"
        "}\n"
    )
    assert found(source, CPP) == [("FSB-MEM-001", 9)]


# --------------------------------------------------------------- bền vững


@pytest.mark.parametrize(
    "source",
    [
        "",
        "int main(",
        "void f() { if (x) { free(p); ",
        "#if 1\nvoid f(void) {\n#else\nvoid g(void) {\n#endif\n}\n",
        "char a[] = {1, 2, 3};\nvoid f(void) { a[3] = 0; }\n",
        "void f(void) { char b[(1 << 40)]; memcpy(b, \"x\", 1); }\n",
        "#define X(a) a##a\nvoid f(void) { X(y)(); }\n",
    ],
)
def test_malformed_input_does_not_crash(source):
    scan_source(source, C, "mau.c", Config())
    scan_source(source, CPP, "mau.cpp", Config())


def test_large_generated_file_finishes_within_budget():
    body = "".join(
        "int f%d(const char *s) {\n    char b[32];\n    snprintf(b, sizeof b, \"%%s\", s);\n    return b[0];\n}\n" % i
        for i in range(1500)
    )
    result = scan_source(body, C, "big.c", Config())
    assert [f for f in result if f.rule_id.startswith("FSB-MEM")] == []


def test_analyzer_respects_a_tiny_budget():
    from fortress_scan.analysis.base import AnalysisUnit
    from fortress_scan.analysis.native.memory import NativeMemoryAnalyzer

    unit = AnalysisUnit(relative_path="mau.c", language=C, source=PACKET * 20, config=Config())
    budget = Budget(50, 5.0)
    NativeMemoryAnalyzer().analyze(unit, budget)
    assert budget.exhausted



def test_sample_corpus_pair():
    from pathlib import Path

    samples = Path(__file__).parent / "samples"
    vulnerable = (samples / "vulnerable" / "packet.c").read_text(encoding="utf-8")
    safe = (samples / "safe" / "packet.c").read_text(encoding="utf-8")
    ids = {f.rule_id for f in scan_source(vulnerable, C, "packet.c", Config())}
    assert {"FSB-MEM-001", "FSB-MEM-002", "FSB-MEM-004", "FSB-MEM-005", "FSB-CMD-001"} <= ids
    assert scan_source(safe, C, "packet.c", Config(min_severity=Severity.INFO)) == []


def test_inline_suppression_uses_c_comments():
    source = (
        "#include <string.h>\n"
        "void copy(const char *src) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, src); // fortress-scan: ignore FSB-MEM-001\n"
        "}\n"
    )
    assert memory_ids(source) == []


def test_directive_inside_a_c_string_does_not_suppress():
    source = (
        "#include <string.h>\n"
        "const char *note = \"// fortress-scan: ignore-file\";\n"
        "void copy(const char *src) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, src);\n"
        "}\n"
    )
    assert memory_ids(source) == ["FSB-MEM-001"]
