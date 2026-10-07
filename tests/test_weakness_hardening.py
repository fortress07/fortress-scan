"""Zip slip, quyền tệp, tệp tạm và chế độ debug.

Bốn họ này quyết định dựa trên MỘT HẰNG SỐ -- `0o777`, `/tmp/x`, `debug=True`,
hay sự VẮNG MẶT của `filter=`. Vì vậy chúng dễ dò đúng, và cũng rất dễ dò bừa.
Ba lằn ranh dưới đây được vạch theo hành vi thật của thư viện, không vạch cho
tiện, và mỗi lằn ranh có mẫu SILENT giữ nó lại:

* `zipfile.extractall` TỰ chuẩn hoá tên thành viên ( `ZipFile._extract_member`
  bỏ dấu phân cách đầu và `..` ), `tarfile` thì không -- đó là CVE-2007-4559.
  Nên chỉ tarfile bị báo.
* `chmod` bỏ qua umask; `open`, `mkdir`, `os.makedirs`, `os.MkdirAll` thì
  không. Nên chỉ họ `chmod` bị báo: `os.MkdirAll(p, 0777)` với umask 022 ra
  0755, và hình đó gặp khắp nơi trong mã Go thật.
* `app.run(debug=True)` trong `if __name__ == "__main__"` là lối chạy trên máy
  dev, không phải cấu hình đi kèm ứng dụng.
"""

from __future__ import annotations

from typing import List, Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Confidence
from fortress_scan.languages import CSHARP, GO, JAVA, JAVASCRIPT, PHP, PYTHON, RUBY, SHELL


def findings(language: str, source: str, path: str = "app/service"):
    return scan_source(source, language, path, Config())


def rule_ids(language: str, source: str, path: str = "app/service") -> List[str]:
    return [f.rule_id for f in findings(language, source, path)]


Case = Tuple[str, str, str]

FIRES: List[Case] = [
    # ---- PATH-002: tarfile của Python, cả ba lối giữ đối tượng
    (
        "FSB-PATH-002",
        PYTHON,
        "import tarfile\n\n\ndef unpack(p, dest):\n    tarfile.open(p).extractall(dest)\n",
    ),
    (
        "FSB-PATH-002",
        PYTHON,
        "import tarfile\n\n\ndef unpack(p, dest):\n    with tarfile.open(p) as tar:\n"
        "        tar.extractall(dest)\n",
    ),
    (
        "FSB-PATH-002",
        PYTHON,
        "import tarfile\n\n\ndef unpack(p, dest):\n    tar = tarfile.open(p)\n"
        "    tar.extractall(dest)\n",
    ),
    (
        "FSB-PATH-002",
        PYTHON,
        "import shutil\n\n\ndef unpack(p, dest):\n    shutil.unpack_archive(p, dest)\n",
    ),
    # ---- PATH-002: Java và Go
    (
        "FSB-PATH-002",
        JAVA,
        "class U {\n  void unzip(ZipInputStream zis, File dir) throws Exception {\n"
        "    ZipEntry entry = zis.getNextEntry();\n"
        "    File out = new File(dir, entry.getName());\n"
        "    new FileOutputStream(out).write(buf);\n  }\n}\n",
    ),
    (
        "FSB-PATH-002",
        GO,
        "func unpack(r io.Reader, dest string) error {\n\ttr := tar.NewReader(r)\n"
        "\thdr, _ := tr.Next()\n\ttarget := filepath.Join(dest, hdr.Name)\n"
        "\treturn os.WriteFile(target, nil, 0600)\n}\n",
    ),
    # ---- PERM-001: họ chmod, 6 ngôn ngữ
    ("FSB-PERM-001", PYTHON, "import os\n\n\ndef publish(p):\n    os.chmod(p, 0o777)\n"),
    (
        "FSB-PERM-001",
        PYTHON,
        "from pathlib import Path\n\n\ndef publish(p):\n    Path(p).chmod(0o666)\n",
    ),
    ("FSB-PERM-001", PYTHON, "import os\n\n\ndef boot():\n    os.umask(0)\n"),
    ("FSB-PERM-001", GO, "func publish(p string) error {\n\treturn os.Chmod(p, 0777)\n}\n"),
    ("FSB-PERM-001", PHP, "<?php\nchmod($file, 0777);\n"),
    ("FSB-PERM-001", RUBY, "FileUtils.chmod(0777, path)\n"),
    (
        "FSB-PERM-001",
        JAVA,
        "class A { void f(File file) { file.setWritable(true, false); } }\n",
    ),
    (
        "FSB-PERM-001",
        JAVA,
        'class A { void f() { Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxrwxrwx")); } }\n',
    ),
    ("FSB-PERM-001", SHELL, "#!/bin/bash\nchmod -R 777 /var/www/html\n"),
    ("FSB-PERM-001", SHELL, "#!/bin/bash\nchmod a+w /var/www/html/uploads\n"),
    # ---- TMP-001
    (
        "FSB-TMP-001",
        PYTHON,
        "import tempfile\n\n\ndef stage():\n    return tempfile.mktemp()\n",
    ),
    (
        "FSB-TMP-001",
        PYTHON,
        "def stage(data):\n    with open('/tmp/fortress-cache', 'w') as fh:\n"
        "        fh.write(data)\n",
    ),
    (
        "FSB-TMP-001",
        JAVASCRIPT,
        "const fs = require('fs');\nfs.writeFileSync('/tmp/session-cache', data);\n",
    ),
    (
        "FSB-TMP-001",
        JAVA,
        'class A { void f() throws Exception { new FileOutputStream(new File("/tmp/app.lock")); } }\n',
    ),
    ("FSB-TMP-001", GO, 'func f() {\n\tos.WriteFile("/tmp/app.state", data, 0600)\n}\n'),
    ("FSB-TMP-001", PHP, "<?php\nfile_put_contents('/tmp/upload.tmp', $data);\n"),
    ("FSB-TMP-001", SHELL, '#!/bin/bash\necho "$TOKEN" > /tmp/deploy.log\n'),
    # ---- DEBUG-001
    (
        "FSB-DEBUG-001",
        PYTHON,
        "from flask import Flask\n\napp = Flask(__name__)\napp.run(debug=True)\n",
    ),
    (
        "FSB-DEBUG-001",
        PYTHON,
        "from werkzeug.debug import DebuggedApplication\n\napp = DebuggedApplication(app, evalex=True)\n",
    ),
    (
        "FSB-DEBUG-001",
        CSHARP,
        "public void Configure(IApplicationBuilder app) {\n    app.UseDeveloperExceptionPage();\n}\n",
    ),
    ("FSB-DEBUG-001", PHP, "<?php\nini_set('display_errors', 1);\n"),
]

SILENT: List[Case] = [
    # `filter=` là đúng phép vá của PEP 706; `members=` là tự lọc tay.
    (
        "FSB-PATH-002",
        PYTHON,
        "import tarfile\n\n\ndef unpack(p, dest):\n    with tarfile.open(p) as tar:\n"
        "        tar.extractall(dest, filter='data')\n",
    ),
    # zipfile tự chuẩn hoá tên thành viên.
    (
        "FSB-PATH-002",
        PYTHON,
        "import zipfile\n\n\ndef unpack(p, dest):\n    with zipfile.ZipFile(p) as z:\n"
        "        z.extractall(dest)\n",
    ),
    (
        "FSB-PATH-002",
        JAVA,
        "class U {\n  void unzip(ZipInputStream zis, File dir) throws Exception {\n"
        "    ZipEntry entry = zis.getNextEntry();\n"
        "    File out = new File(dir, entry.getName());\n"
        "    if (!out.getCanonicalPath().startsWith(dir.getCanonicalPath())) {\n"
        "      throw new IOException();\n    }\n  }\n}\n",
    ),
    (
        "FSB-PATH-002",
        GO,
        "func unpack(r io.Reader, dest string) error {\n\ttr := tar.NewReader(r)\n"
        "\thdr, _ := tr.Next()\n\ttarget := filepath.Join(dest, hdr.Name)\n"
        "\tif !strings.HasPrefix(target, dest) {\n\t\treturn errBad\n\t}\n\treturn nil\n}\n",
    ),
    # filepath.Join không dính gì tới tệp nén thì không phải zip slip.
    (
        "FSB-PATH-002",
        GO,
        "func build(dest string, cfg Config) string {\n\treturn filepath.Join(dest, cfg.Name)\n}\n",
    ),
    # ---- PERM-001: quyền hẹp, và chế độ TẠO tệp ( còn bị umask che )
    ("FSB-PERM-001", PYTHON, "import os\n\n\ndef publish(p):\n    os.chmod(p, 0o644)\n"),
    ("FSB-PERM-001", PYTHON, "import os\n\n\ndef publish(p):\n    os.makedirs(p, 0o777)\n"),
    ("FSB-PERM-001", GO, "func publish(p string) error {\n\treturn os.MkdirAll(p, 0777)\n}\n"),
    ("FSB-PERM-001", PHP, "<?php\nchmod($file, 0644);\n"),
    ("FSB-PERM-001", SHELL, "#!/bin/bash\nchmod 644 /var/www/html/index.php\n"),
    ("FSB-PERM-001", SHELL, "#!/bin/bash\nchmod 755 /usr/local/bin/deploy\n"),
    # setWritable(true) một tham số là chỉ chủ sở hữu.
    ("FSB-PERM-001", JAVA, "class A { void f(File file) { file.setWritable(true); } }\n"),
    # ---- TMP-001: đọc, và hàm tạo tệp tạm đúng cách
    ("FSB-TMP-001", PYTHON, "def stage():\n    return open('/tmp/fortress-cache').read()\n"),
    (
        "FSB-TMP-001",
        PYTHON,
        "import tempfile\n\n\ndef stage():\n    fd, name = tempfile.mkstemp()\n    return name\n",
    ),
    ("FSB-TMP-001", SHELL, '#!/bin/bash\nf=$(mktemp)\necho hi > "$f"\n'),
    ("FSB-TMP-001", GO, 'func f() {\n\tos.ReadFile("/tmp/app.state")\n}\n'),
    # ---- DEBUG-001
    (
        "FSB-DEBUG-001",
        PYTHON,
        "from flask import Flask\n\napp = Flask(__name__)\nif __name__ == '__main__':\n"
        "    app.run(debug=True)\n",
    ),
    (
        "FSB-DEBUG-001",
        PYTHON,
        "from flask import Flask\n\napp = Flask(__name__)\napp.run(debug=False)\n",
    ),
    (
        "FSB-DEBUG-001",
        CSHARP,
        "public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {\n"
        "    if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }\n}\n",
    ),
    ("FSB-DEBUG-001", PHP, "<?php\nini_set('display_errors', 0);\n"),
]


@pytest.mark.parametrize("rule,language,source", FIRES)
def test_rule_fires(rule: str, language: str, source: str):
    assert rule in rule_ids(language, source), source


@pytest.mark.parametrize("rule,language,source", SILENT)
def test_rule_stays_silent(rule: str, language: str, source: str):
    assert rule not in rule_ids(language, source), source


def test_debug_setting_only_in_a_settings_file_and_not_a_dev_one():
    source = "DEBUG = True\nALLOWED_HOSTS = ['*']\n"
    assert "FSB-DEBUG-001" in rule_ids(PYTHON, source, "config/settings.py")
    assert "FSB-DEBUG-001" in rule_ids(PYTHON, source, "myapp/settings/production.py")
    assert "FSB-DEBUG-001" not in rule_ids(PYTHON, source, "config/settings/dev.py")
    assert "FSB-DEBUG-001" not in rule_ids(PYTHON, source, "config/settings/local.py")
    # Không phải tệp cấu hình thì `DEBUG = True` chỉ là một hằng của module.
    assert "FSB-DEBUG-001" not in rule_ids(PYTHON, source, "app/views.py")


def test_unpack_archive_is_lower_confidence_than_tarfile():
    """shutil chọn bộ giải nén theo đuôi tệp, nên chưa chắc là tar."""
    tar = "import tarfile\n\n\ndef f(p, d):\n    tarfile.open(p).extractall(d)\n"
    shutil_any = "import shutil\n\n\ndef f(p, d):\n    shutil.unpack_archive(p, d)\n"
    (first,) = [f for f in findings(PYTHON, tar) if f.rule_id == "FSB-PATH-002"]
    (second,) = [f for f in findings(PYTHON, shutil_any) if f.rule_id == "FSB-PATH-002"]
    assert second.confidence < first.confidence


def test_chmod_finding_prints_the_mode_in_octal():
    (finding,) = [
        f
        for f in findings(PYTHON, "import os\n\n\ndef f(p):\n    os.chmod(p, 0o777)\n")
        if f.rule_id == "FSB-PERM-001"
    ]
    assert "0o777" in finding.message, finding.message
    assert finding.confidence is Confidence.HIGH


def test_temp_path_finding_names_the_path():
    (finding,) = [
        f
        for f in findings(PYTHON, "def f(d):\n    open('/tmp/app.sock', 'w').write(d)\n")
        if f.rule_id == "FSB-TMP-001"
    ]
    assert finding.symbol == "/tmp/app.sock"
    assert "/tmp/app.sock" in finding.message


def test_var_tmp_and_dev_shm_count_too():
    for path in ("/var/tmp/cache.db", "/dev/shm/queue"):
        source = "def f(d):\n    open(%r, 'w').write(d)\n" % path
        assert "FSB-TMP-001" in rule_ids(PYTHON, source), path


def test_debug_in_tests_is_demoted_not_hidden():
    source = "from flask import Flask\n\napp = Flask(__name__)\napp.run(debug=True)\n"
    production = [f for f in findings(PYTHON, source, "app/wsgi.py") if f.rule_id == "FSB-DEBUG-001"]
    test = [f for f in findings(PYTHON, source, "tests/conftest.py") if f.rule_id == "FSB-DEBUG-001"]
    assert len(production) == 1 and len(test) == 1
    assert test[0].confidence < production[0].confidence


def test_umask_zero_is_only_reported_when_the_result_is_discarded():
    """`current = os.umask(0)` rồi `os.umask(current)` là lối ĐỌC umask hiện tại.

    django/core/management/templates.py làm đúng vậy, và bản đầu của rule đã
    báo nhầm vào đó.
    """
    setting = "import os\n\n\ndef boot():\n    os.umask(0)\n"
    reading = (
        "import os\n\n\ndef mode():\n    current = os.umask(0)\n"
        "    os.umask(current)\n    return current\n"
    )
    assert "FSB-PERM-001" in rule_ids(PYTHON, setting)
    assert "FSB-PERM-001" not in rule_ids(PYTHON, reading)


def test_go_umask_read_back_is_silent_too():
    reading = "func mode() int {\n\told := syscall.Umask(0)\n\tsyscall.Umask(old)\n\treturn old\n}\n"
    setting = "func boot() {\n\tsyscall.Umask(0)\n}\n"
    assert "FSB-PERM-001" not in rule_ids(GO, reading)
    assert "FSB-PERM-001" in rule_ids(GO, setting)
