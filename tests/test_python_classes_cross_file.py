"""Python xuyên file theo hướng đối tượng: lớp, kế thừa, re-export, factory.

Ứng dụng Python thật hiếm khi gọi thẳng hàm ở tệp khác. Handler gọi một
service được tạo ở cấp module, service gọi repository lưu trong thuộc tính,
repository gọi phương thức của lớp cha nằm ở tệp thứ ba, và lớp được xuất
lại qua `__init__.py`. Mỗi test ở đây dựng một mắt xích như vậy trong
tmp_path và chạy qua engine.scan(), nơi duy nhất có pha thu thập lặp.
"""

from __future__ import annotations

from pathlib import Path

from fortress_scan.core import engine
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan


def _write(root: Path, name: str, source: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _findings(result, rule_id: str):
    return [finding for finding in result.findings if finding.rule_id == rule_id]


def _layered_app(root: Path) -> None:
    _write(root, "shop/__init__.py", "")
    _write(root, "shop/db/__init__.py", "")
    _write(
        root,
        "shop/db/base.py",
        "class BaseRepository:\n"
        "    def _fetch(self, sql):\n"
        "        return self.cursor.execute(sql)\n"
        "    def _where(self, clause):\n"
        "        return self._fetch('SELECT * FROM items WHERE ' + clause)\n",
    )
    _write(
        root,
        "shop/db/items.py",
        "from .base import BaseRepository\n"
        "class ItemRepository(BaseRepository):\n"
        "    def find_like(self, term):\n"
        "        return self._where(\"name LIKE '%\" + term + \"%'\")\n",
    )
    _write(root, "shop/services/__init__.py", "from .catalog import CatalogService\n")
    _write(
        root,
        "shop/services/catalog.py",
        "from ..db.items import ItemRepository\n"
        "class CatalogService:\n"
        "    def __init__(self, repository=None):\n"
        "        self.repository = repository or ItemRepository()\n"
        "    def search(self, term):\n"
        "        return self.repository.find_like(term.strip())\n",
    )


def test_service_method_reaches_base_class_sink_through_reexport(tmp_path: Path):
    _layered_app(tmp_path)
    _write(
        tmp_path,
        "shop/api.py",
        "from flask import request\n"
        "from .services import CatalogService\n"
        "service = CatalogService()\n"
        "def search():\n"
        "    return service.search(request.args.get('q'))\n",
    )
    result = scan(str(tmp_path), Config())
    found = _findings(result, "FSB-SQL-001")
    assert [(finding.path, finding.line) for finding in found] == [("shop/api.py", 5)]
    # Đường đi kết thúc ở sink thật trong lớp cha, không phải ở lời gọi.
    assert found[0].trace[-1].path == "shop/db/base.py"
    assert not result.notices or all(
        notice.kind != "cross-file-analysis-reduced" for notice in result.notices
    )


def test_cross_file_off_keeps_the_service_call_silent(tmp_path: Path):
    _layered_app(tmp_path)
    _write(
        tmp_path,
        "shop/api.py",
        "from flask import request\n"
        "from .services import CatalogService\n"
        "service = CatalogService()\n"
        "def search():\n"
        "    return service.search(request.args.get('q'))\n",
    )
    result = scan(str(tmp_path), Config(cross_file_analysis=False))
    assert not _findings(result, "FSB-SQL-001")


def test_subclass_override_hides_the_dangerous_base_method(tmp_path: Path):
    _write(
        tmp_path,
        "base.py",
        "import os\n"
        "class Runner:\n"
        "    def run(self, cmd):\n"
        "        os.system(cmd)\n",
    )
    _write(
        tmp_path,
        "safe.py",
        "from base import Runner\n"
        "class EchoRunner(Runner):\n"
        "    def run(self, cmd):\n"
        "        print(cmd)\n",
    )
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from safe import EchoRunner\n"
        "from base import Runner\n"
        "def echo():\n"
        "    EchoRunner().run(request.args.get('c'))\n"
        "def real():\n"
        "    Runner().run(request.args.get('c'))\n",
    )
    result = scan(str(tmp_path), Config())
    assert [(finding.path, finding.line) for finding in _findings(result, "FSB-CMD-001")] == [
        ("app.py", 7)
    ]


def test_annotated_attribute_and_factory_return_give_the_type(tmp_path: Path):
    _write(
        tmp_path,
        "store.py",
        "import sqlite3\n"
        "class Store:\n"
        "    def __init__(self):\n"
        "        self.connection = sqlite3.connect('x.db')\n"
        "    def find(self, name):\n"
        "        return self.connection.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\")\n"
        "def open_store():\n"
        "    return Store()\n",
    )
    _write(
        tmp_path,
        "service.py",
        "from store import Store\n"
        "class Lookup:\n"
        "    store: Store\n"
        "    def by_name(self, name):\n"
        "        return self.store.find(name)\n",
    )
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from service import Lookup\n"
        "from store import open_store\n"
        "def one():\n"
        "    return Lookup().by_name(request.args['n'])\n"
        "def two():\n"
        "    return open_store().find(request.args['n'])\n",
    )
    result = scan(str(tmp_path), Config())
    lines = sorted(finding.line for finding in _findings(result, "FSB-SQL-001") if finding.path == "app.py")
    assert lines == [5, 7]


def test_super_call_resolves_to_the_parent_in_another_file(tmp_path: Path):
    _write(
        tmp_path,
        "base.py",
        "import subprocess\n"
        "class Exporter:\n"
        "    def export(self, name):\n"
        "        subprocess.run('tar czf ' + name, shell=True)\n",
    )
    _write(
        tmp_path,
        "child.py",
        "from base import Exporter\n"
        "class LoggedExporter(Exporter):\n"
        "    def export(self, name):\n"
        "        print('export', name)\n"
        "        return super().export(name)\n",
    )
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from child import LoggedExporter\n"
        "def run():\n"
        "    LoggedExporter().export(request.form['n'])\n",
    )
    result = scan(str(tmp_path), Config())
    assert [(finding.path, finding.line) for finding in _findings(result, "FSB-CMD-001")] == [
        ("app.py", 4)
    ]


def test_relative_import_picks_the_right_package_when_names_repeat(tmp_path: Path):
    """Hai gói cùng có db/repo.py: import tương đối phải về đúng gói của mình."""
    for package, body in (
        ("unsafe_app", "        return self.cursor.execute('SELECT ' + value)\n"),
        ("safe_app", "        return self.cursor.execute('SELECT ?', (value,))\n"),
    ):
        _write(tmp_path, "%s/__init__.py" % package, "")
        _write(tmp_path, "%s/db/__init__.py" % package, "")
        _write(
            tmp_path,
            "%s/db/repo.py" % package,
            "class Repo:\n    def get(self, value):\n" + body,
        )
        _write(
            tmp_path,
            "%s/api.py" % package,
            "from flask import request\n"
            "from .db.repo import Repo\n"
            "def view():\n"
            "    return Repo().get(request.args['v'])\n",
        )
    result = scan(str(tmp_path), Config())
    assert [(finding.path, finding.line) for finding in _findings(result, "FSB-SQL-001")] == [
        ("unsafe_app/api.py", 4)
    ]


def test_unrelated_files_are_collected_once(tmp_path: Path, monkeypatch):
    _layered_app(tmp_path)
    _write(
        tmp_path,
        "shop/api.py",
        "from flask import request\n"
        "from .services import CatalogService\n"
        "service = CatalogService()\n"
        "def search():\n"
        "    return service.search(request.args.get('q'))\n",
    )
    _write(tmp_path, "tools/standalone.py", "def add(a, b):\n    return a + b\n")
    calls = {}
    original = engine._collect_one

    def counting(discovered, config, project, xproject=None):
        calls[discovered.relative] = calls.get(discovered.relative, 0) + 1
        return original(discovered, config, project, xproject)

    monkeypatch.setattr(engine, "_collect_one", counting)
    result = scan(str(tmp_path), Config(jobs=1))
    assert _findings(result, "FSB-SQL-001")
    assert calls["tools/standalone.py"] == 1
    # Chuỗi bốn tệp cần nhiều vòng, nhưng chỉ tệp nằm trên chuỗi bị tính lại.
    assert calls["shop/services/catalog.py"] > 1


def test_round_limit_is_reported_instead_of_silently_cut(tmp_path: Path, monkeypatch):
    _layered_app(tmp_path)
    _write(
        tmp_path,
        "shop/api.py",
        "from flask import request\n"
        "from .services import CatalogService\n"
        "service = CatalogService()\n"
        "def search():\n"
        "    return service.search(request.args.get('q'))\n",
    )
    monkeypatch.setattr(engine, "_MAX_PROJECT_ROUNDS", 1)
    result = scan(str(tmp_path), Config())
    assert any(
        notice.kind == "cross-file-analysis-reduced" and "Python" in notice.summary
        for notice in result.notices
    )
