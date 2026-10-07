"""Những mối nối mà ứng dụng Node thật dựa vào, nhưng chỉ thấy được khi đọc cả dự án.

Mỗi test ở đây là một hình dạng lấy từ mã thật: service xuất ra một thể hiện
duy nhất, câu SQL dựng sẵn nằm ở một trường, phụ thuộc có giá trị mặc định,
hàng đợi tạo một nơi và dùng ở hai nơi khác. Thiếu mối nối, đường đi đứt ở
ranh giới tệp và phát hiện biến mất hoàn toàn.
"""

from __future__ import annotations

from pathlib import Path

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan


def _project(root: Path, files: dict) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _hits(root: Path, rule_id: str, path: str):
    result = scan(str(root), Config())
    return sorted(f.line for f in result.findings if f.rule_id == rule_id and f.path == path)


def test_module_exporting_a_single_instance_is_callable_across_files(tmp_path: Path):
    """`module.exports = new Repo()` rồi `repo.byName(...)` ở tệp khác."""
    _project(
        tmp_path,
        {
            "app.js": (
                "const repo = require('./repo');\n"
                "app.get('/p', (req, res) => repo.byName(req.query.n));\n"
            ),
            "repo.js": (
                "const { Pool } = require('pg');\n"
                "class ProductRepository {\n"
                "  constructor() { this.pool = new Pool(); }\n"
                "  byName(n) { return this.pool.query(\"SELECT * FROM p WHERE n = '\" + n + \"'\"); }\n"
                "}\n"
                "module.exports = new ProductRepository();\n"
            ),
        },
    )
    assert _hits(tmp_path, "FSB-SQL-001", "app.js") == [2]


def test_namespace_import_still_needs_a_real_named_export(tmp_path: Path):
    """ESM `import * as m` chỉ thấy tên được xuất, không thấy thành viên của default."""
    _project(
        tmp_path,
        {
            "app.mjs": (
                "import * as repo from './repo.mjs';\n"
                "app.get('/p', (req, res) => repo.byName(req.query.n));\n"
            ),
            "repo.mjs": (
                "class ProductRepository {\n"
                "  byName(n) { return this.pool.query(\"SELECT * FROM p WHERE n = '\" + n + \"'\"); }\n"
                "}\n"
                "export default new ProductRepository();\n"
            ),
        },
    )
    assert _hits(tmp_path, "FSB-SQL-001", "app.mjs") == []


_BASE = (
    "const { Pool } = require('pg');\n"
    "class BaseRepository {\n"
    "  constructor() { this.pool = new Pool(); }\n"
    "  query(sql, params) { return this.pool.query(sql, params); }\n"
    "  where(clause) { return this.query(this.listQuery + clause); }\n"
    "}\n"
    "module.exports = BaseRepository;\n"
)


def test_query_prefix_in_a_subclass_field_proves_the_sink_is_sql(tmp_path: Path):
    """`where()` ở lớp cơ sở chỉ chạy trên thể hiện của lớp con, nên lấy hằng của lớp con."""
    _project(
        tmp_path,
        {
            "app.js": (
                "const repo = require('./repo');\n"
                "app.get('/p', (req, res) => repo.byName(req.query.n));\n"
            ),
            "base.js": _BASE,
            "repo.js": (
                "const BaseRepository = require('./base');\n"
                "class ProductRepository extends BaseRepository {\n"
                "  constructor() { super(); this.listQuery = 'SELECT * FROM products WHERE '; }\n"
                "  byName(n) { return this.where(\"n = '\" + n + \"'\"); }\n"
                "}\n"
                "module.exports = new ProductRepository();\n"
            ),
        },
    )
    assert _hits(tmp_path, "FSB-SQL-001", "app.js") == [2]


def test_query_prefix_from_a_json_config_field(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.js": (
                "const repo = require('./repo');\n"
                "app.get('/p', (req, res) => repo.byName(req.query.n));\n"
            ),
            "base.js": _BASE,
            "config.json": '{ "listQuery": "SELECT * FROM products WHERE " }\n',
            "repo.js": (
                "const BaseRepository = require('./base');\n"
                "const config = require('./config.json');\n"
                "class ProductRepository extends BaseRepository {\n"
                "  constructor() { super(); this.listQuery = config.listQuery; }\n"
                "  byName(n) { return this.where(\"n = '\" + n + \"'\"); }\n"
                "}\n"
                "module.exports = new ProductRepository();\n"
            ),
        },
    )
    assert _hits(tmp_path, "FSB-SQL-001", "app.js") == [2]


def test_a_field_without_a_query_prefix_stays_unproven(tmp_path: Path):
    """Không có hằng nào chứng minh chuỗi là SQL thì hàm bọc không thành sink SQL."""
    _project(
        tmp_path,
        {
            "app.js": (
                "const repo = require('./repo');\n"
                "app.get('/p', (req, res) => repo.byName(req.query.n));\n"
            ),
            "base.js": _BASE,
            "repo.js": (
                "const BaseRepository = require('./base');\n"
                "class ProductRepository extends BaseRepository {\n"
                "  constructor() { super(); this.listQuery = process.env.PREFIX; }\n"
                "  byName(n) { return this.where(\"n = '\" + n + \"'\"); }\n"
                "}\n"
                "module.exports = new ProductRepository();\n"
            ),
        },
    )
    assert _hits(tmp_path, "FSB-SQL-001", "app.js") == []


def test_dependency_with_a_default_construction_keeps_its_type(tmp_path: Path):
    """`this.repo = repo || new Repo()`: không ai truyền đối số thì kiểu là vế sau."""
    _project(
        tmp_path,
        {
            "app.js": (
                "const service = require('./service');\n"
                "app.get('/p', (req, res) => service.search(req.query.n));\n"
            ),
            "service.js": (
                "const ProductRepository = require('./repo');\n"
                "class CatalogService {\n"
                "  constructor(repository) { this.repository = repository || new ProductRepository(); }\n"
                "  search(n) { return this.repository.byName(n); }\n"
                "}\n"
                "module.exports = new CatalogService();\n"
            ),
            "repo.js": (
                "const { Pool } = require('pg');\n"
                "class ProductRepository {\n"
                "  constructor() { this.pool = new Pool(); }\n"
                "  byName(n) { return this.pool.query(\"SELECT * FROM p WHERE n = '\" + n + \"'\"); }\n"
                "}\n"
                "module.exports = ProductRepository;\n"
            ),
        },
    )
    assert _hits(tmp_path, "FSB-SQL-001", "app.js") == [2]


_QUEUE_FILES = {
    "queue/index.js": (
        "const Queue = require('bull');\n"
        "const thumbnails = new Queue('thumbnails');\n"
        "const mails = new Queue('mails');\n"
        "module.exports = { thumbnails, mails };\n"
    ),
    "api.js": (
        "const { thumbnails } = require('./queue');\n"
        "app.post('/t', (req, res) => thumbnails.add({ source: req.body.source }));\n"
    ),
    "worker.js": (
        "const { execSync, execFile } = require('child_process');\n"
        "const { thumbnails, mails } = require('./queue');\n"
        "thumbnails.process(async (job) => {\n"
        "  execSync('convert ' + job.data.source);\n"
        "});\n"
        "mails.process(async (job) => {\n"
        "  execFile('sendmail', ['-t', job.data.to]);\n"
        "});\n"
    ),
}


def test_queue_created_in_a_third_file_still_carries_the_payload(tmp_path: Path):
    _project(tmp_path, dict(_QUEUE_FILES))
    assert _hits(tmp_path, "FSB-CMD-001", "worker.js") == [4]


def test_a_queue_nobody_feeds_stays_silent(tmp_path: Path):
    files = dict(_QUEUE_FILES)
    files["api.js"] = (
        "const { thumbnails } = require('./queue');\n"
        "app.post('/t', (req, res) => thumbnails.add({ source: 'fixed.png' }));\n"
    )
    _project(tmp_path, files)
    assert _hits(tmp_path, "FSB-CMD-001", "worker.js") == []
