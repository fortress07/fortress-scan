"""Chỉ mục xuyên file trên tệp lớn và tệp rút gọn.

Repo thật mang theo thư viện dựng sẵn ( jquery.js, bootstrap.bundle.min.js ):
hàng trăm hàm trong một tệp, nhiều hàm cùng tên trên cùng một dòng. Hai điều
đó từng làm chỉ mục vừa sai vừa chậm, nên mỗi test ở đây dựng đúng hình dạng
đó bằng mã sinh tại chỗ thay vì tải thư viện thật về.
"""

from __future__ import annotations

from fortress_scan.analysis.xfile import builder
from fortress_scan.analysis.xfile.builder import _MAX_FIXPOINT_FUNCTIONS
from fortress_scan.core.config import Config


def _source(name: str, text: str, language: str = "javascript") -> builder.SourceFile:
    return builder.SourceFile(relative=name, language=language, read=lambda: text)


def _build(*sources: builder.SourceFile):
    return builder.build(list(sources), [], Config())


def test_same_name_on_one_line_keeps_separate_summaries():
    """Tệp rút gọn có nhiều hàm cùng tên trên dòng 1; không được lẫn summary."""
    project, report = _build(
        _source(
            "bundle.js",
            "const cp = require('child_process');\n"
            "function run(x){cp.exec(x)}function run(y){console.log(y)}\n",
        )
    )
    functions = sorted(project.facts["bundle.js"].functions, key=lambda f: f.body_start)
    assert [f.qualname for f in functions] == ["run", "run"]
    assert len({f.key for f in functions}) == 2
    dangerous, harmless = functions
    assert project.summaries[dangerous.key].sinks
    assert not project.summaries[harmless.key].sinks
    # Khóa trùng làm hai hàm ghi đè summary của nhau mãi, nên vòng lặp không
    # bao giờ dừng; một tệp bé thế này phải hội tụ.
    assert report.converged


def _many_functions(count: int) -> str:
    lines = [
        "const cp = require('child_process');",
        "function reach(cmd){cp.exec(cmd)}",
    ]
    lines += ["function noop%d(a){return a + %d}" % (index, index) for index in range(count)]
    lines.append("module.exports = { reach };")
    return "\n".join(lines) + "\n"


def test_file_past_the_function_limit_is_summarized_once():
    project, report = _build(
        _source("vendor.js", _many_functions(_MAX_FIXPOINT_FUNCTIONS + 10)),
        _source("small.js", "function helper(a){return a}\nmodule.exports={helper};\n"),
    )
    assert report.shallow == ["vendor.js"]
    # Vẫn có summary: lời gọi một chặng từ tệp khác vào nó vẫn nối được.
    reach = next(f for f in project.facts["vendor.js"].functions if f.name == "reach")
    assert project.summaries[reach.key].sinks


def test_file_under_the_limit_keeps_the_full_fixpoint():
    project, report = _build(_source("app.js", _many_functions(_MAX_FIXPOINT_FUNCTIONS - 10)))
    assert report.shallow == []


def test_sink_behind_a_large_vendor_file_is_still_reported(tmp_path):
    """Nguồn ở tệp của ứng dụng, sink ở tệp lớn: một chặng nên phải thấy."""
    from fortress_scan.core.engine import scan

    (tmp_path / "vendor.js").write_text(_many_functions(_MAX_FIXPOINT_FUNCTIONS + 10), encoding="utf-8")
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const vendor = require('./vendor');\n"
        "const app = express();\n"
        "app.get('/run', (req, res) => {\n"
        "  vendor.reach(req.query.cmd);\n"
        "  res.end('ok');\n"
        "});\n",
        encoding="utf-8",
    )
    result = scan(str(tmp_path), Config())
    hits = [f for f in result.findings if f.rule_id == "FSB-CMD-001" and f.path == "server.js"]
    assert [f.line for f in hits] == [5]
