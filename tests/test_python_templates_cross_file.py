"""Luồng rời khỏi mã Python và kết thúc trong một tệp template.

`render_template("v.html", note=x)` và `{{ note|safe }}` nằm ở hai tệp khác
loại nhau, nên không đọc cả dự án thì không có cách nào nối hai đầu. Mỗi test
ở đây dựng đúng cặp đó và kiểm tra cả hai chiều: `|safe` phải báo, `{{ }}`
thường ( Jinja tự escape ) phải im.
"""

from __future__ import annotations

from pathlib import Path

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan


def _project(root: Path, files: dict) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _xss(root: Path):
    result = scan(str(root), Config())
    return sorted(
        (finding.path, finding.line)
        for finding in result.findings
        if finding.rule_id == "FSB-XSS-001"
    )


_SAFE_FILTER = "<div>{{ note|safe }}</div>\n"
_ESCAPED = "<div>{{ note }}</div>\n"


def test_safe_filter_in_the_template_makes_the_render_a_sink(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.py": (
                "from flask import render_template, request\n"
                "def view():\n"
                "    return render_template('page.html', note=request.args['note'])\n"
            ),
            "templates/page.html": _SAFE_FILTER,
        },
    )
    assert _xss(tmp_path) == [("app.py", 3)]


def test_the_trace_ends_inside_the_template(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.py": (
                "from flask import render_template, request\n"
                "def view():\n"
                "    return render_template('page.html', note=request.args['note'])\n"
            ),
            "templates/page.html": "<p>ok</p>\n<div>{{ note|safe }}</div>\n",
        },
    )
    result = scan(str(tmp_path), Config())
    finding = next(f for f in result.findings if f.rule_id == "FSB-XSS-001")
    sink = finding.trace[-1]
    assert (sink.path, sink.line) == ("templates/page.html", 2)


def test_an_escaped_placeholder_stays_silent(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.py": (
                "from flask import render_template, request\n"
                "def view():\n"
                "    return render_template('page.html', note=request.args['note'])\n"
            ),
            "templates/page.html": _ESCAPED,
        },
    )
    assert _xss(tmp_path) == []


def test_another_key_in_the_same_template_is_not_the_tainted_one(tmp_path: Path):
    """`{{ bio|safe }}` in ra `bio`; biến bẩn truyền vào là `note`."""
    _project(
        tmp_path,
        {
            "app.py": (
                "from flask import render_template, request\n"
                "def view():\n"
                "    return render_template(\n"
                "        'page.html', note=request.args['note'], bio='tĩnh'\n"
                "    )\n"
            ),
            "templates/page.html": "<div>{{ bio|safe }}</div>\n",
        },
    )
    assert _xss(tmp_path) == []


def test_render_in_a_helper_module_is_reached_from_the_handler(tmp_path: Path):
    """Hàm bọc nằm ở tệp khác: summary của nó phải mang theo sink trong template."""
    _project(
        tmp_path,
        {
            "views.py": (
                "from flask import render_template\n"
                "def show(note):\n"
                "    return render_template('page.html', note=note)\n"
            ),
            "app.py": (
                "from flask import request\n"
                "from views import show\n"
                "def handler():\n"
                "    return show(request.args['note'])\n"
            ),
            "templates/page.html": _SAFE_FILTER,
        },
    )
    assert _xss(tmp_path) == [("app.py", 4)]


def test_a_template_name_that_is_not_a_literal_proves_nothing(tmp_path: Path):
    """Tên template do người dùng chọn thì không biết tệp nào được render."""
    _project(
        tmp_path,
        {
            "app.py": (
                "from flask import render_template, request\n"
                "def view():\n"
                "    name = request.args['tpl'] + '.html'\n"
                "    return render_template(name, note=request.args['note'])\n"
            ),
            "templates/page.html": _SAFE_FILTER,
        },
    )
    assert _xss(tmp_path) == []


def test_django_render_takes_its_context_from_a_dict(tmp_path: Path):
    _project(
        tmp_path,
        {
            "views.py": (
                "from django.shortcuts import render\n"
                "def view(request):\n"
                "    return render(request, 'page.html', {'note': request.GET['note']})\n"
            ),
            "templates/page.html": _SAFE_FILTER,
        },
    )
    assert _xss(tmp_path) == [("views.py", 3)]


def test_cross_file_off_keeps_the_template_out_of_reach(tmp_path: Path):
    _project(
        tmp_path,
        {
            "app.py": (
                "from flask import render_template, request\n"
                "def view():\n"
                "    return render_template('page.html', note=request.args['note'])\n"
            ),
            "templates/page.html": _SAFE_FILTER,
        },
    )
    assert not [
        f for f in scan(str(tmp_path), Config(cross_file_analysis=False)).findings
        if f.rule_id == "FSB-XSS-001"
    ]


def test_a_form_object_in_the_context_is_not_raw_request_text(tmp_path: Path):
    """`{{ form.username|safe }}` in widget của Django, không in lại request.

    Lấy từ pygoat: thiếu chốt này thì mọi trang đăng nhập của Django thành một
    phát hiện XSS, vì dữ liệu POST đi vào constructor của form.
    """
    _project(
        tmp_path,
        {
            "forms.py": (
                "class LoginForm:\n"
                "    def __init__(self, payload=None):\n"
                "        self.payload = payload\n"
                "    def __str__(self):\n"
                "        return self.render()\n"
            ),
            "views.py": (
                "from django.shortcuts import render\n"
                "from forms import LoginForm\n"
                "def view(request):\n"
                "    return render(request, 'login.html', {'form': LoginForm(request.POST)})\n"
            ),
            "templates/login.html": "<div>{{ form.username|safe }}</div>\n",
        },
    )
    assert _xss(tmp_path) == []
