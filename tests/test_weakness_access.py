"""Quyền quyết định bằng trường của request ( FSB-ACCESS-001 ) và mass assignment ( FSB-MASS-001 ).

Hai họ này khác mọi họ khác ở một điểm: cái mang nghĩa là TÊN KHOÁ, không phải
lời gọi. `request.args.get("role")` và `request.args.get("page")` là cùng một
lời gọi, chỉ khác một chuỗi, mà một bên là leo thang quyền còn bên kia là phân
trang. Nên mỗi mẫu SILENT ở đây không phải mẫu "sạch hẳn" -- nó là ĐÚNG hình
dạng của mẫu FIRES, chỉ thiếu một điều kiện, và đó mới là phép thử thật:

* đọc đúng khoá quyền nhưng chỉ để lọc danh sách, không để quyết định;
* đọc khoá quyền từ phiên đã ký của server chứ không từ thứ người gửi đặt được;
* so với một giá trị không phải giá trị quyền ( `== "guest"` );
* ghi một trường đã nêu tên thay vì cả gói dữ liệu.

Hai kiểm tra config-only đã bị BỎ sau khi đo trên repo thật: `$guarded = []`
của Laravel và `fields = "__all__"` của Django chỉ là cấu hình, và chúng nằm
hợp lệ trong chính mã của framework ( Pivot.php, DatabaseNotification.php,
UserChangeForm ). Phải thấy request ở ngay chỗ ghi thì mới có lỗ hổng.
"""

from __future__ import annotations

from typing import List, Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Confidence
from fortress_scan.languages import CSHARP, GO, JAVA, JAVASCRIPT, PHP, PYTHON, RUBY, TYPESCRIPT


def findings(language: str, source: str, path: str = "app/service"):
    return scan_source(source, language, path, Config())


def rule_ids(language: str, source: str, path: str = "app/service") -> List[str]:
    return [f.rule_id for f in findings(language, source, path)]


Case = Tuple[str, str, str]

FIRES: List[Case] = [
    # ---- ACCESS-001: Python, trên AST
    (
        "FSB-ACCESS-001",
        PYTHON,
        "from flask import request\n\n\ndef panel():\n"
        "    if request.args.get('role') == 'admin':\n        return admin_view()\n",
    ),
    (
        "FSB-ACCESS-001",
        PYTHON,
        "def panel(request):\n    if request.GET['role'] in ('admin', 'staff'):\n"
        "        return admin_view()\n",
    ),
    # Khoá là cờ đúng/sai thì dùng thẳng làm điều kiện đã đủ nghĩa.
    (
        "FSB-ACCESS-001",
        PYTHON,
        "from flask import request\n\n\ndef panel():\n"
        "    if request.args.get('is_admin'):\n        return admin_view()\n",
    ),
    # Hàm kiểm quyền trả về thẳng kết quả so sánh.
    (
        "FSB-ACCESS-001",
        PYTHON,
        "def is_admin(request):\n    return request.cookies.get('role') == 'admin'\n",
    ),
    # Header: cùng lớp lỗi, nhưng gateway có thể đã xoá nó -- xem bài hạ mức.
    (
        "FSB-ACCESS-001",
        PYTHON,
        "def panel(request):\n    if request.headers.get('X-Admin') == 'true':\n"
        "        return admin_view()\n",
    ),
    # ---- ACCESS-001: JavaScript và TypeScript
    (
        "FSB-ACCESS-001",
        JAVASCRIPT,
        "app.get('/panel', (req, res) => {\n  if (req.query.role === 'admin') {\n"
        "    return res.send(adminView());\n  }\n  res.sendStatus(403);\n});\n",
    ),
    (
        "FSB-ACCESS-001",
        JAVASCRIPT,
        "function guard(req) {\n  if (req.cookies.isAdmin === 'true') {\n    return true;\n  }\n"
        "  return false;\n}\n",
    ),
    (
        "FSB-ACCESS-001",
        TYPESCRIPT,
        "function guard(req: Request): boolean {\n  if (req.body.role == 'superuser') {\n"
        "    return true;\n  }\n  return false;\n}\n",
    ),
    # ---- ACCESS-001: PHP, Ruby
    (
        "FSB-ACCESS-001",
        PHP,
        "<?php\nif ($_GET['role'] == 'admin') {\n    render_admin();\n}\n",
    ),
    (
        "FSB-ACCESS-001",
        RUBY,
        "def panel\n  if params[:role] == 'admin'\n    render_admin\n  end\nend\n",
    ),
    # Hậu tố `if` của Ruby nằm SAU lời gọi, nên cửa sổ điều kiện phải nhìn cả hai phía.
    (
        "FSB-ACCESS-001",
        RUBY,
        "def panel\n  grant_admin! if params[:user_role] == 'admin'\nend\n",
    ),
    # ---- ACCESS-001: Java, Go, C#
    (
        "FSB-ACCESS-001",
        JAVA,
        "class Panel {\n  void show(HttpServletRequest request) {\n"
        '    if (request.getParameter("role").equals("admin")) {\n      renderAdmin();\n    }\n  }\n}\n',
    ),
    (
        "FSB-ACCESS-001",
        GO,
        'func panel(w http.ResponseWriter, r *http.Request) {\n\tif r.URL.Query().Get("role") == "admin" {\n'
        "\t\trenderAdmin(w)\n\t}\n}\n",
    ),
    (
        "FSB-ACCESS-001",
        GO,
        'func panel(c *gin.Context) {\n\tif c.GetHeader("X-Role") == "superadmin" {\n'
        "\t\trenderAdmin(c)\n\t}\n}\n",
    ),
    (
        "FSB-ACCESS-001",
        CSHARP,
        "public IActionResult Panel() {\n"
        '    if (Request.Query["role"] == "admin") { return AdminView(); }\n'
        "    return Forbid();\n}\n",
    ),
    # ---- MASS-001: JavaScript
    (
        "FSB-MASS-001",
        JAVASCRIPT,
        "app.post('/users', (req, res) => {\n  User.create(req.body);\n  res.sendStatus(201);\n});\n",
    ),
    (
        "FSB-MASS-001",
        JAVASCRIPT,
        "app.put('/users/:id', (req, res) => {\n  User.findByIdAndUpdate(req.params.id, req.body);\n});\n",
    ),
    (
        "FSB-MASS-001",
        JAVASCRIPT,
        "function update(req, user) {\n  Object.assign(user, req.body);\n  return user.save();\n}\n",
    ),
    # ---- MASS-001: Ruby. `permit!` tắt hẳn danh sách trắng.
    (
        "FSB-MASS-001",
        RUBY,
        "def create\n  User.create(params.require(:user).permit!)\nend\n",
    ),
    # Có danh sách trắng, nhưng chính trường quyền nằm trong đó.
    (
        "FSB-MASS-001",
        RUBY,
        "def user_params\n  params.require(:user).permit(:email, :name, :role)\nend\n",
    ),
    # ---- MASS-001: PHP Laravel
    (
        "FSB-MASS-001",
        PHP,
        "<?php\nclass UserController {\n    public function store(Request $request) {\n"
        "        return User::create($request->all());\n    }\n}\n",
    ),
    # ---- MASS-001: Python. Người gửi chọn luôn TÊN trường qua `**`.
    (
        "FSB-MASS-001",
        PYTHON,
        "def signup(request):\n    user = User.objects.create(**request.POST)\n    return user\n",
    ),
    (
        "FSB-MASS-001",
        PYTHON,
        "def signup(request):\n    user = User(**request.POST.dict())\n    user.save()\n",
    ),
    (
        "FSB-MASS-001",
        PYTHON,
        "def signup(request):\n    Account.objects.update_or_create(**request.data)\n",
    ),
]

SILENT: List[Case] = [
    # ---- ACCESS-001: đúng khoá quyền, nhưng không quyết định gì
    (
        "FSB-ACCESS-001",
        PYTHON,
        "from flask import request\n\n\ndef listing():\n"
        "    return render(users=find_users(role=request.args.get('role')))\n",
    ),
    # Phiên do server ký, không phải thứ người gửi tự đặt.
    (
        "FSB-ACCESS-001",
        PYTHON,
        "def panel(request):\n    if request.session.get('role') == 'admin':\n"
        "        return admin_view()\n",
    ),
    # Khoá không nói gì về quyền.
    (
        "FSB-ACCESS-001",
        PYTHON,
        "from flask import request\n\n\ndef listing():\n"
        "    if request.args.get('page') == '2':\n        return page_two()\n",
    ),
    # `role` không phải cờ đúng/sai: đây chỉ là "người gửi có truyền role hay không".
    (
        "FSB-ACCESS-001",
        PYTHON,
        "from flask import request\n\n\ndef listing():\n"
        "    if request.args.get('role'):\n        return filtered()\n",
    ),
    # So với một giá trị KHÔNG phải giá trị quyền.
    (
        "FSB-ACCESS-001",
        JAVASCRIPT,
        "function f(req) {\n  if (req.query.role === 'guest') {\n    return publicView();\n  }\n}\n",
    ),
    # Chỉ đọc ra để ghi log.
    (
        "FSB-ACCESS-001",
        JAVA,
        'class A {\n  void f(HttpServletRequest request) {\n    log.info(request.getParameter("role"));\n  }\n}\n',
    ),
    # Gán vào biến rồi thôi: chỗ quyết định ( nếu có ) nằm ở nơi khác và sẽ do
    # chính đường đi xuyên file trả lời, không phải rule này đoán.
    (
        "FSB-ACCESS-001",
        GO,
        'func f(c *gin.Context) {\n\trole := c.Query("role")\n\tlog.Println(role)\n}\n',
    ),
    # ---- MASS-001: ghi trường đã nêu tên
    (
        "FSB-MASS-001",
        JAVASCRIPT,
        "app.post('/users', (req, res) => {\n  User.create({ name: req.body.name });\n});\n",
    ),
    (
        "FSB-MASS-001",
        RUBY,
        "def user_params\n  params.require(:user).permit(:email, :name)\nend\n",
    ),
    (
        "FSB-MASS-001",
        PHP,
        "<?php\nclass C {\n    public function store(Request $request) {\n"
        "        return User::create(['email' => $request->email]);\n    }\n}\n",
    ),
    (
        "FSB-MASS-001",
        PYTHON,
        "def signup(request):\n    User.objects.create(email=request.POST['email'])\n",
    ),
    # `**request.GET` vào filter là lớp lỗi khác ( lộ dữ liệu ), không phải mass assignment.
    (
        "FSB-MASS-001",
        PYTHON,
        "def listing(request):\n    return User.objects.filter(**request.GET)\n",
    ),
    # Header không phải trường của mô hình.
    (
        "FSB-MASS-001",
        PYTHON,
        "def log_call(request):\n    Audit.objects.create(**request.headers)\n",
    ),
]


@pytest.mark.parametrize("rule,language,source", FIRES)
def test_rule_fires(rule: str, language: str, source: str):
    assert rule in rule_ids(language, source), source


@pytest.mark.parametrize("rule,language,source", SILENT)
def test_rule_stays_silent(rule: str, language: str, source: str):
    assert rule not in rule_ids(language, source), source


def test_header_is_one_notch_lower_than_a_query_parameter():
    """Header có thể do gateway phía trước đặt; tham số truy vấn thì không."""
    query = (
        "from flask import request\n\n\ndef panel():\n"
        "    if request.args.get('role') == 'admin':\n        return admin_view()\n"
    )
    header = (
        "def panel(request):\n    if request.headers.get('X-Role') == 'admin':\n"
        "        return admin_view()\n"
    )
    (first,) = [f for f in findings(PYTHON, query) if f.rule_id == "FSB-ACCESS-001"]
    (second,) = [f for f in findings(PYTHON, header) if f.rule_id == "FSB-ACCESS-001"]
    assert first.confidence is Confidence.HIGH
    assert second.confidence is Confidence.MEDIUM
    assert any("gateway" in part for part in second.evidence), second.evidence


def test_finding_says_which_key_and_which_region_of_the_request():
    source = (
        "from flask import request\n\n\ndef panel():\n"
        "    if request.args.get('role') == 'admin':\n        return admin_view()\n"
    )
    (finding,) = [f for f in findings(PYTHON, source) if f.rule_id == "FSB-ACCESS-001"]
    assert finding.symbol == "role"
    assert "'role'" in finding.message
    assert "truy vấn" in finding.message, finding.message


def test_x_prefixed_header_matches_the_plain_privilege_name():
    """`X-Admin`, `HTTP_X_ADMIN` và `admin` là cùng một khoá sau khi chuẩn hoá."""
    for name in ("X-Admin", "HTTP_X_ADMIN", "x_is_admin"):
        source = (
            "def panel(request):\n    if request.headers.get(%r):\n        return admin_view()\n" % name
        )
        assert "FSB-ACCESS-001" in rule_ids(PYTHON, source), name


def test_privilege_decision_in_tests_is_demoted_not_hidden():
    source = (
        "from flask import request\n\n\ndef panel():\n"
        "    if request.args.get('role') == 'admin':\n        return admin_view()\n"
    )
    production = [f for f in findings(PYTHON, source, "app/views.py") if f.rule_id == "FSB-ACCESS-001"]
    test = [f for f in findings(PYTHON, source, "tests/test_views.py") if f.rule_id == "FSB-ACCESS-001"]
    assert len(production) == 1 and len(test) == 1
    assert test[0].confidence < production[0].confidence


# --------------------------------------------------------- prototype pollution
#
# `obj['__proto__']` trong JavaScript KHÔNG tạo một khoá tên `__proto__`: nó đi
# thẳng vào nguyên mẫu. Nên một hàm gộp ghi `target[key]` theo khoá của nguồn
# bơm được thuộc tính vào mọi đối tượng của tiến trình. Rule đòi hàm phải LÀ
# một hàm gộp ( tên nói vậy, hoặc nó gọi lại chính nó ) -- một vòng lặp
# `for (k in src)` bất kỳ thì chưa nói gì về ý định.

PROTO_FIRES: List[Tuple[str, str]] = [
    # Hàm gộp đệ quy, và chỗ gọi nó với body của request nằm trong cùng tệp.
    (
        JAVASCRIPT,
        "function merge(target, source) {\n  for (const key in source) {\n"
        "    if (typeof source[key] === 'object') {\n"
        "      target[key] = merge(target[key] || {}, source[key]);\n"
        "    } else {\n      target[key] = source[key];\n    }\n  }\n  return target;\n}\n"
        "\napp.post('/settings', (req, res) => {\n  merge(config, req.body);\n"
        "  res.end();\n});\n",
    ),
    # Vòng lặp duyệt thẳng khoá của `req.body`.
    (
        JAVASCRIPT,
        "function mergeSettings(target, req) {\n  for (const key in req.body) {\n"
        "    target[key] = req.body[key];\n  }\n  return target;\n}\n",
    ),
    # JSON.parse cũng là dữ liệu ngoài vào, và nó giữ `__proto__` làm khoá thật.
    (
        JAVASCRIPT,
        "function mergeDeep(target, source) {\n  for (const key in source) {\n"
        "    target[key] = source[key];\n  }\n  return target;\n}\n"
        "\nfunction load(raw) {\n  return mergeDeep(defaults, JSON.parse(raw));\n}\n",
    ),
    (
        TYPESCRIPT,
        "function extendDeep(target: any, source: any) {\n"
        "  for (const key of Object.keys(source)) {\n    target[key] = source[key];\n  }\n"
        "  return target;\n}\n\nrouter.post('/x', (req, res) => {\n"
        "  extendDeep(state, req.body);\n});\n",
    ),
]

PROTO_SILENT: List[Tuple[str, str]] = [
    # Hàm gộp nội bộ của một thư viện: không thấy dữ liệu người gửi nào đi vào.
    # Bản đầu của rule báo đúng hình này ở 9 chỗ trên 28 repo thật -- moment,
    # globalize, cldrjs, ace -- và cả 9 đều là báo nhầm.
    (
        JAVASCRIPT,
        "function merge(target, source) {\n  for (const key in source) {\n"
        "    target[key] = source[key];\n  }\n  return target;\n}\n",
    ),
    # moment.js: `hasOwnProp` là bộ bọc riêng của thư viện, không phải
    # `hasOwnProperty`, nên phép lọc theo nguồn mới là cái giữ nó im lặng.
    (
        JAVASCRIPT,
        "function extend(a, b) {\n  for (var i in b) {\n    if (hasOwnProp(b, i)) {\n"
        "      a[i] = b[i];\n    }\n  }\n  return a;\n}\n",
    ),
    # Chỉ nhận khoá của chính đối tượng.
    (
        JAVASCRIPT,
        "function merge(target, source) {\n  for (const key in source) {\n"
        "    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;\n"
        "    target[key] = source[key];\n  }\n  return target;\n}\n"
        "\napp.post('/s', (req, res) => { merge(config, req.body); });\n",
    ),
    # Loại thẳng ba khoá nguy hiểm.
    (
        JAVASCRIPT,
        "function merge(target, source) {\n  for (const key in source) {\n"
        "    if (key === '__proto__' || key === 'constructor') continue;\n"
        "    target[key] = source[key];\n  }\n  return target;\n}\n"
        "\napp.post('/s', (req, res) => { merge(config, req.body); });\n",
    ),
    # Không phải hàm gộp, cũng không đệ quy: chưa đủ để nói gì.
    (
        JAVASCRIPT,
        "function render(rows, source) {\n  for (const key in source) {\n"
        "    rows[key] = source[key];\n  }\n  return rows;\n}\n"
        "\napp.post('/s', (req, res) => { render(rows, req.body); });\n",
    ),
    # `for ... of` trên một mảng thì `item` là GIÁ TRỊ, không phải khoá.
    (
        JAVASCRIPT,
        "function mergeList(target, items) {\n  for (const item of items) {\n"
        "    target[item] = true;\n  }\n  return target;\n}\n"
        "\napp.post('/s', (req, res) => { mergeList(target, req.body); });\n",
    ),
]


@pytest.mark.parametrize("language,source", PROTO_FIRES)
def test_prototype_pollution_fires(language: str, source: str):
    assert "FSB-PROTO-001" in rule_ids(language, source), source


@pytest.mark.parametrize("language,source", PROTO_SILENT)
def test_prototype_pollution_stays_silent(language: str, source: str):
    assert "FSB-PROTO-001" not in rule_ids(language, source), source


def test_prototype_finding_names_where_the_untrusted_keys_enter():
    source = (
        "function merge(target, source) {\n  for (const key in source) {\n"
        "    target[key] = source[key];\n  }\n  return target;\n}\n"
        "\napp.post('/s', (req, res) => {\n  merge(config, req.body);\n});\n"
    )
    (finding,) = [f for f in findings(JAVASCRIPT, source) if f.rule_id == "FSB-PROTO-001"]
    assert finding.confidence is Confidence.MEDIUM
    assert any("req.body" in part for part in finding.evidence), finding.evidence
    assert any("dòng 9" in part for part in finding.evidence), finding.evidence
