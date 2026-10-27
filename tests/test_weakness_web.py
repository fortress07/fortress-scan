"""CORS phản chiếu mọi origin ( FSB-CORS-001 ) và cookie thiếu HttpOnly ( FSB-COOKIE-001 ).

Mỗi mẫu FIRES ở đây đã được kiểm bằng cách CHẠY thư viện thật và đọc header
trả về ( flask-cors 6.0.5, Starlette 1.7.0, django-cors-headers 4.9.0, cors
2.8.6 với express 5, Flask 3.1.3, Django 6.1.1, PHP 8.3 ), còn các mẫu đọc từ
mã nguồn thư viện thì ghi rõ trong chú thích. Mẫu SILENT phần lớn là hình mà
trình duyệt TỰ từ chối, hoặc nơi thư viện tự ném lỗi, nên báo chúng là báo sai:

* `Access-Control-Allow-Origin: *` cùng credentials -- trình duyệt bỏ phản hồi;
* `allowedOrigins("*")` + `allowCredentials(true)` của Spring và
  `AllowAnyOrigin()` + `AllowCredentials()` của ASP.NET -- cả hai tự ném lỗi
  lúc dựng cấu hình ( CorsConfiguration.validateAllowCredentials,
  CorsPolicyBuilder.Build );
* `send_wildcard=True` + `supports_credentials=True` của flask-cors -- ném
  ValueError.
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
    # ---- CORS-001: flask-cors. Mặc định origins là '*', và khi có credentials
    # thì flask-cors dội lại Origin của người gửi chứ không ghi '*'.
    ("FSB-CORS-001", PYTHON, "from flask_cors import CORS\nCORS(app, supports_credentials=True)\n"),
    ("FSB-CORS-001", PYTHON, "from flask_cors import CORS\nCORS(app, origins='*', supports_credentials=True)\n"),
    ("FSB-CORS-001", PYTHON, "from flask_cors import CORS\nCORS(app, origins=r'.*', supports_credentials=True)\n"),
    (
        "FSB-CORS-001",
        PYTHON,
        "from flask_cors import CORS\nCORS(app, resources={r'/api/*': {'origins': '*'}}, supports_credentials=True)\n",
    ),
    (
        "FSB-CORS-001",
        PYTHON,
        "from flask_cors import cross_origin\n@cross_origin(supports_credentials=True)\ndef api():\n    return data\n",
    ),
    # ---- CORS-001: Starlette và FastAPI
    (
        "FSB-CORS-001",
        PYTHON,
        "from starlette.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n",
    ),
    (
        "FSB-CORS-001",
        PYTHON,
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origin_regex='.*', allow_credentials=True)\n",
    ),
    # ---- CORS-001: django-cors-headers
    ("FSB-CORS-001", PYTHON, "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n"),
    ("FSB-CORS-001", PYTHON, "CORS_ORIGIN_ALLOW_ALL = True\nCORS_ALLOW_CREDENTIALS = True\n"),
    ("FSB-CORS-001", PYTHON, "CORS_ALLOWED_ORIGIN_REGEXES = [r'^.*$']\nCORS_ALLOW_CREDENTIALS = True\n"),
    # ---- CORS-001: gói cors của express
    ("FSB-CORS-001", JAVASCRIPT, "app.use(cors({ origin: true, credentials: true }));\n"),
    ("FSB-CORS-001", JAVASCRIPT, "app.use(cors({ origin: /.*/, credentials: true }));\n"),
    ("FSB-CORS-001", JAVASCRIPT, "app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));\n"),
    (
        "FSB-CORS-001",
        TYPESCRIPT,
        "app.use(cors({ origin: function (o, cb) { return cb(null, o); }, credentials: true }));\n",
    ),
    # ---- CORS-001: tự ghi header
    (
        "FSB-CORS-001",
        JAVASCRIPT,
        "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
        "res.setHeader('Access-Control-Allow-Credentials', 'true');\n",
    ),
    (
        "FSB-CORS-001",
        JAVASCRIPT,
        "res.set({ 'Access-Control-Allow-Origin': req.headers.origin, "
        "'Access-Control-Allow-Credentials': 'true' });\n",
    ),
    (
        "FSB-CORS-001",
        PHP,
        '<?php\nheader("Access-Control-Allow-Origin: " . $_SERVER["HTTP_ORIGIN"]);\n'
        'header("Access-Control-Allow-Credentials: true");\n',
    ),
    (
        "FSB-CORS-001",
        PHP,
        '<?php\nheader("Access-Control-Allow-Origin: {$_SERVER[\'HTTP_ORIGIN\']}");\n'
        'header("Access-Control-Allow-Credentials: true");\n',
    ),
    (
        "FSB-CORS-001",
        GO,
        'func handle(w http.ResponseWriter, r *http.Request) {\n'
        '\tw.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))\n'
        '\tw.Header().Set("Access-Control-Allow-Credentials", "true")\n}\n',
    ),
    (
        "FSB-CORS-001",
        RUBY,
        "headers['Access-Control-Allow-Origin'] = request.env['HTTP_ORIGIN']\n"
        "headers['Access-Control-Allow-Credentials'] = 'true'\n",
    ),
    (
        "FSB-CORS-001",
        PYTHON,
        "def cors(request, response):\n"
        "    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')\n"
        "    response.headers['Access-Control-Allow-Credentials'] = 'true'\n",
    ),
    # ---- CORS-001: Spring. checkOrigin() trả về chính Origin khi mẫu là "*".
    (
        "FSB-CORS-001",
        JAVA,
        'class Config { void add(CorsRegistry r) { r.addMapping("/**").allowedOriginPatterns("*")'
        ".allowCredentials(true); } }\n",
    ),
    (
        "FSB-CORS-001",
        JAVA,
        'class Config { void f() { CorsConfiguration c = new CorsConfiguration(); '
        'c.addAllowedOriginPattern("*"); c.setAllowCredentials(true); } }\n',
    ),
    (
        "FSB-CORS-001",
        JAVA,
        'class Api { @CrossOrigin(originPatterns = "*", allowCredentials = "true") '
        'public String get() { return "x"; } }\n',
    ),
    # ---- CORS-001: ASP.NET Core. PopulateResult() dội lại Origin khi
    # AllowAnyOrigin false mà IsOriginAllowed true.
    ("FSB-CORS-001", CSHARP, "public void F(CorsPolicyBuilder b) { b.SetIsOriginAllowed(_ => true).AllowCredentials(); }\n"),
    # ---- CORS-001: middleware CORS của Go
    (
        "FSB-CORS-001",
        GO,
        "func main() {\n\tr.Use(cors.New(cors.Config{\n"
        "\t\tAllowOriginFunc: func(origin string) bool { return true },\n"
        "\t\tAllowCredentials: true,\n\t}))\n}\n",
    ),
    # ---- COOKIE-001: mặc định của framework là KHÔNG có HttpOnly
    ("FSB-COOKIE-001", PYTHON, "def login(response, token):\n    response.set_cookie('session_token', token)\n"),
    ("FSB-COOKIE-001", PYTHON, "def login(response, token):\n    response.set_cookie('session', token, httponly=False)\n"),
    ("FSB-COOKIE-001", JAVASCRIPT, "res.cookie('session', value);\n"),
    ("FSB-COOKIE-001", JAVASCRIPT, "res.cookie('jwt', token, { secure: true });\n"),
    ("FSB-COOKIE-001", PHP, '<?php\nsetcookie("session_id", $value);\n'),
    ("FSB-COOKIE-001", PHP, '<?php\nsetcookie("session_id", $value, ["httponly" => false]);\n'),
    (
        "FSB-COOKIE-001",
        GO,
        'func login(w http.ResponseWriter, v string) {\n'
        '\thttp.SetCookie(w, &http.Cookie{Name: "session", Value: v})\n}\n',
    ),
    # ---- COOKIE-001: tắt thẳng cờ
    ("FSB-COOKIE-001", PYTHON, "SESSION_COOKIE_HTTPONLY = False\n"),
    ("FSB-COOKIE-001", PYTHON, "app.config['SESSION_COOKIE_HTTPONLY'] = False\n"),
    ("FSB-COOKIE-001", PYTHON, "app.config.update(SESSION_COOKIE_HTTPONLY=False)\n"),
    ("FSB-COOKIE-001", JAVASCRIPT, "app.use(session({ secret: s, cookie: { httpOnly: false } }));\n"),
    ("FSB-COOKIE-001", JAVA, "class A { void f(Cookie c) { c.setHttpOnly(false); } }\n"),
    ("FSB-COOKIE-001", CSHARP, "var options = new CookieOptions { HttpOnly = false };\n"),
    ("FSB-COOKIE-001", CSHARP, "services.Configure<CookiePolicyOptions>(o => { o.HttpOnly = HttpOnlyPolicy.None; });\n"),
    ("FSB-COOKIE-001", RUBY, "cookies[:session] = { value: token, httponly: false }\n"),
    ("FSB-COOKIE-001", PHP, '<?php\nini_set("session.cookie_httponly", 0);\n'),
]

SILENT: List[Case] = [
    # ---- Không có credentials thì origin mở chỉ là API công khai.
    ("FSB-CORS-001", PYTHON, "from flask_cors import CORS\nCORS(app)\n"),
    ("FSB-CORS-001", PYTHON, "from flask_cors import CORS\nCORS(app, origins='*')\n"),
    ("FSB-CORS-001", PYTHON, "CORS_ALLOW_ALL_ORIGINS = True\n"),
    (
        "FSB-CORS-001",
        PYTHON,
        "from starlette.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n",
    ),
    ("FSB-CORS-001", JAVASCRIPT, "app.use(cors({ origin: true }));\n"),
    (
        "FSB-CORS-001",
        JAVASCRIPT,
        "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n",
    ),
    # ---- Danh sách đóng.
    (
        "FSB-CORS-001",
        PYTHON,
        "from flask_cors import CORS\nCORS(app, origins=['https://app.example'], supports_credentials=True)\n",
    ),
    (
        "FSB-CORS-001",
        PYTHON,
        "from starlette.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['https://app.example'], allow_credentials=True)\n",
    ),
    ("FSB-CORS-001", PYTHON, "CORS_ALLOWED_ORIGINS = ['https://app.example']\nCORS_ALLOW_CREDENTIALS = True\n"),
    ("FSB-CORS-001", JAVASCRIPT, "app.use(cors({ origin: ['https://app.example'], credentials: true }));\n"),
    (
        "FSB-CORS-001",
        JAVASCRIPT,
        "res.setHeader('Access-Control-Allow-Origin', 'https://app.example');\n"
        "res.setHeader('Access-Control-Allow-Credentials', 'true');\n",
    ),
    # ---- Mẫu có neo và có tên miền thật: đây là allowlist, không phải '.*'.
    (
        "FSB-CORS-001",
        PYTHON,
        "from flask_cors import CORS\nCORS(app, origins=r'^https://.*\\.example\\.com$', supports_credentials=True)\n",
    ),
    (
        "FSB-CORS-001",
        JAVASCRIPT,
        "app.use(cors({ origin: /^https:\\/\\/.*\\.example\\.com$/, credentials: true }));\n",
    ),
    (
        "FSB-CORS-001",
        JAVA,
        'class Config { void add(CorsRegistry r) { r.addMapping("/**")'
        '.allowedOriginPatterns("https://*.example.com").allowCredentials(true); } }\n',
    ),
    # ---- Trình duyệt tự từ chối '*' khi request có credentials.
    ("FSB-CORS-001", JAVASCRIPT, "app.use(cors({ origin: '*', credentials: true }));\n"),
    ("FSB-CORS-001", JAVASCRIPT, "app.use(cors({ credentials: true }));\n"),
    # ---- Thư viện tự ném lỗi cho tổ hợp này, nên nó không chạy được.
    (
        "FSB-CORS-001",
        PYTHON,
        "from flask_cors import CORS\nCORS(app, origins='*', supports_credentials=True, send_wildcard=True)\n",
    ),
    (
        "FSB-CORS-001",
        JAVA,
        'class Config { void add(CorsRegistry r) { r.addMapping("/**").allowedOrigins("*")'
        ".allowCredentials(true); } }\n",
    ),
    ("FSB-CORS-001", CSHARP, "public void F(CorsPolicyBuilder b) { b.AllowAnyOrigin().AllowAnyHeader(); }\n"),
    # ---- Có kiểm tra thật trước khi cho qua.
    (
        "FSB-CORS-001",
        JAVASCRIPT,
        "app.use(cors({ origin: (o, cb) => { if (list.includes(o)) return cb(null, true); "
        "cb(new Error()); }, credentials: true }));\n",
    ),
    ("FSB-CORS-001", CSHARP, "public void F(CorsPolicyBuilder b) { b.SetIsOriginAllowed(o => allowed.Contains(o)).AllowCredentials(); }\n"),
    (
        "FSB-CORS-001",
        GO,
        "func main() {\n\tr.Use(cors.New(cors.Config{\n"
        '\t\tAllowOriginFunc: func(origin string) bool { return strings.HasSuffix(origin, ".example.com") },\n'
        "\t\tAllowCredentials: true,\n\t}))\n}\n",
    ),
    (
        "FSB-CORS-001",
        JAVASCRIPT,
        "if (allowedOrigins.includes(req.headers.origin)) {\n"
        "  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
        "  res.setHeader('Access-Control-Allow-Credentials', 'true');\n}\n",
    ),
    # ---- Cookie đã có HttpOnly, hoặc không mang phiên.
    ("FSB-COOKIE-001", PYTHON, "def login(response, token):\n    response.set_cookie('session', token, httponly=True)\n"),
    ("FSB-COOKIE-001", PYTHON, "def ui(response, value):\n    response.set_cookie('locale', value)\n"),
    ("FSB-COOKIE-001", PYTHON, "SESSION_COOKIE_HTTPONLY = True\n"),
    ("FSB-COOKIE-001", JAVASCRIPT, "res.cookie('session', value, { httpOnly: true });\n"),
    ("FSB-COOKIE-001", JAVASCRIPT, "res.cookie('locale', value);\n"),
    ("FSB-COOKIE-001", JAVA, "class A { void f(Cookie c) { c.setHttpOnly(true); } }\n"),
    ("FSB-COOKIE-001", CSHARP, "var options = new CookieOptions { HttpOnly = true };\n"),
    ("FSB-COOKIE-001", RUBY, "cookies[:session] = { value: token, httponly: true }\n"),
    ("FSB-COOKIE-001", PHP, '<?php\nsetcookie("session_id", $value, 0, "/", "", true, true);\n'),
    ("FSB-COOKIE-001", PHP, '<?php\nsetcookie("session_id", $value, ["httponly" => true]);\n'),
    ("FSB-COOKIE-001", PHP, '<?php\nsetcookie("theme", $value);\n'),
    ("FSB-COOKIE-001", PHP, '<?php\nini_set("session.cookie_httponly", 1);\n'),
    (
        "FSB-COOKIE-001",
        GO,
        'func login(w http.ResponseWriter, v string) {\n'
        '\thttp.SetCookie(w, &http.Cookie{Name: "session", Value: v, HttpOnly: true})\n}\n',
    ),
    # ---- Đặt cờ ở dòng sau vẫn là có đặt.
    (
        "FSB-COOKIE-001",
        GO,
        'func login(w http.ResponseWriter, v string) {\n'
        '\tc := &http.Cookie{Name: "session", Value: v}\n\tc.HttpOnly = true\n\thttp.SetCookie(w, c)\n}\n',
    ),
    # ---- Cookie chống CSRF PHẢI đọc được bằng JavaScript của chính trang.
    ("FSB-COOKIE-001", JAVASCRIPT, "res.cookie('XSRF-TOKEN', token);\n"),
    ("FSB-COOKIE-001", PYTHON, "def f(response, token):\n    response.set_cookie('csrftoken', token)\n"),
    # ---- Biến cục bộ tên httponly chưa nói được nó sẽ đi đâu ( DVWA ).
    (
        "FSB-COOKIE-001",
        PHP,
        '<?php\nfunction start_session() {\n  $httponly = false;\n'
        '  session_set_cookie_params($life, "/", "", false, $httponly);\n}\n',
    ),
    ("FSB-COOKIE-001", JAVASCRIPT, "let httpOnly = false;\nconst options = { httpOnly };\n"),
]


@pytest.mark.parametrize("rule,language,source", FIRES)
def test_rule_fires(rule: str, language: str, source: str):
    assert rule in rule_ids(language, source), source


@pytest.mark.parametrize("rule,language,source", SILENT)
def test_rule_stays_silent(rule: str, language: str, source: str):
    assert rule not in rule_ids(language, source), source


def test_missing_flag_is_medium_and_disabled_flag_is_high():
    """Thiếu cờ có thể do một lớp bọc khác đặt; tắt thẳng thì không còn cách hiểu khác."""
    missing = "def login(response, token):\n    response.set_cookie('session', token)\n"
    disabled = "def login(response, token):\n    response.set_cookie('session', token, httponly=False)\n"
    (first,) = [f for f in findings(PYTHON, missing) if f.rule_id == "FSB-COOKIE-001"]
    (second,) = [f for f in findings(PYTHON, disabled) if f.rule_id == "FSB-COOKIE-001"]
    assert first.confidence is Confidence.MEDIUM
    assert second.confidence is Confidence.HIGH


def test_cors_finding_names_the_credentials_line():
    """Hai công tắc ở hai dòng: bằng chứng phải chỉ ra dòng còn lại."""
    source = "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n"
    (finding,) = [f for f in findings(PYTHON, source) if f.rule_id == "FSB-CORS-001"]
    assert finding.line == 1
    assert any("dòng 2" in part for part in finding.evidence), finding.evidence


def test_allowlist_check_in_the_same_function_silences_reflection():
    """saleor: dội lại Origin, nhưng chỉ sau khi so với ALLOWED_GRAPHQL_ORIGINS."""
    source = (
        "def cors(scope, send):\n"
        "    request_origin = read_origin(scope)\n"
        "    origin_match = request_origin in settings.ALLOWED_GRAPHQL_ORIGINS\n"
        "    if origin_match:\n"
        "        headers = [\n"
        '            (b"access-control-allow-origin", request_origin),\n'
        '            (b"access-control-allow-credentials", b"true"),\n'
        "        ]\n"
        "        send(headers)\n"
    )
    assert "FSB-CORS-001" not in rule_ids(PYTHON, source)


def test_permissive_cors_in_tests_is_demoted_not_hidden():
    source = "from flask_cors import CORS\nCORS(app, supports_credentials=True)\n"
    production = [f for f in findings(PYTHON, source, "app/api.py") if f.rule_id == "FSB-CORS-001"]
    test = [f for f in findings(PYTHON, source, "tests/test_api.py") if f.rule_id == "FSB-CORS-001"]
    assert len(production) == 1 and len(test) == 1
    assert test[0].confidence < production[0].confidence
