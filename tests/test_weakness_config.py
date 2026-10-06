"""Cấu hình giải tuần tự đa hình ( FSB-DESER-003 ) và JWT không xác minh ( FSB-JWT-001 ).

Mẫu im lặng ở đây phần lớn rút từ mã thật: thư viện cài đặt chính công tắc đó
( jackson-databind, golang-jwt ), hàm chỉ đọc trước iss / kid rồi mới xác minh,
công cụ dòng lệnh in token ra màn hình.
"""

from __future__ import annotations

from typing import List, Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Confidence
from fortress_scan.languages import CSHARP, GO, JAVA, JAVASCRIPT, PYTHON, RUBY, TYPESCRIPT


def findings(language: str, source: str, path: str = "app/service"):
    return scan_source(source, language, path, Config())


def rule_ids(language: str, source: str, path: str = "app/service") -> List[str]:
    return [f.rule_id for f in findings(language, source, path)]


Case = Tuple[str, str, str]

FIRES: List[Case] = [
    # ---- DESER-003: Json.NET, JavaScriptSerializer
    ("FSB-DESER-003", CSHARP, "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n"),
    ("FSB-DESER-003", CSHARP, "class A { void F() { settings.TypeNameHandling = TypeNameHandling.Auto; } }\n"),
    (
        "FSB-DESER-003",
        CSHARP,
        "class A { [JsonProperty(ItemTypeNameHandling = TypeNameHandling.Objects)] public List<object> Items; }\n",
    ),
    ("FSB-DESER-003", CSHARP, "var s = new JavaScriptSerializer(new SimpleTypeResolver());\n"),
    # ---- DESER-003: Jackson, fastjson, XStream, Kryo
    ("FSB-DESER-003", JAVA, "class A { void f() { ObjectMapper m = new ObjectMapper(); m.enableDefaultTyping(); } }\n"),
    ("FSB-DESER-003", JAVA, "class A { ObjectMapper f() { return new ObjectMapper().enableDefaultTyping(); } }\n"),
    (
        "FSB-DESER-003",
        JAVA,
        "class A { void f() { mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, "
        "ObjectMapper.DefaultTyping.NON_FINAL); } }\n",
    ),
    (
        "FSB-DESER-003",
        JAVA,
        "class A { void f() { PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()"
        ".allowIfSubType(Object.class).build(); mapper.activateDefaultTyping(ptv); } }\n",
    ),
    ("FSB-DESER-003", JAVA, "class A { void f() { ParserConfig.getGlobalInstance().setAutoTypeSupport(true); } }\n"),
    (
        "FSB-DESER-003",
        JAVA,
        "class A { Object f(String s) { return JSON.parseObject(s, Object.class, Feature.SupportAutoType); } }\n",
    ),
    ("FSB-DESER-003", JAVA, "class A { void f() { XStream x = new XStream(); x.addPermission(AnyTypePermission.ANY); } }\n"),
    ("FSB-DESER-003", JAVA, "class A { void f() { Kryo k = new Kryo(); k.setRegistrationRequired(false); } }\n"),
    # ---- DESER-003: Ruby Oj, JSON additions
    ("FSB-DESER-003", RUBY, "obj = Oj.load(request.body.read, mode: :object)\n"),
    ("FSB-DESER-003", RUBY, "Oj.default_options = { mode: :object }\n"),
    ("FSB-DESER-003", RUBY, "data = JSON.parse(body, create_additions: true)\n"),
    # ---- DESER-002: bản Psych giữ hành vi cũ, trước đây bị bỏ sót
    ("FSB-DESER-002", RUBY, 'obj = Psych.unsafe_load(File.read("cfg.yml"))\n'),
    ("FSB-DESER-001", RUBY, "def show\n  obj = YAML.unsafe_load(params[:data])\nend\n"),
    # ---- JWT-001: Python
    (
        "FSB-JWT-001",
        PYTHON,
        'import jwt\ndef user(req):\n    claims = jwt.decode(req.token, options={"verify_signature": False})\n'
        '    return claims["sub"]\n',
    ),
    ("FSB-JWT-001", PYTHON, "import jwt\nclaims = jwt.decode(token, verify=False)\n"),
    ("FSB-JWT-001", PYTHON, 'import jwt\nclaims = jwt.decode(token, key, algorithms=["HS256", "none"])\n'),
    ("FSB-JWT-001", PYTHON, "from jose import jwt\nclaims = jwt.get_unverified_claims(token)\n"),
    (
        "FSB-JWT-001",
        PYTHON,
        'import jwt\nOPTS = {"verify_signature": False}\ndef f(t):\n    return jwt.decode(t, options=OPTS)\n',
    ),
    # ---- JWT-001: Java
    (
        "FSB-JWT-001",
        JAVA,
        "class A { Claims f(String t) { return Jwts.parser().setSigningKey(key).parseClaimsJwt(t).getBody(); } }\n",
    ),
    ("FSB-JWT-001", JAVA, "class A { Jwt f(String t) { return Jwts.parser().setSigningKey(KEY).parse(t); } }\n"),
    (
        "FSB-JWT-001",
        JAVA,
        "class A { void f(String t) { JwtParser p = Jwts.parser().setSigningKey(KEY); Jwt j = p.parse(t); } }\n",
    ),
    (
        "FSB-JWT-001",
        JAVA,
        "class A { void f(String t) { DecodedJWT d = JWT.require(Algorithm.none()).build().verify(t); } }\n",
    ),
    ("FSB-JWT-001", JAVA, "class A { void f(String t) { Jwts.parser().unsecured().build().parse(t); } }\n"),
    # ---- JWT-001: C#
    (
        "FSB-JWT-001",
        CSHARP,
        "var p = new TokenValidationParameters { ValidateIssuer = false, RequireSignedTokens = false };\n",
    ),
    (
        "FSB-JWT-001",
        CSHARP,
        "var p = new TokenValidationParameters { SignatureValidator = (token, parameters) => "
        "new JwtSecurityToken(token), ValidateAudience = false };\n",
    ),
    # ---- JWT-001: Go
    (
        "FSB-JWT-001",
        GO,
        "package a\nfunc User(t string) string {\n\tx := y\n"
        "\ttoken, _, _ := p.ParseUnverified(t, jwt.MapClaims{})\n"
        '\treturn token.Claims.(jwt.MapClaims)["sub"].(string)\n}\n',
    ),
    (
        "FSB-JWT-001",
        GO,
        "package a\nfunc k(t *jwt.Token) (interface{}, error) { return jwt.UnsafeAllowNoneSignatureType, nil }\n",
    ),
    # ---- JWT-001: Ruby
    (
        "FSB-JWT-001",
        RUBY,
        'def current_user\n  payload, _ = JWT.decode(token, nil, false)\n  User.find(payload["user_id"])\nend\n',
    ),
    ("FSB-JWT-001", RUBY, 'payload = JWT.decode(token, key, true, algorithm: "none")\n'),
    ("FSB-JWT-001", RUBY, "payload = JWT.decode(token, key, true, { 'algorithms' => ['HS256', 'none'] })\n"),
    # ---- JWT-001: JavaScript / TypeScript
    (
        "FSB-JWT-001",
        JAVASCRIPT,
        "const jwt = require('jsonwebtoken');\nconst p = jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });\n",
    ),
    (
        "FSB-JWT-001",
        JAVASCRIPT,
        "app.use(expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['none'] }));\n",
    ),
    (
        "FSB-JWT-001",
        JAVASCRIPT,
        "const jwt = require('jsonwebtoken');\nconst opts = { algorithms: ['none'] };\njwt.verify(token, '', opts);\n",
    ),
    ("FSB-JWT-001", TYPESCRIPT, "import * as jose from 'jose';\nconst { payload } = jose.UnsecuredJWT.decode(token);\n"),
]

SILENT: List[Case] = [
    # Json.NET: tắt, so sánh, hoặc có binder giới hạn kiểu.
    ("FSB-DESER-003", CSHARP, "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\n"),
    ("FSB-DESER-003", CSHARP, "if (settings.TypeNameHandling == TypeNameHandling.All) { Log(); }\n"),
    (
        "FSB-DESER-003",
        CSHARP,
        "class A { void F() { var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto, "
        "SerializationBinder = new KnownTypesBinder() }; } }\n",
    ),
    ("FSB-DESER-003", CSHARP, "var s = new JavaScriptSerializer();\n"),
    # Jackson với danh sách cho phép thật; chính jackson-databind cài đặt công tắc.
    (
        "FSB-DESER-003",
        JAVA,
        'class A { void f() { mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder()'
        '.allowIfSubType("com.acme.").build()); } }\n',
    ),
    (
        "FSB-DESER-003",
        JAVA,
        "class ObjectMapper { public ObjectMapper enableDefaultTyping() { "
        "return enableDefaultTyping(DefaultTyping.OBJECT_AND_NON_CONCRETE); } }\n",
    ),
    ("FSB-DESER-003", JAVA, "class A { void f() { k.setRegistrationRequired(true); cfg.setAutoTypeSupport(false); } }\n"),
    (
        "FSB-DESER-003",
        JAVA,
        "class Kryo { public void setRegistrationRequired(boolean registrationRequired) { this.r = registrationRequired; } }\n",
    ),
    ("FSB-DESER-003", RUBY, "obj = Oj.load(body, mode: :strict)\n"),
    ("FSB-DESER-003", RUBY, "data = JSON.parse(body)\n"),
    ("FSB-DESER-003", RUBY, "settings = { mode: :object }\n"),
    # JWT: xác minh đúng cách.
    ("FSB-JWT-001", PYTHON, 'import jwt\nclaims = jwt.decode(token, key, algorithms=["HS256"])\n'),
    (
        "FSB-JWT-001",
        PYTHON,
        'import jwt\nclaims = jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": False})\n',
    ),
    ("FSB-JWT-001", PYTHON, "import json\nclaims = json.decode(token, verify=False)\n"),
    # Đọc trước iss / kid để chọn khoá, rồi mới xác minh trong cùng hàm.
    (
        "FSB-JWT-001",
        PYTHON,
        'import jwt\ndef verify(t):\n    unverified = jwt.decode(t, options={"verify_signature": False})\n'
        '    key = KEYS[unverified["iss"]]\n    return jwt.decode(t, key, algorithms=["RS256"])\n',
    ),
    ("FSB-JWT-001", PYTHON, 'import jwt\nissuer = jwt.decode(t, options={"verify_signature": False})["iss"]\n'),
    (
        "FSB-JWT-001",
        PYTHON,
        'import jwt\ndef f(t):\n    iss = jwt.decode(t, options={"verify_signature": False}).get("iss")\n    return iss\n',
    ),
    (
        "FSB-JWT-001",
        PYTHON,
        'import jwt\ndef decode_unverified(t):\n    return jwt.decode(t, options={"verify_signature": False})\n',
    ),
    (
        "FSB-JWT-001",
        JAVA,
        "class A { Claims f(String t) { return Jwts.parser().setSigningKey(key).parseClaimsJws(t).getBody(); } }\n",
    ),
    (
        "FSB-JWT-001",
        JAVA,
        "class A { Jws<Claims> f(String t) { return Jwts.parser().verifyWith(key).build().parseSignedClaims(t); } }\n",
    ),
    # jjwt 0.12 từ chối token không ký trong parse() trừ khi gọi unsecured().
    ("FSB-JWT-001", JAVA, "class A { Jwt f(String t) { return Jwts.parser().verifyWith(key).build().parse(t); } }\n"),
    ("FSB-JWT-001", JAVA, "class A { void f(String t) { String s = JWT.create().sign(Algorithm.none()); } }\n"),
    ("FSB-JWT-001", JAVA, "class A { Date f(String t) { return LocalDate.parse(t); } }\n"),
    ("FSB-JWT-001", CSHARP, "var p = new TokenValidationParameters { RequireSignedTokens = true };\n"),
    (
        "FSB-JWT-001",
        CSHARP,
        "var p = new TokenValidationParameters { SignatureValidator = (token, parameters) => { "
        "var jwt = new JwtSecurityToken(token); if (!Verify(jwt)) throw new SecurityTokenInvalidSignatureException(); "
        "return jwt; } };\n",
    ),
    (
        "FSB-JWT-001",
        GO,
        "package a\nfunc Verify(t string) (*jwt.Token, error) {\n"
        "\tunverified, _, err := new(jwt.Parser).ParseUnverified(t, jwt.MapClaims{})\n"
        "\tif err != nil { return nil, err }\n"
        '\tkey := keys[unverified.Header["kid"].(string)]\n'
        "\treturn jwt.Parse(t, func(*jwt.Token) (interface{}, error) { return key, nil })\n}\n",
    ),
    (
        "FSB-JWT-001",
        GO,
        "package a\nfunc showToken(t string) {\n\ttok, _, _ := jwt.NewParser().ParseUnverified(t, jwt.MapClaims{})\n"
        "\tfmt.Println(tok.Claims)\n}\n",
    ),
    # Chính golang-jwt: khai báo hằng và hàm.
    (
        "FSB-JWT-001",
        GO,
        'package jwt\nconst UnsafeAllowNoneSignatureType unsafeNoneMagicConstant = "none signing method allowed"\n',
    ),
    (
        "FSB-JWT-001",
        GO,
        "package jwt\nfunc (p *Parser) ParseUnverified(tokenString string, claims Claims) (token *Token, err error) {\n"
        "\treturn nil, nil\n}\n"
        "func (p *Parser) ParseWithClaims(s string, c Claims, k Keyfunc) (*Token, error) {\n"
        "\ttoken, parts, err := p.ParseUnverified(s, c)\n\treturn token, err\n}\n",
    ),
    (
        "FSB-JWT-001",
        RUBY,
        'def verify(token)\n  iss = JWT.decode(token, nil, false)[0]["iss"]\n'
        '  JWT.decode(token, keys[iss], true, algorithm: "RS256")\nend\n',
    ),
    ("FSB-JWT-001", RUBY, 'payload = JWT.decode(token, key, true, algorithm: "HS256")\n'),
    (
        "FSB-JWT-001",
        JAVASCRIPT,
        "const jwt = require('jsonwebtoken');\nconst p = jwt.verify(token, secret, { algorithms: ['HS256'] });\n",
    ),
    # Bên trong chính thư viện jsonwebtoken: phép gán, không phải cấu hình người dùng.
    (
        "FSB-JWT-001",
        JAVASCRIPT,
        "const jwt = 1;\nfunction verify(token, options) { if (!options.algorithms) { options.algorithms = ['none']; } }\n",
    ),
    # 'none' của một cấu hình không liên quan JWT.
    ("FSB-JWT-001", JAVASCRIPT, "const zlib = { algorithms: ['none', 'gzip'] };\n"),
]


@pytest.mark.parametrize("rule,language,source", FIRES)
def test_rule_fires(rule: str, language: str, source: str):
    assert rule in rule_ids(language, source), source


@pytest.mark.parametrize("rule,language,source", SILENT)
def test_rule_stays_silent(rule: str, language: str, source: str):
    assert rule not in rule_ids(language, source), source


def test_unverified_decode_is_medium_and_alg_none_is_high():
    """Đọc không xác minh có thể đã được gateway kiểm; nhận 'none' thì không có đường lui."""
    unverified = 'import jwt\nclaims = jwt.decode(token, options={"verify_signature": False})\n'
    none = 'import jwt\nclaims = jwt.decode(token, key, algorithms=["none"])\n'
    (first,) = [f for f in findings(PYTHON, unverified) if f.rule_id == "FSB-JWT-001"]
    (second,) = [f for f in findings(PYTHON, none) if f.rule_id == "FSB-JWT-001"]
    assert first.confidence is Confidence.MEDIUM
    assert second.confidence is Confidence.HIGH


def test_unverified_decode_next_to_a_project_verifier_is_low_confidence():
    """saleor: hàm định tuyến đọc trước claims, còn xác minh thật nằm ở lớp bọc khác trong cùng tệp."""
    source = (
        "import jwt\n"
        "def jwt_decode(token):\n"
        "    return jwt_manager.decode(token)\n"
        "def is_our_token(token):\n"
        '    payload = jwt.decode(token, options={"verify_signature": False})\n'
        '    return payload.get("owner") == "us"\n'
    )
    (finding,) = [f for f in findings(PYTHON, source) if f.rule_id == "FSB-JWT-001"]
    assert finding.confidence is Confidence.LOW


def test_cli_option_that_enables_alg_none_is_low_confidence():
    """golang-jwt/cmd: chỉ nhận 'none' khi người dùng tự truyền -alg none."""
    source = (
        "package main\n"
        "func verify() {\n"
        "\ttoken, err := jwt.Parse(data, func(t *jwt.Token) (any, error) {\n"
        "\t\tif isNone() {\n"
        "\t\t\treturn jwt.UnsafeAllowNoneSignatureType, nil\n"
        "\t\t}\n"
        "\t\treturn key, nil\n"
        "\t})\n"
        "}\n"
    )
    (finding,) = [f for f in findings(GO, source) if f.rule_id == "FSB-JWT-001"]
    assert finding.confidence is Confidence.LOW


def test_polymorphic_config_in_tests_is_demoted_not_hidden():
    source = "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n"
    production = [f for f in findings(CSHARP, source, "src/Api/Startup.cs") if f.rule_id == "FSB-DESER-003"]
    test = [f for f in findings(CSHARP, source, "tests/Api.Tests/StartupTests.cs") if f.rule_id == "FSB-DESER-003"]
    assert len(production) == 1 and len(test) == 1
    assert test[0].confidence < production[0].confidence
