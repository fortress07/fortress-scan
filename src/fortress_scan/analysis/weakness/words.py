"""Đọc ý nghĩa bảo mật từ TÊN trong mã: tên biến, thuộc tính, hàm, khoá.

Các rule điểm yếu ( mật mã, PRNG, secret ) không có nguồn dữ liệu bẩn để truy
vết: `hashlib.md5(x)` chỉ là lỗ hổng khi `x` là mật khẩu, còn băm nội dung tệp
để làm ETag thì hoàn toàn bình thường. Thứ duy nhất phân biệt được hai chuyện
đó một cách tĩnh là TÊN mà lập trình viên đặt cho dữ liệu.

Nên tên được tách thành TỪ ( snake_case, camelCase, kebab, tiền tố `$` `@` )
rồi mới so, không so chuỗi con: `bypass` không chứa từ `pass`, `design` không
chứa từ `sign`, `tokenizer` không phải `token`.
"""

from __future__ import annotations

import math
import re
from typing import FrozenSet, Iterable, List, Optional, Sequence, Tuple

_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def split_words(identifier: str) -> Tuple[str, ...]:
    words: List[str] = []
    for chunk in re.split(r"[^A-Za-z0-9]+", identifier):
        if not chunk:
            continue
        for word in _CAMEL.findall(chunk):
            words.append(word.lower())
    return tuple(words)


_PASSWORD_WORDS = frozenset({"password", "passwd", "pwd", "passphrase", "pass", "passcode"})
# Những tên CÓ chữ password nhưng không chứa mật khẩu: `password_reset_token`
# là token, `password_min_length` là một con số, `password_field` là tên ô form.
_PASSWORD_EXCLUSIONS = frozenset(
    {
        "reset",
        "token",
        "policy",
        "length",
        "len",
        "min",
        "max",
        "field",
        "label",
        "regex",
        "pattern",
        "strength",
        "prompt",
        "url",
        "file",
        "path",
        "expiry",
        "expires",
        "expired",
        "changed",
        "updated",
        "count",
        "attempt",
        "attempts",
        "hint",
        "placeholder",
        "input",
        "selector",
        "name",
        "type",
        "required",
        "confirm",
        "error",
        "message",
        "msg",
        "manager",
        "validator",
        "rule",
        "rules",
        "through",
        "thru",
    }
)

# Dữ liệu dựng nên một chữ ký hay MAC.
_SECRET_WORDS = frozenset({"secret", "hmac", "signature", "signing", "sig", "apikey"})
_SIGN_WORDS = frozenset({"signature", "signing", "sign", "sig", "hmac", "mac", "signed"})
_NOT_SIGN_FOLLOWERS = frozenset({"in", "up", "out", "on", "off"})

# Giá trị mà đoán trước được thì ai đó chiếm được tài khoản hoặc phiên.
_RANDOM_SECURITY_WORDS = frozenset(
    {
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "otp",
        "totp",
        "nonce",
        "salt",
        "session",
        "sessionid",
        "sid",
        "csrf",
        "xsrf",
        "apikey",
        "credential",
        "credentials",
        "iv",
        "passcode",
    }
)
# `key` một mình là khoá của dict, của cache, của bảng băm. Chỉ tính khi nó đi
# cùng một từ nói rõ đó là khoá bí mật.
_KEY_QUALIFIERS = frozenset(
    {
        "api",
        "secret",
        "private",
        "encryption",
        "aes",
        "signing",
        "session",
        "access",
        "crypto",
        "jwt",
        "hmac",
        "master",
        "auth",
    }
)
# Ngữ cảnh mà "token" là token của bộ phân tích cú pháp hay mô hình ngôn ngữ.
_NLP_WORDS = frozenset(
    {
        "tokenizer",
        "tokenize",
        "tokens",
        "vocab",
        "vocabulary",
        "embedding",
        "embeddings",
        "logits",
        "lexer",
        "corpus",
    }
)
_TEST_WORDS = frozenset({"mock", "fake", "dummy", "fixture", "sample", "example", "demo"})


def _key_qualified(words: Sequence[str], qualifiers: FrozenSet[str] = _KEY_QUALIFIERS) -> bool:
    if "key" not in words and "keys" not in words:
        return False
    return any(word in qualifiers for word in words)


# `SESSION_KEY = "_auth_user_id"` là tên khoá trong dict phiên, không phải khoá
# mật mã; với secret viết cứng thì "session" không đủ để nói `key` là bí mật.
_HOLDER_KEY_QUALIFIERS = _KEY_QUALIFIERS - {"session", "auth"}


def is_password_name(identifier: str) -> bool:
    words = split_words(identifier)
    if not any(word in _PASSWORD_WORDS for word in words):
        return False
    if any(word in _PASSWORD_EXCLUSIONS for word in words):
        return False
    # `pass` chỉ tính khi nó là cả tên hoặc đi với user/db: `user_pass`,
    # `db_pass`. `pass_count`, `first_pass` là chuyện khác.
    if "pass" in words and not any(word in _PASSWORD_WORDS - {"pass"} for word in words):
        return len(words) == 1 or any(w in {"user", "db", "admin", "root", "login"} for w in words)
    return True


def is_secret_name(identifier: str) -> bool:
    words = split_words(identifier)
    if any(word in _SECRET_WORDS for word in words):
        return True
    return _key_qualified(words)


def is_sign_name(identifier: str) -> bool:
    words = split_words(identifier)
    for index, word in enumerate(words):
        if word not in _SIGN_WORDS:
            continue
        following = words[index + 1] if index + 1 < len(words) else ""
        if word == "sign" and following in _NOT_SIGN_FOLLOWERS:
            continue
        if word == "mac" and any(w in {"address", "addr", "os", "osx"} for w in words):
            continue
        return True
    return False


# "reset" một mình là `resetTag`, `resetDelay`; chỉ tính khi đi với thứ mà
# người dùng nhận được để chứng minh danh tính.
_CODE_PREFIXES = frozenset({"reset", "verification", "verify", "activation", "confirmation", "invite", "recovery", "magic", "login"})
_CODE_SUFFIXES = frozenset({"code", "link", "id", "pin", "number", "hash", "url"})


def is_random_security_name(identifier: str) -> bool:
    words = split_words(identifier)
    if any(word in _NLP_WORDS for word in words):
        return False
    if any(word in _TEST_WORDS for word in words):
        return False
    if any(word in _RANDOM_SECURITY_WORDS for word in words):
        return True
    if any(word in _CODE_PREFIXES for word in words) and any(word in _CODE_SUFFIXES for word in words):
        return True
    return _key_qualified(words)


def draws_from_nlp_data(names: Iterable[str]) -> bool:
    """`random.choice(vocab)`, `randint(0, vocab_size)`: bốc một token của mô hình
    ngôn ngữ chứ không sinh secret, dù biến nhận tên là `token`."""
    return any(word in _NLP_WORDS for name in names for word in split_words(name))


# Đọc trước token chưa xác minh chỉ để lấy iss / kid / thuật toán rồi chọn
# khoá, hoặc hàm tự khai là bản đọc không an toàn.
_PEEK_WORDS = frozenset(
    {
        "iss",
        "issuer",
        "kid",
        "header",
        "headers",
        "alg",
        "tenant",
        "tid",
        "unverified",
        "peek",
        "insecure",
        "unsafe",
        "debug",
        "inspect",
        # công cụ in token ra màn hình cho người đọc, không dựa vào nó để cấp quyền
        "show",
        "print",
        "dump",
        "display",
        "pretty",
    }
)


def names_a_peek(identifier: str) -> bool:
    return any(word in _PEEK_WORDS for word in split_words(identifier))


def first_match(names: Iterable[str], predicate) -> Optional[str]:
    for name in names:
        if name and predicate(name):
            return name
    return None


# ---------------------------------------------------------------------------
# Secret viết cứng
# ---------------------------------------------------------------------------

_TOKEN_QUALIFIERS = frozenset(
    {
        "access",
        "auth",
        "bearer",
        "refresh",
        "api",
        "bot",
        "private",
        "github",
        "gitlab",
        "slack",
        "discord",
        "telegram",
        "oauth",
        "jwt",
        "session",
        "personal",
        "deploy",
        "webhook",
        "service",
    }
)
# Tên có từ bí mật nhưng giá trị là siêu dữ liệu về bí mật, không phải bí mật.
_SECRET_NAME_EXCLUSIONS = (_PASSWORD_EXCLUSIONS - {"token", "reset"}) | frozenset(
    {
        "uri",
        "endpoint",
        "dir",
        "env",
        "var",
        "header",
        "param",
        "text",
        "title",
        "format",
        "mode",
        "id",
        "column",
        "col",
        "attr",
        "attribute",
        "xpath",
        "css",
        "hash",
        "hashed",
        "salt",
        "ttl",
        "timeout",
        "cookie",
        "location",
        "provider",
        "store",
        "storage",
        "source",
        "kind",
        "method",
        "version",
        "arn",
        "ref",
        "template",
        "description",
        "desc",
        "help",
        "class",
        "scope",
        "scopes",
        "grant",
    }
)


def is_secret_holder_name(identifier: str) -> bool:
    """Tên biến hoặc khoá cấu hình mà giá trị của nó chính là bí mật."""
    words = split_words(identifier)
    if not words:
        return False
    if any(word in _SECRET_NAME_EXCLUSIONS for word in words if word not in ("key", "keys")):
        return False
    # `password_key = "pwd"` là tên khoá để tra, không phải mật khẩu; còn
    # `secret_key`, `api_key` thì chính là khoá.
    if ("key" in words or "keys" in words) and not _key_qualified(words, _HOLDER_KEY_QUALIFIERS):
        return False
    if any(word in _PASSWORD_WORDS for word in words):
        return is_password_name(identifier)
    if any(word in {"secret", "apikey"} for word in words):
        return True
    if "token" in words:
        # `token` trần là token của bộ tô màu cú pháp, của lexer, của phân
        # trang -- chỉ tính khi có từ nói rõ đó là token xác thực.
        return any(word in _TOKEN_QUALIFIERS for word in words)
    return _key_qualified(words, _HOLDER_KEY_QUALIFIERS)


_PLACEHOLDER_VALUES = frozenset(
    {
        "password",
        "passwd",
        "changeme",
        "change_me",
        "change-me",
        "secret",
        "your_password",
        "yourpassword",
        "your-password",
        "your_secret",
        "your-secret",
        "your_api_key",
        "your-api-key",
        "todo",
        "tbd",
        "none",
        "null",
        "nil",
        "undefined",
        "example",
        "dummy",
        "test",
        "testing",
        "fake",
        "sample",
        "placeholder",
        "redacted",
        "default",
        "xxx",
        "foo",
        "bar",
        "foobar",
        "secret_key",
        "secretkey",
        "mysecret",
        "notasecret",
        "not-a-secret",
        "insecure",
    }
)
_TEMPLATE_MARKERS = ("${", "{{", "%(", "#{", "<%", "$(", "{0}", "%s", "{}")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
_DOTTED_KEY = re.compile(r"^[a-z][a-z0-9_\-]*(\.[a-z0-9_\-]+)+$")
# Khoá tài nguyên bản địa hoá `Plugins.Misc.Brevo.Fields.ApiKey`: từ ba đoạn trở
# lên, mỗi đoạn là một định danh ngắn. JWT viết cứng ( `eyJ...` ) có đoạn dài và
# có `-`, nên không lọt vào đây.
_RESOURCE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,30}(\.[A-Za-z][A-Za-z0-9_]{0,30}){2,}$")
# `passwd == "x-oauth-basic"`: tên lược đồ xác thực, không phải mật khẩu.
_AUTH_SCHEME_WORDS = frozenset(
    {"x", "oauth", "oauth2", "basic", "bearer", "digest", "negotiate", "ntlm", "sso", "saml", "token"}
)
SLOW_KDF_WORDS = frozenset({"pbkdf", "pbkdf2", "bcrypt", "scrypt", "argon", "argon2", "argon2id", "argon2i"})

# Định dạng của những nhà cung cấp mà tiền tố đủ đặc trưng để không cần đoán.
# AKIAIOSFODNN7EXAMPLE là khoá mẫu trong tài liệu AWS, nên bị loại riêng.
KNOWN_TOKEN_FORMATS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("khoá truy cập AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("token GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("token GitHub", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,90}\b")),
    ("token GitLab", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b")),
    ("token Slack", re.compile(r"\bxox[abposr]-[0-9A-Za-z\-]{10,90}\b")),
    ("khoá bí mật Stripe", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{24,99}\b")),
    ("khoá API Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("khoá API SendGrid", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b")),
    ("token npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("khoá API OpenAI", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b")),
    ("khoá API Anthropic", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}")),
)
# Chỉ riêng dòng tiêu đề thì chưa phải khoá: `pem.replace("-----BEGIN PRIVATE
# KEY-----", "")` là mã XỬ LÝ khoá. Phải có phần thân base64 theo sau.
_PEM_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")
_PEM_BODY = re.compile(r"[A-Za-z0-9+/=]{48}")
_URL_CREDENTIALS = re.compile(
    r"\b[a-z][a-z0-9+.\-]{0,30}://([^\s/@:]{1,80}):([^\s/@]{3,120})@([^\s/:]+)", re.IGNORECASE
)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1"})


URL_CREDENTIALS = "mật khẩu nằm trong URL kết nối"


def known_token_format(value: str) -> Optional[str]:
    if "EXAMPLE" in value or "example" in value:
        return None
    for label, pattern in KNOWN_TOKEN_FORMATS:
        if pattern.search(value):
            return label
    header = _PEM_HEADER.search(value)
    if header is not None:
        body = re.sub(r"\\[rn]|[\s\\]", "", value[header.end() : header.end() + 400])
        if _PEM_BODY.match(body):
            return "khoá riêng PEM"
    match = _URL_CREDENTIALS.search(value)
    if match is not None:
        user, password, host = match.group(1), match.group(2), match.group(3)
        weak = password.lower() in ("pass", "password", "pwd", "secret", "passwd")
        # `postgres://saleor:saleor@localhost/saleor`: giá trị mặc định cho máy dev.
        local = host.lower() in _LOCAL_HOSTS or password == user
        if not (weak or local) and not looks_like_placeholder(password) and not password.startswith(("$", "%", "{")):
            return URL_CREDENTIALS
    return None


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_placeholder(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if not stripped:
        return True
    if lowered in _PLACEHOLDER_VALUES:
        return True
    if any(marker in stripped for marker in _TEMPLATE_MARKERS):
        return True
    if stripped.startswith(("<", "[")) and stripped.endswith((">", "]")):
        return True
    if len(set(lowered)) <= 2:
        return True  # "xxxxxxxx", "********", "00000000"
    if lowered.startswith(("your", "my-", "my_", "replace", "insert", "enter", "put-", "put_")):
        return True
    if "change" in lowered and "me" in lowered:
        return True
    return False


def plausible_secret_value(value: str, minimum: int = 6) -> bool:
    """Giá trị trông như một bí mật thật chứ không phải nhãn, tên hay mẫu."""
    if len(value) < minimum or len(value) > 512:
        return False
    if looks_like_placeholder(value):
        return False
    if any(char.isspace() for char in value):
        return False  # câu chữ, nhãn giao diện, thông báo
    if _ENV_NAME.match(value) or _DOTTED_KEY.match(value) or _RESOURCE_KEY.match(value):
        return False  # tên biến môi trường, đường dẫn khoá cấu hình, khoá tài nguyên
    parts = [part for part in re.split(r"[-_]", value.lower()) if part]
    if len(parts) >= 2 and all(part in _AUTH_SCHEME_WORDS for part in parts):
        return False
    if value.startswith(("/", "./", "../", "~/", "http://", "https://", "file:")):
        return False
    if value.startswith(("$2a$", "$2b$", "$2y$", "$argon2", "pbkdf2_", "$6$", "$5$")):
        return False  # đã là giá trị băm, không phải mật khẩu rõ
    return True


def strong_secret_value(value: str) -> bool:
    """Đủ dài và đủ ngẫu nhiên để gần như chắc chắn là khoá thật."""
    if len(value) < 16:
        return False
    classes = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )
    alphanumeric = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
        )
    )
    return classes >= 2 and alphanumeric >= 2 and shannon_entropy(value) >= 3.5


def words_of(names: Iterable[str]) -> FrozenSet[str]:
    result = set()
    for name in names:
        result.update(split_words(name))
    return frozenset(result)


_FIELD_NAME = re.compile(r"^[a-z][a-z0-9]*(?:[_\-.][a-z0-9]+)+$")
_FIELD_WORDS = frozenset(
    {
        "x",
        "api",
        "key",
        "token",
        "secret",
        "auth",
        "access",
        "refresh",
        "header",
        "id",
        "user",
        "username",
        "password",
        "passwd",
        "pass",
        "pwd",
        "name",
        "client",
        "session",
        "csrf",
        "xsrf",
        "bearer",
        "private",
        "public",
        "app",
        "value",
        "field",
        "param",
        "new",
        "old",
        "current",
        "confirm",
        "confirmation",
        "login",
        "db",
        "database",
        "admin",
        "account",
    }
)


def looks_like_field_name(value: str, holder: str) -> bool:
    """Giá trị là TÊN của một trường ( `user_password`, `x-api-key` ), không phải bí mật."""
    if value.endswith(("-", "_", ".", ":", "/")):
        return True  # tiền tố: "django-insecure-", "sess:"
    core = value.lstrip("_")
    if core != value and core.isidentifier() and core.lower() == core:
        return True  # "_auth_user_id", "_csrftoken" -- khoá trong dict phiên
    if _FIELD_NAME.match(core) and not any(char.isdigit() for char in core):
        if all(word in _FIELD_WORDS for word in split_words(core)):
            return True
        if "_" in core or "." in core:
            return True  # snake_case / dotted -- tên khoá cấu hình
    return bool(holder) and split_words(value) == split_words(holder)


_OPTION_WORDS = frozenset({"verify", "verifying", "insecure", "unverified", "ssl", "tls", "cert", "certs", "skip"})


def names_an_option(identifier: str) -> bool:
    """`withoutVerifying()`, `insecure_skip_verify` -- hàm hay biến cài đặt chính tuỳ chọn tắt."""
    return any(word in _OPTION_WORDS for word in split_words(identifier))


# Điều kiện bao quanh cho thấy công tắc chỉ bật khi người dùng chọn, hoặc chỉ
# cho kết nối nội bộ: `if Devise.ldap_tls_no_verify`, `case 'no-verify':`,
# `if internalAPIConnectionIsLocal(...)`.
_GUARD_WORDS = frozenset({"local", "loopback", "localhost", "dev", "development", "debug"})


def names_a_guard(identifier: str) -> bool:
    return names_an_option(identifier) or any(word in _GUARD_WORDS for word in split_words(identifier))


# Điều kiện bao quanh cho thấy origin đã được so với một danh sách trước khi
# được dội lại: `if origin_match:`, `if (allowedOrigins.includes(origin))`.
_ALLOWLIST_WORDS = frozenset(
    {
        "allowed",
        "allowlist",
        "allowedorigins",
        "whitelist",
        "whitelisted",
        "permitted",
        "trusted",
        "valid",
        "match",
        "matched",
        "matches",
        "known",
        "safe",
        "includes",
        "contains",
        "member",
        "index",
        "indexof",
        "in",
    }
)


def names_an_allowlist(identifier: str) -> bool:
    return any(word in _ALLOWLIST_WORDS for word in split_words(identifier))


# Sau khi bỏ neo và tiền tố giao thức, một mẫu origin khớp MỌI tên miền khi
# phần còn lại không có chữ nào ràng buộc được host. `.*\.example\.com` vẫn còn
# chữ "example" nên không vào đây ( nó là lỗi khác: thiếu neo cuối ).
_ANY_ORIGIN_RESIDUE = re.compile(r"^[.*+?()\[\]{}|,:\\/\-\d\s]*$")
_ANY_ORIGIN_MARKERS = (".*", ".+", "\\w")
_ORIGIN_SCHEMES = ("https?", "https", "http")


def matches_any_origin(pattern: str) -> Optional[str]:
    """`*`, `.*`, `^.*$`, `^https?://.*$`: mẫu không loại được origin nào.

    Trả về mô tả ngắn để đưa vào bằng chứng, hoặc None khi mẫu thật sự giới hạn.
    """
    text = pattern.strip()
    if not text:
        return None
    if text == "*":
        return "mọi origin ( '*' )"
    residue = text[1:] if text.startswith("^") else text
    if residue.endswith("$") and not residue.endswith("\\$"):
        residue = residue[:-1]
    for scheme in _ORIGIN_SCHEMES:
        for separator in ("://", ":\\/\\/"):
            if residue.startswith(scheme + separator):
                residue = residue[len(scheme) + len(separator) :]
                break
    if not any(marker in residue for marker in _ANY_ORIGIN_MARKERS):
        return None
    if not _ANY_ORIGIN_RESIDUE.match(residue.replace("\\w", "")):
        return None
    return "mẫu %r khớp mọi origin" % pattern


# Cookie mang phiên đăng nhập. Cookie chống CSRF thì ngược lại: JavaScript của
# chính trang PHẢI đọc được nó để gắn vào header, nên thiếu HttpOnly là đúng.
_SESSION_COOKIE_WORDS = frozenset(
    {
        "session",
        "sessionid",
        "sessid",
        "jsessionid",
        "phpsessid",
        "sess",
        "sid",
        "token",
        "jwt",
        "auth",
        "authorization",
        "login",
        "remember",
        "credential",
        "credentials",
        "apikey",
    }
)
_SCRIPT_READABLE_COOKIE_WORDS = frozenset({"csrf", "xsrf", "csrftoken", "antiforgery"})


def names_a_session_cookie(name: str) -> Optional[str]:
    parts = split_words(name)
    if any(word in _SCRIPT_READABLE_COOKIE_WORDS for word in parts):
        return None
    for word in parts:
        if word in _SESSION_COOKIE_WORDS:
            return word
    return None


# Tệp bản dịch: `'pass': 'Adgangskode'` là chữ "mật khẩu" bằng tiếng Đan Mạch.
_TRANSLATION_DIRECTORIES = frozenset({"i18n", "l10n", "locale", "locales", "lang", "langs", "translations"})


def is_fixture_path(relative_path: str) -> bool:
    """Test, ví dụ, tài liệu và bản dịch: chuỗi ở đây là dữ liệu mẫu hay chữ hiển thị,
    không phải bí mật bị lộ."""
    from ...core.context import classify
    from ...core.model import PathContext

    directories = relative_path.replace("\\", "/").lower().split("/")[:-1]
    if any(part in _TRANSLATION_DIRECTORIES for part in directories):
        return True
    return classify(relative_path) in (
        PathContext.TEST,
        PathContext.EXAMPLE,
        PathContext.DOCUMENTATION,
    )
