"""Điểm yếu mật mã, TLS và secret cho các ngôn ngữ ngoài Python.

Đọc trên chuỗi token của bộ lexer chung ( `analysis.generic.lexer` ), nên nội
dung chuỗi và chú thích không bao giờ bị nhầm thành mã, và một lời gọi được
nhận ra theo chuỗi tên đầy đủ ( `crypto.createHash`, `Digest::MD5.hexdigest` )
chứ không theo một từ khoá đứng lẻ.

Ba thứ mà đọc token phải tự dựng lại vì không có AST:

* **lời gọi**: chuỗi tên + danh sách đối số đã tách theo dấu phẩy ở đúng độ
  sâu ngoặc;
* **ràng buộc hằng**: `iv := make([]byte, 16)`, `static final byte[] IV = {..}`
  -- một tên chỉ được coi là hằng khi MỌI phép gán cho nó đều là hằng, và nó
  không bị một hàm sinh ngẫu nhiên đổ dữ liệu vào ( `rand.Read(iv)` );
* **vùng hàm**: tên hàm bao quanh, để `return md5(...)` trong `hashPassword()`
  mang được nghĩa của tên hàm đó.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget
from ...core.model import Confidence, Severity, StepKind
from ...languages import (
    CSHARP,
    GO,
    JAVA,
    JAVASCRIPT,
    LUA,
    PERL,
    PHP,
    POWERSHELL,
    RUBY,
    RUST,
    SHELL,
    TYPESCRIPT,
)
from ..base import AnalysisUnit, FindingBuilder
from ..generic.lexer import IDENT, NEWLINE, NUMBER, OP, STRING, Token, tokenize
from ..generic.profiles import spec_for
from . import access_tokens, config_tokens, hardening_tokens, web_tokens, words

_SEPARATORS = frozenset({".", "::", "->", "?."})
_ASSIGN = frozenset({"=", ":=", "+=", ".=", "?="})
_PAIR = frozenset({":", "=>", "="})
_MAX_TOKENS = 400_000
_MAX_ARGUMENT_TOKENS = 400
_MAX_LOOKBACK = 60

# Những tên được phép xuất hiện trong một biểu thức mà vẫn coi là hằng: các
# hàm đổi một hằng chuỗi sang byte, và các hàm cấp phát mảng toàn số 0.
_LITERAL_HELPERS = frozenset(
    {
        "new",
        "byte",
        "bytes",
        "u8",
        "char",
        "getBytes",
        "GetBytes",
        "Encoding",
        "UTF8",
        "UTF_8",
        "ASCII",
        "US_ASCII",
        "Unicode",
        "Default",
        "StandardCharsets",
        "Charsets",
        "Charset",
        "forName",
        "toByteArray",
        "encodeToByteArray",
        "toCharArray",
        "Buffer",
        "from",
        "alloc",
        "Uint8Array",
        "make",
        "b",
        "as_bytes",
        "as_ref",
        "to_vec",
        "into",
        "to_owned",
        "as_slice",
        "str_repeat",
        "chr",
        "repeat",
        "CryptoJS",
        "enc",
        "Utf8",
        "Hex",
        "Latin1",
        "parse",
        "Base64",
        "getDecoder",
        "decode",
        "DatatypeConverter",
        "parseHexBinary",
        "decodeHex",
        "hex2bin",
        "base64_decode",
        "Convert",
        "FromBase64String",
        "hex",
        "byteArrayOf",
        "pack",
        "string",
        "String",
        "TextEncoder",
        "encode",
        "unpack",
        "fill",
    }
)
# Hàm đổ byte ngẫu nhiên vào một mảng truyền vào: sau lời gọi này mảng đó không
# còn là hằng nữa dù lúc khai báo nó toàn số 0.
_FILLERS = frozenset(
    {
        "Read",
        "ReadFull",
        "nextBytes",
        "randomFillSync",
        "randomFill",
        "getRandomValues",
        "Fill",
        "GetBytes",
        "GetNonZeroBytes",
        "fill_bytes",
        "try_fill_bytes",
        "fill",
        "copy",
        "arraycopy",
        "BlockCopy",
        "CopyTo",
        "random_bytes",
        "openssl_random_pseudo_bytes",
    }
)
_CONTROL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "foreach",
        "while",
        "switch",
        "catch",
        "using",
        "lock",
        "synchronized",
        "with",
        "elseif",
        "elif",
        "unless",
        "until",
        "return",
        "function",
        "func",
        "fn",
        "fun",
        "sub",
        "new",
        "typeof",
        "sizeof",
        "match",
        "when",
        "select",
    }
)
_SLOW_KDF_NAMES = frozenset(
    {
        "bcrypt",
        "BCrypt",
        "scrypt",
        "argon2",
        "Argon2",
        "pbkdf2",
        "pbkdf2Sync",
        "PBKDF2",
        "password_hash",
        "hash_pbkdf2",
        "BCryptPasswordEncoder",
        "Pbkdf2PasswordEncoder",
        "Argon2PasswordEncoder",
        "GenerateFromPassword",
        "IDKey",
        "Rfc2898DeriveBytes",
        "PasswordHasher",
        "hashpw",
        "hashSync",
        "crypt",
    }
)
_HASH_CHAINS = frozenset(
    {
        "update",
        "Write",
        "write",
        "digest",
        "ComputeHash",
        "TransformBlock",
        "TransformFinalBlock",
        "Sum",
        "hexdigest",
        "hex",
        "finalize",
        "chain_update",
        "input",
    }
)
_HASH_OBJECT_METHODS = frozenset(
    {"update", "Write", "write", "digest", "ComputeHash", "TransformBlock", "TransformFinalBlock",
     "Sum", "chain_update", "input", "hexdigest", "doFinal"}
)
_WEAK_HASH_ALGORITHMS = frozenset({"md5", "sha1", "sha-1", "md4", "md2", "sha"})
_WEAK_CIPHERS = {
    "des": "DES",
    "desede": "3DES",
    "des3": "3DES",
    "3des": "3DES",
    "tripledes": "3DES",
    "rc4": "RC4",
    "arcfour": "RC4",
    "rc2": "RC2",
    "bf": "Blowfish",
    "blowfish": "Blowfish",
    "cast": "CAST",
    "cast5": "CAST5",
    "idea": "IDEA",
    "seed": "SEED",
}
_FATAL_MODES = frozenset({"gcm", "ctr", "ccm", "ocb", "chacha20", "chacha20-poly1305", "eax"})


@dataclass(frozen=True)
class _Call:
    chain: str
    parts: Tuple[str, ...]
    anchor: Token
    index: int
    open_index: int
    close_index: int
    arguments: Tuple[Tuple[Token, ...], ...]

    def argument(self, position: int) -> Tuple[Token, ...]:
        if 0 <= position < len(self.arguments):
            return self.arguments[position]
        return ()


@dataclass(frozen=True)
class _Literal:
    description: str
    line: int


def _matches(parts: Sequence[str], pattern: str) -> bool:
    wanted = pattern.split(".")
    if len(wanted) > len(parts):
        return False
    return tuple(parts[len(parts) - len(wanted) :]) == tuple(wanted)


# ---------------------------------------------------------------------------
# Bảng theo ngôn ngữ
# ---------------------------------------------------------------------------

# ( chuỗi gọi, thuật toán cố định hoặc None, vị trí đối số tên thuật toán )
_HashSpec = Tuple[str, Optional[str], int]
_HASHES: Dict[str, Tuple[_HashSpec, ...]] = {
    JAVASCRIPT: (
        ("createHash", None, 0),
        ("CryptoJS.MD5", "MD5", -1),
        ("CryptoJS.SHA1", "SHA-1", -1),
        ("CryptoJS.SHA256", "SHA-256", -1),
        ("CryptoJS.SHA512", "SHA-512", -1),
    ),
    JAVA: (
        ("MessageDigest.getInstance", None, 0),
        ("DigestUtils.md5Hex", "MD5", -1),
        ("DigestUtils.md5", "MD5", -1),
        ("DigestUtils.sha1Hex", "SHA-1", -1),
        ("DigestUtils.sha1", "SHA-1", -1),
        ("DigestUtils.shaHex", "SHA-1", -1),
        ("DigestUtils.sha256Hex", "SHA-256", -1),
        ("DigestUtils.sha256", "SHA-256", -1),
        ("DigestUtils.sha512Hex", "SHA-512", -1),
        ("Hashing.md5", "MD5", -1),
        ("Hashing.sha1", "SHA-1", -1),
        ("Hashing.sha256", "SHA-256", -1),
    ),
    GO: (
        ("md5.Sum", "MD5", -1),
        ("md5.New", "MD5", -1),
        ("sha1.Sum", "SHA-1", -1),
        ("sha1.New", "SHA-1", -1),
        ("sha256.Sum256", "SHA-256", -1),
        ("sha256.New", "SHA-256", -1),
        ("sha512.Sum512", "SHA-512", -1),
        ("sha512.New", "SHA-512", -1),
    ),
    CSHARP: (
        ("MD5.Create", "MD5", -1),
        ("MD5.HashData", "MD5", -1),
        ("MD5CryptoServiceProvider", "MD5", -1),
        ("SHA1.Create", "SHA-1", -1),
        ("SHA1.HashData", "SHA-1", -1),
        ("SHA1Managed", "SHA-1", -1),
        ("SHA1CryptoServiceProvider", "SHA-1", -1),
        ("SHA256.Create", "SHA-256", -1),
        ("SHA256.HashData", "SHA-256", -1),
        ("SHA256Managed", "SHA-256", -1),
        ("SHA512.Create", "SHA-512", -1),
        ("SHA512.HashData", "SHA-512", -1),
        ("HashAlgorithm.Create", None, 0),
    ),
    PHP: (
        ("md5", "MD5", -1),
        ("sha1", "SHA-1", -1),
        ("hash", None, 0),
        ("hash_init", None, 0),
    ),
    RUBY: (
        ("Digest.MD5.hexdigest", "MD5", -1),
        ("Digest.MD5.digest", "MD5", -1),
        ("Digest.MD5.base64digest", "MD5", -1),
        ("Digest.MD5.new", "MD5", -1),
        ("Digest.SHA1.hexdigest", "SHA-1", -1),
        ("Digest.SHA1.digest", "SHA-1", -1),
        ("Digest.SHA1.new", "SHA-1", -1),
        ("Digest.SHA256.hexdigest", "SHA-256", -1),
        ("Digest.SHA256.digest", "SHA-256", -1),
        ("Digest.SHA512.hexdigest", "SHA-512", -1),
        ("OpenSSL.Digest.MD5.hexdigest", "MD5", -1),
        ("OpenSSL.Digest.SHA1.hexdigest", "SHA-1", -1),
        ("OpenSSL.Digest.new", None, 0),
        ("OpenSSL.Digest.digest", None, 0),
        ("OpenSSL.Digest.hexdigest", None, 0),
    ),
    RUST: (
        ("md5.compute", "MD5", -1),
        ("Md5.new", "MD5", -1),
        ("Md5.digest", "MD5", -1),
        ("Sha1.new", "SHA-1", -1),
        ("Sha1.digest", "SHA-1", -1),
        ("Sha256.new", "SHA-256", -1),
        ("Sha256.digest", "SHA-256", -1),
    ),
    PERL: (
        ("md5_hex", "MD5", -1),
        ("md5_base64", "MD5", -1),
        ("sha1_hex", "SHA-1", -1),
        ("sha1_base64", "SHA-1", -1),
        ("sha256_hex", "SHA-256", -1),
    ),
    LUA: (
        ("ngx.md5", "MD5", -1),
        ("ngx.sha1_bin", "SHA-1", -1),
    ),
}
_HASHES[TYPESCRIPT] = _HASHES[JAVASCRIPT]

# ( chuỗi gọi, vị trí đối số mang tên thuật toán / chế độ )
_CIPHER_STRINGS: Dict[str, Tuple[Tuple[str, int], ...]] = {
    JAVASCRIPT: (
        ("createCipheriv", 0),
        ("createDecipheriv", 0),
        ("createCipher", 0),
        ("createDecipher", 0),
    ),
    JAVA: (
        ("Cipher.getInstance", 0),
        ("SecretKeyFactory.getInstance", 0),
        ("KeyGenerator.getInstance", 0),
    ),
    PHP: (("openssl_encrypt", 1), ("openssl_decrypt", 1)),
    RUBY: (("OpenSSL.Cipher.new", 0),),
}
_CIPHER_STRINGS[TYPESCRIPT] = _CIPHER_STRINGS[JAVASCRIPT]

# Lời gọi mà chỉ riêng tên đã là thuật toán bị phá.
_CIPHER_CALLS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    JAVASCRIPT: (
        ("CryptoJS.DES.encrypt", "DES"),
        ("CryptoJS.TripleDES.encrypt", "3DES"),
        ("CryptoJS.RC4.encrypt", "RC4"),
        ("CryptoJS.RC4Drop.encrypt", "RC4"),
    ),
    GO: (
        ("des.NewCipher", "DES"),
        ("des.NewTripleDESCipher", "3DES"),
        ("rc4.NewCipher", "RC4"),
        ("blowfish.NewCipher", "Blowfish"),
    ),
    CSHARP: (
        ("DES.Create", "DES"),
        ("TripleDES.Create", "3DES"),
        ("RC2.Create", "RC2"),
        ("DESCryptoServiceProvider", "DES"),
        ("TripleDESCryptoServiceProvider", "3DES"),
        ("RC2CryptoServiceProvider", "RC2"),
    ),
    RUST: (
        ("Des.new", "DES"),
        ("TdesEde3.new", "3DES"),
        ("Rc4.new", "RC4"),
    ),
    PERL: (("Crypt.DES.new", "DES"), ("Crypt.Blowfish.new", "Blowfish")),
}
_CIPHER_CALLS[TYPESCRIPT] = _CIPHER_CALLS[JAVASCRIPT]

# Hằng tên chế độ ECB hoặc thuật toán bị phá dùng như một định danh.
_ECB_IDENTIFIERS: Dict[str, FrozenSet[str]] = {
    JAVASCRIPT: frozenset({"CryptoJS.mode.ECB"}),
    CSHARP: frozenset({"CipherMode.ECB"}),
    PHP: frozenset({"MCRYPT_MODE_ECB"}),
    RUST: frozenset({"ecb.Encryptor", "ecb.Decryptor"}),
}
_ECB_IDENTIFIERS[TYPESCRIPT] = _ECB_IDENTIFIERS[JAVASCRIPT]
_WEAK_CIPHER_IDENTIFIERS: Dict[str, Dict[str, str]] = {
    PHP: {
        "MCRYPT_DES": "DES",
        "MCRYPT_3DES": "3DES",
        "MCRYPT_TRIPLEDES": "3DES",
        "MCRYPT_RC2": "RC2",
        "MCRYPT_ARCFOUR": "RC4",
        "MCRYPT_BLOWFISH": "Blowfish",
    },
}

# ( chuỗi gọi, vị trí, loại ): loại là "iv", "nonce" ( lặp lại là chết ) hoặc
# "salt". "iv?" nghĩa là xem đối số thuật toán ở vị trí 0 để biết là chế độ gì.
_IV_ARGUMENTS: Dict[str, Tuple[Tuple[str, int, str], ...]] = {
    JAVASCRIPT: (
        ("createCipheriv", 2, "iv?"),
        ("pbkdf2Sync", 1, "salt"),
        ("pbkdf2", 1, "salt"),
        ("scryptSync", 1, "salt"),
        ("scrypt", 1, "salt"),
    ),
    JAVA: (
        ("IvParameterSpec", 0, "iv"),
        ("GCMParameterSpec", 1, "nonce"),
        ("ChaCha20ParameterSpec", 0, "nonce"),
        ("PBEKeySpec", 1, "salt"),
        ("PBEParameterSpec", 0, "salt"),
    ),
    GO: (
        ("cipher.NewCBCEncrypter", 1, "iv"),
        ("cipher.NewCFBEncrypter", 1, "iv"),
        ("cipher.NewOFB", 1, "iv"),
        ("cipher.NewCTR", 1, "nonce"),
        ("pbkdf2.Key", 1, "salt"),
        ("scrypt.Key", 1, "salt"),
        ("argon2.IDKey", 1, "salt"),
        ("argon2.Key", 1, "salt"),
    ),
    CSHARP: (
        ("CreateEncryptor", 1, "iv"),
        ("Rfc2898DeriveBytes", 1, "salt"),
        ("Rfc2898DeriveBytes.Pbkdf2", 1, "salt"),
    ),
    PHP: (("openssl_encrypt", 4, "iv?"), ("hash_pbkdf2", 2, "salt")),
    RUBY: (("OpenSSL.PKCS5.pbkdf2_hmac", 1, "salt"), ("OpenSSL.KDF.pbkdf2_hmac", 1, "salt")),
    RUST: (("Nonce.from_slice", 0, "nonce"),),
}
_IV_ARGUMENTS[TYPESCRIPT] = _IV_ARGUMENTS[JAVASCRIPT]

_KEY_ARGUMENTS: Dict[str, Tuple[Tuple[str, int], ...]] = {
    JAVASCRIPT: (
        ("createCipheriv", 1),
        ("createDecipheriv", 1),
        ("createHmac", 1),
        ("jwt.sign", 1),
        ("jwt.verify", 1),
        ("jsonwebtoken.sign", 1),
        ("jsonwebtoken.verify", 1),
        ("CryptoJS.AES.encrypt", 1),
        ("CryptoJS.AES.decrypt", 1),
        ("CryptoJS.HmacSHA256", 1),
        ("CryptoJS.HmacSHA1", 1),
        ("CryptoJS.HmacSHA512", 1),
        ("CryptoJS.HmacMD5", 1),
    ),
    JAVA: (
        ("SecretKeySpec", 0),
        ("Algorithm.HMAC256", 0),
        ("Algorithm.HMAC384", 0),
        ("Algorithm.HMAC512", 0),
        ("Keys.hmacShaKeyFor", 0),
        ("setSigningKey", 0),
        ("signWith", 1),
    ),
    GO: (
        ("aes.NewCipher", 0),
        ("des.NewCipher", 0),
        ("chacha20poly1305.New", 0),
        ("hmac.New", 1),
        ("SignedString", 0),
    ),
    CSHARP: (
        ("SymmetricSecurityKey", 0),
        ("HMACSHA256", 0),
        ("HMACSHA1", 0),
        ("HMACSHA384", 0),
        ("HMACSHA512", 0),
        ("HMACMD5", 0),
        ("CreateEncryptor", 0),
    ),
    PHP: (
        ("openssl_encrypt", 2),
        ("openssl_decrypt", 2),
        ("hash_hmac", 2),
        ("JWT.encode", 1),
        ("Key", 0),
    ),
    RUBY: (
        ("JWT.encode", 1),
        ("JWT.decode", 1),
        ("OpenSSL.HMAC.hexdigest", 1),
        ("OpenSSL.HMAC.digest", 1),
    ),
    RUST: (
        ("EncodingKey.from_secret", 0),
        ("DecodingKey.from_secret", 0),
        ("new_from_slice", 0),
    ),
}
_KEY_ARGUMENTS[TYPESCRIPT] = _KEY_ARGUMENTS[JAVASCRIPT]
# Thuộc tính mà gán hằng vào là viết cứng khoá hoặc IV.
_KEY_PROPERTIES: Dict[str, Dict[str, str]] = {
    CSHARP: {"Key": "key", "IV": "iv"},
    RUBY: {"key": "key", "iv": "iv"},
}

# ( chuỗi gọi, vị trí đối số độ dài khoá, thuật toán )
_KEY_SIZES: Dict[str, Tuple[Tuple[str, int, str], ...]] = {
    GO: (("rsa.GenerateKey", 1, "RSA"), ("rsa.GenerateMultiPrimeKey", 2, "RSA")),
    CSHARP: (
        ("RSACryptoServiceProvider", 0, "RSA"),
        ("RSA.Create", 0, "RSA"),
        ("DSACryptoServiceProvider", 0, "DSA"),
        ("KeySize", 0, "RSA"),
    ),
    RUBY: (("OpenSSL.PKey.RSA.new", 0, "RSA"), ("OpenSSL.PKey.RSA.generate", 0, "RSA")),
    RUST: (("RsaPrivateKey.new", 1, "RSA"),),
    JAVA: (("RSAKeyGenParameterSpec", 0, "RSA"),),
}

# Lời gọi PRNG không an toàn ( khớp theo đuôi chuỗi gọi ).
_RANDOM_CALLS: Dict[str, Tuple[str, ...]] = {
    JAVASCRIPT: ("Math.random",),
    JAVA: (
        "Math.random",
        "RandomStringUtils.random",
        "RandomStringUtils.randomAlphanumeric",
        "RandomStringUtils.randomAlphabetic",
        "RandomStringUtils.randomNumeric",
        "RandomStringUtils.randomAscii",
        "ThreadLocalRandom.current.nextInt",
        "ThreadLocalRandom.current.nextLong",
        "Random.nextInt",
        "Random.nextLong",
        "Random.nextBytes",
        "Random.nextDouble",
    ),
    CSHARP: (
        "Random.Shared.Next",
        "Random.Shared.NextBytes",
        "Random.Shared.NextInt64",
        "Random.Next",
        "Random.NextBytes",
    ),
    PHP: ("rand", "mt_rand", "uniqid", "lcg_value", "str_shuffle", "array_rand"),
    RUBY: ("rand", "Random.rand", "Random.new.rand", "Random.new.bytes", "sample", "shuffle"),
    PERL: ("rand",),
    LUA: ("math.random",),
}
_RANDOM_CALLS[TYPESCRIPT] = _RANDOM_CALLS[JAVASCRIPT]
_BARE_CALLS = frozenset(
    {"sample", "shuffle", "rand", "hexdigest", "digest", "base64digest", "md5_hex", "md5_base64",
     "sha1_hex", "sha1_base64", "sha256_hex"}
)
_RNG_CONSTRUCTORS: Dict[str, Tuple[str, ...]] = {
    JAVA: ("Random",),
    CSHARP: ("Random",),
    RUBY: ("Random.new",),
}
_RNG_METHODS = frozenset(
    {"nextInt", "nextLong", "nextBytes", "nextDouble", "nextFloat", "ints", "Next", "NextBytes",
     "NextDouble", "NextInt64", "rand", "bytes"}
)
_GO_RANDOM_FUNCTIONS = frozenset(
    {"Intn", "Int", "Int63", "Int31", "Int63n", "Int31n", "Uint32", "Uint64", "Read", "Perm",
     "Float64", "IntN", "N", "Shuffle", "Int64", "Int64N", "Uint64N"}
)

# Thuộc tính / khoá mà một giá trị nhất định là tắt xác minh TLS.
_TLS_PROPERTIES: Dict[str, Tuple[Tuple[str, FrozenSet[str], str], ...]] = {
    JAVASCRIPT: (
        ("rejectUnauthorized", frozenset({"false"}), "rejectUnauthorized: false"),
        ("NODE_TLS_REJECT_UNAUTHORIZED", frozenset({"0", "'0'", "false"}), "NODE_TLS_REJECT_UNAUTHORIZED=0"),
        ("strictSSL", frozenset({"false"}), "strictSSL: false"),
    ),
    GO: (("InsecureSkipVerify", frozenset({"true"}), "InsecureSkipVerify: true"),),
    PHP: (
        ("verify_peer", frozenset({"false", "0"}), "verify_peer => false"),
        ("verify_peer_name", frozenset({"false", "0"}), "verify_peer_name => false"),
        ("verify", frozenset({"false"}), "'verify' => false"),
    ),
    PERL: (
        ("SSL_verify_mode", frozenset({"0", "SSL_VERIFY_NONE"}), "SSL_verify_mode => SSL_VERIFY_NONE"),
        ("verify_hostname", frozenset({"0"}), "verify_hostname => 0"),
        ("PERL_LWP_SSL_VERIFY_HOSTNAME", frozenset({"0"}), "PERL_LWP_SSL_VERIFY_HOSTNAME = 0"),
    ),
    LUA: (("verify", frozenset({"'none'"}), 'verify = "none"'),),
    RUBY: (("verify_mode", frozenset({"VERIFY_NONE", ":none"}), "verify_mode: VERIFY_NONE"),),
    CSHARP: (),
}
_TLS_PROPERTIES[TYPESCRIPT] = _TLS_PROPERTIES[JAVASCRIPT]
_TLS_IDENTIFIERS: Dict[str, Dict[str, str]] = {
    JAVA: {
        "NoopHostnameVerifier": "NoopHostnameVerifier chấp nhận mọi tên máy chủ",
        "ALLOW_ALL_HOSTNAME_VERIFIER": "ALLOW_ALL_HOSTNAME_VERIFIER chấp nhận mọi tên máy chủ",
        "AllowAllHostnameVerifier": "AllowAllHostnameVerifier chấp nhận mọi tên máy chủ",
        "TrustAllStrategy": "TrustAllStrategy tin mọi chứng chỉ",
        "InsecureTrustManagerFactory": "InsecureTrustManagerFactory tin mọi chứng chỉ",
    },
    CSHARP: {
        "DangerousAcceptAnyServerCertificateValidator": (
            "DangerousAcceptAnyServerCertificateValidator chấp nhận mọi chứng chỉ"
        ),
    },
    RUBY: {"VERIFY_NONE": "OpenSSL::SSL::VERIFY_NONE tắt xác minh chứng chỉ"},
    PHP: {},
}
_TLS_TRUE_CALLS: Dict[str, Tuple[str, ...]] = {
    RUST: ("danger_accept_invalid_certs", "danger_accept_invalid_hostnames"),
}
_CALLBACK_PROPERTIES = frozenset(
    {
        "ServerCertificateValidationCallback",
        "ServerCertificateCustomValidationCallback",
        "RemoteCertificateValidationCallback",
        "setHostnameVerifier",
        "setDefaultHostnameVerifier",
        "hostnameVerifier",
        "HostnameVerifier",
    }
)


class _Scan:
    def __init__(
        self, unit: AnalysisUnit, budget: Budget, builder: FindingBuilder, tokens: List[Token]
    ) -> None:
        self.unit = unit
        self.language = unit.language
        self.budget = budget
        self.builder = builder
        self.raw = tokens
        # Mã thật, không lẫn token nội suy bên trong chuỗi.
        self.flat: List[Token] = []
        self.interpolated: Set[int] = set()
        for index, token in enumerate(tokens):
            if token.in_string or token.kind == NEWLINE:
                continue
            if token.kind == STRING and index + 1 < len(tokens) and tokens[index + 1].in_string:
                self.interpolated.add(len(self.flat))
            self.flat.append(token)
        self.position = {id(token): index for index, token in enumerate(self.flat)}
        self.calls: List[_Call] = []
        self.bindings: Dict[str, List[Optional[Tuple[Token, ...]]]] = {}
        self.binding_lines: Dict[str, int] = {}
        self.regions: List[Tuple[int, int, str]] = []
        self.matching: Dict[int, int] = {}
        self.opening: Dict[int, int] = {}
        self.consumed_lines: Set[int] = set()
        self.reported: Set[Tuple[str, int, int]] = set()
        self.tls_lines: Set[int] = set()

    # ------------------------------------------------------------- building

    def run(self) -> None:
        self._match_brackets()
        self._collect_calls()
        self._collect_bindings()
        self._collect_regions()
        self._check_hashes()
        self._check_ciphers()
        self._check_ivs()
        self._check_keys()
        self._check_random()
        self._check_key_sizes()
        self._check_tls()
        self._check_secrets()
        config_tokens.check(self)
        web_tokens.check(self)
        access_tokens.check(self)
        hardening_tokens.check(self)

    def _match_brackets(self) -> None:
        stack: List[int] = []
        pairs = {")": "(", "]": "[", "}": "{"}
        for index, token in enumerate(self.flat):
            if token.kind != OP:
                continue
            if token.text in "([{":
                stack.append(index)
            elif token.text in pairs:
                while stack and self.flat[stack[-1]].text != pairs[token.text]:
                    stack.pop()
                if stack:
                    opening = stack.pop()
                    self.matching[opening] = index
                    self.opening[index] = opening

    def _chain(
        self, index: int, empty_calls: Optional[List[Tuple[int, int]]] = None
    ) -> Tuple[Optional[List[str]], int]:
        flat = self.flat
        limit = len(flat)
        if index >= limit or flat[index].kind != IDENT:
            return None, index
        parts = [_strip_sigil(flat[index].text)]
        cursor = index + 1
        while cursor + 1 < limit:
            token = flat[cursor]
            if token.kind == OP and token.text == "(":
                # `ThreadLocalRandom.current().nextInt`, `new Random().nextInt`
                if (
                    cursor + 3 < limit
                    and flat[cursor + 1].text == ")"
                    and flat[cursor + 2].text in _SEPARATORS
                    and flat[cursor + 3].kind == IDENT
                ):
                    if empty_calls is not None:
                        # `Math.random().toString(36)` vẫn là lời gọi Math.random()
                        empty_calls.append((len(parts), cursor))
                    parts.append(flat[cursor + 3].text)
                    cursor += 4
                    continue
                break
            if token.kind != OP or token.text not in _SEPARATORS:
                break
            following = flat[cursor + 1]
            if following.kind != IDENT:
                break
            parts.append(_strip_sigil(following.text))
            cursor += 2
        return parts, cursor

    def _collect_calls(self) -> None:
        flat = self.flat
        index = 0
        limit = len(flat)
        while index < limit:
            self.budget.spend()
            empty: List[Tuple[int, int]] = []
            parts, after = self._chain(index, empty)
            if parts is None:
                index += 1
                continue
            for length, paren in empty:
                self.calls.append(
                    _Call(
                        chain=".".join(parts[:length]),
                        parts=tuple(parts[:length]),
                        anchor=flat[index],
                        index=index,
                        open_index=paren,
                        close_index=paren + 1,
                        arguments=(),
                    )
                )
            if (
                self.language in (RUBY, PERL)
                and parts[-1] in _BARE_CALLS
                and not (after < limit and flat[after].text == "(")
            ):
                # Ruby và Perl gọi hàm không cần ngoặc: `chars.sample`,
                # `Digest::MD5.hexdigest password`, `md5_hex $x`.
                end = after
                while end < limit and flat[end].line == flat[index].line and flat[end].text not in (
                    "}",
                    ";",
                    "do",
                    "if",
                    "unless",
                ):
                    end += 1
                self.calls.append(
                    _Call(
                        chain=".".join(parts),
                        parts=tuple(parts),
                        anchor=flat[index],
                        index=index,
                        open_index=after - 1,
                        close_index=max(after - 1, end - 1),
                        arguments=(tuple(flat[after:end]),) if end > after else (),
                    )
                )
            if after < limit and flat[after].kind == OP and flat[after].text == "(":
                close = self.matching.get(after, min(limit - 1, after + _MAX_ARGUMENT_TOKENS))
                self.calls.append(
                    _Call(
                        chain=".".join(parts),
                        parts=tuple(parts),
                        anchor=flat[index],
                        index=index,
                        open_index=after,
                        close_index=close,
                        arguments=tuple(self._split_arguments(after, close)),
                    )
                )
            index = max(after, index + 1)

    def _split_arguments(self, open_index: int, close_index: int) -> List[Tuple[Token, ...]]:
        arguments: List[Tuple[Token, ...]] = []
        current: List[Token] = []
        depth = 0
        for index in range(open_index + 1, min(close_index, open_index + _MAX_ARGUMENT_TOKENS)):
            token = self.flat[index]
            if token.kind == OP:
                if token.text in "([{":
                    depth += 1
                elif token.text in ")]}":
                    depth -= 1
                elif token.text == "," and depth == 0:
                    arguments.append(tuple(current))
                    current = []
                    continue
            current.append(token)
        if current:
            arguments.append(tuple(current))
        return arguments

    def _rhs(self, start: int) -> Tuple[Token, ...]:
        """Vế phải của một phép gán: tới dấu `;` / `,` cùng cấp hoặc hết dòng."""
        flat = self.flat
        depth = 0
        collected: List[Token] = []
        previous_line = flat[start - 1].line if start else 0
        for index in range(start, min(len(flat), start + _MAX_ARGUMENT_TOKENS)):
            token = flat[index]
            if depth == 0 and collected and token.line != previous_line:
                last = collected[-1]
                if not (last.kind == OP and last.text in ("+", ".", ",", "(", "=", "||", "&&", "?", ":", "=>")):
                    break
            if token.kind == OP:
                if token.text in "([{":
                    depth += 1
                elif token.text in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0 and token.text in (";", ","):
                    break
            collected.append(token)
            previous_line = token.line
        return tuple(collected)

    def _collect_bindings(self) -> None:
        flat = self.flat
        for index, token in enumerate(flat):
            if token.kind != OP or token.text not in ("=", ":=") or index == 0:
                continue
            target = flat[index - 1]
            if target.kind != IDENT:
                continue
            # `a.b = x` vẫn ràng buộc tên b; `a[b] = x` thì không.
            self.budget.spend()
            name = _strip_sigil(target.text)
            rhs = self._rhs(index + 1)
            self.bindings.setdefault(name, []).append(rhs)
            self.binding_lines.setdefault(name, target.line)
        # Một tên được đổ byte ngẫu nhiên vào thì không còn là hằng.
        for call in self.calls:
            if call.parts[-1] not in _FILLERS:
                continue
            for argument in call.arguments:
                for token in argument:
                    if token.kind == IDENT:
                        self.bindings.setdefault(_strip_sigil(token.text), []).append(None)

    def _collect_regions(self) -> None:
        flat = self.flat
        for open_index, close_index in self.matching.items():
            if flat[open_index].text != "{":
                continue
            name = self._function_name_before(open_index)
            if name:
                self.regions.append((open_index, close_index, name))
        # Ngôn ngữ dùng `def ... end`: vùng hàm kéo tới header kế tiếp.
        if self.language in (RUBY, LUA):
            headers = [
                (index, flat[index + 1].text)
                for index in range(len(flat) - 1)
                if flat[index].kind == IDENT
                and flat[index].text in ("def", "function")
                and flat[index + 1].kind == IDENT
            ]
            for position, (index, name) in enumerate(headers):
                end = headers[position + 1][0] if position + 1 < len(headers) else len(flat)
                self.regions.append((index, end, _strip_sigil(name.split(".")[-1])))

    def _function_name_before(self, open_index: int) -> Optional[str]:
        flat = self.flat
        cursor = open_index - 1
        steps = 0
        # Bỏ qua kiểu trả về, `throws X`, `async`, mũi tên.
        while cursor >= 0 and steps < 12:
            token = flat[cursor]
            if token.kind == OP and token.text == ")":
                break
            if token.kind == IDENT and flat[cursor - 1].text in ("sub", "function") if cursor else False:
                return _strip_sigil(token.text)
            if token.kind == OP and token.text not in (".", "<", ">", ",", ":", "?", "*", "[", "]", "=>", "->", "&", "::"):
                return None
            cursor -= 1
            steps += 1
        if cursor < 0 or flat[cursor].text != ")":
            return None
        for _ in range(2):
            opening = self.opening.get(cursor)
            if opening is None or opening == 0:
                return None
            before = flat[opening - 1]
            if before.kind == OP and before.text == ")":
                cursor = opening - 1  # Go: func f() (string, error) {
                continue
            if before.kind == OP and before.text in ("=", ":"):
                # const name = (a) => {   |   name: function (a) {
                if opening >= 2 and flat[opening - 2].kind == IDENT:
                    return _strip_sigil(flat[opening - 2].text)
                return None
            if before.kind == IDENT:
                if before.text in ("function", "async") and opening >= 3:
                    if flat[opening - 2].text in ("=", ":") and flat[opening - 3].kind == IDENT:
                        return _strip_sigil(flat[opening - 3].text)
                    return None
                if before.text in _CONTROL_KEYWORDS:
                    return None
                return _strip_sigil(before.text)
            return None
        return None

    def _function_at(self, index: int) -> Optional[Tuple[int, int, str]]:
        best: Optional[Tuple[int, int, str]] = None
        for region in self.regions:
            if region[0] <= index <= region[1]:
                if best is None or region[0] > best[0]:
                    best = region
        return best

    # -------------------------------------------------------------- helpers

    def _literal(self, tokens: Sequence[Token], depth: int = 0) -> Optional[_Literal]:
        if not tokens or depth > 4:
            return None
        if _zero_allocation(tokens):
            return _Literal("mảng byte toàn số 0", tokens[0].line)
        if len(tokens) == 1 and tokens[0].kind == IDENT:
            return self._bound_literal(_strip_sigil(tokens[0].text), depth)
        # `this.IV`, `Config.KEY`, `self::KEY`
        if (
            len(tokens) == 3
            and tokens[0].kind == IDENT
            and tokens[1].text in _SEPARATORS
            and tokens[2].kind == IDENT
            and tokens[0].text in ("this", "self", "static", "$this", "Self")
        ):
            return self._bound_literal(_strip_sigil(tokens[2].text), depth)
        if len(tokens) == 3 and tokens[1].text in _SEPARATORS and tokens[2].text.isupper():
            literal = self._bound_literal(_strip_sigil(tokens[2].text), depth)
            if literal is not None:
                return literal
        has_value = False
        has_string = False
        for token in tokens:
            if token.kind == STRING:
                if id(token) in self._interpolated_ids():
                    return None
                has_value = True
                has_string = True
            elif token.kind == NUMBER:
                has_value = True
            elif token.kind == IDENT:
                if _strip_sigil(token.text) not in _LITERAL_HELPERS:
                    return None
            elif token.kind == OP and token.text in ("=>", "?", "&&", "||", "??"):
                return None
        if not has_value:
            return None
        line = tokens[0].line
        if has_string:
            return _Literal("hằng chuỗi", line)
        return _Literal("mảng byte cố định", line)

    def _interpolated_ids(self) -> Set[int]:
        cached = getattr(self, "_interp_ids", None)
        if cached is None:
            cached = {id(self.flat[index]) for index in self.interpolated}
            self._interp_ids = cached
        return cached

    def _bound_literal(self, name: str, depth: int) -> Optional[_Literal]:
        values = self.bindings.get(name)
        if not values:
            return None
        found: Optional[_Literal] = None
        for value in values:
            if value is None:
                return None
            literal = self._literal(value, depth + 1)
            if literal is None:
                return None
            found = found or _Literal(literal.description, value[0].line if value else 0)
        return found

    def _names(self, tokens: Sequence[Token]) -> List[str]:
        names: List[str] = []
        for token in tokens:
            if token.kind == IDENT:
                names.append(_strip_sigil(token.text))
            elif token.kind == STRING and _IDENTIFIER_LIKE.match(token.text):
                names.append(token.text)
        return names

    def _output_names(self, call: _Call) -> Tuple[List[str], List[str]]:
        """Tên của nơi nhận kết quả lời gọi, như phía Python làm trên AST."""
        flat = self.flat
        names: List[str] = []
        targets: List[str] = []
        cursor = call.index - 1
        depth = 0
        steps = 0
        while cursor >= 0 and steps < _MAX_LOOKBACK:
            token = flat[cursor]
            steps += 1
            if token.kind == OP:
                if token.text in ")]":
                    depth += 1
                elif token.text in "([":
                    if depth:
                        depth -= 1
                elif token.text in (";", "}") or (token.text == "{" and depth == 0 and cursor and flat[cursor - 1].text == ")"):
                    break
                elif depth == 0 and token.text in _ASSIGN | _PAIR and cursor:
                    target = flat[cursor - 1]
                    if target.kind == OP and target.text == "]":
                        # $_SESSION['session_token'] = ...  ->  session_token
                        # b[i] = ...  ->  b
                        opening = self.opening.get(cursor - 1)
                        if cursor >= 2 and flat[cursor - 2].kind == STRING:
                            target = flat[cursor - 2]
                        elif opening:
                            target = flat[opening - 1]
                    if target.kind in (IDENT, STRING):
                        name = _strip_sigil(target.text)
                        names.append(name)
                        if token.text in _ASSIGN:
                            targets.append(name)
                    if token.text in _ASSIGN:
                        break
                elif depth == 0 and token.text in ("==", "===", "!=", "!=="):
                    names.extend(self._names(flat[max(0, cursor - 4) : cursor]))
            elif token.kind == IDENT and token.text == "return" and depth == 0:
                region = self._function_at(call.index)
                if region is not None:
                    names.append(region[2])
                break
            if token.line < call.anchor.line - 2:
                break
            cursor -= 1
        # So sánh ở phía sau: md5(x) == stored_password, .equals(password)
        after = call.close_index + 1
        tail = flat[after : after + 12]
        for position, token in enumerate(tail):
            if token.kind == OP and token.text in ("==", "===", "!=", "!=="):
                names.extend(self._names(tail[position + 1 : position + 5]))
                break
            if token.kind == IDENT and token.text in ("equals", "Equals", "isEqual", "hash_equals"):
                names.extend(self._names(tail[position + 1 : position + 6]))
                break
            if token.kind == OP and token.text in (";", "{", "}"):
                break
        return names, targets

    def _implicit_return(self, call: _Call, region: Tuple[int, int, str]) -> bool:
        """Ruby và Rust trả về biểu thức cuối của hàm mà không cần `return`."""
        if self.language not in (RUBY, RUST):
            return False
        lines = [
            token.line
            for token in self.flat[region[0] + 1 : min(region[1], len(self.flat))]
            if token.text not in ("end", "}", "def", "fn")
        ]
        return bool(lines) and max(lines) == self.flat[call.close_index].line

    def _returned(self, region: Tuple[int, int, str], names: Sequence[str]) -> bool:
        wanted = set(names)
        if not wanted:
            return False
        flat = self.flat
        for index in range(region[0], min(region[1], len(flat))):
            token = flat[index]
            if token.kind == IDENT and token.text == "return":
                line = token.line
                cursor = index + 1
                while cursor < len(flat) and flat[cursor].line == line:
                    if flat[cursor].kind == IDENT and _strip_sigil(flat[cursor].text) in wanted:
                        return True
                    cursor += 1
        return False

    def _mask_tokens(self, tokens: Sequence[Token]) -> None:
        lines = self.unit.lines
        for token in tokens:
            if token.kind != STRING or not (1 <= token.line <= len(lines)):
                continue
            text = lines[token.line - 1]
            self.builder.mask(token.line, token.column, _literal_end(text, token.column))

    def _report(
        self,
        rule_id: str,
        token: Token,
        symbol: str,
        message: str,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        trace=(),
        evidence: Sequence[str] = (),
    ) -> None:
        key = (rule_id, token.line, token.column)
        if key in self.reported:
            return
        self.reported.add(key)
        self.builder.add(
            rule_id,
            token.line,
            token.column,
            symbol,
            message,
            severity=severity,
            confidence=confidence,
            trace=trace,
            evidence=evidence,
        )

    def _string_value(self, tokens: Sequence[Token]) -> Optional[str]:
        meaningful = [token for token in tokens if token.kind != NEWLINE]
        strings = [token for token in meaningful if token.kind == STRING]
        if len(strings) == 1 and id(strings[0]) not in self._interpolated_ids():
            others = [t for t in meaningful if t.kind != STRING]
            if all(t.kind == OP or _strip_sigil(t.text) in _LITERAL_HELPERS for t in others):
                return strings[0].text
        if len(meaningful) == 1 and meaningful[0].kind == IDENT:
            values = self.bindings.get(_strip_sigil(meaningful[0].text)) or []
            if len(values) == 1 and values[0] is not None:
                return self._string_value(values[0])
        return None

    # --------------------------------------------------------------- hashes

    def _check_hashes(self) -> None:
        specs = _HASHES.get(self.language, ())
        if not specs:
            return
        sites: List[Tuple[_Call, str, bool, List[str]]] = []
        objects: Dict[str, int] = {}
        for call in self.calls:
            self.budget.spend()
            for pattern, fixed, algorithm_index in specs:
                if not _matches(call.parts, pattern):
                    continue
                if self.language == PHP and len(call.parts) != 1:
                    continue  # $obj->md5() là phương thức của người dùng
                if fixed is not None:
                    label = fixed
                    weak = fixed in ("MD5", "SHA-1")
                    data = list(call.arguments)
                else:
                    value = self._string_value(call.argument(algorithm_index))
                    if value is None:
                        break
                    label = value.upper()
                    weak = value.lower().replace("_", "-") in _WEAK_HASH_ALGORITHMS
                    data = [arg for pos, arg in enumerate(call.arguments) if pos != algorithm_index]
                inputs: List[str] = []
                for argument in data:
                    inputs.extend(self._names(argument))
                inputs.extend(self._chained_inputs(call))
                sites.append((call, label, weak, inputs))
                _, targets = self._output_names(call)
                for target in targets:
                    objects[target] = len(sites) - 1
                break
        if objects:
            for call in self.calls:
                if len(call.parts) >= 2 and call.parts[-1] in _HASH_OBJECT_METHODS:
                    owner = call.parts[-2]
                    if owner in objects:
                        for argument in call.arguments:
                            sites[objects[owner]][3].extend(self._names(argument))
        for call, label, weak, inputs in sites:
            self.budget.spend()
            if self._near_slow_kdf(call):
                continue
            outputs, targets = self._output_names(call)
            if self._fed_to_slow_kdf(call, targets):
                continue
            password_in = words.first_match(inputs, words.is_password_name)
            password_out = words.first_match(outputs, words.is_password_name)
            if password_in or password_out:
                name = password_in or password_out
                self._report(
                    "FSB-CRYPTO-002",
                    call.anchor,
                    label,
                    "mật khẩu ( %s ) được băm bằng %s, một hàm băm nhanh không làm chậm vét cạn"
                    % (name, label),
                    confidence=Confidence.HIGH if password_in else Confidence.MEDIUM,
                    evidence=(
                        "đầu vào của hàm băm mang tên mật khẩu: %s" % name
                        if password_in
                        else "kết quả băm được gán hoặc so với tên mật khẩu: %s" % name,
                        "không nằm trong bcrypt / scrypt / argon2 / pbkdf2",
                    ),
                )
                continue
            if not weak:
                continue
            secret_in = words.first_match(inputs, words.is_secret_name)
            sign_out = words.first_match(outputs, words.is_sign_name)
            if secret_in or sign_out:
                self._report(
                    "FSB-CRYPTO-001",
                    call.anchor,
                    label,
                    "%s được dùng để dựng giá trị xác thực ( %s ); hàm băm này đã có tấn công va "
                    "chạm và tự ghép bí mật với dữ liệu thì bị tấn công nối dài"
                    % (label, secret_in or sign_out),
                    evidence=(
                        "dữ liệu được băm có chứa bí mật: %s" % secret_in
                        if secret_in
                        else "kết quả được dùng làm chữ ký: %s" % sign_out,
                    ),
                )

    def _chained_inputs(self, call: _Call) -> List[str]:
        """`createHash('md5').update(password).digest('hex')`"""
        flat = self.flat
        names: List[str] = []
        cursor = call.close_index + 1
        for _ in range(6):
            if cursor + 2 >= len(flat):
                break
            if flat[cursor].text not in _SEPARATORS or flat[cursor + 1].kind != IDENT:
                break
            method = flat[cursor + 1].text
            if flat[cursor + 2].text != "(":
                break
            close = self.matching.get(cursor + 2)
            if close is None:
                break
            if method in _HASH_CHAINS:
                for argument in self._split_arguments(cursor + 2, close):
                    names.extend(self._names(argument))
            cursor = close + 1
        return names

    def _statement_span(self, call: _Call) -> Tuple[int, int]:
        start = call.index
        while start > 0 and self.flat[start - 1].line == call.anchor.line:
            start -= 1
        end = call.close_index
        while end + 1 < len(self.flat) and self.flat[end + 1].line == self.flat[call.close_index].line:
            end += 1
        return start, end

    def _near_slow_kdf(self, call: _Call) -> bool:
        start, end = self._statement_span(call)
        for token in self.flat[start : end + 1]:
            if token.kind == IDENT and _strip_sigil(token.text) in _SLOW_KDF_NAMES:
                return True
        return False

    def _fed_to_slow_kdf(self, call: _Call, targets: Sequence[str]) -> bool:
        if not targets:
            return False
        region = self._function_at(call.index)
        low, high = (region[0], region[1]) if region else (0, len(self.flat))
        wanted = set(targets)
        for other in self.calls:
            if not (low <= other.index <= high) or other.index <= call.index:
                continue
            if any(part in _SLOW_KDF_NAMES for part in other.parts) or (
                words.SLOW_KDF_WORDS & set(words.split_words(other.parts[-1]))
            ):
                for argument in other.arguments:
                    if wanted & set(self._names(argument)):
                        return True
        return False

    # -------------------------------------------------------------- ciphers

    def _check_ciphers(self) -> None:
        strings = _CIPHER_STRINGS.get(self.language, ())
        calls = _CIPHER_CALLS.get(self.language, ())
        ecb = _ECB_IDENTIFIERS.get(self.language, frozenset())
        weak_identifiers = _WEAK_CIPHER_IDENTIFIERS.get(self.language, {})
        for call in self.calls:
            self.budget.spend()
            for pattern, position in strings:
                if not _matches(call.parts, pattern):
                    continue
                value = self._string_value(call.argument(position))
                if value is None:
                    break
                self._judge_cipher_string(call, value, pattern)
                break
            for pattern, label in calls:
                if _matches(call.parts, pattern):
                    self._report_cipher(call.anchor, label, pattern)
                    break
            if self.language in (JAVASCRIPT, TYPESCRIPT) and call.parts[-1] in (
                "createCipher",
                "createDecipher",
            ) and len(call.parts) <= 2:
                self._report(
                    "FSB-CRYPTO-005",
                    call.anchor,
                    call.parts[-1],
                    "%s() dẫn xuất khoá và IV từ mật khẩu bằng một vòng MD5 không muối, nên cùng "
                    "mật khẩu luôn cho cùng IV" % call.parts[-1],
                    evidence=("API đã bị gỡ khỏi Node.js 22 vì đúng lý do này",),
                )
        if ecb or weak_identifiers:
            index = 0
            while index < len(self.flat):
                parts, after = self._chain(index)
                if parts is None:
                    index += 1
                    continue
                chain = ".".join(parts)
                for pattern in ecb:
                    if _matches(parts, pattern):
                        self._report(
                            "FSB-CRYPTO-004",
                            self.flat[index],
                            chain,
                            "bộ mã hoá khối chạy ở chế độ ECB ( %s )" % chain,
                            evidence=("hằng chế độ %s" % chain,),
                        )
                label = weak_identifiers.get(parts[-1])
                if label is not None:
                    self._report_cipher(self.flat[index], label, parts[-1])
                index = max(after, index + 1)

    def _judge_cipher_string(self, call: _Call, value: str, pattern: str) -> None:
        lowered = value.lower()
        pieces = [piece for piece in re.split(r"[-/_ ]", lowered) if piece]
        if not pieces:
            return
        head = pieces[0]
        if head.startswith("pbewith"):
            # PBEWithMD5AndDES, PBEWithSHA1AndDESede
            for name, label in (("desede", "3DES"), ("des", "DES"), ("rc2", "RC2"), ("rc4", "RC4")):
                if lowered.endswith("and" + name) or ("and" + name) in lowered:
                    self._report_cipher(call.anchor, label, value)
                    return
            return
        if head in ("des", "des3") and len(pieces) > 1 and pieces[1] == "ede3":
            head = "3des"
        label = _WEAK_CIPHERS.get(head)
        if label is not None:
            self._report_cipher(call.anchor, label, value)
            return
        if head == "rsa":
            return  # "RSA/ECB/..." -- ECB là tên gọi sai, RSA không có chế độ khối
        if "ecb" in pieces or (pattern == "Cipher.getInstance" and len(pieces) == 1 and head == "aes"):
            implicit = "ecb" not in pieces
            self._report(
                "FSB-CRYPTO-004",
                call.anchor,
                value,
                "Cipher.getInstance(\"%s\") không ghi chế độ nên JCE dùng mặc định AES/ECB" % value
                if implicit
                else "bộ mã hoá khối chạy ở chế độ ECB ( \"%s\" )" % value,
                evidence=("chuỗi thuật toán: %s" % value,),
            )

    def _report_cipher(self, token: Token, label: str, source: str) -> None:
        self._report(
            "FSB-CRYPTO-003",
            token,
            label,
            "dữ liệu được mã hoá bằng %s, một thuật toán đã bị phá" % label,
            evidence=("thuật toán xác định từ %s" % source,),
        )

    # ------------------------------------------------------------ IV / key

    def _check_ivs(self) -> None:
        specs = _IV_ARGUMENTS.get(self.language, ())
        properties = _KEY_PROPERTIES.get(self.language, {})
        for call in self.calls:
            self.budget.spend()
            for pattern, position, kind in specs:
                if not _matches(call.parts, pattern):
                    continue
                argument = call.argument(position)
                literal = self._literal(argument)
                if literal is None:
                    break
                if kind == "iv?":
                    mode = (self._string_value(call.argument(1 if self.language == PHP else 0)) or "").lower()
                    fatal = any(piece in _FATAL_MODES for piece in re.split(r"[-/_ ]", mode))
                    kind = "nonce" if fatal else "iv"
                self._report_iv(call, argument, literal, kind)
                break
            # Go: aead.Seal(dst, nonce, plaintext, aad)
            if (
                self.language == GO
                and call.parts[-1] == "Seal"
                and len(call.arguments) == 4
            ):
                literal = self._literal(call.argument(1))
                if literal is not None:
                    self._report_iv(call, call.argument(1), literal, "nonce")
        if properties:
            self._check_properties(properties)

    def _report_iv(self, call: _Call, argument: Sequence[Token], literal: _Literal, kind: str) -> None:
        anchor = argument[0] if argument else call.anchor
        if kind == "nonce":
            message = (
                "nonce là %s: cùng khoá và cùng nonce cho cùng dòng khoá, lộ XOR của các bản rõ"
                % literal.description
            )
        elif kind == "salt":
            message = "muối của hàm dẫn xuất khoá là %s, mọi mật khẩu dùng chung một muối" % (
                literal.description
            )
        else:
            message = "IV là %s nên bản mã của các bản rõ cùng phần đầu sẽ trùng nhau" % (
                literal.description
            )
        trace = ()
        if literal.line and literal.line != anchor.line:
            trace = (
                self.builder.step(StepKind.SOURCE, literal.line, 0, "giá trị cố định được gán ở đây"),
                self.builder.step(StepKind.SINK, anchor.line, anchor.column, call.chain),
            )
        self._report(
            "FSB-CRYPTO-005",
            anchor,
            {"salt": "muối"}.get(kind, kind),
            message,
            severity=Severity.HIGH if kind == "nonce" else None,
            trace=trace,
            evidence=("%s lấy từ %s, không sinh mới cho mỗi lần dùng" % (kind, literal.description),),
        )

    def _check_keys(self) -> None:
        specs = _KEY_ARGUMENTS.get(self.language, ())
        for call in self.calls:
            self.budget.spend()
            for pattern, position in specs:
                if not _matches(call.parts, pattern):
                    continue
                if pattern == "Key" and len(call.parts) != 1:
                    break
                argument = call.argument(position)
                literal = self._literal(argument)
                if literal is None or _empty_or_public(argument):
                    break
                self._report_key(call, argument, literal)
                break
        if self.language == GO:
            self._check_go_keyfunc()

    def _report_key(self, call: _Call, argument: Sequence[Token], literal: _Literal) -> None:
        if words.is_fixture_path(self.unit.relative_path):
            return  # khoá trong test là dữ liệu mẫu, không phải khoá bị lộ
        anchor = argument[0] if argument else call.anchor
        self.consumed_lines.add(literal.line)
        self.consumed_lines.add(anchor.line)
        self._mask_tokens(argument)
        if literal.line != anchor.line:
            self._mask_tokens([t for t in self.flat if t.line == literal.line and t.kind == STRING])
        trace = ()
        if literal.line and literal.line != anchor.line:
            trace = (
                self.builder.step(StepKind.SOURCE, literal.line, 0, "khoá cố định được gán ở đây"),
                self.builder.step(StepKind.SINK, anchor.line, anchor.column, call.chain),
            )
        self._report(
            "FSB-CRYPTO-006",
            anchor,
            call.parts[-1],
            "khoá của %s là %s nằm ngay trong mã nguồn" % (call.chain, literal.description),
            trace=trace,
            evidence=("khoá được giải về %s" % literal.description,),
        )

    def _check_go_keyfunc(self) -> None:
        """jwt.Parse(t, func(*jwt.Token) (interface{}, error) { return []byte("k"), nil })"""
        for call in self.calls:
            if call.parts[-1] not in ("Parse", "ParseWithClaims") or "jwt" not in call.parts[:-1]:
                continue
            for index in range(call.open_index, call.close_index):
                token = self.flat[index]
                if token.kind != IDENT or token.text != "return":
                    continue
                value = self._rhs(index + 1)
                literal = self._literal(value)
                if literal is not None and not _empty_or_public(value):
                    self._report_key(call, value, literal)

    def _check_properties(self, properties: Dict[str, str]) -> None:
        flat = self.flat
        for index in range(1, len(flat) - 1):
            token = flat[index]
            if token.kind != OP or token.text != "=":
                continue
            target = flat[index - 1]
            if target.kind != IDENT or target.text not in properties:
                continue
            if index < 2 or flat[index - 2].text not in _SEPARATORS:
                continue
            value = self._rhs(index + 1)
            literal = self._literal(value)
            if literal is None or _empty_or_public(value):
                continue
            kind = properties[target.text]
            fake = _Call("thuộc tính ." + target.text, (target.text,), target, index - 1, index, index, ())
            if kind == "key":
                self._report_key(fake, value, literal)
            else:
                self._report_iv(fake, value, literal, "iv")

    # ------------------------------------------------------------- key size

    def _check_key_sizes(self) -> None:
        specs = _KEY_SIZES.get(self.language, ())
        generators: Set[str] = set()
        if self.language == JAVA:
            for name, values in self.bindings.items():
                for value in values:
                    if value is None:
                        continue
                    texts = [t.text for t in value]
                    if "KeyPairGenerator" in texts and any(
                        t.kind == STRING and t.text.upper() in ("RSA", "DSA", "DH", "DIFFIEHELLMAN")
                        for t in value
                    ):
                        generators.add(name)
        for call in self.calls:
            self.budget.spend()
            argument: Sequence[Token] = ()
            algorithm = "RSA"
            for pattern, position, label in specs:
                if _matches(call.parts, pattern):
                    argument = call.argument(position)
                    algorithm = label
                    break
            if not argument and generators and len(call.parts) == 2:
                if call.parts[0] in generators and call.parts[1] == "initialize":
                    argument = call.argument(0)
            if not argument:
                # generateKeyPairSync('rsa', { modulusLength: 1024 }),
                # openssl_pkey_new(['private_key_bits' => 1024])
                if call.parts[-1] in ("generateKeyPairSync", "generateKeyPair", "openssl_pkey_new"):
                    argument = self._property_number(call, ("modulusLength", "private_key_bits"))
            bits = self._int_value(argument)
            if bits is None or bits >= 2048 or bits < 256:
                continue
            anchor = argument[0]
            self._report(
                "FSB-CRYPTO-008",
                anchor,
                algorithm,
                "khoá %s chỉ dài %d bit" % (algorithm, bits),
                severity=Severity.HIGH if bits < 1024 else None,
                evidence=("độ dài khoá đọc được là hằng %d" % bits,),
            )

    def _property_number(self, call: _Call, names: Sequence[str]) -> Sequence[Token]:
        for index in range(call.open_index, call.close_index):
            token = self.flat[index]
            if token.kind in (IDENT, STRING) and token.text in names:
                if index + 2 < len(self.flat) and self.flat[index + 1].text in (":", "=>", "="):
                    return (self.flat[index + 2],)
        return ()

    def _int_value(self, tokens: Sequence[Token]) -> Optional[int]:
        meaningful = [token for token in tokens if token.kind != NEWLINE]
        if len(meaningful) == 1:
            token = meaningful[0]
            if token.kind == NUMBER and token.text.isdigit():
                return int(token.text)
            if token.kind == IDENT:
                values = self.bindings.get(_strip_sigil(token.text)) or []
                if len(values) == 1 and values[0] is not None and len(values[0]) == 1:
                    return self._int_value(values[0])
        return None

    # ----------------------------------------------------------------- PRNG

    def _random_sites(self) -> List[Tuple[_Call, str]]:
        sites: List[Tuple[_Call, str]] = []
        patterns = _RANDOM_CALLS.get(self.language, ())
        constructors = _RNG_CONSTRUCTORS.get(self.language, ())
        rng_names: Set[str] = set()
        for name, values in self.bindings.items():
            if not values or any(value is None for value in values):
                continue
            for value in values:
                chain_tokens = [t.text for t in value if t.kind == IDENT and t.text != "new"]
                head = ".".join(chain_tokens[:2])
                if any(head == ctor or (chain_tokens and chain_tokens[0] == ctor) for ctor in constructors):
                    if "SecureRandom" not in chain_tokens:
                        rng_names.add(name)
        go_aliases = self._go_math_rand_aliases() if self.language == GO else set()
        for call in self.calls:
            if self.language == PHP and len(call.parts) != 1:
                continue
            matched = None
            for pattern in patterns:
                if _matches(call.parts, pattern):
                    if self.language == RUBY and pattern in ("sample", "shuffle", "rand"):
                        if pattern == "rand" and len(call.parts) != 1:
                            continue
                    if pattern in ("Random.nextInt", "Random.nextLong", "Random.nextBytes", "Random.nextDouble", "Random.Next", "Random.NextBytes"):
                        if len(call.parts) != 2:
                            continue
                    matched = call.chain
                    break
            if matched is None and len(call.parts) == 2:
                if call.parts[0] in rng_names and call.parts[1] in _RNG_METHODS:
                    matched = call.chain
                elif call.parts[0] in go_aliases and call.parts[1] in _GO_RANDOM_FUNCTIONS:
                    matched = call.chain
            if matched is not None:
                sites.append((call, matched))
        return sites

    def _go_math_rand_aliases(self) -> Set[str]:
        aliases: Set[str] = set()
        for index, token in enumerate(self.flat):
            if token.kind != STRING or token.text not in ("math/rand", "math/rand/v2"):
                continue
            previous = self.flat[index - 1] if index else None
            if previous is not None and previous.kind == IDENT and previous.text not in ("import",):
                if previous.text != "_":
                    aliases.add(previous.text)
            else:
                aliases.add("rand")
        return aliases

    def _check_random(self) -> None:
        sites = self._random_sites()
        if not sites:
            return
        producers: Dict[str, Tuple[_Call, Tuple[int, int, str]]] = {}
        for call, label in sites:
            self.budget.spend()
            if words.draws_from_nlp_data(
                name for argument in call.arguments for name in self._names(argument)
            ):
                continue
            outputs, targets = self._output_names(call)
            region = self._function_at(call.index)
            returned = False
            if region is not None:
                returned = (
                    region[2] in outputs
                    or self._returned(region, targets)
                    or (not targets and self._implicit_return(call, region))
                )
                if returned:
                    producers.setdefault(region[2], (call, region))
                    if region[2] not in outputs:
                        outputs.append(region[2])
            inputs: List[str] = []
            if call.parts[-1] in ("sample", "shuffle", "str_shuffle", "array_rand"):
                for argument in call.arguments:
                    inputs.extend(self._names(argument))
                if len(call.parts) >= 2:
                    inputs.append(call.parts[-2])
            hit = words.first_match(outputs + inputs, words.is_random_security_name)
            if hit is None:
                continue
            self._report_random(call, label, hit)
            if region is not None and returned:
                producers.pop(region[2], None)
        if not producers:
            return
        for call in self.calls:
            name = call.parts[-1]
            if name not in producers:
                continue
            origin, region = producers[name]
            if region[0] <= call.index <= region[1] or call.index == region[0] - 1:
                continue
            if self._function_name_before_call(call):
                continue
            outputs, _ = self._output_names(call)
            hit = words.first_match(outputs, words.is_random_security_name)
            if hit is None:
                continue
            trace = (
                self.builder.step(
                    StepKind.SOURCE, origin.anchor.line, origin.anchor.column, "PRNG không an toàn sinh giá trị"
                ),
                self.builder.step(StepKind.CALL, call.anchor.line, call.anchor.column, "%s() trả giá trị đó về" % name),
            )
            self._report_random(call, "%s()" % name, hit, trace)

    def _function_name_before_call(self, call: _Call) -> bool:
        """Chính header của hàm ( `function makeToken(` ), không phải lời gọi."""
        if call.index == 0:
            return False
        previous = self.flat[call.index - 1]
        return previous.kind == IDENT and previous.text in ("function", "func", "def", "fn", "fun", "sub")

    def _report_random(self, call: _Call, label: str, hit: str, trace=()) -> None:
        self._report(
            "FSB-CRYPTO-007",
            call.anchor,
            label,
            "%s sinh giá trị cho %s; đầu ra của PRNG này dự đoán được sau vài mẫu quan sát" % (label, hit),
            trace=trace,
            evidence=("giá trị ngẫu nhiên đi vào tên mang nghĩa bảo mật: %s" % hit,),
        )

    # ------------------------------------------------------------------ TLS

    def _check_tls(self) -> None:
        if self.language == SHELL:
            self._check_shell_tls()
            return
        if self.language == POWERSHELL:
            for token in self.flat:
                if token.kind == IDENT and token.text.lower() == "-skipcertificatecheck":
                    self._tls(token, "-SkipCertificateCheck", "lệnh gửi request với -SkipCertificateCheck")
        flat = self.flat
        properties = _TLS_PROPERTIES.get(self.language, ())
        identifiers = _TLS_IDENTIFIERS.get(self.language, {})
        for index, token in enumerate(flat):
            self.budget.spend()
            if token.kind in (IDENT, STRING) and properties:
                name = _strip_sigil(token.text)
                for prop, bad, label in properties:
                    if name != prop:
                        continue
                    value = self._pair_value(index)
                    if value is not None and value in bad:
                        self._tls(token, prop, "%s tắt xác minh chứng chỉ máy chủ" % label)
            if token.kind == IDENT and token.text in identifiers:
                self._tls(token, token.text, identifiers[token.text])
            if token.kind == IDENT and token.text.lstrip(":") in _CALLBACK_PROPERTIES:
                if self._callback_accepts_all(index):
                    name = token.text.lstrip(":")
                    self._tls(token, name, "%s luôn trả về true nên mọi chứng chỉ đều được chấp nhận" % name)
        for call in self.calls:
            if self.language == PHP and call.parts[-1] == "curl_setopt" and len(call.arguments) == 3:
                option = [t.text for t in call.argument(1) if t.kind == IDENT]
                value = [t.text.lower() for t in call.argument(2) if t.kind in (IDENT, NUMBER)]
                if option and option[-1] in ("CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST"):
                    if value in (["false"], ["0"]):
                        self._tls(call.anchor, option[-1], "curl được đặt %s = %s" % (option[-1], value[0]))
            for name in _TLS_TRUE_CALLS.get(self.language, ()):
                if call.parts[-1] == name:
                    value = [t.text for t in call.argument(0)]
                    if value == ["true"]:
                        self._tls(call.anchor, name, "%s(true) tắt xác minh chứng chỉ" % name)
        if self.language == JAVA:
            self._check_java_trust_managers()

    def _pair_value(self, index: int) -> Optional[str]:
        flat = self.flat
        cursor = index + 1
        # process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        if cursor < len(flat) and flat[cursor].text == "]":
            cursor += 1
        if cursor + 1 >= len(flat):
            return None
        separator = flat[cursor]
        if separator.kind != OP or separator.text not in (":", "=", "=>", ","):
            return None
        value = flat[cursor + 1]
        if value.kind == STRING:
            return "'%s'" % value.text
        if value.kind == OP and value.text == ":" and cursor + 2 < len(flat):
            return ":" + flat[cursor + 2].text  # Ruby symbol
        if value.kind == IDENT and cursor + 3 < len(flat) and flat[cursor + 2].text in _SEPARATORS:
            # OpenSSL::SSL::VERIFY_NONE
            parts, _ = self._chain(cursor + 1)
            return parts[-1] if parts else value.text
        return value.text

    def _callback_accepts_all(self, index: int) -> bool:
        """`= (a, b, c, d) => true`, `+= delegate { return true; }`, `{ _, _ -> true }`

        Chỉ đọc tới hết câu lệnh chứa thuộc tính đó, để một lambda `-> true` ở
        câu sau không bị gán nhầm cho bộ xác minh.
        """
        window: List[str] = []
        depth = 0
        for token in self.flat[index + 1 : index + 40]:
            if token.kind == OP:
                if token.text in "([{":
                    depth += 1
                elif token.text in ")]}":
                    depth -= 1
                    if depth < 0:
                        break
                elif token.text == ";" and depth == 0:
                    break
            window.append(token.text)
        text = " ".join(window)
        for marker in (") => true", ") -> true", "_ -> true", "{ return true ;", "{ $true }", "=> true"):
            if marker in text:
                return True
        return False

    def _check_java_trust_managers(self) -> None:
        """checkServerTrusted(...) { } rỗng, hoặc verify(...) { return true; }"""
        flat = self.flat
        for index, token in enumerate(flat):
            if token.kind != IDENT or token.text not in ("checkServerTrusted", "verify"):
                continue
            if index + 1 >= len(flat) or flat[index + 1].text != "(":
                continue
            close = self.matching.get(index + 1)
            if close is None:
                continue
            cursor = close + 1
            # throws CertificateException
            while cursor < len(flat) and flat[cursor].kind == IDENT or (
                cursor < len(flat) and flat[cursor].text in (",", ".")
            ):
                cursor += 1
            if cursor >= len(flat) or flat[cursor].text != "{":
                continue
            end = self.matching.get(cursor)
            if end is None:
                continue
            body = [t.text for t in flat[cursor + 1 : end]]
            parameters = [t.text for t in flat[index + 2 : close]]
            if token.text == "checkServerTrusted" and (body == [] or body == ["return", ";"]):
                self._tls(token, token.text, "TrustManager có checkServerTrusted() rỗng, tin mọi chứng chỉ")
            elif token.text == "verify" and "SSLSession" in parameters and body == ["return", "true", ";"]:
                self._tls(token, token.text, "HostnameVerifier.verify() luôn trả về true")

    def _check_shell_tls(self) -> None:
        lines: Dict[int, List[Token]] = {}
        for token in self.flat:
            lines.setdefault(token.line, []).append(token)
        for line_tokens in lines.values():
            texts = _shell_words(line_tokens)
            if not texts:
                continue
            for position, text in enumerate(texts):
                command = text.rsplit("/", 1)[-1]
                rest = texts[position + 1 :]
                if command == "curl" and any(
                    arg in ("-k", "--insecure") or (arg.startswith("-") and not arg.startswith("--") and "k" in arg[1:] and arg[1:].isalpha() and len(arg) <= 6)
                    for arg in rest
                ):
                    self._tls(line_tokens[0], "curl", "curl chạy với -k / --insecure, chấp nhận mọi chứng chỉ")
                elif command == "wget" and "--no-check-certificate" in rest:
                    self._tls(line_tokens[0], "wget", "wget chạy với --no-check-certificate")
                elif command == "git" and any(arg.lower() in ("http.sslverify=false",) for arg in rest):
                    self._tls(line_tokens[0], "git", "git chạy với http.sslVerify=false")
                elif command == "git" and "config" in rest and any(a.lower() == "http.sslverify" for a in rest) and "false" in rest:
                    self._tls(line_tokens[0], "git", "git được cấu hình http.sslVerify false")
                elif command in ("npm", "yarn") and "strict-ssl" in rest and "false" in rest:
                    self._tls(line_tokens[0], command, "%s được cấu hình strict-ssl false" % command)

    def _tls(self, token: Token, symbol: str, message: str) -> None:
        # `verify_mode = OpenSSL::SSL::VERIFY_NONE` khớp hai mẫu cùng lúc;
        # một dòng tắt xác minh chỉ là một phát hiện.
        if token.line in self.tls_lines:
            return
        self.tls_lines.add(token.line)
        index = self.position.get(id(token), 0)
        guard = next((name for name in config_tokens.guard_names(self, index) if words.names_a_guard(name)), None)
        if guard is not None:
            self._report(
                "FSB-TLS-001",
                token,
                symbol,
                message,
                confidence=Confidence.LOW,
                evidence=(
                    "chỉ chạy khi điều kiện %s đúng: có vẻ là tuỳ chọn người dùng tự bật hoặc kết nối nội bộ"
                    % guard,
                ),
            )
            return
        region = self._function_at(index)
        if region is not None and words.names_an_option(region[2]):
            # Thư viện cài đặt chính tuỳ chọn tắt xác minh cho người gọi.
            self._report(
                "FSB-TLS-001",
                token,
                symbol,
                message,
                confidence=Confidence.LOW,
                evidence=(
                    "nằm trong hàm %s(), có vẻ là nơi cài đặt tuỳ chọn mà người gọi tự bật; "
                    "lỗ hổng thật nằm ở nơi bật nó" % region[2],
                ),
            )
            return
        self._report("FSB-TLS-001", token, symbol, message)

    # -------------------------------------------------------------- secrets

    def _check_secrets(self) -> None:
        flat = self.flat
        interpolated = self._interpolated_ids()
        fixture = words.is_fixture_path(self.unit.relative_path)
        for index, token in enumerate(flat):
            self.budget.spend()
            if token.kind != STRING or id(token) in interpolated:
                continue
            fmt = words.known_token_format(token.text)
            if fmt is not None and not (fixture and fmt == words.URL_CREDENTIALS):
                self._report_secret(token, "", fmt)
                continue
            if fixture:
                continue  # mật khẩu mẫu trong test không phải bí mật bị lộ
            holder = self._holder_of(index)
            if holder is None:
                continue
            minimum = 6 if words.is_password_name(holder) else 8
            if not words.plausible_secret_value(token.text, minimum):
                continue
            if _looks_like_field_name(token.text, holder):
                continue
            self._report_secret(token, holder, None)

    def _holder_of(self, index: int) -> Optional[str]:
        """Tên mà hằng chuỗi này được gán cho, nếu chuỗi là TOÀN BỘ giá trị."""
        flat = self.flat
        after = index + 1
        # "x".getBytes(), "x".as_bytes(), "x".to_string()
        while (
            after + 1 < len(flat)
            and flat[after].text in _SEPARATORS
            and _strip_sigil(flat[after + 1].text) in _LITERAL_HELPERS | {"to_string"}
        ):
            after += 2
            if after < len(flat) and flat[after].text == "(":
                after = self.matching.get(after, after) + 1
        following = flat[after] if after < len(flat) else None
        if following is not None:
            if following.kind == OP and following.text not in (";", ",", ")", "}", "]"):
                return None
            if following.kind in (IDENT, STRING, NUMBER) and following.line == flat[index].line:
                return None
        if index < 2:
            return None
        # []byte("x"), Encoding.UTF8.GetBytes("x"), b"x": lùi qua lớp bọc hằng.
        start = index
        steps = 0
        while start >= 2 and steps < 10:
            previous = flat[start - 1]
            if previous.kind == IDENT and _strip_sigil(previous.text) in _LITERAL_HELPERS:
                start -= 1
            elif previous.kind == OP and previous.text in ("(", "[", "]", ".", "::"):
                start -= 1
            else:
                break
            steps += 1
        if start != index:
            opening = start
            if flat[opening].kind == OP and flat[opening].text == "(":
                return None  # chỉ là đối số của một lời gọi khác
            index = start
        operator = flat[index - 1]
        # define('DB_PASSWORD', 'x')
        if operator.text == "," and flat[index - 2].kind == STRING and index >= 4:
            if flat[index - 3].text == "(" and flat[index - 4].text == "define":
                name = flat[index - 2].text
                return name if words.is_secret_holder_name(name) else None
        # password == "x", "x".equals(password) không đi qua đây; chỉ so bằng ==
        if operator.kind == OP and operator.text in ("==", "===", "!=", "!=="):
            if any(t.text == "typeof" for t in flat[max(0, index - 5) : index]):
                return None  # typeof x === 'function'
            name = _strip_sigil(flat[index - 2].text)
            return name if (flat[index - 2].kind == IDENT and words.is_secret_holder_name(name)) else None
        if operator.kind != OP or operator.text not in _ASSIGN | _PAIR:
            return None
        target = flat[index - 2]
        if target.kind == OP and target.text == "]" and index >= 4:
            target = flat[index - 3]  # $config['password'] = 'x'
        if target.kind not in (IDENT, STRING):
            return None
        if operator.text == ":" and target.kind == IDENT and index >= 3:
            # Toán tử ba ngôi `a ? b : "x"` và nhãn case không phải cặp khoá.
            before = flat[index - 3]
            if before.kind == OP and before.text in ("?",):
                return None
            if before.kind == IDENT and before.text == "case":
                return None
        name = _strip_sigil(target.text)
        if target.kind == IDENT and name.startswith(":"):
            name = name[1:]
        return name if words.is_secret_holder_name(name) else None

    def _report_secret(self, token: Token, holder: str, fmt: Optional[str]) -> None:
        if token.line in self.consumed_lines and not fmt:
            return
        strong = fmt is not None or words.strong_secret_value(token.text)
        self._mask_tokens([token])
        self._report(
            "FSB-SECRET-001",
            token,
            holder or (fmt or "secret"),
            "%s ( %s ) được viết thẳng vào mã nguồn" % (fmt or "giá trị bí mật", holder or "hằng chuỗi"),
            confidence=Confidence.HIGH if strong else None,
            evidence=(
                ("khớp định dạng %s" % fmt) if fmt else "tên %s mang nghĩa bí mật" % holder,
                "giá trị dài %d ký tự, không phải chuỗi mẫu hay tên biến môi trường" % len(token.text),
            ),
        )


_IDENTIFIER_LIKE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,48}$")


def _strip_sigil(text: str) -> str:
    return text.lstrip("$@%&")


def _literal_end(text: str, start: int) -> int:
    """Cột ngay sau dấu nháy đóng của chuỗi bắt đầu ở `start` ( hoặc cuối dòng )."""
    if start >= len(text):
        return len(text)
    quote = text[start]
    if quote not in "'\"`":
        return len(text)
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    return len(text)


def _shell_words(tokens: Sequence[Token]) -> List[str]:
    """Ghép lại các token dính liền nhau thành từ của shell: `http.sslVerify=false`."""
    result: List[str] = []
    end = -1
    for token in tokens:
        if token.kind == STRING:
            result.append(token.text)
            end = -1
            continue
        if result and token.column == end:
            result[-1] += token.text
        else:
            result.append(token.text)
        end = token.column + len(token.text)
    return result


def _zero_allocation(tokens: Sequence[Token]) -> bool:
    """Cấp phát một mảng mới mà không đổ dữ liệu vào: luôn toàn số 0.

    `make([]byte, aes.BlockSize)` toàn số 0 bất kể độ dài lấy từ đâu, nên
    không thể đòi mọi tên trong biểu thức đều là hằng như với chuỗi.
    """
    texts = [token.text for token in tokens]
    if texts[:5] == ["make", "(", "[", "]", "byte"]:
        return True
    if texts[:3] == ["new", "byte", "["] and "{" not in texts:
        return True
    if texts[:3] == ["Buffer", ".", "alloc"] and texts.count(",") == 0:
        return True
    if texts[:3] == ["new", "Uint8Array", "("] and len(tokens) <= 8:
        return all(t.kind != STRING for t in tokens)
    return False


def _empty_or_public(tokens: Sequence[Token]) -> bool:
    strings = [token.text for token in tokens if token.kind == STRING]
    if not strings:
        return False
    if all(not text for text in strings):
        return True
    return any("PUBLIC KEY" in text or text.startswith(("ssh-rsa", "ssh-ed25519")) for text in strings)


def _looks_like_field_name(value: str, holder: str) -> bool:
    """`PASSWORD_PARAM = "user_password"` -- tên một trường, không phải mật khẩu."""
    return words.looks_like_field_name(value, holder)


def scan_tokens(unit: AnalysisUnit, budget: Budget, builder: FindingBuilder) -> None:
    spec = spec_for(unit.language)
    if spec is None:
        return
    tokens = tokenize(unit.source, spec.lexer, budget)
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
    _Scan(unit, budget, builder, tokens).run()


__all__ = ["scan_tokens"]
