"""Rule mật mã, TLS và secret: mẫu bắn, mẫu im lặng, và từng kiểu báo nhầm đã gặp.

Mỗi mẫu âm tính ở đây là một đoạn mã an toàn có HÌNH DẠNG giống lỗ hổng. Phần
lớn được rút ra từ chính những lần chạy công cụ trên mã nguồn thật ( Django,
requests, httpx, paramiko, Laravel, axios, node-jsonwebtoken, WebGoat... ):
một rule kêu ở đó là kêu trên mã của mọi người.
"""

from __future__ import annotations

from typing import List, Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Confidence
from fortress_scan.languages import (
    CSHARP,
    GO,
    JAVA,
    JAVASCRIPT,
    LUA,
    PERL,
    PHP,
    POWERSHELL,
    PYTHON,
    RUBY,
    RUST,
    SHELL,
    TYPESCRIPT,
)


def findings(language: str, source: str, path: str = "app/service"):
    return scan_source(source, language, path, Config())


def rule_ids(language: str, source: str, path: str = "app/service") -> List[str]:
    return [f.rule_id for f in findings(language, source, path)]


Case = Tuple[str, str, str]

# Token mẫu ghép lúc chạy: để nguyên văn trong tệp thì bộ quét secret của
# GitHub ( và của người dùng ) sẽ chặn hoặc báo chính bộ kiểm thử này.
AWS_KEY = "AKIA" + "Z3MSJVQ5LXR7T2PB"
GITHUB_TOKEN = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
SLACK_TOKEN = "xox" + "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"

FIRES: List[Case] = [
    # ---- CRYPTO-001: MD5 / SHA-1 dựng chữ ký
    ("FSB-CRYPTO-001", PYTHON, "import hashlib\ndef sig(secret, body):\n    return hashlib.md5(secret + body).hexdigest()\n"),
    ("FSB-CRYPTO-001", PYTHON, "import hashlib\nsignature = hashlib.sha1(payload).hexdigest()\n"),
    ("FSB-CRYPTO-001", JAVASCRIPT, "const signature = crypto.createHash('sha1').update(apiSecret + body).digest('hex');\n"),
    ("FSB-CRYPTO-001", PHP, "<?php\n$sig = md5($secret . $payload);\n"),
    # ---- CRYPTO-002: mật khẩu băm nhanh
    ("FSB-CRYPTO-002", PYTHON, "import hashlib\ndef store(password):\n    return hashlib.md5(password.encode()).hexdigest()\n"),
    ("FSB-CRYPTO-002", PYTHON, "from hashlib import sha256 as h\ndef store(pw_user, password):\n    return h(password.encode()).hexdigest()\n"),
    ("FSB-CRYPTO-002", PYTHON, "import hashlib\ndef store(password):\n    d = hashlib.sha1()\n    d.update(password)\n    return d.hexdigest()\n"),
    ("FSB-CRYPTO-002", PYTHON, "import hashlib\ndef check(user, raw):\n    return hashlib.md5(raw).hexdigest() == user.password\n"),
    ("FSB-CRYPTO-002", JAVASCRIPT, "function hashPassword(password) {\n  return crypto.createHash('md5').update(password).digest('hex');\n}\n"),
    ("FSB-CRYPTO-002", TYPESCRIPT, "const hashed: string = crypto.createHash('sha256').update(password).digest('hex');\n"),
    ("FSB-CRYPTO-002", JAVA, "class A { String h(String password) throws Exception {\n  MessageDigest md = MessageDigest.getInstance(\"MD5\");\n  md.update(password.getBytes());\n  return new String(md.digest());\n} }\n"),
    ("FSB-CRYPTO-002", JAVA, "class A { String h(String password) { return DigestUtils.sha256Hex(password); } }\n"),
    ("FSB-CRYPTO-002", GO, "func Hash(password string) [16]byte {\n\treturn md5.Sum([]byte(password))\n}\n"),
    ("FSB-CRYPTO-002", CSHARP, "class A { string H(string password) { using (var md5 = MD5.Create()) { return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password))); } } }\n"),
    ("FSB-CRYPTO-002", PHP, "<?php\n$hash = md5($password);\n"),
    ("FSB-CRYPTO-002", PHP, "<?php\n$hash = hash('sha256', $_POST['password']);\n"),
    ("FSB-CRYPTO-002", RUBY, "def hash_password(password)\n  Digest::MD5.hexdigest(password)\nend\n"),
    ("FSB-CRYPTO-002", RUBY, "def hash_password(password)\n  Digest::SHA256.hexdigest password\nend\n"),
    ("FSB-CRYPTO-002", RUST, "fn h(password: &str) -> String { format!(\"{:x}\", md5::compute(password)) }\n"),
    ("FSB-CRYPTO-002", PERL, "my $h = md5_hex($password);\n"),
    # ---- CRYPTO-003: thuật toán mã hoá bị phá
    ("FSB-CRYPTO-003", PYTHON, "from Crypto.Cipher import DES\nc = DES.new(key, DES.MODE_CBC, iv)\n"),
    ("FSB-CRYPTO-003", PYTHON, "from cryptography.hazmat.primitives.ciphers import algorithms\na = algorithms.TripleDES(key)\n"),
    ("FSB-CRYPTO-003", JAVASCRIPT, "const c = crypto.createCipheriv('des-ede3-cbc', key, iv);\n"),
    ("FSB-CRYPTO-003", JAVASCRIPT, "const c = crypto.createCipheriv('rc4', key, '');\n"),
    ("FSB-CRYPTO-003", JAVA, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"DESede/CBC/PKCS5Padding\"); } }\n"),
    ("FSB-CRYPTO-003", JAVA, "class A { void f() throws Exception { SecretKeyFactory f = SecretKeyFactory.getInstance(\"PBEWithMD5AndDES\"); } }\n"),
    ("FSB-CRYPTO-003", GO, "func f(k []byte) { b, _ := des.NewCipher(k); _ = b }\n"),
    ("FSB-CRYPTO-003", CSHARP, "class A { void F() { var d = TripleDES.Create(); } }\n"),
    ("FSB-CRYPTO-003", PHP, "<?php\n$c = openssl_encrypt($d, 'bf-cbc', $k, 0, $iv);\n"),
    ("FSB-CRYPTO-003", RUBY, "c = OpenSSL::Cipher.new('des-cbc')\n"),
    # ---- CRYPTO-004: ECB
    ("FSB-CRYPTO-004", PYTHON, "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_ECB)\n"),
    ("FSB-CRYPTO-004", PYTHON, "from cryptography.hazmat.primitives.ciphers import modes\nm = modes.ECB()\n"),
    ("FSB-CRYPTO-004", JAVA, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES\"); } }\n"),
    ("FSB-CRYPTO-004", JAVA, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\"); } }\n"),
    ("FSB-CRYPTO-004", JAVASCRIPT, "const c = crypto.createCipheriv('aes-256-ecb', key, null);\n"),
    ("FSB-CRYPTO-004", CSHARP, "class A { void F(Aes aes) { aes.Mode = CipherMode.ECB; } }\n"),
    ("FSB-CRYPTO-004", PHP, "<?php\n$e = openssl_encrypt($p, 'aes-128-ecb', $key);\n"),
    # ---- CRYPTO-005: IV / nonce / muối cố định
    ("FSB-CRYPTO-005", PYTHON, "from Crypto.Cipher import AES\nIV = b'\\x00' * 16\ndef e(k, d):\n    return AES.new(k, AES.MODE_CBC, IV).encrypt(d)\n"),
    ("FSB-CRYPTO-005", PYTHON, "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\ndef e(k, d):\n    g = AESGCM(k)\n    return g.encrypt(b'nonce-12byte', d, None)\n"),
    ("FSB-CRYPTO-005", PYTHON, "from cryptography.hazmat.primitives.ciphers import modes\nm = modes.CBC(bytes(16))\n"),
    ("FSB-CRYPTO-005", PYTHON, "import hashlib\ndk = hashlib.pbkdf2_hmac('sha256', pw, b'static-salt', 600000)\n"),
    ("FSB-CRYPTO-005", JAVASCRIPT, "const IV = Buffer.alloc(16);\nconst c = crypto.createCipheriv('aes-256-cbc', key, IV);\n"),
    ("FSB-CRYPTO-005", JAVASCRIPT, "const c = crypto.createCipheriv('aes-256-gcm', key, 'fixednonce12');\n"),
    ("FSB-CRYPTO-005", JAVASCRIPT, "const c = crypto.createCipher('aes-256-cbc', password);\n"),
    ("FSB-CRYPTO-005", JAVA, "class A { static final byte[] IV = new byte[16];\n void f() { IvParameterSpec s = new IvParameterSpec(IV); } }\n"),
    ("FSB-CRYPTO-005", JAVA, "class A { void f() { GCMParameterSpec s = new GCMParameterSpec(128, \"0123456789ab\".getBytes()); } }\n"),
    ("FSB-CRYPTO-005", GO, "func e(b cipher.Block) {\n\tiv := make([]byte, aes.BlockSize)\n\tm := cipher.NewCBCEncrypter(b, iv)\n\t_ = m\n}\n"),
    ("FSB-CRYPTO-005", CSHARP, "class A { void F(Aes aes) { aes.IV = new byte[16]; } }\n"),
    ("FSB-CRYPTO-005", PHP, "<?php\n$e = openssl_encrypt($p, 'aes-256-cbc', $k, 0, '1234567890123456');\n"),
    ("FSB-CRYPTO-005", RUBY, "c.iv = \"\\0\" * 16\n"),
    ("FSB-CRYPTO-005", RUST, "let nonce = Nonce::from_slice(b\"unique nonce\");\n"),
    # ---- CRYPTO-006: khoá viết cứng
    ("FSB-CRYPTO-006", PYTHON, "import jwt\ntok = jwt.encode({'a': 1}, 'my-jwt-secret', algorithm='HS256')\n"),
    ("FSB-CRYPTO-006", PYTHON, "import hmac, hashlib\nKEY = b'0123456789abcdef'\nmac = hmac.new(KEY, msg, hashlib.sha256)\n"),
    ("FSB-CRYPTO-006", PYTHON, "from cryptography.fernet import Fernet\nf = Fernet(b'Zm9vYmFyYmF6cXV4cXV1eGZvb2JhcmJhenF1eHF1dXg=')\n"),
    ("FSB-CRYPTO-006", JAVASCRIPT, "const t = jwt.sign({ sub: 1 }, 'jwt-signing-secret');\n"),
    ("FSB-CRYPTO-006", JAVASCRIPT, "const h = crypto.createHmac('sha256', 'webhook-secret').update(b).digest('hex');\n"),
    ("FSB-CRYPTO-006", JAVA, "class A { void f() { SecretKeySpec k = new SecretKeySpec(\"0123456789abcdef\".getBytes(), \"AES\"); } }\n"),
    ("FSB-CRYPTO-006", JAVA, "class A { static final String S = \"x\";\n String t() { return Jwts.builder().signWith(SignatureAlgorithm.HS256, S).compact(); } }\n"),
    ("FSB-CRYPTO-006", GO, "func f() { b, _ := aes.NewCipher([]byte(\"0123456789abcdef\")); _ = b }\n"),
    ("FSB-CRYPTO-006", GO, "func f(s string) { jwt.Parse(s, func(t *jwt.Token) (interface{}, error) { return []byte(\"k3y\"), nil }) }\n"),
    ("FSB-CRYPTO-006", CSHARP, "class A { void F() { var k = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(\"a-long-signing-secret\")); } }\n"),
    ("FSB-CRYPTO-006", PHP, "<?php\n$s = hash_hmac('sha256', $data, 'webhook-secret-xyz');\n"),
    ("FSB-CRYPTO-006", RUBY, "JWT.encode(payload, 'my_jwt_secret_123', 'HS256')\n"),
    ("FSB-CRYPTO-006", RUST, "let k = EncodingKey::from_secret(b\"jwt-secret-for-prod\");\n"),
    # ---- CRYPTO-007: PRNG đoán được
    ("FSB-CRYPTO-007", PYTHON, "import random\ntoken = ''.join(random.choice('abc') for _ in range(32))\n"),
    ("FSB-CRYPTO-007", PYTHON, "import random\ndef make_otp():\n    return random.randint(100000, 999999)\n"),
    ("FSB-CRYPTO-007", PYTHON, "import random\ndef rnd(n):\n    return ''.join(random.choice('ab') for _ in range(n))\ndef reset(user):\n    user.reset_token = rnd(32)\n"),
    ("FSB-CRYPTO-007", JAVASCRIPT, "const sessionId = Math.random().toString(36).slice(2);\n"),
    ("FSB-CRYPTO-007", JAVASCRIPT, "function makeResetToken() { return Math.random().toString(36); }\n"),
    ("FSB-CRYPTO-007", JAVA, "class A { String newToken() { Random rnd = new Random();\n return Long.toHexString(rnd.nextLong()); } }\n"),
    ("FSB-CRYPTO-007", JAVA, "class A { void f() { String sessionToken = RandomStringUtils.randomAlphanumeric(32); } }\n"),
    ("FSB-CRYPTO-007", GO, "import \"math/rand\"\nfunc NewSessionToken() string {\n\tb := make([]byte, 16)\n\tfor i := range b { b[i] = letters[rand.Intn(len(letters))] }\n\treturn string(b)\n}\n"),
    ("FSB-CRYPTO-007", CSHARP, "class A { void F() { var rng = new Random();\n string resetToken = rng.Next().ToString(); } }\n"),
    ("FSB-CRYPTO-007", PHP, "<?php\n$otp = rand(100000, 999999);\n"),
    ("FSB-CRYPTO-007", PHP, "<?php\n$_SESSION['csrf_token'] = md5(uniqid());\n"),
    ("FSB-CRYPTO-007", RUBY, "def reset_token\n  (0...32).map { ('a'..'z').to_a.sample }.join\nend\n"),
    ("FSB-CRYPTO-007", LUA, "local token = tostring(math.random(100000, 999999))\n"),
    ("FSB-CRYPTO-007", PERL, "my $token = int(rand(1000000));\n"),
    # ---- CRYPTO-008: khoá ngắn
    ("FSB-CRYPTO-008", PYTHON, "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"),
    ("FSB-CRYPTO-008", PYTHON, "from Crypto.PublicKey import RSA\nk = RSA.generate(1024)\n"),
    ("FSB-CRYPTO-008", GO, "func f() { k, _ := rsa.GenerateKey(rand.Reader, 1024); _ = k }\n"),
    ("FSB-CRYPTO-008", JAVA, "class A { void f() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance(\"RSA\");\n g.initialize(1024); } }\n"),
    ("FSB-CRYPTO-008", JAVASCRIPT, "const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });\n"),
    ("FSB-CRYPTO-008", CSHARP, "class A { void F() { var r = new RSACryptoServiceProvider(1024); } }\n"),
    ("FSB-CRYPTO-008", RUBY, "k = OpenSSL::PKey::RSA.new(1024)\n"),
    # ---- TLS-001
    ("FSB-TLS-001", PYTHON, "import requests\nr = requests.get('https://api.example.com', verify=False)\n"),
    ("FSB-TLS-001", PYTHON, "import requests\ns = requests.Session()\ns.verify = False\n"),
    ("FSB-TLS-001", PYTHON, "import httpx\nc = httpx.Client(verify=False)\n"),
    ("FSB-TLS-001", PYTHON, "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\n"),
    ("FSB-TLS-001", PYTHON, "import ssl\nctx = ssl._create_unverified_context()\n"),
    ("FSB-TLS-001", PYTHON, "import paramiko\nc = paramiko.SSHClient()\nc.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"),
    ("FSB-TLS-001", JAVASCRIPT, "const agent = new https.Agent({ rejectUnauthorized: false });\n"),
    ("FSB-TLS-001", JAVASCRIPT, "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"),
    ("FSB-TLS-001", GO, "func c() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }\n"),
    ("FSB-TLS-001", JAVA, "class A { TrustManager t = new X509TrustManager() {\n public void checkServerTrusted(X509Certificate[] c, String a) {}\n}; }\n"),
    ("FSB-TLS-001", JAVA, "class A { void f(HttpsURLConnection c) { c.setHostnameVerifier((h, s) -> true); } }\n"),
    ("FSB-TLS-001", JAVA, "class A { void f(HttpClientBuilder b) { b.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE); } }\n"),
    ("FSB-TLS-001", CSHARP, "class A { void F() { ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true; } }\n"),
    ("FSB-TLS-001", PHP, "<?php\ncurl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n"),
    ("FSB-TLS-001", PHP, "<?php\n$ctx = stream_context_create(['ssl' => ['verify_peer' => false]]);\n"),
    ("FSB-TLS-001", RUBY, "http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"),
    ("FSB-TLS-001", RUST, "let c = reqwest::Client::builder().danger_accept_invalid_certs(true).build();\n"),
    ("FSB-TLS-001", SHELL, "#!/bin/sh\ncurl -sSLk https://internal/api\n"),
    ("FSB-TLS-001", SHELL, "#!/bin/sh\nwget --no-check-certificate https://x/y\n"),
    ("FSB-TLS-001", SHELL, "#!/bin/sh\ngit -c http.sslVerify=false clone https://x/y\n"),
    ("FSB-TLS-001", POWERSHELL, "Invoke-RestMethod -Uri $u -SkipCertificateCheck\n"),
    ("FSB-TLS-001", PERL, "my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });\n"),
    ("FSB-TLS-001", LUA, 'local p = { mode = "client", verify = "none" }\n'),
    # ---- SECRET-001
    ("FSB-SECRET-001", PYTHON, "DB_PASSWORD = 'S3cr3t!Pass2024'\n"),
    ("FSB-SECRET-001", PYTHON, "import psycopg2\nc = psycopg2.connect(host='db', password='Pr0d-Db-P4ss')\n"),
    ("FSB-SECRET-001", PYTHON, "def login(u, password):\n    return password == 'hunter2hunter2'\n"),
    ("FSB-SECRET-001", PYTHON, "aws = '%s'\n" % AWS_KEY),
    ("FSB-SECRET-001", JAVASCRIPT, "const config = { password: 'Sup3rS3cret!' };\n"),
    ("FSB-SECRET-001", JAVASCRIPT, "const gh = '%s';\n" % GITHUB_TOKEN),
    ("FSB-SECRET-001", JAVA, "class A { private String dbPassword = \"Pr0dP@ssw0rd\"; }\n"),
    ("FSB-SECRET-001", GO, "var jwtKey = []byte(\"super-secret-signing-key\")\n"),
    ("FSB-SECRET-001", CSHARP, "class A { private const string ApiKey = \"k8f2Lq9xVb3Nw7Zt\"; }\n"),
    ("FSB-SECRET-001", PHP, "<?php\ndefine('DB_PASSWORD', 'Pr0d-Db-P4ss!');\n"),
    ("FSB-SECRET-001", RUBY, "API_KEY = \"a8f5f167f44f4964e6c998dee827110c\"\n"),
    ("FSB-SECRET-001", RUST, "const API_TOKEN: &str = \"%s\";\n" % SLACK_TOKEN),
    ("FSB-SECRET-001", SHELL, "#!/bin/sh\nexport DB_PASSWORD=\"Pr0dDbPass99\"\n"),
    ("FSB-SECRET-001", POWERSHELL, '$password = "Adm1nP@ssw0rd"\n'),
    ("FSB-SECRET-001", LUA, 'local secret_key = "lua-secret-signing-key-2"\n'),
]

SILENT: List[Case] = [
    # Băm nội dung không phải bí mật: ETag, khoá cache, checksum.
    ("FSB-CRYPTO-001", PYTHON, "import hashlib\ndef etag(body):\n    return hashlib.md5(body).hexdigest()\n"),
    ("FSB-CRYPTO-001", PYTHON, "import hashlib\ncache_key = hashlib.md5(url.encode()).hexdigest()\n"),
    ("FSB-CRYPTO-001", PYTHON, "import hashlib\ndef sig(secret, body):\n    return hashlib.md5(secret + body, usedforsecurity=False).hexdigest()\n"),
    ("FSB-CRYPTO-001", JAVASCRIPT, "function etag(body) { return crypto.createHash('md5').update(body).digest('hex'); }\n"),
    ("FSB-CRYPTO-001", GO, "func Checksum(b []byte) [16]byte { return md5.Sum(b) }\n"),
    # Hàm tự viết trùng tên không phải hashlib.
    ("FSB-CRYPTO-002", PYTHON, "def md5(x):\n    return x\ndef store(password):\n    return md5(password)\n"),
    # Băm trước rồi mới đưa vào bcrypt: bcrypt cắt mật khẩu ở 72 byte.
    ("FSB-CRYPTO-002", PYTHON, "import bcrypt, hashlib, base64\ndef h(password):\n    return bcrypt.hashpw(base64.b64encode(hashlib.sha256(password).digest()), bcrypt.gensalt())\n"),
    ("FSB-CRYPTO-002", PYTHON, "import bcrypt, hashlib\ndef h(password):\n    pre = hashlib.sha256(password).digest()\n    return bcrypt.hashpw(pre, bcrypt.gensalt())\n"),
    ("FSB-CRYPTO-002", PHP, "<?php\n$ok = password_hash($password, PASSWORD_DEFAULT);\n"),
    ("FSB-CRYPTO-002", PYTHON, "import hashlib\nPASSWORD_MIN_LENGTH = 8\nh = hashlib.sha256(password_reset_token).hexdigest()\n"),
    ("FSB-CRYPTO-002", PHP, "<?php\n$e = $obj->md5($password);\n"),
    # Chế độ an toàn.
    ("FSB-CRYPTO-004", JAVA, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\"); } }\n"),
    ("FSB-CRYPTO-004", JAVA, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\"); } }\n"),
    ("FSB-CRYPTO-003", JAVA, "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\"); } }\n"),
    # IV sinh ngẫu nhiên, kể cả khi khai báo bằng mảng 0 rồi đổ byte vào.
    ("FSB-CRYPTO-005", PYTHON, "import os\nfrom Crypto.Cipher import AES\ndef e(k, d):\n    iv = os.urandom(16)\n    return AES.new(k, AES.MODE_CBC, iv).encrypt(d)\n"),
    ("FSB-CRYPTO-005", JAVASCRIPT, "const iv = crypto.randomBytes(16);\nconst c = crypto.createCipheriv('aes-256-cbc', key, iv);\n"),
    ("FSB-CRYPTO-005", JAVASCRIPT, "const iv = Buffer.alloc(16);\ncrypto.randomFillSync(iv);\nconst c = crypto.createCipheriv('aes-256-cbc', key, iv);\n"),
    ("FSB-CRYPTO-005", JAVA, "class A { void f() { byte[] iv = new byte[12];\n new SecureRandom().nextBytes(iv);\n GCMParameterSpec s = new GCMParameterSpec(128, iv); } }\n"),
    ("FSB-CRYPTO-005", GO, "func e(g cipher.AEAD, d []byte) []byte {\n\tnonce := make([]byte, g.NonceSize())\n\tif _, err := io.ReadFull(rand.Reader, nonce); err != nil { panic(err) }\n\treturn g.Seal(nil, nonce, d, nil)\n}\n"),
    # Khoá lấy từ môi trường hoặc tham số.
    ("FSB-CRYPTO-006", PYTHON, "import os, jwt\ntok = jwt.encode({'a': 1}, os.environ['JWT_SECRET'], algorithm='HS256')\n"),
    ("FSB-CRYPTO-006", PYTHON, "import jwt\ndef v(t, key):\n    return jwt.decode(t, key, algorithms=['RS256'])\n"),
    ("FSB-CRYPTO-006", PYTHON, "import jwt\nPUB = '-----BEGIN PUBLIC KEY-----\\nMIIB...'\nc = jwt.decode(t, PUB, algorithms=['RS256'])\n"),
    ("FSB-CRYPTO-006", JAVASCRIPT, "const t = jwt.sign({ sub: 1 }, process.env.JWT_SECRET);\n"),
    ("FSB-CRYPTO-006", GO, "func f() { b, _ := aes.NewCipher([]byte(os.Getenv(\"KEY\"))); _ = b }\n"),
    ("FSB-CRYPTO-006", JAVA, "class A { void f(byte[] k) { SecretKeySpec s = new SecretKeySpec(k, \"AES\"); } }\n"),
    # PRNG cho việc không phải bảo mật.
    ("FSB-CRYPTO-007", PYTHON, "import random\ndelay = random.randint(1, 3)\n"),
    ("FSB-CRYPTO-007", PYTHON, "import random\ndef reset_password(user):\n    delay = random.randint(1, 3)\n    time.sleep(delay)\n"),
    ("FSB-CRYPTO-007", PYTHON, "import random\nrandom.shuffle(tokens)\n"),
    ("FSB-CRYPTO-007", PYTHON, "import secrets\ntoken = secrets.token_urlsafe(32)\n"),
    ("FSB-CRYPTO-007", PYTHON, "import random\ntoken = random.SystemRandom().choice('abc')\n"),
    ("FSB-CRYPTO-007", JAVASCRIPT, "const jitter = Math.random() * 100;\n"),
    ("FSB-CRYPTO-007", JAVA, "class A { void f() { int retry = new Random().nextInt(5); } }\n"),
    ("FSB-CRYPTO-007", JAVA, "class A { void f() { String token = Long.toHexString(new SecureRandom().nextLong()); } }\n"),
    ("FSB-CRYPTO-007", GO, "import \"crypto/rand\"\nfunc NewToken() string { b := make([]byte, 16); rand.Read(b); return hex.EncodeToString(b) }\n"),
    ("FSB-CRYPTO-007", GO, "import \"math/rand\"\nfunc jitter() int { return rand.Intn(100) }\n"),
    ("FSB-CRYPTO-007", PHP, "<?php\n$resetTag = str_replace('.', '', uniqid('', true));\n"),
    ("FSB-CRYPTO-007", PHP, "<?php\n$token = bin2hex(random_bytes(16));\n"),
    # Bốc token của mô hình ngôn ngữ từ bộ từ vựng: "token" ở đây không phải secret.
    ("FSB-CRYPTO-007", PYTHON, "import random\nnext_token = random.choice(vocab)\n"),
    ("FSB-CRYPTO-007", PYTHON, "import random\ndef next_token(tokenizer):\n    return random.choice(tokenizer.vocab)\n"),
    ("FSB-CRYPTO-007", PYTHON, "import random\ntoken_id = random.randint(0, vocab_size - 1)\n"),
    (
        "FSB-CRYPTO-007",
        JAVA,
        "class A { String f(List<String> vocab) { Random r = new Random(); return vocab.get(r.nextInt(vocab.size())); } "
        "String token(List<String> v) { return f(v); } }\n",
    ),
    # Khoá đủ dài.
    ("FSB-CRYPTO-008", PYTHON, "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"),
    ("FSB-CRYPTO-008", GO, "func f() { k, _ := rsa.GenerateKey(rand.Reader, 4096); _ = k }\n"),
    # Xác minh bật, hoặc trỏ tới CA riêng.
    ("FSB-TLS-001", PYTHON, "import requests\nr = requests.get('https://x', verify='/etc/ca.pem')\n"),
    ("FSB-TLS-001", PYTHON, "import requests\nr = requests.get('https://x', verify=True)\n"),
    ("FSB-TLS-001", PYTHON, "import jwt\nc = jwt.decode(t, k, algorithms=['HS256'], verify=False)\n"),
    ("FSB-TLS-001", JAVASCRIPT, "const agent = new https.Agent({ rejectUnauthorized: true, ca });\n"),
    ("FSB-TLS-001", GO, "func c() *tls.Config { return &tls.Config{InsecureSkipVerify: false} }\n"),
    ("FSB-TLS-001", SHELL, "#!/bin/sh\ncurl -fsSL https://example.com/install.sh\n"),
    ("FSB-TLS-001", JAVA, "class A { void f(List<String> l) { setHostnameVerifier(v); l.removeIf((a) -> true); } }\n"),
    # Secret: nhãn, tên trường, tên biến môi trường, mẫu, enum, khoá phiên.
    ("FSB-SECRET-001", PYTHON, "PASSWORD_FIELD = 'password'\nAPI_TOKEN_HEADER = 'x-api-token'\n"),
    ("FSB-SECRET-001", PYTHON, "DB_PASSWORD = os.environ.get('DB_PASSWORD')\npassword_env = 'DB_PASSWORD'\n"),
    ("FSB-SECRET-001", PYTHON, "password = 'changeme'\napi_key = '<your-api-key>'\nsecret = '${SECRET}'\n"),
    ("FSB-SECRET-001", PYTHON, "from enum import Enum\nclass Category(str, Enum):\n    SECRET = 'hardcoded-secret'\n"),
    ("FSB-SECRET-001", PYTHON, "SESSION_KEY = '_auth_user_id'\nCSRF_SESSION_KEY = '_csrftoken'\n"),
    ("FSB-SECRET-001", PYTHON, "SECRET_KEY_INSECURE_PREFIX = 'django-insecure-'\n"),
    ("FSB-SECRET-001", PYTHON, "prompt = {'password': 'Enter your password'}\n"),
    ("FSB-SECRET-001", PYTHON, "aws = 'AKIAIOSFODNN7EXAMPLE'\n"),
    ("FSB-SECRET-001", PYTHON, "pem = text.replace('-----BEGIN PRIVATE KEY-----', '')\n"),
    ("FSB-SECRET-001", JAVASCRIPT, "if (typeof secretOrPublicKey === 'function') { f(); }\n"),
    ("FSB-SECRET-001", JAVASCRIPT, "const rules = [{ token: 'keyword.control', regex: 'if' }];\n"),
    ("FSB-SECRET-001", JAVASCRIPT, "const opts = { withCredentials: 'same-origin' };\n"),
    ("FSB-SECRET-001", JAVASCRIPT, "const password = process.env.DB_PASSWORD;\n"),
    ("FSB-SECRET-001", JAVA, "class A { String passwordParam = \"user_password\"; }\n"),
]


@pytest.mark.parametrize("rule_id,language,source", FIRES)
def test_rule_fires(rule_id: str, language: str, source: str):
    found = rule_ids(language, source)
    assert rule_id in found, "%s phai ban tren mau %s; nhan duoc %s" % (rule_id, language, found)


@pytest.mark.parametrize("rule_id,language,source", SILENT)
def test_rule_stays_silent(rule_id: str, language: str, source: str):
    found = rule_ids(language, source)
    assert rule_id not in found, "%s bao nham tren ma an toan (%s); nhan duoc %s" % (
        rule_id,
        language,
        found,
    )


def test_every_new_rule_has_positive_and_negative_cases():
    fired = {case[0] for case in FIRES}
    silent = {case[0] for case in SILENT}
    for rule in (
        "FSB-CRYPTO-001",
        "FSB-CRYPTO-002",
        "FSB-CRYPTO-004",
        "FSB-CRYPTO-005",
        "FSB-CRYPTO-006",
        "FSB-CRYPTO-007",
        "FSB-CRYPTO-008",
        "FSB-TLS-001",
        "FSB-SECRET-001",
    ):
        assert rule in fired and rule in silent, rule


def test_secret_values_never_reach_the_report():
    """Báo cáo đi vào CI log và SARIF; in bí mật ra đó là lộ lần thứ hai."""
    cases = [
        (PYTHON, "ADMIN_PASSWORD_LINK = '375afe1104f4a487a73823c50a9292a2'\n", "375afe11"),
        (JAVA, "class A { static final String secretValue = \"secr37Value\"; }\n", "secr37"),
        (JAVASCRIPT, "const h = crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwm').update(d);\n", "pa4qacea"),
        (PYTHON, "import jwt\nK = 'binding-line-secret'\nt = jwt.encode({}, K)\n", "binding-line"),
    ]
    for language, source, fragment in cases:
        result = findings(language, source)
        assert result, (language, source)
        for finding in result:
            assert fragment not in finding.snippet, finding.snippet
            for step in finding.trace:
                assert fragment not in step.code, step.code
            assert fragment not in finding.message


def test_test_fixtures_do_not_report_sample_passwords():
    """Mật khẩu mẫu trong test là dữ liệu kiểm thử, không phải bí mật bị lộ."""
    source = "def test_login(client):\n    client.login(username='u', password='pygmalion42')\n"
    assert "FSB-SECRET-001" not in rule_ids(PYTHON, source, "tests/test_login.py")
    assert "FSB-SECRET-001" in rule_ids(PYTHON, source, "app/login.py")
    js = "jwt.sign({ a: 1 }, 'secret-for-tests');\n"
    assert "FSB-CRYPTO-006" not in rule_ids(JAVASCRIPT, js, "test/sign.test.js")


def test_provider_tokens_are_reported_even_in_tests():
    """Một token GitHub thật trong thư mục test vẫn là token thật bị lộ."""
    source = "TOKEN = '%s'\n" % GITHUB_TOKEN
    assert "FSB-SECRET-001" in rule_ids(PYTHON, source, "tests/conftest.py")


def test_library_implementing_the_insecure_option_is_low_confidence():
    """httpx, Laravel: mã cài đặt chính tuỳ chọn verify=False cho người gọi."""
    source = (
        "import ssl\n"
        "def create_ssl_context(verify=True):\n"
        "    ctx = ssl.create_default_context()\n"
        "    if not verify:\n"
        "        ctx.verify_mode = ssl.CERT_NONE\n"
        "    return ctx\n"
    )
    result = [f for f in findings(PYTHON, source) if f.rule_id == "FSB-TLS-001"]
    assert result and all(f.confidence == Confidence.LOW for f in result)
    php = "<?php\nclass R { public function withoutVerifying() { $this->options['verify'] = false; } }\n"
    result = [f for f in findings(PHP, php) if f.rule_id == "FSB-TLS-001"]
    assert result and all(f.confidence == Confidence.LOW for f in result)


def test_one_tls_finding_per_ssl_context():
    source = (
        "import ssl\n"
        "def make():\n"
        "    ctx = ssl.create_default_context()\n"
        "    ctx.check_hostname = False\n"
        "    ctx.verify_mode = ssl.CERT_NONE\n"
        "    return ctx\n"
    )
    assert rule_ids(PYTHON, source).count("FSB-TLS-001") == 1


def test_nonce_reuse_is_rated_higher_than_static_cbc_iv():
    gcm = "const c = crypto.createCipheriv('aes-256-gcm', key, 'fixednonce12');\n"
    cbc = "const c = crypto.createCipheriv('aes-256-cbc', key, 'fixed-iv-16bytes');\n"
    high = [f for f in findings(JAVASCRIPT, gcm) if f.rule_id == "FSB-CRYPTO-005"]
    medium = [f for f in findings(JAVASCRIPT, cbc) if f.rule_id == "FSB-CRYPTO-005"]
    assert high and medium
    assert high[0].severity > medium[0].severity


def test_strings_and_comments_are_never_code():
    """Tên API trong chú thích hay trong chuỗi không phải lời gọi."""
    source = (
        "// crypto.createHash('md5').update(password)\n"
        "const doc = \"rejectUnauthorized: false disables TLS\";\n"
    )
    assert rule_ids(JAVASCRIPT, source) == []
