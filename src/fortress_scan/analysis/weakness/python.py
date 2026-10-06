"""Điểm yếu mật mã, TLS và secret trong mã Python, đọc trên AST.

Khác phần truy vết taint ở `analysis.python`: ở đây không có nguồn bẩn. Lỗ hổng
nằm ở CHÍNH cấu hình của lời gọi -- thuật toán nào, khoá lấy từ đâu, cờ xác
minh bật hay tắt -- nên thứ cần đọc là đối số, hằng số và tên mà kết quả được
gán vào. Mọi tên gọi đều được giải qua bảng import để `from hashlib import md5
as h` vẫn được nhận ra, còn một hàm tự viết trùng tên thì không.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget
from ...core.model import Confidence, Severity, StepKind
from ..base import AnalysisUnit, FindingBuilder
from ..python.imports import ImportResolver, dotted_name
from . import words

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_MAX_LITERAL_DEPTH = 4
_IDENTIFIER_LIKE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,48}$")

_CRYPTO_ROOTS = ("Crypto", "Cryptodome")

_WEAK_HASHES: Dict[str, str] = {
    "hashlib.md5": "MD5",
    "hashlib.sha1": "SHA-1",
    "cryptography.hazmat.primitives.hashes.MD5": "MD5",
    "cryptography.hazmat.primitives.hashes.SHA1": "SHA-1",
}
_FAST_HASHES: Dict[str, str] = {
    "hashlib.sha224": "SHA-224",
    "hashlib.sha256": "SHA-256",
    "hashlib.sha384": "SHA-384",
    "hashlib.sha512": "SHA-512",
    "hashlib.sha3_224": "SHA3-224",
    "hashlib.sha3_256": "SHA3-256",
    "hashlib.sha3_384": "SHA3-384",
    "hashlib.sha3_512": "SHA3-512",
    "hashlib.blake2b": "BLAKE2b",
    "hashlib.blake2s": "BLAKE2s",
    "cryptography.hazmat.primitives.hashes.SHA256": "SHA-256",
    "cryptography.hazmat.primitives.hashes.SHA512": "SHA-512",
}
for _root in _CRYPTO_ROOTS:
    for _name, _label in (("MD5", "MD5"), ("MD4", "MD4"), ("MD2", "MD2"), ("SHA1", "SHA-1"), ("SHA", "SHA-1")):
        _WEAK_HASHES["%s.Hash.%s.new" % (_root, _name)] = _label
    for _name, _label in (("SHA256", "SHA-256"), ("SHA512", "SHA-512"), ("SHA384", "SHA-384")):
        _FAST_HASHES["%s.Hash.%s.new" % (_root, _name)] = _label
_FAST_HASHES.update(_WEAK_HASHES)
_WEAK_HASH_NAMES = frozenset({"md5", "sha1", "sha-1", "md4", "md2"})

# Đi qua một trong những hàm này thì giá trị băm nhanh chỉ là bước tiền xử lý
# ( bcrypt cắt mật khẩu ở 72 byte nên người ta băm SHA-256 trước ).
_SLOW_KDF_PREFIXES = (
    "bcrypt.",
    "argon2.",
    "passlib.",
    "hashlib.pbkdf2_hmac",
    "hashlib.scrypt",
    "werkzeug.security.generate_password_hash",
    "django.contrib.auth.hashers.",
    "cryptography.hazmat.primitives.kdf.",
    "nacl.pwhash.",
    "scrypt.",
    "Crypto.Protocol.KDF.",
    "Cryptodome.Protocol.KDF.",
)

_BROKEN_CIPHERS: Dict[str, str] = {
    "pyDes.des": "DES",
    "pyDes.triple_des": "3DES",
}
for _root in _CRYPTO_ROOTS:
    for _name, _label in (
        ("DES", "DES"),
        ("DES3", "3DES"),
        ("ARC4", "RC4"),
        ("ARC2", "RC2"),
        ("Blowfish", "Blowfish"),
        ("CAST", "CAST-128"),
        ("XOR", "XOR"),
    ):
        _BROKEN_CIPHERS["%s.Cipher.%s.new" % (_root, _name)] = _label
for _package in (
    "cryptography.hazmat.primitives.ciphers.algorithms",
    "cryptography.hazmat.decrepit.ciphers.algorithms",
):
    for _name, _label in (
        ("TripleDES", "3DES"),
        ("ARC4", "RC4"),
        ("Blowfish", "Blowfish"),
        ("CAST5", "CAST5"),
        ("IDEA", "IDEA"),
        ("SEED", "SEED"),
        ("RC2", "RC2"),
    ):
        _BROKEN_CIPHERS["%s.%s" % (_package, _name)] = _label

_MODES = "cryptography.hazmat.primitives.ciphers.modes."
_AEAD = "cryptography.hazmat.primitives.ciphers.aead."
# Chế độ mà nonce lặp lại là lộ dòng khoá, không chỉ lộ cấu trúc.
_STREAM_MODES = frozenset({"MODE_CTR", "MODE_GCM", "MODE_EAX", "MODE_CCM", "MODE_OCB"})
_AEAD_REUSE_FATAL = frozenset({"AESGCM", "ChaCha20Poly1305", "AESCCM", "AESOCB3"})

# ( vị trí, tên keyword ) của khoá trong từng API.
_KEY_ARGUMENTS: Dict[str, Tuple[int, Tuple[str, ...]]] = {
    "cryptography.fernet.Fernet": (0, ("key",)),
    "hmac.new": (0, ("key",)),
    "hmac.HMAC": (0, ("key",)),
    "hmac.digest": (0, ("key",)),
    "cryptography.hazmat.primitives.hmac.HMAC": (0, ("key",)),
    "jwt.encode": (1, ("key",)),
    "jwt.decode": (1, ("key",)),
    "jose.jwt.encode": (1, ("key",)),
    "jose.jwt.decode": (1, ("key",)),
    "nacl.secret.SecretBox": (0, ("key",)),
}
for _name in (
    "Serializer",
    "URLSafeSerializer",
    "TimedSerializer",
    "URLSafeTimedSerializer",
    "Signer",
    "TimestampSigner",
    "TimedJSONWebSignatureSerializer",
    "JSONWebSignatureSerializer",
):
    _KEY_ARGUMENTS["itsdangerous.%s" % _name] = (0, ("secret_key",))
for _name in ("AES", "Camellia", "ChaCha20", "SM4", "TripleDES", "Blowfish", "ARC4"):
    _KEY_ARGUMENTS["cryptography.hazmat.primitives.ciphers.algorithms.%s" % _name] = (0, ("key",))
for _name in ("AESGCM", "ChaCha20Poly1305", "AESCCM", "AESOCB3", "AESSIV", "AESGCMSIV"):
    _KEY_ARGUMENTS[_AEAD + _name] = (0, ("key",))
for _root in _CRYPTO_ROOTS:
    _KEY_ARGUMENTS["%s.Hash.HMAC.new" % _root] = (0, ("key",))

_SALT_ARGUMENTS: Dict[str, Tuple[int, Tuple[str, ...]]] = {
    "hashlib.pbkdf2_hmac": (2, ("salt",)),
    "hashlib.scrypt": (-1, ("salt",)),
    "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC": (2, ("salt",)),
    "cryptography.hazmat.primitives.kdf.scrypt.Scrypt": (0, ("salt",)),
    "bcrypt.hashpw": (1, ("salt",)),
    "argon2.low_level.hash_secret": (1, ("salt",)),
    "argon2.low_level.hash_secret_raw": (1, ("salt",)),
}
for _root in _CRYPTO_ROOTS:
    _SALT_ARGUMENTS["%s.Protocol.KDF.PBKDF2" % _root] = (1, ("salt",))
    _SALT_ARGUMENTS["%s.Protocol.KDF.scrypt" % _root] = (1, ("salt",))

_KEY_SIZE_ARGUMENTS: Dict[str, Tuple[int, Tuple[str, ...], str]] = {
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": (
        1,
        ("key_size",),
        "RSA",
    ),
    "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": (
        0,
        ("key_size",),
        "DSA",
    ),
    "rsa.newkeys": (0, ("nbits",), "RSA"),
}
for _root in _CRYPTO_ROOTS:
    _KEY_SIZE_ARGUMENTS["%s.PublicKey.RSA.generate" % _root] = (0, ("bits",), "RSA")
    _KEY_SIZE_ARGUMENTS["%s.PublicKey.DSA.generate" % _root] = (0, ("bits",), "DSA")

_INSECURE_RANDOM = frozenset(
    {
        "random.random",
        "random.randint",
        "random.randrange",
        "random.choice",
        "random.choices",
        "random.getrandbits",
        "random.sample",
        "random.shuffle",
        "random.uniform",
        "random.randbytes",
        "numpy.random.rand",
        "numpy.random.randint",
        "numpy.random.choice",
        "numpy.random.bytes",
        "numpy.random.random",
    }
)
_RANDOM_PICKERS = frozenset({"choice", "choices", "sample"})

_HTTP_CLIENT_ROOTS = frozenset({"requests", "httpx"})
_HTTP_METHODS = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
        "send",
        "stream",
        "Client",
        "AsyncClient",
        "Session",
        "mount",
    }
)
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")


class _Literal:
    __slots__ = ("description", "line", "binding")

    def __init__(self, description: str, line: int, binding: Optional[ast.AST] = None) -> None:
        self.description = description
        self.line = line
        self.binding = binding


class PythonWeaknessChecks:
    def __init__(self, unit: AnalysisUnit, budget: Budget, builder: FindingBuilder) -> None:
        self.unit = unit
        self.budget = budget
        self.builder = builder
        self.resolver = ImportResolver()
        self.parents: Dict[int, ast.AST] = {}
        self.bindings: Dict[str, List[Optional[ast.expr]]] = {}
        self.attribute_bindings: Dict[str, List[Optional[ast.expr]]] = {}
        self.calls: List[ast.Call] = []
        self.attributes: List[ast.Attribute] = []
        self.assignments: List[ast.AST] = []
        self.constants: List[ast.Constant] = []
        self.compares: List[ast.Compare] = []
        self.functions: List[ast.AST] = []
        self.docstrings: Set[int] = set()
        # Dòng gán hằng đã được báo dưới dạng khoá viết cứng; không báo lại nó
        # là secret nữa.
        self.consumed: Set[int] = set()
        self.tls_reported: Set[Tuple[int, str]] = set()

    # ------------------------------------------------------------------ index

    def run(self, tree: ast.AST) -> None:
        self.resolver.collect(tree)
        self._index(tree)
        self._check_hashes()
        for call in self.calls:
            self.budget.spend()
            qual = self._qual(call.func)
            self._check_cipher(call, qual)
            self._check_iv(call, qual)
            self._check_key(call, qual)
            self._check_key_size(call, qual)
            self._check_tls_call(call, qual)
        for attribute in self.attributes:
            self.budget.spend()
            self._check_attribute(attribute)
        for node in self.assignments:
            self.budget.spend()
            self._check_tls_assignment(node)
        self._check_random()
        self._check_secrets()

    def _index(self, tree: ast.AST) -> None:
        for parent in ast.walk(tree):
            self.budget.spend()
            if isinstance(parent, (ast.Module, ast.ClassDef) + _FUNCTIONS):
                body = getattr(parent, "body", [])
                if body and isinstance(body[0], ast.Expr):
                    value = body[0].value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        self.docstrings.add(id(value))
            for child in ast.iter_child_nodes(parent):
                self.parents[id(child)] = parent
            if isinstance(parent, ast.Call):
                self.calls.append(parent)
            elif isinstance(parent, ast.Attribute):
                if isinstance(parent.ctx, ast.Load):
                    self.attributes.append(parent)
                else:
                    self._bind_attribute(parent)
            elif isinstance(parent, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                self.assignments.append(parent)
            elif isinstance(parent, ast.Constant):
                self.constants.append(parent)
            elif isinstance(parent, ast.Compare):
                self.compares.append(parent)
            elif isinstance(parent, _FUNCTIONS):
                self.functions.append(parent)
                for argument in parent.args.args + parent.args.kwonlyargs:
                    self.bindings.setdefault(argument.arg, []).append(None)
            elif isinstance(parent, ast.Name) and not isinstance(parent.ctx, ast.Load):
                self._bind_name(parent)

    def _bind_name(self, node: ast.Name) -> None:
        parent = self.parents.get(id(node))
        value: Optional[ast.expr] = None
        if isinstance(parent, ast.Assign) and node in parent.targets:
            value = parent.value
        elif isinstance(parent, ast.AnnAssign) and parent.target is node:
            value = parent.value
        self.bindings.setdefault(node.id, []).append(value)

    def _bind_attribute(self, node: ast.Attribute) -> None:
        parent = self.parents.get(id(node))
        value: Optional[ast.expr] = None
        if isinstance(parent, ast.Assign) and node in parent.targets:
            value = parent.value
        self.attribute_bindings.setdefault(node.attr, []).append(value)

    # ---------------------------------------------------------------- helpers

    def _qual(self, node: ast.AST) -> str:
        return self.resolver.qualname_of(node) or ""

    def _is_module_alias(self, name: str) -> bool:
        return self.resolver.resolve(name) != name or name in _HTTP_CLIENT_ROOTS

    def _function_of(self, node: ast.AST) -> Optional[ast.AST]:
        current = self.parents.get(id(node))
        while current is not None:
            if isinstance(current, _FUNCTIONS):
                return current
            current = self.parents.get(id(current))
        return None

    def _statement_of(self, node: ast.AST) -> ast.AST:
        current = node
        while True:
            parent = self.parents.get(id(current))
            if parent is None or isinstance(current, ast.stmt):
                return current
            current = parent

    def _literal(self, node: Optional[ast.AST], depth: int = 0) -> Optional[_Literal]:
        """Biểu thức này có phải một giá trị cố định ngay trong mã không."""
        if node is None or depth > _MAX_LITERAL_DEPTH:
            return None
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return _Literal("hằng chuỗi", line)
        if isinstance(node, ast.BinOp):
            left = self._literal(node.left, depth + 1)
            right = self._literal(node.right, depth + 1)
            if isinstance(node.op, ast.Mult):
                pair = (left, node.right) if left else (right, node.left)
                if pair[0] is not None and _is_int_constant(pair[1]):
                    return _Literal("chuỗi byte lặp lại cố định", line)
            if isinstance(node.op, ast.Add) and left is not None and right is not None:
                return _Literal("hằng chuỗi ghép", line)
            return None
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "encode":
                inner = self._literal(func.value, depth + 1)
                if inner is not None:
                    return _Literal(inner.description, inner.line, inner.binding)
            qual = self._qual(func)
            if qual in ("bytes", "bytearray") and len(node.args) == 1:
                if _is_int_constant(node.args[0]):
                    return _Literal("mảng byte toàn số 0", line)
                if isinstance(node.args[0], (ast.List, ast.Tuple)) and all(
                    _is_int_constant(item) for item in node.args[0].elts
                ):
                    return _Literal("mảng byte cố định", line)
            if qual in (
                "bytes.fromhex",
                "binascii.unhexlify",
                "binascii.a2b_hex",
                "base64.b64decode",
                "base64.urlsafe_b64decode",
                "base64.b16decode",
                "codecs.decode",
            ) and node.args:
                inner = self._literal(node.args[0], depth + 1)
                if inner is not None:
                    return _Literal("hằng chuỗi đã mã hoá", line, inner.binding)
            return None
        if isinstance(node, ast.Name):
            return self._bound_literal(self.bindings.get(node.id), depth)
        if isinstance(node, ast.Attribute):
            receiver = node.value
            if isinstance(receiver, ast.Name) and receiver.id in ("self", "cls"):
                found = self._bound_literal(self.attribute_bindings.get(node.attr), depth)
                if found is not None:
                    return found
                return self._bound_literal(self.bindings.get(node.attr), depth)
            if isinstance(receiver, ast.Name) and not self._is_module_alias(receiver.id):
                # Thuộc tính lớp viết hoa: `Config.SECRET`.
                if node.attr.isupper():
                    return self._bound_literal(self.bindings.get(node.attr), depth)
        return None

    def _bound_literal(
        self, values: Optional[List[Optional[ast.expr]]], depth: int
    ) -> Optional[_Literal]:
        if not values:
            return None
        found: Optional[_Literal] = None
        for value in values:
            literal = self._literal(value, depth + 1)
            if literal is None:
                return None
            found = found or _Literal(literal.description, getattr(value, "lineno", 0), value)
        return found

    def _argument(
        self, call: ast.Call, position: int, keywords: Sequence[str]
    ) -> Optional[ast.expr]:
        for keyword in call.keywords:
            if keyword.arg in keywords:
                return keyword.value
        if 0 <= position < len(call.args):
            argument = call.args[position]
            if not isinstance(argument, ast.Starred):
                return argument
        return None

    def _keyword(self, call: ast.Call, name: str) -> Optional[ast.expr]:
        for keyword in call.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    def _is_false(self, node: Optional[ast.AST]) -> bool:
        if isinstance(node, ast.Constant):
            return node.value is False or (node.value == 0 and not isinstance(node.value, str))
        if isinstance(node, ast.Name):
            values = self.bindings.get(node.id)
            return bool(values) and all(
                isinstance(value, ast.Constant) and value.value is False for value in values
            )
        return False

    def _names_in(self, node: Optional[ast.AST]) -> List[str]:
        """Mọi tên và khoá chuỗi xuất hiện trong một biểu thức."""
        found: List[str] = []
        if node is None:
            return found
        for child in ast.walk(node):
            self.budget.spend()
            if isinstance(child, ast.Name):
                found.append(child.id)
            elif isinstance(child, ast.Attribute):
                found.append(child.attr)
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                if _IDENTIFIER_LIKE.match(child.value):
                    found.append(child.value)
            elif isinstance(child, ast.keyword) and child.arg:
                found.append(child.arg)
        return found

    def _receiver_names(self, call: ast.Call) -> List[str]:
        """Tên của chính lời gọi, để không lấy `hashlib`, `md5` làm ngữ cảnh."""
        return self._names_in(call.func)

    def _output_names(self, node: ast.AST) -> Tuple[List[str], List[str]]:
        """Tên của nơi nhận giá trị ( vế trái, keyword, khoá dict, phép so ).

        Trả thêm danh sách tên đích trực tiếp ( vế trái phép gán ) để lần theo
        biến đó tới lệnh return của hàm.
        """
        names: List[str] = []
        targets: List[str] = []
        current = node
        while True:
            parent = self.parents.get(id(current))
            if parent is None:
                break
            if isinstance(parent, ast.keyword) and parent.arg:
                names.append(parent.arg)
            elif isinstance(parent, ast.Dict):
                for key, value in zip(parent.keys, parent.values):
                    if value is current and isinstance(key, ast.Constant):
                        if isinstance(key.value, str):
                            names.append(key.value)
            elif isinstance(parent, ast.Compare):
                for operand in [parent.left] + list(parent.comparators):
                    if operand is not current:
                        names.extend(self._names_in(operand))
            elif isinstance(parent, ast.Call):
                qual = self._qual(parent.func)
                if qual.endswith("compare_digest"):
                    for argument in parent.args:
                        if argument is not current:
                            names.extend(self._names_in(argument))
            if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                raw_targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                for target in raw_targets:
                    for name in _target_names(target):
                        names.append(name)
                        targets.append(name)
                break
            if isinstance(parent, ast.Return):
                function = self._function_of(parent)
                if function is not None:
                    names.append(function.name)  # type: ignore[attr-defined]
                break
            if isinstance(parent, ast.stmt):
                break
            current = parent
        return names, targets

    def _mask(self, node: ast.AST) -> None:
        """Che mọi hằng chuỗi của biểu thức trong snippet báo cáo."""
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, (str, bytes)):
                line = child.lineno
                end = getattr(child, "end_col_offset", None)
                if getattr(child, "end_lineno", line) != line or end is None:
                    end = len(self.unit.lines[line - 1]) if line <= len(self.unit.lines) else 0
                self.builder.mask(line, child.col_offset, end)

    def _in_enum(self, node: ast.AST) -> bool:
        parent = self.parents.get(id(node))
        if not isinstance(parent, ast.ClassDef):
            return False
        for base in parent.bases:
            name = (dotted_name(base) or "").rsplit(".", 1)[-1]
            if name.endswith(("Enum", "Flag", "Choices")):
                return True
        return False

    def _returned_names(self, function: ast.AST) -> Set[str]:
        returned: Set[str] = set()
        for child in ast.walk(function):
            if isinstance(child, ast.Return) and child.value is not None:
                for sub in ast.walk(child.value):
                    if isinstance(sub, ast.Name):
                        returned.add(sub.id)
        return returned

    def _inside_slow_kdf(self, node: ast.AST) -> bool:
        current = self.parents.get(id(node))
        while current is not None and not isinstance(current, ast.stmt):
            if isinstance(current, ast.Call):
                if self._qual(current.func).startswith(_SLOW_KDF_PREFIXES):
                    return True
            current = self.parents.get(id(current))
        return False

    def _fed_to_slow_kdf(self, function: Optional[ast.AST], targets: Iterable[str]) -> bool:
        wanted = set(targets)
        if not wanted:
            return False
        scope = function if function is not None else None
        calls = (
            [node for node in ast.walk(scope) if isinstance(node, ast.Call)]
            if scope is not None
            else self.calls
        )
        for call in calls:
            if self._qual(call.func).startswith(_SLOW_KDF_PREFIXES):
                if wanted & set(self._names_in(call)):
                    return True
        return False

    # ----------------------------------------------------------------- hashes

    def _hash_algorithm(self, call: ast.Call, qual: str) -> Optional[Tuple[str, bool, List[ast.expr]]]:
        """( tên thuật toán, có bị phá không, các đối số dữ liệu )."""
        if qual in _FAST_HASHES:
            data = [arg for arg in call.args if not isinstance(arg, ast.Starred)]
            data.extend(kw.value for kw in call.keywords if kw.arg in ("data", "string"))
            return _FAST_HASHES[qual], qual in _WEAK_HASHES, data
        if qual == "hashlib.new" and call.args:
            name = call.args[0]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                label = name.value.lower()
                data = list(call.args[1:])
                data.extend(kw.value for kw in call.keywords if kw.arg in ("data", "string"))
                return label.upper(), label in _WEAK_HASH_NAMES, data
        return None

    def _check_hashes(self) -> None:
        hashes: List[Tuple[ast.Call, str, bool, List[ast.expr]]] = []
        objects: Dict[str, int] = {}
        for call in self.calls:
            self.budget.spend()
            found = self._hash_algorithm(call, self._qual(call.func))
            if found is None:
                continue
            hashes.append((call, found[0], found[1], list(found[2])))
            statement = self._statement_of(call)
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        objects[target.id] = len(hashes) - 1
        # h = hashlib.md5(); h.update(password)
        if objects:
            for call in self.calls:
                func = call.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "update"
                    and isinstance(func.value, ast.Name)
                    and func.value.id in objects
                ):
                    hashes[objects[func.value.id]][3].extend(call.args)

        for call, label, weak, data in hashes:
            self.budget.spend()
            if self._inside_slow_kdf(call):
                continue
            inputs: List[str] = []
            for argument in data:
                inputs.extend(self._names_in(argument))
            outputs, targets = self._output_names(call)
            function = self._function_of(call)
            if self._fed_to_slow_kdf(function, targets):
                continue
            password_in = words.first_match(inputs, words.is_password_name)
            password_out = words.first_match(outputs, words.is_password_name)
            if password_in or password_out:
                name = password_in or password_out
                self.builder.add(
                    "FSB-CRYPTO-002",
                    call.lineno,
                    call.col_offset,
                    label,
                    "mật khẩu ( %s ) được băm bằng %s, một hàm băm nhanh không làm chậm vét cạn"
                    % (name, label),
                    end_line=getattr(call, "end_lineno", None),
                    end_column=getattr(call, "end_col_offset", None),
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
            if self._keyword(call, "usedforsecurity") is not None and self._is_false(
                self._keyword(call, "usedforsecurity")
            ):
                continue
            secret_in = words.first_match(inputs, words.is_secret_name)
            sign_out = words.first_match(outputs, words.is_sign_name)
            if secret_in or sign_out:
                self.builder.add(
                    "FSB-CRYPTO-001",
                    call.lineno,
                    call.col_offset,
                    label,
                    "%s được dùng để dựng giá trị xác thực ( %s ); hàm băm này đã có tấn công va "
                    "chạm và tự ghép bí mật với dữ liệu thì bị tấn công nối dài"
                    % (label, secret_in or sign_out),
                    end_line=getattr(call, "end_lineno", None),
                    end_column=getattr(call, "end_col_offset", None),
                    evidence=(
                        "dữ liệu được băm có chứa bí mật: %s" % secret_in
                        if secret_in
                        else "kết quả được dùng làm chữ ký: %s" % sign_out,
                    ),
                )

    # ---------------------------------------------------------------- ciphers

    def _check_cipher(self, call: ast.Call, qual: str) -> None:
        if qual == _MODES + "ECB":
            self.builder.add(
                "FSB-CRYPTO-004",
                call.lineno,
                call.col_offset,
                "modes.ECB",
                "bộ mã hoá khối chạy ở chế độ ECB, khối bản rõ giống nhau cho bản mã giống nhau",
                end_column=getattr(call, "end_col_offset", None),
                evidence=("chế độ %s" % qual,),
            )
            return
        label = _BROKEN_CIPHERS.get(qual)
        if label is None:
            return
        self.builder.add(
            "FSB-CRYPTO-003",
            call.lineno,
            call.col_offset,
            label,
            "dữ liệu được mã hoá bằng %s, một thuật toán đã bị phá" % label,
            end_line=getattr(call, "end_lineno", None),
            end_column=getattr(call, "end_col_offset", None),
            evidence=("thuật toán xác định từ lời gọi %s" % qual,),
        )

    def _check_attribute(self, node: ast.Attribute) -> None:
        if node.attr == "MODE_ECB":
            qual = self._qual(node)
            if qual.split(".", 1)[0] in _CRYPTO_ROOTS:
                self.builder.add(
                    "FSB-CRYPTO-004",
                    node.lineno,
                    node.col_offset,
                    "MODE_ECB",
                    "bộ mã hoá khối chạy ở chế độ ECB, khối bản rõ giống nhau cho bản mã giống nhau",
                    end_column=getattr(node, "end_col_offset", None),
                    evidence=("hằng chế độ %s" % qual,),
                )
            return
        if node.attr in ("CERT_NONE", "_create_unverified_context"):
            qual = self._qual(node)
            if qual in ("ssl.CERT_NONE", "ssl._create_unverified_context"):
                self._report_tls(
                    node,
                    "ssl-context",
                    "ngữ cảnh SSL được dựng với %s nên không xác minh chứng chỉ máy chủ" % qual,
                )

    def _check_iv(self, call: ast.Call, qual: str) -> None:
        root, _, rest = qual.partition(".")
        argument: Optional[ast.expr] = None
        what = "IV"
        fatal = False
        if root in _CRYPTO_ROOTS and rest.startswith("Cipher.") and rest.endswith(".new"):
            mode = call.args[1] if len(call.args) > 1 else self._keyword(call, "mode")
            mode_name = mode.attr if isinstance(mode, ast.Attribute) else ""
            argument = self._argument(call, 2, ("iv", "nonce"))
            if rest.startswith("Cipher.ChaCha20") or rest.startswith("Cipher.Salsa20"):
                argument = self._keyword(call, "nonce")
                fatal = True
            elif mode_name in _STREAM_MODES or self._keyword(call, "nonce") is not None:
                fatal = True
            what = "nonce" if fatal else "IV"
        elif qual.startswith(_MODES):
            mode_name = qual[len(_MODES) :]
            if mode_name in ("CBC", "CFB", "CFB8", "OFB"):
                argument = self._argument(call, 0, ("initialization_vector",))
            elif mode_name in ("CTR", "GCM"):
                argument = self._argument(call, 0, ("nonce", "initialization_vector"))
                fatal, what = True, "nonce"
        elif qual.startswith(_AEAD) and qual.endswith((".encrypt", ".decrypt")):
            if qual[len(_AEAD) :].split(".", 1)[0] in _AEAD_REUSE_FATAL and qual.endswith(".encrypt"):
                argument = self._argument(call, 0, ("nonce",))
                fatal, what = True, "nonce"
        elif isinstance(call.func, ast.Attribute) and call.func.attr == "encrypt":
            receiver = call.func.value
            if isinstance(receiver, ast.Name) and self._bound_to_aead(receiver.id):
                argument = self._argument(call, 0, ("nonce",))
                fatal, what = True, "nonce"
        elif qual in _SALT_ARGUMENTS:
            position, keywords = _SALT_ARGUMENTS[qual]
            argument = self._argument(call, position, keywords)
            what = "muối"
        if argument is None:
            return
        literal = self._literal(argument)
        if literal is None:
            return
        if fatal:
            message = (
                "nonce là %s: cùng khoá và cùng nonce cho cùng dòng khoá, lộ XOR của các bản rõ"
                % literal.description
            )
        elif what == "muối":
            message = "muối của hàm dẫn xuất khoá là %s, mọi mật khẩu dùng chung một muối" % (
                literal.description
            )
        else:
            message = "IV là %s nên bản mã của các bản rõ cùng phần đầu sẽ trùng nhau" % (
                literal.description
            )
        trace = ()
        if literal.line and literal.line != argument.lineno:
            trace = (
                self.builder.step(StepKind.SOURCE, literal.line, 0, "giá trị cố định được gán ở đây"),
                self.builder.step(StepKind.SINK, call.lineno, call.col_offset, "dùng làm %s" % what),
            )
        self.builder.add(
            "FSB-CRYPTO-005",
            argument.lineno,
            argument.col_offset,
            what,
            message,
            end_column=getattr(argument, "end_col_offset", None),
            severity=Severity.HIGH if fatal else None,
            trace=trace,
            evidence=("%s lấy từ %s, không sinh mới cho mỗi lần dùng" % (what, literal.description),),
        )

    def _bound_to_aead(self, name: str) -> bool:
        values = self.bindings.get(name)
        if not values:
            return False
        for value in values:
            if not isinstance(value, ast.Call):
                return False
            qual = self._qual(value.func)
            if not qual.startswith(_AEAD) or qual[len(_AEAD) :] not in _AEAD_REUSE_FATAL:
                return False
        return True

    def _check_key(self, call: ast.Call, qual: str) -> None:
        root, _, rest = qual.partition(".")
        if root in _CRYPTO_ROOTS and rest.startswith("Cipher.") and rest.endswith(".new"):
            spec: Optional[Tuple[int, Tuple[str, ...]]] = (0, ("key",))
        else:
            spec = _KEY_ARGUMENTS.get(qual)
        if spec is None:
            return
        argument = self._argument(call, spec[0], spec[1])
        if argument is None:
            return
        literal = self._literal(argument)
        if literal is None:
            return
        if _is_empty_or_public(argument, literal):
            return
        if words.is_fixture_path(self.unit.relative_path):
            return  # khoá trong test là dữ liệu mẫu, không phải khoá bị lộ
        if literal.binding is not None:
            self.consumed.add(getattr(literal.binding, "lineno", 0))
            self._mask(literal.binding)
        self.consumed.add(argument.lineno)
        self._mask(argument)
        trace = ()
        if literal.line and literal.line != argument.lineno:
            trace = (
                self.builder.step(StepKind.SOURCE, literal.line, 0, "khoá cố định được gán ở đây"),
                self.builder.step(StepKind.SINK, call.lineno, call.col_offset, qual),
            )
        self.builder.add(
            "FSB-CRYPTO-006",
            argument.lineno,
            argument.col_offset,
            qual.rsplit(".", 1)[-1],
            "khoá của %s là %s nằm ngay trong mã nguồn" % (qual, literal.description),
            end_column=getattr(argument, "end_col_offset", None),
            trace=trace,
            evidence=("khoá được giải về %s" % literal.description,),
        )

    def _check_key_size(self, call: ast.Call, qual: str) -> None:
        spec = _KEY_SIZE_ARGUMENTS.get(qual)
        algorithm = ""
        argument: Optional[ast.expr] = None
        if spec is not None:
            argument = self._argument(call, spec[0], spec[1])
            algorithm = spec[2]
        elif (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "generate_key"
            and len(call.args) == 2
            and isinstance(call.args[0], ast.Attribute)
            and call.args[0].attr in ("TYPE_RSA", "TYPE_DSA")
        ):
            argument = call.args[1]
            algorithm = call.args[0].attr[5:]
        if argument is None:
            return
        bits = self._int_value(argument)
        if bits is None or bits >= 2048:
            return
        self.builder.add(
            "FSB-CRYPTO-008",
            argument.lineno,
            argument.col_offset,
            algorithm,
            "khoá %s chỉ dài %d bit" % (algorithm, bits),
            end_column=getattr(argument, "end_col_offset", None),
            severity=Severity.HIGH if bits < 1024 else None,
            evidence=("độ dài khoá đọc được là hằng %d" % bits,),
        )

    def _int_value(self, node: ast.AST) -> Optional[int]:
        if _is_int_constant(node):
            return int(node.value)  # type: ignore[attr-defined]
        if isinstance(node, ast.Name):
            values = self.bindings.get(node.id)
            if values and all(_is_int_constant(value) for value in values):
                return min(int(value.value) for value in values)  # type: ignore[union-attr]
        return None

    # -------------------------------------------------------------------- TLS

    def _report_tls(self, node: ast.AST, group: str, message: str, confidence=None) -> None:
        function = self._function_of(node)
        key = (id(function) if function is not None else 0, group)
        if group and key in self.tls_reported:
            return
        self.tls_reported.add(key)
        evidence: Tuple[str, ...] = ()
        option = self._guarding_option(node)
        if option is None and function is not None and words.names_an_option(function.name):  # type: ignore[attr-defined]
            option = "hàm %s()" % function.name  # type: ignore[attr-defined]
        if option is not None:
            # Thư viện cài đặt chính tuỳ chọn "verify=False" cho người dùng:
            # đúng là tắt xác minh, nhưng chỉ khi bên gọi yêu cầu.
            confidence = Confidence.LOW
            evidence = (
                "chỉ chạy khi điều kiện %s cho phép; nếu đây là tuỳ chọn người dùng tự bật thì "
                "lỗ hổng nằm ở nơi bật nó" % option,
            )
        self.builder.add(
            "FSB-TLS-001",
            node.lineno,  # type: ignore[attr-defined]
            node.col_offset,  # type: ignore[attr-defined]
            group or "tls",
            message,
            end_column=getattr(node, "end_col_offset", None),
            confidence=confidence,
            evidence=evidence,
        )

    def _guarding_option(self, node: ast.AST) -> Optional[str]:
        current = self.parents.get(id(node))
        child = node
        while current is not None and not isinstance(current, _FUNCTIONS):
            if isinstance(current, (ast.If, ast.IfExp)) and child is not current.test:
                for name in self._names_in(current.test):
                    if words.names_an_option(name):
                        return name
            child = current
            current = self.parents.get(id(current))
        return None

    def _check_tls_call(self, call: ast.Call, qual: str) -> None:
        root = qual.split(".", 1)[0]
        func = call.func
        receiver_is_local = (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, (ast.Name, ast.Call, ast.Attribute))
            and not self._is_module_alias(_head(func.value))
        )
        verify = self._keyword(call, "verify")
        if verify is not None and self._is_false(verify):
            http_client = root in _HTTP_CLIENT_ROOTS or (
                receiver_is_local
                and func.attr in _HTTP_METHODS  # type: ignore[union-attr]
                and self.resolver.imports_any(_HTTP_CLIENT_ROOTS)
            )
            if http_client:
                self._report_tls(
                    verify,
                    "",
                    "request HTTPS gửi với verify=False nên chấp nhận mọi chứng chỉ",
                    confidence=Confidence.MEDIUM if _targets_local_host(call) else None,
                )
                return
        for name in ("ssl", "verify_ssl"):
            value = self._keyword(call, name)
            if value is not None and self._is_false(value):
                if root == "aiohttp" or (receiver_is_local and self.resolver.imports_any(frozenset({"aiohttp"}))):
                    self._report_tls(
                        value,
                        "",
                        "request aiohttp gửi với %s=False nên chấp nhận mọi chứng chỉ" % name,
                        confidence=Confidence.MEDIUM if _targets_local_host(call) else None,
                    )
                    return
        cert_reqs = self._keyword(call, "cert_reqs")
        if isinstance(cert_reqs, ast.Constant) and cert_reqs.value in ("CERT_NONE", "NONE"):
            self._report_tls(cert_reqs, "", "kết nối được tạo với cert_reqs='%s'" % cert_reqs.value)
            return
        disabled = self._keyword(call, "disable_ssl_certificate_validation")
        if isinstance(disabled, ast.Constant) and disabled.value is True:
            self._report_tls(disabled, "", "httplib2 được tạo với disable_ssl_certificate_validation=True")
            return
        if isinstance(func, ast.Attribute) and func.attr == "set_missing_host_key_policy" and call.args:
            policy = self._qual(call.args[0])
            if policy.split(".")[-1] in ("AutoAddPolicy", "WarningPolicy") and policy.startswith("paramiko"):
                self._report_tls(
                    call,
                    "",
                    "SSH chấp nhận khoá máy chủ lạ ( %s ), ai đứng giữa đường cũng mạo danh được máy "
                    "chủ" % policy.split(".")[-1],
                )
            return
        if isinstance(func, ast.Attribute) and func.attr == "setopt" and len(call.args) == 2:
            option = self._qual(call.args[0])
            if option in ("pycurl.SSL_VERIFYPEER", "pycurl.SSL_VERIFYHOST") and self._is_false(call.args[1]):
                self._report_tls(call, "", "pycurl được đặt %s=0" % option.split(".")[-1])

    def _check_tls_assignment(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Assign):
            return
        for target in node.targets:
            if not isinstance(target, ast.Attribute):
                continue
            if target.attr == "check_hostname" and self._is_false(node.value):
                self._report_tls(
                    target,
                    "ssl-context",
                    "ngữ cảnh SSL tắt check_hostname nên chấp nhận chứng chỉ của tên miền khác",
                )
            elif target.attr == "verify" and self._is_false(node.value):
                if self.resolver.imports_any(_HTTP_CLIENT_ROOTS):
                    self._report_tls(
                        target,
                        "",
                        "phiên HTTP đặt verify = False nên mọi request của nó chấp nhận mọi chứng chỉ",
                    )

    # ------------------------------------------------------------------ PRNG

    def _check_random(self) -> None:
        producers: Dict[str, Tuple[ast.Call, ast.AST]] = {}
        sites: List[Tuple[ast.Call, str]] = []
        for call in self.calls:
            self.budget.spend()
            qual = self._qual(call.func)
            if qual in _INSECURE_RANDOM or (
                qual.startswith("random.Random.") and qual.count(".") == 2
            ):
                sites.append((call, qual))

        for call, qual in sites:
            drawn: List[str] = []
            for argument in call.args:
                drawn.extend(self._names_in(argument))
            if words.draws_from_nlp_data(drawn):
                continue
            outputs, targets = self._output_names(call)
            inputs: List[str] = []
            if qual.rsplit(".", 1)[-1] in _RANDOM_PICKERS:
                for argument in call.args:
                    inputs.extend(self._names_in(argument))
            function = self._function_of(call)
            # Giá trị chảy tới return thì tên hàm chính là tên của giá trị.
            returned = False
            if function is not None:
                statement = self._statement_of(call)
                returned = isinstance(statement, ast.Return) or bool(
                    set(targets) & self._returned_names(function)
                )
                if returned:
                    producers.setdefault(function.name, (call, function))  # type: ignore[attr-defined]
                    if function.name not in outputs:  # type: ignore[attr-defined]
                        outputs.append(function.name)  # type: ignore[attr-defined]
            hit = words.first_match(outputs + inputs, words.is_random_security_name)
            if hit is None:
                continue
            self._report_random(call, qual, hit)
            if function is not None and returned:
                producers.pop(function.name, None)  # type: ignore[attr-defined]

        if not producers:
            return
        for call in self.calls:
            self.budget.spend()
            func = call.func
            name = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else ""
            )
            if name not in producers:
                continue
            origin, function = producers[name]
            if self._function_of(call) is function:
                continue
            outputs, _ = self._output_names(call)
            hit = words.first_match(outputs, words.is_random_security_name)
            if hit is None:
                continue
            trace = (
                self.builder.step(
                    StepKind.SOURCE, origin.lineno, origin.col_offset, "PRNG không an toàn sinh giá trị"
                ),
                self.builder.step(StepKind.CALL, call.lineno, call.col_offset, "%s() trả giá trị đó về" % name),
            )
            self._report_random(call, "%s()" % name, hit, trace)

    def _report_random(self, call: ast.Call, qual: str, hit: str, trace=()) -> None:
        self.builder.add(
            "FSB-CRYPTO-007",
            call.lineno,
            call.col_offset,
            qual,
            "%s sinh giá trị cho %s; đầu ra của PRNG này dự đoán được sau vài mẫu quan sát" % (qual, hit),
            end_line=getattr(call, "end_lineno", None),
            end_column=getattr(call, "end_col_offset", None),
            trace=trace,
            evidence=("giá trị ngẫu nhiên đi vào tên mang nghĩa bảo mật: %s" % hit,),
        )

    # ---------------------------------------------------------------- secrets

    def _check_secrets(self) -> None:
        reported: Set[int] = set()
        fixture = words.is_fixture_path(self.unit.relative_path)

        def report(value: ast.Constant, holder: str, how: str) -> None:
            if id(value) in reported or value.lineno in self.consumed:
                return
            text = value.value if isinstance(value.value, str) else ""
            fmt = words.known_token_format(text)
            if (fmt is None or fmt == words.URL_CREDENTIALS) and fixture:
                return  # mật khẩu mẫu trong test không phải bí mật bị lộ
            if fmt is None:
                minimum = 6 if words.is_password_name(holder) else 8
                if not words.plausible_secret_value(text, minimum):
                    return
                if _looks_like_field_name(text, holder):
                    return
            reported.add(id(value))
            self._mask(value)
            strong = fmt is not None or words.strong_secret_value(text)
            self.builder.add(
                "FSB-SECRET-001",
                value.lineno,
                value.col_offset,
                holder or (fmt or "secret"),
                "%s ( %s ) được viết thẳng vào mã nguồn" % (fmt or "giá trị bí mật", holder or how),
                end_column=getattr(value, "end_col_offset", None),
                confidence=Confidence.HIGH if strong else None,
                evidence=(
                    ("khớp định dạng %s" % fmt) if fmt else "tên %s mang nghĩa bí mật" % holder,
                    "giá trị dài %d ký tự, không phải chuỗi mẫu hay tên biến môi trường" % len(text),
                ),
            )

        for node in self.assignments:
            value = getattr(node, "value", None)
            if not _is_str_constant(value):
                continue
            if self._in_enum(node):
                continue  # class Kind(Enum): SECRET = "secret" là nhãn, không phải bí mật
            raw_targets = node.targets if isinstance(node, ast.Assign) else [node.target]  # type: ignore[attr-defined]
            for target in raw_targets:
                for name in _target_names(target):
                    if words.is_secret_holder_name(name):
                        report(value, name, "phép gán")  # type: ignore[arg-type]
                        break
        for call in self.calls:
            for keyword in call.keywords:
                if keyword.arg and _is_str_constant(keyword.value):
                    if words.is_secret_holder_name(keyword.arg):
                        report(keyword.value, keyword.arg, "đối số")  # type: ignore[arg-type]
        for compare in self.compares:
            operands = [compare.left] + list(compare.comparators)
            if not all(isinstance(op, (ast.Eq, ast.NotEq)) for op in compare.ops):
                continue
            holder = None
            for operand in operands:
                if isinstance(operand, (ast.Name, ast.Attribute)):
                    name = operand.id if isinstance(operand, ast.Name) else operand.attr
                    if words.is_password_name(name) or words.is_secret_holder_name(name):
                        holder = name
            if holder is None:
                continue
            for operand in operands:
                if _is_str_constant(operand):
                    report(operand, holder, "phép so sánh")  # type: ignore[arg-type]
        for function in self.functions:
            arguments = function.args  # type: ignore[attr-defined]
            positional = arguments.args[len(arguments.args) - len(arguments.defaults) :]
            pairs = list(zip(positional, arguments.defaults)) + [
                (arg, default)
                for arg, default in zip(arguments.kwonlyargs, arguments.kw_defaults)
                if default is not None
            ]
            for argument, default in pairs:
                if _is_str_constant(default) and words.is_secret_holder_name(argument.arg):
                    report(default, argument.arg, "giá trị mặc định")  # type: ignore[arg-type]
        for constant in self.constants:
            self.budget.spend()
            if id(constant) in self.docstrings or not isinstance(constant.value, str):
                continue
            parent = self.parents.get(id(constant))
            if isinstance(parent, ast.Dict):
                for key, value in zip(parent.keys, parent.values):
                    if value is constant and _is_str_constant(key):
                        if words.is_secret_holder_name(key.value):  # type: ignore[union-attr]
                            report(constant, key.value, "khoá dict")  # type: ignore[union-attr]
            if words.known_token_format(constant.value):
                report(constant, "", "hằng chuỗi")


def _is_str_constant(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_int_constant(node: Optional[ast.AST]) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    )


def _target_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, ast.Subscript):
        key = target.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return [key.value]
    return []


def _head(node: ast.AST) -> str:
    dotted = dotted_name(node)
    return dotted.split(".", 1)[0] if dotted else ""


def _targets_local_host(call: ast.Call) -> bool:
    for argument in call.args[:1]:
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            return any(host in argument.value for host in _LOCAL_HOSTS)
        if isinstance(argument, ast.JoinedStr):
            for part in argument.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    if any(host in part.value for host in _LOCAL_HOSTS):
                        return True
    return False


def _is_empty_or_public(argument: ast.AST, literal: _Literal) -> bool:
    node = literal.binding if literal.binding is not None else argument
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        text = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
        if not text:
            return True
        if "PUBLIC KEY" in text or text.startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-")):
            return True
    return False




def _looks_like_field_name(value: str, holder: str) -> bool:
    """`PASSWORD_PARAM = "user_password"` -- tên một trường, không phải mật khẩu."""
    return words.looks_like_field_name(value, holder)


def scan_python(unit: AnalysisUnit, budget: Budget, builder: FindingBuilder) -> None:
    try:
        tree = ast.parse(unit.source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return
    PythonWeaknessChecks(unit, budget, builder).run(tree)

