"""Script thực thi được: PowerShell, batch, VBScript, JScript, HTA, shell, Python.

Script không có "import table", nên năng lực của nó được đọc thẳng từ văn
bản. Lớp làm rối phổ biến nhất ( base64 của -EncodedCommand, base64 + gzip,
nối chuỗi, dấu backtick / caret ) được gỡ có trần để detector nhìn thấy cùng
một nội dung mà trình thông dịch sẽ thấy. Không có gì được thực thi.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from typing import List, Optional, Tuple

from ..model import Parsed

MAX_DECODE_DEPTH = 3
MAX_DECODED_BYTES = 4 << 20
MAX_BLOBS = 32

SCRIPT_TYPES = {
    ".ps1": "PowerShell",
    ".psm1": "PowerShell",
    ".psd1": "PowerShell",
    ".bat": "batch",
    ".cmd": "batch",
    ".vbs": "VBScript",
    ".vbe": "VBScript ( encoded )",
    ".js": "JScript / JavaScript",
    ".jse": "JScript ( encoded )",
    ".wsf": "Windows Script File",
    ".hta": "HTML Application",
    ".sh": "shell",
    ".bash": "shell",
    ".ksh": "shell",
    ".zsh": "shell",
    ".command": "shell",
    ".py": "Python",
    ".pyw": "Python",
    ".applescript": "AppleScript",
}

# Những loại luôn được quét khi duyệt thư mục. .js và .py thì chỉ khi có
# shebang hoặc được chỉ định trực tiếp: trong một repo web thường chúng là
# mã nguồn, quét hết sẽ chỉ sinh nhiễu.
DIRECTORY_SCRIPT_SUFFIXES = (
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".jse", ".wsf", ".hta", ".sh", ".bash", ".ksh", ".zsh", ".command",
)

_SHEBANG = re.compile(rb"^#!\s*(\S+)(?:\s+(\S+))?")
_ENCODED_COMMAND = re.compile(
    r"(?i)(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+['\"]?([A-Za-z0-9+/]{20,}={0,2})"
)
_FROM_BASE64 = re.compile(r"(?i)FromBase64String\(\s*['\"]([A-Za-z0-9+/\s]{24,}={0,2})['\"]")
_LONG_BASE64 = re.compile(r"['\"]([A-Za-z0-9+/]{120,}={0,2})['\"]")
_CONCAT = re.compile(r"""(['"])\s*(?:\+|&|\.\.)\s*\1""")
_PS_BACKTICK = re.compile(r"`(?=[A-Za-z])")
_BATCH_CARET = re.compile(r"\^(?=[A-Za-z/\-])")


def script_type(name: str, head: bytes) -> Optional[str]:
    lowered = name.lower()
    for suffix, label in SCRIPT_TYPES.items():
        if lowered.endswith(suffix):
            return label
    match = _SHEBANG.match(head[:256])
    if match:
        interpreter = match.group(1).split(b"/")[-1]
        if interpreter == b"env" and match.group(2):
            interpreter = match.group(2)
        interpreter = interpreter.decode("latin-1", errors="replace").lower()
        if interpreter.startswith(("python",)):
            return "Python"
        if interpreter.startswith(("pwsh", "powershell")):
            return "PowerShell"
        if interpreter.startswith(("node",)):
            return "JScript / JavaScript"
        if interpreter.startswith(("osascript",)):
            return "AppleScript"
        if interpreter.startswith(("perl", "ruby", "php", "lua")):
            return interpreter.rstrip("0123456789.")
        return "shell"
    return None


def _decode_text(raw: bytes) -> str:
    """Giải mã văn bản, tự nhận UTF-16LE kể cả khi không có BOM.

    Ngưỡng phải thấp và không được đòi độ dài tối thiểu lớn: PowerShell
    -EncodedCommand LUÔN là UTF-16LE không BOM, và một lệnh một dòng chỉ dài
    vài chục byte. Đòi 64 byte là bỏ sót đúng trường hợp phổ biến nhất.
    """
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    odd = raw[1:256:2]
    if len(raw) >= 8 and len(raw) % 2 == 0 and odd and odd.count(0) / len(odd) > 0.4:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _b64(value: str) -> Optional[bytes]:
    cleaned = re.sub(r"\s+", "", value)
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=True)[:MAX_DECODED_BYTES]
    except (binascii.Error, ValueError):
        return None


def _maybe_inflate(blob: bytes) -> bytes:
    for wbits in (31, -15, 15):  # gzip, deflate thô, zlib
        try:
            engine = zlib.decompressobj(wbits)
            out = engine.decompress(blob, MAX_DECODED_BYTES)
            if out:
                return out
        except zlib.error:
            continue
    return blob


def _readable(blob: bytes) -> Optional[str]:
    inflated = _maybe_inflate(blob)
    for candidate in ((inflated, blob) if inflated is not blob else (blob,)):
        text = _decode_text(candidate)
        if not text:
            continue
        sample = text[:4000]
        printable = sum(1 for char in sample if char.isprintable() or char in "\r\n\t")
        if printable / len(sample) >= 0.85:
            return text
    return None


def deobfuscate(text: str, language: str) -> str:
    """Gỡ các lớp làm rối ở mức ký tự, giữ nguyên ngữ nghĩa để so khớp."""
    result = _CONCAT.sub("", text)
    if language == "PowerShell":
        result = _PS_BACKTICK.sub("", result)
    if language == "batch":
        result = _BATCH_CARET.sub("", result)
    return result


def decode_layers(text: str) -> List[Tuple[str, str]]:
    """Các khối base64 ( kể cả base64 + gzip ) giải được thành văn bản, đệ quy có trần."""
    layers: List[Tuple[str, str]] = []
    queue = [(text, 0)]
    while queue and len(layers) < MAX_BLOBS:
        current, depth = queue.pop(0)
        if depth >= MAX_DECODE_DEPTH:
            continue
        for pattern, label in (
            (_ENCODED_COMMAND, "-EncodedCommand"),
            (_FROM_BASE64, "FromBase64String"),
            (_LONG_BASE64, "chuỗi base64 dài"),
        ):
            for match in pattern.finditer(current):
                blob = _b64(match.group(1))
                if not blob:
                    continue
                decoded = _readable(blob)
                if decoded is None:
                    continue
                layers.append(("đã giải mã %s ( lớp %d )" % (label, depth + 1), decoded))
                queue.append((decoded, depth + 1))
                if len(layers) >= MAX_BLOBS:
                    return layers
    return layers


def parse(data: bytes, name: str, language: str) -> Parsed:
    parsed = Parsed(format="%s script" % language, family="script")
    parsed.traits.append("script")
    if data[:4] == b"#@~^":
        parsed.traits.append("encoded-script")
        parsed.anomalies.append(
            "script được mã hoá bằng Script Encoder ( #@~^ ); nội dung thật không đọc được nếu chưa giải mã"
        )
    text = _decode_text(data)
    parsed.embedded_text.append(("script", text))
    clean = deobfuscate(text, language)
    if clean != text:
        parsed.embedded_text.append(("script sau khi gỡ nối chuỗi / ký tự thoát", clean))
        removed = len(text) - len(clean)
        if removed > 40:
            parsed.traits.append("obfuscated")
    layers = decode_layers(clean)
    for label, decoded in layers:
        parsed.embedded_text.append((label, deobfuscate(decoded, language)))
    if layers:
        parsed.traits.append("base64-payload")
    return parsed
