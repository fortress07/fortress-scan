from __future__ import annotations

import re
from typing import Pattern, Tuple

PLACEHOLDER = "[redacted]"

_PATTERNS: Tuple[Pattern[str], ...] = (
    # Che cả phần thân base64 nằm cùng dòng ( chuỗi PEM viết trên một dòng với
    # `\n` thoát ), không chỉ dòng tiêu đề. Một lớp ký tự duy nhất, có chặn
    # trên, nên không có quay lui.
    re.compile(r"-----BEGIN[A-Z ]{0,40}PRIVATE KEY-----[A-Za-z0-9+/=\s\\]{0,8192}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,80}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,90}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,90}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,80}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,200}\.[A-Za-z0-9_\-]{10,200}\.[A-Za-z0-9_\-]{10,200}\b"),
    re.compile(
        r"(?i)\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
        r"client[_-]?secret|auth)\b\s*[:=]\s*['\"]([^'\"\n]{4,120})['\"]"
    ),
    re.compile(
        r"(?i)\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*"
        r"([^\s'\";,)\]}]{8,120})"
    ),
    # Tên giao thức có chặn trên, và đó không phải chuyện thẩm mỹ. Bản cũ viết
    # `[a-z][a-z0-9+.\-]*://`, mà lớp ký tự đó nuốt được chữ, số và dấu chấm
    # còn `:` thì không, nên trên chuỗi dài không có `://` bộ máy quét tới cuối
    # rồi lùi từng ký tự, lặp lại ở mọi vị trí bắt đầu. Đo được 3,0 giây cho
    # 32 KB, và redact() chạy trên từng dòng của mọi phát hiện.
    #
    # Tên giao thức dài nhất IANA từng đăng ký chưa tới 30 ký tự, nên chặn ở 30
    # không bỏ sót gì mà biến phép quay lui thành hằng số.
    re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{0,30}://[^\s/@]+:([^\s/@]{3,120})@"),
)

# Chặn trên cho MỘT lần gọi redact(). Đây là lưới an toàn thứ hai, độc lập với
# việc từng mẫu có tuyến tính hay không: mọi thứ redact() trả về đều bị
# make_snippet() cắt còn vài trăm ký tự, nên soi quá mức này không thêm được
# một ký tự nào vào báo cáo -- chỉ thêm thời gian cho một dòng dài bất thường.
MAX_REDACT_LENGTH = 8192


def redact(text: str) -> str:
    if not text:
        return ""
    result = text[:MAX_REDACT_LENGTH]
    for pattern in _PATTERNS:
        result = _apply(pattern, result)
    return result


def _apply(pattern: Pattern[str], text: str) -> str:
    def _replace(match: "re.Match[str]") -> str:
        if pattern.groups == 0:
            return PLACEHOLDER
        whole = match.group(0)
        secret = match.group(1)
        if not secret:
            return whole
        start = match.start(1) - match.start(0)
        end = match.end(1) - match.start(0)
        return whole[:start] + PLACEHOLDER + whole[end:]

    return pattern.sub(_replace, text)
