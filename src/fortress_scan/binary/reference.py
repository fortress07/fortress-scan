"""Nhận ra tài liệu / bộ quy tắc NÓI VỀ tấn công, thay vì tệp tấn công.

Vì sao cần: một repo thật hay có sẵn quy tắc Sigma, luật YARA, cấu hình EDR,
playbook ứng cứu, hoặc chính một bộ dò như công cụ này. Những tệp đó chứa đủ
mọi chuỗi đặc trưng của ransomware - đó là việc của chúng. Gọi chúng là
ransomware thì người dùng mất lòng tin vào mọi kết luận còn lại, và đó là
một bộ dò vô dụng.

Cách phân biệt được chọn ở đây là thứ chỉ tài liệu phát hiện mới có và kẻ
tấn công không có lý do gì để mang theo: mã kỹ thuật MITRE ATT&CK, mã CWE,
tên các bộ quy tắc. Mã độc thật không tự dán nhãn ATT&CK cho mình.

Phép này KHÔNG tha bổng tệp nào. Nó chỉ CHẶN TRẦN kết luận ở mức "đáng ngờ",
giữ nguyên mọi dấu hiệu kèm bằng chứng, và nói thẳng trong báo cáo rằng trần
đã được áp cùng lý do - để người đọc tự bỏ qua nếu tệp không phải tài liệu.
"""

from __future__ import annotations

import re
from typing import Optional

from .strings import StringPool

# Mã kỹ thuật ATT&CK Enterprise: T1486, T1490.001 ...
_ATTACK_ID = re.compile(r"(?<![a-z0-9])t1\d{3}(?:\.\d{3})?(?![0-9])")
_CWE_ID = re.compile(r"(?<![a-z0-9])cwe-\d{1,4}(?![0-9])")
_RULE_MARKERS = re.compile(
    r"\bmitre\b|att&ck|\battack\.t1\d|\bsigma\b|\byara\b|\brule[_ -]?id\b|\bdetection\b"
    r"|\bindicator\b|\bfalse positive\b|stopransomware|\bplaybook\b|\bremediation\b"
    r"|\bdấu hiệu\b|\bkhắc phục\b|\bphát hiện\b"
)

# Mảnh cú pháp regex: mã nguồn của một bộ quy tắc trông như thế này, còn một
# dòng lệnh thật thì không bao giờ.
_REGEX_SOURCE = re.compile(r"\(\?:|\(\?i\)|\(\?<|\[\^|\\b|\\w\{|\\W\{|\\s\{|\{\d,\d+\}")

MIN_REGEX_FRAGMENTS = 120
MIN_REGEX_KINDS = 5

MIN_ATTACK_IDS = 5
MIN_ATTACK_IDS_WITH_MARKERS = 3
MIN_MARKERS = 2


def looks_like_reference(pool: StringPool) -> Optional[str]:
    """Lý do con người đọc được, hoặc None nếu đây không phải tài liệu."""
    lower = pool.lower
    fragments = _REGEX_SOURCE.findall(lower)
    if len(fragments) >= MIN_REGEX_FRAGMENTS and len(set(fragments)) >= MIN_REGEX_KINDS:
        return "%d mảnh cú pháp regex thuộc %d dạng, tức là mã nguồn của một bộ quy tắc" % (
            len(fragments),
            len(set(fragments)),
        )
    attack = {match.group() for match in _ATTACK_ID.finditer(lower)}
    if len(attack) < MIN_ATTACK_IDS_WITH_MARKERS:
        return None
    cwe = {match.group() for match in _CWE_ID.finditer(lower)}
    markers = {match.group() for match in _RULE_MARKERS.finditer(lower)}
    enough = len(attack) >= MIN_ATTACK_IDS or (
        len(attack) >= MIN_ATTACK_IDS_WITH_MARKERS and len(markers) + len(cwe) >= MIN_MARKERS
    )
    if not enough:
        return None
    parts = ["%d mã ATT&CK khác nhau" % len(attack)]
    if cwe:
        parts.append("%d mã CWE" % len(cwe))
    if markers:
        parts.append("các từ của tài liệu phát hiện ( %s )" % ", ".join(sorted(markers)[:4]))
    return ", ".join(parts)
